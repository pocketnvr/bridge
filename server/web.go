package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

//go:embed web/index.html
var webFS embed.FS

var pageTmpls = func() map[string]*template.Template {
	m := map[string]*template.Template{}
	for _, lang := range languages {
		m[lang] = template.Must(template.New("index.html").Funcs(template.FuncMap{
			"t":     func(key string, args ...any) string { return tr(lang, key, args...) },
			"tHTML": func(key string) template.HTML { return template.HTML(tr(lang, key)) },
			"ago":   func(t time.Time) string { return ago(lang, t) },
			"bytes": func(n uint64) string { return humanBytes(lang, n) },
		}).ParseFS(webFS, "web/index.html"))
	}
	return m
}()

const (
	sessionCookie = "pnvr_session"
	sessionTTL    = 7 * 24 * time.Hour
	pendingTTL    = 15 * time.Minute

	maxLoginFailures = 5
	failureWindow    = 10 * time.Minute
)

var bcryptSlots = make(chan struct{}, 2)

type pending struct {
	phoneID string
	conf    string
	token   string
	expires time.Time
}

type Web struct {
	cfg    *Config
	store  *Store
	tun    *Tunnel
	pub    *PublicAddr
	upnp   *PortKeeper
	health *FrigateHealth
	lanIP  string

	mu       sync.Mutex
	pend     map[string]*pending
	failures map[string][]time.Time
}

func newWeb(cfg *Config, store *Store, tun *Tunnel, pub *PublicAddr, up *PortKeeper, health *FrigateHealth, lanIP string) *Web {
	return &Web{
		cfg: cfg, store: store, tun: tun, pub: pub, upnp: up, health: health, lanIP: lanIP,
		pend:     map[string]*pending{},
		failures: map[string][]time.Time{},
	}
}

func (w *Web) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", w.index)
	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, _ *http.Request) { rw.Write([]byte("ok")) })
	mux.HandleFunc("POST /setup", w.setup)
	mux.HandleFunc("POST /login", w.login)
	mux.HandleFunc("POST /logout", w.logout)
	mux.HandleFunc("POST /phones", w.auth(w.addPhone))
	mux.HandleFunc("POST /phones/{id}/rekey", w.auth(w.rekey))
	mux.HandleFunc("POST /phones/{id}/delete", w.auth(w.deletePhone))
	mux.HandleFunc("GET /phones/{id}/qr.png", w.auth(w.qr))
	mux.HandleFunc("GET /phones/{id}/conf", w.auth(w.confFile))
	mux.HandleFunc("GET /api/status", w.auth(w.apiStatus))
	mux.HandleFunc("GET /import/{token}", w.importConf)
	return securityHeaders(w.localOnly(mux))
}

func (w *Web) localOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			h.ServeHTTP(rw, r)
			return
		}
		if ip, err := netip.ParseAddr(clientIP(r)); err != nil || !isLocalClient(ip) {
			http.Error(rw, tr(langOf(r), "err.lanOnly"), http.StatusForbidden)
			return
		}
		if !w.hostAllowed(r.Host) {
			http.Error(rw, tr(langOf(r), "err.host"), http.StatusMisdirectedRequest)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(rw, r.Body, 8<<10)
		}
		h.ServeHTTP(rw, r)
	})
}

func isLocalClient(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

func (w *Web) hostAllowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if host == "" {
		return false
	}
	if !strings.Contains(host, ".") || host == "localhost" {
		return true
	}
	for _, suffix := range []string{".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	for _, a := range w.cfg.AllowedHosts {
		if host == a {
			return true
		}
	}
	return false
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		hd := rw.Header()
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("Cache-Control", "no-store")
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		h.ServeHTTP(rw, r)
	})
}

func (w *Web) sign(exp int64) string {
	m := hmac.New(sha256.New, w.store.SessionKey())
	fmt.Fprint(m, exp)
	return fmt.Sprintf("%d.%s", exp, base64.RawURLEncoding.EncodeToString(m.Sum(nil)))
}

func (w *Web) loggedIn(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	expStr, _, ok := strings.Cut(c.Value, ".")
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if !ok || err != nil || time.Now().Unix() > exp {
		return false
	}
	return hmac.Equal([]byte(c.Value), []byte(w.sign(exp)))
}

func (w *Web) startSession(rw http.ResponseWriter) {
	exp := time.Now().Add(sessionTTL).Unix()
	http.SetCookie(rw, &http.Cookie{
		Name: sessionCookie, Value: w.sign(exp), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()),
	})
}

func sameOrigin(r *http.Request) bool {
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" {
		return true
	}
	u, err := url.Parse(src)
	return err == nil && u.Host == r.Host
}

func (w *Web) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if !w.loggedIn(r) {
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/") {
				http.Error(rw, tr(langOf(r), "err.notLoggedIn"), http.StatusUnauthorized)
				return
			}
			http.Redirect(rw, r, "/", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && !sameOrigin(r) {
			http.Error(rw, tr(langOf(r), "err.badOrigin"), http.StatusForbidden)
			return
		}
		h(rw, r)
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func failureKey(r *http.Request) string {
	ip, err := netip.ParseAddr(clientIP(r))
	if err != nil {
		return clientIP(r)
	}
	ip = ip.Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

func (w *Web) reserveAttempt(key string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	recent := w.failures[key][:0]
	for _, t := range w.failures[key] {
		if time.Since(t) < failureWindow {
			recent = append(recent, t)
		}
	}
	if len(recent) >= maxLoginFailures {
		w.failures[key] = recent
		return false
	}
	w.failures[key] = append(recent, time.Now())
	return true
}

func (w *Web) forgetAttempts(key string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.failures, key)
}

func checkPassword(hash, pw string) bool {
	bcryptSlots <- struct{}{}
	defer func() { <-bcryptSlots }()
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func (w *Web) sweep() {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	for id, p := range w.pend {
		if now.After(p.expires) {
			delete(w.pend, id)
		}
	}
	for k, ts := range w.failures {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > failureWindow {
			delete(w.failures, k)
		}
	}
}

func (w *Web) setup(rw http.ResponseWriter, r *http.Request) {
	if w.store.AdminHash() != "" || !sameOrigin(r) {
		http.Redirect(rw, r, "/", http.StatusSeeOther)
		return
	}
	pw, confirm := r.PostFormValue("password"), r.PostFormValue("confirm")
	if len(pw) < 8 || pw != confirm {
		w.render(rw, r, pageData{View: "setup", Error: tr(langOf(r), "err.pwShort")})
		return
	}
	if len(pw) > 72 {
		w.render(rw, r, pageData{View: "setup", Error: tr(langOf(r), "err.pwLong")})
		return
	}
	bcryptSlots <- struct{}{}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	<-bcryptSlots
	if err == nil {
		err = w.store.SetAdminHash(string(h))
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	w.startSession(rw)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (w *Web) login(rw http.ResponseWriter, r *http.Request) {
	key := failureKey(r)
	if !sameOrigin(r) {
		http.Redirect(rw, r, "/", http.StatusSeeOther)
		return
	}
	if !w.reserveAttempt(key) {
		w.render(rw, r, pageData{View: "login", Error: tr(langOf(r), "err.tooMany")})
		return
	}
	if !checkPassword(w.store.AdminHash(), r.PostFormValue("password")) {
		time.Sleep(700 * time.Millisecond)
		w.render(rw, r, pageData{View: "login", Error: tr(langOf(r), "err.badPassword")})
		return
	}
	w.forgetAttempts(key)
	w.startSession(rw)
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (w *Web) logout(rw http.ResponseWriter, r *http.Request) {
	if w.loggedIn(r) && sameOrigin(r) {
		_ = w.store.RevokeSessions()
	}
	http.SetCookie(rw, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

var errNoPublicAddr = errors.New("public address unknown: set PUBLIC_HOST")

func issueError(lang string, err error) string {
	switch {
	case errors.Is(err, errNoPublicAddr):
		return tr(lang, "err.noPublic")
	case errors.Is(err, errNoFreeAddress):
		return tr(lang, "err.noFreeAddr")
	default:
		return tr(lang, "err.generic", err.Error())
	}
}

func (w *Web) issue(name, id string) (*pending, error) {
	endpoint := w.pub.Endpoint()
	if endpoint == "" {
		return nil, errNoPublicAddr
	}
	priv, pubKey, err := newKeyPair()
	if err != nil {
		return nil, err
	}
	var ph Phone
	if id == "" {
		ph, err = w.store.AddPhone(name, pubKey, w.cfg.ClientNet, endpoint)
	} else {
		ph, err = w.store.ReplaceKey(id, pubKey, endpoint)
	}
	if err != nil {
		return nil, err
	}
	if err := w.tun.SyncPhones(); err != nil {
		return nil, fmt.Errorf("updating WireGuard: %w", err)
	}
	if id != "" {
		w.tun.DropPhone(ph.Address)
	}
	serverPub, err := publicKeyOf(w.store.ServerKey())
	if err != nil {
		return nil, err
	}
	p := &pending{
		phoneID: ph.ID,
		conf:    clientConfig(w.cfg, serverPub, priv, ph, endpoint),
		token:   randomID() + randomID(),
		expires: time.Now().Add(pendingTTL),
	}
	w.mu.Lock()
	w.pend[ph.ID] = p
	w.mu.Unlock()
	log.Printf("phone %q: new key (%s)", ph.Name, ph.Address)
	return p, nil
}

func (w *Web) pendingFor(id string) *pending {
	w.mu.Lock()
	defer w.mu.Unlock()
	p := w.pend[id]
	if p == nil || time.Now().After(p.expires) {
		delete(w.pend, id)
		return nil
	}
	cp := *p
	return &cp
}

func (w *Web) addPhone(rw http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" {
		name = "iPhone"
	}
	if len([]rune(name)) > 40 {
		name = string([]rune(name)[:40])
	}
	p, err := w.issue(name, "")
	if err != nil {
		w.render(rw, r, pageData{View: "dashboard", Error: issueError(langOf(r), err)})
		return
	}
	http.Redirect(rw, r, "/?new="+url.QueryEscape(p.phoneID), http.StatusSeeOther)
}

func (w *Web) rekey(rw http.ResponseWriter, r *http.Request) {
	p, err := w.issue("", r.PathValue("id"))
	if err != nil {
		w.render(rw, r, pageData{View: "dashboard", Error: issueError(langOf(r), err)})
		return
	}
	http.Redirect(rw, r, "/?new="+url.QueryEscape(p.phoneID), http.StatusSeeOther)
}

func (w *Web) deletePhone(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ph, err := w.store.DeletePhone(id)
	if err == nil {
		w.mu.Lock()
		delete(w.pend, id)
		w.mu.Unlock()
		if err = w.tun.SyncPhones(); err == nil {
			w.tun.DropPhone(ph.Address)
			log.Printf("phone %q deleted", ph.Name)
		}
	}
	if err != nil && err != errNotFound {
		w.render(rw, r, pageData{View: "dashboard", Error: tr(langOf(r), "err.deleteFailed", err.Error())})
		return
	}
	http.Redirect(rw, r, "/", http.StatusSeeOther)
}

func (w *Web) qr(rw http.ResponseWriter, r *http.Request) {
	p := w.pendingFor(r.PathValue("id"))
	if p == nil {
		http.Error(rw, tr(langOf(r), "err.qrExpired"), http.StatusNotFound)
		return
	}
	png, err := qrcode.Encode(p.conf, qrcode.Medium, 512)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "image/png")
	rw.Write(png)
}

func (w *Web) confFile(rw http.ResponseWriter, r *http.Request) {
	p := w.pendingFor(r.PathValue("id"))
	if p == nil {
		http.Error(rw, tr(langOf(r), "err.fileExpired"), http.StatusNotFound)
		return
	}
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.Header().Set("Content-Disposition", `attachment; filename="pocketnvr.conf"`)
	rw.Write([]byte(p.conf))
}

func (w *Web) importConf(rw http.ResponseWriter, r *http.Request) {
	tok := r.PathValue("token")
	w.mu.Lock()
	var found *pending
	for _, p := range w.pend {
		if p.token != "" && hmac.Equal([]byte(p.token), []byte(tok)) && time.Now().Before(p.expires) {
			found = p
			p.token = ""
			break
		}
	}
	w.mu.Unlock()
	if found == nil {
		http.Error(rw, tr(langOf(r), "err.linkExpired"), http.StatusNotFound)
		return
	}
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.Write([]byte(found.conf))
}

type phoneView struct {
	Phone
	Stats   PhoneStats
	Online  bool
	Pending *pending
}

type pageData struct {
	View        string
	Error       string
	Phones      []phoneView
	New         *phoneView
	ImportLink  template.URL
	Endpoint    string
	PhoneURL    string
	Warnings    []Warning
	FrigateOK   bool
	UPnP        *UPnPStatus
	WGPort      int
	PublicPort  int
	ClientCount int
}

func (w *Web) dashboard(r *http.Request) pageData {
	stats := w.tun.Stats()
	d := pageData{View: "dashboard", Endpoint: w.pub.Endpoint(), PhoneURL: w.cfg.phoneURL, WGPort: w.cfg.WGPort, PublicPort: w.cfg.PublicPort}
	for _, p := range w.store.Phones() {
		st := stats[p.PublicKey]
		d.Phones = append(d.Phones, phoneView{
			Phone:   p,
			Stats:   st,
			Online:  !st.LastHandshake.IsZero() && time.Since(st.LastHandshake) < 3*time.Minute,
			Pending: w.pendingFor(p.ID),
		})
	}
	sort.Slice(d.Phones, func(i, j int) bool { return d.Phones[i].CreatedAt.Before(d.Phones[j].CreatedAt) })
	d.ClientCount = len(d.Phones)
	if id := r.URL.Query().Get("new"); id != "" {
		for i := range d.Phones {
			if d.Phones[i].ID == id && d.Phones[i].Pending != nil {
				d.New = &d.Phones[i]
				from := w.importOrigin(r) + "/import/" + d.New.Pending.token
				if d.New.Pending.token != "" {
					d.ImportLink = template.URL("pocketnvr://import?from=" + url.QueryEscape(from))
				}
			}
		}
	}
	ok, ferr := w.health.Snapshot()
	d.FrigateOK = ok
	if w.upnp != nil {
		st := w.upnp.Status()
		d.UPnP = &st
	}
	d.Warnings = diagnose(langOf(r), w.cfg, w.pub.Snapshot(), d.UPnP, ok, ferr, w.lanIP, w.store.Phones())
	return d
}

func (w *Web) importOrigin(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if _, err := netip.ParseAddr(host); err == nil || !strings.Contains(host, ".") || strings.HasSuffix(host, ".local") {
		return "http://" + r.Host
	}
	ip, port := w.lanIP, strconv.Itoa(w.cfg.WebPort)
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok {
		port = strconv.Itoa(la.Port)
		if a, ok := netip.AddrFromSlice(la.IP); ok {
			if a = a.Unmap(); isLocalClient(a) && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
				ip = a.String()
			}
		}
	}
	if _, err := netip.ParseAddr(ip); err != nil {
		return "http://" + r.Host
	}
	return "http://" + net.JoinHostPort(ip, port)
}

func (w *Web) index(rw http.ResponseWriter, r *http.Request) {
	switch {
	case w.store.AdminHash() == "":
		w.render(rw, r, pageData{View: "setup"})
	case !w.loggedIn(r):
		w.render(rw, r, pageData{View: "login"})
	default:
		w.render(rw, r, w.dashboard(r))
	}
}

func (w *Web) render(rw http.ResponseWriter, r *http.Request, d pageData) {
	if d.View == "dashboard" && d.Phones == nil && d.Error != "" {
		e := d.Error
		d = w.dashboard(r)
		d.Error = e
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Content-Language", langOf(r))
	rw.Header().Add("Vary", "Accept-Language")
	if err := pageTmpls[langOf(r)].Execute(rw, d); err != nil {
		log.Printf("page: %v", err)
	}
}

func (w *Web) apiStatus(rw http.ResponseWriter, r *http.Request) {
	d := w.dashboard(r)
	lang := langOf(r)
	type phoneJSON struct {
		ID       string `json:"id"`
		Online   bool   `json:"online"`
		LastSeen string `json:"lastSeen"`
		Traffic  string `json:"traffic"`
	}
	out := struct {
		FrigateOK bool        `json:"frigateOk"`
		Endpoint  string      `json:"endpoint"`
		Phones    []phoneJSON `json:"phones"`
		Warnings  []Warning   `json:"warnings"`
	}{FrigateOK: d.FrigateOK, Endpoint: d.Endpoint, Warnings: d.Warnings}
	for _, p := range d.Phones {
		out.Phones = append(out.Phones, phoneJSON{
			ID: p.ID, Online: p.Online, LastSeen: ago(lang, p.Stats.LastHandshake),
			Traffic: humanBytes(lang, p.Stats.Total()),
		})
	}
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(out)
}

func ago(lang string, t time.Time) string {
	if t.IsZero() {
		return tr(lang, "ago.never")
	}
	d := time.Since(t)
	switch {
	case d < 10*time.Second:
		return tr(lang, "ago.now")
	case d < time.Minute:
		return tr(lang, "ago.seconds", int(d.Seconds()))
	case d < time.Hour:
		return tr(lang, "ago.minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return tr(lang, "ago.hours", int(d.Hours()))
	default:
		return t.Local().Format(tr(lang, "ago.date"))
	}
}

func humanBytes(lang string, n uint64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d %s", n, tr(lang, "unit.b"))
	case n < 1<<20:
		return fmt.Sprintf("%.0f %s", float64(n)/1024, tr(lang, "unit.kb"))
	case n < 1<<30:
		return decimalMark(lang, fmt.Sprintf("%.1f", float64(n)/(1<<20))) + " " + tr(lang, "unit.mb")
	default:
		return decimalMark(lang, fmt.Sprintf("%.2f", float64(n)/(1<<30))) + " " + tr(lang, "unit.gb")
	}
}
