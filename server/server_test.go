package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func clearEnv(t *testing.T) {
	for _, k := range []string{"FRIGATE_URL", "PUBLIC_HOST", "WG_PORT", "PUBLIC_PORT", "WEB_PORT", "UPNP", "CLIENT_NET", "DATA_DIR"} {
		t.Setenv(k, "")
	}
}

func TestConfig(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	t.Setenv("DATA_DIR", dir)

	t.Setenv("FRIGATE_URL", "https://192.168.1.20:8971/")
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.phoneIP.String() != "192.168.1.20" || c.phoneURL != "https://192.168.1.20:8971" ||
		c.forwardAddr != "192.168.1.20:8971" || c.WGPort != 51820 || c.PublicPort != 51820 || !c.UPnP {
		t.Fatalf("unexpected config: %+v", c)
	}

	t.Setenv("FRIGATE_URL", "http://localhost:5000")
	t.Setenv("PUBLIC_PORT", "41000")
	t.Setenv("UPNP", "false")
	c, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	lan, _ := primaryLANAddr()
	if c.phoneIP != lan || c.forwardAddr != "localhost:5000" || c.PublicPort != 41000 || c.UPnP {
		t.Fatalf("localhost config: %+v (lan %s)", c, lan)
	}

	for _, bad := range []string{"", "ftp://x", "http://10.77.0.9:5000", "http://192.168.1.20:0"} {
		t.Setenv("FRIGATE_URL", bad)
		if _, err := LoadConfig(); err == nil {
			t.Errorf("FRIGATE_URL=%q should be rejected", bad)
		}
	}

	t.Setenv("FRIGATE_URL", "")
	t.Setenv("PUBLIC_PORT", "")
	t.Setenv("UPNP", "")
	os.WriteFile(filepath.Join(dir, "options.json"), []byte(`{"frigate_url":"http://192.168.1.30:5000","public_host":"maison.duckdns.org","wg_port":51999,"upnp":false}`), 0o600)
	c, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.phoneIP.String() != "192.168.1.30" || c.PublicHost != "maison.duckdns.org" || c.WGPort != 51999 || c.PublicPort != 51999 || c.UPnP {
		t.Fatalf("add-on options not applied: %+v", c)
	}

	os.WriteFile(filepath.Join(dir, "options.json"), []byte(`{"frigate_url":"","upnp":true}`), 0o600)
	c, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.phoneIP != lan || c.phoneURL != "https://"+lan.String()+":8971" || c.frigatePort != 8971 {
		t.Fatalf("add-on default: %+v (lan %s)", c, lan)
	}
	os.Remove(filepath.Join(dir, "options.json"))
	if _, err := LoadConfig(); err == nil {
		t.Error("FRIGATE_URL should be required without the add-on")
	}
}

func TestStoreAddresses(t *testing.T) {
	dir := t.TempDir()
	s, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	net := netip.MustParsePrefix("10.77.0.0/24")
	var ids []string
	for i := 0; i < 3; i++ {
		_, pub, _ := newKeyPair()
		p, err := s.AddPhone(fmt.Sprint("p", i), pub, net, "203.0.113.7:51820")
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("10.77.0.%d", i+2); p.Address != want {
			t.Fatalf("address %s, want %s", p.Address, want)
		}
		ids = append(ids, p.ID)
	}
	if _, err := s.DeletePhone(ids[1]); err != nil {
		t.Fatal(err)
	}
	_, pub, _ := newKeyPair()
	p, _ := s.AddPhone("again", pub, net, "")
	if p.Address != "10.77.0.5" {
		t.Fatalf("expected next address 10.77.0.5, got %s", p.Address)
	}
	_, pub2, _ := newKeyPair()
	r, err := s.ReplaceKey(p.ID, pub2, "198.51.100.4:51820")
	if err != nil || r.Address != p.Address || r.PublicKey != pub2 || r.Endpoint != "198.51.100.4:51820" {
		t.Fatalf("rekey: %+v %v", r, err)
	}

	s2, err := openStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Phones()) != 3 || s2.ServerKey() != s.ServerKey() || s2.d.LastAddr != "10.77.0.5" {
		t.Fatal("state not persisted")
	}
	fi, _ := os.Stat(filepath.Join(dir, "state.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state.json mode %v", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if strings.Contains(strings.ToLower(string(b)), "privatekey") {
		t.Fatal("phone private keys must not be stored")
	}

	small, _ := openStore(t.TempDir())
	n := netip.MustParsePrefix("10.9.0.0/29")
	count := 0
	for {
		_, pub, _ := newKeyPair()
		if _, err := small.AddPhone("x", pub, n, ""); err != nil {
			break
		}
		count++
	}
	if count != 5 {
		t.Fatalf("/29 gave %d phones, want 5", count)
	}
}

func fakeStun(t *testing.T, reply func(req []byte) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(reply(append([]byte(nil), buf[:n]...)), from)
		}
	}()
	return pc.LocalAddr().String()
}

func stunReply(req []byte, attrType uint16, ip [4]byte) []byte {
	if attrType == 0x0020 {
		binary.BigEndian.PutUint32(ip[:], binary.BigEndian.Uint32(ip[:])^stunMagicCookie)
	}
	attr := make([]byte, 12)
	binary.BigEndian.PutUint16(attr[0:], attrType)
	binary.BigEndian.PutUint16(attr[2:], 8)
	attr[5] = 0x01
	copy(attr[8:], ip[:])
	unknown := []byte{0x80, 0x22, 0x00, 0x03, 'a', 'b', 'c', 0}
	body := append(unknown, attr...)
	resp := make([]byte, 20)
	binary.BigEndian.PutUint16(resp[0:], 0x0101)
	binary.BigEndian.PutUint16(resp[2:], uint16(len(body)))
	copy(resp[4:20], req[4:20])
	return append(resp, body...)
}

func TestStun(t *testing.T) {
	old := stunServers
	t.Cleanup(func() { stunServers = old })

	xor := fakeStun(t, func(req []byte) []byte { return stunReply(req, 0x0020, [4]byte{203, 0, 113, 7}) })
	plain := fakeStun(t, func(req []byte) []byte { return stunReply(req, 0x0001, [4]byte{198, 51, 100, 9}) })
	garbage := fakeStun(t, func(req []byte) []byte { return []byte("nope") })

	stunServers = []string{garbage, xor}
	ip, err := publicIPv4(context.Background())
	if err != nil || ip.String() != "203.0.113.7" {
		t.Fatalf("got %v %v", ip, err)
	}
	stunServers = []string{plain}
	if ip, err := publicIPv4(context.Background()); err != nil || ip.String() != "198.51.100.9" {
		t.Fatalf("MAPPED-ADDRESS: got %v %v", ip, err)
	}

	tx := make([]byte, 12)
	head := func(body []byte) []byte {
		b := make([]byte, 20, 20+len(body))
		binary.BigEndian.PutUint16(b[0:], 0x0101)
		binary.BigEndian.PutUint16(b[2:], uint16(len(body)))
		binary.BigEndian.PutUint32(b[4:], stunMagicCookie)
		return append(b, body...)
	}
	for _, body := range [][]byte{
		{0x80, 0x22, 0x00, 0x03, 'a', 'b', 'c'},
		{0x00, 0x20, 0x00, 0x08, 0x00, 0x01},
		{0x00, 0x20, 0xff, 0xff},
		{},
	} {
		parseStunResponse(head(body), tx)
	}
}

type fakeIGD struct {
	mu       sync.Mutex
	calls    []string
	mappings map[string]map[string]string
	only0    bool
	extIP    string
}

func (f *fakeIGD) serve(t *testing.T) (location string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/desc.xml", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <friendlyName>Freebox Server</friendlyName>
  <serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3f</controlURL></service></serviceList>
  <deviceList><device>
   <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
   <deviceList><device>
    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
    <serviceList><service>
     <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
     <controlURL>ctl/IPConn</controlURL>
    </service></serviceList>
   </device></deviceList>
  </device></deviceList>
 </device>
</root>`)
	})
	mux.HandleFunc("/ctl/IPConn", func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("SOAPAction")
		body, _ := io.ReadAll(r.Body)
		arg := func(name string) string {
			m := regexp.MustCompile("<" + name + ">([^<]*)</" + name + ">").FindSubmatch(body)
			if m == nil {
				return ""
			}
			return string(m[1])
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case strings.Contains(action, "#AddPortMapping"):
			f.calls = append(f.calls, "add:"+arg("NewLeaseDuration"))
			if f.only0 && arg("NewLeaseDuration") != "0" {
				w.WriteHeader(500)
				io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>725</errorCode><errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>`)
				return
			}
			f.mappings[arg("NewExternalPort")] = map[string]string{
				"proto": arg("NewProtocol"), "client": arg("NewInternalClient"), "port": arg("NewInternalPort"),
			}
			io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/></s:Body></s:Envelope>`)
		case strings.Contains(action, "#GetExternalIPAddress"):
			f.calls = append(f.calls, "ext")
			fmt.Fprintf(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewExternalIPAddress>%s</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`, f.extIP)
		case strings.Contains(action, "#DeletePortMapping"):
			f.calls = append(f.calls, "del:"+arg("NewExternalPort"))
			delete(f.mappings, arg("NewExternalPort"))
			io.WriteString(w, `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>`)
		default:
			w.WriteHeader(500)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if bytes.HasPrefix(buf[:n], []byte("M-SEARCH")) {
				fmt.Fprintf(writerTo{pc, from}, "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: %s/desc.xml\r\nST: upnp:rootdevice\r\nUSN: uuid:test\r\n\r\n", srv.URL)
			}
		}
	}()
	old := ssdpAddr
	ssdpAddr = pc.LocalAddr().String()
	t.Cleanup(func() { ssdpAddr = old })
	return srv.URL + "/desc.xml"
}

type writerTo struct {
	pc net.PacketConn
	to net.Addr
}

func (w writerTo) Write(b []byte) (int, error) { return w.pc.WriteTo(b, w.to) }

func TestUPnPPortKeeper(t *testing.T) {
	f := &fakeIGD{mappings: map[string]map[string]string{}, only0: true, extIP: "192.168.1.254"}
	f.serve(t)

	k := newPortKeeper(51820, 51821)
	k.refresh(context.Background())
	st := k.Status()
	if !st.OK || st.Router != "Freebox Server" || st.ExternalIP.String() != "192.168.1.254" {
		t.Fatalf("status: %+v", st)
	}
	m := f.mappings["51820"]
	if m == nil || m["proto"] != "UDP" || m["port"] != "51821" || m["client"] != "127.0.0.1" {
		t.Fatalf("mapping: %+v", f.mappings)
	}
	if strings.Join(f.calls, ",") != "add:3600,add:0,ext" {
		t.Fatalf("calls: %v", f.calls)
	}

	k.refresh(context.Background())
	if f.calls[len(f.calls)-2] != "add:0" {
		t.Fatalf("renewal calls: %v", f.calls)
	}

	cfg := &Config{PublicPort: 51820, WGPort: 51821, forwardAddr: "x"}
	w := diagnose(langFR, cfg, PublicSnapshot{IP: netip.MustParseAddr("203.0.113.7")}, &st, true, "", "192.168.1.10", nil)
	if len(w) == 0 || !strings.Contains(w[0].Text, "double NAT") {
		t.Fatalf("expected double NAT warning: %+v", w)
	}

	k.Close()
	if f.calls[len(f.calls)-1] != "del:51820" || len(f.mappings) != 0 {
		t.Fatalf("mapping not removed: %v %v", f.calls, f.mappings)
	}
}

func TestDiagnose(t *testing.T) {
	cfg := &Config{PublicPort: 51820, WGPort: 51820, forwardAddr: "192.168.1.20:5000"}
	pubIP := PublicSnapshot{IP: netip.MustParseAddr("203.0.113.7")}
	has := func(ws []Warning, s string) bool {
		for _, w := range ws {
			if strings.Contains(w.Text, s) {
				return true
			}
		}
		return false
	}
	ok := &UPnPStatus{OK: true, ExternalIP: netip.MustParseAddr("203.0.113.7")}
	if w := diagnose(langFR, cfg, PublicSnapshot{Configured: "maison.duckdns.org"}, ok, true, "", "192.168.1.10", nil); len(w) != 0 {
		t.Fatalf("all good should give no warning: %+v", w)
	}
	if !has(diagnose(langFR, cfg, pubIP, nil, true, "", "192.168.1.10", nil), "redirigez le port UDP 51820 vers 192.168.1.10") {
		t.Fatal("UPnP off: manual forwarding advice expected")
	}
	shared := &UPnPStatus{OK: true, ExternalIP: netip.MustParseAddr("198.51.100.1")}
	if !has(diagnose(langFR, cfg, pubIP, shared, true, "", "x", nil), "partage") {
		t.Fatal("different public IP: shared IPv4 advice expected")
	}
	cgnat := &UPnPStatus{OK: true, ExternalIP: netip.MustParseAddr("100.70.1.2")}
	if !has(diagnose(langFR, cfg, pubIP, cgnat, true, "", "x", nil), "double NAT") {
		t.Fatal("CGNAT address: advice expected")
	}
	if !has(diagnose(langFR, cfg, PublicSnapshot{}, ok, false, "refused", "x", nil), "Frigate injoignable") ||
		!has(diagnose(langFR, cfg, PublicSnapshot{}, ok, true, "", "x", nil), "Adresse publique inconnue") {
		t.Fatal("frigate / public address errors expected")
	}

	phones := []Phone{
		{Name: "iPhone de Camille", Endpoint: "198.51.100.4:51820"},
		{Name: "Pixel", Endpoint: "203.0.113.7:51820"},
		{Name: "iPad", Endpoint: "198.51.100.4:51820"},
		{Name: "Vieux", Endpoint: ""},
		{Name: "Galaxy", Endpoint: "maison.duckdns.org:51820"},
		{Name: "Avant-hier", Endpoint: "192.0.2.9:51820"},
	}
	stale := 0
	for _, w := range diagnose(langFR, cfg, pubIP, ok, true, "", "x", phones) {
		if strings.Contains(w.Text, "maintenant 203.0.113.7") {
			stale++
			if w.Level != "error" || strings.Contains(w.Text, "Pixel") || strings.Contains(w.Text, "Vieux") || strings.Contains(w.Text, "Galaxy") {
				t.Errorf("only phones on a former address: %+v", w)
			}
		}
	}
	all := diagnose(langFR, cfg, pubIP, ok, true, "", "x", phones)
	if stale != 2 || !has(all, "(198.51.100.4, maintenant 203.0.113.7)") || !has(all, "(iPhone de Camille, iPad)") ||
		!has(all, "(192.0.2.9, maintenant 203.0.113.7)") || !has(all, "PUBLIC_HOST") {
		t.Fatalf("stale phone addresses expected: %+v", all)
	}
	withHost := diagnose(langFR, cfg, PublicSnapshot{Configured: "maison.duckdns.org", IP: pubIP.IP}, ok, true, "", "x", phones)
	if !has(withHost, "(198.51.100.4, maintenant 203.0.113.7)") || !has(withHost, "(iPhone de Camille, iPad)") ||
		!has(withHost, "(192.0.2.9, maintenant 203.0.113.7)") || !has(withHost, "Nouveau QR") || has(withHost, "PUBLIC_HOST") {
		t.Fatalf("with PUBLIC_HOST, phones on a former address expected, without the PUBLIC_HOST step: %+v", withHost)
	}
	fixedHost := diagnose(langFR, cfg, PublicSnapshot{Configured: "198.51.100.4", IP: pubIP.IP}, ok, true, "", "x", phones)
	if has(fixedHost, "198.51.100.4, maintenant") || !has(fixedHost, "(192.0.2.9, maintenant 203.0.113.7)") {
		t.Fatalf("phones on the address set as PUBLIC_HOST are fine: %+v", fixedHost)
	}
	if has(diagnose(langFR, cfg, PublicSnapshot{Configured: "maison.duckdns.org"}, ok, true, "", "x", phones), "maintenant") {
		t.Fatal("public address unknown: nothing to say about former addresses")
	}
}

type testBridge struct {
	cfg     *Config
	b       *Bridge
	web     *httptest.Server
	client  *http.Client
	frigate net.Listener
}

func newTestBridge(t *testing.T) *testBridge {
	t.Helper()
	clearEnv(t)
	lan, err := primaryLANAddr()
	if err != nil {
		t.Skip("no LAN address")
	}
	fr, err := net.Listen("tcp4", lan.String()+":0")
	if err != nil {
		t.Skip(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "frigate-ok") })
	go http.Serve(fr, mux)
	t.Cleanup(func() { fr.Close() })

	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("FRIGATE_URL", "http://"+fr.Addr().String())
	t.Setenv("PUBLIC_HOST", "127.0.0.1")
	t.Setenv("WG_PORT", fmt.Sprint(freeUDPPort(t)))
	t.Setenv("UPNP", "false")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go b.health.Run(ctx)

	web := httptest.NewServer(b.web.Handler())
	t.Cleanup(web.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &testBridge{cfg: cfg, b: b, web: web, client: client, frigate: fr}
}

func (tb *testBridge) post(t *testing.T, path string, form url.Values, origin string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, tb.web.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin == "" {
		origin = tb.web.URL
	}
	req.Header.Set("Origin", origin)
	resp, err := tb.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (tb *testBridge) get(t *testing.T, path string, c *http.Client) (int, string, http.Header) {
	t.Helper()
	if c == nil {
		c = tb.client
	}
	resp, err := c.Get(tb.web.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func TestAdminFlowAndIsolation(t *testing.T) {
	tb := newTestBridge(t)

	if _, body, _ := tb.get(t, "/", nil); !strings.Contains(body, "Choose the password") {
		t.Fatal("setup page expected")
	}
	resp := tb.post(t, "/setup", url.Values{"password": {"short"}, "confirm": {"short"}}, "")
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "At least 8 characters") {
		t.Fatal("short password must be refused")
	}
	if resp := tb.post(t, "/setup", url.Values{"password": {"correct horse"}, "confirm": {"correct horse"}}, ""); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("setup: %d", resp.StatusCode)
	}

	if _, _, h := tb.get(t, "/", nil); h.Get("Referrer-Policy") == "no-referrer" {
		t.Fatal("Referrer-Policy no-referrer breaks form posts in browsers")
	}
	if resp := tb.post(t, "/phones", url.Values{"name": {"x"}}, "null"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Origin null must be refused: %d", resp.StatusCode)
	}

	if resp := tb.post(t, "/phones", url.Values{"name": {"evil"}}, "http://evil.example"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("CSRF post: %d", resp.StatusCode)
	}

	resp = tb.post(t, "/phones", url.Values{"name": {"iPhone de Camille"}}, "")
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/?new=") {
		t.Fatalf("add phone: %d %q", resp.StatusCode, loc)
	}
	id := strings.TrimPrefix(loc, "/?new=")

	_, page, _ := tb.get(t, loc, nil)
	if !strings.Contains(page, "/phones/"+id+"/qr.png") || !strings.Contains(page, "pocketnvr://import?from=") {
		t.Fatalf("QR and import link expected on the page:\n%s", page[strings.Index(page, "<main>"):min(len(page), strings.Index(page, "<main>")+2500)])
	}
	code, png, hdr := tb.get(t, "/phones/"+id+"/qr.png", nil)
	if code != 200 || hdr.Get("Content-Type") != "image/png" || !strings.HasPrefix(png, "\x89PNG") {
		t.Fatalf("qr: %d %s", code, hdr.Get("Content-Type"))
	}
	_, conf, _ := tb.get(t, "/phones/"+id+"/conf", nil)
	for _, want := range []string{
		"[Interface]", "Address = 10.77.0.2/32", "Endpoint = 127.0.0.1:" + fmt.Sprint(tb.cfg.WGPort),
		"AllowedIPs = " + tb.cfg.phoneIP.String() + "/32", "# PocketNVR url=" + tb.cfg.phoneURL,
	} {
		if !strings.Contains(conf, want) {
			t.Fatalf("conf lacks %q:\n%s", want, conf)
		}
	}

	m := regexp.MustCompile(`pocketnvr://import\?from=([^"]+)`).FindStringSubmatch(page)
	from, _ := url.QueryUnescape(strings.ReplaceAll(m[1], "&amp;", "&"))
	u, _ := url.Parse(from)
	anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if code, body, _ := tb.get(t, u.Path, anon); code != 200 || body != conf {
		t.Fatalf("import: %d", code)
	}
	if code, _, _ := tb.get(t, u.Path, anon); code != 404 {
		t.Fatalf("import link must be single use, got %d", code)
	}

	if code, _, _ := tb.get(t, "/phones/"+id+"/conf", anon); code != http.StatusSeeOther {
		t.Fatalf("conf without session: %d", code)
	}
	if code, _, _ := tb.get(t, "/api/status", anon); code != http.StatusUnauthorized {
		t.Fatalf("status without session: %d", code)
	}

	tnet := dialAsPhone(t, conf)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := tnet.DialContext(ctx, "tcp", tb.cfg.forwardAddr)
	if err != nil {
		t.Fatalf("frigate through the bridge: %v", err)
	}
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	reply, _ := io.ReadAll(c)
	c.Close()
	if !strings.Contains(string(reply), "frigate-ok") {
		t.Fatalf("reply %q", reply)
	}

	other, err := net.Listen("tcp4", tb.cfg.phoneIP.String()+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if c, err := tnet.DialContext(ctx2, "tcp", other.Addr().String()); err == nil {
		c.Close()
		t.Fatal("another port on the same machine must not be reachable")
	}

	_, status, _ := tb.get(t, "/api/status", nil)
	if !strings.Contains(status, `"online":true`) {
		t.Fatalf("phone should be online: %s", status)
	}

	if resp := tb.post(t, "/phones/"+id+"/rekey", nil, ""); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("rekey: %d", resp.StatusCode)
	}
	if len(tb.b.store.Phones()) != 1 {
		t.Fatal("rekey must keep the phone")
	}
	if resp := tb.post(t, "/phones/"+id+"/delete", nil, ""); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if len(tb.b.store.Phones()) != 0 {
		t.Fatal("phone not deleted")
	}
}

func TestLoginLockout(t *testing.T) {
	tb := newTestBridge(t)
	tb.post(t, "/setup", url.Values{"password": {"correct horse"}, "confirm": {"correct horse"}}, "")
	tb.post(t, "/logout", nil, "")
	tb.client.Jar, _ = cookiejar.New(nil)

	for i := 0; i < 5; i++ {
		tb.post(t, "/login", url.Values{"password": {"wrong"}}, "")
	}
	resp := tb.post(t, "/login", url.Values{"password": {"correct horse"}}, "")
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "Too many attempts") {
		t.Fatal("expected lockout after 5 failures")
	}
}

func dialAsPhone(t *testing.T, conf string) *netstack.Net {
	t.Helper()
	get := func(key string) string {
		m := regexp.MustCompile(`(?m)^` + key + ` = (.+)$`).FindStringSubmatch(conf)
		if m == nil {
			t.Fatalf("%s missing in conf", key)
		}
		return strings.TrimSpace(m[1])
	}
	hexKey := func(b64 string) string {
		b, _ := base64.StdEncoding.DecodeString(b64)
		return hex.EncodeToString(b)
	}
	addr := netip.MustParsePrefix(get("Address")).Addr()
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1380)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "phone: "))
	err = dev.IpcSet(fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s\npersistent_keepalive_interval=25\n",
		hexKey(get("PrivateKey")), hexKey(get("PublicKey")), get("Endpoint"), get("AllowedIPs")))
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	return tnet
}

func TestAdminPageLocalOnly(t *testing.T) {
	tb := newTestBridge(t)
	h := tb.b.web.Handler()
	req := func(host, remote string) int {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host, r.RemoteAddr = host, remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	for _, c := range []struct {
		host, remote string
		want         int
	}{
		{"192.168.1.10:8765", "192.168.1.50:5555", 200},
		{"[fd00::10]:8765", "[fd00::50]:5555", 200},
		{"nas:8765", "10.0.0.5:1", 200},
		{"nas.local:8765", "10.0.0.5:1", 200},
		{"bridge.tail1234.ts.net:8765", "100.80.1.2:1", http.StatusMisdirectedRequest},
		{"evil.example.com:8765", "192.168.1.50:5555", http.StatusMisdirectedRequest},
		{"192.168.1.10:8765", "203.0.113.9:5555", http.StatusForbidden},
		{"[2001:db8::1]:8765", "[2001:db8::99]:5555", http.StatusForbidden},
	} {
		if got := req(c.host, c.remote); got != c.want {
			t.Errorf("Host %s from %s: %d, want %d", c.host, c.remote, got, c.want)
		}
	}
	tb.cfg.AllowedHosts = []string{"bridge.tail1234.ts.net"}
	if got := req("bridge.tail1234.ts.net:8765", "100.80.1.2:1"); got != 200 {
		t.Errorf("ALLOWED_HOSTS not honored: %d", got)
	}
}

func TestImportOrigin(t *testing.T) {
	w := &Web{cfg: &Config{WebPort: 8765, AllowedHosts: []string{"bridge.example.com"}}, lanIP: "192.168.1.10"}
	tcp := func(s string) *net.TCPAddr { return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s)) }
	for _, c := range []struct {
		host  string
		local *net.TCPAddr
		want  string
	}{
		{"192.168.1.10:8765", nil, "http://192.168.1.10:8765"},
		{"[fd00::10]:8765", nil, "http://[fd00::10]:8765"},
		{"nas:8765", nil, "http://nas:8765"},
		{"nas.local:8765", nil, "http://nas.local:8765"},
		{"bridge.example.com", tcp("192.168.1.10:8765"), "http://192.168.1.10:8765"},
		{"nas.lan:8765", tcp("[::ffff:192.168.1.10]:8765"), "http://192.168.1.10:8765"},
		{"bridge.tail1234.ts.net", tcp("100.80.1.2:8765"), "http://100.80.1.2:8765"},
		{"bridge.example.com", tcp("[fd00::10]:8765"), "http://[fd00::10]:8765"},
		{"bridge.example.com", tcp("127.0.0.1:8765"), "http://192.168.1.10:8765"},
		{"bridge.example.com", tcp("[fe80::1]:8765"), "http://192.168.1.10:8765"},
		{"bridge.example.com", nil, "http://192.168.1.10:8765"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = c.host
		if c.local != nil {
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, c.local))
		}
		if got := w.importOrigin(r); got != c.want {
			t.Errorf("importOrigin(%q, %v) = %q, want %q", c.host, c.local, got, c.want)
		}
	}
	w.lanIP = "cette machine"
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "bridge.example.com"
	if got := w.importOrigin(r); got != "http://bridge.example.com" {
		t.Errorf("without a LAN address: %q", got)
	}
}

func TestParallelLoginLockout(t *testing.T) {
	tb := newTestBridge(t)
	tb.post(t, "/setup", url.Values{"password": {"correct horse"}, "confirm": {"correct horse"}}, "")

	var wg sync.WaitGroup
	var mu sync.Mutex
	wrong := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			req, _ := http.NewRequest(http.MethodPost, tb.web.URL+"/login", strings.NewReader("password=nope"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", tb.web.URL)
			resp, err := c.Do(req)
			if err != nil {
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(b), "Mot de passe incorrect") {
				mu.Lock()
				wrong++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wrong > maxLoginFailures {
		t.Fatalf("%d passwords checked in parallel, limit is %d", wrong, maxLoginFailures)
	}
}

func TestPhonesStayConnectedAndRevocation(t *testing.T) {
	tb := newTestBridge(t)
	tb.post(t, "/setup", url.Values{"password": {"correct horse"}, "confirm": {"correct horse"}}, "")
	add := func(name string) (id, conf string) {
		loc := tb.post(t, "/phones", url.Values{"name": {name}}, "").Header.Get("Location")
		id = strings.TrimPrefix(loc, "/?new=")
		_, conf, _ = tb.get(t, "/phones/"+id+"/conf", nil)
		return
	}
	idA, confA := add("A")
	phoneA := dialAsPhone(t, confA)
	open := func() net.Conn {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := phoneA.DialContext(ctx, "tcp", tb.cfg.forwardAddr)
		if err != nil {
			t.Fatalf("phone A: %v", err)
		}
		return c
	}
	c := open()
	c.Close()
	before := tb.b.tun.Stats()[tb.b.store.Phones()[0].PublicKey].LastHandshake

	add("B")
	if after := tb.b.tun.Stats()[tb.b.store.Phones()[0].PublicKey].LastHandshake; !after.Equal(before) || after.IsZero() {
		t.Fatalf("phone A's session was reset (%v → %v)", before, after)
	}
	start := time.Now()
	c = open()
	if time.Since(start) > 2*time.Second {
		t.Fatalf("phone A needed %v to reconnect", time.Since(start))
	}

	addrA := tb.b.store.Phones()[0].Address
	countA := func() int {
		tb.b.tun.mu.Lock()
		defer tb.b.tun.mu.Unlock()
		n := 0
		for _, a := range tb.b.tun.conns {
			if a == addrA {
				n++
			}
		}
		return n
	}
	deadline := time.Now().Add(2 * time.Second)
	for countA() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if countA() == 0 {
		t.Fatal("phone A's relay should be open before deletion")
	}
	tb.post(t, "/phones/"+idA+"/delete", nil, "")
	deadline = time.Now().Add(2 * time.Second)
	for countA() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := countA(); n > 0 {
		t.Fatalf("%d relay(s) of the deleted phone still open", n)
	}
	c.Close()
	if keys, _ := tb.b.tun.peerKeys(); len(keys) != 1 {
		t.Fatalf("WireGuard should keep only phone B, has %d peers", len(keys))
	}
}

func TestPort5000Warning(t *testing.T) {
	cfg := &Config{PublicPort: 51820, WGPort: 51820, forwardAddr: "192.168.1.20:5000", frigatePort: 5000}
	w := diagnose(langFR, cfg, PublicSnapshot{Configured: "x.duckdns.org"}, &UPnPStatus{OK: true}, true, "", "x", nil)
	if len(w) == 0 || !strings.Contains(w[0].Text, "port 5000") {
		t.Fatalf("expected a port 5000 warning: %+v", w)
	}
}

func TestUPnPIgnoresForeignLocation(t *testing.T) {
	f := &fakeIGD{mappings: map[string]map[string]string{}, extIP: "203.0.113.7"}
	loc := f.serve(t)
	u, _ := url.Parse(loc)
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		n, from, err := pc.ReadFrom(buf)
		if err == nil && bytes.HasPrefix(buf[:n], []byte("M-SEARCH")) {
			fmt.Fprintf(writerTo{pc, from}, "HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.2:%s/desc.xml\r\n\r\n", u.Port())
		}
	}()
	ssdpAddr = pc.LocalAddr().String()
	if _, err := discoverIGD(context.Background()); err == nil {
		t.Fatal("a LOCATION on another host must be ignored")
	}
}

func TestLanguage(t *testing.T) {
	cases := map[string]string{
		"":                                 langEN,
		"fr-FR,fr;q=0.9,en-US;q=0.8":       langFR,
		"en-US,en;q=0.9,fr;q=0.8":          langEN,
		"de-DE,de;q=0.9,fr;q=0.7,en;q=0.5": langDE,
		"de-DE":                            langDE,
		"pt-BR,es;q=0.8":                   langES,
		"pt-BR":                            langEN,
		"it-IT,fr;q=0.5":                   langIT,
		"nl-BE,fr;q=0.5":                   langNL,
		"pt-PT,fr;q=0.5":                   langFR,
		"fr;q=0.2,en;q=0.8":                langEN,
		"FR-ca":                            langFR,
	}
	for header, want := range cases {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept-Language", header)
		if got := langOf(r); got != want {
			t.Errorf("Accept-Language %q: got %s, want %s", header, got, want)
		}
	}
	verbs := regexp.MustCompile(`%[a-z]`)
	for key, m := range messages {
		for _, lang := range languages {
			if m[lang] == "" {
				t.Errorf("%s: missing %s translation", key, lang)
			}
			if !slices.Equal(verbs.FindAllString(m[lang], -1), verbs.FindAllString(m[langEN], -1)) {
				t.Errorf("%s: placeholders differ in %s", key, lang)
			}
		}
	}
	cfg := &Config{PublicPort: 51820, WGPort: 51820, forwardAddr: "192.168.1.20:5000"}
	en := diagnose(langEN, cfg, PublicSnapshot{Configured: "x.duckdns.org"}, &UPnPStatus{Code: upnpConflict, Error: "x"}, true, "", "192.168.1.10", nil)
	if len(en) == 0 || !strings.Contains(en[0].Text, "already used") || !strings.Contains(en[0].Text, "forward UDP port 51820 to 192.168.1.10") {
		t.Fatalf("English UPnP conflict advice expected: %+v", en)
	}
	if got := ago(langFR, time.Now().Add(-5*time.Minute)); got != "il y a 5 min" {
		t.Fatalf("ago fr: %q", got)
	}
	if got := humanBytes(langEN, 2048); got != "2 KB" {
		t.Fatalf("bytes en: %q", got)
	}
	if got := humanBytes(langDE, 3<<19); got != "1,5 MB" {
		t.Fatalf("bytes de: %q", got)
	}
	if got := ago(langDE, time.Now().Add(-5*time.Minute)); got != "vor 5 Min." {
		t.Fatalf("ago de: %q", got)
	}
	if got := humanBytes(langNL, 3<<19); got != "1,5 MB" {
		t.Fatalf("bytes nl: %q", got)
	}
	if got := ago(langIT, time.Now().Add(-5*time.Minute)); got != "5 min fa" {
		t.Fatalf("ago it: %q", got)
	}
}

func TestPageLanguage(t *testing.T) {
	tb := newTestBridge(t)
	for _, c := range []struct{ header, lang, text string }{
		{"fr-FR,fr;q=0.9", "fr", "Choisissez le mot de passe"},
		{"de-DE,de;q=0.9", "de", "Wählen Sie das Passwort"},
		{"es-419,es;q=0.9", "es", "Elija la contraseña"},
		{"it-CH,it;q=0.9,de;q=0.8", "it", "Scelga la password"},
		{"nl-NL,nl;q=0.9", "nl", "Kies het wachtwoord"},
	} {
		req, _ := http.NewRequest(http.MethodGet, tb.web.URL+"/", nil)
		req.Header.Set("Accept-Language", c.header)
		resp, err := tb.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(b), `lang="`+c.lang+`"`) || !strings.Contains(string(b), c.text) {
			t.Fatalf("%s setup page expected", c.lang)
		}
		if !strings.Contains(resp.Header.Get("Vary"), "Accept-Language") {
			t.Fatal("Vary: Accept-Language expected")
		}
	}
}

func TestFrigateURLWithoutScheme(t *testing.T) {
	for _, c := range []struct {
		in, out  string
		explicit bool
	}{
		{"192.168.1.20:8971", "https://192.168.1.20:8971", false},
		{"192.168.1.20", "https://192.168.1.20:8971", false},
		{" frigate.local:8971/ ", "https://frigate.local:8971", false},
		{"http://192.168.1.20:5000", "http://192.168.1.20:5000", true},
		{"", "", true},
	} {
		if got, explicit := normalizeFrigateURL(c.in); got != c.out || explicit != c.explicit {
			t.Errorf("%q: %q %v, want %q %v", c.in, got, explicit, c.out, c.explicit)
		}
	}

	clearEnv(t)
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("FRIGATE_URL", "192.168.1.20:8971")
	c, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if c.PhoneURL() != "https://192.168.1.20:8971" || c.forwardAddr != "192.168.1.20:8971" || c.schemeSet {
		t.Fatalf("address without scheme: %+v", c)
	}
}

func TestProbeScheme(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer secure.Close()
	closed, _ := net.Listen("tcp4", "127.0.0.1:0")
	closedAddr := closed.Addr().String()
	closed.Close()
	addr := func(s string) string {
		u, _ := url.Parse(s)
		return u.Host
	}

	ctx := context.Background()
	for _, c := range []struct{ addr, want string }{
		{addr(plain.URL), "http"},
		{addr(secure.URL), "https"},
		{closedAddr, ""},
	} {
		if got := probeScheme(ctx, c.addr); got != c.want {
			t.Errorf("%s: %q, want %q", c.addr, got, c.want)
		}
	}

	cfg := &Config{forwardAddr: addr(plain.URL), phoneURL: "https://192.168.1.20:8971", schemeSet: true}
	cfg.detectScheme(ctx)
	if cfg.PhoneURL() != "http://192.168.1.20:8971" {
		t.Fatalf("Frigate in plain HTTP: %s", cfg.PhoneURL())
	}
	cfg.forwardAddr = addr(secure.URL)
	cfg.detectScheme(ctx)
	if cfg.PhoneURL() != "https://192.168.1.20:8971" {
		t.Fatalf("Frigate in HTTPS: %s", cfg.PhoneURL())
	}
	cfg.forwardAddr = closedAddr
	cfg.detectScheme(ctx)
	if cfg.PhoneURL() != "https://192.168.1.20:8971" {
		t.Fatalf("Frigate unreachable: the address must stay as it is, got %s", cfg.PhoneURL())
	}
}

func TestWGPortCandidates(t *testing.T) {
	if got := wgPortCandidates(51999, true, 51821); !slices.Equal(got, []int{51999}) {
		t.Errorf("port set by the user: %v", got)
	}
	got := wgPortCandidates(51820, false, 51823)
	if len(got) != 10 || got[0] != 51823 || got[1] != 51820 || slices.Contains(got[2:], 51823) || got[9] != 51829 {
		t.Errorf("saved port first, then 51820 to 51829: %v", got)
	}
	if got := wgPortCandidates(51820, false, 0); got[0] != 51820 || len(got) != 10 {
		t.Errorf("no saved port: %v", got)
	}
}

func TestWGPortInUse(t *testing.T) {
	clearEnv(t)
	busy, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.LocalAddr().(*net.UDPAddr).Port
	if port > 65000 {
		t.Skip("port too high to try the next ones")
	}
	t.Setenv("DATA_DIR", t.TempDir())
	t.Setenv("FRIGATE_URL", "http://192.168.1.20:5000")
	t.Setenv("PUBLIC_HOST", "127.0.0.1")
	t.Setenv("UPNP", "false")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.WGPort = port
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WGPort <= port || cfg.WGPort > port+9 || cfg.PublicPort != cfg.WGPort || b.store.WGPort() != cfg.WGPort {
		t.Fatalf("busy port %d: WireGuard on %d, public %d, saved %d", port, cfg.WGPort, cfg.PublicPort, b.store.WGPort())
	}
	chosen := cfg.WGPort
	b.Close()

	cfg, _ = LoadConfig()
	cfg.WGPort = port
	b, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WGPort != chosen {
		t.Fatalf("the port phones were set up with must be kept: %d, want %d", cfg.WGPort, chosen)
	}
	b.Close()

	t.Setenv("WG_PORT", fmt.Sprint(port))
	cfg, _ = LoadConfig()
	if _, err := New(cfg); err == nil || !strings.Contains(err.Error(), "wg_port") {
		t.Fatalf("port set by the user and in use: %v", err)
	}
}

func TestStalePortWarning(t *testing.T) {
	cfg := &Config{PublicPort: 51821, WGPort: 51821, forwardAddr: "192.168.1.20:8971"}
	ok := &UPnPStatus{OK: true, ExternalIP: netip.MustParseAddr("203.0.113.7")}
	phones := []Phone{
		{Name: "iPhone de Camille", Endpoint: "203.0.113.7:51820"},
		{Name: "Pixel", Endpoint: "203.0.113.7:51821"},
		{Name: "Vieux", Endpoint: ""},
	}
	var found []Warning
	for _, w := range diagnose(langFR, cfg, PublicSnapshot{Configured: "203.0.113.7", IP: netip.MustParseAddr("203.0.113.7")}, ok, true, "", "x", phones) {
		if strings.Contains(w.Text, "port WireGuard") {
			found = append(found, w)
		}
	}
	if len(found) != 1 || found[0].Level != "error" || !strings.Contains(found[0].Text, "(iPhone de Camille)") || !strings.Contains(found[0].Text, "51821") {
		t.Fatalf("phones set up with the former port: %+v", found)
	}
}

func TestIngress(t *testing.T) {
	tb := newTestBridge(t)
	h := tb.b.web.Handler()
	const base = "/api/hassio_ingress/AbC-123_x"
	do := func(method, path, host, remote string, hdr map[string]string, form url.Values) *httptest.ResponseRecorder {
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		r := httptest.NewRequest(method, path, body)
		r.Host, r.RemoteAddr = host, remote
		if form != nil {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}
	ingress := func(extra map[string]string) map[string]string {
		m := map[string]string{"X-Ingress-Path": base, "X-Forwarded-Host": "ha.example.com", "Origin": "https://ha.example.com"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	if rec := do("GET", "/", "ha.example.com", supervisorIP+":4000", ingress(nil), nil); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("outside Home Assistant, Ingress headers must not be trusted: %d", rec.Code)
	}
	tb.cfg.Addon = true
	if rec := do("GET", "/", "ha.example.com", "192.168.1.50:4000", ingress(nil), nil); rec.Code != http.StatusMisdirectedRequest {
		t.Fatalf("Ingress headers from another address than the Supervisor: %d", rec.Code)
	}
	rec := do("GET", "/", "ha.example.com", supervisorIP+":4000", ingress(nil), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `action="`+base+`/setup"`) || rec.Header().Get("X-Frame-Options") != "SAMEORIGIN" ||
		!strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'self'") {
		t.Fatalf("Ingress page: %d %v", rec.Code, rec.Header())
	}

	rec = do("POST", "/setup", "172.30.32.1:8765", supervisorIP+":4000", ingress(nil), url.Values{"password": {"correct horse"}, "confirm": {"correct horse"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != base+"/" {
		t.Fatalf("setup through Ingress: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			session = c
		}
	}
	if session == nil || session.Path != base+"/" {
		t.Fatalf("session cookie: %+v", session)
	}
	withCookie := ingress(map[string]string{"Cookie": session.Name + "=" + session.Value})

	evil := ingress(map[string]string{"Cookie": session.Name + "=" + session.Value, "Origin": "https://evil.example"})
	if rec := do("POST", "/phones", "172.30.32.1:8765", supervisorIP+":4000", evil, url.Values{"name": {"x"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site post through Ingress: %d", rec.Code)
	}
	rec = do("POST", "/phones", "172.30.32.1:8765", supervisorIP+":4000", withCookie, url.Values{"name": {"iPhone de Camille"}})
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, base+"/?new=") {
		t.Fatalf("add phone through Ingress: %d %q", rec.Code, loc)
	}
	rec = do("GET", strings.TrimPrefix(loc, base), "172.30.32.1:8765", supervisorIP+":4000", withCookie, nil)
	page := rec.Body.String()
	from := url.QueryEscape("http://" + net.JoinHostPort(tb.b.lanIP, fmt.Sprint(tb.cfg.WebPort)) + "/import/")
	if !strings.Contains(page, `src="`+base+`/phones/`) || !strings.Contains(page, "pocketnvr://import?from="+from) {
		t.Fatalf("QR and import link through Ingress:\n%s", page)
	}
}
