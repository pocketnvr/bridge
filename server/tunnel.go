package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Tunnel struct {
	cfg   *Config
	store *Store
	dev   *device.Device
	tnet  *netstack.Net
	ln    net.Listener

	syncMu sync.Mutex

	mu      sync.Mutex
	conns   map[net.Conn]string
	perAddr map[string]int
}

const (
	maxRelays         = 512
	maxRelaysPerPhone = 128
)

type PhoneStats struct {
	LastHandshake time.Time
	Endpoint      string
	Rx, Tx        uint64
}

func (s PhoneStats) Total() uint64 { return s.Rx + s.Tx }

func startTunnel(cfg *Config, store *Store) (*Tunnel, error) {
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{cfg.phoneIP}, nil, 1420)
	if err != nil {
		return nil, fmt.Errorf("network stack: %w", err)
	}
	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   func(f string, a ...any) { log.Printf("wireguard: "+f, a...) },
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	t := &Tunnel{cfg: cfg, store: store, dev: dev, tnet: tnet, conns: map[net.Conn]string{}, perAddr: map[string]int{}}

	key, err := b64ToHex(store.ServerKey())
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(fmt.Sprintf("private_key=%s\n", key)); err != nil {
		dev.Close()
		return nil, err
	}
	if err := t.listen(); err != nil {
		dev.Close()
		return nil, err
	}
	if err := t.SyncPhones(); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("WireGuard on UDP port %d: %w (another WireGuard? set wg_port or WG_PORT to a free port)", cfg.WGPort, err)
	}

	t.ln, err = tnet.ListenTCP(&net.TCPAddr{IP: net.IP(cfg.phoneIP.AsSlice()), Port: int(cfg.frigatePort)})
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("listening in the tunnel: %w", err)
	}
	go t.serve()
	return t, nil
}

func wgPortCandidates(configured int, set bool, saved int) []int {
	if set {
		return []int{configured}
	}
	var out []int
	add := func(p int) {
		if p > 0 && p <= 65535 && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	add(saved)
	for p := configured; p < configured+10; p++ {
		add(p)
	}
	return out
}

func udpFree(port int) bool {
	pc, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	pc.Close()
	return true
}

func (t *Tunnel) listen() error {
	cfg := t.cfg
	saved := t.store.WGPort()
	candidates := wgPortCandidates(cfg.WGPort, cfg.wgPortSet, saved)
	chosen := candidates[0]
	if len(candidates) > 1 {
		chosen = 0
		for _, p := range candidates {
			if udpFree(p) {
				chosen = p
				break
			}
		}
		if chosen == 0 {
			return fmt.Errorf("UDP ports %d to %d all in use: set wg_port (WG_PORT) to a free port", cfg.WGPort, cfg.WGPort+9)
		}
		if chosen != cfg.WGPort && chosen != saved {
			log.Printf("UDP port %d already in use (another WireGuard?): using %d", cfg.WGPort, chosen)
		}
	}
	if err := t.dev.IpcSet(fmt.Sprintf("listen_port=%d\n", chosen)); err != nil {
		return fmt.Errorf("WireGuard on UDP port %d: %w (another WireGuard? set wg_port or WG_PORT to a free port)", chosen, err)
	}
	cfg.WGPort = chosen
	if !cfg.publicPortSet {
		cfg.PublicPort = chosen
	}
	return t.store.SetWGPort(chosen)
}

func (t *Tunnel) SyncPhones() error {
	t.syncMu.Lock()
	defer t.syncMu.Unlock()

	want := map[string]Phone{}
	for _, p := range t.store.Phones() {
		pub, err := b64ToHex(p.PublicKey)
		if err != nil {
			return fmt.Errorf("phone %q: %w", p.Name, err)
		}
		want[pub] = p
	}
	have, err := t.peerKeys()
	if err != nil {
		return err
	}

	var b strings.Builder
	for pub := range have {
		if _, ok := want[pub]; !ok {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", pub)
		}
	}
	for pub, p := range want {
		fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", pub, p.Address)
	}
	if b.Len() == 0 {
		return nil
	}
	return t.dev.IpcSet(b.String())
}

func (t *Tunnel) peerKeys() (map[string]bool, error) {
	ipc, err := t.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(ipc))
	for sc.Scan() {
		if k, v, _ := strings.Cut(sc.Text(), "="); k == "public_key" {
			keys[v] = true
		}
	}
	return keys, nil
}

func (t *Tunnel) DropPhone(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for c, a := range t.conns {
		if a == addr {
			c.Close()
		}
	}
}

func (t *Tunnel) Stats() map[string]PhoneStats {
	out := map[string]PhoneStats{}
	ipc, err := t.dev.IpcGet()
	if err != nil {
		return out
	}
	var cur string
	var st PhoneStats
	flush := func() {
		if cur != "" {
			out[cur] = st
		}
	}
	sc := bufio.NewScanner(strings.NewReader(ipc))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "public_key":
			flush()
			raw, _ := hex.DecodeString(v)
			cur, st = base64.StdEncoding.EncodeToString(raw), PhoneStats{}
		case "last_handshake_time_sec":
			if n, _ := strconv.ParseInt(v, 10, 64); n > 0 {
				st.LastHandshake = time.Unix(n, 0)
			}
		case "endpoint":
			st.Endpoint = v
		case "rx_bytes":
			st.Rx, _ = strconv.ParseUint(v, 10, 64)
		case "tx_bytes":
			st.Tx, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	flush()
	return out
}

func (t *Tunnel) serve() {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			return
		}
		go t.relay(c)
	}
}

func (t *Tunnel) relay(phone net.Conn) {
	defer phone.Close()
	addr := ""
	if ap, err := netip.ParseAddrPort(phone.RemoteAddr().String()); err == nil {
		addr = ap.Addr().String()
	}
	if !t.admit(phone, addr) {
		return
	}
	defer t.release(phone, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	frigate, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", t.cfg.forwardAddr)
	cancel()
	if err != nil {
		log.Printf("relay: Frigate unreachable (%s): %v", t.cfg.forwardAddr, err)
		return
	}
	t.mu.Lock()
	t.conns[frigate] = addr
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		delete(t.conns, frigate)
		t.mu.Unlock()
		frigate.Close()
	}()

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go pipe(frigate, phone)
	go pipe(phone, frigate)
	<-done
	<-done
}

func (t *Tunnel) admit(c net.Conn, addr string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.conns) >= 2*maxRelays || t.perAddr[addr] >= maxRelaysPerPhone {
		return false
	}
	t.conns[c] = addr
	t.perAddr[addr]++
	return true
}

func (t *Tunnel) release(c net.Conn, addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.conns, c)
	if t.perAddr[addr]--; t.perAddr[addr] <= 0 {
		delete(t.perAddr, addr)
	}
}

func (t *Tunnel) Close() {
	if t.ln != nil {
		t.ln.Close()
	}
	t.mu.Lock()
	for c := range t.conns {
		c.Close()
	}
	t.mu.Unlock()
	t.dev.Close()
}

func clientConfig(cfg *Config, serverPublicKey, phonePrivateKey string, phone Phone, endpoint string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
MTU = 1380

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s/32
PersistentKeepalive = 25

# PocketNVR url=%s
`, phonePrivateKey, phone.Address, serverPublicKey, endpoint, cfg.phoneIP, cfg.PhoneURL())
}

func b64ToHex(k string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		return "", errors.New("invalid WireGuard key")
	}
	return hex.EncodeToString(b), nil
}
