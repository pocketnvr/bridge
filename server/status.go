package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type PublicAddr struct {
	configured string
	port       int

	mu      sync.Mutex
	ip      netip.Addr
	err     string
	checked time.Time
}

func newPublicAddr(cfg *Config) *PublicAddr {
	return &PublicAddr{configured: cfg.PublicHost, port: cfg.PublicPort}
}

func (p *PublicAddr) Run(ctx context.Context) {
	for {
		p.refresh(ctx)
		wait := 10 * time.Minute
		if p.Snapshot().IP == (netip.Addr{}) {
			wait = time.Minute
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (p *PublicAddr) refresh(ctx context.Context) {
	ip, err := publicIPv4(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checked = time.Now()
	if err != nil {
		p.err = err.Error()
		return
	}
	if p.ip != ip {
		log.Printf("public address: %s", ip)
	}
	p.ip, p.err = ip, ""
}

type PublicSnapshot struct {
	Configured string
	IP         netip.Addr
	Err        string
}

func (p *PublicAddr) Snapshot() PublicSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PublicSnapshot{Configured: p.configured, IP: p.ip, Err: p.err}
}

func (p *PublicAddr) Endpoint() string {
	s := p.Snapshot()
	host := s.Configured
	if host == "" && s.IP.IsValid() {
		host = s.IP.String()
	}
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, fmt.Sprint(p.port))
}

type FrigateHealth struct {
	addr string

	mu      sync.Mutex
	ok      bool
	known   bool
	err     string
	checked time.Time
}

func (h *FrigateHealth) Run(ctx context.Context) {
	for {
		h.check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

func (h *FrigateHealth) check(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", h.addr)
	h.mu.Lock()
	defer h.mu.Unlock()
	wasOK, known := h.ok, h.known
	h.checked, h.known = time.Now(), true
	if err != nil {
		h.ok, h.err = false, err.Error()
		if wasOK || !known {
			log.Printf("Frigate unreachable (%s): %v", h.addr, err)
		}
		return
	}
	c.Close()
	if !wasOK {
		log.Printf("Frigate reachable (%s)", h.addr)
	}
	h.ok, h.err = true, ""
}

func (h *FrigateHealth) Snapshot() (ok bool, err string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ok, h.err
}

func isPublicIPv4(ip netip.Addr) bool {
	return ip.Is4() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
		!ip.IsUnspecified() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

type Warning struct {
	Level string
	Text  string
}

type staleEndpoint struct {
	old   netip.Addr
	names []string
}

func staleEndpoints(phones []Phone, now netip.Addr, configured string) []staleEndpoint {
	fixed, _ := netip.ParseAddr(configured)
	var out []staleEndpoint
	for _, p := range phones {
		host, _, err := net.SplitHostPort(p.Endpoint)
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Unmap().Is4() || ip.Unmap() == now.Unmap() || (fixed.IsValid() && ip.Unmap() == fixed.Unmap()) {
			continue
		}
		ip = ip.Unmap()
		i := 0
		for i < len(out) && out[i].old != ip {
			i++
		}
		if i == len(out) {
			out = append(out, staleEndpoint{old: ip})
		}
		out[i].names = append(out[i].names, p.Name)
	}
	return out
}

func diagnose(lang string, cfg *Config, pub PublicSnapshot, up *UPnPStatus, frigateOK bool, frigateErr string, lanIP string, phones []Phone) []Warning {
	var w []Warning
	if !frigateOK && frigateErr != "" {
		w = append(w, Warning{"error", tr(lang, "warn.frigateDown", cfg.forwardAddr)})
	}
	if cfg.frigatePort == 5000 {
		w = append(w, Warning{"warn", tr(lang, "warn.port5000")})
	}
	if pub.Configured == "" && !pub.IP.IsValid() {
		w = append(w, Warning{"error", tr(lang, "warn.noPublic")})
	}
	if pub.IP.IsValid() {
		key := "warn.staleEndpoint"
		if pub.Configured != "" {
			key = "warn.staleEndpointHost"
		}
		for _, s := range staleEndpoints(phones, pub.IP, pub.Configured) {
			w = append(w, Warning{"error", tr(lang, key, s.old, pub.IP, strings.Join(s.names, ", "))})
		}
	}
	manual := tr(lang, "warn.manual", cfg.PublicPort, lanIP, cfg.WGPort)
	switch {
	case up == nil:
		w = append(w, Warning{"info", tr(lang, "warn.upnpOff", manual)})
	case !up.OK && up.Code == upnpNoRouter:
		w = append(w, Warning{"warn", tr(lang, "warn.upnpNoRouter", manual)})
	case !up.OK && up.Code == upnpConflict:
		w = append(w, Warning{"warn", tr(lang, "warn.upnpConflict", cfg.PublicPort, manual)})
	case !up.OK && up.Error != "":
		w = append(w, Warning{"warn", tr(lang, "warn.upnpFailed", up.Error, manual)})
	case up.OK && up.ExternalIP.IsValid() && !isPublicIPv4(up.ExternalIP):
		w = append(w, Warning{"warn", tr(lang, "warn.doubleNAT", up.ExternalIP, cfg.PublicPort)})
	case up.OK && up.ExternalIP.IsValid() && pub.IP.IsValid() && up.ExternalIP != pub.IP:
		w = append(w, Warning{"warn", tr(lang, "warn.cgnat", pub.IP, up.ExternalIP)})
	}
	if pub.Configured == "" && pub.IP.IsValid() {
		w = append(w, Warning{"info", tr(lang, "warn.dyndns")})
	}
	return w
}
