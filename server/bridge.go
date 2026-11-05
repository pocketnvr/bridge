package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

var Version = "dev"

type Bridge struct {
	cfg    *Config
	store  *Store
	tun    *Tunnel
	pub    *PublicAddr
	upnp   *PortKeeper
	health *FrigateHealth
	web    *Web
	srv    *http.Server
	ln     net.Listener
	lanIP  string
}

func New(cfg *Config) (*Bridge, error) {
	store, err := openStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	tun, err := startTunnel(cfg, store)
	if err != nil {
		return nil, err
	}
	b := &Bridge{
		cfg:    cfg,
		store:  store,
		tun:    tun,
		pub:    newPublicAddr(cfg),
		health: &FrigateHealth{addr: cfg.forwardAddr},
		lanIP:  "cette machine",
	}
	if ip, err := primaryLANAddr(); err == nil {
		b.lanIP = ip.String()
	}
	if cfg.UPnP {
		b.upnp = newPortKeeper(cfg.PublicPort, cfg.WGPort)
	}
	b.web = newWeb(cfg, store, tun, b.pub, b.upnp, b.health, b.lanIP)
	return b, nil
}

func (b *Bridge) Start(ctx context.Context) error {
	go b.pub.Run(ctx)
	go b.health.Run(ctx)
	if b.upnp != nil {
		go b.upnp.Run(ctx)
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				b.web.sweep()
			}
		}
	}()
	b.srv = &http.Server{
		Handler:           b.web.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", b.cfg.WebPort))
	if err != nil {
		return fmt.Errorf("web port %d unavailable: %w", b.cfg.WebPort, err)
	}
	b.ln = ln
	go func() {
		if err := b.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("web page: %v", err)
		}
	}()
	log.Printf("PocketNVR Bridge %s: Frigate %s, WireGuard UDP %d", Version, b.cfg.forwardAddr, b.cfg.WGPort)
	log.Printf("Add a phone at http://%s:%d", b.lanIP, b.WebPort())
	return nil
}

func (b *Bridge) WebPort() int {
	if b.ln == nil {
		return b.cfg.WebPort
	}
	return b.ln.Addr().(*net.TCPAddr).Port
}

func (b *Bridge) Close() {
	if b.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = b.srv.Shutdown(ctx)
		cancel()
	}
	if b.upnp != nil {
		b.upnp.Close()
	}
	b.tun.Close()
}
