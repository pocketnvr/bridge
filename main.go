package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pocketnvr/bridge/server"
)

var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	server.Version = version
	if err := run(); err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := server.LoadConfig()
	if err != nil {
		return err
	}
	b, err := server.New(cfg)
	if err != nil {
		return err
	}
	defer b.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := b.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	log.Printf("stopping")
	return nil
}

func healthcheck() int {
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", server.HealthPort()))
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
