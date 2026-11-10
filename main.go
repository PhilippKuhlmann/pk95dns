// PK95 DNS: network-wide DNS filter (AdGuard Home / Pi-hole style), standalone or under PK95 Core.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	_ "time/tzdata" // TZ works without /usr/share/zoneinfo (static binary, minimal images)

	"pk95dns/internal/app"
)

// version is set by the image build (-ldflags "-X main.version=…").
var version = "1.1.0"

func main() {
	cfg := app.Config{
		Version:   version,
		Listen:    env("PK95DNS_LISTEN", "0.0.0.0:8053"),
		DNSListen: env("PK95DNS_DNS_LISTEN", ":53"),
		DataDir:   env("PK95DNS_DATA_DIR", "/var/lib/pk95dns"),
		CoreMode:  os.Getenv("PK95_CORE_MODE") == "1",
		CoreURL:   os.Getenv("PK95_CORE_URL"),
		CoreToken: os.Getenv("PK95_CORE_TOKEN"),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg); err != nil {
		log.Fatal(err)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
