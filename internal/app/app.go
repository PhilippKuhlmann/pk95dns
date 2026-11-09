// Package app wires PK95 DNS together: store, filter engine, lists, upstream router, cache,
// query log, statistics, DNS server, HTTP API and events to Core.
package app

import "context"

// Config comes from the environment (main.go).
type Config struct {
	Version   string
	Listen    string // HTTP, e.g. "0.0.0.0:8053"
	DNSListen string // e.g. ":53"
	DataDir   string
	CoreMode  bool
	CoreURL   string
	CoreToken string
}

// Run starts everything and blocks until ctx is done, then shuts down gracefully
// (HTTP shutdown, DNS listeners closed, query log and statistics flushed).
func Run(ctx context.Context, cfg Config) error { panic("not implemented") }
