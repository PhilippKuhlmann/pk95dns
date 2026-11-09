// Package upstream talks to upstream DNS servers: plain UDP/TCP, DNS-over-TLS and
// DNS-over-HTTPS, with bootstrap resolution, routing (conditional forwarding, private PTR),
// modes (load_balance, parallel, sequential), fallback and health tracking
// (docs/design.md → Upstreams). It must not import internal/config (config imports it).
package upstream

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

// Spec is a parsed upstream address.
type Spec struct {
	Raw    string // as configured
	Scheme string // "udp" (plain, UDP with TCP retry), "tcp", "tls", "https"
	Host   string // IP or host name
	Port   string // default 53, 853 (tls), 443 (https)
	Path   string // https only, e.g. "/dns-query"
}

// ParseAddress parses "9.9.9.9", "9.9.9.9:53", "[2620:fe::fe]:53", "udp://…", "tcp://…",
// "tls://host[:port]", "https://host[:port]/path". Plain and tcp:// need an IP address
// (no host names, they could not be resolved without a resolver). German error messages.
func ParseAddress(s string) (Spec, error) {
	panic("not implemented")
}

// ParseBootstrap accepts a plain IP with optional port and returns "ip:port".
func ParseBootstrap(s string) (string, error) {
	panic("not implemented")
}

// Options for a single upstream.
type Options struct {
	Timeout   time.Duration // per exchange
	Bootstrap []string      // "ip[:port]" resolvers for DoT/DoH host names; empty = system resolver
}

// Upstream is one upstream server. Exchange must be safe for concurrent use and must not
// modify req.
type Upstream interface {
	Address() string
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	Close() error
}

// New creates an upstream for a configured address.
func New(addr string, opt Options) (Upstream, error) {
	panic("not implemented")
}

// Route sends a domain and its subdomains to one upstream (conditional forwarding).
type Route struct {
	Domain   string
	Upstream string
}

// Config of a Router (built by the app from config.Settings).
type Config struct {
	Upstreams        []string
	Fallback         []string
	Bootstrap        []string
	Mode             string // "load_balance", "parallel", "sequential"
	Timeout          time.Duration
	Routes           []Route
	PrivatePTR       bool
	PrivateUpstreams []string
}

// Health of one upstream address. Kept in a package-level registry keyed by address, so it
// survives Router rebuilds.
type Health struct {
	Address   string  `json:"address"`
	OK        bool    `json:"ok"`
	AvgMS     float64 `json:"avg_ms"`
	Queries   int64   `json:"queries"`
	Failures  int64   `json:"failures"`
	LastError string  `json:"last_error"`
	LastOK    int64   `json:"-"` // unix ms of the last good answer, 0 = never
}

// Router resolves queries through the configured upstreams.
type Router struct {
	// unexported fields
}

// NewRouter validates the config and creates all upstreams.
func NewRouter(cfg Config) (*Router, error) {
	panic("not implemented")
}

// Resolve answers req (it is not modified). Returns the answer, the address of the upstream
// that answered ("" when answered locally, e.g. private PTR NXDOMAIN) and an error when no
// upstream gave a good answer. The answer's Id equals req.Id.
func (r *Router) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	panic("not implemented")
}

// Health returns the health of the main upstreams (config order).
func (r *Router) Health() []Health {
	panic("not implemented")
}

// Close closes all upstreams (idle connections). Resolve calls in flight may still finish.
func (r *Router) Close() {
	panic("not implemented")
}

// Test asks addr for "example.org A" and returns the round trip time.
func Test(ctx context.Context, addr string, bootstrap []string, timeout time.Duration) (time.Duration, error) {
	panic("not implemented")
}

// IsPrivatePTR reports whether name (lowercase, no trailing dot) is a reverse lookup in a
// private range: 10/8, 172.16/12, 192.168/16, 100.64/10, 127/8, 169.254/16, fc00::/7, fe80::/10, ::1.
func IsPrivatePTR(name string) bool {
	panic("not implemented")
}
