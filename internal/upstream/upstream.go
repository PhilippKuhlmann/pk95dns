// Package upstream talks to upstream DNS servers: plain UDP/TCP, DNS-over-TLS,
// DNS-over-HTTPS (HTTP/2 and HTTP/3) and DNS-over-QUIC, with bootstrap resolution, routing (conditional forwarding, private PTR),
// modes (load_balance, parallel, sequential), fallback and health tracking
// (docs/design.md → Upstreams). It must not import internal/config (config imports it).
package upstream

import (
	"context"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// Spec is a parsed upstream address.
type Spec struct {
	Raw    string // as configured
	Scheme string // "udp" (plain, UDP with TCP retry), "tcp", "tls", "https", "h3", "quic"
	Host   string // IP or host name
	Port   string // default 53, 853 (tls, quic), 443 (https, h3)
	Path   string // https and h3 only, e.g. "/dns-query"
}

// Protocol returns a short human label of the transport: "DNS", "DNS/TCP", "DoT", "DoH",
// "DoH3" or "DoQ".
func (s Spec) Protocol() string {
	switch s.Scheme {
	case "tcp":
		return "DNS/TCP"
	case "tls":
		return "DoT"
	case "https":
		return "DoH"
	case "h3":
		return "DoH3"
	case "quic":
		return "DoQ"
	default:
		return "DNS"
	}
}

// Encrypted reports whether the transport is encrypted and authenticated (DoT, DoH,
// DoH3, DoQ).
func (s Spec) Encrypted() bool {
	switch s.Scheme {
	case "tls", "https", "h3", "quic":
		return true
	}
	return false
}

// Encrypted reports whether addr is a valid address of an encrypted upstream
// (tls://, https://, h3://, quic://). Invalid addresses are not encrypted.
func Encrypted(addr string) bool {
	spec, err := ParseAddress(addr)
	return err == nil && spec.Encrypted()
}

// LANOnly reports whether addr is a valid plain address (udp/tcp, no encryption) whose IP
// is in a private range: 10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT), 127/8,
// 169.254/16, fc00::/7, fe80::/10, ::1. Plain DNS to such an address stays in the LAN.
func LANOnly(addr string) bool {
	spec, err := ParseAddress(addr)
	if err != nil || spec.Encrypted() {
		return false
	}
	a, err := netip.ParseAddr(spec.Host)
	if err != nil {
		return false
	}
	a = a.WithZone("").Unmap()
	for _, n := range privateNets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// Options for a single upstream.
type Options struct {
	Timeout   time.Duration // per exchange
	Bootstrap []string      // "ip[:port]" resolvers for DoT/DoH/DoQ host names; empty = system resolver
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
	res, err := newResolver(opt.Bootstrap, timeoutOf(opt))
	if err != nil {
		return nil, err
	}
	return newWithResolver(addr, opt, res)
}

// newWithResolver creates an upstream that resolves DoT/DoH/DoQ host names through res
// (shared by all upstreams of a Router).
func newWithResolver(addr string, opt Options, res *resolver) (Upstream, error) {
	spec, err := ParseAddress(addr)
	if err != nil {
		return nil, err
	}
	switch spec.Scheme {
	case "tls":
		return newDoT(spec, opt, res), nil
	case "https":
		return newDoH(spec, opt, res), nil
	case "h3":
		return newDoH3(spec, opt, res), nil
	case "quic":
		return newDoQ(spec, opt, res), nil
	default:
		return newPlain(spec, opt), nil
	}
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
