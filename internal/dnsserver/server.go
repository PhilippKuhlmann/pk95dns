// Package dnsserver runs the DNS listeners (UDP and TCP) and the query pipeline of
// docs/design.md → Query pipeline: access control, rate limit, clients, local records,
// filtering, cache, upstreams, CNAME check, query log and statistics.
package dnsserver

import (
	"context"

	"github.com/miekg/dns"

	"pk95dns/internal/cache"
	"pk95dns/internal/config"
	"pk95dns/internal/filter"
	"pk95dns/internal/querylog"
	"pk95dns/internal/stats"
	"pk95dns/internal/store"
	"pk95dns/internal/upstream"
)

// Runtime is the configuration the pipeline works with; Apply swaps it atomically.
type Runtime struct {
	Settings config.Settings
	Router   *upstream.Router
	Rewrites *filter.Rewrites // enabled local records
	Clients  []store.Client
}

// Deps are the long-lived components. Log and Stats may be nil (tests).
type Deps struct {
	Filter *filter.Engine
	Cache  *cache.Cache
	Log    *querylog.Writer
	Stats  *stats.Recorder
	// OnListen is called when binding fails (ok=false, German message) and when it works
	// again after a failure (ok=true). Optional.
	OnListen func(ok bool, msg string)
}

// ListenStatus is the dns part of GET /api/status.
type ListenStatus struct {
	Listen string `json:"listen"`
	UDP    bool   `json:"udp"`
	TCP    bool   `json:"tcp"`
	Error  string `json:"error"`
}

// CheckResult is the answer of GET /api/check (docs/api.md).
type CheckResult struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	ClientIP   string `json:"client_ip"`
	ClientName string `json:"client_name"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	Rule       string `json:"rule"`
	ListID     int64  `json:"list_id"`
	ListName   string `json:"list_name"` // filled by the API
	Service    string `json:"service"`
	Answer     string `json:"answer"`
}

// Server implements dns.Handler. Safe for concurrent use.
type Server struct {
	// unexported fields
}

// New creates a server. Apply must be called before it answers queries (until then it
// answers SERVFAIL).
func New(deps Deps) *Server { panic("not implemented") }

// Apply swaps the runtime. The previous Router is closed after 30 seconds (in-flight
// queries may still use it). Also clears per-client rate limit state when the limit changes.
func (s *Server) Apply(rt Runtime) { panic("not implemented") }

// ListenAndServe binds UDP and TCP on addr and serves until ctx is done. When binding fails
// it reports through Deps.OnListen and Status and retries every 30 seconds.
func (s *Server) ListenAndServe(ctx context.Context, addr string) { panic("not implemented") }

// Status of the listeners.
func (s *Server) Status() ListenStatus { panic("not implemented") }

// ServeDNS answers one query (dns.Handler).
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) { panic("not implemented") }

// Check runs the pipeline for name/qtype/client up to the filtering decision without asking
// an upstream (local records, filtering, SafeSearch; status "ok" when nothing matched).
func (s *Server) Check(name string, qtype uint16, clientIP string) CheckResult {
	panic("not implemented")
}

// ClientName returns the configured client name for ip ("" when none).
func (s *Server) ClientName(ip string) string { panic("not implemented") }

// Hostname returns the cached reverse-DNS name of ip ("" when unknown) and starts a
// background lookup through the router when it is not cached (cache 1 h, failures 10 min).
func (s *Server) Hostname(ip string) string { panic("not implemented") }
