// Package dnsserver runs the DNS listeners (UDP and TCP) and the query pipeline of
// docs/design.md → Query pipeline: access control, rate limit, clients, own zones and
// records, filtering, cache, upstreams, CNAME check, query log and statistics.
package dnsserver

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"pk95dns/internal/cache"
	"pk95dns/internal/config"
	"pk95dns/internal/filter"
	"pk95dns/internal/querylog"
	"pk95dns/internal/records"
	"pk95dns/internal/stats"
	"pk95dns/internal/store"
	"pk95dns/internal/upstream"
)

// Runtime is the configuration the pipeline works with; Apply swaps it atomically.
type Runtime struct {
	Settings config.Settings
	Router   *upstream.Router
	Records  *records.Index // compiled own zones and records (nil: none)
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

// Defaults of the timing knobs; tests change the copies in Server.
const (
	defaultRouterCloseDelay = 30 * time.Second
	defaultListenRetry      = 30 * time.Second
)

// Server implements dns.Handler. Safe for concurrent use.
type Server struct {
	deps    Deps
	state   atomic.Pointer[state]
	limiter *rateLimiter
	hosts   *hostCache

	statusMu sync.Mutex
	status   ListenStatus

	// Replaced in tests (set before use).
	now              func() time.Time
	routerCloseDelay time.Duration
	listenRetry      time.Duration
	onQuery          func(q store.Query, ev stats.Event, withStats bool) // called for every logged query
}

// New creates a server. Apply must be called before it answers queries (until then it
// answers SERVFAIL).
func New(deps Deps) *Server {
	return &Server{
		deps:             deps,
		limiter:          newRateLimiter(),
		hosts:            newHostCache(),
		now:              time.Now,
		routerCloseDelay: defaultRouterCloseDelay,
		listenRetry:      defaultListenRetry,
	}
}

// Apply swaps the runtime. The previous Router is closed after 30 seconds (in-flight
// queries may still use it). Also clears per-client rate limit state when the limit changes.
func (s *Server) Apply(rt Runtime) {
	st := compile(rt)
	if s.deps.Cache != nil {
		s.deps.Cache.Configure(st.settings.CacheSize, st.settings.CacheMinTTL, st.settings.CacheMaxTTL)
	}
	s.limiter.setRate(st.settings.Ratelimit)
	old := s.state.Swap(st)
	if old != nil && old.router != nil && old.router != st.router {
		time.AfterFunc(s.routerCloseDelay, old.router.Close)
	}
}

// Status of the listeners.
func (s *Server) Status() ListenStatus {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	return s.status
}

// ServeDNS answers one query (dns.Handler).
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if req == nil || req.Response {
		return
	}
	start := time.Now()
	if len(req.Question) != 1 {
		s.write(w, req, rcodeReply(req, dns.RcodeFormatError), false)
		return
	}
	if req.Opcode != dns.OpcodeQuery {
		s.write(w, req, rcodeReply(req, dns.RcodeNotImplemented), false)
		return
	}
	if opt := req.IsEdns0(); opt != nil && opt.Version() != 0 {
		// RFC 6891 6.1.3: only EDNS version 0 is implemented. finish adds an OPT (version
		// 0) that carries the extended rcode.
		s.write(w, req, rcodeReply(req, dns.RcodeBadVers), false)
		return
	}
	// The cache generation is read before the state: an answer resolved through a router
	// that was replaced (and the cache flushed) meanwhile is not cached (Cache.SetGen).
	var gen uint64
	if s.deps.Cache != nil {
		gen = s.deps.Cache.Gen()
	}
	st := s.state.Load()
	if st == nil {
		s.write(w, req, rcodeReply(req, dns.RcodeServerFailure), false)
		return
	}
	client := addrOf(w.RemoteAddr())
	now := s.now()
	o := s.process(st, req, client, now, gen)
	if o.drop {
		if o.logDrop {
			s.log(st, req, client, &o, "", start, now, false)
		}
		return
	}
	answer := summarize(o.resp.Answer)
	s.write(w, req, o.resp, o.authoritative)
	s.log(st, req, client, &o, answer, start, now, true)
}

// write finalizes resp for req (AA bit = aa) and sends it.
func (s *Server) write(w dns.ResponseWriter, req, resp *dns.Msg, aa bool) {
	finish(req, resp, isTCP(w), aa)
	_ = w.WriteMsg(resp)
}

// log writes the query log entry and (withStats) the statistics event of one query.
func (s *Server) log(st *state, req *dns.Msg, client netip.Addr, o *outcome, answer string, start, now time.Time, withStats bool) {
	if s.deps.Log == nil && s.deps.Stats == nil && s.onQuery == nil {
		return
	}
	elapsed := float64(time.Since(start).Microseconds()) / 1000
	q := req.Question[0]
	ip := ""
	if client.IsValid() {
		ip = client.String()
	}
	name := ""
	if st.settings.AnonymizeIP {
		// No reverse lookups of the real address when the log must not identify clients.
		if p, ok := st.clients.match(client); ok {
			name = p.name
		}
		ip = querylog.Anonymize(ip)
	} else {
		name = s.displayName(st, client)
	}
	rcode := ""
	if o.resp != nil {
		rcode = rcodeString(o.resp.Rcode)
	}
	entry := store.Query{
		TS:         now.UnixMilli(),
		ClientIP:   ip,
		ClientName: name,
		Name:       filter.NormalizeName(q.Name),
		QType:      typeString(q.Qtype),
		Status:     o.status,
		Reason:     o.reason,
		Rule:       o.rule,
		ListID:     o.listID,
		Service:    o.service,
		Upstream:   o.upstream,
		Rcode:      rcode,
		Answer:     answer,
		ElapsedMS:  elapsed,
		Cached:     o.cached,
	}
	ev := stats.Event{
		TS:        now,
		Client:    ip,
		Name:      entry.Name,
		Status:    o.status,
		Upstream:  o.upstream,
		ElapsedMS: elapsed,
		Cached:    o.cached,
	}
	if s.deps.Log != nil {
		s.deps.Log.Add(entry)
	}
	if withStats && s.deps.Stats != nil {
		s.deps.Stats.Record(ev)
	}
	if s.onQuery != nil {
		s.onQuery(entry, ev, withStats)
	}
}

// displayName is the configured client name, else the cached reverse-DNS name.
func (s *Server) displayName(st *state, a netip.Addr) string {
	if p, ok := st.clients.match(a); ok && p.name != "" {
		return p.name
	}
	return s.hostname(st, a)
}

// Check runs the pipeline for name/qtype/client up to the filtering decision without asking
// an upstream (own zones and records, filtering, SafeSearch; status "ok" when nothing
// matched).
func (s *Server) Check(name string, qtype uint16, clientIP string) CheckResult {
	n := filter.NormalizeName(strings.TrimSpace(name))
	res := CheckResult{Name: n, Type: typeString(qtype), ClientIP: strings.TrimSpace(clientIP), Status: statusOK}
	client := parseClientIP(clientIP)
	if client.IsValid() {
		res.ClientIP = client.String()
	}
	st := s.state.Load()
	if st == nil {
		return res
	}
	if client.IsValid() {
		res.ClientName = s.displayName(st, client)
	}

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(n), qtype)
	o := s.decide(context.Background(), st, req, client, s.now(), false)
	res.Status, res.Reason, res.Rule = o.status, o.reason, o.rule
	res.ListID, res.Service = o.listID, o.service
	if o.resp != nil {
		res.Answer = summarize(o.resp.Answer)
	}
	return res
}

// ClientName returns the configured client name for ip ("" when none).
func (s *Server) ClientName(ip string) string {
	st := s.state.Load()
	if st == nil {
		return ""
	}
	if p, ok := st.clients.match(parseClientIP(ip)); ok {
		return p.name
	}
	return ""
}

// Records returns the records index in use (nil before Apply or without records).
func (s *Server) Records() *records.Index {
	if st := s.state.Load(); st != nil {
		return st.index
	}
	return nil
}

// Hostname returns the reverse-DNS name of ip ("" when unknown). Own PTR records (explicit
// or synthesized from A/AAAA with ptr) answer first; otherwise it returns the cached name and
// starts a background lookup through the router when it is not cached (cache 1 h, failures
// 10 min).
func (s *Server) Hostname(ip string) string {
	return s.hostname(s.state.Load(), parseClientIP(ip))
}

func (s *Server) hostname(st *state, a netip.Addr) string {
	if st != nil && a.IsValid() {
		if name, ok := localHostname(st.index, a); ok {
			return name
		}
	}
	var resolve func(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	if st != nil && st.router != nil {
		r := st.router
		resolve = func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
			resp, _, err := r.Resolve(ctx, req)
			return resp, err
		}
	}
	return s.hosts.lookup(a, s.now(), resolve)
}

// localHostname answers the reverse lookup of a from the records index. ok is true when the
// index owns the reverse name (a PTR record, or an authoritative zone without one: then
// name is "" and no upstream is asked).
func localHostname(ix *records.Index, a netip.Addr) (name string, ok bool) {
	arpa, err := dns.ReverseAddr(a.String())
	if err != nil {
		return "", false
	}
	res := ix.Resolve(arpa, dns.TypePTR)
	if !res.Found {
		return "", false
	}
	for _, rr := range res.Answer {
		if ptr, isPTR := rr.(*dns.PTR); isPTR {
			if n := strings.TrimSuffix(strings.ToLower(ptr.Ptr), "."); n != "" {
				return n, true
			}
		}
	}
	return "", true
}
