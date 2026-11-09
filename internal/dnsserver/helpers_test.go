package dnsserver

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"pk95dns/internal/cache"
	"pk95dns/internal/config"
	"pk95dns/internal/filter"
	"pk95dns/internal/records"
	"pk95dns/internal/stats"
	"pk95dns/internal/store"
	"pk95dns/internal/upstream"
)

// ---------------------------------------------------------------------------
// Fake response writer

type fakeWriter struct {
	remote net.Addr
	mu     sync.Mutex
	msgs   []*dns.Msg
	sizes  []int // packed sizes
}

func newUDPWriter(ip string) *fakeWriter {
	return &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP(ip), Port: 40000}}
}

func newTCPWriter(ip string) *fakeWriter {
	return &fakeWriter{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}
}

func (w *fakeWriter) LocalAddr() net.Addr  { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (w *fakeWriter) RemoteAddr() net.Addr { return w.remote }
func (w *fakeWriter) WriteMsg(m *dns.Msg) error {
	buf, err := m.Pack()
	if err != nil {
		return err
	}
	// Store what the client would see.
	out := new(dns.Msg)
	if err := out.Unpack(buf); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.msgs = append(w.msgs, out)
	w.sizes = append(w.sizes, len(buf))
	return nil
}
func (w *fakeWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *fakeWriter) Close() error                { return nil }
func (w *fakeWriter) TsigStatus() error           { return nil }
func (w *fakeWriter) TsigTimersOnly(bool)         {}
func (w *fakeWriter) Hijack()                     {}

func (w *fakeWriter) last() (*dns.Msg, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.msgs) == 0 {
		return nil, 0
	}
	return w.msgs[len(w.msgs)-1], w.sizes[len(w.sizes)-1]
}

// ---------------------------------------------------------------------------
// Test upstream server

// testUpstream is a DNS server on 127.0.0.1 (UDP and TCP, same port) with deterministic
// answers:
//
//	servfail.example.        SERVFAIL
//	nx.example.              NXDOMAIN with SOA
//	chain.example.           CNAME mid.example. → CNAME end.example. → A 192.0.2.3
//	cloak.example.           CNAME ads.tracker.example. + A 192.0.2.4
//	cloak-allowed.example.   CNAME x.tracker.example. + A 192.0.2.5
//	secure.example.          A 192.0.2.6, AD when the query had AD or DO
//	big.example.             100 A records
//	mx.example. MX           10 mail.example.
//	1.0.0.127.in-addr.arpa.  PTR myhost.lan.
//	other PTR                NXDOMAIN
//	any other A              192.0.2.1, AAAA 2001:db8::1 (TTL 300), other types NODATA with SOA
type testUpstream struct {
	addr    string
	failAll bool

	mu     sync.Mutex
	counts map[string]int // "name|TYPE"
	last   map[string]*dns.Msg
}

func startUpstream(t *testing.T, failAll bool) *testUpstream {
	t.Helper()
	u := &testUpstream{failAll: failAll, counts: map[string]int{}, last: map[string]*dns.Msg{}}
	// A free UDP port is not necessarily free for TCP (parallel test packages): retry like
	// freePort does.
	var (
		pc   net.PacketConn
		ln   net.Listener
		port int
	)
	for range 20 {
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port = pc.LocalAddr().(*net.UDPAddr).Port
		ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
		pc.Close()
		pc, ln = nil, nil
	}
	if ln == nil {
		t.Fatal("no free port for UDP and TCP")
	}
	u.addr = fmt.Sprintf("127.0.0.1:%d", port)
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: u}, {Listener: ln, Handler: u}} {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { _ = srv.ActivateAndServe() }()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("test upstream did not start")
		}
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return u
}

func (u *testUpstream) count(name string, qtype uint16) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.counts[strings.ToLower(dns.Fqdn(name))+"|"+dns.TypeToString[qtype]]
}

func (u *testUpstream) lastReq(name string, qtype uint16) *dns.Msg {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.last[strings.ToLower(dns.Fqdn(name))+"|"+dns.TypeToString[qtype]]
}

func mustRR(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return r
}

func (u *testUpstream) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	key := name + "|" + dns.TypeToString[q.Qtype]
	u.mu.Lock()
	u.counts[key]++
	u.last[key] = req.Copy()
	u.mu.Unlock()

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	if opt := req.IsEdns0(); opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	}
	soa := mustRR("example. 300 IN SOA ns.example. hostmaster.example. 1 3600 600 86400 120")
	if u.failAll {
		resp.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(resp)
		return
	}
	switch {
	case name == "servfail.example.":
		resp.Rcode = dns.RcodeServerFailure
	case name == "nx.example.":
		resp.Rcode = dns.RcodeNameError
		resp.Ns = []dns.RR{soa}
	case name == "chain.example." && q.Qtype == dns.TypeA:
		resp.Answer = []dns.RR{
			mustRR("chain.example. 300 IN CNAME mid.example."),
			mustRR("mid.example. 300 IN CNAME end.example."),
			mustRR("end.example. 300 IN A 192.0.2.3"),
		}
	case name == "cloak.example." && q.Qtype == dns.TypeA:
		resp.Answer = []dns.RR{
			mustRR("cloak.example. 300 IN CNAME ads.tracker.example."),
			mustRR("ads.tracker.example. 300 IN A 192.0.2.4"),
		}
	case name == "cloak-allowed.example." && q.Qtype == dns.TypeA:
		resp.Answer = []dns.RR{
			mustRR("cloak-allowed.example. 300 IN CNAME x.tracker.example."),
			mustRR("x.tracker.example. 300 IN A 192.0.2.5"),
		}
	case name == "secure.example." && q.Qtype == dns.TypeA:
		// A validating resolver: AD only when the query had AD or DO (RFC 6840 5.7/5.8).
		resp.Answer = []dns.RR{mustRR("secure.example. 300 IN A 192.0.2.6")}
		resp.AuthenticatedData = req.AuthenticatedData || (req.IsEdns0() != nil && req.IsEdns0().Do())
	case name == "big.example." && q.Qtype == dns.TypeA:
		for i := 0; i < 100; i++ {
			resp.Answer = append(resp.Answer, mustRR(fmt.Sprintf("big.example. 300 IN A 10.0.%d.%d", i/250, i%250+1)))
		}
	case name == "mx.example." && q.Qtype == dns.TypeMX:
		resp.Answer = []dns.RR{mustRR("mx.example. 300 IN MX 10 mail.example.")}
	case q.Qtype == dns.TypePTR && name == "1.0.0.127.in-addr.arpa.":
		resp.Answer = []dns.RR{mustRR("1.0.0.127.in-addr.arpa. 300 IN PTR myhost.lan.")}
	case q.Qtype == dns.TypePTR:
		resp.Rcode = dns.RcodeNameError
		resp.Ns = []dns.RR{soa}
	case q.Qtype == dns.TypeA:
		resp.Answer = []dns.RR{mustRR(q.Name + " 300 IN A 192.0.2.1")}
	case q.Qtype == dns.TypeAAAA:
		resp.Answer = []dns.RR{mustRR(q.Name + " 300 IN AAAA 2001:db8::1")}
	case q.Qtype == dns.TypeANY:
		resp.Answer = []dns.RR{mustRR(q.Name + " 300 IN A 192.0.2.1")}
	default:
		resp.Ns = []dns.RR{soa}
	}
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		resp.Truncate(size)
	}
	_ = w.WriteMsg(resp)
}

// ---------------------------------------------------------------------------
// Test environment

const (
	customRules = `||blocked-custom.example^
@@||allowed.example^
@@||cloak-allowed.example^
192.168.1.5 nas.hosts.example
2001:db8::5 nas.hosts.example
`
	listRules = `||ads.example^
||tracker.example^
||allowed.example^
`
	listAllow = `goodads.ads.example
`
)

// longTXT is the value of long.corp.lan TXT: 600 characters (3 strings on the wire).
var longTXT = strings.Repeat("abcdefghij", 60)

// testZones: corp.lan (enabled, TTL 120), the reverse zone 168.192.in-addr.arpa and the
// disabled zone off.lan.
func testZones() []records.Zone {
	return []records.Zone{
		{ID: 1, Name: "corp.lan", TTL: 120, PrimaryNS: "ns.corp.lan", Enabled: true, Serial: 2026110901},
		{ID: 2, Name: "168.192.in-addr.arpa", TTL: 300, PrimaryNS: "ns.corp.lan", Enabled: true, Serial: 2026110901},
		{ID: 3, Name: "off.lan", TTL: 300, PrimaryNS: "ns.off.lan", Enabled: false, Serial: 2026110901},
	}
}

// testRecords are the own records of the test environment: single records below home.lan
// and *.lan (TTL 60, like migrated v1 rewrites) and the records of the test zones.
func testRecords() []records.Record {
	single := func(name, typ, value string) records.Record {
		return records.Record{Name: name, Type: typ, Value: value, TTL: records.RewriteTTL, Enabled: true}
	}
	zoned := func(name, typ, value string) records.Record {
		return records.Record{Name: name, Type: typ, Value: value, TTL: 300, Enabled: true}
	}
	mx := zoned("mail.corp.lan", "MX", "mx.corp.lan")
	mx.Priority = 10
	apexMX := zoned("corp.lan", "MX", "mx.corp.lan")
	apexMX.Priority = 20
	srv := zoned("_ldap._tcp.corp.lan", "SRV", "ldap.corp.lan")
	srv.Weight, srv.Port = 5, 389
	www4 := zoned("www.corp.lan", "A", "10.0.0.80")
	www4.PTR = true
	www6 := zoned("www.corp.lan", "AAAA", "fd00::80")
	www6.PTR = true
	nas5 := zoned("nas5.corp.lan", "A", "192.168.5.5")
	nas5.PTR = true
	host6 := zoned("host6.corp.lan", "A", "192.168.5.6")
	host6.PTR = true
	disabled := zoned("disabled.corp.lan", "A", "10.0.0.66")
	disabled.Enabled = false
	return []records.Record{
		single("nas.home.lan", "A", "192.168.1.10"),
		single("nas.home.lan", "AAAA", "fd00::10"),
		single("v4only.home.lan", "A", "192.168.1.11"),
		single("*.home.lan", "A", "192.168.1.99"),
		single("alias.home.lan", "CNAME", "nas.home.lan"),
		single("ext.home.lan", "CNAME", "target.example"),
		single("extnx.home.lan", "CNAME", "nx.example"),
		single("loop1.lan", "CNAME", "loop2.lan"),
		single("loop2.lan", "CNAME", "loop1.lan"),
		single("blockedtarget.lan", "CNAME", "ads.example"),
		single("failtarget.lan", "CNAME", "servfail.example"),
		single("x.ads.example", "A", "192.168.1.77"),
		single("tozone.lan", "CNAME", "www.corp.lan"),

		zoned("ns.corp.lan", "A", "10.0.0.53"),
		www4, www6, mx, apexMX, srv, nas5, host6, disabled,
		zoned("mx.corp.lan", "A", "10.0.0.25"),
		zoned("ldap.corp.lan", "A", "10.0.0.89"),
		zoned("corp.lan", "TXT", "v=spf1 mx -all"),
		zoned("long.corp.lan", "TXT", longTXT),
		zoned("a.b.corp.lan", "A", "10.0.0.1"),
		zoned("*.dyn.corp.lan", "A", "10.0.0.99"),
		zoned("fixed.dyn.corp.lan", "A", "10.0.0.98"),
		zoned("alias.corp.lan", "CNAME", "www.corp.lan"),
		zoned("out.corp.lan", "CNAME", "target.example"),
		zoned("outnx.corp.lan", "CNAME", "nx.example"),
		zoned("l1.corp.lan", "CNAME", "l2.corp.lan"),
		zoned("l2.corp.lan", "CNAME", "l1.corp.lan"),
		zoned("c1.corp.lan", "CNAME", "c2.corp.lan"),
		zoned("c2.corp.lan", "CNAME", "c3.corp.lan"),
		zoned("c3.corp.lan", "CNAME", "c4.corp.lan"),
		zoned("c4.corp.lan", "CNAME", "c5.corp.lan"),
		zoned("c5.corp.lan", "CNAME", "c6.corp.lan"),
		zoned("c6.corp.lan", "CNAME", "www.corp.lan"),
		zoned("6.5.168.192.in-addr.arpa", "PTR", "explicit.corp.lan"),
		zoned("host.off.lan", "A", "10.9.9.9"),
	}
}

func testEngine(t *testing.T) *filter.Engine {
	t.Helper()
	e := filter.NewEngine()
	custom, _ := filter.Compile([]filter.Source{{ID: 0, Data: []byte(customRules)}})
	lists, _ := filter.Compile([]filter.Source{
		{ID: 1, Data: []byte(listRules)},
		{ID: 2, Allow: true, Data: []byte(listAllow)},
	})
	e.SetCustom(custom)
	e.SetLists(lists)
	return e
}

func baseSettings(upstreams ...string) config.Settings {
	s := config.Defaults()
	s.Upstreams = upstreams
	s.Fallback = []string{}
	s.Bootstrap = []string{}
	s.UpstreamMode = config.ModeSequential
	s.UpstreamTimeoutMS = 2000
	s.PrivatePTR = false
	s.Ratelimit = 0
	return s
}

func newRouter(t *testing.T, s config.Settings) *upstream.Router {
	t.Helper()
	r, err := upstream.NewRouter(upstream.Config{
		Upstreams:        s.Upstreams,
		Fallback:         s.Fallback,
		Bootstrap:        s.Bootstrap,
		Mode:             s.UpstreamMode,
		Timeout:          s.UpstreamTimeout(),
		PrivatePTR:       s.PrivatePTR,
		PrivateUpstreams: s.PrivateUpstreams,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

type logged struct {
	q         store.Query
	ev        stats.Event
	withStats bool
}

type env struct {
	t        *testing.T
	srv      *Server
	up       *testUpstream
	engine   *filter.Engine
	cache    *cache.Cache
	settings config.Settings
	clients  []store.Client
	zones    []records.Zone
	recs     []records.Record

	clock struct {
		sync.Mutex
		now time.Time
	}

	mu   sync.Mutex
	logs []logged
}

func newEnv(t *testing.T, mutate func(*config.Settings)) *env {
	t.Helper()
	e := &env{t: t, up: startUpstream(t, false), engine: testEngine(t), cache: cache.New(1000, 0, 0)}
	e.clock.now = time.Now()
	e.settings = baseSettings(e.up.addr)
	if mutate != nil {
		mutate(&e.settings)
	}
	e.zones, e.recs = testZones(), testRecords()
	e.srv = New(Deps{Filter: e.engine, Cache: e.cache})
	e.srv.routerCloseDelay = time.Millisecond
	e.srv.now = e.now
	e.srv.onQuery = func(q store.Query, ev stats.Event, withStats bool) {
		e.mu.Lock()
		e.logs = append(e.logs, logged{q: q, ev: ev, withStats: withStats})
		e.mu.Unlock()
	}
	t.Cleanup(e.srv.hosts.wg.Wait)
	e.apply()
	return e
}

func (e *env) now() time.Time {
	e.clock.Lock()
	defer e.clock.Unlock()
	return e.clock.now
}

func (e *env) advance(d time.Duration) {
	e.clock.Lock()
	e.clock.now = e.clock.now.Add(d)
	e.clock.Unlock()
}

// apply builds a fresh router from e.settings and applies the runtime.
func (e *env) apply() {
	e.t.Helper()
	e.srv.Apply(Runtime{
		Settings: e.settings,
		Router:   newRouter(e.t, e.settings),
		Records:  records.Compile(e.zones, e.recs),
		Clients:  e.clients,
	})
}

func (e *env) update(mutate func(*config.Settings)) {
	e.t.Helper()
	mutate(&e.settings)
	e.apply()
}

func (e *env) lastLog() (logged, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.logs) == 0 {
		return logged{}, false
	}
	return e.logs[len(e.logs)-1], true
}

func (e *env) logCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.logs)
}

type queryOpt func(req *dns.Msg, w **fakeWriter)

func fromIP(ip string) queryOpt {
	return func(_ *dns.Msg, w **fakeWriter) { *w = newUDPWriter(ip) }
}

func overTCP(ip string) queryOpt {
	return func(_ *dns.Msg, w **fakeWriter) { *w = newTCPWriter(ip) }
}

func withEDNS(size uint16, do bool) queryOpt {
	return func(req *dns.Msg, _ **fakeWriter) { req.SetEdns0(size, do) }
}

// query sends one query through ServeDNS and returns the reply (nil when none) and the
// log entry it produced (zero when none).
func (e *env) query(name string, qtype uint16, opts ...queryOpt) (*dns.Msg, logged) {
	e.t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	req.Id = 4711
	w := newUDPWriter("192.168.1.20")
	for _, o := range opts {
		o(req, &w)
	}
	before := e.logCount()
	e.srv.ServeDNS(w, req)
	resp, _ := w.last()
	var l logged
	if e.logCount() > before {
		l, _ = e.lastLog()
	}
	if resp != nil && resp.Id != req.Id {
		e.t.Errorf("%s: reply id %d, want %d", name, resp.Id, req.Id)
	}
	return resp, l
}

// answers renders the answer section as "TYPE data" strings without TTLs.
func answers(m *dns.Msg) []string {
	if m == nil {
		return nil
	}
	var out []string
	for _, r := range m.Answer {
		h := r.Header()
		out = append(out, dns.TypeToString[h.Rrtype]+" "+strings.TrimSpace(strings.TrimPrefix(r.String(), h.String())))
	}
	return out
}

func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		pc.Close()
		if err != nil {
			continue
		}
		ln.Close()
		return port
	}
	t.Fatal("no free port")
	return 0
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
