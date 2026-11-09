package dnsserver

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
	"pk95dns/internal/filter"
	"pk95dns/internal/store"
)

func TestServeBeforeApplyIsServfail(t *testing.T) {
	srv := New(Deps{})
	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	w := newUDPWriter("192.168.1.20")
	srv.ServeDNS(w, req)
	resp, _ := w.last()
	if resp == nil || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("want SERVFAIL, got %v", resp)
	}
}

func TestMalformedRequests(t *testing.T) {
	e := newEnv(t, nil)
	tests := []struct {
		name  string
		build func() *dns.Msg
		rcode int
	}{
		{"no question", func() *dns.Msg { m := new(dns.Msg); m.Id = 1; return m }, dns.RcodeFormatError},
		{"two questions", func() *dns.Msg {
			m := new(dns.Msg)
			m.SetQuestion("a.example.", dns.TypeA)
			m.Question = append(m.Question, dns.Question{Name: "b.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
			return m
		}, dns.RcodeFormatError},
		{"notify opcode", func() *dns.Msg {
			m := new(dns.Msg)
			m.SetNotify("example.")
			return m
		}, dns.RcodeNotImplemented},
		// RFC 6891 6.1.3: EDNS versions above 0 get BADVERS with an OPT of version 0.
		{"EDNS version 1", func() *dns.Msg {
			m := new(dns.Msg)
			m.SetQuestion("edns1.example.", dns.TypeA)
			m.SetEdns0(1232, false)
			m.IsEdns0().SetVersion(1)
			return m
		}, dns.RcodeBadVers},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newUDPWriter("192.168.1.20")
			e.srv.ServeDNS(w, tt.build())
			resp, _ := w.last()
			if resp == nil || resp.Rcode != tt.rcode {
				t.Fatalf("rcode: got %v, want %s", resp, dns.RcodeToString[tt.rcode])
			}
			if tt.rcode == dns.RcodeBadVers {
				if opt := resp.IsEdns0(); opt == nil || opt.Version() != 0 || len(resp.Answer) != 0 {
					t.Fatalf("BADVERS reply: %v", resp)
				}
			}
		})
	}
	if n := e.up.count("edns1.example", dns.TypeA); n != 0 {
		t.Fatalf("EDNS version 1 query forwarded %d times", n)
	}
	// A response is ignored.
	w := newUDPWriter("192.168.1.20")
	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeA)
	m.Response = true
	e.srv.ServeDNS(w, m)
	if resp, _ := w.last(); resp != nil {
		t.Fatal("answered a response")
	}
}

func TestForwardOK(t *testing.T) {
	e := newEnv(t, nil)
	resp, l := e.query("WWW.Example.COM", dns.TypeA)
	if resp == nil {
		t.Fatal("no reply")
	}
	if resp.Rcode != dns.RcodeSuccess || !resp.RecursionAvailable || !resp.RecursionDesired || resp.Authoritative {
		t.Fatalf("flags/rcode wrong: %v", resp)
	}
	if resp.Question[0].Name != "WWW.Example.COM." {
		t.Fatalf("question not kept: %v", resp.Question[0])
	}
	if got := answers(resp); !slices.Equal(got, []string{"A 192.0.2.1"}) {
		t.Fatalf("answer %v", got)
	}
	q := l.q
	if q.Status != "ok" || q.Reason != "" || q.Name != "www.example.com" || q.QType != "A" ||
		q.Upstream != e.up.addr || q.Rcode != "NOERROR" || q.Answer != "192.0.2.1" || q.Cached ||
		q.ClientIP != "192.168.1.20" {
		t.Fatalf("log entry %+v", q)
	}
	if !l.withStats || l.ev.Status != "ok" || l.ev.Upstream != e.up.addr || l.ev.Client != "192.168.1.20" || l.ev.Name != "www.example.com" {
		t.Fatalf("stats event %+v", l.ev)
	}
	if q.ElapsedMS < 0 || q.TS == 0 {
		t.Fatalf("timing %+v", q)
	}
}

func TestUpstreamRequest(t *testing.T) {
	e := newEnv(t, nil)
	tests := []struct {
		name   string
		dnssec bool
		opts   []queryOpt
		wantDO bool
	}{
		{"plain", false, nil, false},
		{"client DO", false, []queryOpt{withEDNS(4096, true)}, true},
		{"dnssec setting", true, nil, true},
		{"client EDNS without DO", false, []queryOpt{withEDNS(4096, false)}, false},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e.update(func(s *config.Settings) { s.DNSSEC = tt.dnssec; s.CacheEnabled = false })
			name := "up" + string(rune('a'+i)) + ".example"
			e.query(name, dns.TypeA, tt.opts...)
			up := e.up.lastReq(name, dns.TypeA)
			if up == nil {
				t.Fatal("upstream not asked")
			}
			opt := up.IsEdns0()
			if opt == nil || opt.UDPSize() != 1232 {
				t.Fatalf("upstream OPT %v", opt)
			}
			if opt.Do() != tt.wantDO {
				t.Fatalf("DO %v, want %v", opt.Do(), tt.wantDO)
			}
			if !up.RecursionDesired {
				t.Fatal("RD not set")
			}
		})
	}

	// ECS of the client is not passed on and the id is fresh.
	e.update(func(s *config.Settings) { s.CacheEnabled = false })
	req := new(dns.Msg)
	req.SetQuestion("ecs.example.", dns.TypeA)
	req.Id = 4711
	req.RecursionDesired = false
	req.SetEdns0(4096, false)
	opt := req.IsEdns0()
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: []byte{192, 168, 1, 0}})
	sawFresh := false
	for i := 0; i < 3 && !sawFresh; i++ {
		e.srv.ServeDNS(newUDPWriter("192.168.1.20"), req)
		up := e.up.lastReq("ecs.example", dns.TypeA)
		if up == nil {
			t.Fatal("upstream not asked")
		}
		if len(up.IsEdns0().Option) != 0 {
			t.Fatalf("client EDNS options forwarded: %v", up.IsEdns0().Option)
		}
		if !up.RecursionDesired {
			t.Fatal("RD must be set towards upstreams")
		}
		sawFresh = up.Id != req.Id
	}
	if !sawFresh {
		t.Fatal("upstream id equals the client id")
	}
	// RD of the client is kept in the answer.
	w := newUDPWriter("192.168.1.20")
	e.srv.ServeDNS(w, req)
	if resp, _ := w.last(); resp == nil || resp.RecursionDesired {
		t.Fatalf("RD not kept: %v", resp)
	}
}

// AD is asked for upstream, so validating upstreams report it to clients that set AD
// without DO (RFC 6840 5.7, e.g. glibc trust-ad); clients that asked for neither do not get it.
func TestAuthenticatedData(t *testing.T) {
	e := newEnv(t, nil) // dnssec off (default), cache on
	ad := func(req *dns.Msg, _ **fakeWriter) { req.AuthenticatedData = true }
	for i := range 2 { // second round comes from the cache
		resp, _ := e.query("secure.example", dns.TypeA, ad)
		if resp == nil || !resp.AuthenticatedData {
			t.Fatalf("round %d: AD client did not get AD: %v", i, resp)
		}
		resp, _ = e.query("secure.example", dns.TypeA)
		if resp == nil || resp.AuthenticatedData {
			t.Fatalf("round %d: AD set for a client that did not ask: %v", i, resp)
		}
	}
	if up := e.up.lastReq("secure.example", dns.TypeA); up == nil || !up.AuthenticatedData {
		t.Fatalf("AD not set towards the upstream: %v", up)
	}
}

func TestEDNSEcho(t *testing.T) {
	e := newEnv(t, nil)
	tests := []struct {
		name     string
		opts     []queryOpt
		wantOPT  bool
		wantSize uint16
		wantDO   bool
	}{
		{"no OPT", nil, false, 0, false},
		{"4096", []queryOpt{withEDNS(4096, false)}, true, 1232, false},
		{"4096 DO", []queryOpt{withEDNS(4096, true)}, true, 1232, true},
		{"1000", []queryOpt{withEDNS(1000, false)}, true, 1000, false},
		{"300 floors to 512", []queryOpt{withEDNS(300, false)}, true, 512, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, name := range []string{"edns.example", "ads.example", "nas.home.lan"} {
				resp, _ := e.query(name, dns.TypeA, tt.opts...)
				opt := resp.IsEdns0()
				if (opt != nil) != tt.wantOPT {
					t.Fatalf("%s: OPT present %v, want %v", name, opt != nil, tt.wantOPT)
				}
				if opt == nil {
					continue
				}
				if opt.UDPSize() != tt.wantSize || opt.Do() != tt.wantDO {
					t.Fatalf("%s: OPT size %d do %v", name, opt.UDPSize(), opt.Do())
				}
				if len(opt.Option) != 0 {
					t.Fatalf("%s: options echoed: %v", name, opt.Option)
				}
			}
		})
	}
}

func TestTruncation(t *testing.T) {
	e := newEnv(t, nil)
	tests := []struct {
		name    string
		opts    []queryOpt
		wantTC  bool
		maxSize int
		wantAll bool
	}{
		{"udp no OPT", nil, true, 512, false},
		{"udp 1232", []queryOpt{withEDNS(1232, false)}, true, 1232, false},
		{"udp 4096", []queryOpt{withEDNS(4096, false)}, false, 4096, true},
		{"tcp", []queryOpt{overTCP("192.168.1.20")}, false, 65535, true},
		{"tcp with small OPT", []queryOpt{overTCP("192.168.1.20"), withEDNS(512, false)}, false, 65535, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion("big.example.", dns.TypeA)
			w := newUDPWriter("192.168.1.20")
			for _, o := range tt.opts {
				o(req, &w)
			}
			e.srv.ServeDNS(w, req)
			resp, size := w.last()
			if resp == nil {
				t.Fatal("no reply")
			}
			if resp.Truncated != tt.wantTC {
				t.Fatalf("TC %v, want %v", resp.Truncated, tt.wantTC)
			}
			if size > tt.maxSize {
				t.Fatalf("size %d > %d", size, tt.maxSize)
			}
			if tt.wantAll && len(resp.Answer) != 100 {
				t.Fatalf("answers %d, want 100", len(resp.Answer))
			}
			if !tt.wantAll && len(resp.Answer) >= 100 {
				t.Fatalf("answers not truncated: %d", len(resp.Answer))
			}
		})
	}
}

func TestAccess(t *testing.T) {
	tests := []struct {
		name       string
		allowed    []string
		disallowed []string
		ip         string
		refused    bool
	}{
		{"private allowed", config.PrivateNets, nil, "192.168.1.20", false},
		{"public refused", config.PrivateNets, nil, "8.8.8.8", true},
		{"mapped v4 allowed", config.PrivateNets, nil, "::ffff:192.168.1.20", false},
		{"ipv6 ula allowed", config.PrivateNets, nil, "fd00::1", false},
		{"ipv6 public refused", config.PrivateNets, nil, "2001:db8::7", true},
		{"empty allowed = open", []string{}, nil, "8.8.8.8", false},
		{"disallowed single ip", config.PrivateNets, []string{"192.168.1.20"}, "192.168.1.20", true},
		{"disallowed cidr", []string{}, []string{"10.0.0.0/8"}, "10.1.2.3", true},
		{"disallowed beats allowed", []string{"192.168.1.20"}, []string{"192.168.0.0/16"}, "192.168.1.20", true},
		{"allowed single ip", []string{"192.168.1.20"}, nil, "192.168.1.20", false},
		{"allowed single ip other", []string{"192.168.1.20"}, nil, "192.168.1.21", true},
		{"invalid entries ignored", []string{"nonsense", "192.168.1.0/24"}, nil, "192.168.1.9", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, func(s *config.Settings) {
				s.AllowedClients = tt.allowed
				s.DisallowedClients = tt.disallowed
			})
			resp, l := e.query("access.example", dns.TypeA, fromIP(tt.ip))
			if tt.refused {
				if resp.Rcode != dns.RcodeRefused || l.q.Status != "refused" || l.q.Reason != "access" || l.q.Rcode != "REFUSED" {
					t.Fatalf("want refused/access, got %s %+v", dns.RcodeToString[resp.Rcode], l.q)
				}
				if e.up.count("access.example", dns.TypeA) != 0 {
					t.Fatal("refused query reached the upstream")
				}
				return
			}
			if resp.Rcode != dns.RcodeSuccess || l.q.Status != "ok" {
				t.Fatalf("want ok, got %s %+v", dns.RcodeToString[resp.Rcode], l.q)
			}
		})
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.Ratelimit = 3 })
	for i := 0; i < 3; i++ {
		if resp, _ := e.query("rl.example", dns.TypeA); resp == nil {
			t.Fatalf("query %d dropped", i)
		}
	}
	resp, l := e.query("rl.example", dns.TypeA)
	if resp != nil {
		t.Fatal("4th query answered")
	}
	if l.q.Status != "refused" || l.q.Reason != "ratelimit" || l.withStats {
		t.Fatalf("drop log %+v stats %v", l.q, l.withStats)
	}
	before := e.logCount()
	if resp, _ := e.query("rl.example", dns.TypeA); resp != nil {
		t.Fatal("5th query answered")
	}
	if e.logCount() != before {
		t.Fatal("second drop within a second logged")
	}
	// Another client has its own bucket.
	if resp, _ := e.query("rl.example", dns.TypeA, fromIP("192.168.1.21")); resp == nil {
		t.Fatal("other client limited")
	}
	// Tokens refill over time; a later drop is logged again.
	e.advance(time.Second)
	for i := 0; i < 3; i++ {
		if resp, _ := e.query("rl.example", dns.TypeA); resp == nil {
			t.Fatalf("after refill query %d dropped", i)
		}
	}
	before = e.logCount()
	if resp, _ := e.query("rl.example", dns.TypeA); resp != nil {
		t.Fatal("over limit after refill answered")
	}
	if e.logCount() != before+1 {
		t.Fatal("drop after a second not logged")
	}
	// Changing the limit clears the state.
	if e.srv.limiter.size() == 0 {
		t.Fatal("limiter empty")
	}
	e.update(func(s *config.Settings) { s.Ratelimit = 5 })
	if n := e.srv.limiter.size(); n != 0 {
		t.Fatalf("limiter has %d entries after change", n)
	}
	// Same limit keeps the state.
	e.query("rl.example", dns.TypeA)
	e.update(func(s *config.Settings) { s.BlockedTTL = 11 })
	if e.srv.limiter.size() != 1 {
		t.Fatal("state cleared without limit change")
	}
	// Off.
	e.update(func(s *config.Settings) { s.Ratelimit = 0 })
	for i := 0; i < 20; i++ {
		if resp, _ := e.query("rl.example", dns.TypeA); resp == nil {
			t.Fatal("dropped with limit off")
		}
	}
}

func TestRateLimiterUnit(t *testing.T) {
	l := newRateLimiter()
	l.setRate(2)
	now := time.Unix(1000, 0)
	a := parseClientIP("10.0.0.1")
	steps := []struct {
		dt      time.Duration
		ok, log bool
	}{
		{0, true, false},
		{0, true, false},
		{0, false, true},
		{100 * time.Millisecond, false, false}, // 0.2 tokens
		{400 * time.Millisecond, true, false},  // 1.0 token
		{0, false, false},                      // logged 0.5 s ago
		{600 * time.Millisecond, true, false},  // 1.2 tokens
		{0, false, true},                       // last log 1.1 s ago
	}
	for i, s := range steps {
		now = now.Add(s.dt)
		ok, logIt := l.allow(a, now)
		if ok != s.ok || logIt != s.log {
			t.Fatalf("step %d: got ok=%v log=%v, want ok=%v log=%v", i, ok, logIt, s.ok, s.log)
		}
	}
	// Idle entries are cleaned.
	now = now.Add(time.Minute)
	l.allow(parseClientIP("10.0.0.2"), now)
	if n := l.size(); n != 1 {
		t.Fatalf("entries after clean: %d", n)
	}
	// rate 0 allows everything.
	l.setRate(0)
	for i := 0; i < 10; i++ {
		if ok, _ := l.allow(a, now); !ok {
			t.Fatal("rate 0 limited")
		}
	}
}

func TestAnyQueries(t *testing.T) {
	e := newEnv(t, nil)
	resp, l := e.query("any.example", dns.TypeANY)
	if resp.Rcode != dns.RcodeNotImplemented || l.q.Status != "refused" || l.q.Reason != "any" || l.q.QType != "ANY" {
		t.Fatalf("ANY: %s %+v", dns.RcodeToString[resp.Rcode], l.q)
	}
	e.update(func(s *config.Settings) { s.RefuseAny = false })
	resp, l = e.query("any.example", dns.TypeANY)
	if resp.Rcode != dns.RcodeSuccess || l.q.Status != "ok" || e.up.count("any.example", dns.TypeANY) != 1 {
		t.Fatalf("ANY forwarded: %s %+v", dns.RcodeToString[resp.Rcode], l.q)
	}
}

func TestBlockingModes(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		v4, v6  string
		qtype   uint16
		rcode   int
		answer  []string
		soa     bool
		summary string
	}{
		{"null_ip A", config.BlockNullIP, "", "", dns.TypeA, dns.RcodeSuccess, []string{"A 0.0.0.0"}, false, "0.0.0.0"},
		{"null_ip AAAA", config.BlockNullIP, "", "", dns.TypeAAAA, dns.RcodeSuccess, []string{"AAAA ::"}, false, "::"},
		{"null_ip MX", config.BlockNullIP, "", "", dns.TypeMX, dns.RcodeSuccess, nil, false, ""},
		{"empty mode is null_ip", "", "", "", dns.TypeA, dns.RcodeSuccess, []string{"A 0.0.0.0"}, false, "0.0.0.0"},
		{"nxdomain A", config.BlockNXDomain, "", "", dns.TypeA, dns.RcodeNameError, nil, true, ""},
		{"nxdomain HTTPS", config.BlockNXDomain, "", "", dns.TypeHTTPS, dns.RcodeNameError, nil, true, ""},
		{"refused", config.BlockRefused, "", "", dns.TypeA, dns.RcodeRefused, nil, false, ""},
		{"custom v4", config.BlockCustomIP, "10.9.9.9", "", dns.TypeA, dns.RcodeSuccess, []string{"A 10.9.9.9"}, false, "10.9.9.9"},
		{"custom v4 AAAA empty", config.BlockCustomIP, "10.9.9.9", "", dns.TypeAAAA, dns.RcodeSuccess, nil, false, ""},
		{"custom both AAAA", config.BlockCustomIP, "10.9.9.9", "fd00::9", dns.TypeAAAA, dns.RcodeSuccess, []string{"AAAA fd00::9"}, false, "fd00::9"},
		{"custom TXT empty", config.BlockCustomIP, "10.9.9.9", "fd00::9", dns.TypeTXT, dns.RcodeSuccess, nil, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, func(s *config.Settings) {
				s.BlockingMode = tt.mode
				s.BlockingIPv4 = tt.v4
				s.BlockingIPv6 = tt.v6
				s.BlockedTTL = 42
			})
			resp, l := e.query("ads.example", tt.qtype)
			if resp.Rcode != tt.rcode {
				t.Fatalf("rcode %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.rcode])
			}
			if got := answers(resp); !slices.Equal(got, tt.answer) {
				t.Fatalf("answer %v, want %v", got, tt.answer)
			}
			for _, r := range resp.Answer {
				if r.Header().Ttl != 42 {
					t.Fatalf("TTL %d", r.Header().Ttl)
				}
			}
			if tt.soa {
				if len(resp.Ns) != 1 {
					t.Fatalf("authority %v", resp.Ns)
				}
				soa, ok := resp.Ns[0].(*dns.SOA)
				if !ok || soa.Ns != "fake-for-negative-caching.pk95dns." || soa.Hdr.Ttl != 42 || soa.Minttl != 42 || soa.Hdr.Name != "ads.example." {
					t.Fatalf("SOA %v", resp.Ns[0])
				}
			} else if len(resp.Ns) != 0 {
				t.Fatalf("unexpected authority %v", resp.Ns)
			}
			if resp.Authoritative || !resp.RecursionAvailable || !resp.RecursionDesired {
				t.Fatal("flags")
			}
			if l.q.Status != "blocked" || l.q.Reason != "list" || l.q.Rule != "||ads.example^" || l.q.ListID != 1 || l.q.Answer != tt.summary {
				t.Fatalf("log %+v", l.q)
			}
			if e.up.count("ads.example", tt.qtype) != 0 {
				t.Fatal("blocked query reached the upstream")
			}
		})
	}
}

func TestFilterStatuses(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.BlockedServices = []string{"tiktok"} })
	tests := []struct {
		name    string
		qname   string
		qtype   uint16
		status  string
		reason  string
		rule    string
		listID  int64
		service string
		answer  []string
		forward bool
	}{
		{"custom block", "x.blocked-custom.example", dns.TypeA, "blocked", "custom", "||blocked-custom.example^", 0, "", []string{"A 0.0.0.0"}, false},
		{"list block", "sub.ads.example", dns.TypeA, "blocked", "list", "||ads.example^", 1, "", []string{"A 0.0.0.0"}, false},
		{"service", "www.tiktok.com", dns.TypeA, "blocked_service", "service", "||tiktok.com^", 0, "tiktok", []string{"A 0.0.0.0"}, false},
		{"custom allow beats list", "allowed.example", dns.TypeA, "allowed", "custom", "@@||allowed.example^", 0, "", []string{"A 192.0.2.1"}, true},
		{"allow list beats block list", "goodads.ads.example", dns.TypeA, "allowed", "list", "goodads.ads.example", 2, "", []string{"A 192.0.2.1"}, true},
		{"hosts rewrite A", "nas.hosts.example", dns.TypeA, "rewrite", "custom", "192.168.1.5 nas.hosts.example", 0, "", []string{"A 192.168.1.5"}, false},
		{"hosts rewrite AAAA", "nas.hosts.example", dns.TypeAAAA, "rewrite", "custom", "", 0, "", []string{"AAAA 2001:db8::5"}, false},
		{"hosts rewrite MX", "nas.hosts.example", dns.TypeMX, "rewrite", "custom", "", 0, "", nil, false},
		{"nothing", "plain.example", dns.TypeA, "ok", "", "", 0, "", []string{"A 192.0.2.1"}, true},
		{"nxdomain forwarded", "nx.example", dns.TypeA, "ok", "", "", 0, "", nil, true},
		{"mx forwarded", "mx.example", dns.TypeMX, "ok", "", "", 0, "", []string{"MX 10 mail.example."}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, l := e.query(tt.qname, tt.qtype)
			if got := answers(resp); !slices.Equal(got, tt.answer) {
				t.Fatalf("answer %v, want %v", got, tt.answer)
			}
			q := l.q
			if q.Status != tt.status || q.Reason != tt.reason || q.ListID != tt.listID || q.Service != tt.service {
				t.Fatalf("log %+v", q)
			}
			if tt.rule != "" && q.Rule != tt.rule {
				t.Fatalf("rule %q, want %q", q.Rule, tt.rule)
			}
			if forwarded := e.up.count(tt.qname, tt.qtype) > 0; forwarded != tt.forward {
				t.Fatalf("forwarded %v, want %v", forwarded, tt.forward)
			}
			if tt.forward && q.Upstream != e.up.addr && !q.Cached {
				t.Fatalf("upstream %q", q.Upstream)
			}
			if !tt.forward && q.Upstream != "" {
				t.Fatalf("upstream %q for a local answer", q.Upstream)
			}
		})
	}
	// TTL of hosts rewrites is blocked_ttl.
	resp, _ := e.query("nas.hosts.example", dns.TypeA)
	if resp.Answer[0].Header().Ttl != e.settings.BlockedTTL {
		t.Fatalf("hosts TTL %d", resp.Answer[0].Header().Ttl)
	}
	// NXDOMAIN rcode string.
	_, l := e.query("nx.example", dns.TypeA)
	if l.q.Rcode != "NXDOMAIN" {
		t.Fatalf("rcode %q", l.q.Rcode)
	}
}

func TestLocalRecords(t *testing.T) {
	tests := []struct {
		name    string
		qname   string
		qtype   uint16
		rcode   int
		answer  []string
		summary string
		asked   []string // names the upstream must have been asked (type qtype)
		notAsk  []string
	}{
		{"exact A", "nas.home.lan", dns.TypeA, 0, []string{"A 192.168.1.10"}, "192.168.1.10", nil, []string{"nas.home.lan"}},
		{"exact AAAA", "nas.home.lan", dns.TypeAAAA, 0, []string{"AAAA fd00::10"}, "fd00::10", nil, nil},
		{"case insensitive", "NAS.Home.LAN", dns.TypeA, 0, []string{"A 192.168.1.10"}, "192.168.1.10", nil, nil},
		{"other family empty", "v4only.home.lan", dns.TypeAAAA, 0, nil, "", nil, []string{"v4only.home.lan"}},
		{"other type empty", "nas.home.lan", dns.TypeMX, 0, nil, "", nil, []string{"nas.home.lan"}},
		{"wildcard", "printer.home.lan", dns.TypeA, 0, []string{"A 192.168.1.99"}, "192.168.1.99", nil, nil},
		{"wildcard deep", "a.b.home.lan", dns.TypeA, 0, []string{"A 192.168.1.99"}, "192.168.1.99", nil, nil},
		{"cname to local", "alias.home.lan", dns.TypeA, 0, []string{"CNAME nas.home.lan.", "A 192.168.1.10"}, "CNAME nas.home.lan, 192.168.1.10", nil, []string{"nas.home.lan"}},
		{"cname to upstream", "ext.home.lan", dns.TypeA, 0, []string{"CNAME target.example.", "A 192.0.2.1"}, "CNAME target.example, 192.0.2.1", []string{"target.example"}, nil},
		{"cname to upstream nxdomain", "extnx.home.lan", dns.TypeA, dns.RcodeNameError, []string{"CNAME nx.example."}, "CNAME nx.example", []string{"nx.example"}, nil},
		{"cname qtype CNAME", "ext.home.lan", dns.TypeCNAME, 0, []string{"CNAME target.example."}, "CNAME target.example", nil, []string{"target.example"}},
		{"cname target not filtered", "blockedtarget.lan", dns.TypeA, 0, []string{"CNAME ads.example.", "A 192.0.2.1"}, "CNAME ads.example, 192.0.2.1", []string{"ads.example"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, nil)
			resp, l := e.query(tt.qname, tt.qtype)
			if resp.Rcode != tt.rcode {
				t.Fatalf("rcode %s", dns.RcodeToString[resp.Rcode])
			}
			if got := answers(resp); !slices.Equal(got, tt.answer) {
				t.Fatalf("answer %v, want %v", got, tt.answer)
			}
			if l.q.Status != "rewrite" || l.q.Reason != "rewrite" || l.q.Answer != tt.summary {
				t.Fatalf("log %+v", l.q)
			}
			for _, r := range resp.Answer {
				if strings.HasSuffix(r.Header().Name, "home.lan.") && r.Header().Ttl != localTTL {
					t.Fatalf("local TTL %d", r.Header().Ttl)
				}
			}
			for _, n := range tt.asked {
				if e.up.count(n, tt.qtype) == 0 {
					t.Fatalf("upstream not asked for %s", n)
				}
			}
			for _, n := range tt.notAsk {
				for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX} {
					if e.up.count(n, qt) != 0 {
						t.Fatalf("upstream asked for %s", n)
					}
				}
			}
		})
	}

	t.Run("not the wildcard domain itself", func(t *testing.T) {
		e := newEnv(t, nil)
		_, l := e.query("home.lan", dns.TypeA)
		if l.q.Status != "ok" {
			t.Fatalf("home.lan: %+v", l.q)
		}
	})
	t.Run("loop terminates", func(t *testing.T) {
		e := newEnv(t, nil)
		resp, l := e.query("loop1.lan", dns.TypeA)
		if resp == nil || resp.Rcode != dns.RcodeSuccess || l.q.Status != "rewrite" {
			t.Fatalf("loop: %v %+v", resp, l.q)
		}
		if n := len(resp.Answer); n != maxCNAMEDepth+1 {
			t.Fatalf("CNAMEs in loop answer: %d", n)
		}
	})
	t.Run("upstream failure of target", func(t *testing.T) {
		e := newEnv(t, nil)
		resp, l := e.query("failtarget.lan", dns.TypeA)
		if resp.Rcode != dns.RcodeServerFailure || l.q.Status != "error" || l.q.Reason != "upstream" {
			t.Fatalf("got %s %+v", dns.RcodeToString[resp.Rcode], l.q)
		}
	})
	t.Run("active when protection is off", func(t *testing.T) {
		e := newEnv(t, func(s *config.Settings) { s.ProtectionEnabled = false })
		resp, l := e.query("nas.home.lan", dns.TypeA)
		if got := answers(resp); !slices.Equal(got, []string{"A 192.168.1.10"}) || l.q.Status != "rewrite" {
			t.Fatalf("got %v %+v", got, l.q)
		}
	})
	t.Run("local AAAA with disable_ipv6", func(t *testing.T) {
		e := newEnv(t, func(s *config.Settings) { s.DisableIPv6 = true })
		resp, _ := e.query("nas.home.lan", dns.TypeAAAA)
		if got := answers(resp); !slices.Equal(got, []string{"AAAA fd00::10"}) {
			t.Fatalf("got %v", got)
		}
	})
	t.Run("local records beat filtering", func(t *testing.T) {
		e := newEnv(t, nil)
		e.rewrites = filter.NewRewrites([]filter.RewriteEntry{{Domain: "ads.example", Answer: "192.168.1.77"}})
		e.apply()
		resp, l := e.query("ads.example", dns.TypeA)
		if got := answers(resp); !slices.Equal(got, []string{"A 192.168.1.77"}) || l.q.Status != "rewrite" {
			t.Fatalf("got %v %+v", got, l.q)
		}
	})
}

func TestSafeSearch(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.SafeSearch.Enabled = true; s.BlockedTTL = 33 })
	resp, l := e.query("www.bing.com", dns.TypeA)
	if got := answers(resp); !slices.Equal(got, []string{"CNAME strict.bing.com.", "A 192.0.2.1"}) {
		t.Fatalf("answer %v", got)
	}
	if l.q.Status != "safesearch" || l.q.Reason != "safesearch" || l.q.Answer != "CNAME strict.bing.com, 192.0.2.1" || l.q.Upstream != e.up.addr {
		t.Fatalf("log %+v", l.q)
	}
	if resp.Answer[0].Header().Ttl != 33 {
		t.Fatalf("CNAME TTL %d", resp.Answer[0].Header().Ttl)
	}
	if e.up.count("www.bing.com", dns.TypeA) != 0 || e.up.count("strict.bing.com", dns.TypeA) != 1 {
		t.Fatal("upstream must be asked for the safe host only")
	}
	// AAAA too.
	resp, _ = e.query("www.bing.com", dns.TypeAAAA)
	if got := answers(resp); !slices.Equal(got, []string{"CNAME strict.bing.com.", "AAAA 2001:db8::1"}) {
		t.Fatalf("AAAA answer %v", got)
	}
	// Second query for the target comes from the cache.
	_, l = e.query("www.bing.com", dns.TypeA)
	if !l.q.Cached || e.up.count("strict.bing.com", dns.TypeA) != 1 {
		t.Fatalf("target not cached: %+v", l.q)
	}
	// Engine switched off → normal forwarding.
	e.update(func(s *config.Settings) { s.SafeSearch.Bing = false })
	_, l = e.query("www.bing.com", dns.TypeA)
	if l.q.Status != "ok" {
		t.Fatalf("bing off: %+v", l.q)
	}
	// Disabled globally.
	e.update(func(s *config.Settings) { s.SafeSearch.Enabled = false; s.SafeSearch.Bing = true })
	_, l = e.query("duckduckgo.com", dns.TypeA)
	if l.q.Status != "ok" {
		t.Fatalf("safesearch off: %+v", l.q)
	}
	// Upstream failure for the target.
	e2 := newEnv(t, func(s *config.Settings) { s.SafeSearch.Enabled = true })
	failing := startUpstream(t, true)
	e2.update(func(s *config.Settings) { s.Upstreams = []string{failing.addr} })
	resp, l = e2.query("www.bing.com", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure || l.q.Status != "error" || l.q.Reason != "upstream" {
		t.Fatalf("failure: %s %+v", dns.RcodeToString[resp.Rcode], l.q)
	}
}

func TestDisableIPv6(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.DisableIPv6 = true })
	resp, l := e.query("v6.example", dns.TypeAAAA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || l.q.Status != "ok" || l.q.Upstream != "" {
		t.Fatalf("got %v %+v", resp, l.q)
	}
	if e.up.count("v6.example", dns.TypeAAAA) != 0 {
		t.Fatal("AAAA forwarded")
	}
	// Blocking still comes first.
	_, l = e.query("ads.example", dns.TypeAAAA)
	if l.q.Status != "blocked" {
		t.Fatalf("blocked AAAA: %+v", l.q)
	}
	// A is unaffected.
	resp, _ = e.query("v6.example", dns.TypeA)
	if len(resp.Answer) != 1 {
		t.Fatal("A affected")
	}
	// CNAME target of a local record.
	resp, _ = e.query("ext.home.lan", dns.TypeAAAA)
	if got := answers(resp); !slices.Equal(got, []string{"CNAME target.example."}) {
		t.Fatalf("local CNAME AAAA %v", got)
	}
}

func TestCNAMECloaking(t *testing.T) {
	e := newEnv(t, nil)
	resp, l := e.query("cloak.example", dns.TypeA)
	if got := answers(resp); !slices.Equal(got, []string{"A 0.0.0.0"}) {
		t.Fatalf("answer %v", got)
	}
	if resp.Question[0].Name != "cloak.example." || resp.Answer[0].Header().Name != "cloak.example." {
		t.Fatal("blocked answer must be for the original question")
	}
	if l.q.Status != "blocked" || l.q.Reason != "list" || l.q.Rule != "||tracker.example^" || l.q.ListID != 1 || l.q.Upstream != e.up.addr {
		t.Fatalf("log %+v", l.q)
	}
	// From the cache it is checked as well.
	resp, l = e.query("cloak.example", dns.TypeA)
	if l.q.Status != "blocked" || !l.q.Cached || answers(resp)[0] != "A 0.0.0.0" {
		t.Fatalf("cached cloak: %+v", l.q)
	}
	if e.up.count("cloak.example", dns.TypeA) != 1 {
		t.Fatal("cache not used")
	}
	// An allow rule for the queried name skips the check.
	resp, l = e.query("cloak-allowed.example", dns.TypeA)
	if l.q.Status != "allowed" || len(resp.Answer) != 2 {
		t.Fatalf("allowed cloak: %v %+v", answers(resp), l.q)
	}
	// Protection off: no check.
	e.update(func(s *config.Settings) { s.ProtectionEnabled = false })
	_, l = e.query("cloak.example", dns.TypeA)
	if l.q.Status != "ok" {
		t.Fatalf("protection off: %+v", l.q)
	}
	// Chains are passed through with all CNAMEs.
	resp, l = e.query("chain.example", dns.TypeA)
	if l.q.Answer != "CNAME mid.example, CNAME end.example, 192.0.2.3" || len(resp.Answer) != 3 {
		t.Fatalf("chain %+v", l.q)
	}
}

func TestCache(t *testing.T) {
	e := newEnv(t, nil)
	_, l1 := e.query("cached.example", dns.TypeA)
	resp, l2 := e.query("cached.example", dns.TypeA)
	if l1.q.Cached || !l2.q.Cached || l2.q.Upstream != "" || l2.q.Status != "ok" {
		t.Fatalf("first %+v second %+v", l1.q, l2.q)
	}
	if !l2.ev.Cached || l2.ev.Upstream != "" {
		t.Fatalf("stats event %+v", l2.ev)
	}
	if got := answers(resp); !slices.Equal(got, []string{"A 192.0.2.1"}) {
		t.Fatalf("cached answer %v", got)
	}
	if resp.Id != 4711 {
		t.Fatal("cached answer id")
	}
	if n := e.up.count("cached.example", dns.TypeA); n != 1 {
		t.Fatalf("upstream asked %d times", n)
	}
	// Blocked and local answers are not cached.
	e.query("ads.example", dns.TypeA)
	e.query("nas.home.lan", dns.TypeA)
	if n := e.cache.Stats().Entries; n != 1 {
		t.Fatalf("cache entries %d", n)
	}
	// DO is part of the key.
	_, l := e.query("cached.example", dns.TypeA, withEDNS(1232, true))
	if l.q.Cached {
		t.Fatal("DO query answered from the non-DO entry")
	}
	// Cache off → always asked.
	e.update(func(s *config.Settings) { s.CacheEnabled = false })
	e.query("nocache.example", dns.TypeA)
	_, l = e.query("nocache.example", dns.TypeA)
	if l.q.Cached || e.up.count("nocache.example", dns.TypeA) != 2 {
		t.Fatal("cache used while disabled")
	}
	// Apply configures the size.
	e.update(func(s *config.Settings) { s.CacheEnabled = true; s.CacheSize = 0 })
	e.query("zero.example", dns.TypeA)
	_, l = e.query("zero.example", dns.TypeA)
	if l.q.Cached {
		t.Fatal("cache size 0 stored")
	}
	// SERVFAIL is never cached.
	e.update(func(s *config.Settings) { s.CacheSize = 100 })
	e.query("servfail.example", dns.TypeA)
	e.query("servfail.example", dns.TypeA)
	if n := e.up.count("servfail.example", dns.TypeA); n != 2 {
		t.Fatalf("servfail asked %d times", n)
	}
}

func TestUpstreamFailure(t *testing.T) {
	e := newEnv(t, nil)
	resp, l := e.query("servfail.example", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure || l.q.Status != "error" || l.q.Reason != "upstream" || l.q.Rcode != "SERVFAIL" || l.q.Upstream != "" {
		t.Fatalf("got %s %+v", dns.RcodeToString[resp.Rcode], l.q)
	}
	if !l.withStats || l.ev.Status != "error" {
		t.Fatal("error not counted")
	}
	// An allowed query that fails keeps the error status.
	failing := startUpstream(t, true)
	e.update(func(s *config.Settings) { s.Upstreams = []string{failing.addr} })
	resp, l = e.query("allowed.example", dns.TypeA)
	if resp.Rcode != dns.RcodeServerFailure || l.q.Status != "error" {
		t.Fatalf("allowed failure %+v", l.q)
	}
}

func TestClientPolicies(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) {
		s.BlockedServices = []string{"youtube"}
	})
	e.clients = []store.Client{
		{ID: 1, Name: "Laptop", IDs: []string{"192.168.1.30"}, UseGlobalSettings: true, UseGlobalServices: true},
		{ID: 2, Name: "Kinder-Netz", IDs: []string{"192.168.50.0/24"}, FilteringEnabled: true,
			SafeSearch:        config.SafeSearch{Enabled: true, Bing: true},
			UseGlobalServices: false, BlockedServices: []string{"tiktok"}},
		{ID: 3, Name: "TV", IDs: []string{"192.168.50.7"}, FilteringEnabled: false, UseGlobalServices: true},
		{ID: 4, Name: "Heimnetz", IDs: []string{"192.168.0.0/16"}, FilteringEnabled: true, UseGlobalServices: false},
		{ID: 5, Name: "Mapped", IDs: []string{"::ffff:10.1.1.1"}, FilteringEnabled: false, UseGlobalServices: true},
	}
	e.apply()
	tests := []struct {
		name       string
		ip         string
		qname      string
		status     string
		clientName string
	}{
		{"global settings client blocks", "192.168.1.30", "ads.example", "blocked", "Laptop"},
		{"global services apply", "192.168.1.30", "www.youtube.com", "blocked_service", "Laptop"},
		{"own services: tiktok", "192.168.50.20", "www.tiktok.com", "blocked_service", "Kinder-Netz"},
		{"own services: no youtube", "192.168.50.20", "youtube.com", "ok", "Kinder-Netz"},
		{"own safesearch", "192.168.50.20", "www.bing.com", "safesearch", "Kinder-Netz"},
		{"exact ip beats cidr", "192.168.50.7", "ads.example", "ok", "TV"},
		{"exact ip global services", "192.168.50.7", "www.youtube.com", "ok", "TV"}, // filtering off
		{"/24 beats /16", "192.168.50.8", "www.tiktok.com", "blocked_service", "Kinder-Netz"},
		{"/16 no services", "192.168.2.2", "www.youtube.com", "ok", "Heimnetz"},
		{"/16 filtering", "192.168.2.2", "ads.example", "blocked", "Heimnetz"},
		{"mapped id", "10.1.1.1", "ads.example", "ok", "Mapped"},
		{"unknown client global", "10.9.9.9", "www.youtube.com", "blocked_service", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, l := e.query(tt.qname, dns.TypeA, fromIP(tt.ip))
			if l.q.Status != tt.status {
				t.Fatalf("status %q, want %q (%+v)", l.q.Status, tt.status, l.q)
			}
			if tt.clientName != "" && l.q.ClientName != tt.clientName {
				t.Fatalf("client name %q, want %q", l.q.ClientName, tt.clientName)
			}
			if got := e.srv.ClientName(tt.ip); got != tt.clientName {
				t.Fatalf("ClientName %q, want %q", got, tt.clientName)
			}
		})
	}
	// Global SafeSearch reaches use_global_settings clients.
	e.update(func(s *config.Settings) { s.SafeSearch.Enabled = true })
	_, l := e.query("www.bing.com", dns.TypeA, fromIP("192.168.1.30"))
	if l.q.Status != "safesearch" {
		t.Fatalf("global safesearch for Laptop: %+v", l.q)
	}
	// ... but not to clients with their own settings and safesearch off.
	_, l = e.query("www.bing.com", dns.TypeA, fromIP("192.168.2.2"))
	if l.q.Status != "ok" {
		t.Fatalf("own settings: %+v", l.q)
	}
}

func TestProtection(t *testing.T) {
	e := newEnv(t, nil)
	now := e.now()
	e.update(func(s *config.Settings) { s.ProtectionPausedUntil = now.Add(10 * time.Minute).UnixMilli() })
	_, l := e.query("ads.example", dns.TypeA)
	if l.q.Status != "ok" {
		t.Fatalf("paused: %+v", l.q)
	}
	e.advance(11 * time.Minute)
	_, l = e.query("ads.example", dns.TypeA)
	if l.q.Status != "blocked" {
		t.Fatalf("pause over: %+v", l.q)
	}
	e.update(func(s *config.Settings) {
		s.ProtectionPausedUntil = 0
		s.ProtectionEnabled = false
		s.SafeSearch.Enabled = true
	})
	for _, n := range []string{"ads.example", "www.bing.com", "x.blocked-custom.example"} {
		_, l = e.query(n, dns.TypeA)
		if l.q.Status != "ok" {
			t.Fatalf("protection off %s: %+v", n, l.q)
		}
	}
}

func TestCheck(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) {
		s.BlockedServices = []string{"tiktok"}
		s.SafeSearch.Enabled = true
		s.DisallowedClients = []string{"192.168.9.9"}
	})
	e.clients = []store.Client{{ID: 1, Name: "TV", IDs: []string{"192.168.1.50"}, FilteringEnabled: false, UseGlobalServices: false}}
	e.apply()
	tests := []struct {
		name, qname string
		qtype       uint16
		client      string
		want        CheckResult
	}{
		{"list", "ads.example", dns.TypeA, "192.168.1.20", CheckResult{Name: "ads.example", Type: "A", ClientIP: "192.168.1.20", Status: "blocked", Reason: "list", Rule: "||ads.example^", ListID: 1, Answer: "0.0.0.0"}},
		{"trailing dot and case", "ADS.example.", dns.TypeAAAA, "", CheckResult{Name: "ads.example", Type: "AAAA", Status: "blocked", Reason: "list", Rule: "||ads.example^", ListID: 1, Answer: "::"}},
		{"service", "tiktok.com", dns.TypeA, "", CheckResult{Name: "tiktok.com", Type: "A", Status: "blocked_service", Reason: "service", Rule: "||tiktok.com^", Service: "tiktok", Answer: "0.0.0.0"}},
		{"allowed", "allowed.example", dns.TypeA, "", CheckResult{Name: "allowed.example", Type: "A", Status: "allowed", Reason: "custom", Rule: "@@||allowed.example^"}},
		{"safesearch", "www.bing.com", dns.TypeA, "", CheckResult{Name: "www.bing.com", Type: "A", Status: "safesearch", Reason: "safesearch", Answer: "CNAME strict.bing.com"}},
		{"local", "nas.home.lan", dns.TypeA, "", CheckResult{Name: "nas.home.lan", Type: "A", Status: "rewrite", Reason: "rewrite", Answer: "192.168.1.10"}},
		{"local cname", "ext.home.lan", dns.TypeA, "", CheckResult{Name: "ext.home.lan", Type: "A", Status: "rewrite", Reason: "rewrite", Answer: "CNAME target.example"}},
		{"hosts", "nas.hosts.example", dns.TypeA, "", CheckResult{Name: "nas.hosts.example", Type: "A", Status: "rewrite", Reason: "custom", Rule: "192.168.1.5 nas.hosts.example", Answer: "192.168.1.5"}},
		{"nothing", "plain.example", dns.TypeA, "", CheckResult{Name: "plain.example", Type: "A", Status: "ok"}},
		{"client filtering off", "ads.example", dns.TypeA, "192.168.1.50", CheckResult{Name: "ads.example", Type: "A", ClientIP: "192.168.1.50", ClientName: "TV", Status: "ok"}},
		{"invalid client = global", "ads.example", dns.TypeA, "kaputt", CheckResult{Name: "ads.example", Type: "A", ClientIP: "kaputt", Status: "blocked", Reason: "list", Rule: "||ads.example^", ListID: 1, Answer: "0.0.0.0"}},
		{"disallowed client", "plain.example", dns.TypeA, "192.168.9.9", CheckResult{Name: "plain.example", Type: "A", ClientIP: "192.168.9.9", Status: "refused", Reason: "access"}},
		{"any", "plain.example", dns.TypeANY, "", CheckResult{Name: "plain.example", Type: "ANY", Status: "refused", Reason: "any"}},
		{"unknown type", "plain.example", 65280, "", CheckResult{Name: "plain.example", Type: "TYPE65280", Status: "ok"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.srv.Check(tt.qname, tt.qtype, tt.client)
			if got != tt.want {
				t.Fatalf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
	if e.logCount() != 0 {
		t.Fatal("Check logged queries")
	}
	for _, n := range []string{"plain.example", "strict.bing.com", "target.example", "allowed.example"} {
		if e.up.count(n, dns.TypeA) != 0 {
			t.Fatalf("Check asked the upstream for %s", n)
		}
	}
	// Before Apply.
	if got := New(Deps{}).Check("x.example", dns.TypeA, ""); got.Status != "ok" || got.Name != "x.example" {
		t.Fatalf("before apply: %+v", got)
	}
}

func TestHostname(t *testing.T) {
	e := newEnv(t, nil)
	if got := e.srv.Hostname("127.0.0.1"); got != "" {
		t.Fatalf("first call %q", got)
	}
	e.srv.hosts.wg.Wait()
	if got := e.srv.Hostname("127.0.0.1"); got != "myhost.lan" {
		t.Fatalf("hostname %q", got)
	}
	if n := e.up.count("1.0.0.127.in-addr.arpa", dns.TypePTR); n != 1 {
		t.Fatalf("PTR asked %d times", n)
	}
	// Failures are cached too.
	e.srv.Hostname("192.0.2.99")
	e.srv.hosts.wg.Wait()
	e.srv.Hostname("192.0.2.99")
	e.srv.hosts.wg.Wait()
	if n := e.up.count("99.2.0.192.in-addr.arpa", dns.TypePTR); n != 1 {
		t.Fatalf("failed PTR asked %d times", n)
	}
	// Success expires after an hour, failures after 10 minutes (the cache uses the server clock).
	e.advance(11 * time.Minute)
	e.srv.Hostname("192.0.2.99")
	e.srv.hosts.wg.Wait()
	if n := e.up.count("99.2.0.192.in-addr.arpa", dns.TypePTR); n != 2 {
		t.Fatalf("failed PTR not retried: %d", n)
	}
	if got := e.srv.Hostname("127.0.0.1"); got != "myhost.lan" {
		t.Fatalf("hostname expired early: %q", got)
	}
	// Invalid input.
	if got := e.srv.Hostname("nonsense"); got != "" {
		t.Fatalf("invalid %q", got)
	}
	// Name in the log when no client is configured.
	_, l := e.query("x.example", dns.TypeA, fromIP("127.0.0.1"))
	if l.q.ClientName != "myhost.lan" {
		t.Fatalf("log client name %q", l.q.ClientName)
	}
	// Configured name wins.
	e.clients = []store.Client{{ID: 1, Name: "Server", IDs: []string{"127.0.0.1"}, UseGlobalSettings: true, UseGlobalServices: true}}
	e.apply()
	_, l = e.query("x.example", dns.TypeA, fromIP("127.0.0.1"))
	if l.q.ClientName != "Server" {
		t.Fatalf("log client name %q", l.q.ClientName)
	}
}

func TestHostCacheLimits(t *testing.T) {
	h := newHostCache()
	now := time.Unix(1000, 0)
	for i := 0; i < hostMaxEntries+10; i++ {
		a := parseClientIP("10.0.0.0").As4()
		a[2], a[3] = byte(i>>8), byte(i)
		a[1] = byte(i >> 16)
		h.store(netip.AddrFrom4(a), "h", true, now)
	}
	if n := len(h.entries); n > hostMaxEntries {
		t.Fatalf("entries %d > %d", n, hostMaxEntries)
	}
	// Bounded concurrency: with all slots busy no lookup starts.
	block := make(chan struct{})
	var started sync.WaitGroup
	calls := 0
	var mu sync.Mutex
	resolve := func(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		started.Done()
		<-block
		return nil, errors.New("test")
	}
	started.Add(hostLookups)
	for i := 0; i < hostLookups+3; i++ {
		h.lookup(parseClientIP("172.16.0."+strconv.Itoa(i+1)), now, resolve)
	}
	started.Wait()
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != hostLookups {
		t.Fatalf("concurrent lookups %d, want %d", got, hostLookups)
	}
	close(block)
	h.wg.Wait()
}

func TestLogging(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.AnonymizeIP = true })
	_, l := e.query("anon.example", dns.TypeA, fromIP("192.168.1.20"))
	if l.q.ClientIP != "192.168.1.0" || l.ev.Client != "192.168.1.0" || l.q.ClientName != "" {
		t.Fatalf("anonymized %+v %+v", l.q, l.ev)
	}
	_, l = e.query("anon.example", dns.TypeA, fromIP("2001:db8:1:2::5"), withEDNS(1232, false))
	if l.q.Status != "refused" { // not in allowed_clients
		t.Fatalf("v6 public %+v", l.q)
	}
	e.update(func(s *config.Settings) { s.AllowedClients = []string{} })
	_, l = e.query("anon.example", dns.TypeA, fromIP("2001:db8:1:2::5"))
	if l.q.ClientIP != "2001:db8:1::" {
		t.Fatalf("v6 anonymized %q", l.q.ClientIP)
	}
	e.query("anon.example", dns.TypeA, fromIP("127.0.0.1"))
	e.srv.hosts.wg.Wait()
	if n := e.up.count("1.0.0.127.in-addr.arpa", dns.TypePTR); n != 0 {
		t.Fatal("reverse lookup while anonymizing")
	}
	// Unknown types.
	_, l = e.query("plain.example", 65280)
	if l.q.QType != "TYPE65280" {
		t.Fatalf("qtype %q", l.q.QType)
	}
}

func TestConcurrentApply(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.Ratelimit = 100000 })
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			names := []string{"ads.example", "plain.example", "nas.home.lan", "ext.home.lan", "cloak.example", "www.bing.com"}
			for j := 0; ; j++ {
				select {
				case <-stop:
					return
				default:
				}
				req := new(dns.Msg)
				req.SetQuestion(names[j%len(names)]+".", dns.TypeA)
				w := newUDPWriter("192.168.1.20")
				e.srv.ServeDNS(w, req)
				if resp, _ := w.last(); resp == nil {
					t.Error("no reply")
					return
				}
				e.srv.Check(names[j%len(names)], dns.TypeA, "192.168.1.20")
			}
		}()
	}
	for i := 0; i < 20; i++ {
		e.update(func(s *config.Settings) { s.BlockingMode = []string{config.BlockNullIP, config.BlockNXDomain}[i%2] })
		time.Sleep(2 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
}
