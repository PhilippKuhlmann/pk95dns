package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Add(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}

func newTestCache(size int, minTTL, maxTTL uint32) (*Cache, *fakeClock) {
	c := New(size, minTTL, maxTTL)
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	c.now = clk.Now
	return c, clk
}

func req(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

func rr(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return r
}

// answer builds a NOERROR reply to q with the given records.
func answer(q *dns.Msg, records ...string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	for _, s := range records {
		m.Answer = append(m.Answer, rr(s))
	}
	return m
}

func soa(zone string, ttl, minimum uint32) dns.RR {
	return rr(fmt.Sprintf("%s %d IN SOA ns.%s hostmaster.%s 1 7200 3600 1209600 %d", zone, ttl, zone, zone, minimum))
}

func ttls(m *dns.Msg) []uint32 {
	var out []uint32
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, r := range sec {
			if r.Header().Rrtype != dns.TypeOPT {
				out = append(out, r.Header().Ttl)
			}
		}
	}
	return out
}

func TestTTLDecrementAndExpiry(t *testing.T) {
	c, clk := newTestCache(10, 0, 0)
	q := req("example.org", dns.TypeA)
	resp := answer(q, "example.org. 300 IN A 192.0.2.1", "example.org. 100 IN A 192.0.2.2")
	c.Set(q, resp)
	if resp.Answer[0].Header().Ttl != 300 {
		t.Fatal("Set modified the response")
	}

	clk.Add(30*time.Second + 500*time.Millisecond)
	got := c.Get(q)
	if got == nil {
		t.Fatal("miss")
	}
	if want := []uint32{270, 70}; fmt.Sprint(ttls(got)) != fmt.Sprint(want) {
		t.Fatalf("ttls = %v, want %v", ttls(got), want)
	}
	// The cached copy is independent of the returned message.
	got.Answer[0].Header().Ttl = 1
	got.Answer = nil
	if again := c.Get(q); again == nil || len(again.Answer) != 2 || again.Answer[0].Header().Ttl != 270 {
		t.Fatalf("cache entry modified through returned message: %v", again)
	}

	// Entry lives for the minimum TTL (100 s).
	clk.Add(69 * time.Second)
	if c.Get(q) == nil {
		t.Fatal("expired too early")
	}
	clk.Add(time.Second)
	if c.Get(q) != nil {
		t.Fatal("expired entry returned")
	}
	if s := c.Stats(); s.Entries != 0 {
		t.Fatalf("expired entry not evicted: %+v", s)
	}
	if s := c.Stats(); s.Hits != 3 || s.Misses != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestIDAndQuestionFromRequest(t *testing.T) {
	c, _ := newTestCache(10, 0, 0)
	q := req("Example.ORG", dns.TypeA)
	q.Id = 1
	c.Set(q, answer(q, "Example.ORG. 300 IN A 192.0.2.1", "other.example. 300 IN A 192.0.2.2"))

	q2 := req("eXample.org", dns.TypeA)
	q2.Id = 5555
	got := c.Get(q2)
	if got == nil {
		t.Fatal("case-insensitive lookup missed")
	}
	if got.Id != 5555 {
		t.Fatalf("id = %d", got.Id)
	}
	if got.Question[0].Name != "eXample.org." {
		t.Fatalf("question = %q", got.Question[0].Name)
	}
	if got.Answer[0].Header().Name != "eXample.org." || got.Answer[1].Header().Name != "other.example." {
		t.Fatalf("owner names %q %q", got.Answer[0].Header().Name, got.Answer[1].Header().Name)
	}
	// Mutating the returned question does not affect the request.
	got.Question[0].Name = "x."
	if q2.Question[0].Name != "eXample.org." {
		t.Fatal("question shared with request")
	}
}

func TestMinMaxClamp(t *testing.T) {
	tests := []struct {
		name         string
		min, max     uint32
		recordTTL    uint32
		wantTTL      uint32 // returned right after storing
		wantLifetime time.Duration
	}{
		{"no limits", 0, 0, 500, 500, 500 * time.Second},
		{"raised to min", 60, 0, 5, 60, 60 * time.Second},
		{"cut to max", 0, 100, 5000, 100, 100 * time.Second},
		{"inside range", 10, 1000, 300, 300, 300 * time.Second},
		{"max 0 is unlimited", 0, 0, 604800, 604800, 604800 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, clk := newTestCache(10, tt.min, tt.max)
			q := req("example.org", dns.TypeA)
			c.Set(q, answer(q, fmt.Sprintf("example.org. %d IN A 192.0.2.1", tt.recordTTL)))
			got := c.Get(q)
			if got == nil || got.Answer[0].Header().Ttl != tt.wantTTL {
				t.Fatalf("got %v, want TTL %d", got, tt.wantTTL)
			}
			clk.Add(tt.wantLifetime - time.Second)
			if got := c.Get(q); got == nil || got.Answer[0].Header().Ttl != 1 {
				t.Fatalf("one second before expiry: %v", got)
			}
			clk.Add(time.Second)
			if c.Get(q) != nil {
				t.Fatal("still cached after lifetime")
			}
		})
	}
}

func TestConfigureClampsNewEntries(t *testing.T) {
	c, _ := newTestCache(10, 0, 0)
	c.Configure(10, 0, 50)
	q := req("example.org", dns.TypeA)
	c.Set(q, answer(q, "example.org. 3600 IN A 192.0.2.1"))
	if got := c.Get(q); got == nil || got.Answer[0].Header().Ttl != 50 {
		t.Fatalf("got %v", got)
	}
}

func TestNegativeCaching(t *testing.T) {
	tests := []struct {
		name      string
		rcode     int
		ns        []dns.RR
		answer    []string
		min, max  uint32
		wantCache bool
		wantTTL   uint32 // lifetime in seconds
	}{
		{name: "NXDOMAIN uses SOA minimum", rcode: dns.RcodeNameError, ns: []dns.RR{soa("example.org.", 3600, 300)}, wantCache: true, wantTTL: 300},
		{name: "NXDOMAIN uses SOA TTL when smaller", rcode: dns.RcodeNameError, ns: []dns.RR{soa("example.org.", 120, 900)}, wantCache: true, wantTTL: 120},
		{name: "NODATA", rcode: dns.RcodeSuccess, ns: []dns.RR{soa("example.org.", 600, 60)}, wantCache: true, wantTTL: 60},
		{name: "NXDOMAIN with CNAME in answer", rcode: dns.RcodeNameError, ns: []dns.RR{soa("example.org.", 600, 600)}, answer: []string{"nx.example.org. 30 IN CNAME gone.example.org."}, wantCache: true, wantTTL: 30},
		{name: "negative clamped to max", rcode: dns.RcodeNameError, ns: []dns.RR{soa("example.org.", 3600, 3600)}, max: 100, wantCache: true, wantTTL: 100},
		{name: "negative raised to min", rcode: dns.RcodeNameError, ns: []dns.RR{soa("example.org.", 3600, 5)}, min: 30, wantCache: true, wantTTL: 30},
		{name: "NXDOMAIN without SOA", rcode: dns.RcodeNameError, wantCache: false},
		{name: "NODATA without SOA", rcode: dns.RcodeSuccess, wantCache: false},
		{name: "SOA minimum 0", rcode: dns.RcodeNameError, ns: []dns.RR{soa("example.org.", 3600, 0)}, wantCache: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, clk := newTestCache(10, tt.min, tt.max)
			q := req("nx.example.org", dns.TypeA)
			resp := answer(q, tt.answer...)
			resp.Rcode = tt.rcode
			resp.Ns = tt.ns
			c.Set(q, resp)
			got := c.Get(q)
			if !tt.wantCache {
				if got != nil {
					t.Fatalf("cached: %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("not cached")
			}
			if got.Rcode != tt.rcode {
				t.Fatalf("rcode %d", got.Rcode)
			}
			for _, r := range got.Ns {
				if s, ok := r.(*dns.SOA); ok && s.Hdr.Ttl < tt.wantTTL {
					t.Fatalf("SOA TTL %d < %d", s.Hdr.Ttl, tt.wantTTL)
				}
			}
			clk.Add(time.Duration(tt.wantTTL-1) * time.Second)
			if c.Get(q) == nil {
				t.Fatal("expired too early")
			}
			clk.Add(time.Second)
			if c.Get(q) != nil {
				t.Fatal("not expired")
			}
		})
	}
}

func TestNotCached(t *testing.T) {
	q := req("example.org", dns.TypeA)
	tests := []struct {
		name string
		req  *dns.Msg
		resp func() *dns.Msg
	}{
		{"SERVFAIL", q, func() *dns.Msg { m := answer(q); m.Rcode = dns.RcodeServerFailure; return m }},
		{"REFUSED", q, func() *dns.Msg { m := answer(q); m.Rcode = dns.RcodeRefused; return m }},
		{"FORMERR", q, func() *dns.Msg { m := answer(q); m.Rcode = dns.RcodeFormatError; return m }},
		{"truncated", q, func() *dns.Msg { m := answer(q, "example.org. 300 IN A 192.0.2.1"); m.Truncated = true; return m }},
		{"TTL 0", q, func() *dns.Msg { return answer(q, "example.org. 0 IN A 192.0.2.1") }},
		{"one record TTL 0", q, func() *dns.Msg {
			return answer(q, "example.org. 300 IN A 192.0.2.1", "example.org. 0 IN A 192.0.2.2")
		}},
		{"question name mismatch", q, func() *dns.Msg {
			return answer(req("evil.example", dns.TypeA), "evil.example. 300 IN A 192.0.2.1")
		}},
		{"question type mismatch", q, func() *dns.Msg {
			return answer(req("example.org", dns.TypeAAAA), "example.org. 300 IN AAAA ::1")
		}},
		{"no question in answer", q, func() *dns.Msg {
			m := answer(q, "example.org. 300 IN A 192.0.2.1")
			m.Question = nil
			return m
		}},
		{"nil answer", q, func() *dns.Msg { return nil }},
		{"request without question", new(dns.Msg), func() *dns.Msg { return answer(q, "example.org. 300 IN A 192.0.2.1") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestCache(10, 0, 0)
			c.Set(tt.req, tt.resp())
			if s := c.Stats(); s.Entries != 0 {
				t.Fatalf("stored: %+v", s)
			}
		})
	}

	// Size 0 disables storing.
	c, _ := newTestCache(0, 0, 0)
	c.Set(q, answer(q, "example.org. 300 IN A 192.0.2.1"))
	if c.Get(q) != nil || c.Stats().Entries != 0 {
		t.Fatal("size 0 stored an entry")
	}
	if c.Get(new(dns.Msg)) != nil {
		t.Fatal("request without question answered")
	}
}

func TestMinTTLDoesNotRescueTTL0(t *testing.T) {
	c, _ := newTestCache(10, 60, 0)
	q := req("example.org", dns.TypeA)
	c.Set(q, answer(q, "example.org. 0 IN A 192.0.2.1"))
	if c.Get(q) != nil {
		t.Fatal("TTL 0 answer cached")
	}
}

func TestOPTIgnoredForTTL(t *testing.T) {
	c, clk := newTestCache(10, 0, 0)
	q := req("example.org", dns.TypeA)
	resp := answer(q, "example.org. 300 IN A 192.0.2.1")
	resp.SetEdns0(1232, false) // OPT "TTL" holds flags, here 0
	c.Set(q, resp)
	clk.Add(299 * time.Second)
	got := c.Get(q)
	if got == nil {
		t.Fatal("OPT record influenced the TTL")
	}
	if got.IsEdns0() == nil || got.IsEdns0().UDPSize() != 1232 {
		t.Fatal("OPT record changed")
	}
}

func TestKeyIncludesTypeClassDOCD(t *testing.T) {
	c, _ := newTestCache(100, 0, 0)
	base := req("example.org", dns.TypeA)
	c.Set(base, answer(base, "example.org. 300 IN A 192.0.2.1"))

	aaaa := req("example.org", dns.TypeAAAA)
	if c.Get(aaaa) != nil {
		t.Fatal("type not part of the key")
	}
	chaos := req("example.org", dns.TypeA)
	chaos.Question[0].Qclass = dns.ClassCHAOS
	if c.Get(chaos) != nil {
		t.Fatal("class not part of the key")
	}
	do := req("example.org", dns.TypeA)
	do.SetEdns0(1232, true)
	if c.Get(do) != nil {
		t.Fatal("DO bit not part of the key")
	}
	cd := req("example.org", dns.TypeA)
	cd.CheckingDisabled = true
	if c.Get(cd) != nil {
		t.Fatal("CD bit not part of the key")
	}
	// EDNS without DO matches the plain entry.
	edns := req("example.org", dns.TypeA)
	edns.SetEdns0(4096, false)
	if c.Get(edns) == nil {
		t.Fatal("EDNS without DO should hit")
	}
	// Trailing dot does not matter.
	nodot := new(dns.Msg)
	nodot.Question = []dns.Question{{Name: "example.org", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	if c.Get(nodot) == nil {
		t.Fatal("name without trailing dot missed")
	}

	// Separate entries for DO and CD.
	doResp := answer(do, "example.org. 300 IN A 192.0.2.9")
	c.Set(do, doResp)
	if got := c.Get(do); got == nil || got.Answer[0].(*dns.A).A.String() != "192.0.2.9" {
		t.Fatalf("DO entry %v", got)
	}
	if got := c.Get(base); got == nil || got.Answer[0].(*dns.A).A.String() != "192.0.2.1" {
		t.Fatalf("plain entry overwritten: %v", got)
	}
	if c.Stats().Entries != 2 {
		t.Fatalf("entries = %d", c.Stats().Entries)
	}
}

func TestLRUEviction(t *testing.T) {
	c, _ := newTestCache(3, 0, 0)
	set := func(name string) {
		q := req(name, dns.TypeA)
		c.Set(q, answer(q, name+". 300 IN A 192.0.2.1"))
	}
	has := func(name string) bool { return c.Get(req(name, dns.TypeA)) != nil }

	set("a.example")
	set("b.example")
	set("c.example")
	if !has("a.example") { // a is now most recently used
		t.Fatal("a missing")
	}
	set("d.example") // evicts b (least recently used)
	if has("b.example") {
		t.Fatal("b should have been evicted")
	}
	for _, n := range []string{"a.example", "c.example", "d.example"} {
		if !has(n) {
			t.Fatalf("%s missing", n)
		}
	}
	// Overwriting an entry does not grow the cache.
	set("d.example")
	if c.Stats().Entries != 3 {
		t.Fatalf("entries = %d", c.Stats().Entries)
	}

	// Shrinking evicts the least recently used entries.
	_ = has("a.example")
	c.Configure(1, 0, 0)
	if c.Stats().Entries != 1 || !has("a.example") {
		t.Fatalf("after shrink: %+v", c.Stats())
	}
	c.Configure(0, 0, 0)
	if c.Stats().Entries != 0 {
		t.Fatal("Configure(0) kept entries")
	}
	c.Configure(5, 0, 0)
	set("x.example")
	if !has("x.example") {
		t.Fatal("cache not usable after growing again")
	}
}

func TestFlushAndStats(t *testing.T) {
	c, _ := newTestCache(10, 0, 0)
	q := req("example.org", dns.TypeA)
	c.Set(q, answer(q, "example.org. 300 IN A 192.0.2.1"))
	c.Get(q)
	c.Get(req("miss.example", dns.TypeA))
	if s := c.Stats(); s != (Stats{Entries: 1, Hits: 1, Misses: 1}) {
		t.Fatalf("stats %+v", s)
	}
	c.Flush()
	if s := c.Stats(); s != (Stats{Entries: 0, Hits: 1, Misses: 1}) {
		t.Fatalf("after flush %+v", s)
	}
	if c.Get(q) != nil {
		t.Fatal("entry survived flush")
	}
	c.Set(q, answer(q, "example.org. 300 IN A 192.0.2.1"))
	if c.Get(q) == nil {
		t.Fatal("cache not usable after flush")
	}
}

func TestNegativeSizeTreatedAsZero(t *testing.T) {
	c := New(-5, 0, 0)
	q := req("example.org", dns.TypeA)
	c.Set(q, answer(q, "example.org. 300 IN A 192.0.2.1"))
	if c.Stats().Entries != 0 {
		t.Fatal("negative size stored entries")
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(50, 0, 0)
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			for i := range 500 {
				name := fmt.Sprintf("h%d.example", (g*7+i)%120)
				q := req(name, dns.TypeA)
				q.Id = uint16(i)
				switch i % 5 {
				case 0, 1:
					c.Set(q, answer(q, name+". 300 IN A 192.0.2.1"))
				case 2, 3:
					if got := c.Get(q); got != nil {
						if got.Id != uint16(i) || got.Question[0].Name != dns.Fqdn(name) {
							t.Errorf("wrong answer %v", got)
						}
						got.Answer[0].Header().Ttl = 0 // must not affect the cache
					}
				case 4:
					if i%100 == 4 {
						c.Configure(40+i%20, 0, 0)
					}
					if i%250 == 4 {
						c.Flush()
					}
					_ = c.Stats()
				}
			}
		})
	}
	wg.Wait()
	if s := c.Stats(); s.Entries > 59 {
		t.Fatalf("entries %d over size", s.Entries)
	}
}

// An answer of a query that started before a Flush is not stored.
func TestSetGenAfterFlush(t *testing.T) {
	c, _ := newTestCache(10, 0, 0)
	q := req("example.org", dns.TypeA)
	gen := c.Gen()
	c.Flush()
	c.SetGen(gen, q, answer(q, "example.org. 300 IN A 192.0.2.1"))
	if c.Get(q) != nil {
		t.Fatal("answer from before the flush stored")
	}
	c.SetGen(c.Gen(), q, answer(q, "example.org. 300 IN A 192.0.2.2"))
	if c.Get(q) == nil {
		t.Fatal("answer of the current generation not stored")
	}
}
