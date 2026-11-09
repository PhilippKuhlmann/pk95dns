package upstream

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newRouter(t *testing.T, cfg Config) *Router {
	t.Helper()
	if cfg.Timeout == 0 {
		cfg.Timeout = time.Second
	}
	r, err := NewRouter(cfg)
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestNewRouterValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"no upstreams", Config{}, "Mindestens ein Upstream"},
		{"bad mode", Config{Upstreams: []string{"9.9.9.9"}, Mode: "random"}, "Unbekannter Upstream-Modus"},
		{"bad upstream", Config{Upstreams: []string{"dns.google"}}, "IP-Adresse nötig"},
		{"bad fallback", Config{Upstreams: []string{"9.9.9.9"}, Fallback: []string{"x://y"}}, "Unbekanntes Protokoll"},
		{"bad private", Config{Upstreams: []string{"9.9.9.9"}, PrivateUpstreams: []string{"a b"}}, "Ungültige Adresse"},
		{"bad bootstrap", Config{Upstreams: []string{"9.9.9.9"}, Bootstrap: []string{"dns.google"}}, "Bootstrap"},
		{"bad route upstream", Config{Upstreams: []string{"9.9.9.9"}, Routes: []Route{{Domain: "lan", Upstream: "lan-dns"}}}, "IP-Adresse"},
		{"empty route domain", Config{Upstreams: []string{"9.9.9.9"}, Routes: []Route{{Domain: ".", Upstream: "192.168.1.1"}}}, "Domain"},
		{"ok default mode", Config{Upstreams: []string{"9.9.9.9", "https://dns.quad9.net/dns-query", "tls://1.1.1.1"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewRouter(tt.cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if r.mode != "load_balance" {
					t.Fatalf("mode = %q", r.mode)
				}
				r.Close()
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestRouterModes(t *testing.T) {
	good := newTestServer(t, answerA("192.0.2.1", 60))
	good2 := newTestServer(t, answerA("192.0.2.2", 60))
	slow := newTestServer(t, slowHandler(400*time.Millisecond, answerA("192.0.2.3", 60)))
	servfail := newTestServer(t, rcodeHandler(dns.RcodeServerFailure))
	refused := newTestServer(t, rcodeHandler(dns.RcodeRefused))
	nxdomain := newTestServer(t, rcodeHandler(dns.RcodeNameError))

	tests := []struct {
		name      string
		mode      string
		upstreams []string
		fallback  []string
		wantAddr  string
		wantErr   bool
		maxTime   time.Duration
	}{
		{name: "sequential first good", mode: "sequential", upstreams: []string{good.addr, good2.addr}, wantAddr: good.addr},
		{name: "sequential skips SERVFAIL and REFUSED", mode: "sequential", upstreams: []string{servfail.addr, refused.addr, good2.addr}, wantAddr: good2.addr},
		{name: "NXDOMAIN is a good answer", mode: "sequential", upstreams: []string{nxdomain.addr, good.addr}, wantAddr: nxdomain.addr},
		{name: "parallel fastest wins", mode: "parallel", upstreams: []string{slow.addr, good.addr}, wantAddr: good.addr, maxTime: 300 * time.Millisecond},
		{name: "parallel ignores bad answers", mode: "parallel", upstreams: []string{servfail.addr, slow.addr}, wantAddr: slow.addr},
		{name: "parallel single", mode: "parallel", upstreams: []string{good2.addr}, wantAddr: good2.addr},
		{name: "load_balance falls through to good", mode: "load_balance", upstreams: []string{servfail.addr, refused.addr, good.addr}, wantAddr: good.addr},
		{name: "fallback after main failed", mode: "sequential", upstreams: []string{servfail.addr}, fallback: []string{refused.addr, good2.addr}, wantAddr: good2.addr},
		{name: "fallback parallel", mode: "parallel", upstreams: []string{servfail.addr, refused.addr}, fallback: []string{good.addr}, wantAddr: good.addr},
		{name: "everything fails", mode: "load_balance", upstreams: []string{servfail.addr}, fallback: []string{refused.addr}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRouter(t, Config{Mode: tt.mode, Upstreams: tt.upstreams, Fallback: tt.fallback})
			req := query("example.org", dns.TypeA)
			req.Id = 777
			before := req.String()
			start := time.Now()
			resp, addr, err := r.Resolve(context.Background(), req)
			elapsed := time.Since(start)
			if req.String() != before {
				t.Fatal("request modified")
			}
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got %v from %s", resp, addr)
				}
				if !strings.HasPrefix(err.Error(), "Kein Upstream hat geantwortet") {
					t.Fatalf("err = %q", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if addr != tt.wantAddr {
				t.Fatalf("answered by %s, want %s", addr, tt.wantAddr)
			}
			if resp.Id != 777 {
				t.Fatalf("id = %d", resp.Id)
			}
			if tt.maxTime > 0 && elapsed > tt.maxTime {
				t.Fatalf("took %v, want < %v", elapsed, tt.maxTime)
			}
		})
	}
}

func TestRouterParallelLosersNotCountedAsFailures(t *testing.T) {
	fast := newTestServer(t, answerA("192.0.2.1", 60))
	slow := newTestServer(t, slowHandler(500*time.Millisecond, answerA("192.0.2.2", 60)))
	r := newRouter(t, Config{Mode: "parallel", Upstreams: []string{fast.addr, slow.addr}, Timeout: 2 * time.Second})
	for range 3 {
		if _, addr, err := r.Resolve(context.Background(), query("example.org", dns.TypeA)); err != nil || addr != fast.addr {
			t.Fatalf("addr=%s err=%v", addr, err)
		}
	}
	h := r.Health()
	if h[1].Failures != 0 || h[1].Queries != 0 {
		t.Fatalf("cancelled loser counted: %+v", h[1])
	}
	if h[0].Queries != 3 || !h[0].OK {
		t.Fatalf("winner health %+v", h[0])
	}
}

func TestRouterRoutes(t *testing.T) {
	main := newTestServer(t, answerA("192.0.2.1", 60))
	fritz := newTestServer(t, answerA("192.168.178.1", 60))
	box := newTestServer(t, answerA("10.0.0.1", 60))
	broken := newTestServer(t, rcodeHandler(dns.RcodeServerFailure))
	fallback := newTestServer(t, answerA("192.0.2.99", 60))

	r := newRouter(t, Config{
		Mode:      "sequential",
		Upstreams: []string{main.addr},
		Fallback:  []string{fallback.addr},
		Routes: []Route{
			{Domain: "box", Upstream: box.addr},
			{Domain: "Fritz.Box.", Upstream: fritz.addr},
			{Domain: "broken.lan", Upstream: broken.addr},
		},
	})
	tests := []struct {
		name     string
		wantAddr string
		wantErr  bool
	}{
		{"fritz.box", fritz.addr, false},
		{"a.fritz.box", fritz.addr, false},
		{"A.B.FRITZ.BOX.", fritz.addr, false},
		{"xfritz.box", box.addr, false},
		{"other.box", box.addr, false},
		{"box", box.addr, false},
		{"example.org", main.addr, false},
		{"fritz.box.example.org", main.addr, false},
		{"x.broken.lan", "", true}, // route only, no fallback
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, addr, err := r.Resolve(context.Background(), query(tt.name, dns.TypeA))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, answered by %s", addr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if addr != tt.wantAddr {
				t.Fatalf("answered by %s, want %s", addr, tt.wantAddr)
			}
		})
	}
}

func TestRouterPrivatePTR(t *testing.T) {
	main := newTestServer(t, answerA("192.0.2.1", 60))
	private := newTestServer(t, answerA("192.0.2.2", 60))
	private2 := newTestServer(t, answerA("192.0.2.3", 60))
	brokenPrivate := newTestServer(t, rcodeHandler(dns.RcodeServerFailure))
	route := newTestServer(t, answerA("192.0.2.4", 60))

	const privName = "5.1.168.192.in-addr.arpa"
	tests := []struct {
		name     string
		cfg      Config
		qname    string
		wantAddr string
		wantNX   bool
		wantErr  bool
	}{
		{"local NXDOMAIN without private upstreams", Config{PrivatePTR: true}, privName, "", true, false},
		{"private upstream", Config{PrivatePTR: true, PrivateUpstreams: []string{private.addr}}, privName, private.addr, false, false},
		{"private upstreams sequential even in parallel mode", Config{Mode: "parallel", PrivatePTR: true, PrivateUpstreams: []string{brokenPrivate.addr, private2.addr}}, privName, private2.addr, false, false},
		{"private upstreams fail without fallback", Config{PrivatePTR: true, PrivateUpstreams: []string{brokenPrivate.addr}, Fallback: []string{main.addr}}, privName, "", false, true},
		{"private_ptr off goes to main", Config{PrivatePTR: false, PrivateUpstreams: []string{private.addr}}, privName, main.addr, false, false},
		{"public PTR goes to main", Config{PrivatePTR: true, PrivateUpstreams: []string{private.addr}}, "8.8.8.8.in-addr.arpa", main.addr, false, false},
		{"IPv6 ULA", Config{PrivatePTR: true}, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa", "", true, false},
		{"route beats private PTR", Config{PrivatePTR: true, Routes: []Route{{Domain: "168.192.in-addr.arpa", Upstream: route.addr}}}, privName, route.addr, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.Upstreams = []string{main.addr}
			r := newRouter(t, cfg)
			req := query(tt.qname, dns.TypePTR)
			req.Id = 4242
			resp, addr, err := r.Resolve(context.Background(), req)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, answered by %s", addr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if addr != tt.wantAddr {
				t.Fatalf("answered by %q, want %q", addr, tt.wantAddr)
			}
			if resp.Id != 4242 {
				t.Fatalf("id = %d", resp.Id)
			}
			if tt.wantNX && resp.Rcode != dns.RcodeNameError {
				t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[resp.Rcode])
			}
			if tt.wantNX && (len(resp.Question) != 1 || resp.Question[0].Name != dns.Fqdn(tt.qname)) {
				t.Fatalf("question = %v", resp.Question)
			}
		})
	}
	if main.udpQueries.Load() != 2 {
		t.Fatalf("main upstream got %d queries, want 2 (private names must not leak)", main.udpQueries.Load())
	}
}

func TestRouterHealth(t *testing.T) {
	good := newTestServer(t, answerA("192.0.2.1", 60))
	bad := newTestServer(t, rcodeHandler(dns.RcodeServerFailure))
	silent := newTestServer(t, silentHandler)

	cfg := Config{Mode: "sequential", Upstreams: []string{bad.addr, silent.addr, good.addr}, Timeout: 150 * time.Millisecond}
	r := newRouter(t, cfg)
	for range 2 {
		if _, addr, err := r.Resolve(context.Background(), query("example.org", dns.TypeA)); err != nil || addr != good.addr {
			t.Fatalf("addr=%s err=%v", addr, err)
		}
	}
	h := r.Health()
	if len(h) != 3 || h[0].Address != bad.addr || h[1].Address != silent.addr || h[2].Address != good.addr {
		t.Fatalf("health order %+v", h)
	}
	if h[0].OK || h[0].Queries != 2 || h[0].Failures != 2 || h[0].LastError != "Upstream antwortete mit SERVFAIL" {
		t.Fatalf("bad: %+v", h[0])
	}
	if h[1].OK || h[1].Failures != 2 || h[1].LastError != "Zeitüberschreitung" {
		t.Fatalf("silent: %+v", h[1])
	}
	if !h[2].OK || h[2].Queries != 2 || h[2].Failures != 0 || h[2].LastError != "" || h[2].LastOK == 0 || h[2].AvgMS <= 0 {
		t.Fatalf("good: %+v", h[2])
	}

	// The registry survives a rebuild.
	r2 := newRouter(t, Config{Upstreams: []string{good.addr}})
	if h := r2.Health(); h[0].Queries != 2 {
		t.Fatalf("health lost on rebuild: %+v", h[0])
	}

	// Fallback answers do not show up in Health (main upstreams only) but are tracked.
	r3 := newRouter(t, Config{Upstreams: []string{bad.addr}, Fallback: []string{good.addr}})
	if _, _, err := r3.Resolve(context.Background(), query("example.org", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	if h := r3.Health(); len(h) != 1 || h[0].Address != bad.addr {
		t.Fatalf("health = %+v", h)
	}
	if healthFor(good.addr).snapshot(good.addr).Queries != 3 {
		t.Fatal("fallback exchange not tracked")
	}
}

func TestHealthRecovery(t *testing.T) {
	h := &healthState{}
	h.record(10*time.Millisecond, nil, time.Second)
	h.record(0, errorf("Zeitüberschreitung"), time.Second)
	s := h.snapshot("x")
	if s.OK || s.LastError != "Zeitüberschreitung" || s.Failures != 1 || s.Queries != 2 {
		t.Fatalf("%+v", s)
	}
	if s.AvgMS != 10 {
		t.Fatalf("avg = %v (failures must not change the shown average)", s.AvgMS)
	}
	w, _ := h.weight()
	if w <= 10 {
		t.Fatalf("weight %v should include the failure penalty", w)
	}
	h.record(20*time.Millisecond, nil, time.Second)
	s = h.snapshot("x")
	if !s.OK || s.LastError != "" || s.AvgMS != 13 {
		t.Fatalf("%+v", s)
	}
	// Cancelled exchanges are ignored.
	h.record(time.Millisecond, &upstreamError{msg: "Abgebrochen", err: context.Canceled}, time.Second)
	if s2 := h.snapshot("x"); s2.Queries != s.Queries {
		t.Fatal("cancelled exchange counted")
	}
}

func TestWeightedOrder(t *testing.T) {
	resetHealth()
	t.Cleanup(resetHealth)
	members := []member{
		{addr: "fast", health: healthFor("fast")},
		{addr: "slow", health: healthFor("slow")},
		{addr: "unknown", health: healthFor("unknown")},
		{addr: "failed", health: healthFor("failed")},
	}
	healthFor("fast").record(10*time.Millisecond, nil, time.Second)
	healthFor("slow").record(500*time.Millisecond, nil, time.Second)
	healthFor("failed").record(time.Millisecond, errors.New("x"), 4*time.Second)

	r := &Router{}
	r.rnd = newTestRand()
	first := map[string]int{}
	const n = 20000
	for range n {
		order := r.weightedOrder(members)
		if len(order) != len(members) {
			t.Fatalf("order %v", order)
		}
		seen := map[string]bool{}
		for _, m := range order {
			if seen[m.addr] {
				t.Fatalf("duplicate in %v", order)
			}
			seen[m.addr] = true
		}
		first[order[0].addr]++
	}
	// Weights: fast 1/10, slow 1/500, failed 1/4000, unknown = mean of those.
	if first["fast"] < first["unknown"] || first["unknown"] < first["slow"] || first["slow"] < first["failed"] {
		t.Fatalf("unexpected distribution %v", first)
	}
	if first["fast"] < n/2 {
		t.Fatalf("fast upstream picked first only %d of %d times", first["fast"], n)
	}
	if first["unknown"] < n/5 {
		t.Fatalf("unknown upstream got no fair chance: %v", first)
	}
	if first["failed"] == 0 || first["slow"] == 0 {
		t.Fatalf("slow/failed upstream never tried: %v", first)
	}

	// No measurements at all: uniform.
	resetHealth()
	fresh := []member{{addr: "a", health: healthFor("a")}, {addr: "b", health: healthFor("b")}}
	cnt := map[string]int{}
	for range n {
		cnt[r.weightedOrder(fresh)[0].addr]++
	}
	if cnt["a"] < n*4/10 || cnt["b"] < n*4/10 {
		t.Fatalf("not uniform: %v", cnt)
	}
}

// newTestRand is a deterministic, concurrency-safe random source.
func newTestRand() func() float64 {
	var mu sync.Mutex
	var x uint64 = 88172645463325252
	return func() float64 {
		mu.Lock()
		defer mu.Unlock()
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		return float64(x>>11) / float64(1<<53)
	}
}

func TestRouterLoadBalancePrefersFast(t *testing.T) {
	fast := newTestServer(t, answerA("192.0.2.1", 60))
	slow := newTestServer(t, slowHandler(60*time.Millisecond, answerA("192.0.2.2", 60)))
	r := newRouter(t, Config{Mode: "load_balance", Upstreams: []string{fast.addr, slow.addr}})
	for range 40 {
		if _, _, err := r.Resolve(context.Background(), query("example.org", dns.TypeA)); err != nil {
			t.Fatal(err)
		}
	}
	h := r.Health()
	if h[0].Queries <= h[1].Queries {
		t.Fatalf("fast %d vs slow %d queries", h[0].Queries, h[1].Queries)
	}
	if h[1].Queries == 0 {
		t.Fatal("slow upstream never measured")
	}
}

func TestRouterConcurrent(t *testing.T) {
	a := newTestServer(t, answerA("192.0.2.1", 60))
	b := newTestServer(t, answerA("192.0.2.2", 60))
	for _, mode := range []string{"load_balance", "parallel", "sequential"} {
		r := newRouter(t, Config{Mode: mode, Upstreams: []string{a.addr, b.addr}})
		var wg sync.WaitGroup
		for i := range 50 {
			wg.Go(func() {
				req := query("example.org", dns.TypeA)
				req.Id = uint16(i)
				resp, _, err := r.Resolve(context.Background(), req)
				if err != nil {
					t.Error(err)
					return
				}
				if resp.Id != uint16(i) {
					t.Errorf("id %d != %d", resp.Id, i)
				}
			})
		}
		wg.Wait()
		_ = r.Health()
	}
}

func TestRouterResolveErrors(t *testing.T) {
	good := newTestServer(t, answerA("192.0.2.1", 60))
	r := newRouter(t, Config{Upstreams: []string{good.addr}})
	if _, _, err := r.Resolve(context.Background(), new(dns.Msg)); err == nil {
		t.Fatal("empty question accepted")
	}
	if _, _, err := r.Resolve(context.Background(), nil); err == nil {
		t.Fatal("nil request accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := r.Resolve(ctx, query("example.org", dns.TypeA)); err == nil {
		t.Fatal("cancelled context answered")
	}
}

// The per-query budget of the DNS server is 2x the upstream timeout. Main upstreams that
// silently drop packets must not use it up completely: the fallback has to be asked.
func TestRouterFallbackGetsBudget(t *testing.T) {
	dead1 := newTestServer(t, silentHandler)
	dead2 := newTestServer(t, silentHandler)
	dead3 := newTestServer(t, silentHandler)
	good := newTestServer(t, answerA("192.0.2.9", 60))
	const timeout = 300 * time.Millisecond
	for _, mode := range []string{"load_balance", "sequential", "parallel"} {
		t.Run(mode, func(t *testing.T) {
			r := newRouter(t, Config{
				Mode:      mode,
				Upstreams: []string{dead1.addr, dead2.addr, dead3.addr},
				Fallback:  []string{dead3.addr, good.addr},
				Timeout:   timeout,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*timeout)
			defer cancel()
			resp, addr, err := r.Resolve(ctx, query("example.org", dns.TypeA))
			if err != nil {
				t.Fatalf("fallback not used: %v", err)
			}
			if addr != good.addr || firstA(t, resp) != "192.0.2.9" {
				t.Fatalf("answered by %s", addr)
			}
		})
	}
}

// Every main upstream is asked even when the first one never answers.
func TestRouterSequentialSharesBudget(t *testing.T) {
	dead := newTestServer(t, silentHandler)
	good := newTestServer(t, answerA("192.0.2.8", 60))
	r := newRouter(t, Config{Mode: "sequential", Upstreams: []string{dead.addr, good.addr}, Timeout: time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, addr, err := r.Resolve(ctx, query("example.org", dns.TypeA))
	if err != nil || addr != good.addr {
		t.Fatalf("addr %s err %v", addr, err)
	}
}
