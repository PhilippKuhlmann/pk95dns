package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"pk95dns/internal/api"
	"pk95dns/internal/config"
	"pk95dns/internal/store"
	"pk95dns/internal/upstream"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "pk95dns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestFirstStart(t *testing.T) {
	st := openStore(t)
	if err := firstStart(st); err != nil {
		t.Fatal(err)
	}
	ls, err := st.Lists()
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 2 {
		t.Fatalf("lists = %+v", ls)
	}
	byName := map[string]store.List{}
	for _, l := range ls {
		byName[l.Name] = l
	}
	if l := byName["AdGuard DNS filter"]; l.URL != "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt" || !l.Enabled || l.Kind != "block" {
		t.Errorf("adguard = %+v", l)
	}
	if l := byName["OISD Small"]; l.URL != "https://small.oisd.nl/" || l.Enabled {
		t.Errorf("oisd = %+v", l)
	}

	// The user removes all lists: they must not come back.
	for _, l := range ls {
		if err := st.DeleteList(l.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := firstStart(st); err != nil {
		t.Fatal(err)
	}
	if ls, _ := st.Lists(); len(ls) != 0 {
		t.Errorf("lists recreated: %+v", ls)
	}
}

func TestFirstStartKeepsExistingLists(t *testing.T) {
	st := openStore(t)
	if _, err := st.CreateList(store.List{Name: "Mine", URL: "https://x.example/l", Kind: "block"}); err != nil {
		t.Fatal(err)
	}
	if err := firstStart(st); err != nil {
		t.Fatal(err)
	}
	if ls, _ := st.Lists(); len(ls) != 1 {
		t.Errorf("lists = %+v", ls)
	}
}

func TestRouterConfig(t *testing.T) {
	s := config.Defaults()
	s.Conditional = []config.Conditional{{Domain: "fritz.box", Upstream: "192.168.178.1"}}
	s.PrivateUpstreams = []string{"192.168.178.1"}
	s.UpstreamTimeoutMS = 2500
	s.UpstreamMode = config.ModeParallel
	c := routerConfig(s)
	if len(c.Routes) != 1 || c.Routes[0] != (upstream.Route{Domain: "fritz.box", Upstream: "192.168.178.1"}) ||
		c.Timeout != 2500*time.Millisecond || c.Mode != "parallel" || !c.PrivatePTR ||
		len(c.PrivateUpstreams) != 1 || len(c.Upstreams) != len(s.Upstreams) || len(c.Bootstrap) != len(s.Bootstrap) {
		t.Errorf("config = %+v", c)
	}
	// No aliasing with the settings.
	c.Upstreams[0] = "changed"
	if s.Upstreams[0] == "changed" {
		t.Error("upstreams aliased")
	}
}

func TestMonitor(t *testing.T) {
	t0 := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	bad := func(lastOK time.Time) upstream.Health {
		h := upstream.Health{Address: "a", Queries: 10, Failures: 5}
		if !lastOK.IsZero() {
			h.LastOK = lastOK.UnixMilli()
		}
		return h
	}
	good := upstream.Health{Address: "b", OK: true, Queries: 10}
	unused := upstream.Health{Address: "c"}

	steps := []struct {
		name   string
		health []upstream.Health
		at     time.Duration
		want   string
	}{
		{"no upstreams", nil, 0, ""},
		{"one good", []upstream.Health{bad(time.Time{}), good}, 0, ""},
		{"unused upstream", []upstream.Health{bad(time.Time{}), unused}, 10 * time.Second, ""},
		{"all bad starts", []upstream.Health{bad(time.Time{}), bad(time.Time{})}, 20 * time.Second, ""},
		{"all bad 50s", []upstream.Health{bad(time.Time{}), bad(time.Time{})}, 70 * time.Second, ""},
		{"all bad 60s", []upstream.Health{bad(time.Time{}), bad(time.Time{})}, 80 * time.Second, "down"},
		{"still down", []upstream.Health{bad(time.Time{}), bad(time.Time{})}, 90 * time.Second, ""},
		{"recovered", []upstream.Health{bad(time.Time{}), good}, 100 * time.Second, "up"},
		{"stays up", []upstream.Health{good}, 110 * time.Second, ""},
		{"bad but recent ok", []upstream.Health{bad(t0.Add(100 * time.Second))}, 120 * time.Second, ""},
		{"bad, ok too old", []upstream.Health{bad(t0.Add(100 * time.Second))}, 170 * time.Second, ""},
		{"bad 60s later", []upstream.Health{bad(t0.Add(100 * time.Second))}, 230 * time.Second, "down"},
	}
	var m upstreamMonitor
	for _, s := range steps {
		if got := m.check(s.health, t0.Add(s.at)); got != s.want {
			t.Errorf("%s: %q, want %q", s.name, got, s.want)
		}
	}
}

// coreServer records events.
type coreServer struct {
	mu     sync.Mutex
	events []event
	status atomic.Int32
	auth   []string
	ctype  []string
}

func (c *coreServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/events" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.auth = append(c.auth, r.Header.Get("Authorization"))
	c.ctype = append(c.ctype, r.Header.Get("Content-Type"))
	c.mu.Unlock()
	st := int(c.status.Load())
	if st == 0 {
		st = http.StatusAccepted
	}
	if st == http.StatusAccepted {
		var ev event
		if err := json.Unmarshal(body, &ev); err == nil {
			c.mu.Lock()
			c.events = append(c.events, ev)
			c.mu.Unlock()
		}
	}
	w.WriteHeader(st)
}

func (c *coreServer) got() []event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]event(nil), c.events...)
}

func TestEventSender(t *testing.T) {
	core := &coreServer{}
	srv := httptest.NewServer(core)
	defer srv.Close()
	s := newEventSender(srv.URL+"/", "tok-123")
	now := time.Date(2026, 11, 9, 10, 41, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	s.send("dns.listen_failed", sevCritical, "Titel", "Text", map[string]any{"listen": ":53"})
	s.deliver(context.Background())
	evs := core.got()
	if len(evs) != 1 {
		t.Fatalf("events = %+v", evs)
	}
	ev := evs[0]
	if ev.Type != "dns.listen_failed" || ev.Severity != "critical" || ev.Title != "Titel" || ev.Body != "Text" ||
		ev.OccurredAt != "2026-11-09T10:41:00Z" || ev.Data["listen"] != ":53" {
		t.Errorf("event = %+v", ev)
	}
	if core.auth[0] != "Bearer tok-123" || core.ctype[0] != "application/json" {
		t.Errorf("headers %v %v", core.auth, core.ctype)
	}
	if s.pending() != 0 {
		t.Error("queue not empty")
	}

	// Core down: kept and retried in order.
	core.status.Store(http.StatusServiceUnavailable)
	s.send("a", sevInfo, "1", "", nil)
	s.send("b", sevInfo, "2", "", nil)
	s.deliver(context.Background())
	if s.pending() != 2 {
		t.Fatalf("pending = %d", s.pending())
	}
	core.status.Store(0)
	s.deliver(context.Background())
	evs = core.got()
	if s.pending() != 0 || len(evs) != 3 || evs[1].Type != "a" || evs[2].Type != "b" {
		t.Fatalf("after retry: %d pending, %+v", s.pending(), evs)
	}
	if evs[1].Data == nil {
		t.Error("data must be an object, not null")
	}

	// 422: dropped, not retried.
	core.status.Store(http.StatusUnprocessableEntity)
	s.send("bad", sevInfo, "x", "", nil)
	s.deliver(context.Background())
	if s.pending() != 0 {
		t.Error("422 event kept")
	}

	// Older than one hour: dropped.
	core.status.Store(http.StatusInternalServerError)
	s.send("old", sevInfo, "x", "", nil)
	now = now.Add(61 * time.Minute)
	core.status.Store(0)
	s.deliver(context.Background())
	if s.pending() != 0 || len(core.got()) != 3 {
		t.Errorf("old event delivered: %+v", core.got())
	}
}

func TestEventSenderQueueLimit(t *testing.T) {
	s := newEventSender("http://127.0.0.1:1", "x")
	for i := 0; i < eventMaxQueue+20; i++ {
		s.send("e", sevInfo, "t", "", map[string]any{"i": i})
	}
	if s.pending() != eventMaxQueue {
		t.Fatalf("pending = %d", s.pending())
	}
	if first := s.queue[0].ev.Data["i"]; first != 20 {
		t.Errorf("oldest kept = %v", first)
	}
}

func TestEventSenderRun(t *testing.T) {
	core := &coreServer{}
	core.status.Store(http.StatusBadGateway)
	srv := httptest.NewServer(core)
	defer srv.Close()
	s := newEventSender(srv.URL, "tok")
	s.retry = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.run(ctx); close(done) }()
	s.send("x", sevWarning, "t", "b", nil)
	time.Sleep(50 * time.Millisecond)
	core.status.Store(0) // Core is back: the retry ticker delivers
	deadline := time.Now().Add(3 * time.Second)
	for len(core.got()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(core.got()) != 1 {
		t.Fatal("event not delivered after retry")
	}
	cancel()
	<-done

	// A nil sender (standalone) is a no-op.
	var nilSender *eventSender
	nilSender.send("x", sevInfo, "t", "", nil)
	nilSender.run(context.Background())
}

func TestListFailureEventsOncePerList(t *testing.T) {
	core := &coreServer{}
	srv := httptest.NewServer(core)
	defer srv.Close()
	a := &app{failedLists: map[int64]bool{}, events: newEventSender(srv.URL, "t")}
	l := store.List{ID: 3, Name: "AdGuard", URL: "https://x.example/l"}
	a.onListResult(l, "HTTP 404")
	a.onListResult(l, "HTTP 404")
	a.onListResult(store.List{ID: 4, Name: "Other"}, "HTTP 500")
	a.onListResult(l, "")
	a.onListResult(l, "Zeitüberschreitung beim Herunterladen")
	if n := a.events.pending(); n != 3 {
		t.Fatalf("queued = %d, want 3", n)
	}
	a.events.deliver(context.Background())
	evs := core.got()
	if evs[0].Type != api.EventListUpdateFailed || evs[0].Severity != "warning" || !strings.Contains(evs[0].Title, "AdGuard") ||
		evs[0].Data["list_id"] != float64(3) {
		t.Errorf("event = %+v", evs[0])
	}
}

func TestListenEvents(t *testing.T) {
	a := &app{cfg: Config{DNSListen: ":53"}, events: newEventSender("http://127.0.0.1:1", "t")}
	a.onListen(false, "Port 53 ist belegt")
	a.onListen(true, "")
	if a.events.pending() != 2 {
		t.Fatal("events not queued")
	}
	q := a.events.queue
	if q[0].ev.Type != api.EventDNSListenFailed || q[0].ev.Severity != "critical" || !strings.Contains(q[0].ev.Body, "Port 53") {
		t.Errorf("failed event %+v", q[0].ev)
	}
	if q[1].ev.Type != api.EventDNSListenOK || q[1].ev.Severity != "info" {
		t.Errorf("ok event %+v", q[1].ev)
	}
}

// testConfig is a Config for a temp data dir (no network needed).
func testConfig(t *testing.T, core bool) Config {
	return Config{
		Version:   "1.0.0-test",
		Listen:    "127.0.0.1:0",
		DNSListen: "127.0.0.1:0",
		DataDir:   filepath.Join(t.TempDir(), "data"),
		CoreMode:  core,
		CoreURL:   "http://127.0.0.1:1",
		CoreToken: strings.Repeat("t", 48),
	}
}

func TestNewAppStandalone(t *testing.T) {
	cfg := testConfig(t, false)
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.st.Close()
	for _, p := range []string{cfg.DataDir, filepath.Join(cfg.DataDir, "lists")} {
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o750 {
			t.Errorf("%s: %v %v", p, fi.Mode(), err)
		}
	}
	if _, err := os.Stat(api.InitialPasswordFile(cfg.DataDir)); err != nil {
		t.Errorf("initial password file: %v", err)
	}
	if n, _ := a.st.UserCount(); n != 1 {
		t.Errorf("users = %d", n)
	}
	if a.events != nil {
		t.Error("events in standalone mode")
	}
	if ls, _ := a.st.Lists(); len(ls) != 2 {
		t.Errorf("default lists = %d", len(ls))
	}
	if a.router.Load() == nil {
		t.Error("no router")
	}
}

func TestNewAppCoreModeNoAdmin(t *testing.T) {
	cfg := testConfig(t, true)
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.st.Close()
	if n, _ := a.st.UserCount(); n != 0 {
		t.Errorf("users in Core mode = %d", n)
	}
	if a.events == nil {
		t.Error("no event sender in Core mode")
	}
}

func TestUpdateSettings(t *testing.T) {
	a, err := newApp(testConfig(t, true))
	if err != nil {
		t.Fatal(err)
	}
	defer a.st.Close()
	builds := 0
	real := a.newRouter
	a.newRouter = func(c upstream.Config) (*upstream.Router, error) {
		builds++
		return real(c)
	}
	oldRouter := a.router.Load()

	// Not upstream-related: same router.
	if err := a.updateSettings(func(s *config.Settings) error { s.Ratelimit = 7; return nil }); err != nil {
		t.Fatal(err)
	}
	if builds != 0 || a.router.Load() != oldRouter || a.currentSettings().Ratelimit != 7 {
		t.Errorf("builds=%d router changed=%v", builds, a.router.Load() != oldRouter)
	}
	if s, _ := a.st.LoadSettings(); s.Ratelimit != 7 {
		t.Error("not stored")
	}

	// Upstream change: new router.
	if err := a.updateSettings(func(s *config.Settings) error { s.UpstreamTimeoutMS = 1500; return nil }); err != nil {
		t.Fatal(err)
	}
	if builds != 1 || a.router.Load() == oldRouter {
		t.Errorf("router not rebuilt: builds=%d", builds)
	}

	// Router error: old router and settings stay, nothing stored.
	keep := a.router.Load()
	a.newRouter = func(upstream.Config) (*upstream.Router, error) { return nil, errors.New("kaputt") }
	err = a.updateSettings(func(s *config.Settings) error { s.UpstreamTimeoutMS = 2000; return nil })
	var ie *api.InvalidError
	if !errors.As(err, &ie) || !strings.Contains(ie.Msg, "kaputt") {
		t.Fatalf("err = %v", err)
	}
	if a.router.Load() != keep || a.currentSettings().UpstreamTimeoutMS != 1500 {
		t.Error("state changed after router error")
	}
	if s, _ := a.st.LoadSettings(); s.UpstreamTimeoutMS != 1500 {
		t.Error("stored after router error")
	}

	// Mutate errors pass through.
	want := errors.New("nope")
	if err := a.updateSettings(func(*config.Settings) error { return want }); err != want {
		t.Errorf("mutate error = %v", err)
	}
	if err := a.reload(); err != nil {
		t.Errorf("reload: %v", err)
	}
}

// Stored upstreams the router rejects: the app starts with the default upstreams, and
// settings changes that do not touch the upstreams keep working.
func TestUnusableStoredUpstreams(t *testing.T) {
	cfg := testConfig(t, true)
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "pk95dns.db"))
	if err != nil {
		t.Fatal(err)
	}
	bad := config.Defaults()
	bad.Upstreams = []string{"bogus://dns.example"}
	if err := st.SaveSettings(bad); err != nil {
		t.Fatal(err)
	}
	st.Close()

	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.st.Close()
	fallback := a.router.Load()
	if fallback == nil {
		t.Fatal("no router")
	}
	for name, mutate := range map[string]func(s *config.Settings){
		"ratelimit": func(s *config.Settings) { s.Ratelimit = 7 },
		"pause": func(s *config.Settings) {
			s.ProtectionEnabled, s.ProtectionPausedUntil = false, time.Now().Add(time.Hour).UnixMilli()
		},
		"services": func(s *config.Settings) { s.BlockedServices = []string{"tiktok"} },
	} {
		if err := a.updateSettings(func(s *config.Settings) error { mutate(s); return nil }); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if a.router.Load() != fallback {
			t.Fatalf("%s: router replaced", name)
		}
	}
	// Changing the upstreams to something usable builds a new router.
	if err := a.updateSettings(func(s *config.Settings) error {
		s.Upstreams = []string{"https://dns.quad9.net/dns-query"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if a.router.Load() == fallback {
		t.Fatal("router not rebuilt after fixing the upstreams")
	}
}

func TestCheckPause(t *testing.T) {
	a, err := newApp(testConfig(t, true))
	if err != nil {
		t.Fatal(err)
	}
	defer a.st.Close()
	now := time.Now()
	a.now = func() time.Time { return now }
	until := now.Add(time.Minute).UnixMilli()
	if err := a.updateSettings(func(s *config.Settings) error {
		s.ProtectionEnabled, s.ProtectionPausedUntil = false, until
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.checkPause()
	if s := a.currentSettings(); s.ProtectionEnabled || s.ProtectionPausedUntil != until {
		t.Fatalf("pause ended early: %+v", s.ProtectionPausedUntil)
	}
	now = now.Add(2 * time.Minute)
	a.checkPause()
	s := a.currentSettings()
	if !s.ProtectionEnabled || s.ProtectionPausedUntil != 0 {
		t.Errorf("pause not ended: %v %v", s.ProtectionEnabled, s.ProtectionPausedUntil)
	}
	if stored, _ := a.st.LoadSettings(); !stored.ProtectionEnabled || stored.ProtectionPausedUntil != 0 {
		t.Error("end of pause not stored")
	}
}

func TestRunServesAndShutsDown(t *testing.T) {
	cfg := testConfig(t, true)
	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// No downloads from the internet in tests.
	ls, _ := a.st.Lists()
	for _, l := range ls {
		if err := a.st.DeleteList(l.ID); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.run(ctx, ln) }()

	base := "http://" + ln.Addr().String()
	resp, err := http.Get(base + "/core/health")
	if err != nil {
		t.Fatal(err)
	}
	var health map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&health)
	resp.Body.Close()
	if resp.StatusCode != 200 || health["version"] != "1.0.0-test" {
		t.Errorf("health %d %v", resp.StatusCode, health)
	}
	req, _ := http.NewRequest("GET", base+"/api/status", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.CoreToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status %d", resp.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not stop")
	}
	if err := a.st.Ping(); err == nil {
		t.Error("store still open after shutdown")
	}
}

func TestRunHTTPPortBusy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := testConfig(t, true)
	cfg.Listen = ln.Addr().String()
	err = Run(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "HTTP-Port") {
		t.Errorf("err = %v", err)
	}
}

// A query in flight at shutdown is answered and still written to the query log and the
// statistics: the final flushes run after the DNS server stopped.
func TestShutdownLogsQueryInFlight(t *testing.T) {
	cfg := testConfig(t, true)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
	cfg.DNSListen = pc.LocalAddr().String()

	// Slow upstream: answers 500 ms after it saw the query.
	upPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan struct{}, 1)
	up := &dns.Server{PacketConn: upPC, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		select {
		case seen <- struct{}{}:
		default:
		}
		time.Sleep(500 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(r)
		rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 192.0.2.77")
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = up.ActivateAndServe() }()
	t.Cleanup(func() { _ = up.Shutdown() })

	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ls, _ := a.st.Lists()
	for _, l := range ls {
		_ = a.st.DeleteList(l.ID)
	}
	if err := a.updateSettings(func(s *config.Settings) error {
		s.Upstreams, s.Fallback = []string{upPC.LocalAddr().String()}, nil
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.run(ctx, ln) }()
	deadline := time.Now().Add(5 * time.Second)
	for !a.dns.Status().UDP && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	answered := make(chan error, 1)
	go func() {
		m := new(dns.Msg)
		m.SetQuestion("inflight.example.", dns.TypeA)
		c := &dns.Client{Timeout: 5 * time.Second}
		_, _, err := c.Exchange(m, cfg.DNSListen)
		answered <- err
	}()
	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("query did not reach the upstream")
	}
	cancel()
	if err := <-answered; err != nil {
		t.Errorf("query in flight not answered: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not stop")
	}

	st, err := store.Open(filepath.Join(cfg.DataDir, "pk95dns.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	qs, err := st.Queries(store.QueryFilter{Search: "inflight.example"})
	if err != nil || len(qs) != 1 {
		t.Fatalf("query log: %v %v", qs, err)
	}
	now := time.Now().Unix()
	hs, err := st.LoadHours(now-2*3600, now+3600)
	var total int64
	for _, h := range hs {
		total += int64(h.Queries)
	}
	if err != nil || total != 1 {
		t.Fatalf("statistics: %+v %v", hs, err)
	}
}
