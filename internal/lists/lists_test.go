package lists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
	"pk95dns/internal/filter"
	"pk95dns/internal/store"
)

// listServer serves one list body with an ETag and counts requests.
type listServer struct {
	mu       sync.Mutex
	body     string
	etag     string
	lastMod  string
	status   int
	size     int // > 0: serve that many bytes of "a"
	requests atomic.Int64
	lastReq  http.Header
	block    chan struct{}
}

func (s *listServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	s.mu.Lock()
	body, etag, lastMod, status, size, block := s.body, s.etag, s.lastMod, s.status, s.size, s.block
	s.lastReq = r.Header.Clone()
	s.mu.Unlock()
	if block != nil {
		<-block
	}
	if status != 0 && status != 200 {
		w.WriteHeader(status)
		return
	}
	if etag != "" {
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
	}
	if lastMod != "" {
		w.Header().Set("Last-Modified", lastMod)
	}
	if size > 0 {
		chunk := []byte(strings.Repeat("a", 1<<20))
		for written := 0; written < size; written += len(chunk) {
			n := min(len(chunk), size-written)
			if _, err := w.Write(chunk[:n]); err != nil {
				return
			}
		}
		return
	}
	_, _ = w.Write([]byte(body))
}

func (s *listServer) set(f func(s *listServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

func (s *listServer) header(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReq.Get(k)
}

type fixture struct {
	st      *store.Store
	eng     *filter.Engine
	m       *Manager
	dir     string
	srv     *httptest.Server
	ls      *listServer
	mu      sync.Mutex
	results []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fixture{st: st, eng: filter.NewEngine(), dir: dir, ls: &listServer{}}
	f.srv = httptest.NewServer(f.ls)
	t.Cleanup(f.srv.Close)
	f.m = NewManager(st, f.eng, dir, Options{
		UserAgent: "PK95-DNS/9.9.9",
		OnResult: func(l store.List, err string) {
			f.mu.Lock()
			f.results = append(f.results, l.Name+":"+err)
			f.mu.Unlock()
		},
	})
	t.Cleanup(func() { f.m.cancel(); f.m.wg.Wait() })
	return f
}

func (f *fixture) addList(t *testing.T, name, path, kind string, enabled bool) store.List {
	t.Helper()
	l, err := f.st.CreateList(store.List{Name: name, URL: f.srv.URL + path, Kind: kind, Enabled: enabled})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (f *fixture) refresh(t *testing.T, ids ...int64) {
	t.Helper()
	f.m.Refresh(ids...)
	f.m.wait()
}

func (f *fixture) get(t *testing.T, id int64) store.List {
	t.Helper()
	l, err := f.st.GetList(id)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (f *fixture) lastResult() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.results) == 0 {
		return ""
	}
	return f.results[len(f.results)-1]
}

func blocked(eng *filter.Engine, name string) bool {
	return eng.Check(filter.Request{Name: name, QType: dns.TypeA}).Action == filter.Block
}

func TestCatalog(t *testing.T) {
	c := Catalog()
	if len(c) < 12 {
		t.Fatalf("catalog has %d entries", len(c))
	}
	seen := map[string]bool{}
	allow := 0
	for _, e := range c {
		u, err := url.Parse(e.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			t.Errorf("%s: bad url %q", e.Name, e.URL)
		}
		if seen[e.URL] {
			t.Errorf("duplicate url %s", e.URL)
		}
		seen[e.URL] = true
		if e.Name == "" || e.Description == "" {
			t.Errorf("entry without name/description: %+v", e)
		}
		switch e.Kind {
		case "block":
		case "allow":
			allow++
		default:
			t.Errorf("%s: kind %q", e.Name, e.Kind)
		}
	}
	if allow == 0 {
		t.Error("no allow list in the catalog")
	}
	for _, want := range []string{
		"https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
		"https://small.oisd.nl/",
		"https://big.oisd.nl/",
		"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		"https://adaway.org/hosts.txt",
		"https://phishing.army/download/phishing_army_blocklist.txt",
	} {
		if !seen[want] {
			t.Errorf("catalog misses %s", want)
		}
	}
	c[0].Name = "changed"
	if Catalog()[0].Name == "changed" {
		t.Error("Catalog returns shared slice")
	}
}

func TestDownloadAndRebuild(t *testing.T) {
	f := newFixture(t)
	f.ls.set(func(s *listServer) {
		s.body = "! comment\n||ads.example.com^\n0.0.0.0 tracker.example.net\nbad$foo\n"
		s.etag = `"v1"`
		s.lastMod = "Mon, 02 Jan 2026 10:00:00 GMT"
	})
	l := f.addList(t, "Liste", "/a.txt", "block", true)
	f.refresh(t)

	got := f.get(t, l.ID)
	if got.RuleCount != 2 || got.LastError != "" || got.UpdatedAt == 0 || got.ETag != `"v1"` ||
		got.LastModified != "Mon, 02 Jan 2026 10:00:00 GMT" {
		t.Fatalf("status = %+v", got)
	}
	if ua := f.ls.header("User-Agent"); ua != "PK95-DNS/9.9.9" {
		t.Errorf("User-Agent = %q", ua)
	}
	if f.ls.header("If-None-Match") != "" {
		t.Error("conditional GET without local copy")
	}
	data, err := os.ReadFile(filepath.Join(f.dir, "lists", "1.txt"))
	if err != nil || !strings.Contains(string(data), "ads.example.com") {
		t.Fatalf("local copy: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "lists", "1.txt.tmp")); err == nil {
		t.Error("temp file left")
	}
	if !blocked(f.eng, "x.ads.example.com") || !blocked(f.eng, "tracker.example.net") {
		t.Error("rules not active after refresh")
	}
	if f.m.Updating(l.ID) {
		t.Error("still updating")
	}
	if r := f.lastResult(); r != "Liste:" {
		t.Errorf("OnResult = %q", r)
	}
}

func TestNotModified(t *testing.T) {
	f := newFixture(t)
	f.ls.set(func(s *listServer) { s.body = "||a.example^\n"; s.etag = `"e1"` })
	l := f.addList(t, "L", "/l", "block", true)
	f.refresh(t, l.ID)
	first := f.get(t, l.ID)

	time.Sleep(5 * time.Millisecond)
	f.ls.set(func(s *listServer) { s.body = "||changed.example^\n" }) // same ETag → 304
	f.refresh(t, l.ID)
	if f.ls.header("If-None-Match") != `"e1"` {
		t.Errorf("If-None-Match = %q", f.ls.header("If-None-Match"))
	}
	second := f.get(t, l.ID)
	if second.UpdatedAt <= first.UpdatedAt || second.RuleCount != 1 || second.ETag != `"e1"` {
		t.Fatalf("after 304: %+v (before %+v)", second, first)
	}
	data, _ := os.ReadFile(f.m.path(l.ID))
	if string(data) != "||a.example^\n" {
		t.Errorf("local copy changed on 304: %q", data)
	}
}

func TestIfModifiedSince(t *testing.T) {
	f := newFixture(t)
	f.ls.set(func(s *listServer) { s.body = "a.example\n"; s.lastMod = "Tue, 03 Feb 2026 08:00:00 GMT" })
	l := f.addList(t, "L", "/l", "block", true)
	f.refresh(t, l.ID)
	f.refresh(t, l.ID)
	if got := f.ls.header("If-Modified-Since"); got != "Tue, 03 Feb 2026 08:00:00 GMT" {
		t.Errorf("If-Modified-Since = %q", got)
	}
}

func TestFailuresKeepOldCopy(t *testing.T) {
	tests := []struct {
		name  string
		setup func(s *listServer)
		want  string
	}{
		{"http 404", func(s *listServer) { s.status = 404 }, "HTTP 404"},
		{"http 500", func(s *listServer) { s.status = 500 }, "HTTP 500"},
		{"empty", func(s *listServer) { s.body = "" }, "Die Liste ist leer"},
		{"no rules", func(s *listServer) { s.body = "<html>nope</html>\n" }, "Die Liste enthält keine gültigen Regeln"},
		{"too big", func(s *listServer) { s.size = maxListSize + 10 }, "Liste ist größer als 64 MiB"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.ls.set(func(s *listServer) { s.body = "||old.example^\n" })
			l := f.addList(t, "L", "/l", "block", true)
			f.refresh(t, l.ID)
			before := f.get(t, l.ID)

			f.ls.set(func(s *listServer) { s.body = ""; s.status = 0; s.size = 0; tc.setup(s) })
			f.refresh(t, l.ID)
			got := f.get(t, l.ID)
			if got.LastError != tc.want {
				t.Errorf("last_error = %q, want %q", got.LastError, tc.want)
			}
			if got.RuleCount != 1 || got.UpdatedAt != before.UpdatedAt {
				t.Errorf("status changed: %+v", got)
			}
			if !blocked(f.eng, "old.example") {
				t.Error("old copy no longer active")
			}
			data, _ := os.ReadFile(f.m.path(l.ID))
			if string(data) != "||old.example^\n" {
				t.Errorf("local copy = %q", data)
			}
			if r := f.lastResult(); r != "L:"+tc.want {
				t.Errorf("OnResult = %q", r)
			}

			// Recovery clears the error.
			f.ls.set(func(s *listServer) { s.status = 0; s.size = 0; s.body = "||new.example^\n" })
			f.refresh(t, l.ID)
			got = f.get(t, l.ID)
			if got.LastError != "" || !blocked(f.eng, "new.example") || blocked(f.eng, "old.example") {
				t.Errorf("after recovery: %+v", got)
			}
		})
	}
}

func TestFailureWithoutCopy(t *testing.T) {
	f := newFixture(t)
	f.ls.set(func(s *listServer) { s.status = 404 })
	l := f.addList(t, "L", "/l", "block", true)
	f.refresh(t, l.ID)
	got := f.get(t, l.ID)
	if got.LastError != "HTTP 404" || got.UpdatedAt != 0 {
		t.Fatalf("got %+v", got)
	}
	if _, err := os.Stat(f.m.path(l.ID)); err == nil {
		t.Error("file written for failed download")
	}
}

func TestNetworkError(t *testing.T) {
	f := newFixture(t)
	l, err := f.st.CreateList(store.List{Name: "L", URL: "http://127.0.0.1:1/x", Kind: "block", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	f.refresh(t, l.ID)
	if got := f.get(t, l.ID); !strings.HasPrefix(got.LastError, "Download fehlgeschlagen") {
		t.Errorf("last_error = %q", got.LastError)
	}
}

func TestTimeout(t *testing.T) {
	f := newFixture(t)
	f.m.client = &http.Client{Timeout: 50 * time.Millisecond}
	block := make(chan struct{})
	defer close(block)
	f.ls.set(func(s *listServer) { s.body = "a.example\n"; s.block = block })
	l := f.addList(t, "L", "/l", "block", true)
	f.refresh(t, l.ID)
	if got := f.get(t, l.ID); got.LastError != "Zeitüberschreitung beim Herunterladen" {
		t.Errorf("last_error = %q", got.LastError)
	}
}

func TestRebuildEnabledAndAllow(t *testing.T) {
	f := newFixture(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/block", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("||example.org^\n||other.example^\n"))
	})
	mux.HandleFunc("/allow", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("||good.example.org^\n"))
	})
	f.srv.Config.Handler = mux
	b := f.addList(t, "B", "/block", "block", true)
	a := f.addList(t, "A", "/allow", "allow", true)
	f.refresh(t)

	if !blocked(f.eng, "ads.example.org") {
		t.Error("block list not active")
	}
	if r := f.eng.Check(filter.Request{Name: "good.example.org", QType: dns.TypeA}); r.Action != filter.Allow || r.ListID != a.ID {
		t.Errorf("allow list: %+v", r)
	}
	if r := f.eng.Check(filter.Request{Name: "other.example", QType: dns.TypeA}); r.ListID != b.ID || r.Reason != filter.ReasonList {
		t.Errorf("list id: %+v", r)
	}

	// Disable the block list.
	b.Enabled = false
	if err := f.st.UpdateList(b); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Rebuild(); err != nil {
		t.Fatal(err)
	}
	if blocked(f.eng, "ads.example.org") {
		t.Error("disabled list still active")
	}

	// Refresh() without ids only downloads enabled lists.
	before := f.get(t, b.ID).UpdatedAt
	time.Sleep(5 * time.Millisecond)
	f.refresh(t)
	if f.get(t, b.ID).UpdatedAt != before {
		t.Error("disabled list downloaded by Refresh()")
	}
}

func TestForget(t *testing.T) {
	f := newFixture(t)
	f.ls.set(func(s *listServer) { s.body = "||gone.example^\n" })
	l := f.addList(t, "L", "/l", "block", true)
	f.refresh(t, l.ID)
	if err := f.st.DeleteList(l.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Forget(l.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.m.path(l.ID)); err == nil {
		t.Error("file still there")
	}
	if blocked(f.eng, "gone.example") {
		t.Error("forgotten list still active")
	}
	if err := f.m.Forget(999); err != nil {
		t.Errorf("Forget unknown: %v", err)
	}
}

func TestUpdatingAndNoDoubleQueue(t *testing.T) {
	f := newFixture(t)
	block := make(chan struct{})
	f.ls.set(func(s *listServer) { s.body = "a.example\n"; s.block = block })
	l := f.addList(t, "L", "/l", "block", true)
	f.m.Refresh(l.ID)
	f.m.Refresh(l.ID)
	f.m.Refresh(l.ID)
	if !f.m.Updating(l.ID) {
		t.Fatal("not updating")
	}
	deadline := time.Now().Add(2 * time.Second)
	for f.ls.requests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(block)
	f.m.wait()
	if n := f.ls.requests.Load(); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
	if f.m.Updating(l.ID) {
		t.Error("still updating after the worker finished")
	}
}

func TestListRemovedWhileDownloading(t *testing.T) {
	f := newFixture(t)
	block := make(chan struct{})
	f.ls.set(func(s *listServer) { s.body = "a.example\n"; s.block = block })
	l := f.addList(t, "L", "/l", "block", true)
	f.m.Refresh(l.ID)
	deadline := time.Now().Add(2 * time.Second)
	for f.ls.requests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if err := f.st.DeleteList(l.ID); err != nil {
		t.Fatal(err)
	}
	close(block)
	f.m.wait()
	if _, err := os.Stat(f.m.path(l.ID)); err == nil {
		t.Error("file of a removed list left behind")
	}
}

func TestDue(t *testing.T) {
	f := newFixture(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f.m.now = func() time.Time { return now }
	mk := func(name string, enabled bool, updated time.Time) store.List {
		l := f.addList(t, name, "/"+name, "block", enabled)
		var ms int64
		if !updated.IsZero() {
			ms = updated.UnixMilli()
		}
		if err := f.st.SetListStatus(l.ID, 1, ms, "", "", ""); err != nil && ms != 0 {
			t.Fatal(err)
		}
		return l
	}
	fresh := mk("fresh", true, now.Add(-time.Hour))
	old := mk("old", true, now.Add(-25*time.Hour))
	never := mk("never", true, time.Time{})
	off := mk("off", false, now.Add(-100*time.Hour))
	_ = fresh
	_ = off

	got := f.m.due(24)
	if len(got) != 2 || got[0] != old.ID && got[1] != old.ID {
		t.Fatalf("due(24) = %v, want old and never", got)
	}
	if f.m.due(0) != nil {
		t.Error("due(0) must be empty")
	}
	// A recent failed attempt delays the retry.
	f.m.attempts[never.ID] = now.Add(-10 * time.Minute)
	got = f.m.due(24)
	if len(got) != 1 || got[0] != old.ID {
		t.Fatalf("due after attempt = %v", got)
	}
	f.m.attempts[never.ID] = now.Add(-61 * time.Minute)
	if got = f.m.due(24); len(got) != 2 {
		t.Fatalf("due after retry interval = %v", got)
	}
}

func TestRunDownloadsMissingAndStops(t *testing.T) {
	f := newFixture(t)
	f.ls.set(func(s *listServer) { s.body = "||run.example^\n" })
	l := f.addList(t, "L", "/l", "block", true)
	off := f.addList(t, "Off", "/off", "block", false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.m.Run(ctx, func() config.Settings { return config.Defaults() })
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !blocked(f.eng, "run.example") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !blocked(f.eng, "run.example") {
		t.Fatal("Run did not download the missing list")
	}
	if f.get(t, off.ID).UpdatedAt != 0 {
		t.Error("disabled list downloaded")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	// After Run ended, Refresh is a no-op.
	n := f.ls.requests.Load()
	f.m.Refresh(l.ID)
	f.m.wait()
	if f.ls.requests.Load() != n {
		t.Error("download after Run ended")
	}
}

func TestRunPeriodic(t *testing.T) {
	f := newFixture(t)
	f.m.interval = 20 * time.Millisecond
	f.ls.set(func(s *listServer) { s.body = "||p.example^\n" })
	l := f.addList(t, "L", "/l", "block", true)
	f.refresh(t, l.ID)
	// Pretend the list is old.
	if err := f.st.SetListStatus(l.ID, 1, time.Now().Add(-48*time.Hour).UnixMilli(), "", "", ""); err != nil {
		t.Fatal(err)
	}
	n := f.ls.requests.Load()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.m.Run(ctx, func() config.Settings { s := config.Defaults(); s.ListsUpdateHours = 24; return s })
	deadline := time.Now().Add(5 * time.Second)
	for f.ls.requests.Load() == n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if f.ls.requests.Load() == n {
		t.Fatal("old list not refreshed by Run")
	}
}

// An https list must not be fetched over http after a redirect.
func TestRedirectDowngradeRefused(t *testing.T) {
	f := newFixture(t)
	f.ls.set(func(s *listServer) { s.body = "203.0.113.66 www.bank.example\n" })
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/down":
			http.Redirect(w, r, f.srv.URL+"/l", http.StatusMovedPermanently)
		case "/up":
			http.Redirect(w, r, "/list", http.StatusFound)
		default:
			_, _ = w.Write([]byte("203.0.113.7 nas.example\n"))
		}
	}))
	defer tlsSrv.Close()
	m := NewManager(f.st, f.eng, f.dir, Options{HTTP: tlsSrv.Client()})
	t.Cleanup(func() { m.cancel(); m.wg.Wait() })

	down, err := f.st.CreateList(store.List{Name: "Down", URL: tlsSrv.URL + "/down", Kind: "block", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	up, err := f.st.CreateList(store.List{Name: "Up", URL: tlsSrv.URL + "/up", Kind: "block", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	m.Refresh(down.ID, up.ID)
	m.wait()
	if n := f.ls.requests.Load(); n != 0 {
		t.Fatalf("http server asked %d times after an https redirect", n)
	}
	if l := f.get(t, down.ID); !strings.Contains(l.LastError, "Weiterleitung") {
		t.Fatalf("downgrade not reported: %+v", l)
	}
	// https → https redirects work, and https lists may rewrite.
	if l := f.get(t, up.ID); l.LastError != "" || l.RuleCount != 1 {
		t.Fatalf("https redirect: %+v", l)
	}
	if r := f.eng.Check(filter.Request{Name: "nas.example", QType: dns.TypeA}); r.Action != filter.Rewrite {
		t.Fatalf("https list rewrite: %+v", r)
	}
}

// Hosts lines of lists fetched over http block instead of rewriting.
func TestHTTPListCannotRewrite(t *testing.T) {
	f := newFixture(t)
	f.ls.set(func(s *listServer) { s.body = "203.0.113.66 www.bank.example\n" })
	f.addList(t, "L", "/l", "block", true)
	f.refresh(t)
	if r := f.eng.Check(filter.Request{Name: "www.bank.example", QType: dns.TypeA}); r.Action != filter.Block {
		t.Fatalf("http list: %+v", r)
	}
}

// Changing a list's address while its download runs fetches the new address afterwards and
// drops what came from the old one (the PUT /api/lists/{id} sequence).
func TestURLChangedWhileDownloading(t *testing.T) {
	f := newFixture(t)
	block := make(chan struct{})
	var oldReqs, newReqs atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/old.txt", func(w http.ResponseWriter, _ *http.Request) {
		oldReqs.Add(1)
		<-block
		w.Header().Set("ETag", `"old"`)
		_, _ = w.Write([]byte("||old.example^\n"))
	})
	mux.HandleFunc("/new.txt", func(w http.ResponseWriter, r *http.Request) {
		newReqs.Add(1)
		if r.Header.Get("If-None-Match") != "" {
			t.Errorf("conditional GET to the new address: %q", r.Header.Get("If-None-Match"))
		}
		w.Header().Set("ETag", `"new"`)
		_, _ = w.Write([]byte("||new.example^\n"))
	})
	f.srv.Config.Handler = mux
	l := f.addList(t, "L", "/old.txt", "block", true)
	f.m.Refresh(l.ID)
	deadline := time.Now().Add(2 * time.Second)
	for oldReqs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	l.URL = f.srv.URL + "/new.txt"
	if err := f.st.UpdateList(l); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetListStatus(l.ID, 0, 0, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Forget(l.ID); err != nil {
		t.Fatal(err)
	}
	f.m.Reload(l.ID)
	close(block)
	f.m.wait()

	if newReqs.Load() != 1 {
		t.Fatalf("new address asked %d times", newReqs.Load())
	}
	if got := f.get(t, l.ID); got.ETag != `"new"` {
		t.Fatalf("status = %+v", got)
	}
	data, _ := os.ReadFile(f.m.path(l.ID))
	if !strings.Contains(string(data), "new.example") {
		t.Fatalf("local copy %q", data)
	}
	if blocked(f.eng, "old.example") || !blocked(f.eng, "new.example") {
		t.Fatal("rules of the old address active")
	}
}

func TestReloadIdleList(t *testing.T) {
	f := newFixture(t)
	f.ls.set(func(s *listServer) { s.body = "a.example\n" })
	l := f.addList(t, "L", "/l", "block", true)
	f.m.Reload(l.ID)
	f.m.wait()
	if n := f.ls.requests.Load(); n != 1 {
		t.Fatalf("requests = %d", n)
	}
}
