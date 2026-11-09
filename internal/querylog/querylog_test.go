package querylog

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pk95dns/internal/config"
	"pk95dns/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func count(t *testing.T, st *store.Store) int {
	t.Helper()
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM queries`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// settingsVar is a concurrency-safe settings source for Run.
type settingsVar struct {
	v atomic.Pointer[config.Settings]
}

func newSettings(mut func(*config.Settings)) *settingsVar {
	s := config.Defaults()
	if mut != nil {
		mut(&s)
	}
	sv := &settingsVar{}
	sv.v.Store(&s)
	return sv
}

func (s *settingsVar) get() config.Settings { return *s.v.Load() }
func (s *settingsVar) set(mut func(*config.Settings)) {
	c := *s.v.Load()
	mut(&c)
	s.v.Store(&c)
}

// startRun runs w in the background; the returned stop cancels and waits for Run to return.
func startRun(t *testing.T, w *Writer, sv *settingsVar) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx, sv.get)
		close(done)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Run did not return")
			}
		})
	}
	t.Cleanup(stop)
	// Wait until Run picked up the settings.
	waitFor(t, "run started", func() bool { return w.settings.Load() != nil })
	return stop
}

func TestAnonymize(t *testing.T) {
	tests := []struct{ in, want string }{
		{"192.168.1.20", "192.168.1.0"},
		{"10.0.0.255", "10.0.0.0"},
		{"0.0.0.0", "0.0.0.0"},
		{"2001:db8:1234:5678::1", "2001:db8:1234::"},
		{"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8:ffff::"},
		{"::1", "::"},
		{"fe80::1%eth0", "fe80::"},
		{"::ffff:192.168.1.20", "::ffff:192.168.1.0"},
		{"", ""},
		{"not-an-ip", "not-an-ip"},
		{"192.168.1.20:53", "192.168.1.20:53"},
		{"192.168.1.0/24", "192.168.1.0/24"},
	}
	for _, tt := range tests {
		got := Anonymize(tt.in)
		if got != tt.want {
			t.Errorf("Anonymize(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if again := Anonymize(got); again != got {
			t.Errorf("Anonymize not idempotent for %q: %q", tt.in, again)
		}
	}
}

func TestFlushWithoutRun(t *testing.T) {
	st := openStore(t)
	w := NewWriter(st)
	w.Flush() // empty is a no-op
	for i := 1; i <= 3; i++ {
		w.Add(store.Query{TS: int64(i), Name: "a.example", ClientIP: "192.168.1.20", Status: "ok"})
	}
	if n := count(t, st); n != 0 {
		t.Fatalf("written before flush: %d", n)
	}
	w.Flush()
	got, err := st.Queries(store.QueryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].TS != 3 || got[2].TS != 1 {
		t.Fatalf("got %+v", got)
	}
	if got[0].ClientIP != "192.168.1.20" {
		t.Fatal("IP must not be anonymized without settings")
	}
}

func TestBufferFull(t *testing.T) {
	st := openStore(t)
	w := NewWriter(st)
	for i := 0; i < bufferSize+7; i++ {
		w.Add(store.Query{TS: int64(i)})
	}
	if d := w.Discarded(); d != 7 {
		t.Fatalf("discarded %d", d)
	}
	w.Flush()
	if n := count(t, st); n != bufferSize {
		t.Fatalf("written %d", n)
	}
	// Room again after the flush.
	w.Add(store.Query{TS: 1})
	if d := w.Discarded(); d != 7 {
		t.Fatalf("discarded %d", d)
	}
}

func TestRunFlushesFullBatch(t *testing.T) {
	st := openStore(t)
	w := NewWriter(st)
	w.flushEvery = time.Hour
	startRun(t, w, newSettings(nil))
	for i := 0; i < batchSize-1; i++ {
		w.Add(store.Query{TS: int64(i)})
	}
	time.Sleep(50 * time.Millisecond)
	if n := count(t, st); n != 0 {
		t.Fatalf("partial batch written: %d", n)
	}
	w.Add(store.Query{TS: 9999})
	waitFor(t, "full batch", func() bool { return count(t, st) == batchSize })
}

func TestRunFlushesOnTimer(t *testing.T) {
	st := openStore(t)
	w := NewWriter(st)
	w.flushEvery = 20 * time.Millisecond
	startRun(t, w, newSettings(nil))
	w.Add(store.Query{TS: 1, Name: "x"})
	waitFor(t, "timer flush", func() bool { return count(t, st) == 1 })
}

func TestRunFinalFlush(t *testing.T) {
	st := openStore(t)
	w := NewWriter(st)
	w.flushEvery = time.Hour
	stop := startRun(t, w, newSettings(nil))
	for i := 0; i < 5; i++ {
		w.Add(store.Query{TS: int64(i)})
	}
	stop()
	if n := count(t, st); n != 5 {
		t.Fatalf("after shutdown %d", n)
	}
}

func TestDisabled(t *testing.T) {
	st := openStore(t)
	w := NewWriter(st)
	w.flushEvery = 10 * time.Millisecond
	sv := newSettings(func(s *config.Settings) { s.QuerylogEnabled = false })
	stop := startRun(t, w, sv)
	for i := 0; i < 10; i++ {
		w.Add(store.Query{TS: int64(i)})
	}
	w.Flush()
	if n := count(t, st); n != 0 {
		t.Fatalf("written while disabled: %d", n)
	}

	sv.set(func(s *config.Settings) { s.QuerylogEnabled = true })
	waitFor(t, "enabled", func() bool { return !w.disabled.Load() })
	w.Add(store.Query{TS: 100})
	w.Flush()
	if n := count(t, st); n != 1 {
		t.Fatalf("written after enabling: %d", n)
	}

	// Entries queued before switching off are discarded at the next flush.
	sv.set(func(s *config.Settings) { s.QuerylogEnabled = false })
	w.mu.Lock()
	w.buf = append(w.buf, store.Query{TS: 200})
	w.mu.Unlock()
	stop()
	if n := count(t, st); n != 1 {
		t.Fatalf("queued entry written although disabled: %d", n)
	}
}

func TestAnonymizeOnWrite(t *testing.T) {
	st := openStore(t)
	w := NewWriter(st)
	w.flushEvery = time.Hour
	startRun(t, w, newSettings(func(s *config.Settings) { s.AnonymizeIP = true }))
	w.Add(store.Query{TS: 1, ClientIP: "192.168.1.20"})
	w.Add(store.Query{TS: 2, ClientIP: "2001:db8:1:2::5"})
	w.Flush()
	got, _ := st.Queries(store.QueryFilter{})
	if len(got) != 2 || got[0].ClientIP != "2001:db8:1::" || got[1].ClientIP != "192.168.1.0" {
		t.Fatalf("got %+v", got)
	}
}

func TestPrune(t *testing.T) {
	st := openStore(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	old := now.Add(-3 * time.Hour).UnixMilli()
	fresh := now.Add(-1 * time.Hour).UnixMilli()
	if err := st.InsertQueries([]store.Query{{TS: old}, {TS: old + 1}, {TS: fresh}}); err != nil {
		t.Fatal(err)
	}
	w := NewWriter(st)
	w.now = func() time.Time { return now }
	w.flushEvery = time.Hour
	startRun(t, w, newSettings(func(s *config.Settings) { s.QuerylogHours = 2 }))
	// Run prunes once right away.
	waitFor(t, "prune", func() bool { return count(t, st) == 1 })
	got, _ := st.Queries(store.QueryFilter{})
	if got[0].TS != fresh {
		t.Fatalf("kept %+v", got)
	}
}

func TestPruneTicker(t *testing.T) {
	st := openStore(t)
	var nowMS atomic.Int64
	start := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	nowMS.Store(start.UnixMilli())
	if err := st.InsertQueries([]store.Query{{TS: start.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	w := NewWriter(st)
	w.now = func() time.Time { return time.UnixMilli(nowMS.Load()) }
	w.flushEvery = time.Hour
	w.pruneEvery = 10 * time.Millisecond
	startRun(t, w, newSettings(func(s *config.Settings) { s.QuerylogHours = 1 }))
	time.Sleep(30 * time.Millisecond)
	if n := count(t, st); n != 1 {
		t.Fatalf("pruned too early: %d", n)
	}
	nowMS.Store(start.Add(2 * time.Hour).UnixMilli())
	waitFor(t, "periodic prune", func() bool { return count(t, st) == 0 })
}

func TestConcurrentAddAndFlush(t *testing.T) {
	st := openStore(t)
	w := NewWriter(st)
	w.flushEvery = 5 * time.Millisecond
	stop := startRun(t, w, newSettings(nil))
	const goroutines, per = 8, 300
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				w.Add(store.Query{TS: int64(g*per + i), Name: "c.example"})
				if i%50 == 0 {
					w.Flush()
				}
			}
		}(g)
	}
	wg.Wait()
	stop()
	if n := count(t, st); n != goroutines*per {
		t.Fatalf("written %d, want %d (discarded %d)", n, goroutines*per, w.Discarded())
	}
}
