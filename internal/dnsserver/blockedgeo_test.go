package dnsserver

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
	"pk95dns/internal/filter"
)

type bgRecord struct {
	hour time.Time
	code string
}

type bgFake struct {
	mu       sync.Mutex
	now      time.Time
	resolved []string
	codes    map[string]string
	records  []bgRecord
}

func newBGFake() (*bgFake, *blockedGeo) {
	f := &bgFake{now: time.Date(2026, 11, 22, 10, 30, 0, 0, time.UTC), codes: map[string]string{"ru.example": "RU", "de.example": "DE"}}
	b := newBlockedGeo(func(_ context.Context, name string) string {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.resolved = append(f.resolved, name)
		return f.codes[name]
	}, func(ts time.Time, code string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.records = append(f.records, bgRecord{ts.UTC().Truncate(time.Hour), code})
	}, func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	})
	return f, b
}

func (f *bgFake) take() []bgRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.records
	f.records = nil
	return r
}

func drainOne(t *testing.T, b *blockedGeo) {
	t.Helper()
	select {
	case name := <-b.queue:
		b.lookup(context.Background(), name)
	default:
		t.Fatal("queue empty")
	}
}

func TestBlockedGeoQueueDedupeAndHours(t *testing.T) {
	f, b := newBGFake()
	h10 := f.now.Truncate(time.Hour)
	h11 := h10.Add(time.Hour)
	if got := b.note("ru.example", f.now, true); got != "" {
		t.Fatalf("not cached yet: %q", got)
	}
	b.note("ru.example", f.now.Add(10*time.Minute), true)
	b.note("ru.example", f.now.Add(45*time.Minute), true) // next hour
	if len(b.queue) != 1 || len(f.take()) != 0 {
		t.Fatal("the name must be queued once and nothing counted yet")
	}
	drainOne(t, b)
	recs := f.take()
	slices.SortFunc(recs, func(a, b bgRecord) int { return a.hour.Compare(b.hour) })
	if want := []bgRecord{{h10, "RU"}, {h10, "RU"}, {h11, "RU"}}; !slices.Equal(recs, want) {
		t.Fatalf("records %v, want %v (counted in the hour of each query)", recs, want)
	}
	// cached: counted at once, the country is returned for the query log, no lookup
	if got := b.note("ru.example", f.now, true); got != "RU" || len(b.queue) != 0 {
		t.Fatalf("cached: %q, queue %d", got, len(b.queue))
	}
	if recs := f.take(); !slices.Equal(recs, []bgRecord{{h10, "RU"}}) {
		t.Fatalf("cached record %v", recs)
	}
	if len(f.resolved) != 1 {
		t.Fatalf("resolved %v", f.resolved)
	}
}

func TestBlockedGeoCacheTTL(t *testing.T) {
	f, b := newBGFake()
	b.note("unknown.example", f.now, true) // resolves to "" (negative)
	drainOne(t, b)
	f.take()
	if got := b.note("unknown.example", f.now, true); got != "" || len(b.queue) != 0 {
		t.Fatal("a negative result must be cached too")
	}
	if recs := f.take(); len(recs) != 1 || recs[0].code != "" {
		t.Fatalf("negative cached record %v", recs)
	}
	f.mu.Lock()
	f.now = f.now.Add(bgCacheTTL - time.Second)
	f.mu.Unlock()
	b.note("unknown.example", f.now, true)
	if len(b.queue) != 0 {
		t.Fatal("looked up again before 24 h")
	}
	f.mu.Lock()
	f.now = f.now.Add(2 * time.Second)
	f.mu.Unlock()
	b.note("unknown.example", f.now, true)
	if len(b.queue) != 1 {
		t.Fatal("not looked up again after 24 h")
	}
}

func TestBlockedGeoOverflowAndDisabled(t *testing.T) {
	f, b := newBGFake()
	for i := range bgQueueSize {
		b.note(fmt.Sprintf("n%d.example", i), f.now, true)
	}
	if len(b.queue) != bgQueueSize || len(f.take()) != 0 {
		t.Fatal("queue not filled")
	}
	b.note("one-too-many.example", f.now, true)
	if recs := f.take(); len(recs) != 1 || recs[0].code != "" || len(b.queue) != bgQueueSize {
		t.Fatalf("overflow must count unknown_blocked at once: %v", recs)
	}
	// a name already waiting still joins its queue entry
	b.note("n5.example", f.now, true)
	if len(f.take()) != 0 {
		t.Fatal("waiting name counted as unknown")
	}

	f2, b2 := newBGFake()
	if got := b2.note("ru.example", f2.now, false); got != "" || len(b2.queue) != 0 {
		t.Fatal("disabled: no lookup")
	}
	if recs := f2.take(); len(recs) != 1 || recs[0].code != "" {
		t.Fatalf("disabled must count unknown_blocked: %v", recs)
	}
}

func TestBlockedGeoRateLimit(t *testing.T) {
	if want := 100 * time.Millisecond; newBlockedGeo(nil, nil, time.Now).every != want {
		t.Fatalf("not %v between lookups (10/s)", want)
	}
	f, b := newBGFake()
	b.every = time.Hour
	for i := range 5 {
		b.note(fmt.Sprintf("r%d.example", i), f.now, true)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.run(ctx); close(done) }()
	time.Sleep(150 * time.Millisecond)
	cancel()
	<-done
	f.mu.Lock()
	n := len(f.resolved)
	f.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d lookups in one interval, want 1", n)
	}
}

// Through the DNS server: a list-blocked query is answered at once, the background lookup
// asks the upstream without a query log entry or client statistics, and the next query
// of the name gets the country in the log.
func TestBlockedGeoServer(t *testing.T) {
	e := geoEnv(t, config.GeoOff)
	custom, _ := filter.Compile([]filter.Source{{ID: 0, Data: []byte("||blocked.geo.example^")}})
	e.engine.SetCustom(custom)
	var mu sync.Mutex
	var recs []bgRecord
	e.srv.bgeo.record = func(ts time.Time, code string) {
		mu.Lock()
		recs = append(recs, bgRecord{ts.UTC().Truncate(time.Hour), code})
		mu.Unlock()
	}

	resp, l := e.query("blocked.geo.example", dns.TypeA)
	if l.q.Status != statusBlocked || l.q.Country != "" || answers(resp)[0] != "A 0.0.0.0" {
		t.Fatalf("blocked query: %+v %v", l.q, answers(resp))
	}
	if e.up.count("blocked.geo.example", dns.TypeA) != 0 || len(e.srv.bgeo.queue) != 1 {
		t.Fatal("the client answer must not wait for the lookup")
	}
	logs := e.logCount()
	drainOne(t, e.srv.bgeo)
	if e.up.count("blocked.geo.example", dns.TypeA) != 1 {
		t.Fatal("the background lookup did not ask the upstream")
	}
	if e.logCount() != logs {
		t.Fatal("the background lookup produced a query log entry / client stats event")
	}
	mu.Lock()
	got := slices.Clone(recs)
	mu.Unlock()
	if len(got) != 1 || got[0].code != "RU" || !got[0].hour.Equal(e.now().UTC().Truncate(time.Hour)) {
		t.Fatalf("records %v", got)
	}
	_, l = e.query("blocked.geo.example", dns.TypeA)
	if l.q.Status != statusBlocked || l.q.Country != "RU" {
		t.Fatalf("second query: %+v", l.q)
	}
	// TXT is not looked up
	e.query("blocked.geo.example", dns.TypeTXT)
	if len(e.srv.bgeo.queue) != 0 {
		t.Fatal("TXT queued")
	}

	// resolve_blocked off: counted as unknown at once, nothing queued
	e.update(func(s *config.Settings) { s.Geo.ResolveBlocked = false })
	mu.Lock()
	recs = nil
	mu.Unlock()
	e.query("other.blocked.geo.example", dns.TypeA)
	mu.Lock()
	defer mu.Unlock()
	if len(e.srv.bgeo.queue) != 0 || len(recs) != 1 || recs[0].code != "" {
		t.Fatalf("resolve_blocked off: queue %d records %v", len(e.srv.bgeo.queue), recs)
	}
}

// Without a GeoIP database there are no lookups.
func TestBlockedGeoWithoutDatabase(t *testing.T) {
	e := newEnv(t, nil)
	custom, _ := filter.Compile([]filter.Source{{ID: 0, Data: []byte("||blocked.geo.example^")}})
	e.engine.SetCustom(custom)
	var codes []string
	e.srv.bgeo.record = func(_ time.Time, code string) { codes = append(codes, code) }
	e.query("blocked.geo.example", dns.TypeA)
	if len(e.srv.bgeo.queue) != 0 || !slices.Equal(codes, []string{""}) {
		t.Fatalf("queue %d codes %v", len(e.srv.bgeo.queue), codes)
	}
}
