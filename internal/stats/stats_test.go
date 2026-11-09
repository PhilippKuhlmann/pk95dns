package stats

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pk95dns/internal/config"
	"pk95dns/internal/store"
)

// base is 2026-11-09 12:30:00 UTC; its hour starts at 12:00.
var base = time.Date(2026, 11, 9, 12, 30, 0, 0, time.UTC)

func baseHour() int64 { return hourOf(base.Unix()) }

type clock struct{ ms atomic.Int64 }

func newClock(t time.Time) *clock {
	c := &clock{}
	c.ms.Store(t.UnixMilli())
	return c
}
func (c *clock) now() time.Time      { return time.UnixMilli(c.ms.Load()).UTC() }
func (c *clock) set(t time.Time)     { c.ms.Store(t.UnixMilli()) }
func (c *clock) add(d time.Duration) { c.ms.Add(d.Milliseconds()) }

func newTest(t *testing.T) (*Recorder, *store.Store, *clock) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r := New(st)
	c := newClock(base)
	r.now = c.now
	return r, st, c
}

func summary(t *testing.T, r *Recorder, hours int, now time.Time) Summary {
	t.Helper()
	s, err := r.Summary(hours, now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHourOf(t *testing.T) {
	tests := []struct{ in, want int64 }{
		{0, 0}, {3599, 0}, {3600, 3600}, {7199, 3600}, {-1, -3600}, {-3600, -3600},
		{base.Unix(), time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC).Unix()},
	}
	for _, tt := range tests {
		if got := hourOf(tt.in); got != tt.want {
			t.Errorf("hourOf(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
	if got, want := dayOf(base.Unix()), time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC).Unix(); got != want {
		t.Errorf("dayOf = %d, want %d", got, want)
	}
}

func TestStatusMapping(t *testing.T) {
	tests := []struct {
		name string
		ev   Event
		want Totals
		// expected top list membership
		domain, blocked, client, clientBlocked, upstream bool
	}{
		{"ok", Event{Status: "ok", Name: "a.example", Client: "10.0.0.1", Upstream: "9.9.9.9", ElapsedMS: 10},
			Totals{Queries: 1, AvgMS: 10}, true, false, true, false, true},
		{"cached", Event{Status: "ok", Name: "a.example", Client: "10.0.0.1", Cached: true},
			Totals{Queries: 1, Cached: 1}, true, false, true, false, false},
		{"blocked", Event{Status: "blocked", Name: "ads.example", Client: "10.0.0.1"},
			Totals{Queries: 1, Blocked: 1, BlockedPct: 100}, true, true, true, true, false},
		{"blocked_service", Event{Status: "blocked_service", Name: "tiktok.com", Client: "10.0.0.1"},
			Totals{Queries: 1, Blocked: 1, BlockedPct: 100, Services: 1}, true, true, true, true, false},
		{"safesearch", Event{Status: "safesearch", Name: "www.google.de", Client: "10.0.0.1", Upstream: "1.1.1.1", ElapsedMS: 4},
			Totals{Queries: 1, SafeSearch: 1, AvgMS: 4}, true, false, true, false, true},
		{"allowed", Event{Status: "allowed", Name: "good.example", Client: "10.0.0.1"},
			Totals{Queries: 1}, true, false, true, false, false},
		{"refused without name", Event{Status: "refused", Client: "10.0.0.1"},
			Totals{Queries: 1}, false, false, true, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _, _ := newTest(t)
			ev := tt.ev
			ev.TS = base
			r.Record(ev)
			s := summary(t, r, 24, base)
			if s.Totals != tt.want {
				t.Fatalf("totals %+v, want %+v", s.Totals, tt.want)
			}
			check := func(kind string, got int, want bool) {
				if (got > 0) != want {
					t.Errorf("%s: %d entries, want present=%v", kind, got, want)
				}
			}
			check("domain", len(s.TopDomains), tt.domain)
			check("blocked", len(s.TopBlocked), tt.blocked)
			check("client", len(s.TopClients), tt.client)
			check("upstream", len(s.TopUpstreams), tt.upstream)
			if tt.client && (s.TopClients[0].Blocked > 0) != tt.clientBlocked {
				t.Errorf("client blocked = %d, want present=%v", s.TopClients[0].Blocked, tt.clientBlocked)
			}
		})
	}
}

func TestSummaryWindows(t *testing.T) {
	r, st, _ := newTest(t)
	cur := baseHour()
	today := dayOf(cur)
	tests := []struct {
		hours, wantHours, points int
		gran                     string
		first                    int64
	}{
		{24, 24, 24, "hour", cur - 23*hourSec},
		{168, 168, 168, "hour", cur - 167*hourSec},
		{720, 720, 30, "day", today - 29*daySec},
		{0, 24, 24, "hour", cur - 23*hourSec},
		{25, 24, 24, "hour", cur - 23*hourSec},
		{-1, 24, 24, "hour", cur - 23*hourSec},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.hours), func(t *testing.T) {
			s := summary(t, r, tt.hours, base)
			if s.Hours != tt.wantHours || s.Granularity != tt.gran || len(s.Series) != tt.points {
				t.Fatalf("hours=%d gran=%s points=%d", s.Hours, s.Granularity, len(s.Series))
			}
			if s.Series[0].T != tt.first*1000 {
				t.Fatalf("first point %d, want %d", s.Series[0].T, tt.first*1000)
			}
			step := hourSec
			if tt.gran == "day" {
				step = daySec
			}
			for i := 1; i < len(s.Series); i++ {
				if s.Series[i].T-s.Series[i-1].T != step*1000 {
					t.Fatalf("step at %d: %d", i, s.Series[i].T-s.Series[i-1].T)
				}
			}
			for _, p := range s.Series {
				if p.Queries != 0 || p.Blocked != 0 {
					t.Fatalf("not zero filled: %+v", p)
				}
			}
			// Empty slices, never nil (JSON []).
			if s.TopDomains == nil || s.TopBlocked == nil || s.TopClients == nil || s.TopUpstreams == nil {
				t.Fatal("nil top list")
			}
		})
	}

	// Stored hours: inside and just outside the windows.
	save := func(hour, queries, blocked int64) {
		if err := st.SaveHour(store.HourStats{Hour: hour, Queries: queries, Blocked: blocked, ElapsedMS: float64(queries)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	save(cur, 1, 0)                // current hour
	save(cur-23*hourSec, 2, 1)     // oldest hour of 24
	save(cur-24*hourSec, 4, 0)     // just outside 24, inside 168
	save(cur-167*hourSec, 8, 0)    // oldest of 168
	save(cur-168*hourSec, 16, 0)   // outside 168
	save(today-29*daySec, 32, 0)   // first hour of the 30-day window
	save(today-29*daySec-1, 64, 0) // hour before (not aligned, but < from)
	save(cur+hourSec, 128, 0)      // future: never counted

	tot := map[int]int64{24: 3, 168: 15, 720: 1 + 2 + 4 + 8 + 16 + 32}
	for hours, want := range tot {
		s := summary(t, r, hours, base)
		if s.Totals.Queries != want {
			t.Errorf("%d: queries %d, want %d", hours, s.Totals.Queries, want)
		}
		var sum int64
		for _, p := range s.Series {
			sum += p.Queries
		}
		if sum != want {
			t.Errorf("%d: series sum %d, want %d", hours, sum, want)
		}
	}
	s24 := summary(t, r, 24, base)
	if s24.Series[0].Queries != 2 || s24.Series[0].Blocked != 1 || s24.Series[23].Queries != 1 {
		t.Fatalf("24h series: first %+v last %+v", s24.Series[0], s24.Series[23])
	}
	if s24.Totals.BlockedPct != 33.3 || s24.Totals.AvgMS != 1 {
		t.Fatalf("pct/avg: %+v", s24.Totals)
	}
	s720 := summary(t, r, 720, base)
	if s720.Series[0].Queries != 32 || s720.Series[29].Queries != 1 {
		t.Fatalf("daily series: first %+v last %+v", s720.Series[0], s720.Series[29])
	}
}

func TestNoDoubleCountAfterFlush(t *testing.T) {
	r, st, c := newTest(t)
	cur := baseHour()
	ev := func(ts time.Time, name string) Event {
		return Event{TS: ts, Name: name, Client: "10.0.0.1", Status: "ok", Upstream: "9.9.9.9", ElapsedMS: 2}
	}
	r.Record(ev(base, "a.example"))
	r.Record(ev(base, "a.example"))
	r.Record(ev(base.Add(-time.Hour), "b.example")) // previous hour, still in memory

	check := func(step string, wantQ, wantA, wantB int64) {
		t.Helper()
		s := summary(t, r, 24, c.now())
		if s.Totals.Queries != wantQ {
			t.Fatalf("%s: queries %d, want %d", step, s.Totals.Queries, wantQ)
		}
		got := map[string]int64{}
		for _, d := range s.TopDomains {
			got[d.Name] = d.Count
		}
		if got["a.example"] != wantA || got["b.example"] != wantB {
			t.Fatalf("%s: domains %v", step, got)
		}
		if len(s.TopClients) != 1 || s.TopClients[0].Count != wantQ {
			t.Fatalf("%s: clients %+v", step, s.TopClients)
		}
		if len(s.TopUpstreams) != 1 || s.TopUpstreams[0].Count != wantQ || s.TopUpstreams[0].AvgMS != 2 {
			t.Fatalf("%s: upstreams %+v", step, s.TopUpstreams)
		}
	}
	check("memory only", 3, 2, 1)
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	check("after flush", 3, 2, 1)
	r.mu.Lock()
	n := len(r.buckets)
	r.mu.Unlock()
	if n != 1 {
		t.Fatalf("previous hour must be dropped (30 min after its end), %d buckets", n)
	}
	r.Record(ev(base, "a.example"))
	check("record after flush", 4, 3, 1)
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	check("second flush", 4, 3, 1)

	// Next hour: the old current hour is kept during the grace period, then dropped.
	c.set(time.Unix(cur+hourSec+60, 0))
	r.Record(ev(c.now(), "c.example"))
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	_, kept := r.buckets[cur]
	r.mu.Unlock()
	if !kept {
		t.Fatal("hour dropped within the grace period")
	}
	c.set(time.Unix(cur+hourSec+10*60, 0))
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	_, kept = r.buckets[cur]
	r.mu.Unlock()
	if kept {
		t.Fatal("hour kept after the grace period")
	}
	s := summary(t, r, 24, c.now())
	if s.Totals.Queries != 5 {
		t.Fatalf("after drop: %d", s.Totals.Queries)
	}
	hs, _ := st.LoadHours(0, 1<<40)
	if len(hs) != 3 {
		t.Fatalf("stored hours %+v", hs)
	}
}

func TestLateEventAfterDrop(t *testing.T) {
	r, st, c := newTest(t)
	cur := baseHour()
	r.Record(Event{TS: base, Name: "a", Status: "ok"})
	c.set(time.Unix(cur+2*hourSec, 0))
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	// A late event for the dropped hour must not replace its stored totals.
	r.Record(Event{TS: base, Name: "late", Status: "ok"})
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	hs, _ := st.LoadHours(cur, cur+hourSec)
	if len(hs) != 1 || hs[0].Queries != 1 {
		t.Fatalf("stored hour changed: %+v", hs)
	}
	s := summary(t, r, 24, c.now())
	if s.Totals.Queries != 2 {
		t.Fatalf("late event lost: %d", s.Totals.Queries)
	}
}

// After the clock went backwards (it ran ahead before), new events count into the current
// hour, not into an hour after the dropped future one.
func TestClockJumpBack(t *testing.T) {
	r, _, c := newTest(t)
	ahead := base.Add(60 * 24 * time.Hour)
	c.set(ahead)
	r.Record(Event{TS: ahead, Name: "a", Status: "ok"})
	c.set(ahead.Add(2 * time.Hour))
	if err := r.Flush(); err != nil { // drops the hour of ahead
		t.Fatal(err)
	}
	c.set(base) // corrected
	for range 10 {
		r.Record(Event{TS: c.now(), Name: "b", Status: "ok"})
	}
	if s := summary(t, r, 24, c.now()); s.Totals.Queries != 10 {
		t.Fatalf("queries after the clock jump = %d, want 10", s.Totals.Queries)
	}
}

func TestTopMerging(t *testing.T) {
	r, st, _ := newTest(t)
	cur := baseHour()
	old := cur - 2*hourSec
	if err := st.SaveHour(store.HourStats{Hour: old, Queries: 8, Blocked: 3}, []store.TopEntry{
		{Kind: kindDomain, Key: "a", Count: 5},
		{Kind: kindDomain, Key: "b", Count: 3},
		{Kind: kindBlocked, Key: "b", Count: 3},
		{Kind: kindClient, Key: "10.0.0.2", Count: 8},
		{Kind: kindClientBlocked, Key: "10.0.0.2", Count: 3},
		{Kind: kindUpstream, Key: "9.9.9.9", Count: 5, Sum: 50},
	}); err != nil {
		t.Fatal(err)
	}
	// A stale stored version of the current hour (memory wins for that hour).
	if err := st.SaveHour(store.HourStats{Hour: cur, Queries: 100}, []store.TopEntry{
		{Kind: kindDomain, Key: "stale", Count: 100},
		{Kind: kindClient, Key: "10.0.0.9", Count: 100},
	}); err != nil {
		t.Fatal(err)
	}
	t1 := base.Add(time.Minute)
	for i := 0; i < 4; i++ {
		r.Record(Event{TS: base, Name: "b", Client: "10.0.0.1", Status: "blocked"})
	}
	r.Record(Event{TS: t1, Name: "c", Client: "10.0.0.1", Status: "ok", Upstream: "9.9.9.9", ElapsedMS: 30})
	r.Record(Event{TS: t1, Name: "c", Client: "10.0.0.2", Status: "ok", Upstream: "1.1.1.1", ElapsedMS: 1})

	s := summary(t, r, 24, base)
	if s.Totals.Queries != 14 || s.Totals.Blocked != 7 {
		t.Fatalf("totals %+v", s.Totals)
	}
	wantDomains := []NameCount{{"b", 7}, {"a", 5}, {"c", 2}}
	if !reflect.DeepEqual(s.TopDomains, wantDomains) {
		t.Fatalf("domains %+v", s.TopDomains)
	}
	if !reflect.DeepEqual(s.TopBlocked, []NameCount{{"b", 7}}) {
		t.Fatalf("blocked %+v", s.TopBlocked)
	}
	wantClients := []ClientCount{
		{IP: "10.0.0.2", Count: 9, Blocked: 3, LastSeen: t1.UnixMilli()},
		{IP: "10.0.0.1", Count: 5, Blocked: 4, LastSeen: t1.UnixMilli()},
	}
	if !reflect.DeepEqual(s.TopClients, wantClients) {
		t.Fatalf("clients %+v", s.TopClients)
	}
	wantUp := []UpstreamCount{{"9.9.9.9", 6, 13.33}, {"1.1.1.1", 1, 1}}
	if !reflect.DeepEqual(s.TopUpstreams, wantUp) {
		t.Fatalf("upstreams %+v", s.TopUpstreams)
	}

	// A client only in the store: LastSeen is its latest hour.
	if err := st.SaveHour(store.HourStats{Hour: old - hourSec, Queries: 1}, []store.TopEntry{
		{Kind: kindClient, Key: "10.0.0.3", Count: 1},
	}); err != nil {
		t.Fatal(err)
	}
	s = summary(t, r, 24, base)
	last := s.TopClients[len(s.TopClients)-1]
	if last.IP != "10.0.0.3" || last.LastSeen != (old-hourSec)*1000 {
		t.Fatalf("stored client %+v", last)
	}
}

func TestTopLimitAndOrder(t *testing.T) {
	r, _, _ := newTest(t)
	for i := 0; i < 30; i++ {
		for j := 0; j <= i; j++ {
			r.Record(Event{TS: base, Name: fmt.Sprintf("d%02d", i), Client: fmt.Sprintf("10.0.0.%d", i), Status: "ok"})
		}
	}
	r.Record(Event{TS: base, Name: "tie-b", Status: "ok"})
	r.Record(Event{TS: base, Name: "tie-a", Status: "ok"})
	s := summary(t, r, 24, base)
	if len(s.TopDomains) != 20 || len(s.TopClients) != 20 {
		t.Fatalf("lengths %d %d", len(s.TopDomains), len(s.TopClients))
	}
	if s.TopDomains[0].Name != "d29" || s.TopDomains[0].Count != 30 || s.TopDomains[19].Name != "d10" {
		t.Fatalf("order %+v", s.TopDomains)
	}
	for i := 1; i < len(s.TopDomains); i++ {
		if s.TopDomains[i].Count > s.TopDomains[i-1].Count {
			t.Fatal("not sorted")
		}
	}
	// Ties are ordered by name.
	got := ranked(map[string]*counter{"b": {count: 1}, "a": {count: 1}, "c": {count: 2}}, 0)
	if got[0].key != "c" || got[1].key != "a" || got[2].key != "b" {
		t.Fatalf("ranked %+v", got)
	}
}

func TestMemoryCapAndStoredTop(t *testing.T) {
	r, st, _ := newTest(t)
	const n = maxKeys + 50
	for i := 0; i < n; i++ {
		r.Record(Event{TS: base, Name: fmt.Sprintf("n%05d.example", i), Client: "10.0.0.1", Status: "ok"})
	}
	// An existing key keeps counting beyond the cap.
	for i := 0; i < 5; i++ {
		r.Record(Event{TS: base, Name: "n00000.example", Status: "ok"})
	}
	r.mu.Lock()
	b := r.buckets[baseHour()]
	keys := len(b.top[kindDomain])
	first := b.top[kindDomain]["n00000.example"].count
	_, over := b.top[kindDomain][fmt.Sprintf("n%05d.example", n-1)]
	r.mu.Unlock()
	if keys != maxKeys || first != 6 || over {
		t.Fatalf("keys=%d first=%d over=%v", keys, first, over)
	}
	s := summary(t, r, 24, base)
	if s.Totals.Queries != n+5 {
		t.Fatalf("totals must count everything: %d", s.Totals.Queries)
	}
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	var stored int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM stats_top WHERE kind = 'domain'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != storeTopN {
		t.Fatalf("stored domain keys %d, want %d", stored, storeTopN)
	}
	top, _ := st.LoadTop(kindDomain, 0, 1<<40, 1)
	if top[0].Key != "n00000.example" || top[0].Count != 6 {
		t.Fatalf("stored top %+v", top)
	}
}

func TestLimitTop(t *testing.T) {
	in := []store.TopEntry{
		{Kind: "a", Key: "x", Count: 1}, {Kind: "a", Key: "y", Count: 3}, {Kind: "a", Key: "z", Count: 2},
		{Kind: "b", Key: "x", Count: 1},
	}
	got := limitTop(in, 2)
	want := []store.TopEntry{{Kind: "a", Key: "y", Count: 3}, {Kind: "a", Key: "z", Count: 2}, {Kind: "b", Key: "x", Count: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestRecentClients(t *testing.T) {
	r, st, _ := newTest(t)
	cur := baseHour()
	if err := st.SaveHour(store.HourStats{Hour: cur - 3*hourSec, Queries: 9}, []store.TopEntry{
		{Kind: kindClient, Key: "10.0.0.5", Count: 9},
		{Kind: kindClientBlocked, Key: "10.0.0.5", Count: 2},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveHour(store.HourStats{Hour: cur - 30*hourSec, Queries: 50}, []store.TopEntry{
		{Kind: kindClient, Key: "10.0.0.6", Count: 50},
	}); err != nil {
		t.Fatal(err)
	}
	r.Record(Event{TS: base, Client: "10.0.0.1", Name: "x", Status: "blocked"})
	r.Record(Event{TS: base, Client: "10.0.0.5", Name: "x", Status: "ok"})

	got, err := r.RecentClients(base.Add(-24*time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []ClientCount{
		{IP: "10.0.0.5", Count: 10, Blocked: 2, LastSeen: base.UnixMilli()},
		{IP: "10.0.0.1", Count: 1, Blocked: 1, LastSeen: base.UnixMilli()},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	got, _ = r.RecentClients(base.Add(-48*time.Hour), 1)
	if len(got) != 1 || got[0].IP != "10.0.0.6" {
		t.Fatalf("limit/longer window: %+v", got)
	}
	got, _ = r.RecentClients(base.Add(time.Hour), 10)
	if got == nil || len(got) != 0 {
		t.Fatalf("future since: %+v", got)
	}
}

func TestReset(t *testing.T) {
	r, st, _ := newTest(t)
	r.Record(Event{TS: base, Name: "a", Status: "ok"})
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	r.Record(Event{TS: base, Name: "b", Status: "ok"})
	if err := r.Reset(); err != nil {
		t.Fatal(err)
	}
	s := summary(t, r, 24, base)
	if s.Totals.Queries != 0 || len(s.TopDomains) != 0 {
		t.Fatalf("after reset %+v", s)
	}
	hs, _ := st.LoadHours(0, 1<<40)
	if len(hs) != 0 {
		t.Fatalf("store not cleared: %+v", hs)
	}
	r.Record(Event{TS: base, Name: "c", Status: "ok"})
	if s := summary(t, r, 24, base); s.Totals.Queries != 1 {
		t.Fatalf("record after reset: %+v", s.Totals)
	}
}

func TestRun(t *testing.T) {
	r, st, _ := newTest(t)
	r.flushEvery = 10 * time.Millisecond
	cur := baseHour()
	// Older than stats_days: pruned when Run starts.
	if err := st.SaveHour(store.HourStats{Hour: cur - 3*daySec, Queries: 1}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveHour(store.HourStats{Hour: cur - daySec, Queries: 1}, nil); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.StatsDays = 2
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx, func() config.Settings { return cfg })
		close(done)
	}()
	r.Record(Event{TS: base, Name: "a", Status: "ok"})
	deadline := time.Now().Add(5 * time.Second)
	for {
		hs, _ := st.LoadHours(cur, cur+hourSec)
		if len(hs) == 1 && hs[0].Queries == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no periodic flush")
		}
		time.Sleep(5 * time.Millisecond)
	}
	hs, _ := st.LoadHours(0, cur)
	if len(hs) != 1 || hs[0].Hour != cur-daySec {
		t.Fatalf("prune: %+v", hs)
	}
	r.flushMu.Lock() // make sure no tick flushes the next record before shutdown
	r.Record(Event{TS: base, Name: "b", Status: "ok"})
	r.flushMu.Unlock()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	hs, _ = st.LoadHours(cur, cur+hourSec)
	if len(hs) != 1 || hs[0].Queries != 2 {
		t.Fatalf("final flush: %+v", hs)
	}
}

func TestConcurrent(t *testing.T) {
	r, _, c := newTest(t)
	var wg sync.WaitGroup
	const goroutines, per = 8, 500
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				r.Record(Event{TS: c.now(), Name: fmt.Sprintf("d%d.example", i%37), Client: fmt.Sprintf("10.0.0.%d", g), Status: "blocked", Upstream: "9.9.9.9", ElapsedMS: 1})
			}
		}(g)
	}
	stop := make(chan struct{})
	var bg sync.WaitGroup
	bg.Add(1)
	go func() {
		defer bg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := r.Flush(); err != nil {
				t.Error(err)
				return
			}
			if _, err := r.Summary(24, c.now()); err != nil {
				t.Error(err)
				return
			}
			if _, err := r.RecentClients(c.now().Add(-time.Hour), 10); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()
	close(stop)
	bg.Wait()
	s := summary(t, r, 24, c.now())
	if s.Totals.Queries != goroutines*per || s.Totals.Blocked != goroutines*per {
		t.Fatalf("totals %+v", s.Totals)
	}
	if len(s.TopClients) != goroutines || s.TopClients[0].Count != per {
		t.Fatalf("clients %+v", s.TopClients)
	}
}
