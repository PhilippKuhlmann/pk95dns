// Package stats aggregates queries per UTC hour in memory, flushes them to the store
// (every minute and on shutdown) and builds the summaries of GET /api/stats.
package stats

import (
	"context"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"

	"pk95dns/internal/config"
	"pk95dns/internal/store"
)

// Event is one answered query.
type Event struct {
	TS        time.Time
	Client    string // client IP (already anonymized when configured)
	Name      string // queried domain
	Status    string // query log status vocabulary
	Upstream  string // "" when not forwarded
	ElapsedMS float64
	Cached    bool
}

// Summary is the answer of GET /api/stats (client names are filled in by the API).
type Summary struct {
	Hours        int             `json:"hours"`
	Granularity  string          `json:"granularity"` // "hour" or "day"
	Totals       Totals          `json:"totals"`
	Series       []Point         `json:"series"`
	TopDomains   []NameCount     `json:"top_domains"`
	TopBlocked   []NameCount     `json:"top_blocked"`
	TopClients   []ClientCount   `json:"top_clients"`
	TopUpstreams []UpstreamCount `json:"top_upstreams"`
}

type Totals struct {
	Queries    int64   `json:"queries"`
	Blocked    int64   `json:"blocked"`
	BlockedPct float64 `json:"blocked_pct"`
	Cached     int64   `json:"cached"`
	SafeSearch int64   `json:"safesearch"`
	Local      int64   `json:"local"` // answers from own zones and records (status rewrite), without SafeSearch
	Services   int64   `json:"services"`
	AvgMS      float64 `json:"avg_ms"`
}

type Point struct {
	T       int64 `json:"t"` // unix ms of the bucket start
	Queries int64 `json:"queries"`
	Blocked int64 `json:"blocked"`
	Cached  int64 `json:"cached"` // answered from the cache, not blocked; <= Queries - Blocked
}

// add sums one stored or in-memory hour into the point. Each hour's cache count is capped
// at its answers that were not blocked, so the segments of a bar always fit (hours
// recorded before blocked cache hits were excluded could exceed it).
func (p *Point) add(h store.HourStats) {
	p.Queries += h.Queries
	p.Blocked += h.Blocked
	p.Cached += min(max(h.Cached, 0), max(h.Queries-h.Blocked, 0))
}

type NameCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type ClientCount struct {
	IP       string `json:"ip"`
	Name     string `json:"name"`
	Count    int64  `json:"count"`
	Blocked  int64  `json:"blocked"`
	LastSeen int64  `json:"last_seen"` // unix ms
}

type UpstreamCount struct {
	Address string  `json:"address"`
	Count   int64   `json:"count"`
	AvgMS   float64 `json:"avg_ms"`
}

// Top list kinds (stats_top.kind).
const (
	kindDomain        = "domain"         // every queried name
	kindBlocked       = "blocked"        // names with status blocked / blocked_service
	kindClient        = "client"         // client IP
	kindClientBlocked = "client_blocked" // client IP of blocked queries
	kindUpstream      = "upstream"       // upstream address, Sum = elapsed ms
)

var allKinds = []string{kindDomain, kindBlocked, kindClient, kindClientBlocked, kindUpstream}

const (
	hourSec = int64(3600)
	daySec  = 24 * hourSec

	maxKeys       = 10000 // distinct keys per kind and hour kept in memory
	storeTopN     = 100   // keys per kind and hour written to the store
	summaryTopN   = 20    // entries of the top lists in a summary
	storeTopLimit = 1000  // keys per kind read from the store for a summary
	recentDefault = 100

	// dropGrace keeps a finished hour in memory a little longer, so queries that were
	// answered late (slow upstream) still land in their hour instead of replacing it.
	dropGrace = 5 * time.Minute
)

// counter of one key in one hour (or merged over several hours).
type counter struct {
	count int64
	sum   float64
	last  int64 // unix ms of the latest event
}

type bucket struct {
	totals  store.HourStats
	top     map[string]map[string]*counter // kind → key → counter
	version uint64                         // incremented on every Record
}

func newBucket(hour int64) *bucket {
	b := &bucket{totals: store.HourStats{Hour: hour}, top: make(map[string]map[string]*counter, len(allKinds))}
	for _, k := range allKinds {
		b.top[k] = map[string]*counter{}
	}
	return b
}

// add counts key into kind; new keys beyond maxKeys are only counted in the totals.
func (b *bucket) add(kind, key string, sum float64, ms int64) {
	if key == "" {
		return
	}
	m := b.top[kind]
	c := m[key]
	if c == nil {
		if len(m) >= maxKeys {
			return
		}
		c = &counter{}
		m[key] = c
	}
	c.count++
	c.sum += sum
	if ms > c.last {
		c.last = ms
	}
}

// Recorder is safe for concurrent use. Record must be cheap (called per query).
type Recorder struct {
	st *store.Store

	// Timing, replaced in tests.
	now        func() time.Time
	loc        *time.Location // day boundaries of the 30-day view: time.Local (from TZ)
	flushEvery time.Duration
	pruneEvery time.Duration

	mu      sync.Mutex
	buckets map[int64]*bucket // key: hour (unix seconds)
	dropped int64             // latest hour dropped from memory after saving; older events move to the next hour

	flushMu sync.Mutex // serializes Flush and Reset
}

// New creates a recorder for st.
func New(st *store.Store) *Recorder {
	return &Recorder{
		st:         st,
		now:        time.Now,
		loc:        time.Local,
		flushEvery: time.Minute,
		pruneEvery: time.Hour,
		buckets:    map[int64]*bucket{},
		dropped:    math.MinInt64,
	}
}

// hourOf returns the start of the UTC hour of unix seconds sec.
func hourOf(sec int64) int64 {
	return sec - ((sec%hourSec)+hourSec)%hourSec
}

// dayStarts returns the starts of the last n local days in loc up to and including the
// day of now, plus the start of the next day (n+1 values, unix seconds). time.Date
// normalises, so days around a DST change have 23 or 25 hours and a midnight that does not
// exist starts the day at the first valid time.
func dayStarts(now time.Time, loc *time.Location, n int) []int64 {
	y, m, d := now.In(loc).Date()
	out := make([]int64, n+1)
	for i := range out {
		out[i] = time.Date(y, m, d-(n-1)+i, 0, 0, 0, 0, loc).Unix()
	}
	return out
}

func isBlocked(status string) bool { return status == "blocked" || status == "blocked_service" }

// Record counts one query into the current hour.
func (r *Recorder) Record(e Event) {
	ts := e.TS
	if ts.IsZero() {
		ts = r.now()
	}
	ms := ts.UnixMilli()
	hour := hourOf(ts.Unix())
	blocked := isBlocked(e.Status)

	cur := hourOf(r.now().Unix())

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.dropped >= cur {
		// Hours are dropped only after they ended, so the clock went backwards (it ran
		// ahead before, e.g. until NTP corrected it). Without this every event would go to
		// an hour after the dropped one, i.e. into the future, and be missing from the
		// summaries until the clock reaches it.
		r.dropped = cur - hourSec
	}
	if hour <= r.dropped {
		// That hour is already saved and gone from memory; saving it again would replace it.
		hour = r.dropped + hourSec
	}
	b := r.buckets[hour]
	if b == nil {
		b = newBucket(hour)
		r.buckets[hour] = b
	}
	b.version++
	t := &b.totals
	t.Queries++
	t.ElapsedMS += e.ElapsedMS
	if blocked {
		t.Blocked++
	}
	if e.Status == "blocked_service" {
		t.Services++
	}
	if e.Status == "safesearch" {
		t.SafeSearch++
	}
	if e.Status == "rewrite" { // SafeSearch has its own status, so nothing is counted twice
		t.Local++
	}
	// Answered from the cache and not blocked (a cached answer can still be blocked by
	// the CNAME check): the same segment the overview shows next to "blocked".
	if e.Cached && !blocked {
		t.Cached++
	}
	b.add(kindDomain, e.Name, 0, ms)
	b.add(kindClient, e.Client, 0, ms)
	if blocked {
		b.add(kindBlocked, e.Name, 0, ms)
		b.add(kindClientBlocked, e.Client, 0, ms)
	}
	if e.Upstream != "" {
		b.add(kindUpstream, e.Upstream, e.ElapsedMS, ms)
	}
}

// Run flushes every minute and on hour change, prunes hours older than settings().StatsDays
// once per hour, and flushes on ctx done.
func (r *Recorder) Run(ctx context.Context, settings func() config.Settings) {
	r.prune(settings())
	flushT := time.NewTicker(r.flushEvery)
	defer flushT.Stop()
	pruneT := time.NewTicker(r.pruneEvery)
	defer pruneT.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := r.Flush(); err != nil {
				slog.Warn("stats: final flush failed", "error", err)
			}
			return
		case <-flushT.C:
			if err := r.Flush(); err != nil {
				slog.Warn("stats: flush failed", "error", err)
			}
		case <-pruneT.C:
			r.prune(settings())
		}
	}
}

func (r *Recorder) prune(cfg config.Settings) {
	if cfg.StatsDays <= 0 {
		return
	}
	before := hourOf(r.now().Unix()) - int64(cfg.StatsDays)*daySec
	if err := r.st.PruneStats(before); err != nil {
		slog.Warn("stats: prune failed", "error", err)
	}
}

// snapshot is the copy of one bucket that Flush writes.
type snapshot struct {
	totals  store.HourStats
	top     []store.TopEntry
	version uint64
}

// Flush writes the in-memory hour(s) now. The current hour stays in memory (it is saved
// again on the next flush, SaveHour replaces it); finished hours are dropped from memory
// after they were saved.
func (r *Recorder) Flush() error {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()

	r.mu.Lock()
	snaps := make([]snapshot, 0, len(r.buckets))
	for _, b := range r.buckets {
		s := snapshot{totals: b.totals, version: b.version}
		for _, kind := range allKinds {
			for key, c := range b.top[kind] {
				s.top = append(s.top, store.TopEntry{Kind: kind, Key: key, Count: c.count, Sum: c.sum})
			}
		}
		snaps = append(snaps, s)
	}
	r.mu.Unlock()

	sort.Slice(snaps, func(i, j int) bool { return snaps[i].totals.Hour < snaps[j].totals.Hour })
	now := r.now()
	var firstErr error
	for _, s := range snaps {
		if err := r.st.SaveHour(s.totals, limitTop(s.top, storeTopN)); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		hourEnd := time.Unix(s.totals.Hour+hourSec, 0)
		if now.Before(hourEnd.Add(dropGrace)) {
			continue
		}
		r.mu.Lock()
		if b := r.buckets[s.totals.Hour]; b != nil && b.version == s.version {
			delete(r.buckets, s.totals.Hour)
			if s.totals.Hour > r.dropped {
				r.dropped = s.totals.Hour
			}
		}
		r.mu.Unlock()
	}
	return firstErr
}

// limitTop keeps the n highest counts per kind.
func limitTop(entries []store.TopEntry, n int) []store.TopEntry {
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Key < b.Key
	})
	out := entries[:0]
	var kind string
	var inKind int
	for _, e := range entries {
		if e.Kind != kind {
			kind, inKind = e.Kind, 0
		}
		if inKind < n {
			out = append(out, e)
		}
		inKind++
	}
	return out
}

// collected is the merged view of memory and store over [from, to).
type collected struct {
	hours map[int64]store.HourStats
	tops  map[string]map[string]*counter
}

// collect merges the in-memory buckets with the stored hours in [from, to). An hour that
// is in memory is never also taken from the store.
func (r *Recorder) collect(from, to int64, kinds []string) (collected, error) {
	c := collected{hours: map[int64]store.HourStats{}, tops: map[string]map[string]*counter{}}
	for _, k := range kinds {
		c.tops[k] = map[string]*counter{}
	}
	var memHours []int64

	r.mu.Lock()
	for h, b := range r.buckets {
		if h < from || h >= to {
			continue
		}
		memHours = append(memHours, h)
		c.hours[h] = b.totals
		for _, kind := range kinds {
			dst := c.tops[kind]
			for key, src := range b.top[kind] {
				mergeCounter(dst, key, src.count, src.sum, src.last)
			}
		}
	}
	r.mu.Unlock()

	inMem := make(map[int64]bool, len(memHours))
	for _, h := range memHours {
		inMem[h] = true
	}
	stored, err := r.st.LoadHours(from, to)
	if err != nil {
		return collected{}, err
	}
	for _, h := range stored {
		if !inMem[h.Hour] {
			c.hours[h.Hour] = h
		}
	}

	// Store top lists only over the hour ranges that are not in memory.
	sort.Slice(memHours, func(i, j int) bool { return memHours[i] < memHours[j] })
	var ranges [][2]int64
	start := from
	for _, h := range memHours {
		if h > start {
			ranges = append(ranges, [2]int64{start, h})
		}
		start = h + hourSec
	}
	if start < to {
		ranges = append(ranges, [2]int64{start, to})
	}
	for _, kind := range kinds {
		dst := c.tops[kind]
		for _, rg := range ranges {
			entries, err := r.st.LoadTop(kind, rg[0], rg[1], storeTopLimit)
			if err != nil {
				return collected{}, err
			}
			for _, e := range entries {
				mergeCounter(dst, e.Key, e.Count, e.Sum, e.Last*1000)
			}
		}
	}
	return c, nil
}

func mergeCounter(m map[string]*counter, key string, count int64, sum float64, last int64) {
	c := m[key]
	if c == nil {
		c = &counter{}
		m[key] = c
	}
	c.count += count
	c.sum += sum
	if last > c.last {
		c.last = last
	}
}

type keyCounter struct {
	key string
	*counter
}

// ranked returns the counters sorted by count (highest first), then key; at most n (n <= 0: all).
func ranked(m map[string]*counter, n int) []keyCounter {
	out := make([]keyCounter, 0, len(m))
	for k, c := range m {
		out = append(out, keyCounter{k, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].key < out[j].key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func round(v float64, decimals int) float64 {
	p := math.Pow10(decimals)
	return math.Round(v*p) / p
}

// Summary for the last hours (24, 168 or 720; others → 24) up to now, store + memory.
// 720 has daily buckets (local days of r.loc, so a bar runs from midnight to midnight
// local time, 23 or 25 hours around a DST change), else hourly; buckets without data are
// present with 0. Top lists at most 20 entries. The 24/168 windows are the last N hours
// including the current one; the 720 window is the last 30 local days including today,
// so the daily series covers it exactly. Statistics are kept per UTC hour, so in a zone
// with a half-hour offset a day starts with the first full hour after local midnight.
func (r *Recorder) Summary(hours int, now time.Time) (Summary, error) {
	switch hours {
	case 24, 168, 720:
	default:
		hours = 24
	}
	cur := hourOf(now.Unix())
	to := cur + hourSec
	var from int64
	var days []int64
	gran := "hour"
	if hours == 720 {
		gran = "day"
		days = dayStarts(now, r.loc, 30)
		from = hourOf(days[0] + hourSec - 1) // first full stored hour of the first day
	} else {
		from = cur - int64(hours-1)*hourSec
	}

	c, err := r.collect(from, to, allKinds)
	if err != nil {
		return Summary{}, err
	}

	s := Summary{Hours: hours, Granularity: gran}
	var elapsed float64
	for _, h := range c.hours {
		s.Totals.Queries += h.Queries
		s.Totals.Blocked += h.Blocked
		s.Totals.Cached += h.Cached
		s.Totals.SafeSearch += h.SafeSearch
		s.Totals.Local += h.Local
		s.Totals.Services += h.Services
		elapsed += h.ElapsedMS
	}
	if s.Totals.Queries > 0 {
		s.Totals.BlockedPct = round(float64(s.Totals.Blocked)*100/float64(s.Totals.Queries), 1)
		s.Totals.AvgMS = round(elapsed/float64(s.Totals.Queries), 2)
	}

	if gran == "hour" {
		s.Series = make([]Point, hours)
		for i := range s.Series {
			h := from + int64(i)*hourSec
			s.Series[i] = Point{T: h * 1000}
			s.Series[i].add(c.hours[h])
		}
	} else {
		s.Series = make([]Point, 30)
		for i := range s.Series {
			s.Series[i].T = days[i] * 1000
		}
		for h, st := range c.hours {
			// the day whose next start lies after the hour (h >= from >= days[0])
			i := sort.Search(len(s.Series), func(i int) bool { return days[i+1] > h })
			if i == len(s.Series) {
				continue // cannot happen: to <= end of today
			}
			s.Series[i].add(st)
		}
	}

	// The series covers the window exactly: its capped cache counts are the total, so the
	// tile "Aus dem Cache" and the bars agree.
	s.Totals.Cached = 0
	for _, p := range s.Series {
		s.Totals.Cached += p.Cached
	}

	s.TopDomains = nameCounts(c.tops[kindDomain])
	s.TopBlocked = nameCounts(c.tops[kindBlocked])
	s.TopClients = clientCounts(c.tops[kindClient], c.tops[kindClientBlocked], summaryTopN)
	s.TopUpstreams = []UpstreamCount{}
	for _, kc := range ranked(c.tops[kindUpstream], summaryTopN) {
		u := UpstreamCount{Address: kc.key, Count: kc.count}
		if kc.count > 0 {
			u.AvgMS = round(kc.sum/float64(kc.count), 2)
		}
		s.TopUpstreams = append(s.TopUpstreams, u)
	}
	return s, nil
}

func nameCounts(m map[string]*counter) []NameCount {
	out := []NameCount{}
	for _, kc := range ranked(m, summaryTopN) {
		out = append(out, NameCount{Name: kc.key, Count: kc.count})
	}
	return out
}

func clientCounts(clients, blocked map[string]*counter, n int) []ClientCount {
	out := []ClientCount{}
	for _, kc := range ranked(clients, n) {
		cc := ClientCount{IP: kc.key, Count: kc.count, LastSeen: kc.last}
		if b := blocked[kc.key]; b != nil {
			cc.Blocked = b.count
		}
		out = append(out, cc)
	}
	return out
}

// RecentClients returns clients seen since since, most queries first, at most limit
// (limit <= 0: 100). Counts cover whole hours, starting with the hour of since.
func (r *Recorder) RecentClients(since time.Time, limit int) ([]ClientCount, error) {
	if limit <= 0 {
		limit = recentDefault
	}
	from := hourOf(since.Unix())
	to := hourOf(r.now().Unix()) + hourSec
	if to <= from {
		to = from + hourSec
	}
	c, err := r.collect(from, to, []string{kindClient, kindClientBlocked})
	if err != nil {
		return nil, err
	}
	return clientCounts(c.tops[kindClient], c.tops[kindClientBlocked], limit), nil
}

// Reset clears memory and store.
func (r *Recorder) Reset() error {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	r.mu.Lock()
	r.buckets = map[int64]*bucket{}
	r.mu.Unlock()
	return r.st.ClearStats()
}
