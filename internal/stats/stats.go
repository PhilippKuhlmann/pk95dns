// Package stats aggregates queries per UTC hour in memory, flushes them to the store
// (every minute and on shutdown) and builds the summaries of GET /api/stats.
package stats

import (
	"context"
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
	Services   int64   `json:"services"`
	AvgMS      float64 `json:"avg_ms"`
}

type Point struct {
	T       int64 `json:"t"` // unix ms of the bucket start
	Queries int64 `json:"queries"`
	Blocked int64 `json:"blocked"`
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

// Recorder is safe for concurrent use. Record must be cheap (called per query).
type Recorder struct {
	// unexported fields
}

// New creates a recorder for st.
func New(st *store.Store) *Recorder { panic("not implemented") }

// Record counts one query into the current hour.
func (r *Recorder) Record(e Event) { panic("not implemented") }

// Run flushes every minute and on hour change, prunes hours older than settings().StatsDays
// once per hour, and flushes on ctx done.
func (r *Recorder) Run(ctx context.Context, settings func() config.Settings) {
	panic("not implemented")
}

// Flush writes the in-memory hour(s) now.
func (r *Recorder) Flush() error { panic("not implemented") }

// Summary for the last hours (24, 168 or 720; others → 24) up to now, store + memory.
// 720 has daily buckets (UTC days), else hourly; buckets without data are present with 0.
// Top lists at most 20 entries.
func (r *Recorder) Summary(hours int, now time.Time) (Summary, error) {
	panic("not implemented")
}

// RecentClients returns clients seen since since, most queries first, at most limit.
func (r *Recorder) RecentClients(since time.Time, limit int) ([]ClientCount, error) {
	panic("not implemented")
}

// Reset clears memory and store.
func (r *Recorder) Reset() error { panic("not implemented") }
