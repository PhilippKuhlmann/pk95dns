// Package querylog buffers query log entries and writes them to the store in batches
// (every second or 500 entries) and prunes old entries (docs/design.md → Storage).
package querylog

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"pk95dns/internal/config"
	"pk95dns/internal/store"
)

const (
	bufferSize = 10000 // entries waiting for the next write
	batchSize  = 500   // a full batch is written right away
)

// Writer is safe for concurrent use.
type Writer struct {
	st *store.Store

	// Timing, replaced in tests.
	flushEvery time.Duration
	pruneEvery time.Duration
	now        func() time.Time

	mu  sync.Mutex
	buf []store.Query

	writeMu sync.Mutex // serializes writes so batches reach the store in order

	wake      chan struct{} // signalled when a batch is full
	discarded atomic.Int64
	disabled  atomic.Bool                            // QuerylogEnabled == false (refreshed by Run)
	settings  atomic.Pointer[func() config.Settings] // set by Run
}

// NewWriter creates a writer for st.
func NewWriter(st *store.Store) *Writer {
	return &Writer{
		st:         st,
		flushEvery: time.Second,
		pruneEvery: 10 * time.Minute,
		now:        time.Now,
		buf:        make([]store.Query, 0, batchSize),
		wake:       make(chan struct{}, 1),
	}
}

// Add queues an entry without blocking. When the buffer (10000 entries) is full the entry
// is discarded and counted.
func (w *Writer) Add(q store.Query) {
	if w.disabled.Load() {
		return
	}
	w.mu.Lock()
	if len(w.buf) >= bufferSize {
		w.mu.Unlock()
		w.discarded.Add(1)
		return
	}
	w.buf = append(w.buf, q)
	n := len(w.buf)
	w.mu.Unlock()
	if n >= batchSize {
		select {
		case w.wake <- struct{}{}:
		default:
		}
	}
}

// Run writes batches until ctx is done (then flushes the rest) and prunes entries older
// than settings().QuerylogHours every 10 minutes. Entries are discarded while
// settings().QuerylogEnabled is false. When settings().AnonymizeIP is set, client IPs
// are anonymized before they are written (Anonymize is idempotent).
func (w *Writer) Run(ctx context.Context, settings func() config.Settings) {
	w.settings.Store(&settings)
	w.refresh()
	w.prune()

	flushT := time.NewTicker(w.flushEvery)
	defer flushT.Stop()
	pruneT := time.NewTicker(w.pruneEvery)
	defer pruneT.Stop()
	for {
		select {
		case <-ctx.Done():
			w.Flush()
			return
		case <-flushT.C:
			w.refresh()
			w.Flush()
		case <-w.wake:
			w.Flush()
		case <-pruneT.C:
			w.prune()
		}
	}
}

// currentSettings returns the settings of Run, ok false before Run started.
func (w *Writer) currentSettings() (config.Settings, bool) {
	f := w.settings.Load()
	if f == nil {
		return config.Settings{}, false
	}
	return (*f)(), true
}

// refresh updates the cached enabled flag used by Add.
func (w *Writer) refresh() {
	if cfg, ok := w.currentSettings(); ok {
		w.disabled.Store(!cfg.QuerylogEnabled)
	}
}

func (w *Writer) prune() {
	cfg, ok := w.currentSettings()
	if !ok || cfg.QuerylogHours <= 0 {
		return
	}
	before := w.now().Add(-time.Duration(cfg.QuerylogHours) * time.Hour).UnixMilli()
	if _, err := w.st.PruneQueries(before); err != nil {
		slog.Warn("querylog: prune failed", "error", err)
	}
}

// Flush writes everything queued now (used by tests and before reads that must see the
// latest entries, e.g. GET /api/querylog).
func (w *Writer) Flush() {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	w.mu.Lock()
	batch := w.buf
	if len(batch) == 0 {
		w.mu.Unlock()
		return
	}
	w.buf = make([]store.Query, 0, batchSize)
	w.mu.Unlock()

	if cfg, ok := w.currentSettings(); ok {
		if !cfg.QuerylogEnabled {
			w.disabled.Store(true)
			return
		}
		if cfg.AnonymizeIP {
			for i := range batch {
				batch[i].ClientIP = Anonymize(batch[i].ClientIP)
			}
		}
	}
	if err := w.st.InsertQueries(batch); err != nil {
		slog.Warn("querylog: write failed", "entries", len(batch), "error", err)
	}
}

// Discarded returns the number of entries lost because the buffer was full.
func (w *Writer) Discarded() int64 { return w.discarded.Load() }

// Anonymize returns the IP with IPv4 last octet 0 and IPv6 cut to /48; other strings unchanged.
// IPv4-mapped IPv6 addresses keep their form with the IPv4 part anonymized; zones are dropped.
func Anonymize(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.WithZone("")
	bits := 48
	switch {
	case a.Is4():
		bits = 24
	case a.Is4In6():
		bits = 120
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ip
	}
	return p.Addr().String()
}
