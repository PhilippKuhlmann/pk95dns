// Package querylog buffers query log entries and writes them to the store in batches
// (every second or 500 entries) and prunes old entries (docs/design.md → Storage).
package querylog

import (
	"context"

	"pk95dns/internal/config"
	"pk95dns/internal/store"
)

// Writer is safe for concurrent use.
type Writer struct {
	// unexported fields
}

// NewWriter creates a writer for st.
func NewWriter(st *store.Store) *Writer { panic("not implemented") }

// Add queues an entry without blocking. When the buffer (10000 entries) is full the entry
// is discarded and counted.
func (w *Writer) Add(q store.Query) { panic("not implemented") }

// Run writes batches until ctx is done (then flushes the rest) and prunes entries older
// than settings().QuerylogHours every 10 minutes. Entries are discarded while
// settings().QuerylogEnabled is false.
func (w *Writer) Run(ctx context.Context, settings func() config.Settings) {
	panic("not implemented")
}

// Flush writes everything queued now (used by tests and before reads that must see the
// latest entries, e.g. GET /api/querylog).
func (w *Writer) Flush() { panic("not implemented") }

// Discarded returns the number of entries lost because the buffer was full.
func (w *Writer) Discarded() int64 { panic("not implemented") }

// Anonymize returns the IP with IPv4 last octet 0 and IPv6 cut to /48; other strings unchanged.
func Anonymize(ip string) string { panic("not implemented") }
