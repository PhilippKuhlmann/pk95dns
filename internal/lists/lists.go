// Package lists downloads and updates block/allow lists, keeps their last good copy in
// <data>/lists/<id>.txt and compiles all enabled lists into the filter engine.
package lists

import (
	"context"
	"net/http"

	"pk95dns/internal/config"
	"pk95dns/internal/filter"
	"pk95dns/internal/store"
)

// CatalogEntry is a well-known list (GET /api/lists/catalog).
type CatalogEntry struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// Catalog returns the well-known lists (AdGuard DNS filter, OISD small/big, StevenBlack,
// HaGeZi Light/Normal/Pro, 1Hosts Lite, AdAway, Phishing Army, …) with German descriptions.
func Catalog() []CatalogEntry { panic("not implemented") }

// Options of the manager.
type Options struct {
	HTTP *http.Client // nil = default client with 60 s timeout
	// OnResult is called after every download attempt (err "" on success). Optional.
	OnResult func(l store.List, err string)
}

// Manager is safe for concurrent use.
type Manager struct {
	// unexported fields
}

// NewManager creates a manager for the lists in st, the files in dataDir/lists and eng.
func NewManager(st *store.Store, eng *filter.Engine, dataDir string, opt Options) *Manager {
	panic("not implemented")
}

// Rebuild compiles all enabled lists from their local copies into the engine
// (eng.SetLists). Called at start and after a list was enabled, disabled or removed.
func (m *Manager) Rebuild() error { panic("not implemented") }

// Refresh downloads the given lists (none = all enabled) in the background, one at a time,
// then rebuilds. A list already being downloaded is not queued twice.
func (m *Manager) Refresh(ids ...int64) { panic("not implemented") }

// Updating reports whether a download for the list is queued or running.
func (m *Manager) Updating(id int64) bool { panic("not implemented") }

// Forget removes the local copy of a removed list and rebuilds.
func (m *Manager) Forget(id int64) error { panic("not implemented") }

// Run refreshes all enabled lists every settings().ListsUpdateHours (0 = never) – counted
// from each list's updated_at, checked every 10 minutes – and lists without a local copy
// right away, until ctx is done.
func (m *Manager) Run(ctx context.Context, settings func() config.Settings) {
	panic("not implemented")
}
