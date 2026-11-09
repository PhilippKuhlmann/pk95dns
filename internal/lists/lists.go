// Package lists downloads and updates block/allow lists, keeps their last good copy in
// <data>/lists/<id>.txt and compiles all enabled lists into the filter engine.
package lists

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

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
func Catalog() []CatalogEntry {
	return append([]CatalogEntry(nil), catalog...)
}

// Download limits.
const (
	maxListSize     = 64 << 20
	downloadTimeout = 60 * time.Second
	defaultAgent    = "PK95-DNS"
	checkEvery      = 10 * time.Minute
	// minRetry: Run tries a list whose download failed again at most this often.
	minRetry = time.Hour
)

// Options of the manager.
type Options struct {
	HTTP *http.Client // nil = default client with 60 s timeout
	// OnResult is called after every download attempt (err "" on success). Optional.
	OnResult func(l store.List, err string)
	// UserAgent of the downloads; "" = "PK95-DNS".
	UserAgent string
}

// States of a list in Manager.pending.
const (
	stateQueued  = 1 // queued or downloading
	stateRebuild = 2 // downloaded, waits for the rebuild at the end of the batch
)

// Manager is safe for concurrent use.
type Manager struct {
	st       *store.Store
	eng      *filter.Engine
	dir      string
	client   *http.Client
	onResult func(l store.List, err string)
	agent    string

	ctx    context.Context // cancelled when Run ends
	cancel context.CancelFunc

	mu       sync.Mutex
	pending  map[int64]int // id → stateQueued / stateRebuild
	queue    []int64
	running  bool // worker goroutine active
	closed   bool // Run ended, no new downloads
	attempts map[int64]time.Time
	again    map[int64]bool // downloading now, download once more afterwards (Reload)
	wg       sync.WaitGroup

	rebuildMu sync.Mutex

	now      func() time.Time
	interval time.Duration // Run check interval
}

// maxRedirects limits the redirects of one list download.
const maxRedirects = 5

// checkRedirect follows at most maxRedirects redirects and never from https to http: the
// content of a list must not travel in clear text when its address promised TLS.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("zu viele Weiterleitungen")
	}
	if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("Weiterleitung von https auf " + req.URL.Scheme + " abgelehnt")
	}
	return nil
}

// isHTTPS reports whether a list address uses TLS. Lists fetched over http may have been
// altered on the way, so their hosts lines cannot rewrite names (filter.Source.NoRewrite).
func isHTTPS(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

// NewManager creates a manager for the lists in st, the files in dataDir/lists and eng.
func NewManager(st *store.Store, eng *filter.Engine, dataDir string, opt Options) *Manager {
	client := &http.Client{Timeout: downloadTimeout}
	if opt.HTTP != nil {
		c := *opt.HTTP
		client = &c
	}
	if client.CheckRedirect == nil {
		client.CheckRedirect = checkRedirect
	}
	agent := opt.UserAgent
	if agent == "" {
		agent = defaultAgent
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		st:       st,
		eng:      eng,
		dir:      filepath.Join(dataDir, "lists"),
		client:   client,
		onResult: opt.OnResult,
		agent:    agent,
		ctx:      ctx,
		cancel:   cancel,
		pending:  map[int64]int{},
		attempts: map[int64]time.Time{},
		again:    map[int64]bool{},
		now:      time.Now,
		interval: checkEvery,
	}
}

func (m *Manager) path(id int64) string {
	return filepath.Join(m.dir, strconv.FormatInt(id, 10)+".txt")
}

// Rebuild compiles all enabled lists from their local copies into the engine
// (eng.SetLists). Called at start and after a list was enabled, disabled or removed.
func (m *Manager) Rebuild() error {
	m.rebuildMu.Lock()
	defer m.rebuildMu.Unlock()
	ls, err := m.st.Lists()
	if err != nil {
		return err
	}
	var sources []filter.Source
	for _, l := range ls {
		if !l.Enabled {
			continue
		}
		data, err := os.ReadFile(m.path(l.ID))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			slog.Warn("lists: local copy unreadable", "list", l.ID, "error", err)
			continue
		}
		sources = append(sources, filter.Source{ID: l.ID, Allow: l.Kind == "allow", NoRewrite: !isHTTPS(l.URL), Data: data})
	}
	rs, _ := filter.Compile(sources)
	m.eng.SetLists(rs)
	return nil
}

// Refresh downloads the given lists (none = all enabled) in the background, one at a time,
// then rebuilds. A list already being downloaded is not queued twice.
func (m *Manager) Refresh(ids ...int64) {
	if len(ids) == 0 {
		ls, err := m.st.Lists()
		if err != nil {
			slog.Warn("lists: cannot read lists", "error", err)
			return
		}
		for _, l := range ls {
			if l.Enabled {
				ids = append(ids, l.ID)
			}
		}
	}
	m.enqueue(ids)
}

// Reload downloads list id again after its address changed. Unlike Refresh it does not
// skip a list whose download is running: that download fetches the old address, so the
// list is downloaded once more when it ends.
func (m *Manager) Reload(id int64) {
	m.mu.Lock()
	if m.pending[id] == stateQueued && !containsID(m.queue, id) {
		m.again[id] = true
	}
	m.mu.Unlock()
	m.enqueue([]int64{id})
}

func (m *Manager) enqueue(ids []int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	for _, id := range ids {
		if m.pending[id] == stateQueued {
			continue
		}
		m.pending[id] = stateQueued
		m.queue = append(m.queue, id)
	}
	if len(m.queue) > 0 && !m.running {
		m.running = true
		m.wg.Add(1)
		go m.work()
	}
}

// work is the single download worker: it drains the queue and rebuilds once at the end
// when a local copy changed. Downloaded lists stay "updating" until that rebuild is done,
// so a client polling the flag sees the new rules afterwards.
func (m *Manager) work() {
	defer m.wg.Done()
	changed := false
	for {
		m.mu.Lock()
		if m.ctx.Err() != nil {
			m.pending = map[int64]int{}
			m.again = map[int64]bool{}
			m.queue = nil
			m.running = false
			m.mu.Unlock()
			return
		}
		if len(m.queue) == 0 {
			if changed {
				m.mu.Unlock()
				if err := m.Rebuild(); err != nil {
					slog.Warn("lists: rebuild failed", "error", err)
				}
				changed = false
				continue
			}
			for id, state := range m.pending {
				if state == stateRebuild {
					delete(m.pending, id)
				}
			}
			m.running = false
			m.mu.Unlock()
			return
		}
		id := m.queue[0]
		m.queue = m.queue[1:]
		m.mu.Unlock()

		c, failed, stale := m.download(id)

		m.mu.Lock()
		if failed {
			m.attempts[id] = m.now()
		} else {
			delete(m.attempts, id)
		}
		if (stale || m.again[id]) && !m.closed && !containsID(m.queue, id) {
			// The address changed during the download: fetch the new one.
			m.pending[id] = stateQueued
			m.queue = append(m.queue, id)
		}
		delete(m.again, id)
		if m.pending[id] == stateQueued && !containsID(m.queue, id) {
			if c {
				m.pending[id] = stateRebuild
			} else {
				delete(m.pending, id)
			}
		}
		m.mu.Unlock()
		changed = changed || c
	}
}

func containsID(ids []int64, id int64) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// Updating reports whether a download for the list is queued or running.
func (m *Manager) Updating(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pending[id] != 0
}

// wait blocks until the worker is idle (tests).
func (m *Manager) wait() {
	for {
		m.mu.Lock()
		idle := !m.running
		m.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Forget removes the local copy of a removed list and rebuilds.
func (m *Manager) Forget(id int64) error {
	if err := os.Remove(m.path(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	m.mu.Lock()
	delete(m.attempts, id)
	m.mu.Unlock()
	return m.Rebuild()
}

// Run refreshes all enabled lists every settings().ListsUpdateHours (0 = never) – counted
// from each list's updated_at, checked every 10 minutes – and lists without a local copy
// right away, until ctx is done.
func (m *Manager) Run(ctx context.Context, settings func() config.Settings) {
	defer func() {
		m.mu.Lock()
		m.closed = true
		m.mu.Unlock()
		m.cancel()
		m.wg.Wait()
	}()
	m.enqueue(m.missing())
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.enqueue(m.due(settings().ListsUpdateHours))
		}
	}
}

// missing returns the enabled lists without a local copy.
func (m *Manager) missing() []int64 {
	ls, err := m.st.Lists()
	if err != nil {
		slog.Warn("lists: cannot read lists", "error", err)
		return nil
	}
	var ids []int64
	for _, l := range ls {
		if !l.Enabled {
			continue
		}
		if _, err := os.Stat(m.path(l.ID)); err != nil {
			ids = append(ids, l.ID)
		}
	}
	return ids
}

// due returns the enabled lists whose last update is at least hours old (hours 0 = none).
// A list whose download failed is tried again at most every hour (or every interval when
// that is shorter), not on every check.
func (m *Manager) due(hours int) []int64 {
	if hours <= 0 {
		return nil
	}
	ls, err := m.st.Lists()
	if err != nil {
		slog.Warn("lists: cannot read lists", "error", err)
		return nil
	}
	interval := time.Duration(hours) * time.Hour
	retry := min(interval, minRetry)
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []int64
	for _, l := range ls {
		if !l.Enabled {
			continue
		}
		if now.Sub(time.UnixMilli(l.UpdatedAt)) < interval {
			continue
		}
		if last, ok := m.attempts[l.ID]; ok && now.Sub(last) < retry {
			continue
		}
		ids = append(ids, l.ID)
	}
	return ids
}

// download fetches one list and stores the result. It reports whether the local copy
// changed (a rebuild is needed), whether the download failed and whether the list's
// address changed during the download (the result was dropped; download again).
func (m *Manager) download(id int64) (changed, failed, stale bool) {
	l, err := m.st.GetList(id)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			slog.Warn("lists: cannot read list", "list", id, "error", err)
		}
		return false, false, false
	}
	changed, res, msg := m.fetch(l)
	if cur, err := m.st.GetList(id); err == nil && cur.URL != l.URL {
		// Content and ETag belong to the old address.
		if changed {
			_ = os.Remove(m.path(id))
		}
		return false, false, true
	}
	if msg != "" {
		if m.ctx.Err() != nil {
			return false, false, false // shutting down: not the list's fault
		}
		slog.Warn("lists: download failed", "list", l.ID, "name", l.Name, "error", msg)
		res = l
		res.LastError = msg
		if err := m.st.SetListStatus(l.ID, l.RuleCount, 0, msg, "", ""); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return false, false, false
			}
			slog.Warn("lists: cannot store status", "list", l.ID, "error", err)
		}
	} else if err := m.st.SetListStatus(res.ID, res.RuleCount, res.UpdatedAt, "", res.ETag, res.LastModified); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Removed while downloading.
			_ = os.Remove(m.path(id))
			return false, false, false
		}
		slog.Warn("lists: cannot store status", "list", l.ID, "error", err)
	}
	if m.onResult != nil {
		m.onResult(res, msg)
	}
	return changed, msg != "", false
}

// fetch downloads l. On success it returns the list with the new status fields and
// whether the local copy was replaced; msg is a German error otherwise.
func (m *Manager) fetch(l store.List) (changed bool, out store.List, msg string) {
	path := m.path(l.ID)
	_, statErr := os.Stat(path)
	haveCopy := statErr == nil

	ctx, cancel := context.WithTimeout(m.ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.URL, nil)
	if err != nil {
		return false, l, "Ungültige Adresse: " + err.Error()
	}
	req.Header.Set("User-Agent", m.agent)
	if haveCopy {
		// Conditional GET only with a local copy: a 304 without one would leave us empty.
		if l.ETag != "" {
			req.Header.Set("If-None-Match", l.ETag)
		}
		if l.LastModified != "" {
			req.Header.Set("If-Modified-Since", l.LastModified)
		}
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return false, l, transferError(err)
	}
	defer resp.Body.Close()

	now := m.now().UnixMilli()
	if resp.StatusCode == http.StatusNotModified && haveCopy {
		l.UpdatedAt = now
		l.LastError = ""
		return false, l, ""
	}
	if resp.StatusCode != http.StatusOK {
		return false, l, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxListSize+1))
	if err != nil {
		return false, l, transferError(err)
	}
	if len(data) > maxListSize {
		return false, l, "Liste ist größer als 64 MiB"
	}
	count, _ := filter.ParseRules(data)
	if count == 0 {
		if len(data) == 0 {
			return false, l, "Die Liste ist leer"
		}
		return false, l, "Die Liste enthält keine gültigen Regeln"
	}
	if err := writeFile(path, data); err != nil {
		return false, l, "Liste kann nicht gespeichert werden: " + err.Error()
	}
	l.RuleCount = count
	l.UpdatedAt = now
	l.LastError = ""
	l.ETag = resp.Header.Get("ETag")
	l.LastModified = resp.Header.Get("Last-Modified")
	return true, l, ""
}

// transferError turns a client error into a German message.
func transferError(err error) string {
	var te interface{ Timeout() bool }
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &te) && te.Timeout() {
		return "Zeitüberschreitung beim Herunterladen"
	}
	return "Download fehlgeschlagen: " + err.Error()
}

// writeFile writes path atomically (temp file + rename).
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
