// Package app wires PK95 DNS together: store, filter engine, lists, upstream router, cache,
// query log, statistics, DNS server, HTTP API and events to Core.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"pk95dns/internal/api"
	"pk95dns/internal/cache"
	"pk95dns/internal/config"
	"pk95dns/internal/dnsserver"
	"pk95dns/internal/filter"
	"pk95dns/internal/lists"
	"pk95dns/internal/querylog"
	"pk95dns/internal/records"
	"pk95dns/internal/stats"
	"pk95dns/internal/store"
	"pk95dns/internal/upstream"
)

// Config comes from the environment (main.go).
type Config struct {
	Version   string
	Listen    string // HTTP, e.g. "0.0.0.0:8053"
	DNSListen string // e.g. ":53"
	DataDir   string
	CoreMode  bool
	CoreURL   string
	CoreToken string
}

// Timing of the background loops.
const (
	pauseCheckEvery    = time.Second
	monitorEvery       = 10 * time.Second
	upstreamDownAfter  = 60 * time.Second
	sessionPruneEvery  = time.Hour
	httpShutdownWait   = 10 * time.Second
	routerErrorMessage = "Die Upstream-Einstellungen können nicht verwendet werden: "
)

// Default lists of a fresh installation (docs/design.md → First start).
var defaultLists = []store.List{
	{Name: "AdGuard DNS filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", Kind: "block", Enabled: true},
	{Name: "OISD Small", URL: "https://small.oisd.nl/", Kind: "block", Enabled: false},
}

// Run starts everything and blocks until ctx is done, then shuts down gracefully
// (HTTP shutdown, DNS listeners closed, query log and statistics flushed).
func Run(ctx context.Context, cfg Config) error {
	a, err := newApp(cfg)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		a.st.Close()
		return fmt.Errorf("HTTP-Port %s kann nicht geöffnet werden: %w", cfg.Listen, err)
	}
	return a.run(ctx, ln)
}

// app holds the long-lived components.
type app struct {
	cfg     Config
	st      *store.Store
	eng     *filter.Engine
	lists   *lists.Manager
	cache   *cache.Cache
	qlog    *querylog.Writer
	stats   *stats.Recorder
	dns     *dnsserver.Server
	events  *eventSender // nil in standalone mode
	started time.Time

	mu       sync.Mutex     // serializes runtime changes
	index    *records.Index // compiled zones and records (guarded by mu, rebuilt by reload)
	settings atomic.Pointer[config.Settings]
	router   atomic.Pointer[upstream.Router]
	// routerCfg is the upstream config of the settings the current router stands for
	// (guarded by mu). When the stored upstreams were unusable at start it is still theirs,
	// while the router uses the defaults: unrelated settings changes keep that router.
	routerCfg upstream.Config
	newRouter func(upstream.Config) (*upstream.Router, error)
	now       func() time.Time

	failedMu    sync.Mutex
	failedLists map[int64]bool // lists with a sent lists.update_failed event

	monitor upstreamMonitor
}

// newApp opens the store and builds every component (nothing runs yet).
func newApp(cfg Config) (*app, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("Datenverzeichnis %s kann nicht angelegt werden: %w", cfg.DataDir, err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "lists"), 0o750); err != nil {
		return nil, fmt.Errorf("Listenverzeichnis kann nicht angelegt werden: %w", err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "pk95dns.db"))
	if err != nil {
		return nil, err
	}
	a := &app{
		cfg:         cfg,
		st:          st,
		started:     time.Now(),
		newRouter:   upstream.NewRouter,
		now:         time.Now,
		failedLists: map[int64]bool{},
	}
	if err := a.init(); err != nil {
		st.Close()
		return nil, err
	}
	return a, nil
}

func (a *app) init() error {
	cfg := a.cfg
	if err := firstStart(a.st); err != nil {
		return err
	}
	if cfg.CoreMode {
		a.events = newEventSender(cfg.CoreURL, cfg.CoreToken)
	} else {
		pw, err := api.EnsureAdmin(a.st, cfg.DataDir)
		if err != nil {
			return fmt.Errorf("Admin-Konto kann nicht angelegt werden: %w", err)
		}
		file := api.InitialPasswordFile(cfg.DataDir)
		if pw != "" {
			slog.Warn("Erster Start: Konto „admin“ angelegt. Bitte nach der Anmeldung das Passwort ändern.",
				"password", pw, "file", file)
		} else if _, err := os.Stat(file); err == nil {
			slog.Info("Das Startpasswort für „admin“ steht noch in der Datei; sie verschwindet nach der ersten Passwortänderung.",
				"file", file)
		}
	}

	s, err := a.st.LoadSettings()
	if err != nil {
		return err
	}
	if fields := s.Validate(); len(fields) > 0 {
		slog.Warn("Gespeicherte Einstellungen sind ungültig; betroffene Werte bitte prüfen.", "fields", fields)
	}
	s = s.Normalized()
	a.settings.Store(&s)

	a.eng = filter.NewEngine()
	text, err := a.st.CustomRules()
	if err != nil {
		return err
	}
	custom, _ := filter.Compile([]filter.Source{{ID: 0, Data: []byte(text)}})
	a.eng.SetCustom(custom)

	a.lists = lists.NewManager(a.st, a.eng, cfg.DataDir, lists.Options{
		UserAgent: "PK95-DNS/" + cfg.Version,
		OnResult:  a.onListResult,
	})
	if err := a.lists.Rebuild(); err != nil {
		return err
	}

	a.cache = cache.New(s.CacheSize, s.CacheMinTTL, s.CacheMaxTTL)
	a.qlog = querylog.NewWriter(a.st)
	a.stats = stats.New(a.st)
	a.dns = dnsserver.New(dnsserver.Deps{
		Filter:   a.eng,
		Cache:    a.cache,
		Log:      a.qlog,
		Stats:    a.stats,
		OnListen: a.onListen,
	})

	rcfg := routerConfig(s)
	router, err := a.newRouter(rcfg)
	if err != nil {
		slog.Error("Upstreams aus den Einstellungen sind unbrauchbar, nutze die Standard-Upstreams.", "error", err)
		if router, err = a.newRouter(routerConfig(config.Defaults())); err != nil {
			return err
		}
		// rcfg stays the stored config: only a change of the upstream settings builds a
		// new router, other changes (pause, protection, services) keep the fallback.
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.routerCfg = rcfg
	if err := a.compileRecordsLocked(); err != nil {
		return err
	}
	return a.applyLocked(s, router)
}

// firstStart creates the default lists and stores the default settings on the very first
// start. The stored settings row marks later starts, so lists the user removed stay gone.
func firstStart(st *store.Store) error {
	var n int
	if err := st.DB.QueryRow(`SELECT COUNT(*) FROM settings WHERE key = 'settings'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	ls, err := st.Lists()
	if err != nil {
		return err
	}
	if len(ls) == 0 {
		for _, l := range defaultLists {
			if _, err := st.CreateList(l); err != nil && !errors.Is(err, store.ErrDuplicate) {
				return err
			}
		}
	}
	return st.SaveSettings(config.Defaults())
}

// routerConfig builds the router configuration from the settings.
func routerConfig(s config.Settings) upstream.Config {
	routes := make([]upstream.Route, 0, len(s.Conditional))
	for _, c := range s.Conditional {
		routes = append(routes, upstream.Route{Domain: c.Domain, Upstream: c.Upstream})
	}
	return upstream.Config{
		Upstreams:        append([]string{}, s.Upstreams...),
		Fallback:         append([]string{}, s.Fallback...),
		Bootstrap:        append([]string{}, s.Bootstrap...),
		Mode:             s.UpstreamMode,
		Timeout:          s.UpstreamTimeout(),
		Routes:           routes,
		PrivatePTR:       s.PrivatePTR,
		PrivateUpstreams: append([]string{}, s.PrivateUpstreams...),
	}
}

// currentSettings returns the settings in use.
func (a *app) currentSettings() config.Settings {
	return a.settings.Load().Clone()
}

// compileRecordsLocked builds the records index from the zones and records in the store.
// Callers hold a.mu.
func (a *app) compileRecordsLocked() error {
	zones, err := a.st.Zones()
	if err != nil {
		return err
	}
	recs, err := a.st.Records(store.RecordFilter{})
	if err != nil {
		return err
	}
	a.index = records.Compile(zones, recs)
	return nil
}

// applyLocked hands settings, router, the records index and clients to the DNS server.
// Callers hold a.mu.
func (a *app) applyLocked(s config.Settings, router *upstream.Router) error {
	clients, err := a.st.Clients()
	if err != nil {
		return err
	}
	a.dns.Apply(dnsserver.Runtime{
		Settings: s,
		Router:   router,
		Records:  a.index,
		Clients:  clients,
	})
	a.router.Store(router)
	return nil
}

// updateSettings implements api.Deps.UpdateSettings: mutate a copy, build a new router
// when the upstream configuration changed (an unusable configuration keeps the old router
// and nothing is stored), store, apply.
func (a *app) updateSettings(mutate func(s *config.Settings) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.currentSettings()
	if err := mutate(&s); err != nil {
		return err
	}
	s = s.Normalized()
	router := a.router.Load()
	rcfg := routerConfig(s)
	changed := !reflect.DeepEqual(rcfg, a.routerCfg)
	if changed {
		r, err := a.newRouter(rcfg)
		if err != nil {
			return &api.InvalidError{Msg: routerErrorMessage + err.Error()}
		}
		router = r
	}
	if err := a.st.SaveSettings(s); err != nil {
		if changed {
			router.Close()
		}
		return err
	}
	a.settings.Store(&s)
	if changed {
		a.routerCfg = rcfg
	}
	err := a.applyLocked(s, router)
	// Flush after the new router is in use: queries that started on the old one cannot
	// store their answers any more (the flush starts a new cache generation). Answers of
	// other upstreams may differ (conditional forwarding, private PTR).
	if changed || !s.CacheEnabled {
		a.cache.Flush()
	}
	return err
}

// reload recompiles zones and records and re-applies them and the clients
// (api.Deps.Reload).
func (a *app) reload() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.compileRecordsLocked(); err != nil {
		return err
	}
	return a.applyLocked(a.currentSettings(), a.router.Load())
}

// upstreamHealth returns the health of the main upstreams.
func (a *app) upstreamHealth() []upstream.Health {
	if r := a.router.Load(); r != nil {
		return r.Health()
	}
	return nil
}

// handler builds the HTTP API.
func (a *app) handler() http.Handler {
	return api.New(api.Deps{
		Store:          a.st,
		Lists:          a.lists,
		Filter:         a.eng,
		DNS:            a.dns,
		Stats:          a.stats,
		QueryLog:       a.qlog,
		Cache:          a.cache,
		Settings:       a.currentSettings,
		UpdateSettings: a.updateSettings,
		Reload:         a.reload,
		Upstreams:      a.upstreamHealth,
		Version:        a.cfg.Version,
		CoreMode:       a.cfg.CoreMode,
		CoreToken:      a.cfg.CoreToken,
		DataDir:        a.cfg.DataDir,
		StartedAt:      a.started,
	})
}

// run serves until ctx is done, then shuts everything down and closes the store.
func (a *app) run(ctx context.Context, ln net.Listener) error {
	defer a.st.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	srv := &http.Server{
		Handler:           a.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
	}

	// Shutdown runs in stages: the DNS server first (it waits for the queries in flight),
	// then the query log and statistics with their final flush, so the last queries are
	// written too, then the store is closed.
	flushCtx, stopFlush := context.WithCancel(context.Background())
	defer stopFlush()
	var wg, dnsWG, flushWG sync.WaitGroup
	startOn := func(g *sync.WaitGroup, f func()) {
		g.Add(1)
		go func() {
			defer g.Done()
			f()
		}()
	}
	start := func(f func()) { startOn(&wg, f) }
	startOn(&dnsWG, func() { a.dns.ListenAndServe(ctx, a.cfg.DNSListen) })
	startOn(&flushWG, func() { a.qlog.Run(flushCtx, a.currentSettings) })
	startOn(&flushWG, func() { a.stats.Run(flushCtx, a.currentSettings) })
	start(func() { a.lists.Run(ctx, a.currentSettings) })
	start(func() { a.loop(ctx, pauseCheckEvery, a.checkPause) })
	start(func() { a.loop(ctx, monitorEvery, a.checkUpstreams) })
	start(func() { a.loop(ctx, sessionPruneEvery, a.pruneSessions) })
	start(func() { a.events.run(ctx) })

	httpErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpErr <- err
		}
		close(httpErr)
	}()

	mode := "standalone"
	if a.cfg.CoreMode {
		mode = "core"
	}
	slog.Info("PK95 DNS gestartet", "version", a.cfg.Version, "http", ln.Addr().String(),
		"dns", a.cfg.DNSListen, "mode", mode, "data", a.cfg.DataDir)

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-httpErr:
		if err != nil {
			runErr = fmt.Errorf("HTTP-Server beendet: %w", err)
		}
	}
	slog.Info("PK95 DNS wird beendet")
	cancel()
	shutdownCtx, stop := context.WithTimeout(context.Background(), httpShutdownWait)
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("HTTP-Server nicht sauber beendet", "error", err)
	}
	stop()
	dnsWG.Wait() // DNS listeners closed, queries in flight answered and logged
	stopFlush()
	flushWG.Wait() // query log and statistics flushed
	wg.Wait()
	if r := a.router.Load(); r != nil {
		r.Close()
	}
	return runErr
}

// loop calls f every interval until ctx is done.
func (a *app) loop(ctx context.Context, every time.Duration, f func()) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}

// checkPause switches protection on again when a pause expired.
func (a *app) checkPause() {
	s := a.settings.Load()
	if s.ProtectionPausedUntil == 0 || a.now().UnixMilli() < s.ProtectionPausedUntil {
		return
	}
	err := a.updateSettings(func(s *config.Settings) error {
		if s.ProtectionPausedUntil != 0 && a.now().UnixMilli() >= s.ProtectionPausedUntil {
			s.ProtectionEnabled = true
			s.ProtectionPausedUntil = 0
		}
		return nil
	})
	if err != nil {
		slog.Warn("Pause des Schutzes kann nicht beendet werden", "error", err)
		return
	}
	slog.Info("Pause beendet, der Schutz ist wieder an")
}

// pruneSessions removes expired login sessions.
func (a *app) pruneSessions() {
	if err := a.st.PruneSessions(a.now().UnixMilli()); err != nil {
		slog.Warn("Abgelaufene Sitzungen können nicht entfernt werden", "error", err)
	}
}

// onListResult sends lists.update_failed once per list until a download works again.
func (a *app) onListResult(l store.List, errMsg string) {
	a.failedMu.Lock()
	already := a.failedLists[l.ID]
	if errMsg == "" {
		delete(a.failedLists, l.ID)
	} else {
		a.failedLists[l.ID] = true
	}
	a.failedMu.Unlock()
	if errMsg == "" || already {
		return
	}
	a.events.send(api.EventListUpdateFailed, sevWarning,
		fmt.Sprintf("Liste „%s“ konnte nicht aktualisiert werden", l.Name),
		errMsg+". Die letzte gute Fassung bleibt in Gebrauch.",
		map[string]any{"list_id": l.ID, "name": l.Name, "url": l.URL})
}

// onListen reports DNS listener problems to Core.
func (a *app) onListen(ok bool, msg string) {
	if ok {
		slog.Info("DNS-Server lauscht wieder", "listen", a.cfg.DNSListen)
		body := msg
		if body == "" {
			body = "Der DNS-Server lauscht auf " + a.cfg.DNSListen + "."
		}
		a.events.send(api.EventDNSListenOK, sevInfo, "DNS-Server läuft wieder", body,
			map[string]any{"listen": a.cfg.DNSListen})
		return
	}
	slog.Error("DNS-Server kann nicht lauschen", "listen", a.cfg.DNSListen, "error", msg)
	a.events.send(api.EventDNSListenFailed, sevCritical, "DNS-Server kann nicht starten",
		msg+" Neuer Versuch alle 30 Sekunden.", map[string]any{"listen": a.cfg.DNSListen})
}
