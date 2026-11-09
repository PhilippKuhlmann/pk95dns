// Package api is the HTTP API of PK95 DNS (docs/api.md): JSON routes for the web UI and the
// PK95 Core module, authentication (session cookie standalone, bearer token in Core mode),
// the Core protocol routes and the embedded web UI.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"pk95dns/internal/cache"
	"pk95dns/internal/config"
	"pk95dns/internal/dnsserver"
	"pk95dns/internal/filter"
	"pk95dns/internal/lists"
	"pk95dns/internal/querylog"
	"pk95dns/internal/stats"
	"pk95dns/internal/store"
	"pk95dns/internal/upstream"
)

// maxBody is the limit of request bodies (413 above).
const maxBody = 2 << 20

// csp is the Content-Security-Policy of every answer.
const csp = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; " +
	"connect-src 'self'; frame-ancestors 'none'"

// Deps are the components the handlers work with.
type Deps struct {
	Store    *store.Store
	Lists    *lists.Manager
	Filter   *filter.Engine
	DNS      *dnsserver.Server // nil: the DNS parts (listen status, check, host names) stay empty
	Stats    *stats.Recorder
	QueryLog *querylog.Writer
	Cache    *cache.Cache

	// Settings returns the current settings (including the json:"-" fields).
	Settings func() config.Settings
	// UpdateSettings changes the settings atomically: it calls mutate with a copy of the
	// current settings; when mutate returns nil, the new settings are applied to the
	// runtime and stored. Errors of mutate are returned unchanged. An *InvalidError (e.g.
	// the upstreams can not be used) is answered with 422, other errors with 500.
	UpdateSettings func(mutate func(s *config.Settings) error) error
	// Reload re-applies zones, records (recompiled index) and clients from the store to the
	// DNS server.
	Reload func() error
	// Upstreams returns the health of the main upstreams (GET /api/status). Optional.
	Upstreams func() []upstream.Health

	Version   string
	CoreMode  bool
	CoreToken string
	DataDir   string // initial-admin-password lives here
	StartedAt time.Time
	Now       func() time.Time // nil = time.Now
}

// InvalidError is an error caused by the submitted values; the API answers it with 422 and
// its German message.
type InvalidError struct {
	Msg string
}

func (e *InvalidError) Error() string { return e.Msg }

// validationError carries field errors from a mutate function to the handler.
type validationError struct {
	fields map[string]string
}

func (e *validationError) Error() string { return "Bitte Eingaben prüfen." }

// API is the HTTP handler.
type API struct {
	d       Deps
	mux     *http.ServeMux
	handler http.Handler
	limiter *loginLimiter

	tokenHash [32]byte // SHA-256 of the Core token
	tokenOK   bool     // the Core token is long enough to be used at all

	rulesMu sync.Mutex // serializes custom rule changes, guards customN
	customN int        // number of valid custom rules, -1 = unknown

	namesMu sync.Mutex
	names   map[int64]string // list id → name, nil = reload

	recordsMu sync.Mutex // serializes zone and record writes (validation against the stored set)
}

// New builds the handler.
func New(d Deps) *API {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Settings == nil {
		d.Settings = config.Defaults
	}
	a := &API{d: d, mux: http.NewServeMux(), limiter: newLoginLimiter(), customN: -1}
	a.initToken()
	a.routes()
	a.handler = a.secure(a.limitBody(a.requireJSON(a.auth(a.mux))))
	return a
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.handler.ServeHTTP(w, r)
}

func (a *API) routes() {
	m := a.mux
	// Authentication.
	m.HandleFunc("POST /api/login", a.handleLogin)
	m.HandleFunc("POST /api/logout", a.handleLogout)
	m.HandleFunc("GET /api/me", a.handleMe)
	m.HandleFunc("POST /api/password", a.handlePassword)

	// Core protocol.
	m.HandleFunc("GET /core/health", a.handleHealth)
	m.HandleFunc("GET /core/manifest", a.handleManifest)
	m.HandleFunc("POST /core/backup/prepare", a.handleBackupPrepare)

	// Status, protection, statistics, query log.
	m.HandleFunc("GET /api/status", a.handleStatus)
	m.HandleFunc("POST /api/protection", a.handleProtection)
	m.HandleFunc("GET /api/stats", a.handleStats)
	m.HandleFunc("DELETE /api/stats", a.handleStatsReset)
	m.HandleFunc("GET /api/querylog", a.handleQuerylog)
	m.HandleFunc("DELETE /api/querylog", a.handleQuerylogClear)

	// Lists.
	m.HandleFunc("GET /api/lists", a.handleLists)
	m.HandleFunc("GET /api/lists/catalog", a.handleCatalog)
	m.HandleFunc("POST /api/lists", a.handleListCreate)
	m.HandleFunc("POST /api/lists/refresh", a.handleListsRefresh)
	m.HandleFunc("PUT /api/lists/{id}", a.handleListUpdate)
	m.HandleFunc("DELETE /api/lists/{id}", a.handleListDelete)
	m.HandleFunc("POST /api/lists/{id}/refresh", a.handleListRefresh)

	// Custom rules and check.
	m.HandleFunc("GET /api/rules", a.handleRules)
	m.HandleFunc("PUT /api/rules", a.handleRulesSave)
	m.HandleFunc("POST /api/rules/quick", a.handleRulesQuick)
	m.HandleFunc("GET /api/check", a.handleCheck)

	// DNS zones and records.
	m.HandleFunc("GET /api/zones", a.handleZones)
	m.HandleFunc("POST /api/zones", a.handleZoneCreate)
	m.HandleFunc("PUT /api/zones/{id}", a.handleZoneUpdate)
	m.HandleFunc("DELETE /api/zones/{id}", a.handleZoneDelete)
	m.HandleFunc("GET /api/records", a.handleRecords)
	m.HandleFunc("POST /api/records", a.handleRecordCreate)
	m.HandleFunc("PUT /api/records/{id}", a.handleRecordUpdate)
	m.HandleFunc("DELETE /api/records/{id}", a.handleRecordDelete)

	// Deprecated view on A/AAAA/CNAME records (version 1.0 "rewrites").
	m.HandleFunc("GET /api/rewrites", a.handleRewrites)
	m.HandleFunc("POST /api/rewrites", a.handleRewriteCreate)
	m.HandleFunc("PUT /api/rewrites/{id}", a.handleRewriteUpdate)
	m.HandleFunc("DELETE /api/rewrites/{id}", a.handleRewriteDelete)

	// Services.
	m.HandleFunc("GET /api/services", a.handleServices)
	m.HandleFunc("PUT /api/services", a.handleServicesSave)

	// Clients.
	m.HandleFunc("GET /api/clients", a.handleClients)
	m.HandleFunc("POST /api/clients", a.handleClientCreate)
	m.HandleFunc("PUT /api/clients/{id}", a.handleClientUpdate)
	m.HandleFunc("DELETE /api/clients/{id}", a.handleClientDelete)

	// Settings, cache, upstream test.
	m.HandleFunc("GET /api/settings", a.handleSettings)
	m.HandleFunc("PUT /api/settings", a.handleSettingsSave)
	m.HandleFunc("DELETE /api/cache", a.handleCacheClear)
	m.HandleFunc("POST /api/upstreams/test", a.handleUpstreamsTest)

	// Unknown API routes answer JSON.
	notFound := func(w http.ResponseWriter, _ *http.Request) { writeError(w, http.StatusNotFound, "Nicht gefunden.") }
	m.HandleFunc("/api/", notFound)
	m.HandleFunc("/core/", notFound)

	// Web UI.
	m.HandleFunc("/", a.handleWeb)
}

// --- Middleware -------------------------------------------------------------

// secure sets the security headers on every answer.
func (a *API) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}

// limitBody rejects bodies over 2 MiB (413).
func (a *API) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxBody {
			writeError(w, http.StatusRequestEntityTooLarge, msgTooLarge)
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

// requireJSON answers 415 for writing requests without Content-Type application/json
// (CSRF guard for the cookie session).
func (a *API) requireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mt != "application/json" {
				writeError(w, http.StatusUnsupportedMediaType, "Content-Type muss application/json sein.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// cleanPath returns the cleaned request path (auth decisions use it, the mux redirects
// unclean paths anyway).
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

func isAPIPath(p string) bool {
	return p == "/api" || strings.HasPrefix(p, "/api/") || p == "/core" || strings.HasPrefix(p, "/core/")
}

// --- JSON helpers -----------------------------------------------------------

const (
	msgTooLarge  = "Die Anfrage ist zu groß (höchstens 2 MiB)."
	msgCheck     = "Bitte Eingaben prüfen."
	msgInternal  = "Interner Fehler. Details stehen im Protokoll von PK95 DNS."
	msgNotFound  = "Nicht gefunden."
	msgBadJSON   = "Ungültiges JSON."
	msgUnauth    = "Bitte melde dich an."
	msgCoreAuth  = "Ungültiger oder fehlender Token."
	msgCoreLogin = "PK95 DNS wird über PK95 Core verwaltet"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		slog.Debug("api: write failed", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeFields(w http.ResponseWriter, fields map[string]string) {
	writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": msgCheck, "fields": fields})
}

func writeNoContent(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// internalError logs err and answers 500.
func internalError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("api: request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	writeError(w, http.StatusInternalServerError, msgInternal)
}

// writeUpdateError answers an error of Deps.UpdateSettings.
func writeUpdateError(w http.ResponseWriter, r *http.Request, err error) {
	var ve *validationError
	var ie *InvalidError
	switch {
	case errors.As(err, &ve):
		writeFields(w, ve.fields)
	case errors.As(err, &ie):
		writeError(w, http.StatusUnprocessableEntity, ie.Msg)
	default:
		internalError(w, r, err)
	}
}

// decode reads the JSON body into v. On failure it answers (400/413) and returns false.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	data, ok := readBody(w, r)
	if !ok {
		return false
	}
	if err := json.Unmarshal(data, v); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) && te.Field != "" {
			writeFields(w, map[string]string{te.Field: "Falscher Datentyp."})
			return false
		}
		writeError(w, http.StatusBadRequest, msgBadJSON)
		return false
	}
	return true
}

// readBody reads the whole body; 413 when it is over the limit.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, msgTooLarge)
			return nil, false
		}
		writeError(w, http.StatusBadRequest, "Die Anfrage konnte nicht gelesen werden.")
		return nil, false
	}
	return data, true
}
