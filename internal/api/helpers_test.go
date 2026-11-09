package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"pk95dns/internal/cache"
	"pk95dns/internal/config"
	"pk95dns/internal/filter"
	"pk95dns/internal/lists"
	"pk95dns/internal/querylog"
	"pk95dns/internal/stats"
	"pk95dns/internal/store"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef" // 48 chars

// env is a complete API with real components (except the DNS server: nil).
type env struct {
	t        *testing.T
	dir      string
	st       *store.Store
	eng      *filter.Engine
	lists    *lists.Manager
	cache    *cache.Cache
	qlog     *querylog.Writer
	stats    *stats.Recorder
	api      *API
	settings atomic.Pointer[config.Settings]
	now      time.Time

	mu         sync.Mutex
	reloads    int
	updateErr  error // returned by UpdateSettings (after mutate) when set
	reloadErr  error
	listServer *httptest.Server
	listBody   atomic.Value // string
	cookie     *http.Cookie
}

type envOpt func(d *Deps)

func coreMode(token string) envOpt {
	return func(d *Deps) {
		d.CoreMode = true
		d.CoreToken = token
	}
}

func newEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "pk95dns.db"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: dir, st: st, eng: filter.NewEngine(), now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	e.listBody.Store("||blocked.example^\n||ads.example.net^\n")
	e.listServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/missing") {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, e.listBody.Load().(string))
	}))
	e.lists = lists.NewManager(st, e.eng, dir, lists.Options{})
	e.cache = cache.New(100, 0, 0)
	e.qlog = querylog.NewWriter(st)
	e.stats = stats.New(st)
	s := config.Defaults()
	e.settings.Store(&s)
	d := Deps{
		Store:    st,
		Lists:    e.lists,
		Filter:   e.eng,
		Stats:    e.stats,
		QueryLog: e.qlog,
		Cache:    e.cache,
		Settings: func() config.Settings { return e.settings.Load().Clone() },
		UpdateSettings: func(mutate func(s *config.Settings) error) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			s := e.settings.Load().Clone()
			if err := mutate(&s); err != nil {
				return err
			}
			if e.updateErr != nil {
				return e.updateErr
			}
			if err := st.SaveSettings(s); err != nil {
				return err
			}
			e.settings.Store(&s)
			return nil
		},
		Reload: func() error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.reloads++
			return e.reloadErr
		},
		Version:   "1.2.3",
		DataDir:   dir,
		StartedAt: time.UnixMilli(1762700000000),
		Now:       func() time.Time { return e.now },
	}
	for _, o := range opts {
		o(&d)
	}
	e.api = New(d)
	t.Cleanup(func() {
		e.listServer.Close()
		waitLists(e.lists)
		st.Close()
	})
	return e
}

// waitLists waits until no list download is running.
func waitLists(m *lists.Manager) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		busy := false
		for id := int64(1); id < 50; id++ {
			if m.Updating(id) {
				busy = true
				break
			}
		}
		if !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type reqOpt func(r *http.Request)

func bearer(tok string) reqOpt {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

func header(k, v string) reqOpt {
	return func(r *http.Request) { r.Header.Set(k, v) }
}

func noCookie() reqOpt {
	return func(r *http.Request) { r.Header.Del("Cookie") }
}

func remote(addr string) reqOpt {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

// do sends a request. body: nil, string (raw) or a value encoded as JSON. Writing methods
// get Content-Type application/json unless an option changes it.
func (e *env) do(method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(data)
	}
	r := httptest.NewRequest(method, path, rd)
	if method != http.MethodGet && method != http.MethodHead {
		r.Header.Set("Content-Type", "application/json")
	}
	if e.cookie != nil {
		r.AddCookie(e.cookie)
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	e.api.ServeHTTP(w, r)
	return w
}

// login creates the admin account (password "start-password-123") and logs in.
func (e *env) login() {
	e.t.Helper()
	e.createUser("admin", "start-password-123")
	w := e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "start-password-123"})
	if w.Code != 200 {
		e.t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	e.cookie = sessionCookieOf(e.t, w)
}

func (e *env) createUser(name, pw string) store.User {
	e.t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		e.t.Fatal(err)
	}
	u, err := e.st.CreateUser(name, string(h))
	if err != nil && !errors.Is(err, store.ErrDuplicate) {
		e.t.Fatal(err)
	}
	return u
}

func sessionCookieOf(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatalf("no session cookie in %v", w.Header())
	return nil
}

// decodeBody decodes the JSON answer into v.
func decodeBody(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
}

// jsonMap decodes the answer into a generic map.
func jsonMap(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	decodeBody(t, w, &m)
	return m
}

// expect checks the status code.
func expect(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("status %d, want %d: %s", w.Code, code, w.Body.String())
	}
}

// expectFields checks a 422 answer with the given field keys.
func expectFields(t *testing.T, w *httptest.ResponseRecorder, keys ...string) map[string]string {
	t.Helper()
	expect(t, w, http.StatusUnprocessableEntity)
	var body struct {
		Error  string            `json:"error"`
		Fields map[string]string `json:"fields"`
	}
	decodeBody(t, w, &body)
	if body.Error != "Bitte Eingaben prüfen." {
		t.Errorf("error = %q", body.Error)
	}
	for _, k := range keys {
		if body.Fields[k] == "" {
			t.Errorf("missing field error %q in %v", k, body.Fields)
		}
	}
	if len(body.Fields) != len(keys) {
		t.Errorf("fields = %v, want keys %v", body.Fields, keys)
	}
	return body.Fields
}

func errorOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	decodeBody(t, w, &body)
	return body.Error
}
