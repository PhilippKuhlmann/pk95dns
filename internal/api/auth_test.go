package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/", "/api/status", "/core/health", "/app.js"} {
		w := e.do("GET", path, nil)
		h := w.Header()
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "same-origin" ||
			h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: headers %v", path, h)
		}
		if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s: CSP %q", path, h.Get("Content-Security-Policy"))
		}
	}
}

func TestContentTypeRequired(t *testing.T) {
	e := newEnv(t, coreMode(testToken))
	tests := []struct {
		method, ctype string
		want          int
	}{
		{"POST", "", http.StatusUnsupportedMediaType},
		{"POST", "text/plain", http.StatusUnsupportedMediaType},
		{"PUT", "application/x-www-form-urlencoded", http.StatusUnsupportedMediaType},
		{"DELETE", "", http.StatusUnsupportedMediaType},
		{"DELETE", "application/json", http.StatusNoContent},
		{"DELETE", "application/json; charset=utf-8", http.StatusNoContent},
	}
	for _, tc := range tests {
		w := e.do(tc.method, "/api/cache", nil, bearer(testToken), header("Content-Type", tc.ctype))
		if w.Code != tc.want {
			t.Errorf("%s %q: %d, want %d", tc.method, tc.ctype, w.Code, tc.want)
		}
	}
	// GET needs no content type.
	w := e.do("GET", "/api/settings", nil, bearer(testToken))
	expect(t, w, 200)
}

func TestContentTypeMissingHeader(t *testing.T) {
	e := newEnv(t, coreMode(testToken))
	w := e.do("POST", "/api/lists/refresh", "{}", bearer(testToken), func(r *http.Request) { r.Header.Del("Content-Type") })
	expect(t, w, http.StatusUnsupportedMediaType)
	if !strings.Contains(errorOf(t, w), "application/json") {
		t.Errorf("message: %s", w.Body)
	}
}

func TestBodyLimit(t *testing.T) {
	e := newEnv(t, coreMode(testToken))
	big := `{"text":"` + strings.Repeat("a", maxBody) + `"}`
	// Known length.
	w := e.do("PUT", "/api/rules", big, bearer(testToken))
	expect(t, w, http.StatusRequestEntityTooLarge)
	// Unknown length (chunked).
	w = e.do("PUT", "/api/rules", big, bearer(testToken), func(r *http.Request) { r.ContentLength = -1 })
	expect(t, w, http.StatusRequestEntityTooLarge)
	if errorOf(t, w) == "" {
		t.Error("no error message")
	}
}

func TestCoreAuth(t *testing.T) {
	e := newEnv(t, coreMode(testToken))
	tests := []struct {
		name   string
		method string
		path   string
		opts   []reqOpt
		want   int
	}{
		{"valid token", "GET", "/api/status", []reqOpt{bearer(testToken)}, 200},
		{"lowercase scheme", "GET", "/api/status", []reqOpt{header("Authorization", "bearer "+testToken)}, 200},
		{"no token", "GET", "/api/status", nil, 401},
		{"wrong token", "GET", "/api/status", []reqOpt{bearer(strings.Repeat("x", 48))}, 401},
		{"prefix of token", "GET", "/api/status", []reqOpt{bearer(testToken[:40])}, 401},
		{"basic auth", "GET", "/api/status", []reqOpt{header("Authorization", "Basic "+testToken)}, 401},
		{"manifest needs token", "GET", "/core/manifest", nil, 401},
		{"manifest with token", "GET", "/core/manifest", []reqOpt{bearer(testToken)}, 200},
		{"backup needs token", "POST", "/core/backup/prepare", nil, 401},
		{"health without token", "GET", "/core/health", nil, 200},
		{"unknown api path", "GET", "/api/nope", nil, 401},
		{"unclean path", "GET", "/api/../api/status", nil, 401},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := e.do(tc.method, tc.path, nil, tc.opts...)
			if w.Code != tc.want {
				t.Fatalf("%d, want %d: %s", w.Code, tc.want, w.Body)
			}
			if w.Code == 401 && errorOf(t, w) == "" {
				t.Error("401 without error message")
			}
		})
	}
}

func TestCoreShortTokenNeverValid(t *testing.T) {
	short := "short-token-123"
	e := newEnv(t, coreMode(short))
	w := e.do("GET", "/api/status", nil, bearer(short))
	expect(t, w, 401)
	e2 := newEnv(t, coreMode(""))
	w = e2.do("GET", "/api/status", nil, bearer(""))
	expect(t, w, 401)
	w = e2.do("GET", "/api/status", nil, header("Authorization", "Bearer"))
	expect(t, w, 401)
}

func TestCoreLoginRoutesOff(t *testing.T) {
	e := newEnv(t, coreMode(testToken))
	for _, path := range []string{"/api/login", "/api/logout", "/api/password"} {
		w := e.do("POST", path, map[string]string{"username": "admin", "password": "x"}, bearer(testToken))
		expect(t, w, 401)
		if got := errorOf(t, w); got != "PK95 DNS wird über PK95 Core verwaltet" {
			t.Errorf("%s: %q", path, got)
		}
	}
	w := e.do("GET", "/api/me", nil, bearer(testToken))
	expect(t, w, 200)
	if m := jsonMap(t, w); m["core_mode"] != true {
		t.Errorf("me = %v", m)
	}
}

func TestCoreModeRootNote(t *testing.T) {
	e := newEnv(t, coreMode(testToken))
	w := e.do("GET", "/", nil)
	expect(t, w, 200)
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(w.Body.String(), "PK95 Core verwaltet") {
		t.Errorf("note: %s %s", w.Header(), w.Body)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Error("CSP missing on HTML")
	}
	if w := e.do("GET", "/app.js", nil); w.Code != 404 {
		t.Errorf("web UI served in Core mode: %d", w.Code)
	}
}

func TestEnsureAdmin(t *testing.T) {
	e := newEnv(t)
	pw, err := EnsureAdmin(e.st, e.dir)
	if err != nil || len(pw) < 20 {
		t.Fatalf("EnsureAdmin = %q, %v", pw, err)
	}
	fi, err := os.Stat(InitialPasswordFile(e.dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(InitialPasswordFile(e.dir))
	if strings.TrimSpace(string(data)) != pw {
		t.Errorf("file content %q", data)
	}
	u, err := e.st.UserByName("admin")
	if err != nil || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pw)) != nil {
		t.Fatalf("admin not usable: %v", err)
	}
	// Second call: nothing new.
	pw2, err := EnsureAdmin(e.st, e.dir)
	if err != nil || pw2 != "" {
		t.Errorf("second EnsureAdmin = %q, %v", pw2, err)
	}

	// Login with it, change the password: the file goes away.
	w := e.do("POST", "/api/login", map[string]string{"username": "admin", "password": pw})
	expect(t, w, 200)
	e.cookie = sessionCookieOf(t, w)
	w = e.do("POST", "/api/password", map[string]string{"current": pw, "new": "a-much-better-password"})
	expect(t, w, 204)
	if _, err := os.Stat(InitialPasswordFile(e.dir)); !os.IsNotExist(err) {
		t.Errorf("initial password file still there: %v", err)
	}
}

func TestStandaloneLoginFlow(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "start-password-123")

	// Without session.
	expect(t, e.do("GET", "/api/me", nil), 401)
	expect(t, e.do("GET", "/api/status", nil), 401)
	expect(t, e.do("GET", "/core/manifest", nil), 401)
	expect(t, e.do("GET", "/core/health", nil), 200)

	tests := []struct {
		name, user, pass string
		want             int
	}{
		{"wrong password", "admin", "nope", 401},
		{"unknown user", "bob", "start-password-123", 401},
		{"too long password", "admin", strings.Repeat("x", 100), 401},
	}
	for _, tc := range tests {
		w := e.do("POST", "/api/login", map[string]string{"username": tc.user, "password": tc.pass}, remote("10.0.0.9:1234"))
		if w.Code != tc.want {
			t.Errorf("%s: %d", tc.name, w.Code)
		}
		if w.Code == 401 && errorOf(t, w) != "Benutzername oder Passwort ist falsch." {
			t.Errorf("%s: %s", tc.name, w.Body)
		}
	}
	expect(t, e.do("POST", "/api/login", "not json"), 400)

	w := e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "start-password-123"})
	expect(t, w, 200)
	if m := jsonMap(t, w); m["username"] != "admin" {
		t.Errorf("login answer %v", m)
	}
	c := sessionCookieOf(t, w)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Secure || c.Path != "/" ||
		c.MaxAge != int((7*24*time.Hour)/time.Second) || len(c.Value) < 40 {
		t.Errorf("cookie = %+v", c)
	}
	// Only the hash is stored.
	var n int
	if err := e.st.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token_hash = ?`, c.Value).Scan(&n); err != nil || n != 0 {
		t.Errorf("raw token stored: %d %v", n, err)
	}
	e.cookie = c
	w = e.do("GET", "/api/me", nil)
	expect(t, w, 200)
	if m := jsonMap(t, w); m["username"] != "admin" || m["core_mode"] != false {
		t.Errorf("me = %v", m)
	}
	expect(t, e.do("GET", "/api/status", nil), 200)

	// Logout ends the session.
	w = e.do("POST", "/api/logout", nil)
	expect(t, w, 204)
	if cleared := sessionCookieOf(t, w); cleared.MaxAge >= 0 {
		t.Errorf("logout cookie = %+v", cleared)
	}
	expect(t, e.do("GET", "/api/me", nil), 401)
	// Logout without session is fine too.
	e.cookie = nil
	expect(t, e.do("POST", "/api/logout", nil), 204)
}

func TestSecureCookie(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "start-password-123")
	w := e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "start-password-123"},
		header("X-Forwarded-Proto", "https"))
	expect(t, w, 200)
	if c := sessionCookieOf(t, w); !c.Secure {
		t.Error("cookie not Secure behind https proxy")
	}
}

func TestExpiredSession(t *testing.T) {
	e := newEnv(t)
	e.login()
	e.now = e.now.Add(8 * 24 * time.Hour)
	expect(t, e.do("GET", "/api/me", nil), 401)
}

func TestLoginLimiter(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "start-password-123")
	ip := remote("192.0.2.7:5555")
	for i := 0; i < 5; i++ {
		w := e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong"}, ip)
		expect(t, w, 401)
	}
	// Blocked, even with the right password.
	w := e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "start-password-123"}, ip)
	expect(t, w, 429)
	if !strings.Contains(errorOf(t, w), "15 Minuten") {
		t.Errorf("429 message: %s", w.Body)
	}
	// Other IPs are not affected.
	w = e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "start-password-123"}, remote("192.0.2.8:1"))
	expect(t, w, 200)
	// After 15 minutes it works again and a success resets the counter.
	e.now = e.now.Add(15*time.Minute + time.Second)
	w = e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "start-password-123"}, ip)
	expect(t, w, 200)
	for i := 0; i < 4; i++ {
		expect(t, e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong"}, ip), 401)
	}
	expect(t, e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "start-password-123"}, ip), 200)
}

func TestLimiterWindow(t *testing.T) {
	l := newLoginLimiter()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if !l.reserve("a", t0.Add(time.Duration(i)*time.Minute)) {
			t.Fatalf("attempt %d refused", i+1)
		}
	}
	if l.reserve("a", t0.Add(5*time.Minute)) {
		t.Fatal("sixth attempt reserved")
	}
	if !l.blocked("a", t0.Add(5*time.Minute)) {
		t.Fatal("not blocked after 5 failures")
	}
	// The first failure leaves the window after 15 minutes.
	if l.blocked("a", t0.Add(15*time.Minute)) {
		t.Error("still blocked after the oldest failure expired")
	}
	if l.blocked("b", t0) {
		t.Error("other ip blocked")
	}
}

// Parallel attempts are counted before the password check: at most loginFailures pass.
func TestLoginLimiterParallel(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "start-password-123")
	const n = 32
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "203.0.113.9:1234"
			w := httptest.NewRecorder()
			e.api.ServeHTTP(w, r)
			codes <- w.Code
		}()
	}
	wg.Wait()
	close(codes)
	got := map[int]int{}
	for c := range codes {
		got[c]++
	}
	if got[401] != loginFailures || got[429] != n-loginFailures {
		t.Fatalf("codes %v, want %d x 401 and %d x 429", got, loginFailures, n-loginFailures)
	}
}

func TestLoginKey(t *testing.T) {
	tests := map[string]string{
		"192.0.2.7":            "192.0.2.7",
		"::ffff:192.0.2.7":     "192.0.2.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2::ffff":   "2001:db8:1:2::/64",
		"fe80::1%eth0":         "fe80::/64",
		"not-an-ip":            "not-an-ip",
	}
	for in, want := range tests {
		if got := loginKey(in); got != want {
			t.Errorf("loginKey(%q) = %q, want %q", in, got, want)
		}
	}
	// A malformed body does not use up an attempt.
	e := newEnv(t)
	e.createUser("admin", "start-password-123")
	for range 10 {
		e.do("POST", "/api/login", "{", remote("[2001:db8::1]:1"))
	}
	// The whole /64 shares one budget.
	for i := range loginFailures {
		addr := fmt.Sprintf("[2001:db8::%x]:1", i+1)
		expect(t, e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong"}, remote(addr)), 401)
	}
	expect(t, e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "start-password-123"}, remote("[2001:db8::99]:1")), 429)
	expect(t, e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "start-password-123"}, remote("[2001:db8:0:1::1]:1")), 200)
}

func TestPasswordChange(t *testing.T) {
	e := newEnv(t)
	e.login()
	// A second session that must end.
	w := e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "start-password-123"}, noCookie())
	other := sessionCookieOf(t, w)

	tests := []struct {
		name   string
		body   map[string]string
		fields []string
	}{
		{"wrong current", map[string]string{"current": "nope", "new": "long-enough-password"}, []string{"current"}},
		{"short new", map[string]string{"current": "start-password-123", "new": "short"}, []string{"new"}},
		{"both", map[string]string{"current": "x", "new": "y"}, []string{"current", "new"}},
		{"too long new", map[string]string{"current": "start-password-123", "new": strings.Repeat("ä", 40)}, []string{"new"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectFields(t, e.do("POST", "/api/password", tc.body), tc.fields...)
		})
	}
	expect(t, e.do("POST", "/api/password", map[string]string{"current": "start-password-123", "new": "new-password-4567"}), 204)
	// This session lives on, the other one is gone.
	expect(t, e.do("GET", "/api/me", nil), 200)
	expect(t, e.do("GET", "/api/me", nil, noCookie(), func(r *http.Request) { r.AddCookie(other) }), 401)
	// New password works, old one not.
	expect(t, e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "start-password-123"}, noCookie()), 401)
	expect(t, e.do("POST", "/api/login", map[string]string{"username": "admin", "password": "new-password-4567"}, noCookie()), 200)
}

func TestWebUI(t *testing.T) {
	e := newEnv(t)
	tests := []struct {
		path, ctype, contains string
	}{
		{"/", "text/html", "<div id=\"app\">"},
		{"/index.html", "text/html", "<div id=\"app\">"},
		{"/app.js", "text/javascript", "use strict"},
		{"/style.css", "text/css", ""},
		{"/lists", "text/html", "<div id=\"app\">"},
		{"/some/deep/route", "text/html", "<div id=\"app\">"},
	}
	for _, tc := range tests {
		w := e.do("GET", tc.path, nil)
		expect(t, w, 200)
		if !strings.HasPrefix(w.Header().Get("Content-Type"), tc.ctype) {
			t.Errorf("%s: content type %q", tc.path, w.Header().Get("Content-Type"))
		}
		if w.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("%s: cache control %q", tc.path, w.Header().Get("Cache-Control"))
		}
		if !strings.Contains(w.Body.String(), tc.contains) {
			t.Errorf("%s: body does not contain %q", tc.path, tc.contains)
		}
	}
	// API and core paths never fall back to the UI.
	e.login()
	w := e.do("GET", "/api/unknown", nil)
	expect(t, w, 404)
	if errorOf(t, w) == "" {
		t.Error("404 without JSON error")
	}
	w = e.do("POST", "/", "{}")
	expect(t, w, http.StatusMethodNotAllowed)
}
