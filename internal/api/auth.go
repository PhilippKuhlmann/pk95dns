package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"pk95dns/internal/store"
)

const (
	sessionCookie   = "pk95dns_session"
	sessionTTL      = 7 * 24 * time.Hour
	minTokenLen     = 32
	minPasswordLen  = 12
	maxPasswordLen  = 72 // bcrypt limit (bytes)
	loginFailures   = 5
	loginWindow     = 15 * time.Minute
	initialPassFile = "initial-admin-password"
	adminUser       = "admin"
)

// dummyHash is compared against for unknown users, so the answer time does not reveal
// whether an account exists.
var dummyHash = func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("pk95dns-dummy-password"), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return h
}()

// InitialPasswordFile is the path of the file with the initial admin password.
func InitialPasswordFile(dataDir string) string {
	return filepath.Join(dataDir, initialPassFile)
}

// EnsureAdmin creates the account "admin" with a random password when there is no user yet
// (standalone first start). The password is written to <dataDir>/initial-admin-password
// (0600) and returned; "" when an account already existed.
func EnsureAdmin(st *store.Store, dataDir string) (string, error) {
	n, err := st.UserCount()
	if err != nil {
		return "", err
	}
	if n > 0 {
		return "", nil
	}
	pw, err := randomPassword()
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(InitialPasswordFile(dataDir), []byte(pw+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("Startpasswort kann nicht gespeichert werden: %w", err)
	}
	if _, err := st.CreateUser(adminUser, string(hash)); err != nil {
		_ = os.Remove(InitialPasswordFile(dataDir))
		return "", err
	}
	return pw, nil
}

// randomPassword returns 18 random bytes, base64url (24 characters).
func randomPassword() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (a *API) initToken() {
	if len(a.d.CoreToken) >= minTokenLen {
		a.tokenHash = sha256.Sum256([]byte(a.d.CoreToken))
		a.tokenOK = true
	}
}

// validBearer compares the bearer token in constant time (over SHA-256 hashes, so the
// length does not leak either).
func (a *API) validBearer(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	scheme, token, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	token = strings.TrimSpace(token)
	got := sha256.Sum256([]byte(token))
	match := subtle.ConstantTimeCompare(got[:], a.tokenHash[:]) == 1
	return match && a.tokenOK && len(token) >= minTokenLen
}

type ctxKey int

const userKey ctxKey = 1

// session is the authenticated standalone user of a request.
type session struct {
	user      store.User
	tokenHash string
}

func sessionOf(r *http.Request) (session, bool) {
	s, ok := r.Context().Value(userKey).(session)
	return s, ok
}

// sessionFromCookie looks up the session of the request cookie.
func (a *API) sessionFromCookie(r *http.Request) (session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" || len(c.Value) > 200 {
		return session{}, false
	}
	h := hashToken(c.Value)
	u, err := a.d.Store.SessionUser(h, a.d.Now().UnixMilli())
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			slog.Warn("api: session lookup failed", "error", err)
		}
		return session{}, false
	}
	return session{user: u, tokenHash: h}, true
}

// auth protects /api/* and /core/* (except GET /core/health and the login routes).
func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := cleanPath(r.URL.Path)
		if !isAPIPath(p) || (p == "/core/health" && r.Method == http.MethodGet) {
			next.ServeHTTP(w, r)
			return
		}
		if a.d.CoreMode {
			switch p {
			case "/api/login", "/api/logout", "/api/password":
				writeError(w, http.StatusUnauthorized, msgCoreLogin)
				return
			}
			if !a.validBearer(r) {
				writeError(w, http.StatusUnauthorized, msgCoreAuth)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if p == "/api/login" || p == "/api/logout" {
			next.ServeHTTP(w, r)
			return
		}
		s, ok := a.sessionFromCookie(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, msgUnauth)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, s)))
	})
}

// clientIP is the remote address without port (the limiter key; proxies are not trusted).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func secureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (a *API) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// loginKey is the limiter key of a client: the IPv4 address, or the /64 of an IPv6 address
// (one host usually owns a whole /64 and could otherwise rotate addresses).
func loginKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	key := loginKey(clientIP(r))
	now := a.d.Now()
	// The attempt is counted before the password check, in one locked step: parallel
	// requests cannot all pass the check before the first failure is recorded.
	if !a.limiter.reserve(key, now) {
		writeError(w, http.StatusTooManyRequests, "Zu viele fehlgeschlagene Anmeldungen. Bitte in 15 Minuten erneut versuchen.")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		a.limiter.release(key, now)
		return
	}
	u, err := a.d.Store.UserByName(strings.TrimSpace(body.Username))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		a.limiter.release(key, now)
		internalError(w, r, err)
		return
	}
	hash := dummyHash
	if err == nil {
		hash = []byte(u.PasswordHash)
	}
	// bcrypt is expensive: only a few checks run at the same time (all clients together).
	select {
	case loginSlots <- struct{}{}:
	case <-r.Context().Done():
		a.limiter.release(key, now)
		return
	}
	pwOK := len(body.Password) <= maxPasswordLen &&
		bcrypt.CompareHashAndPassword(hash, []byte(body.Password)) == nil
	<-loginSlots
	if err != nil || !pwOK {
		// The reserved attempt stays counted as a failure.
		writeError(w, http.StatusUnauthorized, "Benutzername oder Passwort ist falsch.")
		return
	}
	a.limiter.reset(key)

	token, err := newSessionToken()
	if err != nil {
		internalError(w, r, err)
		return
	}
	if err := a.d.Store.CreateSession(hashToken(token), u.ID, now.Add(sessionTTL).UnixMilli()); err != nil {
		internalError(w, r, err)
		return
	}
	if err := a.d.Store.PruneSessions(now.UnixMilli()); err != nil {
		slog.Warn("api: pruning sessions failed", "error", err)
	}
	a.setSessionCookie(w, r, token, int(sessionTTL/time.Second))
	writeJSON(w, http.StatusOK, map[string]string{"username": u.Username})
}

func newSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s, ok := a.sessionFromCookie(r); ok {
		if err := a.d.Store.DeleteSession(s.tokenHash); err != nil {
			internalError(w, r, err)
			return
		}
	}
	a.setSessionCookie(w, r, "", -1)
	writeNoContent(w)
}

func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	if a.d.CoreMode {
		writeJSON(w, http.StatusOK, map[string]any{"username": "PK95 Core", "core_mode": true})
		return
	}
	s, _ := sessionOf(r)
	writeJSON(w, http.StatusOK, map[string]any{"username": s.user.Username, "core_mode": false})
}

func (a *API) handlePassword(w http.ResponseWriter, r *http.Request) {
	s, ok := sessionOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, msgUnauth)
		return
	}
	var body struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decode(w, r, &body) {
		return
	}
	fields := map[string]string{}
	if len(body.Current) > maxPasswordLen ||
		bcrypt.CompareHashAndPassword([]byte(s.user.PasswordHash), []byte(body.Current)) != nil {
		fields["current"] = "Das aktuelle Passwort ist falsch."
	}
	switch {
	case utf8.RuneCountInString(body.New) < minPasswordLen:
		fields["new"] = fmt.Sprintf("Das neue Passwort braucht mindestens %d Zeichen.", minPasswordLen)
	case len(body.New) > maxPasswordLen:
		fields["new"] = fmt.Sprintf("Das neue Passwort darf höchstens %d Bytes lang sein.", maxPasswordLen)
	}
	if len(fields) > 0 {
		writeFields(w, fields)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.New), bcrypt.DefaultCost)
	if err != nil {
		internalError(w, r, err)
		return
	}
	if err := a.d.Store.SetPasswordHash(s.user.ID, string(hash)); err != nil {
		internalError(w, r, err)
		return
	}
	// End all other sessions of the user.
	if err := a.d.Store.DeleteUserSessions(s.user.ID, s.tokenHash); err != nil {
		internalError(w, r, err)
		return
	}
	if a.d.DataDir != "" {
		if err := os.Remove(InitialPasswordFile(a.d.DataDir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("api: cannot remove the initial password file", "error", err)
		}
	}
	writeNoContent(w)
}

// loginSlots limits the password checks running at the same time.
var loginSlots = make(chan struct{}, 4)

// loginLimiter counts login attempts per client key (loginKey): an attempt is reserved
// before the password check and stays counted unless it succeeds (reset) or ends before the
// check (release). After loginFailures within loginWindow the key is blocked until the
// oldest attempt leaves the window.
type loginLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{failures: map[string][]time.Time{}}
}

func (l *loginLimiter) recent(ip string, now time.Time) []time.Time {
	ts := l.failures[ip]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= loginWindow {
		i++
	}
	ts = ts[i:]
	if len(ts) == 0 {
		delete(l.failures, ip)
		return nil
	}
	l.failures[ip] = ts
	return ts
}

func (l *loginLimiter) blocked(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(ip, now)) >= loginFailures
}

// reserve counts an attempt for ip unless ip is blocked; false means blocked.
func (l *loginLimiter) reserve(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.recent(ip, now)) >= loginFailures {
		return false
	}
	l.failures[ip] = append(l.failures[ip], now)
	l.prune(now)
	return true
}

// release removes an attempt reserved at ts that never reached the password check.
func (l *loginLimiter) release(ip string, ts time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	list := l.failures[ip]
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].Equal(ts) {
			list = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(l.failures, ip)
	} else {
		l.failures[ip] = list
	}
}

// prune drops stale keys now and then to keep the map small. Called with mu held.
func (l *loginLimiter) prune(now time.Time) {
	if len(l.failures) > 10000 {
		for k := range l.failures {
			l.recent(k, now)
		}
	}
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
}
