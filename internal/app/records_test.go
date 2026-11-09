package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
	"pk95dns/internal/records"
)

// v1Schema is the schema of PK95 DNS 1.0 (user_version 1), copied from
// internal/store/zones_test.go. Keep it unchanged.
const v1Schema = `
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE lists (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, url TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 1, rule_count INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT '', etag TEXT NOT NULL DEFAULT '', last_modified TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE custom_rules (id INTEGER PRIMARY KEY CHECK (id = 1), text TEXT NOT NULL, updated_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE rewrites (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	domain     TEXT    NOT NULL,
	answer     TEXT    NOT NULL,
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL DEFAULT 0,
	UNIQUE (domain, answer)
);
CREATE TABLE clients (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL COLLATE NOCASE UNIQUE, ids TEXT NOT NULL DEFAULT '[]',
	use_global_settings INTEGER NOT NULL DEFAULT 1, filtering_enabled INTEGER NOT NULL DEFAULT 1,
	safesearch TEXT NOT NULL DEFAULT '{}', use_global_services INTEGER NOT NULL DEFAULT 1,
	blocked_services TEXT NOT NULL DEFAULT '[]', created_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);
CREATE TABLE queries (
	id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, client_ip TEXT NOT NULL DEFAULT '', client_name TEXT NOT NULL DEFAULT '',
	name TEXT NOT NULL DEFAULT '', qtype TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '',
	rule TEXT NOT NULL DEFAULT '', list_id INTEGER NOT NULL DEFAULT 0, service TEXT NOT NULL DEFAULT '', upstream TEXT NOT NULL DEFAULT '',
	rcode TEXT NOT NULL DEFAULT '', answer TEXT NOT NULL DEFAULT '', elapsed_ms REAL NOT NULL DEFAULT 0, cached INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX queries_ts ON queries (ts);
CREATE INDEX queries_name ON queries (name);
CREATE INDEX queries_client_ip ON queries (client_ip);
CREATE TABLE stats_hours (
	hour INTEGER PRIMARY KEY, queries INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0, cached INTEGER NOT NULL DEFAULT 0,
	safesearch INTEGER NOT NULL DEFAULT 0, services INTEGER NOT NULL DEFAULT 0, elapsed_ms REAL NOT NULL DEFAULT 0
);
CREATE TABLE stats_top (
	hour INTEGER NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0, sum REAL NOT NULL DEFAULT 0,
	PRIMARY KEY (hour, kind, key)
) WITHOUT ROWID;
CREATE INDEX stats_top_kind_hour ON stats_top (kind, hour);
PRAGMA user_version = 1;
`

// A 1.0 installation with rewrites starts as 2.0: /api/rewrites and /api/records show the
// same ids, the DNS server answers them, and new records never reuse an old id.
func TestMigrationThroughAPI(t *testing.T) {
	cfg := testConfig(t, true)
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(cfg.DataDir, "pk95dns.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{v1Schema,
		`INSERT INTO rewrites (id, domain, answer, enabled, created_at) VALUES
			(3, 'nas.home.lan', '192.168.1.10', 1, 1000),
			(7, 'nas.home.lan', 'fd00::10', 1, 1001),
			(9, 'alias.lan', 'nas.home.lan', 0, 1002),
			(12, '*.dev.lan', '192.168.1.50', 1, 1003)`,
		`DELETE FROM rewrites WHERE id = 12`, // the highest id was deleted in 1.0
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	db.Close()

	a, err := newApp(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.st.Close()
	h := a.handler()
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(data))
		r.Header.Set("Authorization", "Bearer "+cfg.CoreToken)
		if method != http.MethodGet {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	decode := func(w *httptest.ResponseRecorder, code int, v any) {
		t.Helper()
		if w.Code != code {
			t.Fatalf("status %d, want %d: %s", w.Code, code, w.Body)
		}
		if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
			t.Fatal(err)
		}
	}

	type rewrite struct {
		ID        int64  `json:"id"`
		Domain    string `json:"domain"`
		Answer    string `json:"answer"`
		Enabled   bool   `json:"enabled"`
		CreatedAt int64  `json:"created_at"`
	}
	var rws []rewrite
	decode(call("GET", "/api/rewrites", nil), 200, &rws)
	want := []rewrite{
		{9, "alias.lan", "nas.home.lan", false, 1002},
		{3, "nas.home.lan", "192.168.1.10", true, 1000},
		{7, "nas.home.lan", "fd00::10", true, 1001},
	}
	if len(rws) != len(want) {
		t.Fatalf("rewrites %+v", rws)
	}
	for i := range want {
		if rws[i] != want[i] {
			t.Fatalf("rewrite %d: %+v, want %+v", i, rws[i], want[i])
		}
	}
	var recs []records.Record
	decode(call("GET", "/api/records", nil), 200, &recs)
	types := map[int64]string{}
	for _, r := range recs {
		if r.TTL != records.RewriteTTL || r.ZoneID != 0 {
			t.Fatalf("migrated record %+v", r)
		}
		types[r.ID] = r.Type
	}
	if len(recs) != 3 || types[3] != "A" || types[7] != "AAAA" || types[9] != "CNAME" {
		t.Fatalf("records %+v", recs)
	}

	// The DNS server answers the migrated records.
	if c := a.dns.Check("nas.home.lan", dns.TypeAAAA, ""); c.Status != "rewrite" || c.Reason != "record" || c.Answer != "fd00::10" {
		t.Fatalf("check %+v", c)
	}
	if c := a.dns.Check("alias.lan", dns.TypeA, ""); c.Status == "rewrite" {
		t.Fatalf("disabled record answered: %+v", c)
	}

	// New records continue after the highest 1.0 id (12, deleted).
	var rw rewrite
	decode(call("POST", "/api/rewrites", map[string]any{"domain": "printer.home.lan", "answer": "192.168.1.20"}), 201, &rw)
	if rw.ID != 13 {
		t.Fatalf("new id %d", rw.ID)
	}

	// A zone takes the records over; the reload recompiles the index.
	var z records.Zone
	decode(call("POST", "/api/zones", map[string]any{"name": "home.lan"}), 201, &z)
	if z.RecordCount != 3 {
		t.Fatalf("zone %+v", z)
	}
	if c := a.dns.Check("nas.home.lan", dns.TypeA, ""); c.Reason != "zone" || c.Answer != "192.168.1.10" {
		t.Fatalf("check in zone %+v", c)
	}
	if c := a.dns.Check("missing.home.lan", dns.TypeA, ""); c.Status != "rewrite" || c.Reason != "zone" || c.Answer != "" {
		t.Fatalf("NXDOMAIN of the zone %+v", c)
	}
	var st struct {
		Rules struct {
			Rewrites int `json:"rewrites"`
			Zones    int `json:"zones"`
			Records  int `json:"records"`
		} `json:"rules"`
	}
	decode(call("GET", "/api/status", nil), 200, &st)
	if st.Rules.Zones != 1 || st.Rules.Records != 3 || st.Rules.Rewrites != 3 {
		t.Fatalf("status rules %+v", st.Rules)
	}

	// A settings change keeps the index.
	if err := a.updateSettings(func(s *config.Settings) error { s.Ratelimit = 7; return nil }); err != nil {
		t.Fatal(err)
	}
	if c := a.dns.Check("nas.home.lan", dns.TypeA, ""); c.Reason != "zone" {
		t.Fatalf("after settings change %+v", c)
	}
}
