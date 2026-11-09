package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"pk95dns/internal/records"
)

// v1Schema is the schema of version 1.0 (user_version 1) as it was shipped; tests build
// real v1 databases from it. Keep it unchanged.
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

// buildV1 creates a v1 database at path, runs the statements and closes it.
func buildV1(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?"+dsnOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range append([]string{v1Schema}, stmts...) {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func fixedClock(t *testing.T, ts time.Time) {
	t.Helper()
	old := nowMS
	nowMS = func() int64 { return ts.UnixMilli() }
	t.Cleanup(func() { nowMS = old })
}

func userVersion(t *testing.T, s *Store) int {
	t.Helper()
	var v int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func tableExists(t *testing.T, s *Store, name string) bool {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func TestMigrateV1Rewrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	buildV1(t, path,
		`INSERT INTO lists (name, url, kind) VALUES ('L', 'https://l', 'block')`,
		`INSERT INTO rewrites (domain, answer, enabled, created_at) VALUES ('nas.lan', '192.168.1.10', 1, 111)`, // 1
		`INSERT INTO rewrites (domain, answer, enabled, created_at) VALUES ('gone.lan', '10.0.0.1', 1, 222)`,    // 2
		`INSERT INTO rewrites (domain, answer, enabled, created_at) VALUES ('nas.lan', 'fd00::10', 0, 333)`,     // 3
		`INSERT INTO rewrites (domain, answer, enabled, created_at) VALUES ('*.dev.lan', 'nas.lan', 1, 444)`,    // 4
		`INSERT INTO rewrites (domain, answer, enabled, created_at) VALUES ('tv.lan', 'nas.lan', 1, 555)`,       // 5
		`INSERT INTO rewrites (domain, answer, enabled, created_at) VALUES ('last.lan', '10.0.0.9', 1, 666)`,    // 6
		`DELETE FROM rewrites WHERE id IN (2, 6)`,                                                               // gaps in the middle and at the end
	)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v := userVersion(t, s); v != 2 {
		t.Fatalf("user_version = %d", v)
	}
	if tableExists(t, s, "rewrites") {
		t.Fatal("rewrites still exists")
	}
	got, err := s.Records(RecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	want := []records.Record{
		{ID: 4, Name: "*.dev.lan", Type: "CNAME", Value: "nas.lan", TTL: 60, Enabled: true, CreatedAt: 444},
		{ID: 1, Name: "nas.lan", Type: "A", Value: "192.168.1.10", TTL: 60, Enabled: true, CreatedAt: 111},
		{ID: 3, Name: "nas.lan", Type: "AAAA", Value: "fd00::10", TTL: 60, Enabled: false, CreatedAt: 333},
		{ID: 5, Name: "tv.lan", Type: "CNAME", Value: "nas.lan", TTL: 60, Enabled: true, CreatedAt: 555},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("records =\n%+v\nwant\n%+v", got, want)
	}
	if ls, _ := s.Lists(); len(ls) != 1 {
		t.Fatalf("lists = %v", ls)
	}
	// Deleted v1 ids (6 was the highest) are never handed out again.
	r, err := s.CreateRecord(records.Record{Name: "new.lan", Type: "A", Value: "10.0.0.2", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != 7 {
		t.Fatalf("new id = %d, want 7", r.ID)
	}
	s.Close()

	// Opening again changes nothing.
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if all, _ := s.Records(RecordFilter{}); len(all) != 5 || userVersion(t, s) != 2 {
		t.Fatalf("reopen: %d records, version %d", len(all), userVersion(t, s))
	}
}

func TestMigrateV1Sequences(t *testing.T) {
	tests := []struct {
		name   string
		stmts  []string
		wantID int64
	}{
		{"never any rewrite", nil, 1},
		{"all deleted", []string{
			`INSERT INTO rewrites (domain, answer) VALUES ('a.lan', '10.0.0.1')`,
			`INSERT INTO rewrites (domain, answer) VALUES ('b.lan', '10.0.0.2')`,
			`DELETE FROM rewrites`}, 3},
		{"no gap", []string{
			`INSERT INTO rewrites (domain, answer) VALUES ('a.lan', '10.0.0.1')`}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "v1.db")
			buildV1(t, path, tt.stmts...)
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			r, err := s.CreateRecord(records.Record{Name: "new.lan", Type: "A", Value: "10.0.0.9", Enabled: true})
			if err != nil {
				t.Fatal(err)
			}
			if r.ID != tt.wantID {
				t.Fatalf("id = %d, want %d", r.ID, tt.wantID)
			}
		})
	}
}

func TestMigrateV2FailureRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	// A table named like a v2 table makes the migration fail half way.
	buildV1(t, path, `INSERT INTO rewrites (domain, answer) VALUES ('a.lan', '10.0.0.1')`, `CREATE TABLE records (x INTEGER)`)
	if _, err := Open(path); err == nil {
		t.Fatal("Open succeeded")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v, n int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != 1 {
		t.Fatalf("user_version = %d %v", v, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM rewrites`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rewrites = %d %v", n, err)
	}
}

func TestFreshDatabaseIsV2(t *testing.T) {
	s := openTest(t)
	if v := userVersion(t, s); v != 2 || v != len(migrations) {
		t.Fatalf("user_version = %d", v)
	}
	if tableExists(t, s, "rewrites") || !tableExists(t, s, "zones") || !tableExists(t, s, "records") {
		t.Fatal("tables")
	}
	zs, err := s.Zones()
	if err != nil || len(zs) != 0 || zs == nil {
		t.Fatalf("zones = %v %v", zs, err)
	}
	rs, err := s.Records(RecordFilter{})
	if err != nil || len(rs) != 0 || rs == nil {
		t.Fatalf("records = %v %v", rs, err)
	}
}

func zoneSerial(t *testing.T, s *Store, id int64) uint32 {
	t.Helper()
	z, err := s.GetZone(id)
	if err != nil {
		t.Fatal(err)
	}
	return z.Serial
}

func TestZonesCRUD(t *testing.T) {
	s := openTest(t)
	day := time.Date(2026, 11, 9, 12, 0, 0, 0, time.Local)
	fixedClock(t, day)

	// Single records that a new zone will adopt.
	nas, err := s.CreateRecord(records.Record{Name: "nas.home.lan", Type: "A", Value: "10.0.0.1", TTL: 300, Enabled: true, PTR: true})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := s.CreateRecord(records.Record{Name: "other.lan", Type: "A", Value: "10.0.0.2", Enabled: true})
	if nas.ZoneID != 0 || nas.CreatedAt != day.UnixMilli() {
		t.Fatalf("nas = %+v", nas)
	}

	z, err := s.CreateZone(records.Zone{Name: "home.lan", TTL: 300, PrimaryNS: "ns.home.lan", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	want := records.Zone{ID: z.ID, Name: "home.lan", TTL: 300, PrimaryNS: "ns.home.lan", Enabled: true,
		Serial: 2026110901, RecordCount: 1, CreatedAt: day.UnixMilli()}
	if z != want {
		t.Fatalf("zone = %+v\nwant   %+v", z, want)
	}
	if r, _ := s.GetRecord(nas.ID); r.ZoneID != z.ID {
		t.Fatalf("nas not moved: %+v", r)
	}
	if r, _ := s.GetRecord(other.ID); r.ZoneID != 0 {
		t.Fatalf("other moved: %+v", r)
	}
	if _, err := s.CreateZone(records.Zone{Name: "home.lan", Enabled: true}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate zone: %v", err)
	}

	// Record changes bump the serial.
	mx, err := s.CreateRecord(records.Record{Name: "home.lan", Type: "MX", Value: "nas.home.lan", Priority: 10, Enabled: true})
	if err != nil || mx.ZoneID != z.ID {
		t.Fatalf("mx = %+v %v", mx, err)
	}
	if got := zoneSerial(t, s, z.ID); got != 2026110902 {
		t.Fatalf("serial = %d", got)
	}
	mx.TTL = 60
	if _, err := s.UpdateRecord(mx); err != nil {
		t.Fatal(err)
	}
	if got := zoneSerial(t, s, z.ID); got != 2026110903 {
		t.Fatalf("serial = %d", got)
	}

	// Next day: the counter starts again.
	fixedClock(t, day.AddDate(0, 0, 1))
	if err := s.DeleteRecord(mx.ID); err != nil {
		t.Fatal(err)
	}
	if got := zoneSerial(t, s, z.ID); got != 2026111001 {
		t.Fatalf("serial = %d", got)
	}
	if err := s.DeleteRecord(mx.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete again: %v", err)
	}

	// Update without rename: allowed with records, bumps the serial.
	z.TTL, z.Enabled, z.PrimaryNS = 120, false, "dns.home.lan"
	z2, err := s.UpdateZone(z)
	if err != nil {
		t.Fatal(err)
	}
	if z2.TTL != 120 || z2.Enabled || z2.PrimaryNS != "dns.home.lan" || z2.Serial != 2026111002 || z2.RecordCount != 1 ||
		z2.CreatedAt != day.UnixMilli() {
		t.Fatalf("updated = %+v", z2)
	}
	// Rename while it has records: typed field error.
	z2.Name = "house.lan"
	_, err = s.UpdateZone(z2)
	var fe *FieldError
	if !errors.Is(err, ErrZoneHasRecords) || !errors.As(err, &fe) || fe.Field != "name" || fe.Message == "" {
		t.Fatalf("rename with records: %v", err)
	}
	if _, err := s.UpdateZone(records.Zone{ID: 999, Name: "x.lan"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown zone: %v", err)
	}

	// Rename of an empty zone adopts the records below the new name.
	empty, err := s.CreateZone(records.Zone{Name: "empty.lan", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	empty.Name = "other.lan"
	renamed, err := s.UpdateZone(empty)
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Name != "other.lan" || renamed.RecordCount != 1 {
		t.Fatalf("renamed = %+v", renamed)
	}
	if _, err := s.UpdateZone(records.Zone{ID: renamed.ID, Name: "x.lan"}); !errors.Is(err, ErrZoneHasRecords) {
		t.Fatalf("rename: %v", err)
	}

	zs, err := s.Zones()
	if err != nil || len(zs) != 2 || zs[0].Name != "home.lan" || zs[1].Name != "other.lan" {
		t.Fatalf("zones = %+v %v", zs, err)
	}
	counts, err := s.RecordCounts()
	if err != nil || !reflect.DeepEqual(counts, map[int64]int{z.ID: 1, renamed.ID: 1}) {
		t.Fatalf("counts = %v %v", counts, err)
	}

	// Delete removes the zone and its records.
	if err := s.DeleteZone(z.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetRecord(nas.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("record of deleted zone: %v", err)
	}
	if _, err := s.GetZone(z.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted zone: %v", err)
	}
	if err := s.DeleteZone(z.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete again: %v", err)
	}
	if rs, _ := s.Records(RecordFilter{}); len(rs) != 1 || rs[0].ID != other.ID {
		t.Fatalf("records = %+v", rs)
	}
}

func TestNestedZonesAndMoves(t *testing.T) {
	s := openTest(t)
	fixedClock(t, time.Date(2026, 11, 9, 12, 0, 0, 0, time.Local))
	lan, err := s.CreateZone(records.Zone{Name: "lan", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	pc, _ := s.CreateRecord(records.Record{Name: "pc.lab.lan", Type: "A", Value: "10.0.0.1", Enabled: true})
	x, _ := s.CreateRecord(records.Record{Name: "x.lan", Type: "A", Value: "10.0.0.2", Enabled: true})
	if pc.ZoneID != lan.ID || x.ZoneID != lan.ID || zoneSerial(t, s, lan.ID) != 2026110903 {
		t.Fatalf("pc=%+v x=%+v serial=%d", pc, x, zoneSerial(t, s, lan.ID))
	}

	// A nested zone (disabled: membership does not depend on enabled) takes over pc.lab.lan;
	// the parent zone gets a new serial.
	lab, err := s.CreateZone(records.Zone{Name: "lab.lan", Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if lab.RecordCount != 1 || lab.Serial != 2026110901 || zoneSerial(t, s, lan.ID) != 2026110904 {
		t.Fatalf("lab=%+v lan serial=%d", lab, zoneSerial(t, s, lan.ID))
	}
	if r, _ := s.GetRecord(pc.ID); r.ZoneID != lab.ID {
		t.Fatalf("pc = %+v", r)
	}

	// Moving a record between zones by renaming it bumps both serials.
	x.Name = "x.lab.lan"
	moved, err := s.UpdateRecord(x)
	if err != nil || moved.ZoneID != lab.ID || moved.CreatedAt != x.CreatedAt {
		t.Fatalf("moved = %+v %v", moved, err)
	}
	if zoneSerial(t, s, lan.ID) != 2026110905 || zoneSerial(t, s, lab.ID) != 2026110902 {
		t.Fatalf("serials lan=%d lab=%d", zoneSerial(t, s, lan.ID), zoneSerial(t, s, lab.ID))
	}
	// Out of every zone: a single record, the old zone is bumped.
	moved.Name = "x.example"
	if moved, err = s.UpdateRecord(moved); err != nil || moved.ZoneID != 0 || zoneSerial(t, s, lab.ID) != 2026110903 {
		t.Fatalf("moved = %+v %v serial %d", moved, err, zoneSerial(t, s, lab.ID))
	}

	// Filters.
	zero := int64(0)
	if rs, _ := s.Records(RecordFilter{ZoneID: &zero}); len(rs) != 1 || rs[0].Name != "x.example" {
		t.Fatalf("zone 0: %+v", rs)
	}
	if rs, _ := s.Records(RecordFilter{ZoneID: &lab.ID}); len(rs) != 1 || rs[0].Name != "pc.lab.lan" {
		t.Fatalf("zone lab: %+v", rs)
	}

	// Deleting the nested zone deletes only its records; the parent keeps its own.
	if err := s.DeleteZone(lab.ID); err != nil {
		t.Fatal(err)
	}
	if rs, _ := s.Records(RecordFilter{}); len(rs) != 1 || rs[0].Name != "x.example" {
		t.Fatalf("after delete: %+v", rs)
	}
}

func TestZoneApexCNAME(t *testing.T) {
	s := openTest(t)
	if _, err := s.CreateRecord(records.Record{Name: "app.lan", Type: "CNAME", Value: "nas.lan", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateZone(records.Zone{Name: "app.lan", Enabled: true})
	if !errors.Is(err, ErrZoneApexCNAME) {
		t.Fatalf("create: %v", err)
	}
	if zs, _ := s.Zones(); len(zs) != 0 {
		t.Fatalf("zone created: %+v", zs)
	}
	if rs, _ := s.Records(RecordFilter{}); len(rs) != 1 || rs[0].ZoneID != 0 {
		t.Fatalf("records: %+v", rs)
	}
	// Same when an empty zone is renamed to it.
	z, err := s.CreateZone(records.Zone{Name: "empty.lan", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	z.Name = "app.lan"
	if _, err := s.UpdateZone(z); !errors.Is(err, ErrZoneApexCNAME) {
		t.Fatalf("rename: %v", err)
	}
	if got, _ := s.GetZone(z.ID); got.Name != "empty.lan" {
		t.Fatalf("zone = %+v", got)
	}
}

func TestRecordsCRUD(t *testing.T) {
	s := openTest(t)
	fixedClock(t, time.Date(2026, 11, 9, 12, 0, 0, 0, time.Local))
	in := []records.Record{
		{Name: "nas.lan", Type: "A", Value: "10.0.0.1", TTL: 300, PTR: true, Enabled: true, ManagedBy: "core"},
		{Name: "lan.example", Type: "MX", Value: "mail.lan", TTL: 300, Priority: 20, Enabled: true},
		{Name: "lan.example", Type: "MX", Value: "mail.lan", TTL: 300, Priority: 10, Enabled: true},
		{Name: "_ldap._tcp.lan.example", Type: "SRV", Value: "dc.lan", Priority: 1, Weight: 2, Port: 389, Enabled: true},
		{Name: "t.lan", Type: "TXT", Value: "Hällo 50%_x", Enabled: false},
	}
	var created []records.Record
	for _, r := range in {
		c, err := s.CreateRecord(r)
		if err != nil {
			t.Fatal(err)
		}
		r.ID, r.CreatedAt = c.ID, c.CreatedAt
		if c != r {
			t.Fatalf("created = %+v, want %+v", c, r)
		}
		got, err := s.GetRecord(c.ID)
		if err != nil || got != c {
			t.Fatalf("get = %+v %v", got, err)
		}
		created = append(created, c)
	}
	// Exact duplicate (enabled does not matter).
	dup := in[0]
	dup.Enabled, dup.TTL = false, 60
	if _, err := s.CreateRecord(dup); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	upd := created[1]
	upd.Priority = 10 // now equals created[2]
	if _, err := s.UpdateRecord(upd); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("update duplicate: %v", err)
	}
	if _, err := s.UpdateRecord(records.Record{ID: 999, Name: "x.lan", Type: "A", Value: "1.1.1.1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update unknown: %v", err)
	}
	if _, err := s.GetRecord(999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get unknown: %v", err)
	}

	ids := func(rs []records.Record, err error) []int64 {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		out := []int64{}
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return out
	}
	// Ordered by name, type, priority, value.
	if got := ids(s.Records(RecordFilter{})); !reflect.DeepEqual(got, []int64{4, 3, 2, 1, 5}) {
		t.Fatalf("all = %v", got)
	}
	if got := ids(s.Records(RecordFilter{Type: "mx"})); !reflect.DeepEqual(got, []int64{3, 2}) {
		t.Fatalf("type = %v", got)
	}
	if got := ids(s.Records(RecordFilter{Name: "NAS.lan."})); !reflect.DeepEqual(got, []int64{1}) {
		t.Fatalf("name = %v", got)
	}
	if got := ids(s.Records(RecordFilter{Q: "MAIL"})); !reflect.DeepEqual(got, []int64{3, 2}) {
		t.Fatalf("q value = %v", got)
	}
	if got := ids(s.Records(RecordFilter{Q: "_ldap"})); !reflect.DeepEqual(got, []int64{4}) {
		t.Fatalf("q name = %v", got)
	}
	if got := ids(s.Records(RecordFilter{Q: "50%_"})); !reflect.DeepEqual(got, []int64{5}) {
		t.Fatalf("q escaped = %v", got)
	}
	if got := ids(s.Records(RecordFilter{Q: "5_%"})); len(got) != 0 {
		t.Fatalf("q wildcards = %v", got)
	}
	if got := ids(s.Records(RecordFilter{Type: "MX", Q: "lan.example"})); !reflect.DeepEqual(got, []int64{3, 2}) {
		t.Fatalf("combined = %v", got)
	}

	if err := s.DeleteRecord(created[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRecord(created[0].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete again: %v", err)
	}
	if counts, _ := s.RecordCounts(); !reflect.DeepEqual(counts, map[int64]int{0: 4}) {
		t.Fatalf("counts = %v", counts)
	}
}
