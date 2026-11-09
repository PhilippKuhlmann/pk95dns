package store

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"pk95dns/internal/config"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenMigratesIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateList(List{Name: "a", URL: "https://a", Kind: "block"}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	var v int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != len(migrations) {
		t.Fatalf("user_version = %d, want %d", v, len(migrations))
	}
	ls, err := s.Lists()
	if err != nil || len(ls) != 1 {
		t.Fatalf("lists after reopen: %v %v", ls, err)
	}
	var mode string
	if err := s.DB.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q %v", mode, err)
	}
	var fk int
	if err := s.DB.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign_keys = %d %v", fk, err)
	}
	if err := s.Ping(); err != nil {
		t.Fatal(err)
	}
	if err := s.Checkpoint(); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsDefaultsWhenEmpty(t *testing.T) {
	s := openTest(t)
	got, err := s.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if want := config.Defaults().Normalized(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s := openTest(t)
	st := config.Defaults()
	st.Upstreams = []string{"tls://dns.quad9.net"}
	st.Ratelimit = 7
	st.SafeSearch.Enabled = true
	st.SafeSearch.Bing = false
	st.Conditional = []config.Conditional{{Domain: "fritz.box", Upstream: "192.168.178.1"}}
	st.BlockedServices = []string{"tiktok", "youtube"}
	st.ProtectionEnabled = false
	st.ProtectionPausedUntil = 123456
	if err := s.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, st.Normalized()) {
		t.Fatalf("got %+v\nwant %+v", got, st)
	}
	// Saving again overwrites.
	st.Ratelimit = 9
	st.BlockedServices = nil
	if err := s.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	got, _ = s.LoadSettings()
	if got.Ratelimit != 9 || got.BlockedServices == nil || len(got.BlockedServices) != 0 {
		t.Fatalf("second save: %+v", got)
	}
}

func TestSettingsMissingKeysKeepDefaults(t *testing.T) {
	tests := []struct {
		name  string
		rows  map[string]string
		check func(t *testing.T, st config.Settings)
	}{
		{
			name: "partial settings object",
			rows: map[string]string{"settings": `{"ratelimit": 3, "safesearch": {"enabled": true}}`},
			check: func(t *testing.T, st config.Settings) {
				d := config.Defaults()
				if st.Ratelimit != 3 || !st.SafeSearch.Enabled {
					t.Errorf("stored values lost: %+v", st)
				}
				if !st.SafeSearch.Google || st.QuerylogHours != d.QuerylogHours || !reflect.DeepEqual(st.Upstreams, d.Upstreams) {
					t.Errorf("defaults lost: %+v", st)
				}
				if !st.ProtectionEnabled || st.BlockedServices == nil {
					t.Errorf("json:\"-\" defaults lost: %+v", st)
				}
			},
		},
		{
			name: "only protection",
			rows: map[string]string{"protection": `{"enabled": false, "paused_until": 99}`},
			check: func(t *testing.T, st config.Settings) {
				if st.ProtectionEnabled || st.ProtectionPausedUntil != 99 {
					t.Errorf("protection: %+v", st)
				}
				if st.Ratelimit != config.Defaults().Ratelimit {
					t.Errorf("ratelimit default lost")
				}
			},
		},
		{
			name: "protection without paused_until",
			rows: map[string]string{"protection": `{"enabled": false}`},
			check: func(t *testing.T, st config.Settings) {
				if st.ProtectionEnabled || st.ProtectionPausedUntil != 0 {
					t.Errorf("protection: %+v", st)
				}
			},
		},
		{
			name: "only blocked services",
			rows: map[string]string{"blocked_services": `["netflix"]`},
			check: func(t *testing.T, st config.Settings) {
				if !reflect.DeepEqual(st.BlockedServices, []string{"netflix"}) {
					t.Errorf("services: %v", st.BlockedServices)
				}
			},
		},
		{
			name: "null slices become empty",
			rows: map[string]string{"settings": `{"fallback": null}`, "blocked_services": `null`},
			check: func(t *testing.T, st config.Settings) {
				if st.Fallback == nil || len(st.Fallback) != 0 || st.BlockedServices == nil {
					t.Errorf("nil slices: %+v", st)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openTest(t)
			for k, v := range tt.rows {
				if _, err := s.DB.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)`, k, v); err != nil {
					t.Fatal(err)
				}
			}
			st, err := s.LoadSettings()
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, st)
		})
	}
}

func TestSettingsCorrupt(t *testing.T) {
	s := openTest(t)
	if _, err := s.DB.Exec(`INSERT INTO settings (key, value) VALUES ('settings', '{')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSettings(); err == nil {
		t.Fatal("expected error for corrupt settings")
	}
}

func TestLists(t *testing.T) {
	s := openTest(t)
	oldNow := nowMS
	nowMS = func() int64 { return 1000 }
	t.Cleanup(func() { nowMS = oldNow })

	b, err := s.CreateList(List{Name: "zeta", URL: "https://z", Kind: "block", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if b.ID == 0 || b.CreatedAt != 1000 {
		t.Fatalf("created: %+v", b)
	}
	if _, err := s.CreateList(List{Name: "Alpha", URL: "https://a", Kind: "block"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateList(List{Name: "allow", URL: "https://w", Kind: "allow"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateList(List{Name: "dup", URL: "https://z", Kind: "allow"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate url: %v", err)
	}

	ls, err := s.Lists()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, l := range ls {
		names = append(names, l.Name)
	}
	if want := []string{"Alpha", "zeta", "allow"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("order %v, want %v", names, want)
	}

	got, err := s.GetList(b.ID)
	if err != nil || !reflect.DeepEqual(got, b) {
		t.Fatalf("GetList = %+v %v, want %+v", got, err, b)
	}
	if _, err := s.GetList(999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetList missing: %v", err)
	}

	b.Name, b.Enabled = "zeta2", false
	if err := s.UpdateList(b); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetList(b.ID)
	if got.Name != "zeta2" || got.Enabled {
		t.Fatalf("update: %+v", got)
	}
	// Same values again is still found.
	if err := s.UpdateList(b); err != nil {
		t.Fatalf("no-op update: %v", err)
	}
	b.URL = "https://a"
	if err := s.UpdateList(b); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("update dup url: %v", err)
	}
	if err := s.UpdateList(List{ID: 999, Name: "x", URL: "https://x", Kind: "block"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}

	if err := s.DeleteList(b.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteList(b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	// AUTOINCREMENT: ids are not reused.
	n, _ := s.CreateList(List{Name: "new", URL: "https://n", Kind: "block"})
	if n.ID <= b.ID {
		t.Fatalf("id reused: %d <= %d", n.ID, b.ID)
	}
}

func TestSetListStatus(t *testing.T) {
	s := openTest(t)
	l, err := s.CreateList(List{Name: "a", URL: "https://a", Kind: "block", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name                         string
		count                        int
		updated                      int64
		lastErr, etag, lastMod       string
		wantCount                    int
		wantUpdated                  int64
		wantErr, wantEtag, wantLastM string
	}{
		{"success", 10, 5000, "", "e1", "m1", 10, 5000, "", "e1", "m1"},
		{"failure keeps", 10, 0, "Timeout", "", "", 10, 5000, "Timeout", "e1", "m1"},
		{"failure with new etag", 10, 0, "x", "e2", "", 10, 5000, "x", "e2", "m1"},
		{"success clears", 20, 6000, "", "", "", 20, 6000, "", "", ""},
	}
	for _, st := range steps {
		if err := s.SetListStatus(l.ID, st.count, st.updated, st.lastErr, st.etag, st.lastMod); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		got, _ := s.GetList(l.ID)
		if got.RuleCount != st.wantCount || got.UpdatedAt != st.wantUpdated || got.LastError != st.wantErr ||
			got.ETag != st.wantEtag || got.LastModified != st.wantLastM {
			t.Fatalf("%s: got %+v", st.name, got)
		}
	}
	if err := s.SetListStatus(999, 1, 1, "", "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

func TestCustomRules(t *testing.T) {
	s := openTest(t)
	if txt, err := s.CustomRules(); err != nil || txt != "" {
		t.Fatalf("empty: %q %v", txt, err)
	}
	for _, txt := range []string{"||a^\n@@||b^", "", "x"} {
		if err := s.SaveCustomRules(txt); err != nil {
			t.Fatal(err)
		}
		got, err := s.CustomRules()
		if err != nil || got != txt {
			t.Fatalf("got %q %v want %q", got, err, txt)
		}
	}
}

func TestRewrites(t *testing.T) {
	s := openTest(t)
	in := []Rewrite{
		{Domain: "nas.lan", Answer: "192.168.1.10", Enabled: true},
		{Domain: "*.lan", Answer: "192.168.1.1", Enabled: true},
		{Domain: "nas.lan", Answer: "fd00::10", Enabled: false},
	}
	var created []Rewrite
	for _, r := range in {
		c, err := s.CreateRewrite(r)
		if err != nil {
			t.Fatal(err)
		}
		if c.ID == 0 || c.CreatedAt == 0 {
			t.Fatalf("created %+v", c)
		}
		created = append(created, c)
	}
	if _, err := s.CreateRewrite(in[0]); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("dup: %v", err)
	}
	rs, err := s.Rewrites()
	if err != nil {
		t.Fatal(err)
	}
	want := []Rewrite{created[1], created[0], created[2]}
	if !reflect.DeepEqual(rs, want) {
		t.Fatalf("got %+v\nwant %+v", rs, want)
	}
	upd := created[2]
	upd.Answer = "192.168.1.10"
	if err := s.UpdateRewrite(upd); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("update dup: %v", err)
	}
	upd.Answer, upd.Enabled = "fd00::11", true
	if err := s.UpdateRewrite(upd); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateRewrite(Rewrite{ID: 99, Domain: "x", Answer: "1.1.1.1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if err := s.DeleteRewrite(upd.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRewrite(upd.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
	if rs, _ := s.Rewrites(); len(rs) != 2 {
		t.Fatalf("after delete: %+v", rs)
	}
}

func TestClients(t *testing.T) {
	s := openTest(t)
	if cs, err := s.Clients(); err != nil || cs == nil || len(cs) != 0 {
		t.Fatalf("empty: %v %v", cs, err)
	}
	c1, err := s.CreateClient(Client{
		Name: "Kinder-Tablet", IDs: []string{"192.168.1.40", "192.168.50.0/24"},
		FilteringEnabled: true, SafeSearch: config.SafeSearch{Enabled: true, Google: true},
		BlockedServices: []string{"tiktok"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := s.CreateClient(Client{Name: "laptop", IDs: []string{"10.0.0.2"}, UseGlobalSettings: true, UseGlobalServices: true})
	if err != nil {
		t.Fatal(err)
	}
	if c2.BlockedServices == nil {
		t.Fatal("nil slice from CreateClient")
	}
	if _, err := s.CreateClient(Client{Name: "LAPTOP"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("case-insensitive dup: %v", err)
	}
	got, err := s.GetClient(c1.ID)
	if err != nil || !reflect.DeepEqual(got, c1) {
		t.Fatalf("GetClient = %+v %v\nwant %+v", got, err, c1)
	}
	if _, err := s.GetClient(99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	cs, _ := s.Clients()
	if len(cs) != 2 || cs[0].Name != "Kinder-Tablet" || cs[1].Name != "laptop" {
		t.Fatalf("order: %+v", cs)
	}
	if cs[1].BlockedServices == nil || cs[1].IDs == nil {
		t.Fatal("nil slices")
	}

	c1.Name = "Tablet"
	c1.IDs = nil
	c1.SafeSearch.Bing = true
	c1.CreatedAt = 42 // ignored
	if err := s.UpdateClient(c1); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetClient(c1.ID)
	if got.Name != "Tablet" || got.IDs == nil || len(got.IDs) != 0 || !got.SafeSearch.Bing || got.CreatedAt == 42 {
		t.Fatalf("update: %+v", got)
	}
	c1.Name = "Laptop"
	if err := s.UpdateClient(c1); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("update dup: %v", err)
	}
	if err := s.UpdateClient(Client{ID: 99, Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	if err := s.DeleteClient(c2.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteClient(c2.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

func TestUsersAndSessions(t *testing.T) {
	s := openTest(t)
	if n, _ := s.UserCount(); n != 0 {
		t.Fatalf("count %d", n)
	}
	u, err := s.CreateUser("admin", "hash1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser("admin", "x"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("dup user: %v", err)
	}
	if _, err := s.CreateUser("Admin", "x"); err != nil {
		t.Fatalf("usernames are case-sensitive: %v", err)
	}
	if n, _ := s.UserCount(); n != 2 {
		t.Fatalf("count %d", n)
	}
	got, err := s.UserByName("admin")
	if err != nil || got != u {
		t.Fatalf("UserByName %+v %v", got, err)
	}
	if _, err := s.UserByName("nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	if err := s.SetPasswordHash(u.ID, "hash2"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserByName("admin"); got.PasswordHash != "hash2" {
		t.Fatalf("hash not changed: %+v", got)
	}
	if err := s.SetPasswordHash(999, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	for _, sess := range []struct {
		hash string
		exp  int64
	}{{"a", 100}, {"b", 200}, {"c", 300}} {
		if err := s.CreateSession(sess.hash, u.ID, sess.exp); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateSession("a", u.ID, 1); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("dup session: %v", err)
	}
	if err := s.CreateSession("z", 999, 1); err == nil {
		t.Fatal("session for unknown user must fail (foreign key)")
	}

	tests := []struct {
		hash string
		now  int64
		ok   bool
	}{
		{"a", 99, true},
		{"a", 100, false}, // expired exactly at expires_at
		{"b", 150, true},
		{"x", 0, false},
	}
	for _, tt := range tests {
		got, err := s.SessionUser(tt.hash, tt.now)
		if tt.ok && (err != nil || got.ID != u.ID || got.PasswordHash != "hash2") {
			t.Errorf("SessionUser(%s,%d) = %+v %v", tt.hash, tt.now, got, err)
		}
		if !tt.ok && !errors.Is(err, ErrNotFound) {
			t.Errorf("SessionUser(%s,%d) err = %v", tt.hash, tt.now, err)
		}
	}

	if err := s.PruneSessions(150); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser("a", 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("a should be pruned")
	}
	if err := s.DeleteUserSessions(u.ID, "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser("b", 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("b should be removed")
	}
	if _, err := s.SessionUser("c", 0); err != nil {
		t.Fatal("c should be kept")
	}
	if err := s.DeleteSession("c"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser("c", 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("c should be removed")
	}
	// DeleteUserSessions with "" removes all; cascade on user removal.
	s.CreateSession("d", u.ID, 1000)
	s.CreateSession("e", u.ID, 1000)
	if err := s.DeleteUserSessions(u.ID, ""); err != nil {
		t.Fatal(err)
	}
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n)
	if n != 0 {
		t.Fatalf("sessions left: %d", n)
	}
	s.CreateSession("f", u.ID, 1000)
	if _, err := s.DB.Exec(`DELETE FROM users WHERE id = ?`, u.ID); err != nil {
		t.Fatal(err)
	}
	s.DB.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n)
	if n != 0 {
		t.Fatalf("cascade failed, sessions left: %d", n)
	}
}

func insertQueries(t *testing.T, s *Store, qs []Query) {
	t.Helper()
	if err := s.InsertQueries(qs); err != nil {
		t.Fatal(err)
	}
}

func TestQueriesFilter(t *testing.T) {
	s := openTest(t)
	qs := []Query{
		{TS: 1, ClientIP: "192.168.1.20", ClientName: "Laptop", Name: "ads.example.net", QType: "A", Status: "blocked", Reason: "list", Rule: "||example.net^", ListID: 1, Rcode: "NOERROR", Answer: "0.0.0.0", ElapsedMS: 0.12},
		{TS: 2, ClientIP: "192.168.1.21", Name: "example.org", QType: "AAAA", Status: "ok", Upstream: "9.9.9.9", ElapsedMS: 12.5, Cached: true},
		{TS: 3, ClientIP: "192.168.1.20", ClientName: "Laptop", Name: "foo_bar.example.org", Status: "allowed"},
		{TS: 4, ClientIP: "10.0.0.1", Name: "100%.example.com", Status: "blocked_service", Service: "tiktok"},
		{TS: 5, ClientIP: "10.0.0.1", Name: `back\slash.example`, Status: "error"},
		{TS: 6, ClientIP: "10.0.0.2", Name: "fooxbar.example.org", Status: "rewrite"},
	}
	insertQueries(t, s, qs)
	if err := s.InsertQueries(nil); err != nil {
		t.Fatal(err)
	}

	all, err := s.Queries(QueryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 6 || all[0].TS != 6 || all[5].TS != 1 {
		t.Fatalf("all: %+v", all)
	}
	first := all[5]
	want := qs[0]
	want.ID = first.ID
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", first, want)
	}
	if !all[4].Cached {
		t.Fatal("cached flag lost")
	}

	tsOf := func(qs []Query) []int64 {
		out := []int64{}
		for _, q := range qs {
			out = append(out, q.TS)
		}
		return out
	}
	tests := []struct {
		name string
		f    QueryFilter
		want []int64
	}{
		{"search substring", QueryFilter{Search: "example.org"}, []int64{6, 3, 2}},
		{"search case-insensitive", QueryFilter{Search: "EXAMPLE.ORG"}, []int64{6, 3, 2}},
		{"underscore is literal", QueryFilter{Search: "foo_bar"}, []int64{3}},
		{"percent is literal", QueryFilter{Search: "100%"}, []int64{4}},
		{"backslash is literal", QueryFilter{Search: `k\s`}, []int64{5}},
		{"client ip", QueryFilter{Client: "192.168.1.20"}, []int64{3, 1}},
		{"client name", QueryFilter{Client: "Laptop"}, []int64{3, 1}},
		{"client exact only", QueryFilter{Client: "192.168.1"}, []int64{}},
		{"statuses", QueryFilter{Statuses: []string{"blocked", "blocked_service"}}, []int64{4, 1}},
		{"combined", QueryFilter{Client: "10.0.0.1", Statuses: []string{"error"}}, []int64{5}},
		{"limit", QueryFilter{Limit: 2}, []int64{6, 5}},
		{"before", QueryFilter{Before: all[1].ID, Limit: 2}, []int64{4, 3}},
		{"before end", QueryFilter{Before: all[5].ID}, []int64{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.Queries(tt.f)
			if err != nil {
				t.Fatal(err)
			}
			if g := tsOf(got); !reflect.DeepEqual(g, tt.want) {
				t.Fatalf("got %v want %v", g, tt.want)
			}
		})
	}
}

func TestQueriesLimitClamp(t *testing.T) {
	s := openTest(t)
	qs := make([]Query, 600)
	for i := range qs {
		qs[i] = Query{TS: int64(i), Name: "a.example", Status: "ok"}
	}
	insertQueries(t, s, qs)
	tests := []struct{ limit, want int }{{0, 50}, {-5, 50}, {1, 1}, {500, 500}, {501, 501}, {502, 501}, {10000, 501}}
	for _, tt := range tests {
		got, err := s.Queries(QueryFilter{Limit: tt.limit})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != tt.want {
			t.Errorf("limit %d: got %d want %d", tt.limit, len(got), tt.want)
		}
	}
	// Paging walks all entries exactly once.
	seen := 0
	var before int64
	for {
		page, err := s.Queries(QueryFilter{Limit: 250, Before: before})
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		seen += len(page)
		before = page[len(page)-1].ID
	}
	if seen != 600 {
		t.Fatalf("paging saw %d", seen)
	}
}

func TestPruneAndClearQueries(t *testing.T) {
	s := openTest(t)
	qs := make([]Query, 12000)
	for i := range qs {
		qs[i] = Query{TS: int64(i), Name: "x.example", Status: "ok"}
	}
	insertQueries(t, s, qs)
	n, err := s.PruneQueries(11000)
	if err != nil {
		t.Fatal(err)
	}
	if n != 11000 {
		t.Fatalf("pruned %d", n)
	}
	n, err = s.PruneQueries(11000)
	if err != nil || n != 0 {
		t.Fatalf("second prune %d %v", n, err)
	}
	rest, _ := s.Queries(QueryFilter{Limit: 500})
	if len(rest) != 500 || rest[len(rest)-1].TS < 11000 {
		t.Fatalf("rest: %d entries, oldest %d", len(rest), rest[len(rest)-1].TS)
	}
	if err := s.ClearQueries(); err != nil {
		t.Fatal(err)
	}
	if rest, _ := s.Queries(QueryFilter{}); len(rest) != 0 {
		t.Fatalf("after clear: %d", len(rest))
	}
}

func TestStatsSaveLoad(t *testing.T) {
	s := openTest(t)
	h1 := HourStats{Hour: 3600, Queries: 10, Blocked: 2, Cached: 3, SafeSearch: 1, Services: 1, ElapsedMS: 55.5}
	h2 := HourStats{Hour: 7200, Queries: 20, Blocked: 4}
	if err := s.SaveHour(h1, []TopEntry{
		{Kind: "domain", Key: "a", Count: 5},
		{Kind: "domain", Key: "b", Count: 3},
		{Kind: "upstream", Key: "9.9.9.9", Count: 4, Sum: 40},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveHour(h2, []TopEntry{
		{Kind: "domain", Key: "b", Count: 7},
		{Kind: "domain", Key: "c", Count: 1},
		{Kind: "upstream", Key: "9.9.9.9", Count: 1, Sum: 20},
	}); err != nil {
		t.Fatal(err)
	}

	hs, err := s.LoadHours(0, 10800)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hs, []HourStats{h1, h2}) {
		t.Fatalf("hours %+v", hs)
	}
	if hs, _ := s.LoadHours(3600, 7200); len(hs) != 1 || hs[0].Hour != 3600 {
		t.Fatalf("half-open range: %+v", hs)
	}

	top, err := s.LoadTop("domain", 0, 10800, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []TopEntry{
		{Kind: "domain", Key: "b", Count: 10, Last: 7200},
		{Kind: "domain", Key: "a", Count: 5, Last: 3600},
		{Kind: "domain", Key: "c", Count: 1, Last: 7200},
	}
	if !reflect.DeepEqual(top, want) {
		t.Fatalf("top %+v", top)
	}
	if top, _ := s.LoadTop("domain", 0, 10800, 2); len(top) != 2 {
		t.Fatalf("limit: %+v", top)
	}
	if top, _ := s.LoadTop("domain", 0, 10800, 0); len(top) != 3 {
		t.Fatalf("no limit: %+v", top)
	}
	if top, _ := s.LoadTop("domain", 3600, 7200, 10); len(top) != 2 || top[0].Key != "a" {
		t.Fatalf("range: %+v", top)
	}
	up, _ := s.LoadTop("upstream", 0, 10800, 10)
	if len(up) != 1 || up[0].Count != 5 || up[0].Sum != 60 {
		t.Fatalf("upstream: %+v", up)
	}

	// SaveHour replaces the hour (idempotent).
	h1b := HourStats{Hour: 3600, Queries: 11}
	if err := s.SaveHour(h1b, []TopEntry{{Kind: "domain", Key: "z", Count: 11}, {Kind: "domain", Key: "z", Count: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveHour(h1b, []TopEntry{{Kind: "domain", Key: "z", Count: 11}, {Kind: "domain", Key: "z", Count: 1}}); err != nil {
		t.Fatal(err)
	}
	hs, _ = s.LoadHours(3600, 7200)
	if len(hs) != 1 || hs[0] != h1b {
		t.Fatalf("replaced hour: %+v", hs)
	}
	top, _ = s.LoadTop("domain", 3600, 7200, 10)
	if len(top) != 1 || top[0].Key != "z" || top[0].Count != 12 {
		t.Fatalf("replaced top: %+v", top)
	}

	if err := s.PruneStats(7200); err != nil {
		t.Fatal(err)
	}
	hs, _ = s.LoadHours(0, 1<<40)
	if len(hs) != 1 || hs[0].Hour != 7200 {
		t.Fatalf("after prune: %+v", hs)
	}
	if top, _ := s.LoadTop("domain", 0, 1<<40, 0); len(top) != 2 {
		t.Fatalf("top after prune: %+v", top)
	}
	if err := s.ClearStats(); err != nil {
		t.Fatal(err)
	}
	hs, _ = s.LoadHours(0, 1<<40)
	top, _ = s.LoadTop("domain", 0, 1<<40, 0)
	if len(hs) != 0 || len(top) != 0 {
		t.Fatalf("after clear: %v %v", hs, top)
	}
}

func TestConcurrentWrites(t *testing.T) {
	s := openTest(t)
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if err := s.InsertQueries([]Query{{TS: int64(i), Name: "x"}}); err != nil {
					errs <- err
					return
				}
				if err := s.SaveHour(HourStats{Hour: int64(g*100 + i)}, []TopEntry{{Kind: "domain", Key: "x", Count: 1}}); err != nil {
					errs <- err
					return
				}
				if _, err := s.Queries(QueryFilter{Limit: 5}); err != nil {
					errs <- err
					return
				}
				if _, err := s.CreateRewrite(Rewrite{Domain: fmt.Sprintf("h%d-%d", g, i), Answer: "1.2.3.4"}); err != nil {
					errs <- err
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	all, _ := s.Queries(QueryFilter{Limit: 500})
	if len(all) != 160 {
		t.Fatalf("got %d", len(all))
	}
}

func TestEscapeLike(t *testing.T) {
	tests := map[string]string{
		"abc":   "abc",
		"a_b":   `a\_b`,
		"50%":   `50\%`,
		`a\b`:   `a\\b`,
		`\%_\_`: `\\\%\_\\\_`,
	}
	for in, want := range tests {
		if got := escapeLike(in); got != want {
			t.Errorf("escapeLike(%q) = %q, want %q", in, got, want)
		}
	}
}
