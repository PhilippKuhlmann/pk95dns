package api

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
	"pk95dns/internal/filter"
	"pk95dns/internal/stats"
	"pk95dns/internal/store"
	"pk95dns/internal/upstream"
)

func newCoreEnv(t *testing.T) *env {
	return newEnv(t, coreMode(testToken))
}

// call sends an authenticated request (Core mode).
func (e *env) call(method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.do(method, path, body, append([]reqOpt{bearer(testToken)}, opts...)...)
}

func TestHealthManifestBackup(t *testing.T) {
	e := newCoreEnv(t)
	w := e.do("GET", "/core/health", nil)
	expect(t, w, 200)
	if m := jsonMap(t, w); m["ok"] != true || m["version"] != "1.2.3" {
		t.Errorf("health = %v", m)
	}

	w = e.call("GET", "/core/manifest", nil)
	expect(t, w, 200)
	var got Manifest
	decodeBody(t, w, &got)
	want := Manifest{
		ID: "dns", Name: "PK95 DNS", Version: "1.2.3", Protocol: 1, Icon: "shield",
		Menu: []MenuItem{
			{"overview", "Übersicht", "home"}, {"log", "Abfragen", "list"}, {"lists", "Blocklisten", "shield"},
			{"rules", "Eigene Regeln", "pencil"}, {"rewrites", "Lokale Einträge", "link"}, {"services", "Dienste", "lock"},
			{"clients", "Clients", "user"}, {"settings", "Einstellungen", "cog"},
		},
		Capabilities: []string{"events", "backup"},
		Events:       []string{"upstream.down", "upstream.up", "lists.update_failed", "dns.listen_failed", "dns.listen_ok"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("manifest = %+v", got)
	}

	e.qlog.Add(store.Query{TS: 1, Name: "x.example", Status: "ok"})
	expect(t, e.call("POST", "/core/backup/prepare", nil), 204)
	var n int
	if err := e.st.DB.QueryRow(`SELECT COUNT(*) FROM queries`).Scan(&n); err != nil || n != 1 {
		t.Errorf("query log not flushed before backup: %d %v", n, err)
	}

	// Health fails when the database is gone.
	e.st.Close()
	w = e.do("GET", "/core/health", nil)
	expect(t, w, 503)
}

func TestStatus(t *testing.T) {
	e := newCoreEnv(t)
	e.api.d.Upstreams = func() []upstream.Health {
		return []upstream.Health{{Address: "9.9.9.9", OK: true, AvgMS: 12.5, Queries: 3}}
	}
	if _, err := e.st.CreateList(store.List{Name: "A", URL: "https://a.example/l", Kind: "block", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SetListStatus(1, 1500, 1, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.CreateList(store.List{Name: "B", URL: "https://b.example/l", Kind: "block", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SaveCustomRules("||a.example^\nbad$foo\n@@||b.example^"); err != nil {
		t.Fatal(err)
	}
	for _, rw := range []store.Rewrite{{Domain: "nas.lan", Answer: "192.168.1.2", Enabled: true}, {Domain: "x.lan", Answer: "192.168.1.3"}} {
		if _, err := e.st.CreateRewrite(rw); err != nil {
			t.Fatal(err)
		}
	}
	s := e.settings.Load().Clone()
	s.BlockedServices = []string{"tiktok", "youtube"}
	e.settings.Store(&s)

	w := e.call("GET", "/api/status", nil)
	expect(t, w, 200)
	var st statusJSON
	decodeBody(t, w, &st)
	if st.Version != "1.2.3" || !st.CoreMode || st.StartedAt != 1762700000000 {
		t.Errorf("head = %+v", st)
	}
	if st.Rules != (rulesJSON{Lists: 1, ListRules: 1500, CustomRules: 2, Rewrites: 1, Services: 2}) {
		t.Errorf("rules = %+v", st.Rules)
	}
	if !st.Protection.Enabled || st.Protection.PausedUntil != 0 {
		t.Errorf("protection = %+v", st.Protection)
	}
	if !st.Cache.Enabled || len(st.Upstreams) != 1 || st.Upstreams[0].Address != "9.9.9.9" {
		t.Errorf("cache/upstreams = %+v %+v", st.Cache, st.Upstreams)
	}
	m := jsonMap(t, w)
	for _, k := range []string{"version", "core_mode", "started_at", "dns", "protection", "rules", "cache", "upstreams"} {
		if _, ok := m[k]; !ok {
			t.Errorf("status misses %q", k)
		}
	}
	dnsPart := m["dns"].(map[string]any)
	for _, k := range []string{"listen", "udp", "tcp", "error"} {
		if _, ok := dnsPart[k]; !ok {
			t.Errorf("dns misses %q", k)
		}
	}
	up := m["upstreams"].([]any)[0].(map[string]any)
	for _, k := range []string{"address", "ok", "avg_ms", "queries", "failures", "last_error"} {
		if _, ok := up[k]; !ok {
			t.Errorf("upstream misses %q", k)
		}
	}
}

func TestProtection(t *testing.T) {
	e := newCoreEnv(t)
	now := e.now
	w := e.call("POST", "/api/protection", map[string]any{"enabled": false, "minutes": 10})
	expect(t, w, 200)
	var p protectionJSON
	decodeBody(t, w, &p)
	until := now.Add(10 * time.Minute).UnixMilli()
	if p.Enabled || p.PausedUntil != until {
		t.Errorf("pause = %+v", p)
	}
	if s := e.settings.Load(); s.ProtectionPausedUntil != until || s.ProtectionEnabled {
		t.Errorf("settings = %v %v", s.ProtectionEnabled, s.ProtectionPausedUntil)
	}
	// Status shows the pause; after it expired protection counts as on.
	var st statusJSON
	decodeBody(t, e.call("GET", "/api/status", nil), &st)
	if st.Protection != p {
		t.Errorf("status protection = %+v", st.Protection)
	}
	e.now = now.Add(11 * time.Minute)
	decodeBody(t, e.call("GET", "/api/status", nil), &st)
	if !st.Protection.Enabled || st.Protection.PausedUntil != 0 {
		t.Errorf("after pause = %+v", st.Protection)
	}

	// Off until switched on.
	w = e.call("POST", "/api/protection", map[string]any{"enabled": false})
	expect(t, w, 200)
	decodeBody(t, w, &p)
	if p.Enabled || p.PausedUntil != 0 {
		t.Errorf("off = %+v", p)
	}
	w = e.call("POST", "/api/protection", map[string]any{"enabled": true, "minutes": 5})
	expect(t, w, 200)
	decodeBody(t, w, &p)
	if !p.Enabled || p.PausedUntil != 0 {
		t.Errorf("on = %+v", p)
	}

	expectFields(t, e.call("POST", "/api/protection", map[string]any{"minutes": 5}), "enabled")
	expectFields(t, e.call("POST", "/api/protection", map[string]any{"enabled": false, "minutes": -1}), "minutes")
	expectFields(t, e.call("POST", "/api/protection", map[string]any{"enabled": false, "minutes": 100000}), "minutes")
	expectFields(t, e.call("POST", "/api/protection", map[string]any{"enabled": "yes"}), "enabled")
	expect(t, e.call("POST", "/api/protection", "{"), 400)
}

func TestStats(t *testing.T) {
	e := newCoreEnv(t)
	ts := time.Now()
	for i := 0; i < 3; i++ {
		e.stats.Record(stats.Event{TS: ts, Client: "192.168.1.20", Name: "example.org", Status: "ok", Upstream: "9.9.9.9", ElapsedMS: 10})
	}
	e.stats.Record(stats.Event{TS: ts, Client: "192.168.1.21", Name: "ads.example.net", Status: "blocked"})
	if _, err := e.st.CreateClient(store.Client{Name: "Laptop", IDs: []string{"192.168.1.0/24"}}); err != nil {
		t.Fatal(err)
	}
	e.now = ts
	for _, tc := range []struct {
		q     string
		hours int
		gran  string
	}{{"", 24, "hour"}, {"?hours=168", 168, "hour"}, {"?hours=720", 720, "day"}, {"?hours=5", 24, "hour"}, {"?hours=abc", 24, "hour"}} {
		w := e.call("GET", "/api/stats"+tc.q, nil)
		expect(t, w, 200)
		var s stats.Summary
		decodeBody(t, w, &s)
		if s.Hours != tc.hours || s.Granularity != tc.gran {
			t.Errorf("%s: %d %s", tc.q, s.Hours, s.Granularity)
		}
		if s.Totals.Queries != 4 || s.Totals.Blocked != 1 {
			t.Errorf("%s: totals %+v", tc.q, s.Totals)
		}
		if len(s.TopClients) != 2 || s.TopClients[0].Name != "Laptop" || s.TopClients[0].IP != "192.168.1.20" {
			t.Errorf("%s: clients %+v", tc.q, s.TopClients)
		}
		if len(s.TopBlocked) != 1 || s.TopBlocked[0].Name != "ads.example.net" {
			t.Errorf("%s: top blocked %+v", tc.q, s.TopBlocked)
		}
	}
	m := jsonMap(t, e.call("GET", "/api/stats", nil))
	for _, k := range []string{"hours", "granularity", "totals", "series", "top_domains", "top_blocked", "top_clients", "top_upstreams"} {
		if _, ok := m[k]; !ok {
			t.Errorf("stats misses %q", k)
		}
	}
	expect(t, e.call("DELETE", "/api/stats", nil), 204)
	var s stats.Summary
	decodeBody(t, e.call("GET", "/api/stats", nil), &s)
	if s.Totals.Queries != 0 {
		t.Errorf("after reset: %+v", s.Totals)
	}
}

func TestQuerylog(t *testing.T) {
	e := newCoreEnv(t)
	l, err := e.st.CreateList(store.List{Name: "AdGuard DNS filter", URL: "https://x.example/l", Kind: "block", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	statuses := []string{"ok", "allowed", "blocked", "blocked_service", "safesearch", "rewrite", "refused", "error"}
	for i := 0; i < 16; i++ {
		q := store.Query{TS: int64(1000 + i), ClientIP: "192.168.1.20", Name: fmt.Sprintf("host%d.example.org", i), QType: "A",
			Status: statuses[i%len(statuses)], Rcode: "NOERROR"}
		if q.Status == "blocked" {
			q.ListID, q.Rule, q.Reason = l.ID, "||example.org^", "list"
		}
		if i == 15 {
			q.ClientIP, q.ClientName, q.Name = "10.0.0.5", "Tablet", "Special.Example.COM"
		}
		e.qlog.Add(q) // not flushed yet: the handler must flush
	}

	w := e.call("GET", "/api/querylog", nil)
	expect(t, w, 200)
	var res querylogJSON
	decodeBody(t, w, &res)
	if len(res.Items) != 16 || res.NextBefore != 0 {
		t.Fatalf("items %d next %d", len(res.Items), res.NextBefore)
	}
	if res.Items[0].ID < res.Items[1].ID {
		t.Error("not newest first")
	}
	for _, it := range res.Items {
		if it.Status == "blocked" && it.ListName != "AdGuard DNS filter" {
			t.Errorf("list name = %q", it.ListName)
		}
	}
	item := jsonMap(t, w)["items"].([]any)[0].(map[string]any)
	for _, k := range []string{"id", "ts", "client_ip", "client_name", "name", "qtype", "status", "reason", "rule",
		"list_id", "list_name", "service", "upstream", "rcode", "answer", "elapsed_ms", "cached"} {
		if _, ok := item[k]; !ok {
			t.Errorf("item misses %q", k)
		}
	}

	tests := []struct {
		query string
		count int
	}{
		{"?status=all", 16},
		{"?status=blocked", 4},
		{"?status=allowed", 4},
		{"?status=rewritten", 4},
		{"?status=failed", 4},
		{"?search=HOST1", 6}, // host1, host10..host14
		{"?search=special", 1},
		{"?client=Tablet", 1},
		{"?client=192.168.1.20", 15},
		{"?limit=0", 1},
		{"?limit=9999", 16},
	}
	for _, tc := range tests {
		w := e.call("GET", "/api/querylog"+tc.query, nil)
		expect(t, w, 200)
		decodeBody(t, w, &res)
		if len(res.Items) != tc.count {
			t.Errorf("%s: %d items, want %d", tc.query, len(res.Items), tc.count)
		}
	}

	// Paging.
	var page1, page2 querylogJSON
	decodeBody(t, e.call("GET", "/api/querylog?limit=10", nil), &page1)
	if len(page1.Items) != 10 || page1.NextBefore != page1.Items[9].ID {
		t.Fatalf("page1: %d items, next %d", len(page1.Items), page1.NextBefore)
	}
	decodeBody(t, e.call("GET", fmt.Sprintf("/api/querylog?limit=10&before=%d", page1.NextBefore), nil), &page2)
	if len(page2.Items) != 6 || page2.NextBefore != 0 || page2.Items[0].ID >= page1.NextBefore {
		t.Fatalf("page2: %d items, next %d", len(page2.Items), page2.NextBefore)
	}

	// A last page that is exactly full has no next page (16 entries: 8 + 8).
	decodeBody(t, e.call("GET", "/api/querylog?limit=8", nil), &page1)
	decodeBody(t, e.call("GET", fmt.Sprintf("/api/querylog?limit=8&before=%d", page1.NextBefore), nil), &page2)
	if len(page1.Items) != 8 || page1.NextBefore == 0 || len(page2.Items) != 8 || page2.NextBefore != 0 {
		t.Fatalf("exact pages: %d/%d items, next %d/%d", len(page1.Items), len(page2.Items), page1.NextBefore, page2.NextBefore)
	}
	decodeBody(t, e.call("GET", "/api/querylog?limit=16", nil), &page1)
	if len(page1.Items) != 16 || page1.NextBefore != 0 {
		t.Fatalf("one full page: %d items, next %d", len(page1.Items), page1.NextBefore)
	}

	expectFields(t, e.call("GET", "/api/querylog?status=weird", nil), "status")
	expectFields(t, e.call("GET", "/api/querylog?limit=x", nil), "limit")
	expectFields(t, e.call("GET", "/api/querylog?before=-1", nil), "before")

	expect(t, e.call("DELETE", "/api/querylog", nil), 204)
	decodeBody(t, e.call("GET", "/api/querylog", nil), &res)
	if len(res.Items) != 0 || res.Items == nil {
		t.Errorf("after clear: %+v", res.Items)
	}
}

func TestListsCRUD(t *testing.T) {
	e := newCoreEnv(t)
	url := e.listServer.URL + "/list.txt"

	// Validation.
	tests := []struct {
		name   string
		body   map[string]any
		fields []string
	}{
		{"empty", map[string]any{}, []string{"name", "url"}},
		{"long name", map[string]any{"name": strings.Repeat("ä", 81), "url": url}, []string{"name"}},
		{"bad scheme", map[string]any{"name": "X", "url": "ftp://x.example/l"}, []string{"url"}},
		{"no host", map[string]any{"name": "X", "url": "https:///l"}, []string{"url"}},
		{"long url", map[string]any{"name": "X", "url": "https://x.example/" + strings.Repeat("a", 2000)}, []string{"url"}},
		{"bad kind", map[string]any{"name": "X", "url": url, "kind": "maybe"}, []string{"kind"}},
		{"wrong type", map[string]any{"name": "X", "url": url, "enabled": "yes"}, []string{"enabled"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectFields(t, e.call("POST", "/api/lists", tc.body), tc.fields...)
		})
	}

	// Create: downloaded in the background.
	w := e.call("POST", "/api/lists", map[string]any{"name": " Meine Liste ", "url": url, "kind": "block", "enabled": true})
	expect(t, w, 201)
	var l listJSON
	decodeBody(t, w, &l)
	if l.ID == 0 || l.Name != "Meine Liste" || l.Kind != "block" || !l.Enabled {
		t.Fatalf("created %+v", l)
	}
	m := jsonMap(t, w)
	for _, k := range []string{"id", "name", "url", "kind", "enabled", "rule_count", "updated_at", "last_error", "updating"} {
		if _, ok := m[k]; !ok {
			t.Errorf("list misses %q", k)
		}
	}
	if _, ok := m["etag"]; ok {
		t.Error("etag exposed")
	}
	waitLists(e.lists)
	var all []listJSON
	decodeBody(t, e.call("GET", "/api/lists", nil), &all)
	if len(all) != 1 || all[0].RuleCount != 2 || all[0].UpdatedAt == 0 || all[0].Updating {
		t.Fatalf("after download: %+v", all)
	}
	if e.eng.Check(filter.Request{Name: "ads.example.net", QType: dns.TypeA}).Action != filter.Block {
		t.Error("list not active")
	}

	// Duplicate URL.
	expectFields(t, e.call("POST", "/api/lists", map[string]any{"name": "Again", "url": url}), "url")

	// Disable → rules gone at once.
	w = e.call("PUT", fmt.Sprintf("/api/lists/%d", l.ID), map[string]any{"name": "Meine Liste", "url": url, "kind": "block", "enabled": false})
	expect(t, w, 200)
	decodeBody(t, w, &l)
	if l.Enabled {
		t.Error("still enabled")
	}
	if e.eng.Check(filter.Request{Name: "ads.example.net", QType: dns.TypeA}).Action != filter.None {
		t.Error("disabled list still active")
	}
	// Enable again: the local copy is active right away.
	expect(t, e.call("PUT", fmt.Sprintf("/api/lists/%d", l.ID), map[string]any{"name": "Meine Liste", "url": url, "enabled": true}), 200)
	if e.eng.Check(filter.Request{Name: "ads.example.net", QType: dns.TypeA}).Action != filter.Block {
		t.Error("enabled list not active")
	}
	waitLists(e.lists)

	// Kind change to allow.
	expect(t, e.call("PUT", fmt.Sprintf("/api/lists/%d", l.ID), map[string]any{"name": "Meine Liste", "url": url, "kind": "allow"}), 200)
	if r := e.eng.Check(filter.Request{Name: "ads.example.net", QType: dns.TypeA}); r.Action != filter.Allow {
		t.Errorf("allow list: %+v", r)
	}

	// URL change: old copy dropped, new one downloaded.
	e.listBody.Store("||other.example^\n")
	url2 := e.listServer.URL + "/other.txt"
	w = e.call("PUT", fmt.Sprintf("/api/lists/%d", l.ID), map[string]any{"name": "Neu", "url": url2, "kind": "block"})
	expect(t, w, 200)
	waitLists(e.lists)
	decodeBody(t, e.call("GET", "/api/lists", nil), &all)
	if all[0].URL != url2 || all[0].RuleCount != 1 || all[0].Name != "Neu" {
		t.Errorf("after url change: %+v", all[0])
	}
	if e.eng.Check(filter.Request{Name: "other.example", QType: dns.TypeA}).Action != filter.Block ||
		e.eng.Check(filter.Request{Name: "ads.example.net", QType: dns.TypeA}).Action != filter.None {
		t.Error("rules after url change wrong")
	}

	// A failing list keeps last_error.
	w = e.call("POST", "/api/lists", map[string]any{"name": "Kaputt", "url": e.listServer.URL + "/missing"})
	expect(t, w, 201)
	var broken listJSON
	decodeBody(t, w, &broken)
	waitLists(e.lists)
	decodeBody(t, e.call("GET", "/api/lists", nil), &all)
	for _, x := range all {
		if x.ID == broken.ID && x.LastError != "HTTP 404" {
			t.Errorf("last_error = %q", x.LastError)
		}
	}

	// Refresh routes.
	w = e.call("POST", "/api/lists/refresh", nil)
	expect(t, w, 202)
	if m := jsonMap(t, w); m["ok"] != true {
		t.Errorf("refresh = %v", m)
	}
	expect(t, e.call("POST", fmt.Sprintf("/api/lists/%d/refresh", l.ID), nil), 202)
	expect(t, e.call("POST", "/api/lists/999/refresh", nil), 404)
	waitLists(e.lists)

	// Not found / bad ids.
	expect(t, e.call("PUT", "/api/lists/999", map[string]any{"name": "X", "url": url}), 404)
	expect(t, e.call("PUT", "/api/lists/abc", map[string]any{"name": "X", "url": url}), 404)
	expect(t, e.call("DELETE", "/api/lists/999", nil), 404)

	// Delete: file and rules gone.
	expect(t, e.call("DELETE", fmt.Sprintf("/api/lists/%d", l.ID), nil), 204)
	if _, err := os.Stat(filepath.Join(e.dir, "lists", fmt.Sprintf("%d.txt", l.ID))); !os.IsNotExist(err) {
		t.Errorf("file still there: %v", err)
	}
	if e.eng.Check(filter.Request{Name: "other.example", QType: dns.TypeA}).Action != filter.None {
		t.Error("deleted list still active")
	}
}

func TestListCatalog(t *testing.T) {
	e := newCoreEnv(t)
	w := e.call("GET", "/api/lists/catalog", nil)
	expect(t, w, 200)
	var c []map[string]string
	decodeBody(t, w, &c)
	if len(c) < 10 {
		t.Fatalf("catalog: %d", len(c))
	}
	for _, k := range []string{"name", "url", "kind", "description"} {
		if c[0][k] == "" {
			t.Errorf("catalog entry misses %q", k)
		}
	}
}

func TestCustomRules(t *testing.T) {
	e := newCoreEnv(t)
	w := e.call("GET", "/api/rules", nil)
	expect(t, w, 200)
	var r rulesOut
	decodeBody(t, w, &r)
	if r.Text != "" || r.RuleCount != 0 || r.Invalid == nil {
		t.Errorf("empty rules = %+v", r)
	}

	text := "||ads.example.com^\n@@||good.example.com^\n||bad$foo\n"
	w = e.call("PUT", "/api/rules", map[string]string{"text": text})
	expect(t, w, 200)
	decodeBody(t, w, &r)
	if r.Text != text || r.RuleCount != 2 || len(r.Invalid) != 1 || r.Invalid[0].Line != 3 || r.Invalid[0].Error == "" {
		t.Errorf("saved = %+v", r)
	}
	if res := e.eng.Check(filter.Request{Name: "x.ads.example.com", QType: dns.TypeA}); res.Action != filter.Block || res.Reason != "custom" {
		t.Errorf("custom rule not active: %+v", res)
	}
	decodeBody(t, e.call("GET", "/api/rules", nil), &r)
	if r.Text != text {
		t.Error("rules not stored")
	}
	var st statusJSON
	decodeBody(t, e.call("GET", "/api/status", nil), &st)
	if st.Rules.CustomRules != 2 {
		t.Errorf("status custom rules = %d", st.Rules.CustomRules)
	}

	expectFields(t, e.call("PUT", "/api/rules", map[string]any{}), "text")
	expectFields(t, e.call("PUT", "/api/rules", map[string]any{"text": strings.Repeat("a", maxRulesSize+1)}), "text")
}

func TestQuickRules(t *testing.T) {
	e := newCoreEnv(t)
	if err := e.st.SaveCustomRules("# mine\n||keep.example^\n||x.example.com^\n||x.example.com^\n"); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		domain, action, want string
	}{
		{"X.Example.com.", "allow", "# mine\n||keep.example^\n@@||x.example.com^"},
		{"x.example.com", "block", "# mine\n||keep.example^\n||x.example.com^"},
		{"x.example.com", "block", "# mine\n||keep.example^\n||x.example.com^"},
		{"x.example.com", "remove", "# mine\n||keep.example^"},
		{"new.example", "allow", "# mine\n||keep.example^\n@@||new.example^"},
	}
	for _, tc := range tests {
		w := e.call("POST", "/api/rules/quick", map[string]string{"domain": tc.domain, "action": tc.action})
		expect(t, w, 200)
		var r rulesOut
		decodeBody(t, w, &r)
		if r.Text != tc.want {
			t.Errorf("%s %s: %q, want %q", tc.action, tc.domain, r.Text, tc.want)
		}
	}
	if res := e.eng.Check(filter.Request{Name: "new.example", QType: dns.TypeA}); res.Action != filter.Allow {
		t.Errorf("quick allow not active: %+v", res)
	}
	expectFields(t, e.call("POST", "/api/rules/quick", map[string]string{"domain": "not a domain", "action": "block"}), "domain")
	expectFields(t, e.call("POST", "/api/rules/quick", map[string]string{"domain": "a.example", "action": "nuke"}), "action")
	expectFields(t, e.call("POST", "/api/rules/quick", map[string]string{"domain": "", "action": ""}), "domain", "action")
}

func TestQuickEdit(t *testing.T) {
	tests := []struct {
		text, domain, add, want string
	}{
		{"", "a.example", "||a.example^", "||a.example^"},
		{"\n\n", "a.example", "", ""},
		{"||b.example^\r\n  ||a.example^  \r\n", "a.example", "@@||a.example^", "||b.example^\n@@||a.example^"},
		{"||sub.a.example^\n||a.example^$important", "a.example", "", "||sub.a.example^\n||a.example^$important"},
	}
	for _, tc := range tests {
		if got := quickEdit(tc.text, tc.domain, tc.add); got != tc.want {
			t.Errorf("quickEdit(%q) = %q, want %q", tc.text, got, tc.want)
		}
	}
}

func TestCheckValidation(t *testing.T) {
	e := newCoreEnv(t)
	expectFields(t, e.call("GET", "/api/check", nil), "name")
	expectFields(t, e.call("GET", "/api/check?name=bad..name", nil), "name")
	expectFields(t, e.call("GET", "/api/check?name=a.example&type=NOPE", nil), "type")
	expectFields(t, e.call("GET", "/api/check?name=a.example&client=999.1.1.1", nil), "client")
	// Without a DNS server (tests) the check answers 503.
	expect(t, e.call("GET", "/api/check?name=a.example", nil), 503)
}

func TestRewrites(t *testing.T) {
	e := newCoreEnv(t)
	tests := []struct {
		name   string
		body   map[string]any
		fields []string
	}{
		{"empty", map[string]any{}, []string{"domain", "answer"}},
		{"bad domain", map[string]any{"domain": "bad domain", "answer": "1.2.3.4"}, []string{"domain"}},
		{"bad answer", map[string]any{"domain": "nas.lan", "answer": "not valid!"}, []string{"answer"}},
		{"self", map[string]any{"domain": "nas.lan", "answer": "NAS.lan."}, []string{"answer"}},
		{"zone", map[string]any{"domain": "nas.lan", "answer": "fe80::1%eth0"}, []string{"answer"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectFields(t, e.call("POST", "/api/rewrites", tc.body), tc.fields...)
		})
	}

	w := e.call("POST", "/api/rewrites", map[string]any{"domain": "NAS.Home.Lan.", "answer": "192.168.1.10"})
	expect(t, w, 201)
	var rw store.Rewrite
	decodeBody(t, w, &rw)
	if rw.ID == 0 || rw.Domain != "nas.home.lan" || rw.Answer != "192.168.1.10" || !rw.Enabled || rw.CreatedAt == 0 {
		t.Errorf("created %+v", rw)
	}
	w = e.call("POST", "/api/rewrites", map[string]any{"domain": "*.home.lan", "answer": "Router.Home.Lan", "enabled": false})
	expect(t, w, 201)
	var wild store.Rewrite
	decodeBody(t, w, &wild)
	if wild.Answer != "router.home.lan" || wild.Enabled {
		t.Errorf("wildcard %+v", wild)
	}
	expectFields(t, e.call("POST", "/api/rewrites", map[string]any{"domain": "nas.home.lan", "answer": "192.168.1.10"}), "domain")

	var all []store.Rewrite
	decodeBody(t, e.call("GET", "/api/rewrites", nil), &all)
	if len(all) != 2 || all[0].Domain != "*.home.lan" {
		t.Errorf("list = %+v", all)
	}

	w = e.call("PUT", fmt.Sprintf("/api/rewrites/%d", rw.ID), map[string]any{"domain": "nas.home.lan", "answer": "fd00::10", "enabled": false})
	expect(t, w, 200)
	decodeBody(t, w, &rw)
	if rw.Answer != "fd00::10" || rw.Enabled {
		t.Errorf("updated %+v", rw)
	}
	expect(t, e.call("PUT", "/api/rewrites/999", map[string]any{"domain": "a.lan", "answer": "1.1.1.1"}), 404)
	expectFields(t, e.call("PUT", fmt.Sprintf("/api/rewrites/%d", rw.ID), map[string]any{"domain": "", "answer": "1.1.1.1"}), "domain")
	expect(t, e.call("DELETE", fmt.Sprintf("/api/rewrites/%d", rw.ID), nil), 204)
	expect(t, e.call("DELETE", fmt.Sprintf("/api/rewrites/%d", rw.ID), nil), 404)
	if e.reloads != 4 {
		t.Errorf("reloads = %d, want 4", e.reloads)
	}

	// A failing reload is reported.
	e.reloadErr = &InvalidError{Msg: "kaputt"}
	w = e.call("POST", "/api/rewrites", map[string]any{"domain": "c.lan", "answer": "1.1.1.1"})
	expect(t, w, 422)
	if errorOf(t, w) != "kaputt" {
		t.Errorf("reload error = %s", w.Body)
	}
	e.reloadErr = errors.New("db gone")
	expect(t, e.call("POST", "/api/rewrites", map[string]any{"domain": "d.lan", "answer": "1.1.1.1"}), 500)
}

func TestServices(t *testing.T) {
	e := newCoreEnv(t)
	w := e.call("GET", "/api/services", nil)
	expect(t, w, 200)
	var s servicesJSON
	decodeBody(t, w, &s)
	if len(s.Services) < 30 || s.Blocked == nil || len(s.Blocked) != 0 {
		t.Fatalf("services = %d blocked %v", len(s.Services), s.Blocked)
	}
	first := jsonMap(t, w)["services"].([]any)[0].(map[string]any)
	if len(first) != 3 || first["id"] == nil || first["name"] == nil || first["group"] == nil {
		t.Errorf("service object = %v", first)
	}

	w = e.call("PUT", "/api/services", map[string]any{"blocked": []string{"tiktok", "youtube", "tiktok"}})
	expect(t, w, 200)
	decodeBody(t, w, &s)
	if !reflect.DeepEqual(s.Blocked, []string{"tiktok", "youtube"}) {
		t.Errorf("blocked = %v", s.Blocked)
	}
	if got := e.settings.Load().BlockedServices; !reflect.DeepEqual(got, []string{"tiktok", "youtube"}) {
		t.Errorf("settings = %v", got)
	}
	f := expectFields(t, e.call("PUT", "/api/services", map[string]any{"blocked": []string{"tiktok", "myspace"}}), "blocked")
	if !strings.Contains(f["blocked"], "myspace") {
		t.Errorf("message %q", f["blocked"])
	}
	expect(t, e.call("PUT", "/api/services", map[string]any{"blocked": nil}), 200)
	if got := e.settings.Load().BlockedServices; len(got) != 0 || got == nil {
		t.Errorf("cleared = %#v", got)
	}
}

func TestClients(t *testing.T) {
	e := newCoreEnv(t)
	w := e.call("POST", "/api/clients", map[string]any{"name": "Kinder-Tablet", "ids": []string{"192.168.1.40", "192.168.50.0/24"},
		"use_global_settings": false, "filtering_enabled": true,
		"safesearch": map[string]bool{"enabled": true, "bing": false}, "use_global_services": false, "blocked_services": []string{"tiktok"}})
	expect(t, w, 201)
	var c store.Client
	decodeBody(t, w, &c)
	if c.ID == 0 || c.UseGlobalSettings || !c.SafeSearch.Enabled || c.SafeSearch.Bing || !c.SafeSearch.Google ||
		!reflect.DeepEqual(c.BlockedServices, []string{"tiktok"}) || c.CreatedAt == 0 {
		t.Errorf("created %+v", c)
	}
	m := jsonMap(t, w)
	for _, k := range []string{"id", "name", "ids", "use_global_settings", "filtering_enabled", "safesearch", "use_global_services", "blocked_services", "created_at"} {
		if _, ok := m[k]; !ok {
			t.Errorf("client misses %q", k)
		}
	}

	// Defaults for a minimal client; ids are canonicalized.
	w = e.call("POST", "/api/clients", map[string]any{"name": "Laptop", "ids": []string{" 192.168.1.20 ", "10.1.2.3/8"}})
	expect(t, w, 201)
	var laptop store.Client
	decodeBody(t, w, &laptop)
	if !laptop.UseGlobalSettings || !laptop.FilteringEnabled || !laptop.UseGlobalServices || laptop.BlockedServices == nil ||
		!reflect.DeepEqual(laptop.IDs, []string{"192.168.1.20", "10.0.0.0/8"}) {
		t.Errorf("defaults %+v", laptop)
	}

	tests := []struct {
		name   string
		body   map[string]any
		fields []string
	}{
		{"empty", map[string]any{}, []string{"name", "ids"}},
		{"dup name", map[string]any{"name": "laptop", "ids": []string{"192.168.1.99"}}, []string{"name"}},
		{"bad id", map[string]any{"name": "X", "ids": []string{"192.168.1.99", "nope"}}, []string{"ids.1"}},
		{"used id", map[string]any{"name": "X", "ids": []string{"192.168.1.40"}}, []string{"ids.0"}},
		{"used cidr", map[string]any{"name": "X", "ids": []string{"192.168.50.1/24"}}, []string{"ids.0"}},
		{"dup id", map[string]any{"name": "X", "ids": []string{"192.168.1.98", "192.168.1.98"}}, []string{"ids.1"}},
		{"too many", map[string]any{"name": "X", "ids": make([]string, 51)}, []string{"ids"}},
		{"unknown service", map[string]any{"name": "X", "ids": []string{"192.168.1.97"}, "blocked_services": []string{"nope"}}, []string{"blocked_services"}},
		{"long name", map[string]any{"name": strings.Repeat("x", 81), "ids": []string{"192.168.1.96"}}, []string{"name"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectFields(t, e.call("POST", "/api/clients", tc.body), tc.fields...)
		})
	}

	// Update keeps omitted fields; own ids may stay.
	w = e.call("PUT", fmt.Sprintf("/api/clients/%d", c.ID), map[string]any{"name": "Tablet", "ids": []string{"192.168.1.40"}})
	expect(t, w, 200)
	decodeBody(t, w, &c)
	if c.Name != "Tablet" || c.UseGlobalSettings || !c.SafeSearch.Enabled || !reflect.DeepEqual(c.BlockedServices, []string{"tiktok"}) {
		t.Errorf("updated %+v", c)
	}
	expectFields(t, e.call("PUT", fmt.Sprintf("/api/clients/%d", c.ID), map[string]any{"name": "Laptop", "ids": []string{"192.168.1.40"}}), "name")
	expect(t, e.call("PUT", "/api/clients/999", map[string]any{"name": "Y", "ids": []string{"1.1.1.1"}}), 404)

	// Recent clients from the statistics.
	e.now = time.Now()
	e.stats.Record(stats.Event{TS: e.now, Client: "192.168.1.40", Name: "a.example", Status: "blocked"})
	e.stats.Record(stats.Event{TS: e.now, Client: "192.168.1.40", Name: "a.example", Status: "ok"})
	e.stats.Record(stats.Event{TS: e.now, Client: "192.168.7.7", Name: "a.example", Status: "ok"})
	w = e.call("GET", "/api/clients", nil)
	expect(t, w, 200)
	var cl struct {
		Clients []store.Client   `json:"clients"`
		Recent  []map[string]any `json:"recent"`
	}
	decodeBody(t, w, &cl)
	if len(cl.Clients) != 2 || cl.Clients[0].Name != "Laptop" {
		t.Errorf("clients = %+v", cl.Clients)
	}
	if len(cl.Recent) != 2 {
		t.Fatalf("recent = %v", cl.Recent)
	}
	r0 := cl.Recent[0]
	if r0["ip"] != "192.168.1.40" || r0["name"] != "Tablet" || r0["client_id"] != float64(c.ID) || r0["queries"] != float64(2) ||
		r0["blocked"] != float64(1) || r0["last_seen"] == float64(0) {
		t.Errorf("recent[0] = %v", r0)
	}
	if _, ok := r0["hostname"]; !ok {
		t.Error("hostname missing")
	}
	if cl.Recent[1]["client_id"] != float64(0) || cl.Recent[1]["name"] != "" {
		t.Errorf("recent[1] = %v", cl.Recent[1])
	}

	expect(t, e.call("DELETE", fmt.Sprintf("/api/clients/%d", c.ID), nil), 204)
	expect(t, e.call("DELETE", fmt.Sprintf("/api/clients/%d", c.ID), nil), 404)
	if e.reloads != 4 {
		t.Errorf("reloads = %d", e.reloads)
	}
}

func TestClientMatcher(t *testing.T) {
	m := newClientMatcher([]store.Client{
		{ID: 1, Name: "net", IDs: []string{"192.168.0.0/16"}},
		{ID: 2, Name: "subnet", IDs: []string{"192.168.1.0/24"}},
		{ID: 3, Name: "host", IDs: []string{"192.168.1.5", "fd00::5"}},
	})
	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.1.5", "host"},
		{"::ffff:192.168.1.5", "host"},
		{"192.168.1.6", "subnet"},
		{"192.168.2.1", "net"},
		{"fd00::5", "host"},
		{"10.0.0.1", ""},
		{"garbage", ""},
	}
	for _, tc := range tests {
		c, _ := m.match(tc.ip)
		if c.Name != tc.want {
			t.Errorf("%s → %q, want %q", tc.ip, c.Name, tc.want)
		}
	}
}

func TestSettings(t *testing.T) {
	e := newCoreEnv(t)
	w := e.call("GET", "/api/settings", nil)
	expect(t, w, 200)
	m := jsonMap(t, w)
	for _, k := range []string{"upstreams", "fallback", "bootstrap", "upstream_mode", "upstream_timeout_ms", "conditional", "private_ptr",
		"private_upstreams", "cache_enabled", "cache_size", "cache_min_ttl", "cache_max_ttl", "blocking_mode", "blocking_ipv4",
		"blocking_ipv6", "blocked_ttl", "ratelimit", "refuse_any", "dnssec", "disable_ipv6", "allowed_clients", "disallowed_clients",
		"querylog_enabled", "querylog_hours", "anonymize_ip", "stats_days", "lists_update_hours", "safesearch"} {
		if _, ok := m[k]; !ok {
			t.Errorf("settings miss %q", k)
		}
	}
	for _, k := range []string{"blocked_services", "protection_enabled", "BlockedServices"} {
		if _, ok := m[k]; ok {
			t.Errorf("settings contain %q", k)
		}
	}

	// Partial update merges.
	w = e.call("PUT", "/api/settings", map[string]any{"ratelimit": 0, "safesearch": map[string]bool{"enabled": true}})
	expect(t, w, 200)
	var s config.Settings
	decodeBody(t, w, &s)
	if s.Ratelimit != 0 || !s.SafeSearch.Enabled || !s.SafeSearch.Google || len(s.Upstreams) != 2 {
		t.Errorf("merged %+v", s)
	}
	if got := e.settings.Load(); got.Ratelimit != 0 || !got.SafeSearch.Enabled {
		t.Error("not applied")
	}
	stored, err := e.st.LoadSettings()
	if err != nil || stored.Ratelimit != 0 {
		t.Errorf("not stored: %v", err)
	}

	// Protected fields can not be changed this way.
	e.call("PUT", "/api/services", map[string]any{"blocked": []string{"tiktok"}})
	expect(t, e.call("PUT", "/api/settings", `{"BlockedServices":[],"blocked_services":[],"ProtectionEnabled":false}`), 200)
	if got := e.settings.Load(); len(got.BlockedServices) != 1 || !got.ProtectionEnabled {
		t.Errorf("hidden fields changed: %+v", got)
	}

	// Validation: nothing is saved.
	before := e.settings.Load().Clone()
	tests := []struct {
		name   string
		body   string
		fields []string
	}{
		{"upstream", `{"upstreams":["tls://dns.quad9.net","nope://x"]}`, []string{"upstreams.1"}},
		{"no upstreams", `{"upstreams":[]}`, []string{"upstreams"}},
		{"ttl", `{"cache_min_ttl":100,"cache_max_ttl":10}`, []string{"cache_min_ttl"}},
		{"mode", `{"upstream_mode":"random","blocking_mode":"x"}`, []string{"upstream_mode", "blocking_mode"}},
		{"type", `{"ratelimit":"fast"}`, []string{"ratelimit"}},
		{"conditional", `{"conditional":[{"domain":"","upstream":"192.168.178.1"}]}`, []string{"conditional.0.domain"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectFields(t, e.call("PUT", "/api/settings", tc.body), tc.fields...)
		})
	}
	if got := e.settings.Load(); !reflect.DeepEqual(*got, before) {
		t.Error("invalid settings applied")
	}
	expect(t, e.call("PUT", "/api/settings", `[1,2]`), 400)
	expect(t, e.call("PUT", "/api/settings", `{"ratelimit":`), 400)

	// Runtime errors (unusable upstreams) → 422 with message, nothing changes.
	e.updateErr = &InvalidError{Msg: "Die Upstream-Einstellungen können nicht verwendet werden: x"}
	w = e.call("PUT", "/api/settings", map[string]any{"ratelimit": 5})
	expect(t, w, 422)
	if !strings.Contains(errorOf(t, w), "Upstream") {
		t.Errorf("error = %s", w.Body)
	}
	e.updateErr = errors.New("disk full")
	expect(t, e.call("PUT", "/api/settings", map[string]any{"ratelimit": 5}), 500)
	if e.settings.Load().Ratelimit != 0 {
		t.Error("failed update applied")
	}
}

func TestCacheClear(t *testing.T) {
	e := newCoreEnv(t)
	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	rr, _ := dns.NewRR("example.org. 300 IN A 1.2.3.4")
	resp.Answer = append(resp.Answer, rr)
	e.cache.Set(req, resp)
	if e.cache.Stats().Entries != 1 {
		t.Fatal("cache not filled")
	}
	expect(t, e.call("DELETE", "/api/cache", nil), 204)
	if e.cache.Stats().Entries != 0 {
		t.Error("cache not cleared")
	}
}

func TestUpstreamsTest(t *testing.T) {
	e := newCoreEnv(t)
	orig, origAll, origOne := testUpstream, testAllTimeout, testTimeout
	t.Cleanup(func() { testUpstream, testAllTimeout, testTimeout = orig, origAll, origOne })
	testAllTimeout = 300 * time.Millisecond
	testTimeout = 200 * time.Millisecond

	var bootMu sync.Mutex
	var gotBoot []string
	testUpstream = func(ctx context.Context, addr string, bootstrap []string, timeout time.Duration) (time.Duration, error) {
		bootMu.Lock()
		gotBoot = bootstrap
		bootMu.Unlock()
		switch addr {
		case "9.9.9.9":
			return 12345 * time.Microsecond, nil
		case "slow":
			<-ctx.Done()
			return 0, errors.New("Zeitüberschreitung")
		case "hang":
			time.Sleep(time.Second) // ignores ctx
			return 0, nil
		default:
			_, err := upstream.ParseAddress(addr)
			if err == nil {
				err = errors.New("Keine Antwort")
			}
			return 0, err
		}
	}
	start := time.Now()
	w := e.call("POST", "/api/upstreams/test", map[string]any{
		"upstreams": []string{"9.9.9.9", "nope://bad", "slow", "hang"}, "bootstrap": []string{"1.1.1.1"},
	})
	expect(t, w, 200)
	if time.Since(start) > 900*time.Millisecond {
		t.Errorf("took %v", time.Since(start))
	}
	var res struct {
		Results []map[string]any `json:"results"`
	}
	decodeBody(t, w, &res)
	if len(res.Results) != 4 {
		t.Fatalf("results = %v", res.Results)
	}
	if r := res.Results[0]; r["upstream"] != "9.9.9.9" || r["ok"] != true || r["ms"] != 12.3 || r["error"] != "" {
		t.Errorf("ok result = %v", r)
	}
	for _, r := range res.Results[1:] {
		if r["ok"] != false || r["error"] == "" {
			t.Errorf("failed result = %v", r)
		}
	}
	bootMu.Lock()
	defer bootMu.Unlock()
	if !reflect.DeepEqual(gotBoot, []string{"1.1.1.1"}) {
		t.Errorf("bootstrap = %v", gotBoot)
	}
	expectFields(t, e.call("POST", "/api/upstreams/test", map[string]any{"upstreams": []string{}}), "upstreams")
	expectFields(t, e.call("POST", "/api/upstreams/test", map[string]any{"upstreams": make([]string, 21)}), "upstreams")
	expectFields(t, e.call("POST", "/api/upstreams/test", map[string]any{"upstreams": []string{"1.1.1.1"}, "bootstrap": make([]string, 11)}), "bootstrap")
}
