package api

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"pk95dns/internal/records"
)

// Tests of /api/zones, /api/records and the deprecated /api/rewrites (docs/api.md → DNS
// zones and records).

func (e *env) reloadCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reloads
}

func createZone(t *testing.T, e *env, body map[string]any) records.Zone {
	t.Helper()
	w := e.call("POST", "/api/zones", body)
	expect(t, w, 201)
	var z records.Zone
	decodeBody(t, w, &z)
	return z
}

func createRecord(t *testing.T, e *env, body map[string]any) records.Record {
	t.Helper()
	w := e.call("POST", "/api/records", body)
	expect(t, w, 201)
	var r records.Record
	decodeBody(t, w, &r)
	return r
}

func listRecords(t *testing.T, e *env, query string) []records.Record {
	t.Helper()
	w := e.call("GET", "/api/records"+query, nil)
	expect(t, w, 200)
	var out []records.Record
	decodeBody(t, w, &out)
	return out
}

func TestZonesAPI(t *testing.T) {
	e := newCoreEnv(t)
	w := e.call("GET", "/api/zones", nil)
	expect(t, w, 200)
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("empty list = %s", w.Body)
	}

	for _, tc := range []struct {
		name   string
		body   any
		fields []string
	}{
		{"empty", map[string]any{}, []string{"name"}},
		{"wildcard", map[string]any{"name": "*.home.lan"}, []string{"name"}},
		{"ip", map[string]any{"name": "192.168.1.1"}, []string{"name"}},
		{"negative ttl", map[string]any{"name": "home.lan", "ttl": -1}, []string{"ttl"}},
		{"ttl too big", map[string]any{"name": "home.lan", "ttl": 604801}, []string{"ttl"}},
		{"ns is an ip", map[string]any{"name": "home.lan", "primary_ns": "10.0.0.1"}, []string{"primary_ns"}},
		{"ttl type", `{"name":"home.lan","ttl":"300"}`, []string{"ttl"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectFields(t, e.call("POST", "/api/zones", tc.body), tc.fields...)
		})
	}
	if e.reloadCount() != 0 {
		t.Fatal("reload after a rejected change")
	}

	// A single record that the new zone takes over.
	nas := createRecord(t, e, map[string]any{"name": "nas.home.lan", "type": "A", "value": "192.168.1.10"})
	if nas.ZoneID != 0 {
		t.Fatalf("single record zone_id %d", nas.ZoneID)
	}

	z := createZone(t, e, map[string]any{"name": "Home.LAN.", "id": 99, "serial": 5, "record_count": 7, "created_at": 1})
	if z.ID == 99 || z.Name != "home.lan" || z.TTL != 300 || z.PrimaryNS != "ns.home.lan" || !z.Enabled ||
		z.Serial < 2026000001 || z.RecordCount != 1 || z.CreatedAt <= 1 {
		t.Fatalf("created %+v", z)
	}
	if got := listRecords(t, e, fmt.Sprintf("?zone_id=%d", z.ID)); len(got) != 1 || got[0].ID != nas.ID || got[0].ZoneID != z.ID {
		t.Fatalf("record not moved into the zone: %+v", got)
	}
	expectFields(t, e.call("POST", "/api/zones", map[string]any{"name": "home.lan"}), "name")

	rev := createZone(t, e, map[string]any{"name": "168.192.in-addr.arpa", "ttl": 0, "primary_ns": "NS.Home.Lan", "enabled": false})
	if rev.TTL != 0 || rev.PrimaryNS != "ns.home.lan" || rev.Enabled {
		t.Fatalf("reverse zone %+v", rev)
	}

	// A CNAME at the name of a new zone.
	createRecord(t, e, map[string]any{"name": "cn.lan", "type": "CNAME", "value": "x.example"})
	expectFields(t, e.call("POST", "/api/zones", map[string]any{"name": "cn.lan"}), "name")

	var all []records.Zone
	decodeBody(t, e.call("GET", "/api/zones", nil), &all)
	if len(all) != 2 || all[0].Name != "168.192.in-addr.arpa" || all[1].Name != "home.lan" || all[1].RecordCount != 1 {
		t.Fatalf("list %+v", all)
	}

	// PUT: missing fields keep their value; the serial grows; read-only fields are ignored.
	w = e.call("PUT", fmt.Sprintf("/api/zones/%d", z.ID), map[string]any{"ttl": 120, "serial": 1, "record_count": 0})
	expect(t, w, 200)
	var up records.Zone
	decodeBody(t, w, &up)
	if up.Name != "home.lan" || up.TTL != 120 || up.PrimaryNS != "ns.home.lan" || !up.Enabled || up.Serial <= z.Serial || up.RecordCount != 1 {
		t.Fatalf("updated %+v (before %+v)", up, z)
	}
	// Renaming a zone with records is refused; an empty zone can be renamed.
	expectFields(t, e.call("PUT", fmt.Sprintf("/api/zones/%d", z.ID), map[string]any{"name": "other.lan"}), "name")
	expectFields(t, e.call("PUT", fmt.Sprintf("/api/zones/%d", rev.ID), map[string]any{"name": "home.lan"}), "name")
	expectFields(t, e.call("PUT", fmt.Sprintf("/api/zones/%d", rev.ID), map[string]any{"ttl": 999999}), "ttl")
	w = e.call("PUT", fmt.Sprintf("/api/zones/%d", rev.ID), map[string]any{"name": "1.168.192.in-addr.arpa"})
	expect(t, w, 200)
	expect(t, e.call("PUT", "/api/zones/999", map[string]any{"ttl": 1}), 404)
	expect(t, e.call("PUT", "/api/zones/abc", map[string]any{"ttl": 1}), 404)

	// DELETE removes the zone and its records.
	before := e.reloadCount()
	expect(t, e.call("DELETE", fmt.Sprintf("/api/zones/%d", z.ID), nil), 204)
	expect(t, e.call("DELETE", fmt.Sprintf("/api/zones/%d", z.ID), nil), 404)
	if got := listRecords(t, e, "?name=nas.home.lan"); len(got) != 0 {
		t.Fatalf("records of the deleted zone: %+v", got)
	}
	if e.reloadCount() != before+1 {
		t.Fatalf("reloads %d → %d", before, e.reloadCount())
	}

	// A failing reload is reported.
	e.reloadErr = &InvalidError{Msg: "kaputt"}
	w = e.call("POST", "/api/zones", map[string]any{"name": "x.lan"})
	expect(t, w, 422)
	if errorOf(t, w) != "kaputt" {
		t.Fatalf("reload error %s", w.Body)
	}
	e.reloadErr = errors.New("db gone")
	expect(t, e.call("POST", "/api/zones", map[string]any{"name": "y.lan"}), 500)
}

func TestRecordsAPI(t *testing.T) {
	e := newCoreEnv(t)
	zone := createZone(t, e, map[string]any{"name": "home.lan"})

	for _, tc := range []struct {
		name   string
		body   any
		fields []string
	}{
		{"empty", map[string]any{}, []string{"name", "type"}},
		{"bad type", map[string]any{"name": "a.lan", "type": "NS", "value": "x.lan"}, []string{"type"}},
		{"bad ipv4", map[string]any{"name": "a.lan", "type": "A", "value": "fd00::1"}, []string{"value"}},
		{"bad ipv6", map[string]any{"name": "a.lan", "type": "AAAA", "value": "10.0.0.1"}, []string{"value"}},
		{"cname to ip", map[string]any{"name": "a.lan", "type": "CNAME", "value": "10.0.0.1"}, []string{"value"}},
		{"negative ttl", map[string]any{"name": "a.lan", "type": "A", "value": "10.0.0.1", "ttl": -5}, []string{"ttl"}},
		{"ttl too big", map[string]any{"name": "a.lan", "type": "A", "value": "10.0.0.1", "ttl": 604801}, []string{"ttl"}},
		{"mx priority", map[string]any{"name": "a.lan", "type": "MX", "value": "mx.lan", "priority": 70000}, []string{"priority"}},
		{"mx negative priority", map[string]any{"name": "a.lan", "type": "MX", "value": "mx.lan", "priority": -1}, []string{"priority"}},
		{"srv without port", map[string]any{"name": "_ldap._tcp.home.lan", "type": "SRV", "value": "ldap.home.lan"}, []string{"port"}},
		{"srv port too big", map[string]any{"name": "_ldap._tcp.home.lan", "type": "SRV", "value": "ldap.home.lan", "port": 65536}, []string{"port"}},
		{"srv weight", map[string]any{"name": "_ldap._tcp.home.lan", "type": "SRV", "value": "ldap.home.lan", "port": 389, "weight": -2}, []string{"weight"}},
		{"srv name", map[string]any{"name": "ldap.home.lan", "type": "SRV", "value": "ldap.home.lan", "port": 389}, []string{"name"}},
		{"ptr name", map[string]any{"name": "x.home.lan", "type": "PTR", "value": "nas.home.lan"}, []string{"name"}},
		{"txt too long", map[string]any{"name": "t.lan", "type": "TXT", "value": strings.Repeat("x", 4001)}, []string{"value"}},
		{"cname at apex", map[string]any{"name": "home.lan", "type": "CNAME", "value": "x.example"}, []string{"name"}},
		{"managed_by", map[string]any{"name": "a.lan", "type": "A", "value": "10.0.0.1", "managed_by": "x"}, []string{"managed_by"}},
		{"float ttl", `{"name":"a.lan","type":"A","value":"10.0.0.1","ttl":1.5}`, []string{"ttl"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectFields(t, e.call("POST", "/api/records", tc.body), tc.fields...)
		})
	}
	if e.reloadCount() != 1 {
		t.Fatalf("reloads %d", e.reloadCount())
	}

	// Defaults, normalisation, read-only fields ignored, fields of other types zeroed.
	nas := createRecord(t, e, map[string]any{"name": "NAS.Home.Lan.", "type": "a", "value": "192.168.1.10", "ptr": true,
		"priority": 70000, "id": 5, "zone_id": 99, "created_at": 1})
	if nas.ID == 5 || nas.ZoneID != zone.ID || nas.Name != "nas.home.lan" || nas.Type != "A" || nas.TTL != 300 ||
		!nas.Enabled || !nas.PTR || nas.Priority != 0 || nas.ManagedBy != "" || nas.CreatedAt <= 1 {
		t.Fatalf("created %+v", nas)
	}
	mx := createRecord(t, e, map[string]any{"name": "home.lan", "type": "MX", "value": "Mail.Home.Lan", "priority": 10, "ttl": 0, "ptr": true})
	if mx.Value != "mail.home.lan" || mx.Priority != 10 || mx.TTL != 0 || mx.PTR {
		t.Fatalf("mx %+v", mx)
	}
	srv := createRecord(t, e, map[string]any{"name": "_ldap._tcp.home.lan", "type": "SRV", "value": "ldap.home.lan", "priority": 0, "weight": 5, "port": 389})
	single := createRecord(t, e, map[string]any{"name": "printer.lan", "type": "A", "value": "10.0.0.9", "managed_by": "core", "enabled": false})
	if single.ZoneID != 0 || single.ManagedBy != "core" || single.Enabled {
		t.Fatalf("single %+v", single)
	}
	txt := createRecord(t, e, map[string]any{"name": "home.lan", "type": "TXT", "value": "  v=spf1 mx -all  "})
	if txt.Value != "v=spf1 mx -all" {
		t.Fatalf("txt %+v", txt)
	}

	// Conflicts.
	expectFields(t, e.call("POST", "/api/records", map[string]any{"name": "nas.home.lan", "type": "A", "value": "192.168.1.10"}), "name")
	expectFields(t, e.call("POST", "/api/records", map[string]any{"name": "nas.home.lan", "type": "CNAME", "value": "x.example"}), "name")
	createRecord(t, e, map[string]any{"name": "alias.home.lan", "type": "CNAME", "value": "nas.home.lan"})
	expectFields(t, e.call("POST", "/api/records", map[string]any{"name": "alias.home.lan", "type": "TXT", "value": "x"}), "name")

	// Filters.
	for _, tc := range []struct {
		query string
		want  []int64
	}{
		{"", nil},
		{"?zone_id=0", []int64{single.ID}},
		{fmt.Sprintf("?zone_id=%d&type=mx", zone.ID), []int64{mx.ID}},
		{"?name=NAS.home.lan", []int64{nas.ID}},
		{"?q=192.168", []int64{nas.ID}},
		{"?q=LDAP", []int64{srv.ID}},
		{"?type=PTR", []int64{}},
	} {
		got := listRecords(t, e, tc.query)
		ids := []int64{}
		for _, r := range got {
			ids = append(ids, r.ID)
		}
		if tc.query == "" {
			if len(ids) != 6 {
				t.Errorf("all: %v", ids)
			}
			continue
		}
		if fmt.Sprint(ids) != fmt.Sprint(tc.want) {
			t.Errorf("%s: %v, want %v", tc.query, ids, tc.want)
		}
	}
	expectFields(t, e.call("GET", "/api/records?zone_id=abc", nil), "zone_id")
	expectFields(t, e.call("GET", "/api/records?zone_id=-1", nil), "zone_id")
	if w := e.call("GET", "/api/records?type=PTR", nil); strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("empty result %s", w.Body)
	}

	// PUT: missing fields keep their value; a new name moves the record out of the zone.
	w := e.call("PUT", fmt.Sprintf("/api/records/%d", nas.ID), map[string]any{"enabled": false, "zone_id": 42})
	expect(t, w, 200)
	var up records.Record
	decodeBody(t, w, &up)
	if up.Enabled || up.Name != "nas.home.lan" || up.Value != "192.168.1.10" || !up.PTR || up.ZoneID != zone.ID || up.CreatedAt != nas.CreatedAt {
		t.Fatalf("updated %+v", up)
	}
	w = e.call("PUT", fmt.Sprintf("/api/records/%d", single.ID), map[string]any{"name": "printer.home.lan", "managed_by": ""})
	expect(t, w, 200)
	decodeBody(t, w, &up)
	if up.ZoneID != zone.ID || up.ManagedBy != "" {
		t.Fatalf("moved %+v", up)
	}
	expectFields(t, e.call("PUT", fmt.Sprintf("/api/records/%d", mx.ID), map[string]any{"priority": 65536}), "priority")
	expectFields(t, e.call("PUT", fmt.Sprintf("/api/records/%d", srv.ID), map[string]any{"value": "1.2.3.4"}), "value")
	expect(t, e.call("PUT", "/api/records/999", map[string]any{"ttl": 1}), 404)

	// Zone record counts follow.
	var zs []records.Zone
	decodeBody(t, e.call("GET", "/api/zones", nil), &zs)
	if len(zs) != 1 || zs[0].RecordCount != 6 {
		t.Fatalf("zones %+v", zs)
	}

	before := e.reloadCount()
	expect(t, e.call("DELETE", fmt.Sprintf("/api/records/%d", mx.ID), nil), 204)
	expect(t, e.call("DELETE", fmt.Sprintf("/api/records/%d", mx.ID), nil), 404)
	if e.reloadCount() != before+1 {
		t.Fatal("no reload after delete")
	}
	// Writing requests need JSON (also DELETE).
	expect(t, e.call("DELETE", fmt.Sprintf("/api/records/%d", srv.ID), nil, header("Content-Type", "text/plain")), 415)
}

func TestRewritesCompat(t *testing.T) {
	e := newCoreEnv(t)
	for _, tc := range []struct {
		name   string
		body   map[string]any
		fields []string
	}{
		{"empty", map[string]any{}, []string{"domain", "answer"}},
		{"bad domain", map[string]any{"domain": "bad domain", "answer": "1.2.3.4"}, []string{"domain"}},
		{"bad answer", map[string]any{"domain": "nas.lan", "answer": "not valid!"}, []string{"answer"}},
		{"self", map[string]any{"domain": "nas.lan", "answer": "NAS.lan."}, []string{"answer"}},
		{"zone", map[string]any{"domain": "nas.lan", "answer": "fe80::1%eth0"}, []string{"answer"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectFields(t, e.call("POST", "/api/rewrites", tc.body), tc.fields...)
		})
	}

	w := e.call("POST", "/api/rewrites", map[string]any{"domain": "NAS.Home.Lan.", "answer": "192.168.1.10"})
	expect(t, w, 201)
	var rw rewriteJSON
	decodeBody(t, w, &rw)
	if rw.ID == 0 || rw.Domain != "nas.home.lan" || rw.Answer != "192.168.1.10" || !rw.Enabled || rw.CreatedAt == 0 {
		t.Fatalf("created %+v", rw)
	}
	if m := jsonMap(t, w); len(m) != 5 {
		t.Fatalf("rewrite keys %v", m)
	}
	recs := listRecords(t, e, "?name=nas.home.lan")
	if len(recs) != 1 || recs[0].ID != rw.ID || recs[0].Type != "A" || recs[0].TTL != records.RewriteTTL {
		t.Fatalf("record of the rewrite %+v", recs)
	}
	w = e.call("POST", "/api/rewrites", map[string]any{"domain": "nas.home.lan", "answer": "fd00::10"})
	expect(t, w, 201)
	var v6 rewriteJSON
	decodeBody(t, w, &v6)
	w = e.call("POST", "/api/rewrites", map[string]any{"domain": "*.home.lan", "answer": "Router.Home.Lan", "enabled": false})
	expect(t, w, 201)
	var wild rewriteJSON
	decodeBody(t, w, &wild)
	if wild.Answer != "router.home.lan" || wild.Enabled {
		t.Fatalf("wildcard %+v", wild)
	}
	if recs := listRecords(t, e, "?type=CNAME"); len(recs) != 1 || recs[0].ID != wild.ID || recs[0].Name != "*.home.lan" {
		t.Fatalf("CNAME %+v", recs)
	}
	expectFields(t, e.call("POST", "/api/rewrites", map[string]any{"domain": "nas.home.lan", "answer": "192.168.1.10"}), "domain")

	// Other types are not part of the view.
	mx := createRecord(t, e, map[string]any{"name": "nas.home.lan", "type": "MX", "value": "mx.home.lan", "priority": 10})
	var all []rewriteJSON
	decodeBody(t, e.call("GET", "/api/rewrites", nil), &all)
	if len(all) != 3 || all[0].ID != wild.ID || all[1].ID != rw.ID || all[2].ID != v6.ID {
		t.Fatalf("list %+v", all)
	}
	expect(t, e.call("PUT", fmt.Sprintf("/api/rewrites/%d", mx.ID), map[string]any{"domain": "a.lan", "answer": "1.1.1.1"}), 404)
	expect(t, e.call("DELETE", fmt.Sprintf("/api/rewrites/%d", mx.ID), nil), 404)
	expect(t, e.call("PUT", "/api/rewrites/999", map[string]any{"domain": "a.lan", "answer": "1.1.1.1"}), 404)

	// PUT: the type follows the answer; CNAME conflicts are reported on "domain".
	expectFields(t, e.call("PUT", fmt.Sprintf("/api/rewrites/%d", rw.ID), map[string]any{"answer": "other.example"}), "domain")
	expectFields(t, e.call("PUT", fmt.Sprintf("/api/rewrites/%d", rw.ID), map[string]any{"domain": "", "answer": "1.1.1.1"}), "domain")
	w = e.call("PUT", fmt.Sprintf("/api/rewrites/%d", rw.ID), map[string]any{"domain": "nas.home.lan", "answer": "fd00::11", "enabled": false})
	expect(t, w, 200)
	decodeBody(t, w, &rw)
	if rw.Answer != "fd00::11" || rw.Enabled || rw.Domain != "nas.home.lan" {
		t.Fatalf("updated %+v", rw)
	}
	if recs := listRecords(t, e, "?type=AAAA"); len(recs) != 2 || recs[0].TTL != records.RewriteTTL {
		t.Fatalf("type follows the answer: %+v", recs)
	}
	w = e.call("PUT", fmt.Sprintf("/api/rewrites/%d", wild.ID), map[string]any{"answer": "10.0.0.1"})
	expect(t, w, 200)
	if recs := listRecords(t, e, "?name=*.home.lan"); len(recs) != 1 || recs[0].Type != "A" || recs[0].Value != "10.0.0.1" {
		t.Fatalf("CNAME → A %+v", recs)
	}

	before := e.reloadCount()
	expect(t, e.call("DELETE", fmt.Sprintf("/api/rewrites/%d", rw.ID), nil), 204)
	expect(t, e.call("DELETE", fmt.Sprintf("/api/rewrites/%d", rw.ID), nil), 404)
	if e.reloadCount() != before+1 {
		t.Fatal("no reload after delete")
	}

	e.reloadErr = &InvalidError{Msg: "kaputt"}
	w = e.call("POST", "/api/rewrites", map[string]any{"domain": "c.lan", "answer": "1.1.1.1"})
	expect(t, w, 422)
	if errorOf(t, w) != "kaputt" {
		t.Fatalf("reload error %s", w.Body)
	}
}

func TestStatusCountsFollowRecords(t *testing.T) {
	e := newCoreEnv(t)
	rules := func() rulesJSON {
		var st statusJSON
		decodeBody(t, e.call("GET", "/api/status", nil), &st)
		return st.Rules
	}
	if r := rules(); r.Zones != 0 || r.Records != 0 || r.Rewrites != 0 {
		t.Fatalf("empty %+v", r)
	}
	z := createZone(t, e, map[string]any{"name": "home.lan"})
	createRecord(t, e, map[string]any{"name": "nas.home.lan", "type": "A", "value": "10.0.0.1", "ptr": true})
	createRecord(t, e, map[string]any{"name": "home.lan", "type": "TXT", "value": "hello"})
	createRecord(t, e, map[string]any{"name": "x.lan", "type": "CNAME", "value": "nas.home.lan"})
	if r := rules(); r.Zones != 1 || r.Records != 3 || r.Rewrites != 2 {
		t.Fatalf("counts %+v", r)
	}
	expect(t, e.call("PUT", fmt.Sprintf("/api/zones/%d", z.ID), map[string]any{"enabled": false}), 200)
	if r := rules(); r.Zones != 0 || r.Records != 1 || r.Rewrites != 1 {
		t.Fatalf("disabled zone %+v", r)
	}
}

func TestRecordsWithDNSServer(t *testing.T) {
	e := newCoreEnv(t)
	srv := withDNS(t, e, nil, []records.Record{
		{Name: "nas.lan", Type: "A", Value: "192.168.1.10", TTL: 60, Enabled: true},
		{Name: "mail.lan", Type: "MX", Value: "mx.lan", Priority: 10, TTL: 60, Enabled: true},
	})
	_ = srv
	var st statusJSON
	decodeBody(t, e.call("GET", "/api/status", nil), &st)
	if st.Rules.Records != 2 || st.Rules.Rewrites != 1 || st.Rules.Zones != 0 {
		t.Fatalf("status from the DNS index %+v", st.Rules)
	}
	m := jsonMap(t, e.call("GET", "/api/check?name=mail.lan&type=MX", nil))
	if m["status"] != "rewrite" || m["reason"] != "record" || m["answer"] != "MX 10 mx.lan" {
		t.Fatalf("check %v", m)
	}
}
