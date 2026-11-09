package api

// Tests against the real DNS server (internal/dnsserver).

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"pk95dns/internal/config"
	"pk95dns/internal/dnsserver"
	"pk95dns/internal/records"
	"pk95dns/internal/stats"
	"pk95dns/internal/store"
	"pk95dns/internal/upstream"
)

// withDNS attaches a real DNS server (not listening) with the given clients and records.
func withDNS(t *testing.T, e *env, clients []store.Client, recs []records.Record) *dnsserver.Server {
	t.Helper()
	srv := dnsserver.New(dnsserver.Deps{Filter: e.eng, Cache: e.cache, Log: e.qlog, Stats: e.stats})
	router, err := upstream.NewRouter(upstream.Config{
		Upstreams: []string{"127.0.0.1:1"}, Mode: config.ModeSequential, Timeout: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(router.Close)
	srv.Apply(dnsserver.Runtime{
		Settings: e.settings.Load().Clone(),
		Router:   router,
		Records:  records.Compile(nil, recs),
		Clients:  clients,
	})
	e.api.d.DNS = srv
	return srv
}

func TestCheckWithDNSServer(t *testing.T) {
	e := newCoreEnv(t)
	l, err := e.st.CreateList(store.List{Name: "AdGuard DNS filter", URL: e.listServer.URL + "/l.txt", Kind: "block", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(e.dir, "lists"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "lists", "1.txt"), []byte("||example.net^\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := e.lists.Rebuild(); err != nil {
		t.Fatal(err)
	}
	expect(t, e.call("PUT", "/api/rules", map[string]string{"text": "||custom.example^"}), 200)
	withDNS(t, e,
		[]store.Client{{ID: 1, Name: "Laptop", IDs: []string{"192.168.1.20"}, UseGlobalSettings: true, FilteringEnabled: true, UseGlobalServices: true}},
		[]records.Record{{Name: "nas.lan", Type: "A", Value: "192.168.1.10", TTL: 60, Enabled: true}})

	tests := []struct {
		query                    string
		status, reason, listName string
		listID                   int64
		clientName               string
	}{
		{"name=ads.example.net&type=A&client=192.168.1.20", "blocked", "list", "AdGuard DNS filter", l.ID, "Laptop"},
		{"name=custom.example", "blocked", "custom", "", 0, ""},
		{"name=nas.lan", "rewrite", "record", "", 0, ""},
		{"name=fine.example.org&type=aaaa", "ok", "", "", 0, ""},
	}
	for _, tc := range tests {
		w := e.call("GET", "/api/check?"+tc.query, nil)
		expect(t, w, 200)
		var res dnsserver.CheckResult
		decodeBody(t, w, &res)
		if res.Status != tc.status || res.Reason != tc.reason || res.ListName != tc.listName || res.ListID != tc.listID ||
			res.ClientName != tc.clientName {
			t.Errorf("%s: %+v", tc.query, res)
		}
	}
	m := jsonMap(t, e.call("GET", "/api/check?name=ads.example.net", nil))
	for _, k := range []string{"name", "type", "client_ip", "client_name", "status", "reason", "rule", "list_id", "list_name", "service", "answer"} {
		if _, ok := m[k]; !ok {
			t.Errorf("check misses %q", k)
		}
	}
}

func TestStatusWithDNSServer(t *testing.T) {
	e := newCoreEnv(t)
	withDNS(t, e, nil, nil)
	w := e.call("GET", "/api/status", nil)
	expect(t, w, 200)
	var st statusJSON
	decodeBody(t, w, &st)
	if st.DNS.UDP || st.DNS.TCP {
		t.Errorf("not listening, but dns = %+v", st.DNS)
	}
}

func TestStatsClientNamesWithDNSServer(t *testing.T) {
	e := newCoreEnv(t)
	withDNS(t, e, nil, nil)
	if _, err := e.st.CreateClient(store.Client{Name: "Laptop", IDs: []string{"192.168.1.20"}}); err != nil {
		t.Fatal(err)
	}
	e.now = time.Now()
	e.stats.Record(stats.Event{TS: e.now, Client: "192.168.1.20", Name: "a.example", Status: "ok"})
	e.stats.Record(stats.Event{TS: e.now, Client: "192.168.1.99", Name: "a.example", Status: "ok"})
	w := e.call("GET", "/api/stats", nil)
	expect(t, w, 200)
	var s stats.Summary
	decodeBody(t, w, &s)
	names := map[string]string{}
	for _, c := range s.TopClients {
		names[c.IP] = c.Name
	}
	if names["192.168.1.20"] != "Laptop" {
		t.Errorf("names = %v", names)
	}
	expect(t, e.call("GET", "/api/clients", nil), 200)
}
