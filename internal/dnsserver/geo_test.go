package dnsserver

import (
	"maps"
	"slices"
	"testing"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
	"pk95dns/internal/filter"
	"pk95dns/internal/geo"
	"pk95dns/internal/geo/geotest"
	"pk95dns/internal/records"
)

// geoAnswers are upstream answers with public addresses; countries per geotest.Nets
// (81/8 DE, 5.255/16 RU, 36/8 CN, 2a02:6b8::/32 RU, 9.9.9.9 not in the database).
var geoAnswers = map[string][]string{
	"de.geo.example.|A":      {"de.geo.example. 300 IN A 81.1.1.1"},
	"ru.geo.example.|A":      {"ru.geo.example. 300 IN A 5.255.1.1", "ru.geo.example. 300 IN A 5.255.1.2"},
	"ru.geo.example.|AAAA":   {"ru.geo.example. 300 IN AAAA 2a02:6b8::1"},
	"mixed.geo.example.|A":   {"mixed.geo.example. 300 IN A 5.255.1.1", "mixed.geo.example. 300 IN A 81.1.1.1"},
	"private.geo.example.|A": {"private.geo.example. 300 IN A 192.168.1.5"},
	"unknown.geo.example.|A": {"unknown.geo.example. 300 IN A 9.9.9.9"},
	"allowed.geo.example.|A": {"allowed.geo.example. 300 IN A 5.255.1.9"},
	"blocked.geo.example.|A": {"blocked.geo.example. 300 IN A 5.255.1.10"},
	"cdn.geo.example.|A": {
		"cdn.geo.example. 300 IN CNAME edge.cdn.example.",
		"edge.cdn.example. 300 IN A 36.1.1.1",
	},
}

func geoEnv(t *testing.T, mode string, countries ...string) *env {
	t.Helper()
	var db geo.DB
	if err := db.Load(geotest.Write(t, t.TempDir(), geotest.Nets)); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(s *config.Settings) {
		s.Geo = config.Geo{Mode: mode, Countries: countries, ResolveBlocked: true}
	})
	e.srv.deps.Geo = &db
	return e
}

type geoWant struct {
	status, reason, country string
	answer                  []string
	countries               []string
	removed                 map[string]int
	unknown                 bool
}

func checkGeo(t *testing.T, e *env, name string, qtype uint16, w geoWant) {
	t.Helper()
	resp, l := e.query(name, qtype)
	if resp == nil {
		t.Fatalf("%s: no answer", name)
	}
	if l.q.Status != w.status || l.q.Reason != w.reason || l.q.Country != w.country {
		t.Errorf("%s: status %q reason %q country %q, want %q %q %q", name, l.q.Status, l.q.Reason, l.q.Country, w.status, w.reason, w.country)
	}
	if got := answers(resp); !slices.Equal(got, w.answer) {
		t.Errorf("%s: answer %v, want %v", name, got, w.answer)
	}
	if !slices.Equal(l.ev.Countries, w.countries) || !maps.Equal(l.ev.Removed, w.removed) || l.ev.Unknown != w.unknown {
		t.Errorf("%s: stats event countries %v removed %v unknown %v, want %v %v %v", name, l.ev.Countries, l.ev.Removed, l.ev.Unknown, w.countries, w.removed, w.unknown)
	}
}

func TestGeoBlockMode(t *testing.T) {
	e := geoEnv(t, config.GeoBlock, "RU", "CN")
	// fully blocked: the normal blocked answer of the blocking mode (null_ip)
	checkGeo(t, e, "ru.geo.example", dns.TypeA, geoWant{status: "blocked_country", reason: "country", country: "RU",
		answer: []string{"A 0.0.0.0"}, countries: []string{"RU"}})
	checkGeo(t, e, "ru.geo.example", dns.TypeAAAA, geoWant{status: "blocked_country", reason: "country", country: "RU",
		answer: []string{"AAAA ::"}, countries: []string{"RU"}})
	// partly: the RU address is removed, the DE one stays, status ok
	checkGeo(t, e, "mixed.geo.example", dns.TypeA, geoWant{status: "ok", country: "DE",
		answer: []string{"A 81.1.1.1"}, countries: []string{"RU", "DE"}, removed: map[string]int{"RU": 1}})
	// the country comes from the address after the CNAME chain
	checkGeo(t, e, "cdn.geo.example", dns.TypeA, geoWant{status: "blocked_country", reason: "country", country: "CN",
		answer: []string{"A 0.0.0.0"}, countries: []string{"CN"}})
	checkGeo(t, e, "de.geo.example", dns.TypeA, geoWant{status: "ok", country: "DE", answer: []string{"A 81.1.1.1"}, countries: []string{"DE"}})
	checkGeo(t, e, "private.geo.example", dns.TypeA, geoWant{status: "ok", answer: []string{"A 192.168.1.5"}})
	checkGeo(t, e, "unknown.geo.example", dns.TypeA, geoWant{status: "ok", answer: []string{"A 9.9.9.9"}, unknown: true})

	// a cached answer is checked again (and the cache keeps the full answer)
	checkGeo(t, e, "mixed.geo.example", dns.TypeA, geoWant{status: "ok", country: "DE",
		answer: []string{"A 81.1.1.1"}, countries: []string{"RU", "DE"}, removed: map[string]int{"RU": 1}})
	if e.up.count("mixed.geo.example", dns.TypeA) != 1 {
		t.Fatal("second query not from the cache")
	}
	e.update(func(s *config.Settings) { s.Geo = config.Geo{Mode: config.GeoOff, Countries: []string{}} })
	checkGeo(t, e, "mixed.geo.example", dns.TypeA, geoWant{status: "ok", country: "RU",
		answer: []string{"A 5.255.1.1", "A 81.1.1.1"}, countries: []string{"RU", "DE"}})
}

func TestGeoAllowMode(t *testing.T) {
	e := geoEnv(t, config.GeoAllow, "DE")
	checkGeo(t, e, "de.geo.example", dns.TypeA, geoWant{status: "ok", country: "DE", answer: []string{"A 81.1.1.1"}, countries: []string{"DE"}})
	checkGeo(t, e, "mixed.geo.example", dns.TypeA, geoWant{status: "ok", country: "DE",
		answer: []string{"A 81.1.1.1"}, countries: []string{"RU", "DE"}, removed: map[string]int{"RU": 1}})
	checkGeo(t, e, "cdn.geo.example", dns.TypeA, geoWant{status: "blocked_country", reason: "country", country: "CN",
		answer: []string{"A 0.0.0.0"}, countries: []string{"CN"}})
	// addresses without a country are always allowed
	checkGeo(t, e, "private.geo.example", dns.TypeA, geoWant{status: "ok", answer: []string{"A 192.168.1.5"}})
	checkGeo(t, e, "unknown.geo.example", dns.TypeA, geoWant{status: "ok", answer: []string{"A 9.9.9.9"}, unknown: true})
	// the blocking mode is used for the blocked answer
	e.update(func(s *config.Settings) { s.BlockingMode = config.BlockNXDomain })
	resp, l := e.query("ru.geo.example", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError || l.q.Status != "blocked_country" {
		t.Fatalf("nxdomain mode: %s %q", dns.RcodeToString[resp.Rcode], l.q.Status)
	}
}

// Allow rules, own zones and records, and a paused protection win against the country
// setting; the countries are still recorded where there is an upstream answer.
func TestGeoPrecedence(t *testing.T) {
	e := geoEnv(t, config.GeoBlock, "RU")
	custom, _ := filter.Compile([]filter.Source{{ID: 0, Data: []byte("@@||allowed.geo.example^")}})
	e.engine.SetCustom(custom)
	e.zones = nil
	e.recs = []records.Record{{Name: "local.geo.example", Type: "A", Value: "5.255.7.7", TTL: 60, Enabled: true}}
	e.apply()

	checkGeo(t, e, "allowed.geo.example", dns.TypeA, geoWant{status: "allowed", reason: "custom", country: "RU",
		answer: []string{"A 5.255.1.9"}, countries: []string{"RU"}})
	_, l := e.query("local.geo.example", dns.TypeA)
	if l.q.Status != statusRewrite || l.q.Country != "" || l.ev.Countries != nil {
		t.Fatalf("own record: %+v / %+v", l.q, l.ev)
	}
	e.update(func(s *config.Settings) { s.ProtectionEnabled = false })
	checkGeo(t, e, "ru.geo.example", dns.TypeA, geoWant{status: "ok", country: "RU",
		answer: []string{"A 5.255.1.1", "A 5.255.1.2"}, countries: []string{"RU"}})
}

// Without a database nothing happens: no countries, nothing blocked, no error.
func TestGeoWithoutDatabase(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.Geo = config.Geo{Mode: config.GeoAllow, Countries: []string{"DE"}} })
	for _, db := range []*geo.DB{nil, {}} {
		e.srv.deps.Geo = db
		checkGeo(t, e, "ru.geo.example", dns.TypeA, geoWant{status: "ok", answer: []string{"A 5.255.1.1", "A 5.255.1.2"}})
	}
}

// "Erlauben" in the query log (POST /api/rules/quick allow) adds "@@||name^" to the custom
// rules: a name blocked by country must then really get its addresses, also from the cache.
func TestGeoQuickAllowLetsThrough(t *testing.T) {
	e := geoEnv(t, config.GeoBlock, "RU")
	checkGeo(t, e, "ru.geo.example", dns.TypeA, geoWant{status: "blocked_country", reason: "country", country: "RU",
		answer: []string{"A 0.0.0.0"}, countries: []string{"RU"}})
	custom, _ := filter.Compile([]filter.Source{{ID: 0, Data: []byte("@@||ru.geo.example^")}})
	e.engine.SetCustom(custom)
	checkGeo(t, e, "ru.geo.example", dns.TypeA, geoWant{status: "allowed", reason: "custom", country: "RU",
		answer: []string{"A 5.255.1.1", "A 5.255.1.2"}, countries: []string{"RU"}})
	if e.up.count("ru.geo.example", dns.TypeA) != 1 {
		t.Fatal("the allowed answer did not come from the cache")
	}
}
