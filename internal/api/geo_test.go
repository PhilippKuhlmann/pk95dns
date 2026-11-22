package api

import (
	"slices"
	"strings"
	"testing"

	"pk95dns/internal/geo"
	"pk95dns/internal/geo/geotest"
	"pk95dns/internal/stats"
	"pk95dns/internal/store"
)

func withGeo(db *geo.DB) envOpt { return func(d *Deps) { d.Geo = db } }

func TestGeoSettings(t *testing.T) {
	var db geo.DB
	e := newEnv(t, coreMode(testToken), withGeo(&db))

	var out geoOut
	w := e.call("GET", "/api/geo", nil)
	expect(t, w, 200)
	decodeBody(t, w, &out)
	if out.Mode != "off" || out.Countries == nil || len(out.Countries) != 0 || out.Available || out.DBDate != "" || out.Attribution != geo.Attribution {
		t.Fatalf("defaults without database: %+v", out)
	}

	w = e.call("PUT", "/api/geo", `{"mode":"block","countries":[" cn","RU","ru"]}`)
	expect(t, w, 200)
	decodeBody(t, w, &out)
	if out.Mode != "block" || !slices.Equal(out.Countries, []string{"CN", "RU"}) {
		t.Fatalf("saved: %+v", out)
	}
	if g := e.settings.Load().Geo; g.Mode != "block" || !slices.Equal(g.Countries, []string{"CN", "RU"}) {
		t.Fatalf("settings: %+v", g)
	}
	// only the mode: the countries stay
	w = e.call("PUT", "/api/geo", `{"mode":"off"}`)
	expect(t, w, 200)
	decodeBody(t, w, &out)
	if out.Mode != "off" || !slices.Equal(out.Countries, []string{"CN", "RU"}) {
		t.Fatalf("partial: %+v", out)
	}

	// with a database: available and its date
	if err := db.Load(geotest.Write(t, t.TempDir(), geotest.Nets)); err != nil {
		t.Fatal(err)
	}
	decodeBody(t, e.call("GET", "/api/geo", nil), &out)
	if !out.Available || len(out.DBDate) != 10 {
		t.Fatalf("with database: %+v", out)
	}

	codes := geo.Codes()
	quoted := make([]string, geo.MaxCountries+1)
	for i := range quoted {
		quoted[i] = `"` + codes[i%len(codes)] + `"`
	}
	tooMany := `{"countries":[` + strings.Join(quoted, ",") + `]}`
	before := e.settings.Load().Geo
	for name, tc := range map[string]struct {
		body   string
		fields []string
	}{
		"mode":         {`{"mode":"maybe"}`, []string{"mode"}},
		"unknown code": {`{"countries":["DE","XX","de",""]}`, []string{"countries.1", "countries.3"}},
		"not a string": {`{"countries":["DE",7]}`, []string{"countries.1"}},
		"not a list":   {`{"countries":"DE"}`, []string{"countries"}},
		"too many":     {tooMany, []string{"countries"}},
		"allow empty":  {`{"mode":"allow","countries":[]}`, []string{"countries"}},
	} {
		t.Run(name, func(t *testing.T) {
			expectFields(t, e.call("PUT", "/api/geo", tc.body), tc.fields...)
		})
	}
	if g := e.settings.Load().Geo; g.Mode != before.Mode || !slices.Equal(g.Countries, before.Countries) {
		t.Fatalf("invalid input changed the setting: %+v", g)
	}
}

func TestCountriesAndStats(t *testing.T) {
	e := newEnv(t, coreMode(testToken))
	rec := func(client, status string, countries []string, removed map[string]int, unknown bool) {
		e.stats.Record(stats.Event{TS: e.now, Client: client, Name: "x.example", Status: status,
			Countries: countries, Removed: removed, Unknown: unknown})
	}
	rec("192.168.1.20", "ok", []string{"DE"}, nil, false)
	rec("192.168.1.21", "ok", []string{"DE", "US"}, map[string]int{"US": 2}, false)
	rec("192.168.1.20", "blocked_country", []string{"RU"}, nil, false)
	rec("192.168.1.20", "ok", nil, nil, true) // public, no country

	var c stats.Countries
	w := e.call("GET", "/api/countries?hours=24", nil)
	expect(t, w, 200)
	decodeBody(t, w, &c)
	want := []stats.CountryDetail{
		{CountryCount: stats.CountryCount{Code: "DE", Count: 2}, Clients: 2},
		{CountryCount: stats.CountryCount{Code: "RU", Count: 1, Blocked: 1}, Clients: 1},
		{CountryCount: stats.CountryCount{Code: "US", Count: 1, Removed: 2}, Clients: 1},
	}
	if c.Hours != 24 || c.Unknown != 1 || !slices.Equal(c.Countries, want) {
		t.Fatalf("countries: %+v", c)
	}

	var s stats.Summary
	decodeBody(t, e.call("GET", "/api/stats?hours=24", nil), &s)
	if s.Totals.CountryBlocked != 1 || s.Totals.Blocked != 1 || len(s.TopCountries) != 3 || s.TopCountries[0] != want[0].CountryCount {
		t.Fatalf("stats: totals %+v top %+v", s.Totals, s.TopCountries)
	}

	expect(t, e.call("DELETE", "/api/stats", nil), 204)
	decodeBody(t, e.call("GET", "/api/countries?hours=24", nil), &c)
	if len(c.Countries) != 0 || c.Unknown != 0 {
		t.Fatalf("after reset: %+v", c)
	}
}

func TestQuerylogCountry(t *testing.T) {
	e := newEnv(t, coreMode(testToken))
	if err := e.st.InsertQueries([]store.Query{
		{TS: 1, Name: "a.example", Status: "ok", Country: "DE"},
		{TS: 2, Name: "b.example", Status: "blocked_country", Reason: "country", Country: "RU"},
		{TS: 3, Name: "c.example", Status: "blocked", Reason: "list"},
	}); err != nil {
		t.Fatal(err)
	}
	names := func(status string) []string {
		var out struct{ Items []store.Query }
		decodeBody(t, e.call("GET", "/api/querylog?status="+status, nil), &out)
		var n []string
		for _, q := range out.Items {
			n = append(n, q.Name+"/"+q.Country)
		}
		return n
	}
	if got := names("country"); !slices.Equal(got, []string{"b.example/RU"}) {
		t.Errorf("country: %v", got)
	}
	if got := names("blocked"); !slices.Equal(got, []string{"c.example/", "b.example/RU"}) {
		t.Errorf("blocked: %v", got)
	}
	if got := names("all"); len(got) != 3 || got[2] != "a.example/DE" {
		t.Errorf("all: %v", got)
	}
}

// Core shows the page "Länder" from the manifest menu, after "Dienste".
func TestManifestCountriesMenu(t *testing.T) {
	var keys []string
	for _, m := range ManifestFor("1.2.0").Menu {
		keys = append(keys, m.Key)
	}
	i := slices.Index(keys, "countries")
	if i < 1 || keys[i-1] != "services" {
		t.Fatalf("menu %v", keys)
	}
	if m := ManifestFor("1.2.0").Menu[i]; m.Label != "Länder" || m.Icon != "globe" {
		t.Fatalf("entry %+v", m)
	}
}
