package geo_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pk95dns/internal/geo"
	"pk95dns/internal/geo/geotest"
)

func TestCountry(t *testing.T) {
	var db geo.DB
	if db.Available() || db.Country(netip.MustParseAddr("81.1.2.3")) != "" || db.Date() != "" {
		t.Fatal("empty DB must answer nothing")
	}
	var nilDB *geo.DB
	if nilDB.Available() || nilDB.Country(netip.MustParseAddr("81.1.2.3")) != "" {
		t.Fatal("nil DB must answer nothing")
	}
	if err := db.Load(geotest.Write(t, t.TempDir(), geotest.Nets)); err != nil {
		t.Fatal(err)
	}
	if !db.Available() || len(db.Date()) != 10 {
		t.Fatalf("available %v date %q", db.Available(), db.Date())
	}
	tests := map[string]string{
		"81.1.2.3":          "DE",
		"::ffff:81.1.2.3":   "DE", // IPv4-mapped
		"5.255.255.5":       "RU",
		"36.152.44.96":      "CN",
		"2a00:1450:4001::1": "IE",
		"2a02:6b8::2:242":   "RU",
		"185.199.108.153":   "EU",
		"9.9.9.9":           "", // public, not in the database
		"192.168.1.10":      "", // private
		"10.0.0.1":          "",
		"172.16.5.5":        "",
		"100.64.1.1":        "", // CGNAT
		"127.0.0.1":         "",
		"169.254.1.1":       "",
		"fd00::1":           "", // unique local
		"fe80::1":           "",
		"::1":               "",
		"0.0.0.0":           "",
		"224.0.0.251":       "",
	}
	for ip, want := range tests {
		if got := db.Country(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s: %q, want %q", ip, got, want)
		}
	}
	// A broken file keeps the loaded database.
	bad := filepath.Join(t.TempDir(), "bad.mmdb")
	os.WriteFile(bad, []byte("not a database"), 0o600)
	if err := db.Load(bad); err == nil || db.Country(netip.MustParseAddr("81.1.2.3")) != "DE" {
		t.Fatal("a broken file replaced the database")
	}
}

func TestCodes(t *testing.T) {
	for _, c := range []string{"DE", "US", "CN", "RU", "EU", "AP", "XK"} {
		if !geo.Valid(c) {
			t.Errorf("%s invalid", c)
		}
	}
	for _, c := range []string{"de", "XX", "", "DEU", "ZZ"} {
		if geo.Valid(c) {
			t.Errorf("%q valid", c)
		}
	}
	if n := len(geo.Codes()); n != 252 { // 249 ISO codes, XK, EU, AP
		t.Fatalf("%d codes", n)
	}
}

func TestDue(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "db.mmdb")
	if !geo.Due(path, time.Time{}, now) {
		t.Fatal("missing file must be due")
	}
	if geo.Due(path, now.Add(-time.Hour), now) {
		t.Fatal("retry pause ignored")
	}
	if !geo.Due(path, now.Add(-7*time.Hour), now) {
		t.Fatal("due after the pause")
	}
	os.WriteFile(path, []byte("x"), 0o600)
	os.Chtimes(path, now.Add(-10*24*time.Hour), now.Add(-10*24*time.Hour))
	if geo.Due(path, time.Time{}, now) {
		t.Fatal("fresh file must not be due")
	}
	os.Chtimes(path, now.Add(-40*24*time.Hour), now.Add(-40*24*time.Hour))
	if !geo.Due(path, time.Time{}, now) {
		t.Fatal("old file must be due")
	}
}

// Update tries the current month, then the previous one, and never replaces a good file
// with a broken download.
func TestUpdate(t *testing.T) {
	good := geotest.Write(t, t.TempDir(), geotest.Nets)
	raw, _ := os.ReadFile(good)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(raw)
	zw.Close()

	var asked []string
	serveGood := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.Path)
		switch {
		case strings.Contains(r.URL.Path, "2026-11"):
			http.NotFound(w, r) // the new month is not published yet
		case serveGood:
			w.Write(gz.Bytes())
		default:
			w.Write([]byte("garbage"))
		}
	}))
	defer srv.Close()

	var db geo.DB
	path := filepath.Join(t.TempDir(), "geoip", "dbip-country-lite.mmdb")
	u := geo.NewTestUpdater(&db, path, srv.URL, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	if err := u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"/dbip-country-lite-2026-11.mmdb.gz", "/dbip-country-lite-2026-10.mmdb.gz"}; strings.Join(asked, ",") != strings.Join(want, ",") {
		t.Fatalf("asked %v", asked)
	}
	if db.Country(netip.MustParseAddr("81.1.2.3")) != "DE" {
		t.Fatal("not loaded")
	}
	serveGood = false
	if err := u.Update(context.Background()); err == nil {
		t.Fatal("garbage accepted")
	}
	if db.Country(netip.MustParseAddr("81.1.2.3")) != "DE" {
		t.Fatal("broken download replaced the database")
	}
	if fi, err := os.Stat(path); err != nil || fi.Size() != int64(len(raw)) {
		t.Fatal("file on disk replaced")
	}
}
