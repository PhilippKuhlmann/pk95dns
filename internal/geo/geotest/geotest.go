// Package geotest writes small country databases (mmdb) for tests. Only test files import
// it, so mmdbwriter never ends up in the binary.
package geotest

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// Nets are the networks of the default test database.
var Nets = map[string]string{
	"81.0.0.0/8":       "DE", // Germany
	"5.255.0.0/16":     "RU", // Russia
	"36.0.0.0/8":       "CN", // China
	"8.8.0.0/16":       "US", // United States
	"2a00:1450::/32":   "IE", // Ireland (IPv6)
	"2a02:6b8::/32":    "RU", // Russia (IPv6)
	"185.199.108.0/22": "EU", // only placed on a continent
}

// Write writes a database with nets (CIDR → code) to dir/test.mmdb and returns its path.
func Write(t testing.TB, dir string, nets map[string]string) string {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "DBIP-Country-Lite", Description: map[string]string{"en": "PK95 DNS test database"}, RecordSize: 24, IPVersion: 6})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, code := range nets {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		rec := mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(code)}}
		if err := tree.Insert(n, rec); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "test.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := tree.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	return path
}
