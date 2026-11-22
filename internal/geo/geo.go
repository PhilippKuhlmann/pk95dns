// Package geo maps IP addresses to countries with the DB-IP "IP to Country Lite" database
// (mmdb, CC BY 4.0, https://db-ip.com), keeps it current (monthly download, like PK95 Proxy)
// and knows the valid country codes. Without a database every lookup is "" and nothing
// is blocked: the feature then simply does nothing.
package geo

import (
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Attribution must be shown wherever the data is used (CC BY 4.0).
const Attribution = "IP-Geolocation by DB-IP (https://db-ip.com)"

// DB is the current database. All methods are safe for concurrent use; a nil *DB or a DB
// without a loaded file answers "" / false.
type DB struct {
	cur atomic.Pointer[reader]
}

type reader struct {
	r    *maxminddb.Reader
	date string // build date of the file, YYYY-MM-DD (UTC)
}

// record is the part of a DB-IP (and GeoLite2) country record we use.
type record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// closeDelay keeps a replaced reader open for lookups that are still running.
var closeDelay = time.Minute

// Load opens path and makes it the current database (the previous one is closed a little
// later). An unreadable or invalid file leaves the current database in place.
func (d *DB) Load(path string) error {
	r, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	if err := r.Verify(); err != nil {
		r.Close()
		return err
	}
	date := ""
	if r.Metadata.BuildEpoch > 0 {
		date = time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC().Format("2006-01-02")
	}
	if old := d.cur.Swap(&reader{r: r, date: date}); old != nil {
		time.AfterFunc(closeDelay, func() { old.r.Close() })
	}
	return nil
}

// Available reports whether a database is loaded.
func (d *DB) Available() bool { return d != nil && d.cur.Load() != nil }

// Date is the build date of the loaded database (YYYY-MM-DD), "" without one.
func (d *DB) Date() string {
	if d == nil {
		return ""
	}
	if r := d.cur.Load(); r != nil {
		return r.date
	}
	return ""
}

// Country returns the upper-case ISO-3166 alpha-2 code (or "EU"/"AP" when the database
// says so) of a public address; "" for non-public addresses, unknown addresses or without
// a database.
func (d *DB) Country(a netip.Addr) string {
	if d == nil || !Public(a) {
		return ""
	}
	r := d.cur.Load()
	if r == nil {
		return ""
	}
	var rec record
	res := r.r.Lookup(a.Unmap())
	if !res.Found() || res.Decode(&rec) != nil {
		return ""
	}
	return strings.ToUpper(rec.Country.ISOCode)
}

// nonPublic are the ranges that never get a country: private, CGNAT, loopback,
// link-local, unique local, documentation, benchmarking, multicast and reserved.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/3"), // multicast, reserved, broadcast
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// Public reports whether a has a place on the public internet (and can have a country).
func Public(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap().WithZone("")
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
