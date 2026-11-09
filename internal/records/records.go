// Package records holds the authoritative zones and DNS records of PK95 DNS (docs/api.md →
// DNS zones and records, docs/design.md → Local zones and records): the Zone and Record
// types shared with the store and the API, their normalisation and validation
// (ValidateZone, ValidateRecord), and the compiled lookup Index the DNS server answers from.
//
// Wiring overview:
//
//   - API: decode the body into a Zone/Record, call ValidateZone/ValidateRecord with the
//     current zones and records from the store (they normalise in place and set
//     Record.ZoneID), write 422 with the returned fields, then call the store.
//   - App: after every change load store.Zones() and store.Records(store.RecordFilter{}),
//     build Compile(zones, recs) and swap the *Index atomically into the DNS server.
//   - DNS server (pipeline step 5): res := ix.Resolve(qname, qtype); !res.Found → continue
//     with filtering; otherwise answer from res (see Result) with status "rewrite" and
//     reason res.Reason.
package records

import (
	"net/netip"
	"strings"
	"time"

	"pk95dns/internal/filter"
)

// Record types.
const (
	TypeA     = "A"
	TypeAAAA  = "AAAA"
	TypeCNAME = "CNAME"
	TypeMX    = "MX"
	TypeTXT   = "TXT"
	TypeSRV   = "SRV"
	TypePTR   = "PTR"
)

// Types are the supported record types in display order.
var Types = []string{TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeTXT, TypeSRV, TypePTR}

// Limits and defaults (docs/api.md).
const (
	DefaultTTL    = 300    // zone and record TTL when the request does not name one
	MaxTTL        = 604800 // seconds (7 days)
	MaxRecords    = 50000  // records in total
	MaxTXTLength  = 4000   // characters of a TXT value
	MaxCNAMEDepth = 5      // CNAME hops followed for one query (local and upstream together)
	RewriteTTL    = 60     // TTL of records created through /api/rewrites and by the v1 migration
)

// ManagedByCore marks records PK95 Core created for deployed apps.
const ManagedByCore = "core"

// Query log reasons of local answers (docs/api.md → status vocabulary, status "rewrite").
const (
	ReasonZone   = "zone"   // answer of an authoritative zone (also NXDOMAIN/NODATA)
	ReasonRecord = "record" // single record without zone
)

// Zone is an authoritative zone. RecordCount is not stored: the store computes it when
// listing zones (records with this zone id, enabled or not).
type Zone struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	TTL         uint32 `json:"ttl"`
	PrimaryNS   string `json:"primary_ns"`
	Enabled     bool   `json:"enabled"`
	Serial      uint32 `json:"serial"`
	RecordCount int    `json:"record_count"`
	CreatedAt   int64  `json:"created_at"`
}

// Record is one DNS record. ZoneID is derived from Name (ZoneFor, 0 = single record).
// Priority (MX, SRV), Weight and Port (SRV) and PTR (A, AAAA) are 0/false for other types.
type Record struct {
	ID        int64  `json:"id"`
	ZoneID    int64  `json:"zone_id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	TTL       uint32 `json:"ttl"`
	Priority  uint16 `json:"priority"`
	Weight    uint16 `json:"weight"`
	Port      uint16 `json:"port"`
	PTR       bool   `json:"ptr"`
	Enabled   bool   `json:"enabled"`
	ManagedBy string `json:"managed_by"`
	CreatedAt int64  `json:"created_at"`
}

// NormalizeName lowercases a DNS name, trims spaces and strips the trailing dot.
func NormalizeName(name string) string {
	return filter.NormalizeName(strings.TrimSpace(name))
}

// InZone reports whether name (normalised) is zone or a name below it.
func InZone(name, zone string) bool {
	if zone == "" {
		return false
	}
	return name == zone || (len(name) > len(zone) && strings.HasSuffix(name, zone) && name[len(name)-len(zone)-1] == '.')
}

// ZoneFor returns the id of the longest zone that contains name (the zone apex or a name
// below it; a wildcard "*.x" belongs to the zone of its labels), 0 when no zone does. All
// zones count, disabled ones too: membership does not depend on enabled.
func ZoneFor(name string, zones []Zone) int64 {
	name = NormalizeName(name)
	var best int64
	bestLen := -1
	for _, z := range zones {
		zn := NormalizeName(z.Name)
		if len(zn) > bestLen && InZone(name, zn) {
			best, bestLen = z.ID, len(zn)
		}
	}
	return best
}

// TypeForAnswer maps the answer of a v1 rewrite (/api/rewrites) to a record type: IPv4
// address → A, IPv6 address → AAAA, anything else (host name) → CNAME.
func TypeForAnswer(answer string) string {
	ip, err := netip.ParseAddr(strings.TrimSpace(answer))
	switch {
	case err != nil:
		return TypeCNAME
	case ip.Is4() || ip.Is4In6():
		return TypeA
	default:
		return TypeAAAA
	}
}

// IsRewriteType reports whether records of type t are visible through /api/rewrites
// (A, AAAA, CNAME).
func IsRewriteType(t string) bool {
	return t == TypeA || t == TypeAAAA || t == TypeCNAME
}

// RewriteFields maps validation fields of a record to the field names of /api/rewrites:
// name → domain, value and type → answer; other keys stay. The first message per target
// key wins (name before others, value before type).
func RewriteFields(fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return fields
	}
	out := make(map[string]string, len(fields))
	for _, k := range []string{"name", "value", "type"} {
		msg, ok := fields[k]
		if !ok {
			continue
		}
		key := "answer"
		if k == "name" {
			key = "domain"
		}
		if _, taken := out[key]; !taken {
			out[key] = msg
		}
	}
	for k, msg := range fields {
		switch k {
		case "name", "value", "type":
		default:
			out[k] = msg
		}
	}
	return out
}

// NextSerial returns the zone serial after a change at now: YYYYMMDDnn (date in now's
// location). Within the same day nn counts up from 01; a new day starts again at 01. The
// serial never decreases (more than 99 changes a day or a clock going back keep counting up
// from old).
func NextSerial(old uint32, now time.Time) uint32 {
	y, m, d := now.Date()
	base := uint32(y*10000+int(m)*100+d) * 100
	if old >= base {
		return old + 1
	}
	return base + 1
}
