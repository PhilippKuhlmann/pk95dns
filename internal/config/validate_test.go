package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"pk95dns/internal/upstream"
)

func TestDefaultsAreValid(t *testing.T) {
	d := Defaults()
	if errs := d.Validate(); len(errs) != 0 {
		t.Fatalf("defaults invalid: %v", errs)
	}
	if !d.EncryptedOnly {
		t.Fatal("encrypted_only must be on by default")
	}
	// Fallback by IP: usable without bootstrap.
	for _, f := range d.Fallback {
		spec, err := upstream.ParseAddress(f)
		if err != nil || !spec.Encrypted() {
			t.Fatalf("fallback %q: %+v %v", f, spec, err)
		}
		if _, err := netip.ParseAddr(spec.Host); err != nil {
			t.Fatalf("fallback %q needs bootstrap (host name)", f)
		}
	}
}

func TestEncryptedOnlyJSON(t *testing.T) {
	s, err := Merge(Defaults(), []byte(`{"encrypted_only": false, "upstreams": ["9.9.9.9"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.EncryptedOnly || len(s.Validate()) != 0 {
		t.Fatalf("encrypted_only=%v errs=%v", s.EncryptedOnly, s.Validate())
	}
	// Switching it on again with plain upstreams is rejected.
	s, err = Merge(s, []byte(`{"encrypted_only": true}`))
	if err != nil {
		t.Fatal(err)
	}
	if errs := s.Validate(); errs["upstreams.0"] == "" {
		t.Fatalf("errs = %v", errs)
	}
	b, _ := json.Marshal(Defaults())
	if !strings.Contains(string(b), `"encrypted_only":true`) {
		t.Fatalf("JSON: %s", b)
	}
}

func strs(n int, f func(i int) string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name   string
		modify func(s *Settings)
		want   map[string]string // field → substring of the message; nil = valid
	}{
		// Upstreams.
		{"all address forms", func(s *Settings) {
			s.EncryptedOnly = false
			s.Upstreams = []string{"9.9.9.9", "9.9.9.9:53", "[2620:fe::fe]:53", "udp://1.1.1.1", "tcp://1.1.1.1", "tls://dns.quad9.net", "tls://dns.quad9.net:853", "https://dns.quad9.net/dns-query", "h3://dns.quad9.net/dns-query", "quic://dns.adguard-dns.com", "quic://94.140.14.14:784"}
			s.Fallback = []string{"9.9.9.9", "tcp://1.1.1.1"}
		}, nil},
		{"encrypted forms with encrypted_only", func(s *Settings) {
			s.Upstreams = []string{"tls://dns.quad9.net", "tls://1.1.1.1:853", "https://dns.quad9.net/dns-query", "H3://cloudflare-dns.com/dns-query", "quic://dns.adguard-dns.com", "quic://[2a10:50c0::ad1:ff]"}
			s.Fallback = []string{"tls://9.9.9.9", "quic://94.140.14.14"}
		}, nil},
		{"encrypted_only rejects plain", func(s *Settings) {
			s.Upstreams = []string{"https://dns.quad9.net/dns-query", "9.9.9.9", "tcp://1.1.1.1", "udp://1.1.1.1"}
			s.Fallback = []string{"1.1.1.1", "tls://1.1.1.1"}
		}, map[string]string{
			"upstreams.1": "Nur verschlüsselte Upstreams erlaubt (tls://, https://, h3://, quic://)",
			"upstreams.2": "Nur verschlüsselte Upstreams",
			"upstreams.3": "Nur verschlüsselte Upstreams",
			"fallback.0":  "Klartext-DNS ist nur für bedingte Weiterleitung",
		}},
		{"encrypted_only keeps LAN upstreams plain", func(s *Settings) {
			s.PrivateUpstreams = []string{"192.168.178.1", "tcp://10.0.0.1"}
			s.Conditional = []Conditional{{Domain: "fritz.box", Upstream: "192.168.178.1"}}
		}, nil},
		{"encrypted_only keeps every private range plain", func(s *Settings) {
			s.PrivateUpstreams = []string{"10.1.2.3", "172.16.0.1:5353", "100.64.0.1", "127.0.0.1", "169.254.1.1", "[fd00::1]:53", "udp://fe80::1%eth0", "::1"}
			s.Conditional = []Conditional{{Domain: "lan", Upstream: "tcp://[fd12::53]:5353"}, {Domain: "corp.example", Upstream: "tls://dns.corp.example"}}
		}, nil},
		{"encrypted_only rejects public plain conditional and private upstreams", func(s *Settings) {
			s.Conditional = []Conditional{
				{Domain: "com", Upstream: "8.8.8.8"},
				{Domain: "net", Upstream: "udp://1.1.1.1"},
				{Domain: "org", Upstream: "tcp://[2620:fe::fe]:53"},
				{Domain: "fritz.box", Upstream: "192.168.178.1"},
				{Domain: "example", Upstream: "100.128.0.1"}, // just outside 100.64/10
			}
			s.PrivateUpstreams = []string{"8.8.4.4", "192.168.1.1", "https://dns.quad9.net/dns-query", "::ffff:8.8.8.8"}
		}, map[string]string{
			"conditional.0.upstream": "nur zu einer privaten IP-Adresse (LAN) erlaubt",
			"conditional.1.upstream": "privaten IP-Adresse",
			"conditional.2.upstream": "privaten IP-Adresse",
			"conditional.4.upstream": "privaten IP-Adresse",
			"private_upstreams.0":    "privaten IP-Adresse",
			"private_upstreams.3":    "privaten IP-Adresse",
		}},
		{"encrypted_only off allows public plain conditional", func(s *Settings) {
			s.EncryptedOnly = false
			s.Conditional = []Conditional{{Domain: "com", Upstream: "8.8.8.8"}}
			s.PrivateUpstreams = []string{"8.8.4.4"}
		}, nil},
		{"encrypted_only parse error wins", func(s *Settings) {
			s.Upstreams = []string{"dns.google"}
		}, map[string]string{"upstreams.0": "IP-Adresse nötig"}},
		{"encrypted_only off allows plain", func(s *Settings) {
			s.EncryptedOnly = false
			s.Upstreams = []string{"9.9.9.9"}
			s.Fallback = []string{"1.1.1.1"}
		}, nil},
		{"no upstreams", func(s *Settings) { s.Upstreams = nil }, map[string]string{"upstreams": "Mindestens ein Eintrag"}},
		{"21 upstreams", func(s *Settings) {
			s.Upstreams = strs(21, func(i int) string { return fmt.Sprintf("tls://10.0.0.%d", i+1) })
		}, map[string]string{"upstreams": "Höchstens 20"}},
		{"20 upstreams ok", func(s *Settings) {
			s.Upstreams = strs(20, func(i int) string { return fmt.Sprintf("tls://10.0.0.%d", i+1) })
		}, nil},
		{"bad upstream items", func(s *Settings) { s.Upstreams = []string{"tls://9.9.9.9", "dns.google", "sdns://x"} }, map[string]string{
			"upstreams.1": "IP-Adresse nötig", "upstreams.2": "Unbekanntes Protokoll"}},
		{"bad fallback", func(s *Settings) { s.Fallback = []string{"https://1.1.1.1/dns-query", "nope"} }, map[string]string{"fallback.1": "IP-Adresse"}},
		{"11 fallback", func(s *Settings) { s.Fallback = strs(11, func(i int) string { return "1.1.1.1" }) }, map[string]string{"fallback": "Höchstens 10"}},
		{"empty fallback ok", func(s *Settings) { s.Fallback = nil }, nil},
		{"bootstrap host name", func(s *Settings) { s.Bootstrap = []string{"9.9.9.9", "dns.google", "tls://1.1.1.1", "1.1.1.1:5353"} }, map[string]string{
			"bootstrap.1": "IP-Adressen", "bootstrap.2": "IP-Adressen"}},
		{"11 bootstrap", func(s *Settings) { s.Bootstrap = strs(11, func(i int) string { return "1.1.1.1" }) }, map[string]string{"bootstrap": "Höchstens 10"}},
		{"bad private upstream", func(s *Settings) { s.PrivateUpstreams = []string{"fritz.box"} }, map[string]string{"private_upstreams.0": "IP-Adresse"}},
		{"11 private upstreams", func(s *Settings) { s.PrivateUpstreams = strs(11, func(i int) string { return "192.168.1.1" }) }, map[string]string{"private_upstreams": "Höchstens 10"}},
		{"mode", func(s *Settings) { s.UpstreamMode = "fastest" }, map[string]string{"upstream_mode": "Unbekannter Modus"}},
		{"empty mode", func(s *Settings) { s.UpstreamMode = "" }, map[string]string{"upstream_mode": "Unbekannter Modus"}},
		{"modes ok", func(s *Settings) { s.UpstreamMode = ModeParallel }, nil},
		{"timeout low", func(s *Settings) { s.UpstreamTimeoutMS = 499 }, map[string]string{"upstream_timeout_ms": "500 bis 30000"}},
		{"timeout high", func(s *Settings) { s.UpstreamTimeoutMS = 30001 }, map[string]string{"upstream_timeout_ms": "500 bis 30000"}},
		{"timeout bounds", func(s *Settings) { s.UpstreamTimeoutMS = 500 }, nil},

		// Conditional forwarding.
		{"conditional ok", func(s *Settings) {
			s.Conditional = []Conditional{
				{Domain: "fritz.box", Upstream: "192.168.178.1"},
				{Domain: "168.192.in-addr.arpa", Upstream: "192.168.178.1"},
				{Domain: "lan.", Upstream: "tcp://10.0.0.1:5353"},
				{Domain: "_srv.example", Upstream: "tls://dns.example"},
			}
		}, nil},
		{"conditional errors", func(s *Settings) {
			s.Conditional = []Conditional{
				{Domain: "", Upstream: ""},
				{Domain: "bad domain", Upstream: "router.lan"},
				{Domain: "Fritz.Box", Upstream: "192.168.178.1"},
				{Domain: "fritz.box.", Upstream: "192.168.178.2"},
				{Domain: "-x.lan", Upstream: "192.168.178.1"},
				{Domain: "a..b", Upstream: "192.168.178.1"},
			}
		}, map[string]string{
			"conditional.0.domain":   "Domain fehlt",
			"conditional.0.upstream": "Upstream fehlt",
			"conditional.1.domain":   "Ungültige Domain",
			"conditional.1.upstream": "IP-Adresse",
			"conditional.3.domain":   "doppelt (siehe Eintrag 3)",
			"conditional.4.domain":   "Ungültige Domain",
			"conditional.5.domain":   "Ungültige Domain",
		}},
		{"long label", func(s *Settings) {
			s.Conditional = []Conditional{{Domain: strings.Repeat("a", 64) + ".lan", Upstream: "10.0.0.1"}}
		}, map[string]string{"conditional.0.domain": "Ungültige Domain"}},
		{"long name", func(s *Settings) {
			s.Conditional = []Conditional{{Domain: strings.Repeat("abcdefghi.", 26) + "lan", Upstream: "10.0.0.1"}}
		}, map[string]string{"conditional.0.domain": "Ungültige Domain"}},
		{"51 conditional", func(s *Settings) {
			for i := range 51 {
				s.Conditional = append(s.Conditional, Conditional{Domain: fmt.Sprintf("d%d.lan", i), Upstream: "10.0.0.1"})
			}
		}, map[string]string{"conditional": "Höchstens 50"}},

		// Cache.
		{"cache size negative", func(s *Settings) { s.CacheSize = -1 }, map[string]string{"cache_size": "0 bis 1000000"}},
		{"cache size too big", func(s *Settings) { s.CacheSize = 1000001 }, map[string]string{"cache_size": "0 bis 1000000"}},
		{"cache size 0 ok", func(s *Settings) { s.CacheSize = 0 }, nil},
		{"min ttl too big", func(s *Settings) { s.CacheMinTTL = 3601; s.CacheMaxTTL = 0 }, map[string]string{"cache_min_ttl": "0 bis 3600"}},
		{"max ttl too big", func(s *Settings) { s.CacheMaxTTL = 604801 }, map[string]string{"cache_max_ttl": "0 bis 604800"}},
		{"min > max", func(s *Settings) { s.CacheMinTTL = 600; s.CacheMaxTTL = 300 }, map[string]string{"cache_min_ttl": "nicht größer"}},
		{"min = max ok", func(s *Settings) { s.CacheMinTTL = 300; s.CacheMaxTTL = 300 }, nil},
		{"min with unlimited max ok", func(s *Settings) { s.CacheMinTTL = 3600; s.CacheMaxTTL = 0 }, nil},

		// Blocking.
		{"blocking mode", func(s *Settings) { s.BlockingMode = "block" }, map[string]string{"blocking_mode": "Unbekannter Blockiermodus"}},
		{"custom ip without address", func(s *Settings) { s.BlockingMode = BlockCustomIP }, map[string]string{"blocking_ipv4": "IPv4- und/oder IPv6"}},
		{"custom ip v4 only", func(s *Settings) { s.BlockingMode = BlockCustomIP; s.BlockingIPv4 = "192.168.1.250" }, nil},
		{"custom ip v6 only", func(s *Settings) { s.BlockingMode = BlockCustomIP; s.BlockingIPv6 = "fd00::250" }, nil},
		{"ipv4 field with v6", func(s *Settings) { s.BlockingIPv4 = "::1" }, map[string]string{"blocking_ipv4": "IPv4"}},
		{"ipv4 field garbage", func(s *Settings) { s.BlockingIPv4 = "1.2.3" }, map[string]string{"blocking_ipv4": "IPv4"}},
		{"ipv6 field with v4", func(s *Settings) { s.BlockingIPv6 = "1.2.3.4" }, map[string]string{"blocking_ipv6": "IPv6"}},
		{"ipv6 field mapped v4", func(s *Settings) { s.BlockingIPv6 = "::ffff:1.2.3.4" }, map[string]string{"blocking_ipv6": "IPv6"}},
		{"blocked ttl", func(s *Settings) { s.BlockedTTL = 86401 }, map[string]string{"blocked_ttl": "0 bis 86400"}},

		// Access.
		{"ratelimit negative", func(s *Settings) { s.Ratelimit = -1 }, map[string]string{"ratelimit": "0 bis 100000"}},
		{"ratelimit high", func(s *Settings) { s.Ratelimit = 100001 }, map[string]string{"ratelimit": "0 bis 100000"}},
		{"ratelimit off ok", func(s *Settings) { s.Ratelimit = 0 }, nil},
		{"clients", func(s *Settings) {
			s.AllowedClients = []string{"192.168.1.5", "10.0.0.0/8", "fd00::/8", "::1", "10.0.0.0/33", "host.lan", ""}
			s.DisallowedClients = []string{"1.2.3.4/32", "fe80::1%eth0"}
		}, map[string]string{
			"allowed_clients.4":    "CIDR",
			"allowed_clients.5":    "CIDR",
			"allowed_clients.6":    "CIDR",
			"disallowed_clients.1": "CIDR",
		}},
		{"empty allowed ok", func(s *Settings) { s.AllowedClients = nil }, nil},
		{"201 allowed", func(s *Settings) { s.AllowedClients = strs(201, func(i int) string { return "10.0.0.1" }) }, map[string]string{"allowed_clients": "Höchstens 200"}},
		{"201 disallowed", func(s *Settings) { s.DisallowedClients = strs(201, func(i int) string { return "10.0.0.1" }) }, map[string]string{"disallowed_clients": "Höchstens 200"}},

		// Log, stats, lists.
		{"querylog 0", func(s *Settings) { s.QuerylogHours = 0 }, map[string]string{"querylog_hours": "1 bis 2160"}},
		{"querylog high", func(s *Settings) { s.QuerylogHours = 2161 }, map[string]string{"querylog_hours": "1 bis 2160"}},
		{"stats 0", func(s *Settings) { s.StatsDays = 0 }, map[string]string{"stats_days": "1 bis 90"}},
		{"stats high", func(s *Settings) { s.StatsDays = 91 }, map[string]string{"stats_days": "1 bis 90"}},
		{"lists negative", func(s *Settings) { s.ListsUpdateHours = -1 }, map[string]string{"lists_update_hours": "0 bis 168"}},
		{"lists high", func(s *Settings) { s.ListsUpdateHours = 169 }, map[string]string{"lists_update_hours": "0 bis 168"}},
		{"lists off ok", func(s *Settings) { s.ListsUpdateHours = 0 }, nil},
		{"upper bounds ok", func(s *Settings) {
			s.UpstreamTimeoutMS = 30000
			s.CacheSize = 1000000
			s.CacheMinTTL = 3600
			s.CacheMaxTTL = 604800
			s.BlockedTTL = 86400
			s.Ratelimit = 100000
			s.QuerylogHours = 2160
			s.StatsDays = 90
			s.ListsUpdateHours = 168
		}, nil},

		// Several errors at once.
		{"many", func(s *Settings) {
			s.Upstreams = []string{"x"}
			s.UpstreamMode = "x"
			s.StatsDays = 0
		}, map[string]string{"upstreams.0": "", "upstream_mode": "", "stats_days": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Defaults()
			tt.modify(&s)
			got := s.Validate()
			if got == nil {
				t.Fatal("Validate returned nil map")
			}
			if len(got) != len(tt.want) {
				t.Fatalf("errors = %v, want keys %v", got, tt.want)
			}
			for field, sub := range tt.want {
				msg, ok := got[field]
				if !ok {
					t.Fatalf("missing error for %q, got %v", field, got)
				}
				if !strings.Contains(msg, sub) {
					t.Fatalf("%s: %q does not contain %q", field, msg, sub)
				}
			}
		})
	}
}

// A conditional entry sent with PUT replaces the old one: keys missing in it are not taken
// from the entry that was at the same index before.
func TestMergeReplacesConditional(t *testing.T) {
	base := Defaults()
	base.Conditional = []Conditional{{Domain: "fritz.box", Upstream: "192.168.178.1"}}
	s, err := Merge(base, []byte(`{"conditional":[{"domain":"other.lan"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Conditional) != 1 || s.Conditional[0] != (Conditional{Domain: "other.lan"}) {
		t.Fatalf("conditional = %+v", s.Conditional)
	}
	if errs := s.Validate(); errs["conditional.0.upstream"] == "" {
		t.Fatalf("missing upstream accepted: %v", errs)
	}
	if base.Conditional[0].Upstream != "192.168.178.1" {
		t.Fatal("base modified")
	}
	// Without the key the entries stay; null clears them.
	if s, _ := Merge(base, []byte(`{"ratelimit":3}`)); len(s.Conditional) != 1 || s.Conditional[0].Domain != "fritz.box" {
		t.Fatalf("conditional lost: %+v", s.Conditional)
	}
	if s, _ := Merge(base, []byte(`{"conditional":null}`)); s.Conditional == nil || len(s.Conditional) != 0 {
		t.Fatalf("null: %+v", s.Conditional)
	}
}
