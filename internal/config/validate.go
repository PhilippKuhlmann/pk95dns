package config

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"pk95dns/internal/upstream"
)

// Limits of the settings (docs/api.md → Settings).
const (
	maxUpstreams        = 20
	maxFallback         = 10
	maxBootstrap        = 10
	maxPrivateUpstreams = 10
	maxConditional      = 50
	maxClientEntries    = 200
	minUpstreamTimeout  = 500
	maxUpstreamTimeout  = 30000
	maxCacheSize        = 1000000
	maxCacheMinTTL      = 3600
	maxCacheMaxTTL      = 604800
	maxBlockedTTL       = 86400
	maxRatelimit        = 100000
	maxQuerylogHours    = 2160
	maxStatsDays        = 90
	maxListsUpdateHours = 168
)

// Validate checks every field against the limits in docs/api.md → Settings and returns
// German messages keyed by JSON field name ("upstreams.2", "safesearch.google", "cache_min_ttl").
// An empty map means valid. Upstream addresses are checked with upstream.ParseAddress;
// when encrypted_only is on, upstreams and fallback must be upstream.Encrypted and
// conditional and private upstreams upstream.Encrypted or upstream.LANOnly,
// bootstrap entries must be plain IPs with optional port, client entries IPs or CIDRs,
// conditional domains valid host names.
func (s Settings) Validate() map[string]string {
	v := validator{errs: map[string]string{}}

	// Upstreams. With encrypted_only the public upstreams (main and fallback) must be
	// encrypted; conditional and private upstreams are meant for the LAN and may be plain,
	// but only to a private IP – otherwise queries would leave the LAN unencrypted.
	mainPolicy, lanPolicy := policyAny, policyAny
	if s.EncryptedOnly {
		mainPolicy, lanPolicy = policyEncrypted, policyEncryptedOrLAN
	}
	v.addressList("upstreams", s.Upstreams, 1, maxUpstreams, mainPolicy)
	v.addressList("fallback", s.Fallback, 0, maxFallback, mainPolicy)
	v.addressList("private_upstreams", s.PrivateUpstreams, 0, maxPrivateUpstreams, lanPolicy)
	if v.count("bootstrap", len(s.Bootstrap), 0, maxBootstrap) {
		for i, b := range s.Bootstrap {
			if _, err := upstream.ParseBootstrap(b); err != nil {
				v.set(item("bootstrap", i), err.Error())
			}
		}
	}
	switch s.UpstreamMode {
	case ModeLoadBalance, ModeParallel, ModeSequential:
	default:
		v.set("upstream_mode", "Unbekannter Modus. Erlaubt: load_balance, parallel, sequential.")
	}
	v.intRange("upstream_timeout_ms", s.UpstreamTimeoutMS, minUpstreamTimeout, maxUpstreamTimeout)

	// Conditional forwarding.
	if v.count("conditional", len(s.Conditional), 0, maxConditional) {
		seen := map[string]int{}
		for i, c := range s.Conditional {
			key := item("conditional", i)
			d := strings.TrimSuffix(strings.ToLower(c.Domain), ".")
			switch {
			case c.Domain == "":
				v.set(key+".domain", "Domain fehlt.")
			case !validDomain(d):
				v.set(key+".domain", "Ungültige Domain: "+c.Domain)
			default:
				if first, dup := seen[d]; dup {
					v.set(key+".domain", fmt.Sprintf("Domain ist doppelt (siehe Eintrag %d).", first+1))
				} else {
					seen[d] = i
				}
			}
			if c.Upstream == "" {
				v.set(key+".upstream", "Upstream fehlt.")
			} else {
				v.address(key+".upstream", c.Upstream, lanPolicy)
			}
		}
	}

	// Cache.
	v.intRange("cache_size", s.CacheSize, 0, maxCacheSize)
	v.uintMax("cache_min_ttl", s.CacheMinTTL, maxCacheMinTTL)
	v.uintMax("cache_max_ttl", s.CacheMaxTTL, maxCacheMaxTTL)
	if _, bad := v.errs["cache_min_ttl"]; !bad && s.CacheMaxTTL > 0 && s.CacheMinTTL > s.CacheMaxTTL {
		v.set("cache_min_ttl", "Die minimale TTL darf nicht größer als die maximale TTL sein.")
	}

	// Blocking.
	switch s.BlockingMode {
	case BlockNullIP, BlockNXDomain, BlockRefused, BlockCustomIP:
	default:
		v.set("blocking_mode", "Unbekannter Blockiermodus. Erlaubt: null_ip, nxdomain, refused, custom_ip.")
	}
	if s.BlockingIPv4 != "" {
		if a, err := netip.ParseAddr(s.BlockingIPv4); err != nil || !a.Is4() {
			v.set("blocking_ipv4", "Keine gültige IPv4-Adresse.")
		}
	}
	if s.BlockingIPv6 != "" {
		if a, err := netip.ParseAddr(s.BlockingIPv6); err != nil || !a.Is6() || a.Is4In6() || a.Zone() != "" {
			v.set("blocking_ipv6", "Keine gültige IPv6-Adresse.")
		}
	}
	if s.BlockingMode == BlockCustomIP && s.BlockingIPv4 == "" && s.BlockingIPv6 == "" {
		v.set("blocking_ipv4", "Für eigene IP-Adresse ist eine IPv4- und/oder IPv6-Adresse nötig.")
	}
	v.uintMax("blocked_ttl", s.BlockedTTL, maxBlockedTTL)

	// Access and limits.
	v.intRange("ratelimit", s.Ratelimit, 0, maxRatelimit)
	v.clientList("allowed_clients", s.AllowedClients)
	v.clientList("disallowed_clients", s.DisallowedClients)

	// Query log, statistics, lists.
	v.intRange("querylog_hours", s.QuerylogHours, 1, maxQuerylogHours)
	v.intRange("stats_days", s.StatsDays, 1, maxStatsDays)
	v.intRange("lists_update_hours", s.ListsUpdateHours, 0, maxListsUpdateHours)

	return v.errs
}

type validator struct {
	errs map[string]string
}

func (v *validator) set(key, msg string) {
	if _, exists := v.errs[key]; !exists {
		v.errs[key] = msg
	}
}

func item(field string, i int) string {
	return field + "." + strconv.Itoa(i)
}

// count checks the number of entries of a list and reports whether the items should be
// checked as well.
func (v *validator) count(field string, n, minN, maxN int) bool {
	switch {
	case n < minN && minN == 1:
		v.set(field, "Mindestens ein Eintrag ist nötig.")
		return false
	case n < minN:
		v.set(field, fmt.Sprintf("Mindestens %d Einträge sind nötig.", minN))
		return false
	case n > maxN:
		v.set(field, fmt.Sprintf("Höchstens %d Einträge sind erlaubt.", maxN))
		return false
	}
	return true
}

// msgEncryptedOnly is the error for a plain upstream while encrypted_only is on.
const msgEncryptedOnly = "Nur verschlüsselte Upstreams erlaubt (tls://, https://, h3://, quic://). " +
	"Klartext-DNS ist nur für bedingte Weiterleitung und private PTR-Anfragen vorgesehen."

// msgEncryptedOrLAN is the error for a plain conditional or private upstream with a public
// IP while encrypted_only is on.
const msgEncryptedOrLAN = "Bei „Nur verschlüsselte Upstreams“ ist Klartext-DNS nur zu einer privaten IP-Adresse (LAN) erlaubt. " +
	"Für öffentliche Server tls://, https://, h3:// oder quic:// verwenden."

// addressPolicy says which transports an upstream address may use.
type addressPolicy int

const (
	policyAny            addressPolicy = iota // every valid address
	policyEncrypted                           // encrypted only (encrypted_only: upstreams, fallback)
	policyEncryptedOrLAN                      // encrypted, or plain to a private IP (encrypted_only: conditional, private)
)

func (v *validator) addressList(field string, list []string, minN, maxN int, p addressPolicy) {
	if !v.count(field, len(list), minN, maxN) {
		return
	}
	for i, a := range list {
		v.address(item(field, i), a, p)
	}
}

func (v *validator) address(key, a string, p addressPolicy) {
	if _, err := upstream.ParseAddress(a); err != nil {
		v.set(key, err.Error())
		return
	}
	switch {
	case p == policyEncrypted && !upstream.Encrypted(a):
		v.set(key, msgEncryptedOnly)
	case p == policyEncryptedOrLAN && !upstream.Encrypted(a) && !upstream.LANOnly(a):
		v.set(key, msgEncryptedOrLAN)
	}
}

func (v *validator) clientList(field string, list []string) {
	if !v.count(field, len(list), 0, maxClientEntries) {
		return
	}
	for i, c := range list {
		if !validIPOrCIDR(c) {
			v.set(item(field, i), "Keine gültige IP-Adresse oder kein gültiges Netz (CIDR): "+c)
		}
	}
}

func (v *validator) intRange(field string, n, minN, maxN int) {
	if n < minN || n > maxN {
		v.set(field, fmt.Sprintf("Erlaubt sind Werte von %d bis %d.", minN, maxN))
	}
}

func (v *validator) uintMax(field string, n, maxN uint32) {
	if n > maxN {
		v.set(field, fmt.Sprintf("Erlaubt sind Werte von 0 bis %d.", maxN))
	}
}

// validIPOrCIDR accepts "192.168.1.5", "192.168.1.0/24", "fd00::1", "fd00::/8".
func validIPOrCIDR(s string) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == ""
}

// validDomain checks a lowercase domain name without trailing dot. Labels: 1–63 chars of
// a–z, 0–9, "-" and "_" (not starting or ending with "-"), total at most 253 chars.
// Single-label names ("lan") and reverse zones ("168.192.in-addr.arpa") are allowed.
func validDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}
