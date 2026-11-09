package upstream

import (
	"net/netip"
	"strconv"
	"strings"
)

// privateNets are the ranges whose reverse lookups count as private.
var privateNets = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

// IsPrivatePTR reports whether name (lowercase, no trailing dot) lies in the reverse zone of
// a private range: 10/8, 172.16/12, 192.168/16, 100.64/10, 127/8, 169.254/16, fc00::/7,
// fe80::/10, ::1. Names with extra leading labels count too, e.g. the DNS-SD browse names
// "lb._dns-sd._udp.0.1.168.192.in-addr.arpa" (RFC 6763 11) that macOS, iOS and Avahi send:
// the longest numeric suffix below in-addr.arpa / ip6.arpa decides.
func IsPrivatePTR(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	var zone string
	var maxLabels int
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		zone, maxLabels = ".in-addr.arpa", 4
	case strings.HasSuffix(name, ".ip6.arpa"):
		zone, maxLabels = ".ip6.arpa", 32
	default:
		return false
	}
	labels := strings.Split(strings.TrimSuffix(name, zone), ".")
	for start := max(0, len(labels)-maxLabels); start < len(labels); start++ {
		p, ok := reversePrefix(strings.Join(labels[start:], ".") + zone)
		if !ok {
			continue
		}
		for _, n := range privateNets {
			if n.Addr().Is4() == p.Addr().Is4() && p.Bits() >= n.Bits() && n.Contains(p.Addr()) {
				return true
			}
		}
		return false // the longest numeric suffix is public
	}
	return false
}

// reversePrefix turns "1.168.192.in-addr.arpa" into 192.168.1.0/24 and nibble names below
// ip6.arpa into an IPv6 prefix. Partial names give shorter prefixes.
func reversePrefix(name string) (netip.Prefix, bool) {
	switch {
	case strings.HasSuffix(name, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(labels) > 4 {
			return netip.Prefix{}, false
		}
		var b [4]byte
		for i, l := range labels {
			if l == "" || len(l) > 3 {
				return netip.Prefix{}, false
			}
			n, err := strconv.Atoi(l)
			if err != nil || n < 0 || n > 255 || (len(l) > 1 && l[0] == '0') {
				return netip.Prefix{}, false
			}
			b[len(labels)-1-i] = byte(n)
		}
		return netip.PrefixFrom(netip.AddrFrom4(b), 8*len(labels)), true

	case strings.HasSuffix(name, ".ip6.arpa"):
		labels := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
		if len(labels) > 32 {
			return netip.Prefix{}, false
		}
		var b [16]byte
		for i, l := range labels {
			if len(l) != 1 {
				return netip.Prefix{}, false
			}
			v, err := strconv.ParseUint(l, 16, 8)
			if err != nil {
				return netip.Prefix{}, false
			}
			nibble := len(labels) - 1 - i // position from the start of the address
			if nibble%2 == 0 {
				b[nibble/2] |= byte(v) << 4
			} else {
				b[nibble/2] |= byte(v)
			}
		}
		return netip.PrefixFrom(netip.AddrFrom16(b), 4*len(labels)), true
	}
	return netip.Prefix{}, false
}
