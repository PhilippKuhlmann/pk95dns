package dnsserver

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"pk95dns/internal/config"
	"pk95dns/internal/filter"
	"pk95dns/internal/store"
	"pk95dns/internal/upstream"
)

// localTTL is the TTL of answers from local DNS records.
const localTTL = 60

// maxCNAMEDepth limits CNAME chasing through local records.
const maxCNAMEDepth = 5

// state is the compiled form of a Runtime. Immutable after compile.
type state struct {
	settings config.Settings
	router   *upstream.Router
	rewrites *filter.Rewrites

	allowed    prefixSet
	disallowed prefixSet
	clients    clientMatcher
	global     policy

	blockMode string
	blockIPv4 netip.Addr // custom_ip
	blockIPv6 netip.Addr // custom_ip
	blockTTL  uint32

	upstreamTimeout time.Duration // overall budget of one upstream resolution
}

// policy is the effective filtering configuration of a client.
type policy struct {
	name       string // configured client name ("" for the global policy)
	filtering  bool
	safeSearch config.SafeSearch
	services   []string
}

// prefixSet is a set of IP prefixes (single addresses as /32 or /128).
type prefixSet struct {
	exact    map[netip.Addr]struct{}
	prefixes []netip.Prefix
}

func (p prefixSet) empty() bool { return len(p.exact) == 0 && len(p.prefixes) == 0 }

func (p prefixSet) contains(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if _, ok := p.exact[a]; ok {
		return true
	}
	for _, pr := range p.prefixes {
		if pr.Contains(a) {
			return true
		}
	}
	return false
}

func compilePrefixes(items []string) prefixSet {
	ps := prefixSet{exact: map[netip.Addr]struct{}{}}
	for _, it := range items {
		pr, ok := parsePrefix(it)
		if !ok {
			continue
		}
		if pr.IsSingleIP() {
			ps.exact[pr.Addr()] = struct{}{}
			continue
		}
		ps.prefixes = append(ps.prefixes, pr)
	}
	return ps
}

// parsePrefix parses an IP or CIDR; IPv4-mapped IPv6 addresses are unmapped, the prefix
// is masked.
func parsePrefix(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		a := p.Addr().WithZone("")
		bits := p.Bits()
		if a.Is4In6() {
			if bits < 96 {
				// A mapped prefix shorter than /96 has no IPv4 equivalent; keep it as IPv6.
				return netip.PrefixFrom(a, bits).Masked(), true
			}
			a = a.Unmap()
			bits -= 96
		}
		return netip.PrefixFrom(a, bits).Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), true
}

// clientMatcher finds the most specific configured client for an address.
type clientMatcher struct {
	exact    map[netip.Addr]*policy
	prefixes []clientPrefix // longest prefix first
}

type clientPrefix struct {
	prefix netip.Prefix
	pol    *policy
}

func (m clientMatcher) match(a netip.Addr) (*policy, bool) {
	if !a.IsValid() {
		return nil, false
	}
	if p, ok := m.exact[a]; ok {
		return p, true
	}
	for _, cp := range m.prefixes {
		if cp.prefix.Contains(a) {
			return cp.pol, true
		}
	}
	return nil, false
}

func compileClients(clients []store.Client, global policy) clientMatcher {
	m := clientMatcher{exact: map[netip.Addr]*policy{}}
	for _, c := range clients {
		pol := &policy{name: c.Name}
		if c.UseGlobalSettings {
			pol.filtering = global.filtering
			pol.safeSearch = global.safeSearch
		} else {
			pol.filtering = c.FilteringEnabled
			pol.safeSearch = c.SafeSearch
		}
		if c.UseGlobalServices {
			pol.services = global.services
		} else {
			pol.services = append([]string(nil), c.BlockedServices...)
		}
		for _, id := range c.IDs {
			pr, ok := parsePrefix(id)
			if !ok {
				continue
			}
			if pr.IsSingleIP() {
				if _, dup := m.exact[pr.Addr()]; !dup {
					m.exact[pr.Addr()] = pol
				}
				continue
			}
			m.prefixes = append(m.prefixes, clientPrefix{prefix: pr, pol: pol})
		}
	}
	sort.SliceStable(m.prefixes, func(i, j int) bool {
		return m.prefixes[i].prefix.Bits() > m.prefixes[j].prefix.Bits()
	})
	return m
}

// compile builds the immutable state of a runtime.
func compile(rt Runtime) *state {
	cfg := rt.Settings.Clone()
	st := &state{
		settings:   cfg,
		router:     rt.Router,
		rewrites:   rt.Rewrites,
		allowed:    compilePrefixes(cfg.AllowedClients),
		disallowed: compilePrefixes(cfg.DisallowedClients),
		blockMode:  cfg.BlockingMode,
		blockTTL:   cfg.BlockedTTL,
	}
	st.global = policy{
		filtering:  true,
		safeSearch: cfg.SafeSearch,
		services:   append([]string(nil), cfg.BlockedServices...),
	}
	st.clients = compileClients(rt.Clients, st.global)
	if st.blockMode == "" {
		st.blockMode = config.BlockNullIP
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(cfg.BlockingIPv4)); err == nil && a.Unmap().Is4() {
		st.blockIPv4 = a.Unmap()
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(cfg.BlockingIPv6)); err == nil && a.Is6() && !a.Is4In6() {
		st.blockIPv6 = a.WithZone("")
	}
	t := cfg.UpstreamTimeout()
	if t <= 0 {
		t = 4 * time.Second
	}
	st.upstreamTimeout = 2 * t
	return st
}

// policyFor returns the effective policy of client a.
func (st *state) policyFor(a netip.Addr) policy {
	if p, ok := st.clients.match(a); ok {
		return *p
	}
	return st.global
}

// accessDenied reports whether a may not query.
func (st *state) accessDenied(a netip.Addr) bool {
	if st.disallowed.contains(a) {
		return true
	}
	return !st.allowed.empty() && !st.allowed.contains(a)
}

// addrOf extracts the client address of a net.Addr (UDP/TCP), unmapped and without zone.
func addrOf(addr net.Addr) netip.Addr {
	var ap netip.AddrPort
	switch a := addr.(type) {
	case *net.UDPAddr:
		ap = a.AddrPort()
	case *net.TCPAddr:
		ap = a.AddrPort()
	case nil:
		return netip.Addr{}
	default:
		var err error
		ap, err = netip.ParseAddrPort(addr.String())
		if err != nil {
			ip, perr := netip.ParseAddr(addr.String())
			if perr != nil {
				return netip.Addr{}
			}
			return ip.Unmap().WithZone("")
		}
	}
	return ap.Addr().Unmap().WithZone("")
}

// parseClientIP parses a client IP given as text (Check, Hostname).
func parseClientIP(s string) netip.Addr {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
}
