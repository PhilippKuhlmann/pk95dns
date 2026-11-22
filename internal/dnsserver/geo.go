package dnsserver

import (
	"net/netip"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
	"pk95dns/internal/geo"
)

const reasonCountry = "country"

// applyGeo looks at the A/AAAA addresses of an upstream or cache answer (after the CNAME
// chain): it records their countries for the statistics and the query log and, when
// filtering is active, the answer was not explicitly allowed and the geo setting is on,
// removes the addresses in blocked countries. Without any address left the query gets the
// normal blocked answer with status blocked_country; otherwise the remaining addresses
// are answered (status unchanged) and the removed ones are counted. Addresses without a
// country (private, unknown) are never removed. Own zones and records, rewrites and
// SafeSearch never come here, so they have no country.
func (s *Server) applyGeo(st *state, req *dns.Msg, o outcome, filtering bool) outcome {
	g := s.deps.Geo
	if g == nil || !g.Available() || o.resp == nil {
		return o
	}
	enforce := filtering && o.status != statusAllowed && st.geoMode != config.GeoOff && st.geoMode != ""

	var (
		keep      = make([]dns.RR, 0, len(o.resp.Answer))
		addresses int
		kept      int
		public    bool
		first     string // country of the first kept address
		blocked   string // first removed country
	)
	seen := map[string]bool{}
	for _, rr := range o.resp.Answer {
		a, ok := rrAddr(rr)
		if !ok {
			keep = append(keep, rr)
			continue
		}
		addresses++
		if geo.Public(a) {
			public = true
		}
		code := g.Country(a)
		if code != "" && !seen[code] {
			seen[code] = true
			o.countries = append(o.countries, code)
		}
		if enforce && st.geoBlocked(code) {
			if o.removed == nil {
				o.removed = map[string]int{}
			}
			o.removed[code]++
			if blocked == "" {
				blocked = code
			}
			continue
		}
		keep = append(keep, rr)
		kept++
		if first == "" {
			first = code
		}
	}
	o.unknownCountry = public && len(o.countries) == 0
	o.country = first
	if len(o.removed) == 0 {
		return o
	}
	if kept == 0 && addresses > 0 {
		return outcome{
			resp: st.blockedAnswer(req), status: statusBlockedCountry, reason: reasonCountry,
			upstream: o.upstream, cached: o.cached,
			country: blocked, countries: o.countries, unknownCountry: o.unknownCountry,
		}
	}
	resp := o.resp.Copy()
	resp.Answer = keep
	o.resp = resp
	return o
}

func rrAddr(rr dns.RR) (netip.Addr, bool) {
	switch v := rr.(type) {
	case *dns.A:
		return netip.AddrFromSlice(v.A.To4())
	case *dns.AAAA:
		return netip.AddrFromSlice(v.AAAA.To16())
	}
	return netip.Addr{}, false
}
