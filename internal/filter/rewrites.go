package filter

import (
	"slices"
	"strings"
)

// RewriteEntry is one local DNS record: Domain is a host name or "*.example.lan",
// Answer an IPv4/IPv6 address or a host name (CNAME).
type RewriteEntry struct {
	Domain string
	Answer string
}

// Rewrites is an immutable lookup table of local DNS records.
type Rewrites struct {
	exact    map[string][]RewriteEntry // key: host name
	wildcard map[string][]RewriteEntry // key: the domain below "*." ("*.b.lan" → "b.lan")
	n        int
}

// NewRewrites builds the table (only enabled entries are passed in).
func NewRewrites(entries []RewriteEntry) *Rewrites {
	r := &Rewrites{
		exact:    make(map[string][]RewriteEntry),
		wildcard: make(map[string][]RewriteEntry),
	}
	for _, e := range entries {
		domain := NormalizeName(strings.TrimSpace(e.Domain))
		if !ValidDomain(domain, true) {
			continue
		}
		e.Domain = domain
		e.Answer = strings.TrimSpace(e.Answer)
		if rest, ok := strings.CutPrefix(domain, "*."); ok {
			r.wildcard[rest] = append(r.wildcard[rest], e)
		} else {
			r.exact[domain] = append(r.exact[domain], e)
		}
		r.n++
	}
	return r
}

// Lookup returns the entries for name: all exact entries if any, otherwise the entries of
// the most specific matching wildcard ("*.a.b.lan" before "*.b.lan"). nil when none match.
func (r *Rewrites) Lookup(name string) []RewriteEntry {
	if r == nil || r.n == 0 {
		return nil
	}
	name = NormalizeName(name)
	if es, ok := r.exact[name]; ok {
		return slices.Clone(es)
	}
	if len(r.wildcard) == 0 {
		return nil
	}
	// "*.b.lan" matches the proper subdomains of "b.lan" only.
	for p, ok := parentDomain(name); ok; p, ok = parentDomain(p) {
		if es, found := r.wildcard[p]; found {
			return slices.Clone(es)
		}
	}
	return nil
}

// Len is the number of entries.
func (r *Rewrites) Len() int {
	if r == nil {
		return 0
	}
	return r.n
}
