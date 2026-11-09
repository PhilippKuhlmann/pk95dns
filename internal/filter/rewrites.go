package filter

// RewriteEntry is one local DNS record: Domain is a host name or "*.example.lan",
// Answer an IPv4/IPv6 address or a host name (CNAME).
type RewriteEntry struct {
	Domain string
	Answer string
}

// Rewrites is an immutable lookup table of local DNS records.
type Rewrites struct {
	// unexported fields
}

// NewRewrites builds the table (only enabled entries are passed in).
func NewRewrites(entries []RewriteEntry) *Rewrites {
	panic("not implemented")
}

// Lookup returns the entries for name: all exact entries if any, otherwise the entries of
// the most specific matching wildcard ("*.a.b.lan" before "*.b.lan"). nil when none match.
func (r *Rewrites) Lookup(name string) []RewriteEntry {
	panic("not implemented")
}

// Len is the number of entries.
func (r *Rewrites) Len() int {
	panic("not implemented")
}
