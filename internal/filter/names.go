package filter

// NormalizeName lowercases a DNS name and strips the trailing dot.
func NormalizeName(name string) string {
	panic("not implemented")
}

// ValidDomain reports whether name is a valid host name (labels 1–63 chars of a-z0-9-_,
// not starting/ending with "-", total ≤ 253, at least one label; punycode allowed).
// With wildcard true, a leading "*." is accepted.
func ValidDomain(name string, wildcard bool) bool {
	panic("not implemented")
}
