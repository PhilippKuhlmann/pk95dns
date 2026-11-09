package filter

import "strings"

// NormalizeName lowercases a DNS name and strips the trailing dot.
func NormalizeName(name string) string {
	for i := 0; i < len(name); i++ {
		if c := name[i]; c >= 'A' && c <= 'Z' {
			name = strings.ToLower(name)
			break
		}
	}
	if n := len(name); n > 0 && name[n-1] == '.' {
		name = name[:n-1]
	}
	return name
}

// ValidDomain reports whether name is a valid host name (labels 1–63 chars of a-z0-9-_,
// not starting/ending with "-", total ≤ 253, at least one label; punycode allowed).
// With wildcard true, a leading "*." is accepted.
func ValidDomain(name string, wildcard bool) bool {
	if wildcard && strings.HasPrefix(name, "*.") {
		name = name[2:]
	}
	if name == "" || len(name) > 253 {
		return false
	}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i < len(name) && name[i] != '.' {
			c := name[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
			continue
		}
		label := name[start:i]
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		start = i + 1
	}
	return true
}

// lastLabelNumeric reports whether the last label of name consists of digits only
// (an IPv4 address or an IPv4 prefix like "192.168", never a real host name).
func lastLabelNumeric(name string) bool {
	label := name[strings.LastIndexByte(name, '.')+1:]
	if label == "" {
		return false
	}
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}

// parentDomain returns the parent of name ("a.b.c" → "b.c") and false for a single label.
func parentDomain(name string) (string, bool) {
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return "", false
	}
	return name[i+1:], true
}
