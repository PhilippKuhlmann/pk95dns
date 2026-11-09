package config

// Validate checks every field against the limits in docs/api.md → Settings and returns
// German messages keyed by JSON field name ("upstreams.2", "safesearch.google", "cache_min_ttl").
// An empty map means valid. Upstream addresses are checked with upstream.ParseAddress,
// bootstrap entries must be plain IPs with optional port, client entries IPs or CIDRs,
// conditional domains valid host names.
//
// TODO(upstream agent): implement.
func (s Settings) Validate() map[string]string {
	panic("not implemented")
}
