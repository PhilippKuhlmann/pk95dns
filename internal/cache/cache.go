// Package cache is the DNS answer cache: LRU with a maximum number of entries, TTL taken
// from the answer (min/max clamped), negative caching from the SOA minimum (RFC 2308).
package cache

import "github.com/miekg/dns"

// Stats of the cache.
type Stats struct {
	Entries int   `json:"entries"`
	Hits    int64 `json:"hits"`
	Misses  int64 `json:"misses"`
}

// Cache is safe for concurrent use.
type Cache struct {
	// unexported fields
}

// New creates a cache. size 0 disables storing. maxTTL 0 = no upper limit.
func New(size int, minTTL, maxTTL uint32) *Cache {
	panic("not implemented")
}

// Configure changes the limits and keeps entries (evicting down to size).
func (c *Cache) Configure(size int, minTTL, maxTTL uint32) {
	panic("not implemented")
}

// Get returns a copy of the cached answer for req with TTLs reduced by the elapsed time and
// Id/question taken from req, or nil. Key: lowercase name, type, class, DO and CD bits.
func (c *Cache) Get(req *dns.Msg) *dns.Msg {
	panic("not implemented")
}

// Set stores resp for req. Only NOERROR and NXDOMAIN answers that are not truncated; an
// effective TTL of 0 is not stored.
func (c *Cache) Set(req, resp *dns.Msg) {
	panic("not implemented")
}

// Flush removes all entries (counters stay).
func (c *Cache) Flush() {
	panic("not implemented")
}

// Stats returns the current numbers.
func (c *Cache) Stats() Stats {
	panic("not implemented")
}
