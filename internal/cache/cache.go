// Package cache is the DNS answer cache: LRU with a maximum number of entries, TTL taken
// from the answer (min/max clamped), negative caching from the SOA minimum (RFC 2308).
package cache

import (
	"container/list"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Stats of the cache.
type Stats struct {
	Entries int   `json:"entries"`
	Hits    int64 `json:"hits"`
	Misses  int64 `json:"misses"`
}

// Cache is safe for concurrent use.
type Cache struct {
	mu     sync.Mutex
	size   int
	minTTL uint32
	maxTTL uint32
	ll     *list.List // front = most recently used; values are *entry
	items  map[key]*list.Element
	hits   int64
	misses int64
	gen    uint64 // incremented by Flush

	now func() time.Time // replaceable in tests
}

type key struct {
	name   string // lowercase FQDN
	qtype  uint16
	qclass uint16
	do     bool
	cd     bool
}

type entry struct {
	k       key
	msg     *dns.Msg // never modified after storing
	stored  time.Time
	expires time.Time
}

// New creates a cache. size 0 disables storing. maxTTL 0 = no upper limit.
func New(size int, minTTL, maxTTL uint32) *Cache {
	return &Cache{
		size:   max(size, 0),
		minTTL: minTTL,
		maxTTL: maxTTL,
		ll:     list.New(),
		items:  map[key]*list.Element{},
		now:    time.Now,
	}
}

// Configure changes the limits and keeps entries (evicting down to size).
func (c *Cache) Configure(size int, minTTL, maxTTL uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.size = max(size, 0)
	c.minTTL = minTTL
	c.maxTTL = maxTTL
	for c.ll.Len() > c.size {
		c.removeElement(c.ll.Back())
	}
}

// Get returns a copy of the cached answer for req with TTLs reduced by the elapsed time and
// Id/question taken from req, or nil. Key: lowercase name, type, class, DO and CD bits.
func (c *Cache) Get(req *dns.Msg) *dns.Msg {
	k, ok := keyOf(req)
	c.mu.Lock()
	if !ok {
		c.misses++
		c.mu.Unlock()
		return nil
	}
	el, found := c.items[k]
	if !found {
		c.misses++
		c.mu.Unlock()
		return nil
	}
	e := el.Value.(*entry)
	now := c.now()
	if !now.Before(e.expires) {
		c.removeElement(el)
		c.misses++
		c.mu.Unlock()
		return nil
	}
	c.ll.MoveToFront(el)
	c.hits++
	stored, msg := e.stored, e.msg
	c.mu.Unlock()

	// The stored message is never modified, so copying outside the lock is safe.
	elapsed := uint32(now.Sub(stored) / time.Second)
	out := msg.Copy()
	out.Id = req.Id
	origName := ""
	if len(out.Question) > 0 {
		origName = out.Question[0].Name
	}
	out.Question = append([]dns.Question(nil), req.Question...)
	reqName := req.Question[0].Name
	for _, section := range [][]dns.RR{out.Answer, out.Ns, out.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if h.Ttl > elapsed {
				h.Ttl -= elapsed
			} else {
				h.Ttl = 0
			}
			// Answer with the spelling of the request (0x20 randomisation, mixed case).
			if origName != "" && h.Name != reqName && strings.EqualFold(h.Name, origName) {
				h.Name = reqName
			}
		}
	}
	return out
}

// Gen returns the flush generation for SetGen. Read it before the query picks the upstream
// configuration it resolves with.
func (c *Cache) Gen() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// Set stores resp for req. Only NOERROR and NXDOMAIN answers that are not truncated; an
// effective TTL of 0 is not stored.
func (c *Cache) Set(req, resp *dns.Msg) { c.set(req, resp, 0, false) }

// SetGen is Set for an answer of a query that started at generation gen (Gen): it is
// dropped when the cache was flushed since, e.g. because the upstream configuration changed
// while the query was resolved through the old one.
func (c *Cache) SetGen(gen uint64, req, resp *dns.Msg) { c.set(req, resp, gen, true) }

func (c *Cache) set(req, resp *dns.Msg, gen uint64, checkGen bool) {
	if resp == nil || resp.Truncated {
		return
	}
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		return
	}
	k, ok := keyOf(req)
	if !ok || len(resp.Question) != 1 {
		return
	}
	q, rq := req.Question[0], resp.Question[0]
	if q.Qtype != rq.Qtype || q.Qclass != rq.Qclass || !strings.EqualFold(dns.Fqdn(q.Name), dns.Fqdn(rq.Name)) {
		return
	}

	c.mu.Lock()
	size, minTTL, maxTTL := c.size, c.minTTL, c.maxTTL
	c.mu.Unlock()
	if size == 0 {
		return
	}

	ttl, ok := answerTTL(resp)
	if !ok || ttl == 0 {
		return
	}
	ttl = clamp(ttl, minTTL, maxTTL)

	msg := resp.Copy()
	negative := isNegative(resp)
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			if soa, isSOA := rr.(*dns.SOA); negative && isSOA {
				// RFC 2308: the SOA of a negative answer carries the negative TTL.
				h.Ttl = clamp(min(soa.Hdr.Ttl, soa.Minttl), minTTL, maxTTL)
				continue
			}
			h.Ttl = clamp(h.Ttl, minTTL, maxTTL)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.size == 0 || (checkGen && gen != c.gen) {
		return
	}
	now := c.now()
	e := &entry{k: k, msg: msg, stored: now, expires: now.Add(time.Duration(ttl) * time.Second)}
	if el, exists := c.items[k]; exists {
		el.Value = e
		c.ll.MoveToFront(el)
		return
	}
	c.items[k] = c.ll.PushFront(e)
	for c.ll.Len() > c.size {
		c.removeElement(c.ll.Back())
	}
}

// Flush removes all entries (counters stay) and starts a new generation: answers of
// queries that started before are not stored by SetGen.
func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	c.ll.Init()
	c.items = map[key]*list.Element{}
}

// Stats returns the current numbers.
func (c *Cache) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Stats{Entries: c.ll.Len(), Hits: c.hits, Misses: c.misses}
}

func (c *Cache) removeElement(el *list.Element) {
	if el == nil {
		return
	}
	e := c.ll.Remove(el).(*entry)
	delete(c.items, e.k)
}

func keyOf(req *dns.Msg) (key, bool) {
	if req == nil || len(req.Question) != 1 {
		return key{}, false
	}
	q := req.Question[0]
	k := key{
		name:   strings.ToLower(dns.Fqdn(q.Name)),
		qtype:  q.Qtype,
		qclass: q.Qclass,
		cd:     req.CheckingDisabled,
	}
	if opt := req.IsEdns0(); opt != nil {
		k.do = opt.Do()
	}
	return k, true
}

// isNegative reports NXDOMAIN and NODATA (NOERROR without answer records).
func isNegative(resp *dns.Msg) bool {
	return resp.Rcode == dns.RcodeNameError || len(resp.Answer) == 0
}

// answerTTL returns the TTL the answer may be cached for (before clamping): the minimum
// TTL over all records except OPT. In negative answers the SOA counts with
// min(SOA TTL, SOA minimum) (RFC 2308); negative answers without SOA are not cached.
func answerTTL(resp *dns.Msg) (uint32, bool) {
	negative := isNegative(resp)
	var (
		ttl     uint32
		found   bool
		haveSOA bool
	)
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			t := h.Ttl
			if soa, ok := rr.(*dns.SOA); ok && negative {
				t = min(soa.Hdr.Ttl, soa.Minttl)
				haveSOA = true
			}
			if !found || t < ttl {
				ttl = t
				found = true
			}
		}
	}
	if negative && !haveSOA {
		return 0, false
	}
	return ttl, found
}

func clamp(ttl, minTTL, maxTTL uint32) uint32 {
	if ttl < minTTL {
		ttl = minTTL
	}
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl
}
