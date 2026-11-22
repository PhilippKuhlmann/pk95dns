package dnsserver

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"

	"pk95dns/internal/geo"
)

// Background lookup of the countries of blocked names (docs/design.md → Countries): a
// query blocked by a list, custom rule or service is answered at once without asking an
// upstream, so its country is unknown. note() counts it right away when the country of the
// name is cached, otherwise queues the name; run() resolves queued names through the normal
// upstreams (and the answer cache), at most bgRate per second, never as a client query, and
// counts every waiting query in the hour it was made.
const (
	bgQueueSize = 1000           // distinct names waiting; more are counted as unknown_blocked
	bgCacheTTL  = 24 * time.Hour // name → country, also "no country"
	bgCacheMax  = 100000         // cache entries before expired ones are swept
	bgRate      = 10             // lookups per second
	bgTimeout   = 5 * time.Second
)

type bgEntry struct {
	code    string
	expires time.Time
}

type blockedGeo struct {
	// resolve returns the country of the first public address of name ("" when none or
	// unknown); record counts a blocked query in the hour of ts (code "" = unknown_blocked).
	resolve func(ctx context.Context, name string) string
	record  func(ts time.Time, code string)
	now     func() time.Time
	every   time.Duration // between lookups

	mu      sync.Mutex
	cache   map[string]bgEntry
	pending map[string]map[int64]int // name → hour (unix seconds) → waiting queries
	queue   chan string
}

func newBlockedGeo(resolve func(context.Context, string) string, record func(time.Time, string), now func() time.Time) *blockedGeo {
	return &blockedGeo{
		resolve: resolve, record: record, now: now, every: time.Second / bgRate,
		cache: map[string]bgEntry{}, pending: map[string]map[int64]int{}, queue: make(chan string, bgQueueSize),
	}
}

// note counts one blocked query for name at ts. enabled false (resolve_blocked off or no
// GeoIP database) counts it as unknown. It returns the cached country (for the query log)
// or "" and never blocks.
func (b *blockedGeo) note(name string, ts time.Time, enabled bool) string {
	if !enabled {
		b.record(ts, "")
		return ""
	}
	hour := ts.Unix() - ((ts.Unix()%3600)+3600)%3600
	b.mu.Lock()
	if e, ok := b.cache[name]; ok && b.now().Before(e.expires) {
		b.mu.Unlock()
		b.record(ts, e.code)
		return e.code
	}
	if p := b.pending[name]; p != nil {
		p[hour]++
		b.mu.Unlock()
		return ""
	}
	select {
	case b.queue <- name:
		b.pending[name] = map[int64]int{hour: 1}
		b.mu.Unlock()
	default:
		b.mu.Unlock()
		b.record(ts, "") // queue full
	}
	return ""
}

// run resolves queued names until ctx is done, one every b.every.
func (b *blockedGeo) run(ctx context.Context) {
	t := time.NewTicker(b.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case name := <-b.queue:
			b.lookup(ctx, name)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// lookup resolves one queued name, caches the result and counts its waiting queries.
func (b *blockedGeo) lookup(ctx context.Context, name string) {
	lctx, cancel := context.WithTimeout(ctx, bgTimeout)
	code := b.resolve(lctx, name)
	cancel()
	if ctx.Err() != nil {
		return
	}
	b.mu.Lock()
	if len(b.cache) >= bgCacheMax {
		now := b.now()
		for k, e := range b.cache {
			if !now.Before(e.expires) {
				delete(b.cache, k)
			}
		}
		if len(b.cache) >= bgCacheMax {
			b.cache = map[string]bgEntry{} // still full: start over rather than grow
		}
	}
	b.cache[name] = bgEntry{code: code, expires: b.now().Add(bgCacheTTL)}
	waiting := b.pending[name]
	delete(b.pending, name)
	b.mu.Unlock()
	for hour, n := range waiting {
		for range n {
			b.record(time.Unix(hour, 0), code)
		}
	}
}

// resolveCountry asks the upstreams (through the answer cache, without filtering, query
// log or statistics) for name and returns the country of the first public A, else AAAA,
// address. No connection to the address itself is ever made.
func (s *Server) resolveCountry(ctx context.Context, name string) string {
	st := s.state.Load()
	if st == nil || !s.deps.Geo.Available() {
		return ""
	}
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(name), qt)
		resp, _, _, err := s.resolveUpstream(ctx, st, req.Question[0], req)
		if err != nil || resp == nil {
			continue
		}
		for _, rr := range resp.Answer {
			if a, ok := rrAddr(rr); ok && geo.Public(a) {
				return s.deps.Geo.Country(a)
			}
		}
	}
	return ""
}

// RunBlockedGeo resolves the countries of blocked names in the background until ctx is
// done (started by the app).
func (s *Server) RunBlockedGeo(ctx context.Context) { s.bgeo.run(ctx) }
