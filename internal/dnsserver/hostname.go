package dnsserver

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	hostTTLOK      = time.Hour
	hostTTLFail    = 10 * time.Minute
	hostMaxEntries = 10000
	hostLookups    = 4 // concurrent background PTR lookups
	hostTimeout    = 5 * time.Second
)

// hostCache caches reverse-DNS names of client addresses.
type hostCache struct {
	mu      sync.Mutex
	entries map[netip.Addr]hostEntry
	pending map[netip.Addr]struct{}
	sem     chan struct{}
	wg      sync.WaitGroup // background lookups (tests wait for them)
}

type hostEntry struct {
	name    string
	expires time.Time
}

func newHostCache() *hostCache {
	return &hostCache{
		entries: map[netip.Addr]hostEntry{},
		pending: map[netip.Addr]struct{}{},
		sem:     make(chan struct{}, hostLookups),
	}
}

// lookup returns the cached name of a and starts a background lookup through resolve when
// there is no valid entry. resolve may be nil (no router yet).
func (h *hostCache) lookup(a netip.Addr, now time.Time, resolve func(ctx context.Context, req *dns.Msg) (*dns.Msg, error)) string {
	if !a.IsValid() {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.entries[a]
	if ok && now.Before(e.expires) {
		return e.name
	}
	if resolve == nil {
		return e.name
	}
	if _, busy := h.pending[a]; busy {
		return e.name
	}
	select {
	case h.sem <- struct{}{}:
	default:
		// All lookup slots are busy; a later call tries again.
		return e.name
	}
	h.pending[a] = struct{}{}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		defer func() { <-h.sem }()
		name, found := ptrLookup(a, resolve)
		h.store(a, name, found, now)
	}()
	return e.name
}

func (h *hostCache) store(a netip.Addr, name string, found bool, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.pending, a)
	ttl := hostTTLOK
	if !found {
		ttl = hostTTLFail
	}
	if _, exists := h.entries[a]; !exists && len(h.entries) >= hostMaxEntries {
		h.evict(now)
	}
	h.entries[a] = hostEntry{name: name, expires: now.Add(ttl)}
}

// evict removes expired entries; when none expired, it removes arbitrary entries until
// there is room for one more. h.mu must be held.
func (h *hostCache) evict(now time.Time) {
	for a, e := range h.entries {
		if !now.Before(e.expires) {
			delete(h.entries, a)
		}
	}
	for a := range h.entries {
		if len(h.entries) < hostMaxEntries {
			break
		}
		delete(h.entries, a)
	}
}

// ptrLookup asks for the PTR record of a. found is false on errors and empty answers.
func ptrLookup(a netip.Addr, resolve func(ctx context.Context, req *dns.Msg) (*dns.Msg, error)) (string, bool) {
	arpa, err := dns.ReverseAddr(a.String())
	if err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), hostTimeout)
	defer cancel()
	req := new(dns.Msg)
	req.SetQuestion(arpa, dns.TypePTR)
	req.RecursionDesired = true
	resp, err := resolve(ctx, req)
	if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
		return "", false
	}
	for _, rr := range resp.Answer {
		if ptr, ok := rr.(*dns.PTR); ok {
			name := strings.TrimSuffix(strings.ToLower(ptr.Ptr), ".")
			if name != "" {
				return name, true
			}
		}
	}
	return "", false
}
