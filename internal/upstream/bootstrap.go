package upstream

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// bootstrapMinTTL is the minimum time a resolved host name is cached.
	bootstrapMinTTL = 60 * time.Second
	// bootstrapMaxTTL caps the cache time. Bootstrap answers come over plain DNS: a forged
	// answer with a huge TTL must not pin an upstream to a wrong address for long.
	bootstrapMaxTTL = time.Hour
	// bootstrapSystemTTL is used for answers of the system resolver (no TTL available).
	bootstrapSystemTTL = 5 * time.Minute
)

// resolver resolves the host names of DoT/DoH upstreams through the bootstrap servers
// (or the system resolver when there are none) and caches the addresses.
type resolver struct {
	servers []string // "ip:port"
	timeout time.Duration

	mu    sync.Mutex
	cache map[string]resolved

	// lookupSystem is replaceable in tests.
	lookupSystem func(ctx context.Context, host string) ([]netip.Addr, error)
	now          func() time.Time
}

type resolved struct {
	addrs   []netip.Addr
	expires time.Time
}

func newResolver(bootstrap []string, timeout time.Duration) (*resolver, error) {
	r := &resolver{
		timeout: timeout,
		cache:   map[string]resolved{},
		lookupSystem: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		now: time.Now,
	}
	for _, b := range bootstrap {
		addr, err := ParseBootstrap(b)
		if err != nil {
			return nil, err
		}
		r.servers = append(r.servers, addr)
	}
	return r, nil
}

// lookup returns the addresses of host (IPv4 first). IP literals are returned as they are.
func (r *resolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	r.mu.Lock()
	if e, ok := r.cache[host]; ok && r.now().Before(e.expires) {
		r.mu.Unlock()
		return e.addrs, nil
	}
	r.mu.Unlock()

	var (
		addrs []netip.Addr
		ttl   time.Duration
		err   error
	)
	if len(r.servers) == 0 {
		addrs, err = r.lookupSystem(ctx, host)
		ttl = bootstrapSystemTTL
		addrs = sortV4First(addrs)
	} else {
		addrs, ttl, err = r.lookupBootstrap(ctx, host)
	}
	if err != nil {
		return nil, &upstreamError{msg: "Hostname " + host + " konnte nicht aufgelöst werden: " + germanError(err).Error(), err: err}
	}
	if len(addrs) == 0 {
		return nil, errorf("Hostname %s konnte nicht aufgelöst werden: keine Adressen", host)
	}
	ttl = min(max(ttl, bootstrapMinTTL), bootstrapMaxTTL)
	r.mu.Lock()
	r.cache[host] = resolved{addrs: addrs, expires: r.now().Add(ttl)}
	r.mu.Unlock()
	return addrs, nil
}

func sortV4First(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		if a.Unmap().Is4() {
			out = append(out, a.Unmap())
		}
	}
	for _, a := range in {
		if !a.Unmap().Is4() {
			out = append(out, a)
		}
	}
	return out
}

// lookupBootstrap asks the bootstrap servers in order for A and AAAA records.
func (r *resolver) lookupBootstrap(ctx context.Context, host string) ([]netip.Addr, time.Duration, error) {
	var lastErr error
	for _, server := range r.servers {
		addrs, ttl, err := r.queryServer(ctx, server, host)
		if err == nil && len(addrs) > 0 {
			return addrs, ttl, nil
		}
		if err == nil {
			err = errors.New("keine Adressen")
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, 0, lastErr
}

func (r *resolver) queryServer(ctx context.Context, server, host string) ([]netip.Addr, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	type result struct {
		addrs []netip.Addr
		ttl   uint32
		err   error
	}
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	results := make([]result, len(qtypes))
	var wg sync.WaitGroup
	for i, qt := range qtypes {
		wg.Go(func() {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(host), qt)
			m.RecursionDesired = true
			resp, err := exchangePlain(ctx, m, server, false)
			if err != nil {
				results[i].err = err
				return
			}
			if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
				results[i].err = errBadRcode(resp.Rcode)
				return
			}
			ttl := uint32(0)
			for _, rr := range resp.Answer {
				var a netip.Addr
				switch v := rr.(type) {
				case *dns.A:
					a, _ = netip.AddrFromSlice(v.A.To4())
				case *dns.AAAA:
					a, _ = netip.AddrFromSlice(v.AAAA.To16())
				default:
					continue
				}
				if !a.IsValid() {
					continue
				}
				if ttl == 0 || rr.Header().Ttl < ttl {
					ttl = rr.Header().Ttl
				}
				results[i].addrs = append(results[i].addrs, a)
			}
			results[i].ttl = ttl
		})
	}
	wg.Wait()

	var (
		addrs  []netip.Addr
		minTTL uint32
		errs   []error
	)
	for _, res := range results {
		if res.err != nil {
			errs = append(errs, res.err)
			continue
		}
		if len(res.addrs) > 0 && (minTTL == 0 || res.ttl < minTTL) {
			minTTL = res.ttl
		}
		addrs = append(addrs, res.addrs...)
	}
	if len(addrs) == 0 && len(errs) > 0 {
		return nil, 0, errs[0]
	}
	return addrs, time.Duration(minTTL) * time.Second, nil
}

// invalidate drops the cached addresses of host after a connection to every one of them
// failed, so the next query resolves the name again (a server moved, or a forged bootstrap
// answer). A dial that was cancelled says nothing about the addresses and keeps them.
// Only the entry that held addrs is dropped, not a newer one stored in the meantime.
func (r *resolver) invalidate(ctx context.Context, host string, addrs []netip.Addr, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.cache[host]; ok && slices.Equal(e.addrs, addrs) {
		delete(r.cache, host)
	}
}

// shareContext limits one of several attempts to a fair share of the time left before the
// deadline of ctx (left attempts remain, this one included), so an address or upstream that
// silently drops packets cannot use up the whole deadline and keep the remaining ones from
// being tried. The last attempt gets all that is left; without a deadline ctx is returned.
func shareContext(ctx context.Context, left int) (context.Context, context.CancelFunc) {
	if left > 1 {
		if dl, ok := ctx.Deadline(); ok {
			return context.WithTimeout(ctx, time.Until(dl)/time.Duration(left))
		}
	}
	return ctx, func() {}
}

// dial connects to host:port over TCP, trying every resolved address in order. Each address
// gets a fair share of the remaining time (shareContext).
func (r *resolver) dial(ctx context.Context, host, port string) (net.Conn, error) {
	addrs, err := r.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	var lastErr error
	for i, a := range addrs {
		actx, cancel := shareContext(ctx, len(addrs)-i)
		conn, err := d.DialContext(actx, "tcp", net.JoinHostPort(a.String(), port))
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	r.invalidate(ctx, host, addrs, lastErr)
	return nil, lastErr
}
