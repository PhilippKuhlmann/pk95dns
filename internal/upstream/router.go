package upstream

import (
	"context"
	"errors"
	"math/rand/v2"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Router resolves queries through the configured upstreams.
type Router struct {
	mode       string
	timeout    time.Duration
	main       []member
	fallback   []member
	routes     []route // longest domain first
	privatePTR bool
	private    []member
	all        []Upstream

	rnd func() float64 // random source for load_balance (tests replace it)
}

type member struct {
	addr   string
	up     Upstream
	health *healthState
}

type route struct {
	domain string // lowercase, no trailing dot
	m      member
}

// NewRouter validates the config and creates all upstreams.
func NewRouter(cfg Config) (*Router, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = "load_balance"
	}
	switch mode {
	case "load_balance", "parallel", "sequential":
	default:
		return nil, errorf("Unbekannter Upstream-Modus: %s", cfg.Mode)
	}
	if len(cfg.Upstreams) == 0 {
		return nil, errorf("Mindestens ein Upstream ist nötig")
	}
	opt := Options{Timeout: cfg.Timeout, Bootstrap: cfg.Bootstrap}
	res, err := newResolver(cfg.Bootstrap, timeoutOf(opt))
	if err != nil {
		return nil, err
	}

	r := &Router{
		mode:       mode,
		timeout:    timeoutOf(opt),
		privatePTR: cfg.PrivatePTR,
		rnd:        rand.Float64,
	}
	byAddr := map[string]Upstream{}
	get := func(addr string) (member, error) {
		up, ok := byAddr[addr]
		if !ok {
			var err error
			up, err = newWithResolver(addr, opt, res)
			if err != nil {
				return member{}, &upstreamError{msg: err.Error() + " (" + addr + ")", err: err}
			}
			byAddr[addr] = up
			r.all = append(r.all, up)
		}
		return member{addr: addr, up: up, health: healthFor(addr)}, nil
	}
	build := func(addrs []string) ([]member, error) {
		out := make([]member, 0, len(addrs))
		for _, a := range addrs {
			m, err := get(a)
			if err != nil {
				return nil, err
			}
			out = append(out, m)
		}
		return out, nil
	}

	fail := func(err error) (*Router, error) {
		r.Close()
		return nil, err
	}
	if r.main, err = build(cfg.Upstreams); err != nil {
		return fail(err)
	}
	if r.fallback, err = build(cfg.Fallback); err != nil {
		return fail(err)
	}
	if r.private, err = build(cfg.PrivateUpstreams); err != nil {
		return fail(err)
	}
	for _, rt := range cfg.Routes {
		d := normalizeName(rt.Domain)
		if d == "" {
			return fail(errorf("Domain für bedingte Weiterleitung fehlt"))
		}
		m, err := get(rt.Upstream)
		if err != nil {
			return fail(err)
		}
		r.routes = append(r.routes, route{domain: d, m: m})
	}
	sort.SliceStable(r.routes, func(i, j int) bool {
		return len(r.routes[i].domain) > len(r.routes[j].domain)
	})
	return r, nil
}

func normalizeName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// Resolve answers req (it is not modified). Returns the answer, the address of the upstream
// that answered ("" when answered locally, e.g. private PTR NXDOMAIN) and an error when no
// upstream gave a good answer. The answer's Id equals req.Id.
func (r *Router) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, string, error) {
	if req == nil || len(req.Question) == 0 {
		return nil, "", errorf("Anfrage ohne Frage")
	}
	name := normalizeName(req.Question[0].Name)

	if rt, ok := r.matchRoute(name); ok {
		resp, err := r.try(ctx, rt.m, req)
		if err != nil {
			return nil, "", err
		}
		return resp, rt.m.addr, nil
	}

	if r.privatePTR && IsPrivatePTR(name) {
		if len(r.private) == 0 {
			resp := new(dns.Msg)
			resp.SetRcode(req, dns.RcodeNameError)
			resp.RecursionAvailable = true
			return resp, "", nil
		}
		return r.sequential(ctx, r.private, req)
	}

	var (
		resp *dns.Msg
		addr string
		err  error
	)
	// Keep part of the query budget for the fallback upstreams: otherwise main upstreams
	// that silently drop packets use up the whole deadline and the fallback (e.g. IP based
	// upstreams for a network that blocks the bootstrap) is never asked.
	mctx := ctx
	if len(r.fallback) > 0 {
		if dl, ok := ctx.Deadline(); ok {
			if rem := time.Until(dl); rem > 0 {
				var cancel context.CancelFunc
				mctx, cancel = context.WithDeadline(ctx, dl.Add(-min(r.timeout, rem/2)))
				defer cancel()
			}
		}
	}
	switch r.mode {
	case "parallel":
		resp, addr, err = r.parallel(mctx, r.main, req)
	case "sequential":
		resp, addr, err = r.sequential(mctx, r.main, req)
	default:
		resp, addr, err = r.sequential(mctx, r.weightedOrder(r.main), req)
	}
	if err == nil {
		return resp, addr, nil
	}
	if len(r.fallback) > 0 && ctx.Err() == nil {
		resp, addr, ferr := r.sequential(ctx, r.fallback, req)
		if ferr == nil {
			return resp, addr, nil
		}
		err = ferr
	}
	return nil, "", &upstreamError{msg: "Kein Upstream hat geantwortet: " + err.Error(), err: err}
}

// matchRoute finds the longest conditional domain that equals name or is a parent of it.
func (r *Router) matchRoute(name string) (route, bool) {
	for _, rt := range r.routes {
		if name == rt.domain || strings.HasSuffix(name, "."+rt.domain) {
			return rt, true
		}
	}
	return route{}, false
}

// try runs one exchange, records the health and treats SERVFAIL/REFUSED as failure.
func (r *Router) try(ctx context.Context, m member, req *dns.Msg) (*dns.Msg, error) {
	start := time.Now()
	resp, err := m.up.Exchange(ctx, req)
	rtt := time.Since(start)
	if err == nil && (resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused) {
		err = errBadRcode(resp.Rcode)
	}
	m.health.record(rtt, err, r.timeout)
	if err != nil {
		return nil, err
	}
	resp.Id = req.Id
	return resp, nil
}

// sequential asks members one after another. When ctx has a deadline, each try gets at most
// a fair share of the remaining time, so one upstream that never answers cannot keep the
// later ones from being asked.
func (r *Router) sequential(ctx context.Context, members []member, req *dns.Msg) (*dns.Msg, string, error) {
	var lastErr error
	for i, m := range members {
		tctx, cancel := shareContext(ctx, len(members)-i)
		resp, err := r.try(tctx, m, req)
		cancel()
		if err == nil {
			return resp, m.addr, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, "", germanError(ctx.Err())
		}
	}
	if lastErr == nil {
		lastErr = errorf("Keine Upstreams konfiguriert")
	}
	return nil, "", lastErr
}

// parallel asks all members at once; the first good answer wins and the others are cancelled.
func (r *Router) parallel(ctx context.Context, members []member, req *dns.Msg) (*dns.Msg, string, error) {
	if len(members) == 1 {
		return r.sequential(ctx, members, req)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		resp *dns.Msg
		addr string
		err  error
	}
	ch := make(chan result, len(members))
	for _, m := range members {
		go func() {
			resp, err := r.try(ctx, m, req)
			ch <- result{resp: resp, addr: m.addr, err: err}
		}()
	}
	var lastErr error
	for range members {
		res := <-ch
		if res.err == nil {
			return res.resp, res.addr, nil
		}
		if lastErr == nil || !errors.Is(res.err, context.Canceled) {
			lastErr = res.err
		}
	}
	return nil, "", lastErr
}

// weightedOrder returns members in a random order where faster upstreams (lower EWMA RTT)
// are more likely to come first. Upstreams without measurements get the mean weight of the
// measured ones, failures count with the timeout as RTT, so slow or failing upstreams still
// get a chance and can recover.
func (r *Router) weightedOrder(members []member) []member {
	if len(members) <= 1 {
		return members
	}
	weights := make([]float64, len(members))
	var sum float64
	var known int
	for i, m := range members {
		ms, ok := m.health.weight()
		if ok {
			weights[i] = 1 / ms
			sum += weights[i]
			known++
		}
	}
	unknown := 1.0
	if known > 0 {
		unknown = sum / float64(known)
	}
	for i, m := range members {
		if _, ok := m.health.weight(); !ok {
			weights[i] = unknown
		}
	}

	pool := append([]member(nil), members...)
	out := make([]member, 0, len(members))
	for len(pool) > 0 {
		var total float64
		for _, w := range weights {
			total += w
		}
		x := r.rnd() * total
		idx := len(pool) - 1
		for i, w := range weights {
			if x < w {
				idx = i
				break
			}
			x -= w
		}
		out = append(out, pool[idx])
		pool = append(pool[:idx], pool[idx+1:]...)
		weights = append(weights[:idx], weights[idx+1:]...)
	}
	return out
}

// Health returns the health of the main upstreams (config order).
func (r *Router) Health() []Health {
	out := make([]Health, 0, len(r.main))
	for _, m := range r.main {
		out = append(out, m.health.snapshot(m.addr))
	}
	return out
}

// Close closes all upstreams (idle connections). Resolve calls in flight may still finish.
func (r *Router) Close() {
	for _, up := range r.all {
		_ = up.Close()
	}
}

// Test asks addr for "example.org A" and returns the round trip time.
func Test(ctx context.Context, addr string, bootstrap []string, timeout time.Duration) (time.Duration, error) {
	up, err := New(addr, Options{Timeout: timeout, Bootstrap: bootstrap})
	if err != nil {
		return 0, err
	}
	defer up.Close()
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	m.RecursionDesired = true
	start := time.Now()
	resp, err := up.Exchange(ctx, m)
	rtt := time.Since(start)
	if err != nil {
		return 0, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return 0, errBadRcode(resp.Rcode)
	}
	return rtt, nil
}
