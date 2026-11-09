package dnsserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
	"pk95dns/internal/filter"
)

// Query log statuses (docs/api.md → Query log).
const (
	statusOK             = "ok"
	statusAllowed        = "allowed"
	statusBlocked        = "blocked"
	statusBlockedService = "blocked_service"
	statusSafeSearch     = "safesearch"
	statusRewrite        = "rewrite"
	statusRefused        = "refused"
	statusError          = "error"
)

// Reasons that are not filter reasons.
const (
	reasonRewrite   = "rewrite"
	reasonAccess    = "access"
	reasonAny       = "any"
	reasonRatelimit = "ratelimit"
	reasonUpstream  = "upstream"
)

// upstreamUDPSize is the EDNS0 buffer size towards upstreams and the largest size echoed
// to clients (DNS flag day 2020).
const upstreamUDPSize = 1232

// negSOAName is the primary name server of synthetic negative answers.
const negSOAName = "fake-for-negative-caching.pk95dns."

// outcome is the result of the pipeline for one query.
type outcome struct {
	resp     *dns.Msg
	status   string
	reason   string
	rule     string
	listID   int64
	service  string
	upstream string
	cached   bool
	drop     bool // rate limited: no answer
	logDrop  bool // log the dropped query
}

// cacheGenKey carries the cache generation of a query (Cache.Gen, read before its state).
type cacheGenKey struct{}

// process runs the full pipeline for a query received from client. gen is the cache
// generation read before st was loaded.
func (s *Server) process(st *state, req *dns.Msg, client netip.Addr, now time.Time, gen uint64) outcome {
	if st.accessDenied(client) {
		return refused(req, dns.RcodeRefused, reasonAccess)
	}
	if st.settings.Ratelimit > 0 {
		if ok, logIt := s.limiter.allow(client, now); !ok {
			return outcome{drop: true, logDrop: logIt, status: statusRefused, reason: reasonRatelimit}
		}
	}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), cacheGenKey{}, gen), st.upstreamTimeout)
	defer cancel()
	return s.decide(ctx, st, req, client, now, true)
}

func refused(req *dns.Msg, rcode int, reason string) outcome {
	return outcome{resp: rcodeReply(req, rcode), status: statusRefused, reason: reason}
}

// decide runs the pipeline from the ANY check on. With forward false (Check) nothing is
// asked upstream: local records are not chased and unfiltered queries end with status ok.
func (s *Server) decide(ctx context.Context, st *state, req *dns.Msg, client netip.Addr, now time.Time, forward bool) outcome {
	q := req.Question[0]
	name := filter.NormalizeName(q.Name)
	qtype := q.Qtype

	if !forward && client.IsValid() && st.accessDenied(client) {
		return refused(req, dns.RcodeRefused, reasonAccess)
	}
	if qtype == dns.TypeANY && st.settings.RefuseAny {
		return refused(req, dns.RcodeNotImplemented, reasonAny)
	}
	pol := st.policyFor(client)

	// Local records: always active.
	if entries := st.rewrites.Lookup(name); len(entries) > 0 {
		ch := s.localAnswer(ctx, st, req, q.Name, qtype, entries, 0, forward)
		if ch.err != nil {
			return upstreamFailure(req)
		}
		resp := reply(req, ch.rcode)
		resp.Answer, resp.Ns = ch.answer, ch.ns
		return outcome{resp: resp, status: statusRewrite, reason: reasonRewrite, upstream: ch.upstream, cached: ch.cached}
	}

	o := outcome{status: statusOK}
	filtering := s.deps.Filter != nil && pol.filtering && st.settings.ProtectionActive(now)
	if filtering {
		res := s.deps.Filter.Check(filter.Request{Name: name, QType: qtype, SafeSearch: pol.safeSearch, Services: pol.services})
		switch res.Action {
		case filter.Block:
			return st.blockedOutcome(req, res)
		case filter.Rewrite:
			if res.CNAME != "" {
				return s.safeSearch(ctx, st, req, res.CNAME, forward)
			}
			resp := reply(req, dns.RcodeSuccess)
			resp.Answer = addressRRs(q.Name, qtype, res.IPs, st.blockTTL)
			return outcome{resp: resp, status: statusRewrite, reason: res.Reason, rule: res.Rule, listID: res.ListID}
		case filter.Allow:
			o.status, o.reason, o.rule, o.listID = statusAllowed, res.Reason, res.Rule, res.ListID
		}
	}

	if st.settings.DisableIPv6 && qtype == dns.TypeAAAA {
		o.resp = reply(req, dns.RcodeSuccess)
		return o
	}
	if !forward {
		return o
	}

	resp, addr, cached, err := s.resolveUpstream(ctx, st, q, req)
	if err != nil {
		f := upstreamFailure(req)
		f.rule, f.listID = o.rule, o.listID
		return f
	}
	o.upstream, o.cached = addr, cached

	// CNAME cloaking: a blocked CNAME target blocks the original question.
	if filtering && o.status != statusAllowed {
		for _, rr := range resp.Answer {
			cn, ok := rr.(*dns.CNAME)
			if !ok {
				continue
			}
			if res := s.deps.Filter.CheckCNAME(cn.Target, qtype, pol.services); res.Action == filter.Block {
				b := st.blockedOutcome(req, res)
				b.upstream, b.cached = addr, cached
				return b
			}
		}
	}
	o.resp = resp
	return o
}

func upstreamFailure(req *dns.Msg) outcome {
	return outcome{resp: rcodeReply(req, dns.RcodeServerFailure), status: statusError, reason: reasonUpstream}
}

// chain is the (partial) answer for one name while chasing CNAMEs.
type chain struct {
	answer   []dns.RR
	ns       []dns.RR
	rcode    int
	upstream string
	cached   bool
	err      error
}

// localAnswer answers owner (as asked) from local records. Host name records become a
// CNAME plus the resolved target (chase) – targets of local records are trusted and not
// filtered.
func (s *Server) localAnswer(ctx context.Context, st *state, req *dns.Msg, owner string, qtype uint16, entries []filter.RewriteEntry, depth int, chase bool) chain {
	var v4, v6 []netip.Addr
	cname := ""
	for _, e := range entries {
		if a, err := netip.ParseAddr(e.Answer); err == nil {
			a = a.Unmap().WithZone("")
			if a.Is4() {
				v4 = append(v4, a)
			} else {
				v6 = append(v6, a)
			}
			continue
		}
		if cname == "" {
			cname = filter.NormalizeName(e.Answer)
		}
	}
	switch {
	case qtype == dns.TypeA && len(v4) > 0:
		return chain{answer: addressRRs(owner, qtype, v4, localTTL)}
	case qtype == dns.TypeAAAA && len(v6) > 0:
		return chain{answer: addressRRs(owner, qtype, v6, localTTL)}
	case cname != "":
		rr := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: localTTL},
			Target: dns.Fqdn(cname),
		}
		if !chase || qtype == dns.TypeCNAME {
			return chain{answer: []dns.RR{rr}}
		}
		sub := s.resolveTrusted(ctx, st, req, cname, qtype, depth+1)
		sub.answer = append([]dns.RR{rr}, sub.answer...)
		return sub
	}
	// The name has records, but none for this type: empty NOERROR.
	return chain{}
}

// resolveTrusted resolves a CNAME target without filtering: local records, then cache and
// upstreams.
func (s *Server) resolveTrusted(ctx context.Context, st *state, req *dns.Msg, name string, qtype uint16, depth int) chain {
	if depth > maxCNAMEDepth {
		return chain{}
	}
	fqdn := dns.Fqdn(name)
	if entries := st.rewrites.Lookup(name); len(entries) > 0 {
		return s.localAnswer(ctx, st, req, fqdn, qtype, entries, depth, true)
	}
	if st.settings.DisableIPv6 && qtype == dns.TypeAAAA {
		return chain{}
	}
	q := dns.Question{Name: fqdn, Qtype: qtype, Qclass: req.Question[0].Qclass}
	resp, addr, cached, err := s.resolveUpstream(ctx, st, q, req)
	if err != nil {
		return chain{err: err}
	}
	return chain{answer: resp.Answer, ns: resp.Ns, rcode: resp.Rcode, upstream: addr, cached: cached}
}

// safeSearch answers with a CNAME to the safe host plus its resolved records.
func (s *Server) safeSearch(ctx context.Context, st *state, req *dns.Msg, target string, forward bool) outcome {
	q := req.Question[0]
	rr := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: st.blockTTL},
		Target: dns.Fqdn(target),
	}
	o := outcome{status: statusSafeSearch, reason: filter.ReasonSafeSearch}
	resp := reply(req, dns.RcodeSuccess)
	resp.Answer = []dns.RR{rr}
	if forward && q.Qtype != dns.TypeCNAME {
		sub := s.resolveTrusted(ctx, st, req, target, q.Qtype, 1)
		if sub.err != nil {
			return upstreamFailure(req)
		}
		resp.Rcode = sub.rcode
		resp.Answer = append(resp.Answer, sub.answer...)
		resp.Ns = sub.ns
		o.upstream, o.cached = sub.upstream, sub.cached
	}
	o.resp = resp
	return o
}

var errNoRouter = errors.New("Keine Upstreams konfiguriert")

// resolveUpstream asks the cache and then the router for question q of the client request
// req. The upstream request has a fresh id, RD, AD and an EDNS0 OPT (UDP 1232, DO when
// dnssec or the client set it); client EDNS options (ECS) are not passed on. AD is always
// set (RFC 6840 5.7) so validating upstreams report authenticated data even without DO;
// finish strips AD for clients that asked for neither AD nor DO, so the cache key needs no
// AD bit.
func (s *Server) resolveUpstream(ctx context.Context, st *state, q dns.Question, req *dns.Msg) (*dns.Msg, string, bool, error) {
	do := st.settings.DNSSEC
	if opt := req.IsEdns0(); opt != nil && opt.Do() {
		do = true
	}
	ureq := new(dns.Msg)
	ureq.Id = dns.Id()
	ureq.Opcode = dns.OpcodeQuery
	ureq.RecursionDesired = true
	ureq.AuthenticatedData = true
	ureq.CheckingDisabled = req.CheckingDisabled
	ureq.Question = []dns.Question{q}
	ureq.SetEdns0(upstreamUDPSize, do)

	useCache := s.deps.Cache != nil && st.settings.CacheEnabled
	if useCache {
		if c := s.deps.Cache.Get(ureq); c != nil {
			return c, "", true, nil
		}
	}
	if st.router == nil {
		return nil, "", false, errNoRouter
	}
	resp, addr, err := st.router.Resolve(ctx, ureq)
	if err != nil {
		return nil, "", false, err
	}
	if resp == nil {
		return nil, "", false, errNoRouter
	}
	if useCache {
		if gen, ok := ctx.Value(cacheGenKey{}).(uint64); ok {
			s.deps.Cache.SetGen(gen, ureq, resp)
		} else {
			s.deps.Cache.Set(ureq, resp)
		}
	}
	return resp, addr, false, nil
}

// blockedOutcome builds the blocked answer of a filter block decision.
func (st *state) blockedOutcome(req *dns.Msg, res filter.Result) outcome {
	o := outcome{
		resp:    st.blockedAnswer(req),
		status:  statusBlocked,
		reason:  res.Reason,
		rule:    res.Rule,
		listID:  res.ListID,
		service: res.Service,
	}
	if res.Reason == filter.ReasonService {
		o.status = statusBlockedService
	}
	return o
}

// blockedAnswer builds the answer of the configured blocking mode (docs/design.md).
func (st *state) blockedAnswer(req *dns.Msg) *dns.Msg {
	q := req.Question[0]
	switch st.blockMode {
	case config.BlockNXDomain:
		resp := reply(req, dns.RcodeNameError)
		resp.Ns = []dns.RR{&dns.SOA{
			Hdr:     dns.RR_Header{Name: dns.Fqdn(q.Name), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: st.blockTTL},
			Ns:      negSOAName,
			Mbox:    "hostmaster.pk95dns.",
			Serial:  1,
			Refresh: 1800,
			Retry:   900,
			Expire:  604800,
			Minttl:  st.blockTTL,
		}}
		return resp
	case config.BlockRefused:
		return rcodeReply(req, dns.RcodeRefused)
	case config.BlockCustomIP:
		resp := reply(req, dns.RcodeSuccess)
		var ips []netip.Addr
		if st.blockIPv4.IsValid() {
			ips = append(ips, st.blockIPv4)
		}
		if st.blockIPv6.IsValid() {
			ips = append(ips, st.blockIPv6)
		}
		resp.Answer = addressRRs(q.Name, q.Qtype, ips, st.blockTTL)
		return resp
	default: // null_ip
		resp := reply(req, dns.RcodeSuccess)
		resp.Answer = addressRRs(q.Name, q.Qtype, []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()}, st.blockTTL)
		return resp
	}
}

// addressRRs returns A records (qtype A) or AAAA records (qtype AAAA) for the addresses of
// the matching family; other types get none.
func addressRRs(owner string, qtype uint16, ips []netip.Addr, ttl uint32) []dns.RR {
	var out []dns.RR
	for _, a := range ips {
		a = a.Unmap()
		hdr := dns.RR_Header{Name: owner, Rrtype: qtype, Class: dns.ClassINET, Ttl: ttl}
		switch {
		case qtype == dns.TypeA && a.Is4():
			out = append(out, &dns.A{Hdr: hdr, A: net.IP(a.AsSlice())})
		case qtype == dns.TypeAAAA && a.Is6():
			out = append(out, &dns.AAAA{Hdr: hdr, AAAA: net.IP(a.AsSlice())})
		}
	}
	return out
}

// reply returns an empty answer to req with rcode.
func reply(req *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	return m
}

// rcodeReply is reply for error answers (no records).
func rcodeReply(req *dns.Msg, rcode int) *dns.Msg { return reply(req, rcode) }

// finish turns resp into the answer for req: id, question and flags of the request, OPT
// echoed only when the client sent one (UDP size min(client, 1232), at least 512), DNSSEC
// records only for DO clients, truncation to the client's UDP size (never over TCP).
func finish(req, resp *dns.Msg, tcp bool) {
	resp.Id = req.Id
	resp.Response = true
	resp.Opcode = req.Opcode
	resp.Question = append([]dns.Question(nil), req.Question...)
	resp.RecursionDesired = req.RecursionDesired
	resp.RecursionAvailable = true
	resp.Authoritative = false
	resp.CheckingDisabled = req.CheckingDisabled
	resp.Truncated = false
	resp.Extra = withoutOPT(resp.Extra)

	clientOpt := req.IsEdns0()
	clientDO := clientOpt != nil && clientOpt.Do()
	if !clientDO {
		var qtype uint16
		if len(req.Question) > 0 {
			qtype = req.Question[0].Qtype
		}
		resp.Answer = withoutDNSSEC(resp.Answer, qtype)
		resp.Ns = withoutDNSSEC(resp.Ns, qtype)
		resp.Extra = withoutDNSSEC(resp.Extra, qtype)
		resp.AuthenticatedData = resp.AuthenticatedData && req.AuthenticatedData
	}

	size := dns.MinMsgSize
	if clientOpt != nil {
		echo := min(max(int(clientOpt.UDPSize()), dns.MinMsgSize), upstreamUDPSize)
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(uint16(echo))
		if clientDO {
			opt.SetDo()
		}
		resp.Extra = append(resp.Extra, opt)
		size = max(int(clientOpt.UDPSize()), dns.MinMsgSize)
	} else if resp.Rcode > 0xF {
		// Extended rcodes need an OPT record the client did not send.
		resp.Rcode = dns.RcodeServerFailure
	}
	if tcp {
		resp.Compress = true
		return
	}
	resp.Truncate(size)
}

func withoutOPT(rrs []dns.RR) []dns.RR {
	out := rrs[:0:0]
	for _, rr := range rrs {
		if rr.Header().Rrtype != dns.TypeOPT {
			out = append(out, rr)
		}
	}
	return out
}

// withoutDNSSEC removes RRSIG/NSEC/NSEC3 records (unless they were asked for).
func withoutDNSSEC(rrs []dns.RR, qtype uint16) []dns.RR {
	out := rrs[:0:0]
	for _, rr := range rrs {
		switch t := rr.Header().Rrtype; t {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
			if t != qtype {
				continue
			}
		}
		out = append(out, rr)
	}
	return out
}

func isTCP(w dns.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.TCPAddr)
	return ok
}

// maxAnswerText limits the answer summary of the query log.
const maxAnswerText = 200

// summarize renders the answer section for the query log ("1.2.3.4, ::1", "CNAME x").
func summarize(rrs []dns.RR) string {
	var b strings.Builder
	for _, rr := range rrs {
		var part string
		switch v := rr.(type) {
		case *dns.A:
			part = v.A.String()
		case *dns.AAAA:
			part = v.AAAA.String()
		case *dns.CNAME:
			part = "CNAME " + strings.TrimSuffix(v.Target, ".")
		case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.OPT:
			continue
		default:
			h := rr.Header()
			data := strings.TrimSpace(strings.TrimPrefix(rr.String(), h.String()))
			part = strings.TrimSpace(typeString(h.Rrtype) + " " + strings.TrimSuffix(data, "."))
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(part)
		if b.Len() >= maxAnswerText {
			break
		}
	}
	out := b.String()
	if len(out) > maxAnswerText {
		out = strings.ToValidUTF8(out[:maxAnswerText], "")
	}
	return out
}

func typeString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func rcodeString(rc int) string {
	if s, ok := dns.RcodeToString[rc]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(rc)
}
