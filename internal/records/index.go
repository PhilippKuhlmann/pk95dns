package records

import (
	"cmp"
	"net"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/miekg/dns"
)

// SOA timers of the synthesized zone SOA (docs/api.md → Zones).
const (
	soaRefresh = 3600
	soaRetry   = 600
	soaExpire  = 604800
)

// Result is the answer of the index for one question.
//
//   - Found false: the name is not ours (no enabled zone covers it and no single record
//     matches) → the server continues with filtering, cache and upstream.
//   - Found true: answer with Rcode, Answer, Ns (authority) and Extra (additional) as given,
//     AA bit = Authoritative, status "rewrite", reason Reason. Never cache it.
//   - CNAMETarget != "": the answer ends with a CNAME whose target (lowercase, no trailing
//     dot) the index cannot answer; the server resolves it via cache/upstream (no
//     filtering) for the same qtype and appends that answer (Depth CNAMEs are already in
//     Answer; MaxCNAMEDepth in total). Lookup sets it on every CNAME, Resolve only when the
//     chain leaves the index.
//   - Rcode REFUSED: AXFR/IXFR for a name inside a zone or with single records (no zone
//     transfers).
//   - Rcode SERVFAIL (Resolve only): CNAME loop or more than MaxCNAMEDepth local CNAMEs.
type Result struct {
	Found         bool
	Authoritative bool
	Rcode         int // dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeRefused, dns.RcodeServerFailure
	Answer        []dns.RR
	Ns            []dns.RR
	Extra         []dns.RR
	CNAMETarget   string
	Depth         int    // CNAME records in Answer
	Reason        string // ReasonZone or ReasonRecord
	Zone          string // name of the answering zone ("" for single records)
}

// Index is the compiled, immutable lookup structure of the enabled zones and records. It is
// safe for concurrent use; build a new one with Compile on every change and swap the pointer
// (e.g. atomic.Pointer[records.Index]). A nil *Index answers nothing (Found false).
type Index struct {
	zones     map[string]*zoneData // enabled zones by name
	single    table                // records outside every zone
	nZones    int
	nRecords  int
	nRewrites int
}

type zoneData struct {
	name  string // normalised, no trailing dot
	fqdn  string
	ttl   uint32
	soa   *dns.SOA
	ns    *dns.NS
	names map[string]*node // owner names with records ("*.x" wildcards included)
	ents  map[string]bool  // empty non-terminals (below the apex, records only below them)
}

type table struct {
	names map[string]*node // exact names
	wild  map[string]*node // "*.b.lan" under "b.lan"
}

type node struct {
	rrs   []dns.RR // record templates (owner name set on copy), sorted
	cname dns.RR   // first CNAME of rrs, nil if none
}

func (n *node) add(rr dns.RR) {
	n.rrs = append(n.rrs, rr)
	if n.cname == nil && rr.Header().Rrtype == dns.TypeCNAME {
		n.cname = rr
	}
}

// ZoneCount is the number of enabled zones.
func (ix *Index) ZoneCount() int {
	if ix == nil {
		return 0
	}
	return ix.nZones
}

// RecordCount is the number of served records (enabled, and their zone enabled when they
// have one); synthesized PTRs are not counted.
func (ix *Index) RecordCount() int {
	if ix == nil {
		return 0
	}
	return ix.nRecords
}

// RewriteCount is the number of served A, AAAA and CNAME records (/api/status
// rules.rewrites, deprecated).
func (ix *Index) RewriteCount() int {
	if ix == nil {
		return 0
	}
	return ix.nRewrites
}

var typeOrder = map[string]int{TypeA: 0, TypeAAAA: 1, TypeCNAME: 2, TypeMX: 3, TypeTXT: 4, TypeSRV: 5, TypePTR: 6}

// Compile builds the index. Only enabled zones and enabled records count; records of a
// disabled zone are ignored entirely (zone membership is derived from the name over all
// zones, see ZoneFor, not from Record.ZoneID). Records that cannot be turned into a DNS
// record (invalid value) and CNAMEs at a zone apex are skipped. A/AAAA records with PTR
// set (not wildcards) add a synthesized PTR at the reverse name of their address, unless
// an explicit served PTR record exists for that name; it is served like a record placed
// there (inside a zone when the reverse name belongs to an enabled one, ignored when it
// belongs to a disabled one, otherwise as a single record).
func Compile(zones []Zone, recs []Record) *Index {
	ix := &Index{
		zones:  map[string]*zoneData{},
		single: table{names: map[string]*node{}, wild: map[string]*node{}},
	}
	all := map[string]bool{} // every zone name → enabled
	for _, z := range zones {
		name := NormalizeName(z.Name)
		if name == "" {
			continue
		}
		all[name] = all[name] || z.Enabled
		if !z.Enabled || ix.zones[name] != nil {
			continue
		}
		ix.zones[name] = newZoneData(name, z)
		ix.nZones++
	}

	sorted := make([]Record, 0, len(recs))
	for _, r := range recs {
		if !r.Enabled {
			continue
		}
		r.Name = NormalizeName(r.Name)
		r.Type = strings.ToUpper(r.Type)
		if r.Name == "" {
			continue
		}
		sorted = append(sorted, r)
	}
	slices.SortFunc(sorted, func(a, b Record) int {
		return cmp.Or(
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(typeOrder[a.Type], typeOrder[b.Type]),
			cmp.Compare(a.Priority, b.Priority),
			cmp.Compare(a.Weight, b.Weight),
			cmp.Compare(a.Port, b.Port),
			cmp.Compare(a.Value, b.Value),
			cmp.Compare(a.ID, b.ID),
		)
	})

	type synth struct {
		rev, target string
		ttl         uint32
	}
	var synths []synth
	explicitPTR := map[string]bool{}
	for i := range sorted {
		r := &sorted[i]
		z, served := ix.container(r.Name, all)
		if !served {
			continue
		}
		if z != nil && r.Type == TypeCNAME && r.Name == z.name {
			continue // no CNAME at the apex (SOA/NS live there)
		}
		rr := buildRR(r)
		if rr == nil {
			continue
		}
		ix.place(z, r.Name, rr)
		ix.nRecords++
		if IsRewriteType(r.Type) {
			ix.nRewrites++
		}
		if r.Type == TypePTR {
			explicitPTR[r.Name] = true
		}
		if r.PTR && (r.Type == TypeA || r.Type == TypeAAAA) && !strings.HasPrefix(r.Name, "*.") {
			if rev, err := dns.ReverseAddr(r.Value); err == nil {
				synths = append(synths, synth{rev: NormalizeName(rev), target: r.Name, ttl: r.TTL})
			}
		}
	}
	seen := map[[2]string]bool{}
	for _, s := range synths {
		key := [2]string{s.rev, s.target}
		if explicitPTR[s.rev] || seen[key] {
			continue
		}
		seen[key] = true
		z, served := ix.container(s.rev, all)
		if !served {
			continue
		}
		ix.place(z, s.rev, &dns.PTR{
			Hdr: dns.RR_Header{Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: s.ttl},
			Ptr: dns.Fqdn(s.target),
		})
	}

	for _, z := range ix.zones {
		for name := range z.names {
			for p, ok := parent(name); ok && p != z.name && InZone(p, z.name); p, ok = parent(p) {
				if z.names[p] == nil {
					z.ents[p] = true
				}
			}
		}
	}
	return ix
}

func newZoneData(name string, z Zone) *zoneData {
	fqdn := dns.Fqdn(name)
	ns := NormalizeName(z.PrimaryNS)
	if ns == "" {
		ns = "ns." + name
	}
	return &zoneData{
		name: name,
		fqdn: fqdn,
		ttl:  z.TTL,
		soa: &dns.SOA{
			Hdr:     dns.RR_Header{Name: fqdn, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: z.TTL},
			Ns:      dns.Fqdn(ns),
			Mbox:    "hostmaster." + fqdn,
			Serial:  z.Serial,
			Refresh: soaRefresh,
			Retry:   soaRetry,
			Expire:  soaExpire,
			Minttl:  z.TTL,
		},
		ns: &dns.NS{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: z.TTL},
			Ns:  dns.Fqdn(ns),
		},
		names: map[string]*node{},
		ents:  map[string]bool{},
	}
}

// container returns where a record named name lives: the enabled zone (non-nil), or nil
// for a single record. served is false when the name belongs to a disabled zone.
func (ix *Index) container(name string, all map[string]bool) (*zoneData, bool) {
	for p, ok := name, true; ok; p, ok = parent(p) {
		if enabled, found := all[p]; found {
			if !enabled {
				return nil, false
			}
			return ix.zones[p], true
		}
	}
	return nil, true
}

func (ix *Index) place(z *zoneData, name string, rr dns.RR) {
	var m map[string]*node
	key := name
	switch {
	case z != nil:
		m = z.names
	case strings.HasPrefix(name, "*."):
		m, key = ix.single.wild, name[2:]
	default:
		m = ix.single.names
	}
	n := m[key]
	if n == nil {
		n = &node{}
		m[key] = n
	}
	n.add(rr)
}

// buildRR turns a record into a template RR (owner name empty), nil when its value is invalid.
func buildRR(r *Record) dns.RR {
	hdr := dns.RR_Header{Class: dns.ClassINET, Ttl: r.TTL}
	host := func() string { return dns.Fqdn(NormalizeName(r.Value)) }
	switch r.Type {
	case TypeA:
		ip, err := netip.ParseAddr(strings.TrimSpace(r.Value))
		if err != nil || !(ip.Is4() || ip.Is4In6()) {
			return nil
		}
		hdr.Rrtype = dns.TypeA
		return &dns.A{Hdr: hdr, A: net.IP(ip.Unmap().AsSlice())}
	case TypeAAAA:
		ip, err := netip.ParseAddr(strings.TrimSpace(r.Value))
		if err != nil || !ip.Is6() || ip.Is4In6() {
			return nil
		}
		hdr.Rrtype = dns.TypeAAAA
		return &dns.AAAA{Hdr: hdr, AAAA: net.IP(ip.WithZone("").AsSlice())}
	case TypeCNAME:
		if NormalizeName(r.Value) == "" {
			return nil
		}
		hdr.Rrtype = dns.TypeCNAME
		return &dns.CNAME{Hdr: hdr, Target: host()}
	case TypeMX:
		if NormalizeName(r.Value) == "" {
			return nil
		}
		hdr.Rrtype = dns.TypeMX
		return &dns.MX{Hdr: hdr, Preference: r.Priority, Mx: host()}
	case TypeSRV:
		if NormalizeName(r.Value) == "" {
			return nil
		}
		hdr.Rrtype = dns.TypeSRV
		return &dns.SRV{Hdr: hdr, Priority: r.Priority, Weight: r.Weight, Port: r.Port, Target: host()}
	case TypePTR:
		if NormalizeName(r.Value) == "" {
			return nil
		}
		hdr.Rrtype = dns.TypePTR
		return &dns.PTR{Hdr: hdr, Ptr: host()}
	case TypeTXT:
		if r.Value == "" {
			return nil
		}
		hdr.Rrtype = dns.TypeTXT
		return &dns.TXT{Hdr: hdr, Txt: SplitTXT(r.Value)}
	}
	return nil
}

// SplitTXT splits a TXT value into character-strings of at most 255 bytes (at UTF-8
// boundaries) in the presentation form miekg/dns packs: backslashes are escaped.
func SplitTXT(v string) []string {
	var out []string
	for len(v) > 0 {
		n := min(len(v), 255)
		for n < len(v) && n > 0 && !utf8.RuneStart(v[n]) {
			n--
		}
		out = append(out, strings.ReplaceAll(v[:n], `\`, `\\`))
		v = v[n:]
	}
	return out
}

func parent(name string) (string, bool) {
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return "", false
	}
	return name[i+1:], true
}

// Lookup answers one question from the index without following CNAMEs (see Result).
// qname is the name as asked (any case, trailing dot optional); answers carry it as owner
// name unchanged (0x20 case randomisation). Semantics: docs/design.md → Local zones and
// records.
func (ix *Index) Lookup(qname string, qtype uint16) Result {
	if ix == nil {
		return Result{}
	}
	qn := NormalizeName(qname)
	if qn == "" {
		return Result{}
	}
	return ix.lookup(qn, dns.Fqdn(strings.TrimSpace(qname)), qtype, true)
}

// Resolve is Lookup plus following CNAMEs inside the index (at most MaxCNAMEDepth): the
// answers of the targets are appended, Rcode/Ns/Extra come from the last step. When a
// target is not in the index, CNAMETarget names it for the upstream. A loop or a longer
// chain gives SERVFAIL without records.
func (ix *Index) Resolve(qname string, qtype uint16) Result {
	res := ix.Lookup(qname, qtype)
	if !res.Found || res.CNAMETarget == "" {
		return res
	}
	servfail := Result{Found: true, Authoritative: res.Authoritative, Rcode: dns.RcodeServerFailure,
		Reason: res.Reason, Zone: res.Zone}
	seen := map[string]bool{NormalizeName(qname): true}
	for res.CNAMETarget != "" {
		target := res.CNAMETarget
		if seen[target] {
			return servfail // loop
		}
		seen[target] = true
		next := ix.lookup(target, dns.Fqdn(target), qtype, true)
		if !next.Found {
			return res // the upstream resolves the target
		}
		res.Depth += next.Depth
		if res.Depth > MaxCNAMEDepth {
			return servfail
		}
		res.Answer = append(res.Answer, next.Answer...)
		res.Ns, res.Extra = next.Ns, next.Extra
		res.Rcode = next.Rcode
		res.CNAMETarget = next.CNAMETarget
	}
	return res
}

func (ix *Index) zoneOf(qn string) *zoneData {
	if len(ix.zones) == 0 {
		return nil
	}
	for p, ok := qn, true; ok; p, ok = parent(p) {
		if z := ix.zones[p]; z != nil {
			return z
		}
	}
	return nil
}

func (ix *Index) lookup(qn, owner string, qtype uint16, extra bool) Result {
	if z := ix.zoneOf(qn); z != nil {
		return ix.zoneLookup(z, qn, owner, qtype, extra)
	}
	n := ix.single.names[qn]
	if n == nil && len(ix.single.wild) > 0 {
		for p, ok := parent(qn); ok; p, ok = parent(p) {
			if n = ix.single.wild[p]; n != nil {
				break
			}
		}
	}
	if n == nil {
		return Result{}
	}
	res := Result{Found: true, Rcode: dns.RcodeSuccess, Reason: ReasonRecord}
	if qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
		res.Rcode = dns.RcodeRefused
		return res
	}
	ix.answer(&res, nil, n, false, owner, qtype, extra)
	if len(res.Answer) == 0 && !hasAddress(n, qtype) {
		// A single record only overrides what it defines: other types (MX, TXT, …) of the
		// name still come from the upstream. Only the other address family stays empty, so
		// a client never gets the public IPv6 next to a local IPv4 (split horizon).
		return Result{}
	}
	return res
}

// hasAddress reports whether qtype is A or AAAA and the node has an address record of
// either family.
func hasAddress(n *node, qtype uint16) bool {
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return false
	}
	for _, rr := range n.rrs {
		if t := rr.Header().Rrtype; t == dns.TypeA || t == dns.TypeAAAA {
			return true
		}
	}
	return false
}

func (ix *Index) zoneLookup(z *zoneData, qn, owner string, qtype uint16, extra bool) Result {
	res := Result{Found: true, Authoritative: true, Rcode: dns.RcodeSuccess, Reason: ReasonZone, Zone: z.name}
	switch qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		res.Authoritative = false
		res.Rcode = dns.RcodeRefused
		return res
	case dns.TypeDS, dns.TypeDNSKEY, dns.TypeRRSIG:
		res.Ns = []dns.RR{dns.Copy(z.soa)}
		return res
	}
	if n := z.names[qn]; n != nil || qn == z.name {
		ix.answer(&res, z, n, qn == z.name, owner, qtype, extra)
		return res
	}
	if z.ents[qn] {
		res.Ns = []dns.RR{dns.Copy(z.soa)}
		return res
	}
	// RFC 4592: the closest encloser is the longest existing ancestor; its "*" child, if
	// any, answers with the query name as owner.
	ce := z.name
	for p, ok := parent(qn); ok && p != z.name; p, ok = parent(p) {
		if z.names[p] != nil || z.ents[p] {
			ce = p
			break
		}
	}
	if w := z.names["*."+ce]; w != nil {
		ix.answer(&res, z, w, false, owner, qtype, extra)
		return res
	}
	res.Rcode = dns.RcodeNameError
	res.Ns = []dns.RR{dns.Copy(z.soa)}
	return res
}

// answer fills res from node n (nil only at a zone apex without records). z is the zone
// (nil for single records): SOA/NS at the apex and the SOA of negative answers.
func (ix *Index) answer(res *Result, z *zoneData, n *node, apex bool, owner string, qtype uint16, extra bool) {
	isAny := qtype == dns.TypeANY
	if apex {
		if qtype == dns.TypeSOA || isAny {
			res.Answer = append(res.Answer, withOwner(z.soa, owner))
		}
		if qtype == dns.TypeNS || isAny {
			res.Answer = append(res.Answer, withOwner(z.ns, owner))
		}
	}
	if n != nil {
		for _, rr := range n.rrs {
			if isAny || rr.Header().Rrtype == qtype {
				res.Answer = append(res.Answer, withOwner(rr, owner))
			}
		}
	}
	if len(res.Answer) > 0 {
		if extra {
			res.Extra = ix.additional(res.Answer)
		}
		return
	}
	if n != nil && n.cname != nil && qtype != dns.TypeCNAME {
		res.Answer = []dns.RR{withOwner(n.cname, owner)}
		res.CNAMETarget = NormalizeName(n.cname.(*dns.CNAME).Target)
		res.Depth = 1
		return
	}
	if z != nil {
		res.Ns = []dns.RR{dns.Copy(z.soa)} // NODATA
	}
}

// additional returns the A/AAAA records from the index for the targets of MX, SRV and NS
// answers.
func (ix *Index) additional(answer []dns.RR) []dns.RR {
	var targets []string
	for _, rr := range answer {
		var t string
		switch v := rr.(type) {
		case *dns.MX:
			t = v.Mx
		case *dns.SRV:
			t = v.Target
		case *dns.NS:
			t = v.Ns
		default:
			continue
		}
		if t = NormalizeName(t); t != "" && !slices.Contains(targets, t) {
			targets = append(targets, t)
		}
	}
	var out []dns.RR
	for _, t := range targets {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			r := ix.lookup(t, dns.Fqdn(t), qt, false)
			for _, rr := range r.Answer {
				if rr.Header().Rrtype == qt {
					out = append(out, rr)
				}
			}
		}
	}
	return out
}

func withOwner(rr dns.RR, owner string) dns.RR {
	c := dns.Copy(rr)
	c.Header().Name = owner
	return c
}
