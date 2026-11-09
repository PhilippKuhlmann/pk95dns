package records

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

func z(id int64, name string) Zone {
	return Zone{ID: id, Name: name, TTL: 300, Enabled: true, Serial: 2026110901}
}

var nextID int64

func r(name, typ, value string) Record {
	nextID++
	return Record{ID: nextID, Name: name, Type: typ, Value: value, TTL: 60, Enabled: true}
}

func mx(name string, prio uint16, value string) Record {
	rec := r(name, TypeMX, value)
	rec.Priority = prio
	return rec
}

func srv(name, target string, port uint16) Record {
	rec := r(name, TypeSRV, target)
	rec.Priority, rec.Weight, rec.Port = 1, 2, port
	return rec
}

func ptr(rec Record) Record {
	rec.PTR = true
	return rec
}

func disabled(rec Record) Record {
	rec.Enabled = false
	return rec
}

// fmtRRs renders RRs as "owner TTL TYPE rdata".
func fmtRRs(rrs []dns.RR) []string {
	var out []string
	for _, rr := range rrs {
		h := rr.Header()
		rdata := strings.TrimPrefix(rr.String(), h.String())
		out = append(out, fmt.Sprintf("%s %d %s %s", h.Name, h.Ttl, dns.TypeToString[h.Rrtype], rdata))
	}
	return out
}

const soaExample = "example. 300 SOA ns.example. hostmaster.example. 2026110901 3600 600 604800 300"

type lookupCase struct {
	qname  string
	qtype  uint16
	found  bool
	aa     bool
	rcode  int
	answer []string
	ns     []string
	extra  []string
	target string
	reason string
}

func runCases(t *testing.T, ix *Index, resolve bool, cases []lookupCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.qname+"/"+dns.TypeToString[c.qtype], func(t *testing.T) {
			var res Result
			if resolve {
				res = ix.Resolve(c.qname, c.qtype)
			} else {
				res = ix.Lookup(c.qname, c.qtype)
			}
			if res.Found != c.found {
				t.Fatalf("found = %v, want %v", res.Found, c.found)
			}
			if !c.found {
				return
			}
			if res.Authoritative != c.aa || res.Rcode != c.rcode {
				t.Errorf("aa=%v rcode=%s, want aa=%v rcode=%s", res.Authoritative, dns.RcodeToString[res.Rcode],
					c.aa, dns.RcodeToString[c.rcode])
			}
			if got := fmtRRs(res.Answer); !reflect.DeepEqual(got, c.answer) {
				t.Errorf("answer =\n%q\nwant\n%q", got, c.answer)
			}
			if got := fmtRRs(res.Ns); !reflect.DeepEqual(got, c.ns) {
				t.Errorf("ns =\n%q\nwant\n%q", got, c.ns)
			}
			if got := fmtRRs(res.Extra); !reflect.DeepEqual(got, c.extra) {
				t.Errorf("extra =\n%q\nwant\n%q", got, c.extra)
			}
			if res.CNAMETarget != c.target {
				t.Errorf("target = %q, want %q", res.CNAMETarget, c.target)
			}
			if c.reason != "" && res.Reason != c.reason {
				t.Errorf("reason = %q, want %q", res.Reason, c.reason)
			}
		})
	}
}

// RFC 4592 section 2.2.1, adapted (no delegation: subdel is left out; the apex NS records
// are synthesized from primary_ns).
func TestRFC4592Examples(t *testing.T) {
	ix := Compile([]Zone{z(1, "example")}, []Record{
		r("*.example", TypeTXT, "this is a wildcard"),
		mx("*.example", 10, "host1.example"),
		r("sub.*.example", TypeTXT, "this is not a wildcard"),
		r("host1.example", TypeA, "192.0.2.1"),
		srv("_ssh._tcp.host1.example", "host1.example", 22),
		srv("_ssh._tcp.host2.example", "host2.example", 22),
	})
	nodata := []string{soaExample}
	runCases(t, ix, false, []lookupCase{
		// Synthesized from *.example; the MX target's address goes to the additional section.
		{qname: "host3.example.", qtype: dns.TypeMX, found: true, aa: true,
			answer: []string{"host3.example. 60 MX 10 host1.example."},
			extra:  []string{"host1.example. 60 A 192.0.2.1"}, reason: ReasonZone},
		{qname: "host3.example.", qtype: dns.TypeA, found: true, aa: true, ns: nodata},
		{qname: "foo.bar.example.", qtype: dns.TypeTXT, found: true, aa: true,
			answer: []string{`foo.bar.example. 60 TXT "this is a wildcard"`}},
		// host1.example exists: no wildcard.
		{qname: "host1.example.", qtype: dns.TypeMX, found: true, aa: true, ns: nodata},
		{qname: "sub.*.example.", qtype: dns.TypeMX, found: true, aa: true, ns: nodata},
		// Closest encloser _tcp.host1.example (empty non-terminal) has no wildcard child.
		{qname: "_telnet._tcp.host1.example.", qtype: dns.TypeSRV, found: true, aa: true,
			rcode: dns.RcodeNameError, ns: nodata},
		// Closest encloser *.example; *.*.example does not exist.
		{qname: "ghost.*.example.", qtype: dns.TypeMX, found: true, aa: true, rcode: dns.RcodeNameError, ns: nodata},
		// Empty non-terminals exist: NODATA, the wildcard does not apply.
		{qname: "host2.example.", qtype: dns.TypeA, found: true, aa: true, ns: nodata},
		{qname: "_tcp.host1.example.", qtype: dns.TypeA, found: true, aa: true, ns: nodata},
		// The wildcard owner itself is an ordinary name.
		{qname: "*.example.", qtype: dns.TypeTXT, found: true, aa: true,
			answer: []string{`*.example. 60 TXT "this is a wildcard"`}},
		{qname: "_ssh._tcp.host1.example", qtype: dns.TypeSRV, found: true, aa: true,
			answer: []string{"_ssh._tcp.host1.example. 60 SRV 1 2 22 host1.example."},
			extra:  []string{"host1.example. 60 A 192.0.2.1"}},
		// The wildcard does not cover the encloser (apex).
		{qname: "example.", qtype: dns.TypeTXT, found: true, aa: true, ns: nodata},
		{qname: "example.", qtype: dns.TypeSOA, found: true, aa: true, answer: nodata},
		{qname: "example.", qtype: dns.TypeNS, found: true, aa: true, answer: []string{"example. 300 NS ns.example."}},
	})
}

func TestZoneAnswers(t *testing.T) {
	cn := r("www.home.lan", TypeCNAME, "nas.home.lan")
	zones := []Zone{z(1, "home.lan")}
	zones[0].PrimaryNS = "ns.home.lan"
	ix := Compile(zones, []Record{
		r("nas.home.lan", TypeA, "192.168.1.10"),
		r("nas.home.lan", TypeAAAA, "fd00::10"),
		r("ns.home.lan", TypeA, "192.168.1.1"),
		cn,
		r("home.lan", TypeA, "192.168.1.2"),
		r("home.lan", TypeCNAME, "elsewhere.example"), // invalid at the apex: skipped
		mx("home.lan", 20, "mx2.home.lan"),
		mx("home.lan", 10, "nas.home.lan"),
		r("a.b.home.lan", TypeA, "192.168.1.30"),
		disabled(r("off.home.lan", TypeA, "192.168.1.40")),
	})
	soa := "home.lan. 300 SOA ns.home.lan. hostmaster.home.lan. 2026110901 3600 600 604800 300"
	runCases(t, ix, false, []lookupCase{
		{qname: "nas.home.lan", qtype: dns.TypeA, found: true, aa: true, answer: []string{"nas.home.lan. 60 A 192.168.1.10"}},
		// Owner name keeps the case of the question (0x20).
		{qname: "NaS.HoMe.LaN.", qtype: dns.TypeAAAA, found: true, aa: true, answer: []string{"NaS.HoMe.LaN. 60 AAAA fd00::10"}},
		{qname: "nas.home.lan", qtype: dns.TypeTXT, found: true, aa: true, ns: []string{soa}},
		{qname: "missing.home.lan", qtype: dns.TypeA, found: true, aa: true, rcode: dns.RcodeNameError, ns: []string{soa}},
		{qname: "off.home.lan", qtype: dns.TypeA, found: true, aa: true, rcode: dns.RcodeNameError, ns: []string{soa}},
		// CNAME at the name for another type: only the CNAME, the target is chased by the caller.
		{qname: "WWW.home.lan", qtype: dns.TypeA, found: true, aa: true,
			answer: []string{"WWW.home.lan. 60 CNAME nas.home.lan."}, target: "nas.home.lan"},
		{qname: "www.home.lan", qtype: dns.TypeCNAME, found: true, aa: true,
			answer: []string{"www.home.lan. 60 CNAME nas.home.lan."}},
		// Apex: SOA/NS synthesized, records next to them, MX sorted by priority with additional.
		{qname: "home.lan", qtype: dns.TypeSOA, found: true, aa: true, answer: []string{soa}},
		{qname: "home.lan", qtype: dns.TypeNS, found: true, aa: true,
			answer: []string{"home.lan. 300 NS ns.home.lan."}, extra: []string{"ns.home.lan. 60 A 192.168.1.1"}},
		{qname: "home.lan", qtype: dns.TypeA, found: true, aa: true, answer: []string{"home.lan. 60 A 192.168.1.2"}},
		{qname: "home.lan", qtype: dns.TypeCNAME, found: true, aa: true, ns: []string{soa}},
		{qname: "home.lan", qtype: dns.TypeMX, found: true, aa: true,
			answer: []string{"home.lan. 60 MX 10 nas.home.lan.", "home.lan. 60 MX 20 mx2.home.lan."},
			extra:  []string{"nas.home.lan. 60 A 192.168.1.10", "nas.home.lan. 60 AAAA fd00::10"}},
		{qname: "home.lan", qtype: dns.TypeANY, found: true, aa: true,
			answer: []string{soa, "home.lan. 300 NS ns.home.lan.", "home.lan. 60 A 192.168.1.2",
				"home.lan. 60 MX 10 nas.home.lan.", "home.lan. 60 MX 20 mx2.home.lan."},
			extra: []string{"ns.home.lan. 60 A 192.168.1.1", "nas.home.lan. 60 A 192.168.1.10", "nas.home.lan. 60 AAAA fd00::10"}},
		// Empty non-terminal.
		{qname: "b.home.lan", qtype: dns.TypeA, found: true, aa: true, ns: []string{soa}},
		{qname: "x.b.home.lan", qtype: dns.TypeA, found: true, aa: true, rcode: dns.RcodeNameError, ns: []string{soa}},
		// DNSSEC types: NODATA; zone transfers refused.
		{qname: "home.lan", qtype: dns.TypeDS, found: true, aa: true, ns: []string{soa}},
		{qname: "nas.home.lan", qtype: dns.TypeDNSKEY, found: true, aa: true, ns: []string{soa}},
		{qname: "nas.home.lan", qtype: dns.TypeRRSIG, found: true, aa: true, ns: []string{soa}},
		{qname: "home.lan", qtype: dns.TypeAXFR, found: true, aa: false, rcode: dns.RcodeRefused},
		{qname: "home.lan", qtype: dns.TypeIXFR, found: true, aa: false, rcode: dns.RcodeRefused},
		// Outside the zone: not ours.
		{qname: "example.com", qtype: dns.TypeA, found: false},
		{qname: "example.com", qtype: dns.TypeAXFR, found: false},
		{qname: "lan", qtype: dns.TypeA, found: false},
		{qname: "xhome.lan", qtype: dns.TypeA, found: false},
		{qname: ".", qtype: dns.TypeNS, found: false},
	})
	if ix.ZoneCount() != 1 || ix.RecordCount() != 8 || ix.RewriteCount() != 6 {
		t.Fatalf("counts = %d %d %d", ix.ZoneCount(), ix.RecordCount(), ix.RewriteCount())
	}
}

func TestZoneWildcards(t *testing.T) {
	ix := Compile([]Zone{z(1, "home.lan")}, []Record{
		r("*.home.lan", TypeA, "10.0.0.1"),
		r("nas.home.lan", TypeAAAA, "fd00::1"),
		r("deep.x.home.lan", TypeA, "10.0.0.2"),
		r("*.c.home.lan", TypeCNAME, "nas.home.lan"),
	})
	soa := "home.lan. 300 SOA ns.home.lan. hostmaster.home.lan. 2026110901 3600 600 604800 300"
	runCases(t, ix, false, []lookupCase{
		{qname: "other.home.lan", qtype: dns.TypeA, found: true, aa: true, answer: []string{"other.home.lan. 60 A 10.0.0.1"}},
		{qname: "a.b.home.lan", qtype: dns.TypeA, found: true, aa: true, answer: []string{"a.b.home.lan. 60 A 10.0.0.1"}},
		{qname: "other.home.lan", qtype: dns.TypeAAAA, found: true, aa: true, ns: []string{soa}},
		// Existing name: the wildcard does not match.
		{qname: "nas.home.lan", qtype: dns.TypeA, found: true, aa: true, ns: []string{soa}},
		// Not the encloser itself.
		{qname: "home.lan", qtype: dns.TypeA, found: true, aa: true, ns: []string{soa}},
		// x.home.lan is an empty non-terminal: NODATA; below it the closest encloser is x.home.lan.
		{qname: "x.home.lan", qtype: dns.TypeA, found: true, aa: true, ns: []string{soa}},
		{qname: "y.x.home.lan", qtype: dns.TypeA, found: true, aa: true, rcode: dns.RcodeNameError, ns: []string{soa}},
		// Wildcard CNAME: synthesized with the query name.
		{qname: "Pc.C.home.lan", qtype: dns.TypeA, found: true, aa: true,
			answer: []string{"Pc.C.home.lan. 60 CNAME nas.home.lan."}, target: "nas.home.lan"},
		// c.home.lan exists as empty non-terminal (the wildcard below it).
		{qname: "c.home.lan", qtype: dns.TypeA, found: true, aa: true, ns: []string{soa}},
	})
}

func TestNestedAndDisabledZones(t *testing.T) {
	recs := []Record{
		r("nas.home.lan", TypeA, "10.0.1.1"),
		r("x.lan", TypeA, "10.0.0.1"),
		r("pc.off.lan", TypeA, "10.0.2.1"),
	}
	zones := []Zone{z(1, "lan"), z(2, "home.lan"), z(3, "off.lan"), z(4, "solo.example")}
	zones[2].Enabled = false
	zones[3].Enabled = false
	soaLan := "lan. 300 SOA ns.lan. hostmaster.lan. 2026110901 3600 600 604800 300"
	soaHome := "home.lan. 300 SOA ns.home.lan. hostmaster.home.lan. 2026110901 3600 600 604800 300"
	ix := Compile(zones, append(recs, r("pc.solo.example", TypeA, "10.0.3.1")))
	runCases(t, ix, false, []lookupCase{
		{qname: "nas.home.lan", qtype: dns.TypeA, found: true, aa: true, answer: []string{"nas.home.lan. 60 A 10.0.1.1"}},
		{qname: "y.home.lan", qtype: dns.TypeA, found: true, aa: true, rcode: dns.RcodeNameError, ns: []string{soaHome}},
		{qname: "x.lan", qtype: dns.TypeA, found: true, aa: true, answer: []string{"x.lan. 60 A 10.0.0.1"}},
		// home.lan is not an empty non-terminal of lan: it is its own zone.
		{qname: "home.lan", qtype: dns.TypeSOA, found: true, aa: true, answer: []string{soaHome}},
		// off.lan is disabled: its records are ignored entirely, lan answers.
		{qname: "pc.off.lan", qtype: dns.TypeA, found: true, aa: true, rcode: dns.RcodeNameError, ns: []string{soaLan}},
		{qname: "off.lan", qtype: dns.TypeA, found: true, aa: true, rcode: dns.RcodeNameError, ns: []string{soaLan}},
		// A disabled zone without an enabled parent: not ours, and its records are not single records.
		{qname: "pc.solo.example", qtype: dns.TypeA, found: false},
	})
	if ix.ZoneCount() != 2 || ix.RecordCount() != 2 {
		t.Fatalf("counts = %d %d", ix.ZoneCount(), ix.RecordCount())
	}

	// home.lan disabled: lan answers NXDOMAIN for its names.
	zones[1].Enabled = false
	ix = Compile(zones, recs)
	runCases(t, ix, false, []lookupCase{
		{qname: "nas.home.lan", qtype: dns.TypeA, found: true, aa: true, rcode: dns.RcodeNameError, ns: []string{soaLan}},
	})
}

func TestSingleRecords(t *testing.T) {
	ix := Compile(nil, []Record{
		r("nas.lan", TypeA, "192.168.1.10"),
		r("*.lan", TypeA, "192.168.1.1"),
		r("*.b.lan", TypeA, "192.168.1.2"),
		r("exact.b.lan", TypeTXT, "hi"),
		r("tv.lan", TypeCNAME, "nas.lan"),
		r("ext.example", TypeCNAME, "Target.Example.ORG"),
		mx("mail.example", 5, "nas.lan"),
		disabled(r("off.example", TypeA, "10.0.0.1")),
	})
	runCases(t, ix, false, []lookupCase{
		{qname: "nas.lan", qtype: dns.TypeA, found: true, answer: []string{"nas.lan. 60 A 192.168.1.10"}, reason: ReasonRecord},
		// Records but none of this type: empty NOERROR without SOA.
		{qname: "nas.lan", qtype: dns.TypeAAAA, found: true},
		{qname: "x.lan", qtype: dns.TypeA, found: true, answer: []string{"x.lan. 60 A 192.168.1.1"}},
		// The most specific wildcard wins, exact beats wildcard.
		{qname: "a.b.lan", qtype: dns.TypeA, found: true, answer: []string{"a.b.lan. 60 A 192.168.1.2"}},
		{qname: "z.a.b.lan", qtype: dns.TypeA, found: true, answer: []string{"z.a.b.lan. 60 A 192.168.1.2"}},
		// Other types of a single record name are not ours: they go upstream.
		{qname: "exact.b.lan", qtype: dns.TypeA, found: false},
		// "*.lan" matches names below lan only.
		{qname: "lan", qtype: dns.TypeA, found: false},
		{qname: "tv.lan", qtype: dns.TypeA, found: true, answer: []string{"tv.lan. 60 CNAME nas.lan."}, target: "nas.lan"},
		{qname: "ext.example", qtype: dns.TypeA, found: true, answer: []string{"ext.example. 60 CNAME target.example.org."},
			target: "target.example.org"},
		{qname: "mail.example", qtype: dns.TypeMX, found: true, answer: []string{"mail.example. 60 MX 5 nas.lan."},
			extra: []string{"nas.lan. 60 A 192.168.1.10"}},
		{qname: "off.example", qtype: dns.TypeA, found: false},
		{qname: "example.org", qtype: dns.TypeA, found: false},
		// No zone transfers.
		{qname: "nas.lan", qtype: dns.TypeAXFR, found: true, rcode: dns.RcodeRefused},
	})
	var nilIx *Index
	if nilIx.Lookup("nas.lan", dns.TypeA).Found || nilIx.Resolve("nas.lan", dns.TypeA).Found || nilIx.RecordCount() != 0 {
		t.Fatal("nil index answers")
	}
}

func TestResolveChains(t *testing.T) {
	recs := []Record{
		r("www.home.lan", TypeCNAME, "web.lan"),
		r("web.lan", TypeCNAME, "nas.home.lan"),
		r("nas.home.lan", TypeA, "10.0.0.1"),
		r("ext.home.lan", TypeCNAME, "www.example.com"),
		r("dead.home.lan", TypeCNAME, "missing.home.lan"),
		r("loop1.lan", TypeCNAME, "loop2.lan"),
		r("loop2.lan", TypeCNAME, "loop1.lan"),
		mx("m.lan", 1, "nas.home.lan"),
		r("mx.lan", TypeCNAME, "m.lan"),
	}
	for i := 1; i <= 6; i++ {
		recs = append(recs, r(fmt.Sprintf("c%d.lan", i), TypeCNAME, fmt.Sprintf("c%d.lan", i+1)))
	}
	recs = append(recs, r("c7.lan", TypeA, "10.0.0.7"))
	ix := Compile([]Zone{z(1, "home.lan")}, recs)
	soa := "home.lan. 300 SOA ns.home.lan. hostmaster.home.lan. 2026110901 3600 600 604800 300"
	runCases(t, ix, true, []lookupCase{
		{qname: "WWW.home.lan", qtype: dns.TypeA, found: true, aa: true, answer: []string{
			"WWW.home.lan. 60 CNAME web.lan.", "web.lan. 60 CNAME nas.home.lan.", "nas.home.lan. 60 A 10.0.0.1"}},
		// Target outside the index: left to the upstream.
		{qname: "ext.home.lan", qtype: dns.TypeA, found: true, aa: true,
			answer: []string{"ext.home.lan. 60 CNAME www.example.com."}, target: "www.example.com"},
		// Target inside the zone does not exist: NXDOMAIN of the last name (RFC 6604).
		{qname: "dead.home.lan", qtype: dns.TypeA, found: true, aa: true, rcode: dns.RcodeNameError,
			answer: []string{"dead.home.lan. 60 CNAME missing.home.lan."}, ns: []string{soa}},
		{qname: "loop1.lan", qtype: dns.TypeA, found: true, rcode: dns.RcodeServerFailure},
		// Six CNAMEs: more than MaxCNAMEDepth.
		{qname: "c1.lan", qtype: dns.TypeA, found: true, rcode: dns.RcodeServerFailure},
		{qname: "c2.lan", qtype: dns.TypeA, found: true, answer: []string{
			"c2.lan. 60 CNAME c3.lan.", "c3.lan. 60 CNAME c4.lan.", "c4.lan. 60 CNAME c5.lan.",
			"c5.lan. 60 CNAME c6.lan.", "c6.lan. 60 CNAME c7.lan.", "c7.lan. 60 A 10.0.0.7"}},
		{qname: "mx.lan", qtype: dns.TypeMX, found: true, answer: []string{"mx.lan. 60 CNAME m.lan.", "m.lan. 60 MX 1 nas.home.lan."},
			extra: []string{"nas.home.lan. 60 A 10.0.0.1"}},
	})
	if res := ix.Resolve("c2.lan", dns.TypeA); res.Depth != 5 {
		t.Fatalf("depth = %d", res.Depth)
	}
}

func TestTXTSplit(t *testing.T) {
	long := strings.Repeat("a", 254) + "ü" + strings.Repeat("b", 300) + `\"x`
	ix := Compile(nil, []Record{r("t.lan", TypeTXT, long)})
	res := ix.Lookup("t.lan", dns.TypeTXT)
	if len(res.Answer) != 1 {
		t.Fatalf("answer %v", res.Answer)
	}
	txt := res.Answer[0].(*dns.TXT)
	if len(txt.Txt) != 3 || len(txt.Txt[0]) != 254 || !strings.HasPrefix(txt.Txt[1], "ü") {
		t.Fatalf("split = %q", txt.Txt)
	}
	// Wire round trip: every string ≤ 255 bytes, the bytes are the value.
	m := new(dns.Msg)
	m.SetQuestion("t.lan.", dns.TypeTXT)
	m.Answer = res.Answer
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var back dns.Msg
	if err := back.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, s := range back.Answer[0].(*dns.TXT).Txt {
		sb.WriteString(s)
	}
	unescaped := unescapeTXT(sb.String())
	if unescaped != long {
		t.Fatalf("round trip = %q", unescaped)
	}
	if got := SplitTXT(strings.Repeat("x", 600)); len(got) != 3 || len(got[0]) != 255 || len(got[2]) != 90 {
		t.Fatalf("SplitTXT lengths %d", len(got))
	}
}

func TestAutoPTR(t *testing.T) {
	recs := []Record{
		ptr(r("nas.home.lan", TypeA, "192.168.1.10")),
		ptr(r("nas.lan", TypeA, "192.168.1.10")),
		ptr(r("v6.home.lan", TypeAAAA, "fd00::10")),
		r("noptr.home.lan", TypeA, "192.168.1.11"),
		ptr(disabled(r("off.home.lan", TypeA, "192.168.1.12"))),
		ptr(r("*.home.lan", TypeA, "192.168.1.13")),
		ptr(r("printer.home.lan", TypeA, "192.168.1.20")),
		r("20.1.168.192.in-addr.arpa", TypePTR, "explicit.home.lan"),
	}
	rev6 := "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa."
	ix := Compile([]Zone{z(1, "home.lan")}, recs)
	runCases(t, ix, false, []lookupCase{
		// No reverse zone: single answer, all names of the address.
		{qname: "10.1.168.192.in-addr.arpa.", qtype: dns.TypePTR, found: true, reason: ReasonRecord, answer: []string{
			"10.1.168.192.in-addr.arpa. 60 PTR nas.home.lan.", "10.1.168.192.in-addr.arpa. 60 PTR nas.lan."}},
		{qname: "10.1.168.192.in-addr.arpa.", qtype: dns.TypeA, found: false},
		{qname: rev6, qtype: dns.TypePTR, found: true, answer: []string{rev6 + " 60 PTR v6.home.lan."}},
		{qname: "11.1.168.192.in-addr.arpa.", qtype: dns.TypePTR, found: false},
		{qname: "12.1.168.192.in-addr.arpa.", qtype: dns.TypePTR, found: false},
		{qname: "13.1.168.192.in-addr.arpa.", qtype: dns.TypePTR, found: false},
		// The explicit PTR wins.
		{qname: "20.1.168.192.in-addr.arpa.", qtype: dns.TypePTR, found: true, answer: []string{
			"20.1.168.192.in-addr.arpa. 60 PTR explicit.home.lan."}},
	})

	// With a reverse zone the answers are authoritative.
	ix = Compile([]Zone{z(1, "home.lan"), z(2, "168.192.in-addr.arpa")}, recs)
	soa := "168.192.in-addr.arpa. 300 SOA ns.168.192.in-addr.arpa. hostmaster.168.192.in-addr.arpa. 2026110901 3600 600 604800 300"
	runCases(t, ix, false, []lookupCase{
		{qname: "10.1.168.192.in-addr.arpa.", qtype: dns.TypePTR, found: true, aa: true, reason: ReasonZone, answer: []string{
			"10.1.168.192.in-addr.arpa. 60 PTR nas.home.lan.", "10.1.168.192.in-addr.arpa. 60 PTR nas.lan."}},
		{qname: "11.1.168.192.in-addr.arpa.", qtype: dns.TypePTR, found: true, aa: true, rcode: dns.RcodeNameError, ns: []string{soa}},
		{qname: "1.168.192.in-addr.arpa.", qtype: dns.TypePTR, found: true, aa: true, ns: []string{soa}},
		{qname: "20.1.168.192.in-addr.arpa.", qtype: dns.TypePTR, found: true, aa: true, answer: []string{
			"20.1.168.192.in-addr.arpa. 60 PTR explicit.home.lan."}},
	})

	// A disabled reverse zone: its names are not served, synthesized PTRs neither.
	zones := []Zone{z(1, "home.lan"), z(2, "168.192.in-addr.arpa")}
	zones[1].Enabled = false
	ix = Compile(zones, recs)
	runCases(t, ix, false, []lookupCase{
		{qname: "10.1.168.192.in-addr.arpa.", qtype: dns.TypePTR, found: false},
	})
}

func TestCompileTolerantInput(t *testing.T) {
	ix := Compile([]Zone{z(1, "Home.LAN."), z(2, "home.lan"), {ID: 3}}, []Record{
		r("NAS.Home.Lan.", "a", "10.0.0.1"),
		r("bad.home.lan", TypeA, "not-an-ip"),
		r("bad6.home.lan", TypeAAAA, "10.0.0.1"),
		r("", TypeA, "10.0.0.1"),
		r("t.home.lan", TypeTXT, ""),
		r("u.home.lan", "NS", "x"),
	})
	if ix.ZoneCount() != 1 || ix.RecordCount() != 1 {
		t.Fatalf("counts %d %d", ix.ZoneCount(), ix.RecordCount())
	}
	if res := ix.Lookup("nas.home.lan", dns.TypeA); len(res.Answer) != 1 {
		t.Fatalf("answer %v", res.Answer)
	}
}

func TestConcurrentLookups(t *testing.T) {
	ix := Compile([]Zone{z(1, "home.lan")}, []Record{
		r("nas.home.lan", TypeA, "10.0.0.1"),
		r("www.home.lan", TypeCNAME, "nas.home.lan"),
		mx("home.lan", 10, "nas.home.lan"),
		ptr(r("pc.lan", TypeA, "10.0.0.2")),
		r("*.home.lan", TypeTXT, "w"),
	})
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				for _, q := range []struct {
					n string
					t uint16
				}{{"nas.home.lan", dns.TypeA}, {"WWW.home.lan", dns.TypeA}, {"home.lan", dns.TypeMX},
					{"2.0.0.10.in-addr.arpa", dns.TypePTR}, {fmt.Sprintf("x%d.home.lan", i), dns.TypeTXT},
					{"missing.x.home.lan", dns.TypeA}, {"home.lan", dns.TypeSOA}} {
					res := ix.Resolve(q.n, q.t)
					if !res.Found {
						t.Errorf("%s not found", q.n)
						return
					}
					// Callers may modify what they get: answers are copies.
					for _, rr := range append(append(res.Answer, res.Ns...), res.Extra...) {
						rr.Header().Ttl = uint32(g)
						rr.Header().Name = "changed."
					}
				}
			}
		}(g)
	}
	wg.Wait()
	if got := fmtRRs(ix.Lookup("home.lan", dns.TypeSOA).Answer); got[0] != "home.lan. 300 SOA ns.home.lan. hostmaster.home.lan. 2026110901 3600 600 604800 300" {
		t.Fatalf("template changed: %v", got)
	}
}

// unescapeTXT reverses the presentation escapes of miekg/dns (\DDD and \X).
func unescapeTXT(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			out = append(out, s[i])
			continue
		}
		if i+3 < len(s) && isDigit(s[i+1]) && isDigit(s[i+2]) && isDigit(s[i+3]) {
			out = append(out, (s[i+1]-'0')*100+(s[i+2]-'0')*10+(s[i+3]-'0'))
			i += 3
			continue
		}
		out = append(out, s[i+1])
		i++
	}
	return string(out)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
