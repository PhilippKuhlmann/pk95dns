package dnsserver

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
)

// Own zones and records (pipeline step 5, docs/design.md → Local zones and records), all
// through ServeDNS. Test data: helpers_test.go → testZones, testRecords.

// rrStrings renders RRs as "TYPE data" without owner and TTL.
func rrStrings(rrs []dns.RR) []string {
	var out []string
	for _, r := range rrs {
		h := r.Header()
		if h.Rrtype == dns.TypeOPT {
			continue
		}
		out = append(out, dns.TypeToString[h.Rrtype]+" "+strings.TrimSpace(strings.TrimPrefix(r.String(), h.String())))
	}
	return out
}

const corpSOA = "SOA ns.corp.lan. hostmaster.corp.lan. 2026110901 3600 600 604800 120"

func TestZoneAnswers(t *testing.T) {
	tests := []struct {
		name    string
		qname   string
		qtype   uint16
		rcode   int
		answer  []string
		ns      []string
		extra   []string
		summary string
	}{
		{"A", "www.corp.lan", dns.TypeA, 0, []string{"A 10.0.0.80"}, nil, nil, "10.0.0.80"},
		{"AAAA", "www.corp.lan", dns.TypeAAAA, 0, []string{"AAAA fd00::80"}, nil, nil, "fd00::80"},
		{"apex SOA", "corp.lan", dns.TypeSOA, 0, []string{corpSOA}, nil, nil, "SOA ns.corp.lan. hostmaster.corp.lan. 2026110901 3600 600 604800 120"},
		{"apex NS with glue", "corp.lan", dns.TypeNS, 0, []string{"NS ns.corp.lan."}, nil, []string{"A 10.0.0.53"}, "NS ns.corp.lan"},
		{"apex MX", "corp.lan", dns.TypeMX, 0, []string{"MX 20 mx.corp.lan."}, nil, []string{"A 10.0.0.25"}, "MX 20 mx.corp.lan"},
		{"apex TXT", "corp.lan", dns.TypeTXT, 0, []string{`TXT "v=spf1 mx -all"`}, nil, nil, `TXT "v=spf1 mx -all"`},
		{"apex A NODATA", "corp.lan", dns.TypeA, 0, nil, []string{corpSOA}, nil, ""},
		{"NXDOMAIN", "nope.corp.lan", dns.TypeA, dns.RcodeNameError, nil, []string{corpSOA}, nil, ""},
		{"NODATA", "www.corp.lan", dns.TypeMX, 0, nil, []string{corpSOA}, nil, ""},
		{"empty non-terminal", "b.corp.lan", dns.TypeA, 0, nil, []string{corpSOA}, nil, ""},
		{"below a record", "x.a.b.corp.lan", dns.TypeA, dns.RcodeNameError, nil, []string{corpSOA}, nil, ""},
		{"wildcard", "x.dyn.corp.lan", dns.TypeA, 0, []string{"A 10.0.0.99"}, nil, nil, "10.0.0.99"},
		{"wildcard deep", "x.y.dyn.corp.lan", dns.TypeA, 0, []string{"A 10.0.0.99"}, nil, nil, "10.0.0.99"},
		{"wildcard other type", "x.dyn.corp.lan", dns.TypeAAAA, 0, nil, []string{corpSOA}, nil, ""},
		{"existing name beats wildcard", "fixed.dyn.corp.lan", dns.TypeA, 0, []string{"A 10.0.0.98"}, nil, nil, "10.0.0.98"},
		{"wildcard not for existing name", "fixed.dyn.corp.lan", dns.TypeAAAA, 0, nil, []string{corpSOA}, nil, ""},
		{"wildcard not for the encloser", "dyn.corp.lan", dns.TypeA, 0, nil, []string{corpSOA}, nil, ""},
		{"MX with additional", "mail.corp.lan", dns.TypeMX, 0, []string{"MX 10 mx.corp.lan."}, nil, []string{"A 10.0.0.25"}, "MX 10 mx.corp.lan"},
		{"SRV with additional", "_ldap._tcp.corp.lan", dns.TypeSRV, 0, []string{"SRV 0 5 389 ldap.corp.lan."}, nil, []string{"A 10.0.0.89"}, "SRV 0 5 389 ldap.corp.lan"},
		{"CNAME inside the zone", "alias.corp.lan", dns.TypeA, 0, []string{"CNAME www.corp.lan.", "A 10.0.0.80"}, nil, nil, "CNAME www.corp.lan, 10.0.0.80"},
		{"CNAME qtype CNAME", "alias.corp.lan", dns.TypeCNAME, 0, []string{"CNAME www.corp.lan."}, nil, nil, "CNAME www.corp.lan"},
		{"chain of 5", "c2.corp.lan", dns.TypeA, 0, []string{"CNAME c3.corp.lan.", "CNAME c4.corp.lan.", "CNAME c5.corp.lan.", "CNAME c6.corp.lan.", "CNAME www.corp.lan.", "A 10.0.0.80"}, nil, nil, ""},
		{"chain of 6 is SERVFAIL", "c1.corp.lan", dns.TypeA, dns.RcodeServerFailure, nil, nil, nil, ""},
		{"loop is SERVFAIL", "l1.corp.lan", dns.TypeA, dns.RcodeServerFailure, nil, nil, nil, ""},
		{"disabled record", "disabled.corp.lan", dns.TypeA, dns.RcodeNameError, nil, []string{corpSOA}, nil, ""},
		{"DS NODATA", "corp.lan", dns.TypeDS, 0, nil, []string{corpSOA}, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, nil)
			resp, l := e.query(tt.qname, tt.qtype)
			if resp.Rcode != tt.rcode {
				t.Fatalf("rcode %s, want %s", dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.rcode])
			}
			if !resp.Authoritative {
				t.Fatal("AA bit missing")
			}
			if got := rrStrings(resp.Answer); !slices.Equal(got, tt.answer) {
				t.Fatalf("answer %v, want %v", got, tt.answer)
			}
			if got := rrStrings(resp.Ns); !slices.Equal(got, tt.ns) {
				t.Fatalf("authority %v, want %v", got, tt.ns)
			}
			if got := rrStrings(resp.Extra); !slices.Equal(got, tt.extra) {
				t.Fatalf("additional %v, want %v", got, tt.extra)
			}
			for _, r := range resp.Ns {
				if r.Header().Ttl != 120 {
					t.Fatalf("SOA TTL %d, want the zone TTL", r.Header().Ttl)
				}
			}
			if l.q.Status != "rewrite" || l.q.Reason != "zone" || l.q.Upstream != "" || l.q.Cached {
				t.Fatalf("log %+v", l.q)
			}
			if tt.summary != "" && l.q.Answer != tt.summary {
				t.Fatalf("summary %q, want %q", l.q.Answer, tt.summary)
			}
			if l.q.Rcode != dns.RcodeToString[tt.rcode] {
				t.Fatalf("log rcode %q", l.q.Rcode)
			}
			for _, n := range []string{tt.qname, "www.corp.lan", "mx.corp.lan"} {
				if e.up.count(n, tt.qtype) != 0 {
					t.Fatalf("upstream asked for %s", n)
				}
			}
		})
	}
}

func TestZoneANY(t *testing.T) {
	// refuse_any (default) comes first.
	e := newEnv(t, nil)
	resp, l := e.query("www.corp.lan", dns.TypeANY)
	if resp.Rcode != dns.RcodeNotImplemented || l.q.Status != "refused" || l.q.Reason != "any" {
		t.Fatalf("refuse_any %v %+v", resp, l.q)
	}
	e.update(func(s *config.Settings) { s.RefuseAny = false })
	resp, l = e.query("www.corp.lan", dns.TypeANY)
	if got := answers(resp); !slices.Equal(got, []string{"A 10.0.0.80", "AAAA fd00::80"}) || !resp.Authoritative || l.q.Reason != "zone" {
		t.Fatalf("ANY %v %+v", got, l.q)
	}
}

func TestZoneOwnerCase(t *testing.T) {
	e := newEnv(t, nil)
	resp, l := e.query("WwW.CoRp.LaN", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].Header().Name != "WwW.CoRp.LaN." || resp.Question[0].Name != "WwW.CoRp.LaN." {
		t.Fatalf("0x20 case lost: %v", resp)
	}
	if l.q.Name != "www.corp.lan" {
		t.Fatalf("log name %q", l.q.Name)
	}
	// A wildcard answer carries the query name too.
	resp, _ = e.query("Host.DYN.corp.lan", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].Header().Name != "Host.DYN.corp.lan." {
		t.Fatalf("wildcard owner %v", resp.Answer)
	}
}

func TestZoneCNAMEToUpstream(t *testing.T) {
	e := newEnv(t, nil)
	resp, l := e.query("out.corp.lan", dns.TypeA)
	if got := answers(resp); !slices.Equal(got, []string{"CNAME target.example.", "A 192.0.2.1"}) {
		t.Fatalf("answer %v", got)
	}
	if !resp.Authoritative || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("flags %v", resp)
	}
	if l.q.Status != "rewrite" || l.q.Reason != "zone" || l.q.Upstream != e.up.addr || l.q.Answer != "CNAME target.example, 192.0.2.1" {
		t.Fatalf("log %+v", l.q)
	}
	if e.up.count("target.example", dns.TypeA) != 1 || e.up.count("out.corp.lan", dns.TypeA) != 0 {
		t.Fatal("upstream questions")
	}
	// The target's answer comes from the cache the second time; the local part is never cached.
	_, l = e.query("out.corp.lan", dns.TypeA)
	if !l.q.Cached || e.up.count("target.example", dns.TypeA) != 1 {
		t.Fatalf("second query %+v", l.q)
	}

	// NXDOMAIN of the target: rcode and authority of the upstream.
	resp, l = e.query("outnx.corp.lan", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError || !slices.Equal(answers(resp), []string{"CNAME nx.example."}) || len(resp.Ns) != 1 {
		t.Fatalf("nx target %v", resp)
	}
	if l.q.Status != "rewrite" || l.q.Rcode != "NXDOMAIN" {
		t.Fatalf("log %+v", l.q)
	}

	// The target is not filtered (blockedtarget.lan → ads.example, on the block list).
	resp, l = e.query("blockedtarget.lan", dns.TypeA)
	if got := answers(resp); !slices.Equal(got, []string{"CNAME ads.example.", "A 192.0.2.1"}) || l.q.Status != "rewrite" {
		t.Fatalf("blocked target %v %+v", got, l.q)
	}

	// A single CNAME into a zone: resolved from the index, no AA (the answer starts outside).
	resp, l = e.query("tozone.lan", dns.TypeA)
	if got := answers(resp); !slices.Equal(got, []string{"CNAME www.corp.lan.", "A 10.0.0.80"}) || resp.Authoritative || l.q.Reason != "record" {
		t.Fatalf("single → zone %v %+v", got, l.q)
	}
	if e.up.count("www.corp.lan", dns.TypeA) != 0 {
		t.Fatal("zone name asked upstream")
	}
}

func TestZoneTXTSplit(t *testing.T) {
	e := newEnv(t, nil)
	resp, l := e.query("long.corp.lan", dns.TypeTXT, overTCP("192.168.1.20"))
	if len(resp.Answer) != 1 || resp.Truncated {
		t.Fatalf("answer %v", resp)
	}
	txt := resp.Answer[0].(*dns.TXT)
	if len(txt.Txt) != 3 || len(txt.Txt[0]) != 255 || len(txt.Txt[1]) != 255 || len(txt.Txt[2]) != 90 {
		t.Fatalf("strings %d", len(txt.Txt))
	}
	if strings.Join(txt.Txt, "") != longTXT {
		t.Fatal("TXT value changed on the wire")
	}
	if want := `TXT "` + longTXT[:maxTXTText] + `…"`; l.q.Answer != want {
		t.Fatalf("summary %q", l.q.Answer)
	}
	// Plain UDP (512 bytes): truncated, the client retries over TCP.
	resp, _ = e.query("long.corp.lan", dns.TypeTXT)
	if !resp.Truncated || !resp.Authoritative {
		t.Fatalf("UDP answer not truncated: %v", resp)
	}
	// EDNS: fits, OPT echoed.
	resp, _ = e.query("long.corp.lan", dns.TypeTXT, withEDNS(1232, false))
	if resp.Truncated || len(resp.Answer) != 1 || resp.IsEdns0() == nil || resp.IsEdns0().UDPSize() != 1232 {
		t.Fatalf("EDNS answer %v", resp)
	}
}

func TestReverseLookups(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) {
		s.PrivatePTR = true
		s.PrivateUpstreams = []string{} // set below (needs the test upstream address)
	})
	e.update(func(s *config.Settings) { s.PrivateUpstreams = []string{e.up.addr} })
	rev6, _ := dns.ReverseAddr("fd00::80")
	tests := []struct {
		name   string
		qname  string
		rcode  int
		answer []string
		aa     bool
		reason string
	}{
		{"auto PTR v4 (single record)", "80.0.0.10.in-addr.arpa", 0, []string{"PTR www.corp.lan."}, false, "record"},
		{"auto PTR v6", rev6, 0, []string{"PTR www.corp.lan."}, false, "record"},
		{"auto PTR in a reverse zone", "5.5.168.192.in-addr.arpa", 0, []string{"PTR nas5.corp.lan."}, true, "zone"},
		{"explicit PTR wins", "6.5.168.192.in-addr.arpa", 0, []string{"PTR explicit.corp.lan."}, true, "zone"},
		{"reverse zone without record", "7.5.168.192.in-addr.arpa", dns.RcodeNameError, nil, true, "zone"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, l := e.query(tt.qname, dns.TypePTR)
			if resp.Rcode != tt.rcode || resp.Authoritative != tt.aa {
				t.Fatalf("rcode %s aa %v", dns.RcodeToString[resp.Rcode], resp.Authoritative)
			}
			if got := answers(resp); !slices.Equal(got, tt.answer) {
				t.Fatalf("answer %v", got)
			}
			if l.q.Status != "rewrite" || l.q.Reason != tt.reason {
				t.Fatalf("log %+v", l.q)
			}
			if e.up.count(tt.qname, dns.TypePTR) != 0 {
				t.Fatal("asked the private upstream")
			}
		})
	}
	// Other private addresses still go through the private-PTR routing.
	_, l := e.query("9.9.0.10.in-addr.arpa", dns.TypePTR)
	if l.q.Status != "ok" || l.q.Upstream != e.up.addr || e.up.count("9.9.0.10.in-addr.arpa", dns.TypePTR) != 1 {
		t.Fatalf("private PTR %+v", l.q)
	}
}

func TestZoneTransfersRefused(t *testing.T) {
	e := newEnv(t, nil)
	for _, tc := range []struct {
		qname  string
		qtype  uint16
		reason string
	}{
		{"corp.lan", dns.TypeAXFR, "zone"},
		{"www.corp.lan", dns.TypeIXFR, "zone"},
		{"nas.home.lan", dns.TypeAXFR, "record"},
	} {
		resp, l := e.query(tc.qname, tc.qtype, overTCP("192.168.1.20"))
		if resp.Rcode != dns.RcodeRefused || len(resp.Answer) != 0 || resp.Authoritative {
			t.Fatalf("%s: %v", tc.qname, resp)
		}
		if l.q.Status != "rewrite" || l.q.Reason != tc.reason || l.q.Rcode != "REFUSED" {
			t.Fatalf("%s: log %+v", tc.qname, l.q)
		}
		if e.up.count(tc.qname, tc.qtype) != 0 {
			t.Fatalf("%s: forwarded", tc.qname)
		}
	}
}

func TestZonesWithoutProtection(t *testing.T) {
	e := newEnv(t, nil)
	now := e.now()
	e.update(func(s *config.Settings) { s.ProtectionPausedUntil = now.Add(10 * time.Minute).UnixMilli() })
	for _, n := range []string{"www.corp.lan", "x.ads.example"} {
		resp, l := e.query(n, dns.TypeA)
		if len(resp.Answer) != 1 || l.q.Status != "rewrite" {
			t.Fatalf("paused %s: %v %+v", n, answers(resp), l.q)
		}
	}
	e.update(func(s *config.Settings) { s.ProtectionPausedUntil = 0; s.ProtectionEnabled = false })
	resp, l := e.query("nope.corp.lan", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError || l.q.Status != "rewrite" || l.q.Reason != "zone" {
		t.Fatalf("off: %v %+v", resp, l.q)
	}
	// A client with filtering off gets them as well.
	e.update(func(s *config.Settings) { s.ProtectionEnabled = true })
	resp, l = e.query("www.corp.lan", dns.TypeA, fromIP("192.168.1.30"))
	if len(resp.Answer) != 1 || l.q.Status != "rewrite" {
		t.Fatalf("client %+v", l.q)
	}
}

func TestDisabledZoneIsForwarded(t *testing.T) {
	e := newEnv(t, nil)
	resp, l := e.query("host.off.lan", dns.TypeA)
	if got := answers(resp); !slices.Equal(got, []string{"A 192.0.2.1"}) || resp.Authoritative || l.q.Status != "ok" {
		t.Fatalf("disabled zone %v %+v", got, l.q)
	}
	if e.up.count("host.off.lan", dns.TypeA) != 1 {
		t.Fatal("not forwarded")
	}
	if ix := e.srv.Records(); ix.ZoneCount() != 2 || ix.RecordCount() == 0 {
		t.Fatalf("index counts %d %d", ix.ZoneCount(), ix.RecordCount())
	}
}

func TestLocalAnswersNotCached(t *testing.T) {
	e := newEnv(t, nil)
	for range 2 {
		for _, q := range []struct {
			name  string
			qtype uint16
		}{{"www.corp.lan", dns.TypeA}, {"nope.corp.lan", dns.TypeA}, {"mail.corp.lan", dns.TypeMX}, {"nas.home.lan", dns.TypeA}, {"80.0.0.10.in-addr.arpa", dns.TypePTR}} {
			_, l := e.query(q.name, q.qtype)
			if l.q.Cached {
				t.Fatalf("%s from the cache", q.name)
			}
		}
	}
	if n := e.cache.Stats().Entries; n != 0 {
		t.Fatalf("cache entries %d", n)
	}
	// A changed record is answered right away (nothing cached).
	e.recs = append(e.recs[:0:0], e.recs...)
	for i := range e.recs {
		if e.recs[i].Name == "www.corp.lan" && e.recs[i].Type == "A" {
			e.recs[i].Value = "10.0.0.81"
		}
	}
	e.apply()
	resp, _ := e.query("www.corp.lan", dns.TypeA)
	if got := answers(resp); !slices.Equal(got, []string{"A 10.0.0.81"}) {
		t.Fatalf("after change %v", got)
	}
}

func TestHostnameFromRecords(t *testing.T) {
	e := newEnv(t, nil)
	if got := e.srv.Hostname("10.0.0.80"); got != "www.corp.lan" {
		t.Fatalf("v4 %q", got)
	}
	if got := e.srv.Hostname("fd00::80"); got != "www.corp.lan" {
		t.Fatalf("v6 %q", got)
	}
	if got := e.srv.Hostname("192.168.5.6"); got != "explicit.corp.lan" {
		t.Fatalf("explicit %q", got)
	}
	// The reverse zone owns 192.168.5.7: no name, and no upstream question.
	if got := e.srv.Hostname("192.168.5.7"); got != "" {
		t.Fatalf("zone without PTR %q", got)
	}
	e.srv.hosts.wg.Wait()
	for _, n := range []string{"80.0.0.10.in-addr.arpa", "7.5.168.192.in-addr.arpa"} {
		if e.up.count(n, dns.TypePTR) != 0 {
			t.Fatalf("asked upstream for %s", n)
		}
	}
	_, l := e.query("x.example", dns.TypeA, fromIP("10.0.0.80"))
	if l.q.ClientName != "www.corp.lan" {
		t.Fatalf("log client name %q", l.q.ClientName)
	}
}
