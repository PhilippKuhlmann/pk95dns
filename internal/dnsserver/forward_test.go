package dnsserver

import (
	"slices"
	"testing"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
	"pk95dns/internal/records"
)

// A conditional forwarding that is more specific than the matching own data wins: a
// wildcard or a zone of the parent domain must not answer for an AD zone forwarded to its
// domain controller (the bug: *.kuhlmannit.de answered gibtsnicht.intern.kuhlmannit.de).
// An own record for exactly the asked name still wins.
func TestConditionalForwardingBeatsLessSpecificOwnData(t *testing.T) {
	rec := func(name, typ, value string) records.Record {
		return records.Record{Name: name, Type: typ, Value: value, TTL: 300, Enabled: true}
	}
	type step struct {
		name    string
		qtype   uint16
		local   bool     // answered from own data (status rewrite), not forwarded
		answer  []string // expected answer RRs (type + value)
		rcode   int
		toAD    bool // the AD upstream was asked
		toRoute bool // the fritz.box upstream was asked
	}
	tests := []struct {
		name  string
		zones []records.Zone
		recs  []records.Record
		steps []step
	}{
		{
			name: "single wildcard of the parent domain",
			recs: []records.Record{
				rec("*.kuhlmannit.de", "A", "10.10.250.50"),
				rec("exact.intern.kuhlmannit.de", "A", "10.0.0.9"), // deliberate override
				rec("alias.kuhlmannit.de", "CNAME", "dc.intern.kuhlmannit.de"),
			},
			steps: []step{
				{name: "gibtsnicht.intern.kuhlmannit.de", qtype: dns.TypeA, answer: []string{"A 192.0.2.1"}, toAD: true},
				{name: "dc.intern.kuhlmannit.de", qtype: dns.TypeAAAA, toAD: true},
				{name: "intern.kuhlmannit.de", qtype: dns.TypeA, answer: []string{"A 192.0.2.1"}, toAD: true},
				{name: "exact.intern.kuhlmannit.de", qtype: dns.TypeA, local: true, answer: []string{"A 10.0.0.9"}},
				{name: "www.kuhlmannit.de", qtype: dns.TypeA, local: true, answer: []string{"A 10.10.250.50"}},
				// a local CNAME into the forwarded zone: the target comes from the AD upstream
				{name: "alias.kuhlmannit.de", qtype: dns.TypeA, local: true, answer: []string{"CNAME dc.intern.kuhlmannit.de.", "A 192.0.2.1"}, toAD: true},
			},
		},
		{
			name:  "zone of the parent domain",
			zones: []records.Zone{{ID: 9, Name: "kuhlmannit.de", TTL: 300, PrimaryNS: "ns.kuhlmannit.de", Enabled: true}},
			recs: []records.Record{
				rec("www.kuhlmannit.de", "A", "10.10.250.50"),
				rec("pinned.intern.kuhlmannit.de", "A", "10.0.0.7"), // exact record inside the zone
			},
			steps: []step{
				{name: "nope.kuhlmannit.de", qtype: dns.TypeA, local: true, rcode: dns.RcodeNameError},
				{name: "x.intern.kuhlmannit.de", qtype: dns.TypeA, answer: []string{"A 192.0.2.1"}, toAD: true},
				{name: "intern.kuhlmannit.de", qtype: dns.TypeA, answer: []string{"A 192.0.2.1"}, toAD: true}, // empty non-terminal of the zone
				{name: "_ldap._tcp.intern.kuhlmannit.de", qtype: dns.TypeSRV, toAD: true},
				{name: "pinned.intern.kuhlmannit.de", qtype: dns.TypeA, local: true, answer: []string{"A 10.0.0.7"}},
				{name: "www.kuhlmannit.de", qtype: dns.TypeA, local: true, answer: []string{"A 10.10.250.50"}},
			},
		},
		{
			name:  "wildcard inside the parent zone",
			zones: []records.Zone{{ID: 9, Name: "kuhlmannit.de", TTL: 300, PrimaryNS: "ns.kuhlmannit.de", Enabled: true}},
			recs:  []records.Record{rec("*.kuhlmannit.de", "A", "10.10.250.50")},
			steps: []step{
				{name: "pc1.intern.kuhlmannit.de", qtype: dns.TypeA, answer: []string{"A 192.0.2.1"}, toAD: true},
				{name: "shop.kuhlmannit.de", qtype: dns.TypeA, local: true, answer: []string{"A 10.10.250.50"}},
			},
		},
		{
			name: "equally specific own data keeps the name",
			recs: []records.Record{rec("*.intern.kuhlmannit.de", "A", "10.0.0.1")},
			steps: []step{
				{name: "pc1.intern.kuhlmannit.de", qtype: dns.TypeA, local: true, answer: []string{"A 10.0.0.1"}},
			},
		},
		{
			name: "fritz.box unchanged",
			recs: []records.Record{
				rec("drucker.fritz.box", "A", "192.168.178.20"), // exact: own record
				rec("*.gast.fritz.box", "A", "192.168.179.1"),   // more specific than the forwarding
			},
			steps: []step{
				{name: "nas.fritz.box", qtype: dns.TypeA, answer: []string{"A 192.0.2.1"}, toRoute: true},
				{name: "drucker.fritz.box", qtype: dns.TypeA, local: true, answer: []string{"A 192.168.178.20"}},
				{name: "tablet.gast.fritz.box", qtype: dns.TypeA, local: true, answer: []string{"A 192.168.179.1"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad, fritz := startUpstream(t, false), startUpstream(t, false)
			e := newEnv(t, func(s *config.Settings) {
				s.Conditional = []config.Conditional{
					{Domain: "intern.kuhlmannit.de", Upstream: ad.addr},
					{Domain: "fritz.box", Upstream: fritz.addr},
				}
			})
			e.zones, e.recs = tt.zones, tt.recs
			e.apply()
			for _, st := range tt.steps {
				resp, l := e.query(st.name, st.qtype)
				if resp == nil {
					t.Fatalf("%s: no answer", st.name)
				}
				if resp.Rcode != st.rcode {
					t.Errorf("%s: rcode %s, want %s", st.name, dns.RcodeToString[resp.Rcode], dns.RcodeToString[st.rcode])
				}
				if st.answer != nil && !slices.Equal(answers(resp), st.answer) {
					t.Errorf("%s: answer %v, want %v", st.name, answers(resp), st.answer)
				}
				if got := l.q.Status == statusRewrite; got != st.local {
					t.Errorf("%s: answered locally = %v (status %q reason %q), want %v", st.name, got, l.q.Status, l.q.Reason, st.local)
				}
				wantAD, wantRoute := 0, 0
				if st.toAD {
					wantAD = 1
				}
				if st.toRoute {
					wantRoute = 1
				}
				adName := st.name
				if st.name == "alias.kuhlmannit.de" {
					adName = "dc.intern.kuhlmannit.de"
				}
				if got := ad.count(adName, st.qtype); got != wantAD {
					t.Errorf("%s: AD upstream asked %d times, want %d", st.name, got, wantAD)
				}
				if got := fritz.count(st.name, st.qtype); got != wantRoute {
					t.Errorf("%s: fritz.box upstream asked %d times, want %d", st.name, got, wantRoute)
				}
				if got := e.up.count(st.name, st.qtype); got != 0 {
					t.Errorf("%s: the main upstream was asked", st.name)
				}
			}
		})
	}
}
