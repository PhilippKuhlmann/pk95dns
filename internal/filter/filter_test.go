package filter

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"pk95dns/internal/config"
)

func compileOrFail(t testing.TB, sources ...Source) *RuleSet {
	t.Helper()
	rs, stats := Compile(sources)
	for id, n := range stats.Invalid {
		if n != 0 {
			t.Fatalf("source %d has %d invalid lines", id, n)
		}
	}
	return rs
}

func src(id int64, lines ...string) Source {
	return Source{ID: id, Data: []byte(strings.Join(lines, "\n"))}
}

func allowSrc(id int64, lines ...string) Source {
	return Source{ID: id, Allow: true, Data: []byte(strings.Join(lines, "\n"))}
}

func engineWith(t testing.TB, custom []string, lists ...Source) *Engine {
	t.Helper()
	e := NewEngine()
	e.SetCustom(compileOrFail(t, src(0, custom...)))
	e.SetLists(compileOrFail(t, lists...))
	return e
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, a := range s {
		out[i] = netip.MustParseAddr(a)
	}
	return out
}

func checkResult(t *testing.T, got, want Result) {
	t.Helper()
	if got.Action != want.Action || got.Reason != want.Reason || got.Rule != want.Rule ||
		got.ListID != want.ListID || got.Service != want.Service || got.CNAME != want.CNAME ||
		!slices.Equal(got.IPs, want.IPs) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

var safeAll = config.SafeSearch{Enabled: true, Google: true, Bing: true, DuckDuckGo: true, YouTube: true, Yandex: true, Pixabay: true}

func TestDecisionOrder(t *testing.T) {
	e := engineWith(t,
		[]string{
			"||c-imp.test^$important",
			"@@||c-imp.test^",
			"@@||c-allow.test^",
			"@@www.google.ch",
			"||www.bing.com^",
			"||c-block.test^",
			"10.0.0.1 c-rw.test",
			"||music.youtube.com^",
			"@@||c-impallow.test^$important",
			"||c-impallow.test^$important",
		},
		src(1,
			"||c-allow.test^",
			"||c-block.test^",
			"||l-imp.test^$important",
			"||l-block.test^",
			"@@||l-allowed.test^",
			"||l-allowed.test^",
			"192.168.1.5 l-rw.test",
			"||youtube.com^",
			"||l-both.test^",
		),
		allowSrc(2, "l-both.test", "l-imp.test", "c-imp.test"),
	)
	services := []string{"youtube"}
	tests := []struct {
		name string
		ss   config.SafeSearch
		svc  []string
		want Result
	}{
		// 1. custom $important block beats custom allow and allow lists
		{"c-imp.test", safeAll, services, Result{Action: Block, Reason: ReasonCustom, Rule: "||c-imp.test^$important"}},
		{"sub.c-imp.test", safeAll, services, Result{Action: Block, Reason: ReasonCustom, Rule: "||c-imp.test^$important"}},
		// an important allow beats an important block
		{"c-impallow.test", safeAll, services, Result{Action: Allow, Reason: ReasonCustom, Rule: "@@||c-impallow.test^$important"}},
		// 2. custom allow beats SafeSearch and list blocks
		{"c-allow.test", safeAll, services, Result{Action: Allow, Reason: ReasonCustom, Rule: "@@||c-allow.test^"}},
		{"www.google.ch", safeAll, services, Result{Action: Allow, Reason: ReasonCustom, Rule: "@@www.google.ch"}},
		// 3. SafeSearch beats custom block rules and services
		{"www.google.de", safeAll, services, Result{Action: Rewrite, Reason: ReasonSafeSearch, CNAME: "forcesafesearch.google.com"}},
		{"www.bing.com", safeAll, services, Result{Action: Rewrite, Reason: ReasonSafeSearch, CNAME: "strict.bing.com"}},
		{"www.youtube.com", safeAll, services, Result{Action: Rewrite, Reason: ReasonSafeSearch, CNAME: "restrictmoderate.youtube.com"}},
		// 4. custom block / hosts rewrite (SafeSearch off for bing)
		{"www.bing.com", config.SafeSearch{}, services, Result{Action: Block, Reason: ReasonCustom, Rule: "||www.bing.com^"}},
		{"c-block.test", safeAll, services, Result{Action: Block, Reason: ReasonCustom, Rule: "||c-block.test^"}},
		{"c-rw.test", safeAll, services, Result{Action: Rewrite, Reason: ReasonCustom, Rule: "10.0.0.1 c-rw.test", IPs: addrs("10.0.0.1")}},
		{"music.youtube.com", safeAll, services, Result{Action: Block, Reason: ReasonCustom, Rule: "||music.youtube.com^"}},
		// 5. blocked service beats lists
		{"www.youtube.com", config.SafeSearch{}, services, Result{Action: Block, Reason: ReasonService, Rule: "||youtube.com^", Service: "youtube"}},
		{"rr1.googlevideo.com", safeAll, services, Result{Action: Block, Reason: ReasonService, Rule: "||googlevideo.com^", Service: "youtube"}},
		// without the service the list rule applies
		{"www.youtube.com", config.SafeSearch{}, nil, Result{Action: Block, Reason: ReasonList, Rule: "||youtube.com^", ListID: 1}},
		// 6. list $important beats allow lists
		{"l-imp.test", safeAll, services, Result{Action: Block, Reason: ReasonList, Rule: "||l-imp.test^$important", ListID: 1}},
		// 7. allow list / @@ rule
		{"l-both.test", safeAll, services, Result{Action: Allow, Reason: ReasonList, Rule: "l-both.test", ListID: 2}},
		{"x.l-both.test", safeAll, services, Result{Action: Block, Reason: ReasonList, Rule: "||l-both.test^", ListID: 1}},
		{"l-allowed.test", safeAll, services, Result{Action: Allow, Reason: ReasonList, Rule: "@@||l-allowed.test^", ListID: 1}},
		// 8. list block / hosts rewrite
		{"l-block.test", safeAll, services, Result{Action: Block, Reason: ReasonList, Rule: "||l-block.test^", ListID: 1}},
		{"a.b.l-block.test", safeAll, services, Result{Action: Block, Reason: ReasonList, Rule: "||l-block.test^", ListID: 1}},
		{"l-rw.test", safeAll, services, Result{Action: Rewrite, Reason: ReasonList, Rule: "192.168.1.5 l-rw.test", ListID: 1, IPs: addrs("192.168.1.5")}},
		// 9. nothing
		{"nothing.test", safeAll, services, Result{}},
		{"block.test", safeAll, services, Result{}},
		{"", safeAll, services, Result{}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%v/%v", tt.name, tt.ss.Enabled, tt.svc), func(t *testing.T) {
			got := e.Check(Request{Name: tt.name, QType: dns.TypeA, SafeSearch: tt.ss, Services: tt.svc})
			checkResult(t, got, tt.want)
		})
	}
}

func TestCheckNormalizesName(t *testing.T) {
	e := engineWith(t, []string{"||ads.test^"})
	got := e.Check(Request{Name: "WWW.Ads.Test.", QType: dns.TypeA})
	checkResult(t, got, Result{Action: Block, Reason: ReasonCustom, Rule: "||ads.test^"})
}

func TestDNSType(t *testing.T) {
	e := engineWith(t, nil, src(1,
		"||only-aaaa.test^$dnstype=AAAA",
		"||not-https.test^$dnstype=~HTTPS",
		"||mixed.test^$dnstype=A|AAAA|~HTTPS",
		"||imp.test^$important,dnstype=A",
		"@@||imp.test^",
		"||fallback.test^",
		"||sub.fallback.test^$dnstype=HTTPS",
		"/^re\\.test$/$dnstype=TXT",
	))
	tests := []struct {
		name  string
		qtype uint16
		want  Result
	}{
		{"only-aaaa.test", dns.TypeA, Result{}},
		{"only-aaaa.test", dns.TypeAAAA, Result{Action: Block, Reason: ReasonList, Rule: "||only-aaaa.test^$dnstype=AAAA", ListID: 1}},
		{"not-https.test", dns.TypeHTTPS, Result{}},
		{"not-https.test", dns.TypeA, Result{Action: Block, Reason: ReasonList, Rule: "||not-https.test^$dnstype=~HTTPS", ListID: 1}},
		{"mixed.test", dns.TypeA, Result{Action: Block, Reason: ReasonList, Rule: "||mixed.test^$dnstype=A|AAAA|~HTTPS", ListID: 1}},
		{"mixed.test", dns.TypeAAAA, Result{Action: Block, Reason: ReasonList, Rule: "||mixed.test^$dnstype=A|AAAA|~HTTPS", ListID: 1}},
		{"mixed.test", dns.TypeMX, Result{}},
		{"mixed.test", dns.TypeHTTPS, Result{}},
		{"imp.test", dns.TypeA, Result{Action: Block, Reason: ReasonList, Rule: "||imp.test^$important,dnstype=A", ListID: 1}},
		{"imp.test", dns.TypeAAAA, Result{Action: Allow, Reason: ReasonList, Rule: "@@||imp.test^", ListID: 1}},
		// a more specific rule restricted to another type does not hide the general rule
		{"sub.fallback.test", dns.TypeA, Result{Action: Block, Reason: ReasonList, Rule: "||fallback.test^", ListID: 1}},
		{"sub.fallback.test", dns.TypeHTTPS, Result{Action: Block, Reason: ReasonList, Rule: "||sub.fallback.test^$dnstype=HTTPS", ListID: 1}},
		{"re.test", dns.TypeA, Result{}},
		{"re.test", dns.TypeTXT, Result{Action: Block, Reason: ReasonList, Rule: "/^re\\.test$/$dnstype=TXT", ListID: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+dns.TypeToString[tt.qtype], func(t *testing.T) {
			checkResult(t, e.Check(Request{Name: tt.name, QType: tt.qtype}), tt.want)
		})
	}
}

func TestListPrecedenceAndSpecificity(t *testing.T) {
	e := engineWith(t, nil,
		src(1, "||a.test^", "||x.test^", "@@||allowed.test^"),
		src(3, "||b.a.test^", "x.test", "||deep.b.allowed.test^"),
		src(4, "||imp.test^$important"),
		src(5, "@@||imp.test^$important", "||a.test^"),
		src(6, "@@||imp.test^"),
	)
	tests := []struct {
		name string
		want Result
	}{
		{"c.a.test", Result{Action: Block, Reason: ReasonList, Rule: "||a.test^", ListID: 1}},
		// most specific domain wins for equal precedence
		{"b.a.test", Result{Action: Block, Reason: ReasonList, Rule: "||b.a.test^", ListID: 3}},
		{"z.b.a.test", Result{Action: Block, Reason: ReasonList, Rule: "||b.a.test^", ListID: 3}},
		// equal length: exact rule before subtree rule
		{"x.test", Result{Action: Block, Reason: ReasonList, Rule: "x.test", ListID: 3}},
		// allow beats a more specific block rule
		{"deep.b.allowed.test", Result{Action: Allow, Reason: ReasonList, Rule: "@@||allowed.test^", ListID: 1}},
		// important allow > important block > allow
		{"imp.test", Result{Action: Allow, Reason: ReasonList, Rule: "@@||imp.test^$important", ListID: 5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkResult(t, e.Check(Request{Name: tt.name, QType: dns.TypeA}), tt.want)
		})
	}

	// Duplicates across lists: the first list wins.
	e = engineWith(t, nil, src(7, "||dup.test^"), src(8, "||dup.test^"))
	checkResult(t, e.Check(Request{Name: "dup.test", QType: dns.TypeA}),
		Result{Action: Block, Reason: ReasonList, Rule: "||dup.test^", ListID: 7})
}

func TestImportant(t *testing.T) {
	e := engineWith(t,
		[]string{"@@||list-imp.test^"},
		src(1, "||list-imp.test^$important", "||plain.test^", "||imp-vs-allow.test^$important"),
		allowSrc(2, "||plain.test^", "||imp-vs-allow.test^"),
	)
	// custom allow (step 2) beats list important (step 6)
	checkResult(t, e.Check(Request{Name: "list-imp.test", QType: dns.TypeA}),
		Result{Action: Allow, Reason: ReasonCustom, Rule: "@@||list-imp.test^"})
	checkResult(t, e.Check(Request{Name: "plain.test", QType: dns.TypeA}),
		Result{Action: Allow, Reason: ReasonList, Rule: "||plain.test^", ListID: 2})
	checkResult(t, e.Check(Request{Name: "a.imp-vs-allow.test", QType: dns.TypeA}),
		Result{Action: Block, Reason: ReasonList, Rule: "||imp-vs-allow.test^$important", ListID: 1})
}

func TestWildcardRules(t *testing.T) {
	e := engineWith(t, nil, src(1,
		"||ads*.example.org^",
		"|ad*.start.test^",
		"*.sub.test",
		"||*.wild.test^",
		"track*er.test",
		"@@||ads-ok*.example.org^",
	))
	tests := []struct {
		name string
		rule string // "" = no match
		act  Action
	}{
		{"ads1.example.org", "||ads*.example.org^", Block},
		{"x.ads-foo.example.org", "||ads*.example.org^", Block},
		{"ads.a.b.example.org", "||ads*.example.org^", Block},
		{"myads.example.org", "", None},
		{"example.org", "", None},
		{"ads1.example.org.evil", "", None},
		{"ads-ok1.example.org", "@@||ads-ok*.example.org^", Allow},
		{"adx.start.test", "|ad*.start.test^", Block},
		{"sub.adx.start.test", "", None},
		{"a.sub.test", "*.sub.test", Block},
		{"a.b.sub.test", "*.sub.test", Block},
		{"sub.test", "", None},
		{"x.wild.test", "*.wild.test", Block},
		{"wild.test", "", None},
		{"tracker.test", "track*er.test", Block},
		{"track-1-er.test", "track*er.test", Block},
		{"a.tracker.test", "", None},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.Check(Request{Name: tt.name, QType: dns.TypeA})
			if got.Action != tt.act || got.Rule != tt.rule {
				t.Errorf("got %v %q, want %v %q", got.Action, got.Rule, tt.act, tt.rule)
			}
		})
	}
}

func TestRegexRules(t *testing.T) {
	e := engineWith(t,
		[]string{"/^custom[0-9]+\\./"},
		src(1, "/^ad[0-9]+\\./", "@@/^ad7\\./", "/tracker/$important", "@@||tracker.good.test^", "||ok.regex.test^"),
		src(2, "/regex\\.test$/"),
	)
	tests := []struct {
		name string
		want Result
	}{
		{"custom12.example.com", Result{Action: Block, Reason: ReasonCustom, Rule: "/^custom[0-9]+\\./"}},
		{"ad1.example.com", Result{Action: Block, Reason: ReasonList, Rule: "/^ad[0-9]+\\./", ListID: 1}},
		{"ad7.example.com", Result{Action: Allow, Reason: ReasonList, Rule: "@@/^ad7\\./", ListID: 1}},
		{"adx.example.com", Result{}},
		// important regex beats a domain allow rule
		{"tracker.good.test", Result{Action: Block, Reason: ReasonList, Rule: "/tracker/$important", ListID: 1}},
		// domain rules win ties against regex rules
		{"ok.regex.test", Result{Action: Block, Reason: ReasonList, Rule: "||ok.regex.test^", ListID: 1}},
		{"x.regex.test", Result{Action: Block, Reason: ReasonList, Rule: "/regex\\.test$/", ListID: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkResult(t, e.Check(Request{Name: tt.name, QType: dns.TypeA}), tt.want)
		})
	}
}

func TestHostsRules(t *testing.T) {
	e := engineWith(t,
		[]string{"192.168.1.9 custom.lan # my nas", "fd00::9 custom.lan"},
		src(1,
			"# hosts file",
			"127.0.0.1 localhost",
			"::1 localhost ip6-localhost ip6-loopback",
			"0.0.0.0 0.0.0.0",
			"192.168.1.5 nas.lan",
			"fe80::5 nas.lan NAS.lan.",
			"192.168.1.5 nas.lan",
			"0.0.0.0 ads.lan tracker.lan # comment",
			"127.0.0.1 local-block.lan",
			":: v6.lan",
			"::1 v6one.lan",
			"0:0:0:0:0:0:0:0 zero.lan",
		),
		src(2, "10.0.0.5 nas.lan", "10.0.0.6 other.lan"),
	)
	tests := []struct {
		name string
		want Result
	}{
		{"nas.lan", Result{Action: Rewrite, Reason: ReasonList, Rule: "192.168.1.5 nas.lan", ListID: 1, IPs: addrs("192.168.1.5", "fe80::5", "10.0.0.5")}},
		{"other.lan", Result{Action: Rewrite, Reason: ReasonList, Rule: "10.0.0.6 other.lan", ListID: 2, IPs: addrs("10.0.0.6")}},
		{"sub.nas.lan", Result{}},
		{"ads.lan", Result{Action: Block, Reason: ReasonList, Rule: "0.0.0.0 ads.lan", ListID: 1}},
		{"tracker.lan", Result{Action: Block, Reason: ReasonList, Rule: "0.0.0.0 tracker.lan", ListID: 1}},
		{"sub.ads.lan", Result{}},
		{"local-block.lan", Result{Action: Block, Reason: ReasonList, Rule: "127.0.0.1 local-block.lan", ListID: 1}},
		{"v6.lan", Result{Action: Block, Reason: ReasonList, Rule: ":: v6.lan", ListID: 1}},
		{"v6one.lan", Result{Action: Block, Reason: ReasonList, Rule: "::1 v6one.lan", ListID: 1}},
		{"zero.lan", Result{Action: Block, Reason: ReasonList, Rule: ":: zero.lan", ListID: 1}},
		{"localhost", Result{}},
		{"ip6-localhost", Result{}},
		{"custom.lan", Result{Action: Rewrite, Reason: ReasonCustom, Rule: "192.168.1.9 custom.lan # my nas", IPs: addrs("192.168.1.9", "fd00::9")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// rewrites answer every query type; the DNS server picks the family
			for _, q := range []uint16{dns.TypeA, dns.TypeAAAA} {
				checkResult(t, e.Check(Request{Name: tt.name, QType: q}), tt.want)
			}
		})
	}
	// result IPs are a copy
	r := e.Check(Request{Name: "nas.lan", QType: dns.TypeA})
	r.IPs[0] = netip.MustParseAddr("1.1.1.1")
	if got := e.Check(Request{Name: "nas.lan", QType: dns.TypeA}); got.IPs[0] != netip.MustParseAddr("192.168.1.5") {
		t.Errorf("IPs shared: %v", got.IPs)
	}
}

func TestAllowList(t *testing.T) {
	e := engineWith(t, nil,
		src(1, "||a.test^", "||b.test^", "||c.test^", "||d.test^", "||re.test^", "||e.test^", "||imp.test^$important", "||f.test^"),
		allowSrc(2,
			"||a.test^",
			"b.test",
			"0.0.0.0 c.test",
			"192.168.1.1 d.test",
			"/^re\\./",
			"@@||e.test^",
			"||imp.test^",
			"*.f.test",
		),
	)
	tests := []struct {
		name string
		want Result
	}{
		{"x.a.test", Result{Action: Allow, Reason: ReasonList, Rule: "||a.test^", ListID: 2}},
		{"b.test", Result{Action: Allow, Reason: ReasonList, Rule: "b.test", ListID: 2}},
		{"x.b.test", Result{Action: Block, Reason: ReasonList, Rule: "||b.test^", ListID: 1}},
		{"c.test", Result{Action: Allow, Reason: ReasonList, Rule: "0.0.0.0 c.test", ListID: 2}},
		{"d.test", Result{Action: Allow, Reason: ReasonList, Rule: "d.test", ListID: 2}},
		{"re.test", Result{Action: Allow, Reason: ReasonList, Rule: "/^re\\./", ListID: 2}},
		{"e.test", Result{Action: Allow, Reason: ReasonList, Rule: "@@||e.test^", ListID: 2}},
		{"imp.test", Result{Action: Block, Reason: ReasonList, Rule: "||imp.test^$important", ListID: 1}},
		{"f.test", Result{Action: Block, Reason: ReasonList, Rule: "||f.test^", ListID: 1}},
		{"x.f.test", Result{Action: Allow, Reason: ReasonList, Rule: "*.f.test", ListID: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkResult(t, e.Check(Request{Name: tt.name, QType: dns.TypeA}), tt.want)
		})
	}
}

func TestRuleText(t *testing.T) {
	e := engineWith(t,
		[]string{"  ||Custom-Imp.Example^$important  ", "Exact.Custom.Example", "|pipe.custom.example^"},
		src(1,
			"||List-Imp.Example.^$important",
			"|pipe.list.example^|",
			"*.Sub.Example",
			"plain.example.",
			"plain2.example^",
			"@@||Allowed.Example^$dnstype=a|~https",
		),
	)
	tests := []struct {
		name, qtype, rule string
	}{
		{"custom-imp.example", "A", "||Custom-Imp.Example^$important"},
		{"exact.custom.example", "A", "Exact.Custom.Example"},
		{"pipe.custom.example", "A", "|pipe.custom.example^"},
		{"list-imp.example", "A", "||list-imp.example^$important"},
		{"pipe.list.example", "A", "pipe.list.example"},
		{"a.sub.example", "A", "*.sub.example"},
		{"plain.example", "A", "plain.example"},
		{"x.plain2.example", "A", "||plain2.example^"},
		{"allowed.example", "A", "@@||allowed.example^$dnstype=A|~HTTPS"},
	}
	for _, tt := range tests {
		got := e.Check(Request{Name: tt.name, QType: dns.StringToType[tt.qtype]})
		if got.Rule != tt.rule {
			t.Errorf("%s: rule %q, want %q", tt.name, got.Rule, tt.rule)
		}
	}
}

func TestCheckCNAME(t *testing.T) {
	e := engineWith(t,
		[]string{"||cloak.test^", "@@||custom-ok.test^", "1.2.3.4 rw-custom.test"},
		src(1, "||tracker.test^", "@@||ok.tracker.test^", "||custom-ok.test^", "5.6.7.8 rw.test", "0.0.0.0 hosts-block.test", "||aaaa.test^$dnstype=AAAA"),
	)
	tests := []struct {
		name  string
		qtype uint16
		svc   []string
		want  Result
	}{
		{"x.cloak.test.", dns.TypeA, nil, Result{Action: Block, Reason: ReasonCustom, Rule: "||cloak.test^"}},
		{"X.Tracker.Test", dns.TypeA, nil, Result{Action: Block, Reason: ReasonList, Rule: "||tracker.test^", ListID: 1}},
		{"ok.tracker.test", dns.TypeA, nil, Result{}},
		{"custom-ok.test", dns.TypeA, nil, Result{}},
		{"rw.test", dns.TypeA, nil, Result{}},
		{"rw-custom.test", dns.TypeA, nil, Result{}},
		{"hosts-block.test", dns.TypeA, nil, Result{Action: Block, Reason: ReasonList, Rule: "0.0.0.0 hosts-block.test", ListID: 1}},
		{"aaaa.test", dns.TypeA, nil, Result{}},
		{"aaaa.test", dns.TypeAAAA, nil, Result{Action: Block, Reason: ReasonList, Rule: "||aaaa.test^$dnstype=AAAA", ListID: 1}},
		{"r3.googlevideo.com", dns.TypeA, []string{"youtube"}, Result{Action: Block, Reason: ReasonService, Rule: "||googlevideo.com^", Service: "youtube"}},
		{"r3.googlevideo.com", dns.TypeA, nil, Result{}},
		// no SafeSearch in CNAME checks
		{"www.bing.com", dns.TypeA, nil, Result{}},
		{"unknown.test", dns.TypeA, nil, Result{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkResult(t, e.CheckCNAME(tt.name, tt.qtype, tt.svc), tt.want)
		})
	}
}

func TestEngineEmptyAndNil(t *testing.T) {
	e := NewEngine()
	if got := e.Check(Request{Name: "example.org", QType: dns.TypeA}); got.Action != None {
		t.Errorf("empty engine: %+v", got)
	}
	e.SetLists(nil)
	e.SetCustom(nil)
	if got := e.CheckCNAME("example.org", dns.TypeA, nil); got.Action != None {
		t.Errorf("nil sets: %+v", got)
	}
	// unknown service ids are ignored
	if got := e.Check(Request{Name: "youtube.com", QType: dns.TypeA, Services: []string{"nope"}}); got.Action != None {
		t.Errorf("unknown service: %+v", got)
	}
}

func TestConcurrentSetAndCheck(t *testing.T) {
	e := NewEngine()
	setA := compileOrFail(t, src(1, "||a.test^", "1.2.3.4 rw.test"))
	setB := compileOrFail(t, src(2, "@@||a.test^", "||b.test^"))
	custom := compileOrFail(t, src(0, "||c.test^"))

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, n := range []string{"x.a.test", "b.test", "c.test", "rw.test", "www.google.de"} {
					r := e.Check(Request{Name: n, QType: dns.TypeA, SafeSearch: safeAll, Services: []string{"youtube"}})
					if n == "x.a.test" && r.Action != None && r.Action != Block && r.Action != Allow {
						t.Errorf("unexpected action %v", r.Action)
					}
					e.CheckCNAME(n, dns.TypeA, nil)
				}
			}
		})
	}
	for i := range 500 {
		if i%2 == 0 {
			e.SetLists(setA)
		} else {
			e.SetLists(setB)
		}
		if i%50 == 0 {
			e.SetCustom(custom)
		}
	}
	close(stop)
	wg.Wait()
	if got := e.Check(Request{Name: "a.test", QType: dns.TypeA}); got.Action != Allow || got.ListID != 2 {
		t.Errorf("final state: %+v", got)
	}
}

// Lists fetched without TLS cannot rewrite names: their hosts lines with another address block.
func TestHostsNoRewrite(t *testing.T) {
	plain := src(1, "203.0.113.66 www.bank.example", "0.0.0.0 ads.example")
	plain.NoRewrite = true
	e := engineWith(t, nil, plain, src(2, "192.168.1.5 nas.lan"))
	for _, q := range []uint16{dns.TypeA, dns.TypeAAAA} {
		r := e.Check(Request{Name: "www.bank.example", QType: q})
		if r.Action != Block || r.ListID != 1 || len(r.IPs) != 0 {
			t.Fatalf("NoRewrite hosts line: %+v", r)
		}
		if r := e.Check(Request{Name: "ads.example", QType: q}); r.Action != Block {
			t.Fatalf("null hosts line: %+v", r)
		}
		if r := e.Check(Request{Name: "nas.lan", QType: q}); r.Action != Rewrite {
			t.Fatalf("rewrite of a TLS list: %+v", r)
		}
	}
}
