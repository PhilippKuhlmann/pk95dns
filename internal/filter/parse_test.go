package filter

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseRulesLines(t *testing.T) {
	tests := []struct {
		line  string
		count int    // valid rules
		err   string // expected error ("" = no invalid line)
	}{
		// comments and empty lines
		{"", 0, ""},
		{"   ", 0, ""},
		{"! comment", 0, ""},
		{"# comment", 0, ""},
		{"[Adblock Plus 2.0]", 0, ""},
		{"## not a rule, a comment", 0, ""},

		// adblock domain rules
		{"||example.org^", 1, ""},
		{"||example.org", 1, ""},
		{"||example.org^|", 1, ""},
		{"|example.org^", 1, ""},
		{"|example.org", 1, ""},
		{"example.org", 1, ""},
		{"example.org.", 1, ""},
		{"||example.org.^", 1, ""},
		{"EXAMPLE.ORG", 1, ""},
		{"example.org^", 1, ""},
		{"*.example.org", 1, ""},
		{"||*.example.org^", 1, ""},
		{"@@||example.org^", 1, ""},
		{"@@example.org", 1, ""},
		{"@@*.example.org", 1, ""},
		{"nas", 1, ""},
		{"_dmarc.example.org", 1, ""},
		{"xn--mnchen-3ya.de", 1, ""},
		{"  ||example.org^  ", 1, ""},

		// wildcards and regex
		{"||ads*.example.org^", 1, ""},
		{"|ad*.example.org^", 1, ""},
		{"ad*.example.org", 1, ""},
		{"@@||*-cdn.example.org^", 1, ""},
		{"/^ads?\\./", 1, ""},
		{"@@/^good\\./", 1, ""},
		{"/ads$/", 1, ""},
		{"/^ads\\./$important", 1, ""},

		// options
		{"||example.org^$important", 1, ""},
		{"||example.org^$dnstype=AAAA", 1, ""},
		{"||example.org^$dnstype=A|AAAA|~HTTPS", 1, ""},
		{"||example.org^$dnstype=aaaa", 1, ""},
		{"||example.org^$important,dnstype=A", 1, ""},
		{"||example.org^$dnstype=~HTTPS,important", 1, ""},
		{"@@||example.org^$important", 1, ""},

		// hosts syntax
		{"0.0.0.0 ads.example", 1, ""},
		{"0.0.0.0 a.example b.example # inline comment", 1, ""},
		{"127.0.0.1\tads.example", 1, ""},
		{":: ads.example", 1, ""},
		{"::1 ads.example", 1, ""},
		{"0:0:0:0:0:0:0:0 ads.example", 1, ""},
		{"192.168.1.5 nas.lan", 1, ""},
		{"fd00::5 nas.lan", 1, ""},
		{"0.0.0.0 ads.example.", 1, ""},
		{"0.0.0.0 0.0.0.0", 0, ""},
		{"127.0.0.1 localhost", 0, ""},
		{"127.0.0.1 localhost localhost.localdomain local broadcasthost", 0, ""},
		{"::1 localhost ip6-localhost ip6-loopback", 0, ""},
		{"ff02::1 ip6-allnodes", 0, ""},
		{"127.0.0.1 localhost real.example", 1, ""},

		// invalid
		{"||example.org^$client=192.168.1.1", 0, "Unbekannte Option: client"},
		{"||example.org^$denyallow=a.com", 0, "Unbekannte Option: denyallow"},
		{"||example.org^$badfilter", 0, "Unbekannte Option: badfilter"},
		{"||example.org^$ctag=device_pc", 0, "Unbekannte Option: ctag"},
		{"||example.org^$dnsrewrite=1.2.3.4", 0, "Unbekannte Option: dnsrewrite"},
		{"||example.org^$important=1", 0, "Unbekannte Option: important"},
		{"||example.org^$", 0, errEmptyOption},
		{"||example.org^$important,", 0, errEmptyOption},
		{"||example.org^$dnstype=FOO", 0, "Unbekannter DNS-Typ: FOO"},
		{"||example.org^$dnstype=", 0, errNoDNSType},
		{"||example.org^$dnstype=A|", 0, "Unbekannter DNS-Typ: "},
		{"/^ads/$client=x", 0, "Unbekannte Option: client"},
		{"example.org##.banner", 0, errCosmetic},
		{"example.org#@#.banner", 0, errCosmetic},
		{"example.org#$#body { color: red }", 0, errCosmetic},
		{"example.org#?#div:has(> a)", 0, errCosmetic},
		{"||example.org/ads", 0, errPath},
		{"||example.org/ads^", 0, errPath},
		{"/ads/banner.gif", 0, errPath},
		{"||1.2.3.4^", 0, errIP},
		{"||192.168.^", 0, errIP},
		{"|10.0.0.1|", 0, errIP},
		{"||[2001:db8::1]^", 0, errIP},
		{"1.2.3.4", 0, errIP},
		{"||exa mple.org^", 0, errInvalid},
		{"||-bad.org^", 0, "Ungültige Domain: -bad.org"},
		{"||bad-.org^", 0, "Ungültige Domain: bad-.org"},
		{"||ex!ample.org^", 0, "Ungültige Domain: ex!ample.org"},
		{"||müller.de^", 0, "Ungültige Domain: müller.de"},
		{"||a..b^", 0, "Ungültige Domain: a..b"},
		{"||example.org:8080^", 0, "Ungültige Domain: example.org:8080"},
		{"||*^", 0, errMatchAll},
		{"*", 0, errMatchAll},
		{"||*.*^", 0, errMatchAll},
		{"*.-bad.org", 0, "Ungültige Domain: *.-bad.org"},
		{"/[/", 0, errRegex},
		{"//", 0, errEmptyRegex},
		{"/", 0, errInvalid},
		{"@@", 0, errEmpty},
		{"||^", 0, errEmpty},
		{"0.0.0.0 bad!name", 0, "Ungültige Domain: bad!name"},
		{"1.2.3.4 # only a comment", 0, errHostsNoName},
		{"0.0.0.0 *.example.org", 0, "Ungültige Domain: *.example.org"},
		{"@@0.0.0.0 a.example", 0, errInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			count, invalid := ParseRules([]byte(tt.line))
			if count != tt.count {
				t.Errorf("count = %d, want %d (invalid %v)", count, tt.count, invalid)
			}
			if tt.err == "" {
				if len(invalid) != 0 {
					t.Errorf("unexpected invalid: %+v", invalid)
				}
				return
			}
			if len(invalid) != 1 {
				t.Fatalf("invalid = %+v, want one error %q", invalid, tt.err)
			}
			if invalid[0].Error != tt.err {
				t.Errorf("error = %q, want %q", invalid[0].Error, tt.err)
			}
			if invalid[0].Line != 1 || invalid[0].Text != strings.TrimSpace(tt.line) {
				t.Errorf("line/text = %d %q", invalid[0].Line, invalid[0].Text)
			}
		})
	}
}

func TestParseRulesLineNumbers(t *testing.T) {
	data := "\ufeff! title\r\n||ok.example^\r\n||bad$foo\n\nexample.org##.x\n0.0.0.0 a.example"
	count, invalid := ParseRules([]byte(data))
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	want := []ParseError{
		{Line: 3, Text: "||bad$foo", Error: "Unbekannte Option: foo"},
		{Line: 5, Text: "example.org##.x", Error: errCosmetic},
	}
	if fmt.Sprint(invalid) != fmt.Sprint(want) {
		t.Errorf("invalid = %+v, want %+v", invalid, want)
	}
}

func TestParseRulesLimits(t *testing.T) {
	var b strings.Builder
	for i := range 150 {
		fmt.Fprintf(&b, "||bad%d.example^$foo\n", i)
	}
	count, invalid := ParseRules([]byte(b.String()))
	if count != 0 || len(invalid) != 100 {
		t.Errorf("count %d, invalid %d; want 0, 100", count, len(invalid))
	}
	if invalid[99].Line != 100 {
		t.Errorf("last reported line = %d", invalid[99].Line)
	}

	long := "||" + strings.Repeat("ä", 400) + "^"
	_, invalid = ParseRules([]byte(long))
	if len(invalid) != 1 || len(invalid[0].Text) > maxErrorText+len("…") || !strings.HasSuffix(invalid[0].Text, "…") {
		t.Errorf("long text not truncated: %d bytes", len(invalid[0].Text))
	}
}

func TestRegexLimitPerSource(t *testing.T) {
	var b strings.Builder
	for i := range maxRegexPerSource + 5 {
		fmt.Fprintf(&b, "/^re%d\\./\n", i)
	}
	b.WriteString("||plain.example^\n")
	data := []byte(b.String())

	count, invalid := ParseRules(data)
	if count != maxRegexPerSource+1 || len(invalid) != 5 {
		t.Fatalf("count %d invalid %d", count, len(invalid))
	}
	if invalid[0].Error != errTooManyRe || invalid[0].Line != maxRegexPerSource+1 {
		t.Errorf("first invalid = %+v", invalid[0])
	}

	// The limit is per source: a second source gets its own budget.
	rs, stats := Compile([]Source{{ID: 1, Data: data}, {ID: 2, Data: data}})
	for _, id := range []int64{1, 2} {
		if stats.Rules[id] != maxRegexPerSource+1 || stats.Invalid[id] != 5 {
			t.Errorf("source %d: rules %d invalid %d", id, stats.Rules[id], stats.Invalid[id])
		}
	}
	if rs.Count() != 2*(maxRegexPerSource+1) {
		t.Errorf("Count = %d", rs.Count())
	}
}

// Wildcard patterns compile to a regex and count against the same limit.
func TestWildcardLimitPerSource(t *testing.T) {
	var b strings.Builder
	for i := range maxRegexPerSource - 1 {
		fmt.Fprintf(&b, "||e*x%d.example^\n", i)
	}
	b.WriteString("/^re\\./\n")          // the 1000th
	b.WriteString("||w*more.example^\n") // over the limit
	b.WriteString("/^re2\\./\n")         // over the limit
	b.WriteString("||plain.example^\n")
	data := []byte(b.String())

	count, invalid := ParseRules(data)
	if count != maxRegexPerSource+1 || len(invalid) != 2 || invalid[0].Error != errTooManyRe {
		t.Fatalf("count %d invalid %+v", count, invalid)
	}
	rs, stats := Compile([]Source{{ID: 1, Data: data}})
	if stats.Rules[1] != maxRegexPerSource+1 || stats.Invalid[1] != 2 || len(rs.regexes) != maxRegexPerSource {
		t.Fatalf("rules %d invalid %d regexes %d", stats.Rules[1], stats.Invalid[1], len(rs.regexes))
	}
}

func TestRegexLimitTotal(t *testing.T) {
	var b strings.Builder
	for i := range maxRegexPerSource {
		fmt.Fprintf(&b, "||e*x%d.example^\n", i)
	}
	data := []byte(b.String())
	n := maxRegexTotal/maxRegexPerSource + 2
	srcs := make([]Source, n)
	for i := range srcs {
		srcs[i] = Source{ID: int64(i + 1), Data: data}
	}
	rs, stats := Compile(srcs)
	if len(rs.regexes) != maxRegexTotal {
		t.Fatalf("regexes %d, want %d", len(rs.regexes), maxRegexTotal)
	}
	if stats.Invalid[int64(n)] != maxRegexPerSource {
		t.Fatalf("last source invalid %d", stats.Invalid[int64(n)])
	}
}

func TestCompileStats(t *testing.T) {
	rs, stats := Compile([]Source{
		{ID: 1, Data: []byte("! list\n||a.example^\nb.example\n||bad$x\n127.0.0.1 localhost\n0.0.0.0 c.example d.example")},
		{ID: 2, Allow: true, Data: []byte("@@||a.example^\nexample.org##x")},
		{ID: 3, Data: nil},
	})
	wantRules := map[int64]int{1: 3, 2: 1, 3: 0}
	wantInvalid := map[int64]int{1: 1, 2: 1, 3: 0}
	for id := range wantRules {
		if stats.Rules[id] != wantRules[id] || stats.Invalid[id] != wantInvalid[id] {
			t.Errorf("source %d: rules %d invalid %d", id, stats.Rules[id], stats.Invalid[id])
		}
	}
	if rs.Count() != 4 {
		t.Errorf("Count = %d, want 4", rs.Count())
	}
	var nilSet *RuleSet
	if nilSet.Count() != 0 {
		t.Error("nil Count")
	}
}
