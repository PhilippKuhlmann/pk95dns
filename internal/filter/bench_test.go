package filter

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// syntheticList returns n rules in the usual mix of list syntaxes.
func syntheticList(n int) []byte {
	var b strings.Builder
	b.Grow(n * 32)
	b.WriteString("! Title: synthetic\n# comment\n")
	for i := range n {
		switch i % 10 {
		case 0, 1, 2, 3, 4:
			fmt.Fprintf(&b, "||ads%d.tracker%d.example^\n", i, i%997)
		case 5, 6:
			fmt.Fprintf(&b, "0.0.0.0 host%d.ad%d.test\n", i, i%113)
		case 7:
			fmt.Fprintf(&b, "plain%d.example.net\n", i)
		case 8:
			fmt.Fprintf(&b, "*.sub%d.example.com\n", i)
		case 9:
			fmt.Fprintf(&b, "@@||ok%d.example.org^\n", i)
		}
	}
	return []byte(b.String())
}

func TestCompileLargeList(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("timing test")
	}
	data := syntheticList(300_000)
	start := time.Now()
	rs, stats := Compile([]Source{{ID: 1, Data: data}})
	elapsed := time.Since(start)
	if stats.Rules[1] != 300_000 || stats.Invalid[1] != 0 {
		t.Fatalf("rules %d invalid %d", stats.Rules[1], stats.Invalid[1])
	}
	if elapsed > 3*time.Second {
		t.Errorf("compile took %v, want < 3s", elapsed)
	}

	e := NewEngine()
	e.SetLists(rs)
	checks := []struct {
		name string
		want Action
		rule string
	}{
		{"x.ads10.tracker10.example", Block, "||ads10.tracker10.example^"},
		{"host5.ad5.test", Block, "0.0.0.0 host5.ad5.test"},
		{"plain7.example.net", Block, "plain7.example.net"},
		{"a.sub8.example.com", Block, "*.sub8.example.com"},
		{"ok9.example.org", Allow, "@@||ok9.example.org^"},
		{"unknown.example", None, ""},
	}
	for _, c := range checks {
		r := e.Check(Request{Name: c.name, QType: dns.TypeA})
		if r.Action != c.want || r.Rule != c.rule {
			t.Errorf("%s: %v %q", c.name, r.Action, r.Rule)
		}
	}

	start = time.Now()
	const n = 100_000
	for i := range n {
		e.Check(Request{Name: fmt.Sprintf("www.host%d.ad%d.test", i, i%113), QType: dns.TypeA})
	}
	if per := time.Since(start) / n; per > 50*time.Microsecond {
		t.Errorf("Check takes %v per query", per)
	}
}

func BenchmarkCompile300k(b *testing.B) {
	data := syntheticList(300_000)
	b.ReportAllocs()
	for b.Loop() {
		Compile([]Source{{ID: 1, Data: data}})
	}
}

func BenchmarkCheck(b *testing.B) {
	rs, _ := Compile([]Source{
		{ID: 1, Data: syntheticList(300_000)},
		{ID: 2, Data: []byte("/^ad[0-9]+\\./\n||ads*.wild.example^\n/tracking/\n")},
	})
	custom, _ := Compile([]Source{{ID: 0, Data: []byte("||custom.example^\n@@||ok.example^")}})
	e := NewEngine()
	e.SetLists(rs)
	e.SetCustom(custom)
	names := []string{
		"a.b.c.ads10.tracker10.example",
		"www.example.com",
		"host5.ad5.test",
		"some.long.name.of.a.cdn.example.net",
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		e.Check(Request{Name: names[i%len(names)], QType: dns.TypeA, SafeSearch: safeAll, Services: []string{"youtube", "tiktok"}})
		i++
	}
}
