package dnsserver

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"pk95dns/internal/querylog"
	"pk95dns/internal/stats"
	"pk95dns/internal/store"
)

func TestParsePrefix(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"192.168.1.5", "192.168.1.5/32", true},
		{" 10.0.0.0/8 ", "10.0.0.0/8", true},
		{"10.1.2.3/8", "10.0.0.0/8", true},
		{"fd00::1", "fd00::1/128", true},
		{"fd00::/7", "fc00::/7", true},
		{"::ffff:192.168.1.5", "192.168.1.5/32", true},
		{"::ffff:192.168.0.0/112", "192.168.0.0/16", true},
		{"fe80::1%eth0", "fe80::1/128", true},
		{"", "", false},
		{"nonsense", "", false},
		{"10.0.0.0/33", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			p, ok := parsePrefix(tt.in)
			if ok != tt.ok || (ok && p.String() != tt.want) {
				t.Fatalf("got %v %v, want %v %v", p, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestAddrOf(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want string
	}{
		{"udp v4", &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 1}, "192.168.1.2"},
		{"udp mapped", &net.UDPAddr{IP: net.ParseIP("::ffff:192.168.1.2"), Port: 1}, "192.168.1.2"},
		{"tcp v6 zone", &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 1, Zone: "eth0"}, "fe80::1"},
		{"nil", nil, "invalid IP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addrOf(tt.addr).String(); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	long := make([]dns.RR, 0, 40)
	for i := 0; i < 40; i++ {
		long = append(long, mustRR("a.example. 60 IN AAAA 2001:db8:1234:5678:9abc:def0:1234:5678"))
	}
	tests := []struct {
		name string
		rrs  []dns.RR
		want string
	}{
		{"empty", nil, ""},
		{"a and aaaa", []dns.RR{mustRR("a. 1 IN A 1.2.3.4"), mustRR("a. 1 IN AAAA ::1")}, "1.2.3.4, ::1"},
		{"cname", []dns.RR{mustRR("a. 1 IN CNAME x.example.")}, "CNAME x.example"},
		{"mx", []dns.RR{mustRR("a. 1 IN MX 10 mail.example.")}, "MX 10 mail.example"},
		{"txt", []dns.RR{mustRR(`a. 1 IN TXT "hello"`)}, `TXT "hello"`},
		{"rrsig skipped", []dns.RR{mustRR("a. 1 IN A 1.2.3.4"), mustRR("a. 1 IN RRSIG A 8 1 300 20300101000000 20200101000000 1 a. AAAA")}, "1.2.3.4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := summarize(tt.rrs); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
	if got := summarize(long); len(got) > maxAnswerText || !strings.HasPrefix(got, "2001:db8:1234") {
		t.Fatalf("long summary %d chars: %q", len(got), got)
	}
}

func TestTypeAndRcodeStrings(t *testing.T) {
	if typeString(dns.TypeAAAA) != "AAAA" || typeString(65280) != "TYPE65280" {
		t.Fatal("typeString")
	}
	if rcodeString(dns.RcodeNameError) != "NXDOMAIN" || rcodeString(3000) != "RCODE3000" {
		t.Fatal("rcodeString")
	}
}

func TestFinishStripsDNSSECForNonDOClients(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("a.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.AuthenticatedData = true
	resp.Answer = []dns.RR{
		mustRR("a.example. 60 IN A 1.2.3.4"),
		mustRR("a.example. 60 IN RRSIG A 8 2 60 20300101000000 20200101000000 1 example. AAAA"),
	}
	resp.Ns = []dns.RR{mustRR("x.example. 60 IN NSEC z.example. A")}
	resp.SetEdns0(1232, true)
	finish(req, resp, false, false)
	if len(resp.Answer) != 1 || len(resp.Ns) != 0 || resp.IsEdns0() != nil || resp.AuthenticatedData {
		t.Fatalf("not stripped: %v", resp)
	}

	// A DO client keeps them.
	req.SetEdns0(4096, true)
	resp = new(dns.Msg)
	resp.SetReply(req)
	resp.AuthenticatedData = true
	resp.Answer = []dns.RR{
		mustRR("a.example. 60 IN A 1.2.3.4"),
		mustRR("a.example. 60 IN RRSIG A 8 2 60 20300101000000 20200101000000 1 example. AAAA"),
	}
	finish(req, resp, false, false)
	if len(resp.Answer) != 2 || !resp.AuthenticatedData || resp.IsEdns0() == nil || !resp.IsEdns0().Do() {
		t.Fatalf("DO client: %v", resp)
	}
}

func TestApplyClosesOldRouter(t *testing.T) {
	e := newEnv(t, nil)
	e.srv.routerCloseDelay = time.Hour
	old := e.srv.state.Load().router
	e.apply()
	if e.srv.state.Load().router == old {
		t.Fatal("router not swapped")
	}
	// The old router still answers in-flight queries until it is closed.
	req := new(dns.Msg)
	req.SetQuestion("still.example.", dns.TypeA)
	if _, _, err := old.Resolve(context.Background(), req); err != nil {
		t.Fatalf("old router: %v", err)
	}
}

// TestRealLogAndStats wires the real query log writer and statistics recorder.
func TestRealLogAndStats(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "pk95dns.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	lw := querylog.NewWriter(st)
	rec := stats.New(st)

	up := startUpstream(t, false)
	srv := New(Deps{Filter: testEngine(t), Log: lw, Stats: rec})
	srv.routerCloseDelay = time.Millisecond
	t.Cleanup(srv.hosts.wg.Wait)
	cfg := baseSettings(up.addr)
	cfg.CacheEnabled = false
	cfg.Ratelimit = 1
	srv.Apply(Runtime{Settings: cfg, Router: newRouter(t, cfg), Clients: []store.Client{{ID: 1, Name: "Laptop", IDs: []string{"192.168.1.20"}, UseGlobalSettings: true, UseGlobalServices: true}}})

	for _, n := range []string{"plain.example.", "ads.example."} {
		req := new(dns.Msg)
		req.SetQuestion(n, dns.TypeA)
		srv.ServeDNS(newUDPWriter("192.168.1.20"), req)
		srv.limiter.setRate(0)
		srv.limiter.setRate(1)
	}
	// Rate limited: logged, not counted.
	for i := 0; i < 2; i++ {
		req := new(dns.Msg)
		req.SetQuestion("rl.example.", dns.TypeA)
		srv.ServeDNS(newUDPWriter("192.168.1.20"), req)
	}
	lw.Flush()
	qs, err := st.Queries(store.QueryFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(qs) != 4 {
		t.Fatalf("log entries %d: %+v", len(qs), qs)
	}
	byStatus := map[string]store.Query{}
	for _, q := range qs {
		byStatus[q.Status+"|"+q.Name] = q
	}
	if q := byStatus["blocked|ads.example"]; q.ClientName != "Laptop" || q.Rule != "||ads.example^" || q.ListID != 1 || q.Answer != "0.0.0.0" {
		t.Fatalf("blocked entry %+v", q)
	}
	if q := byStatus["ok|plain.example"]; q.Upstream != up.addr || q.Rcode != "NOERROR" {
		t.Fatalf("ok entry %+v", q)
	}
	if q := byStatus["refused|rl.example"]; q.Reason != "ratelimit" {
		t.Fatalf("ratelimit entry %+v (%v)", q, byStatus)
	}
	sum, err := rec.Summary(24, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Totals.Queries != 3 || sum.Totals.Blocked != 1 {
		t.Fatalf("stats totals %+v", sum.Totals)
	}
}
