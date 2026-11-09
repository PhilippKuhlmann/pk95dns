package upstream

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestPlainUDPAddsEDNSAndKeepsRequest(t *testing.T) {
	srv := newTestServer(t, answerA("192.0.2.1", 300))
	up, err := New(srv.addr, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	if up.Address() != srv.addr {
		t.Fatalf("Address() = %q", up.Address())
	}

	req := query("example.org", dns.TypeA)
	req.Id = 4711
	before := req.String()
	resp, err := up.Exchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if req.String() != before || req.IsEdns0() != nil {
		t.Fatal("Exchange modified the request")
	}
	if resp.Id != 4711 {
		t.Fatalf("answer id %d", resp.Id)
	}
	if got := firstA(t, resp); got != "192.0.2.1" {
		t.Fatalf("A = %s", got)
	}
	if resp.IsEdns0() != nil {
		t.Fatal("OPT added by the upstream must be removed from the answer")
	}
	if _, size := srv.last(); size != ednsUDPSize {
		t.Fatalf("EDNS0 size sent = %d, want %d", size, ednsUDPSize)
	}
	if srv.udpQueries.Load() != 1 || srv.tcpQueries.Load() != 0 {
		t.Fatalf("udp=%d tcp=%d", srv.udpQueries.Load(), srv.tcpQueries.Load())
	}

	// A request with its own EDNS0 keeps its size and gets the OPT back.
	req2 := query("example.org", dns.TypeA)
	req2.SetEdns0(4096, true)
	resp2, err := up.Exchange(context.Background(), req2)
	if err != nil {
		t.Fatal(err)
	}
	if _, size := srv.last(); size != 4096 {
		t.Fatalf("EDNS0 size sent = %d, want 4096", size)
	}
	if last, _ := srv.last(); last.IsEdns0() == nil || !last.IsEdns0().Do() {
		t.Fatal("DO bit not forwarded")
	}
	if resp2.IsEdns0() == nil {
		t.Fatal("OPT of the server missing")
	}
}

func TestPlainTruncatedRetriesOverTCP(t *testing.T) {
	srv := newTestServer(t, func(w dns.ResponseWriter, r *dns.Msg, proto string) {
		m := new(dns.Msg)
		m.SetReply(r)
		if proto == "udp" {
			m.Truncated = true
		} else {
			rr, _ := dns.NewRR(r.Question[0].Name + " 60 IN A 192.0.2.7")
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	})
	up, err := New("udp://"+srv.addr, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := up.Exchange(context.Background(), query("big.example", dns.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Truncated || firstA(t, resp) != "192.0.2.7" {
		t.Fatalf("unexpected answer %v", resp)
	}
	if srv.udpQueries.Load() != 1 || srv.tcpQueries.Load() != 1 {
		t.Fatalf("udp=%d tcp=%d", srv.udpQueries.Load(), srv.tcpQueries.Load())
	}
}

func TestTCPOnly(t *testing.T) {
	srv := newTestServer(t, answerA("192.0.2.2", 60))
	up, err := New("tcp://"+srv.addr, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		resp, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
		if err != nil {
			t.Fatal(err)
		}
		if firstA(t, resp) != "192.0.2.2" {
			t.Fatal("wrong answer")
		}
	}
	if srv.udpQueries.Load() != 0 || srv.tcpQueries.Load() != 3 {
		t.Fatalf("udp=%d tcp=%d", srv.udpQueries.Load(), srv.tcpQueries.Load())
	}
}

func TestPlainTimeoutAndCancel(t *testing.T) {
	srv := newTestServer(t, silentHandler)
	up, err := New(srv.addr, Options{Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = up.Exchange(context.Background(), query("example.org", dns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "Zeitüberschreitung") {
		t.Fatalf("err = %v, want Zeitüberschreitung", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("timeout took %v", d)
	}

	// Cancellation of the caller's context ends the exchange early.
	up2, _ := New(srv.addr, Options{Timeout: 10 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start = time.Now()
	_, err = up2.Exchange(ctx, query("example.org", dns.TypeA))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("cancel took %v", d)
	}
}

func TestPlainRejectsMismatchedAnswer(t *testing.T) {
	srv := newTestServer(t, func(w dns.ResponseWriter, r *dns.Msg, _ string) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Question[0].Name = "evil.example."
		_ = w.WriteMsg(m)
	})
	up, _ := New("tcp://"+srv.addr, Options{Timeout: time.Second})
	_, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "passt nicht") {
		t.Fatalf("err = %v", err)
	}
}

func TestPlainConnectionRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	up, _ := New("tcp://"+addr, Options{Timeout: time.Second})
	_, err = up.Exchange(context.Background(), query("example.org", dns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "Verbindung abgelehnt") {
		t.Fatalf("err = %v", err)
	}
}

// bootstrapServer answers "<host> A 127.0.0.1" for every name.
func bootstrapServer(t *testing.T, ttl uint32) *testServer {
	return newTestServer(t, answerA("127.0.0.1", ttl))
}

func TestDoT(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newTLSServer(t, cert, answerA("192.0.2.3", 60), 0)
	boot := bootstrapServer(t, 300)

	up, err := New("tls://dns.test:"+port(srv.addr), Options{Timeout: 2 * time.Second, Bootstrap: []string{boot.addr}})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	dot := up.(*dotUpstream)

	req := query("example.org", dns.TypeA)
	req.Id = 99
	before := req.String()
	for i := range 5 {
		resp, err := up.Exchange(context.Background(), req)
		if err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
		if resp.Id != 99 || firstA(t, resp) != "192.0.2.3" {
			t.Fatalf("unexpected answer %v", resp)
		}
	}
	if req.String() != before {
		t.Fatal("request modified")
	}
	if n := srv.accepts.Load(); n != 1 {
		t.Fatalf("connections = %d, want 1 (reuse)", n)
	}
	if n := dot.idleCount(); n != 1 {
		t.Fatalf("idle = %d", n)
	}
	// Bootstrap was asked once (A + AAAA).
	if n := boot.udpQueries.Load(); n != 2 {
		t.Fatalf("bootstrap queries = %d, want 2", n)
	}

	// Concurrent exchanges open more connections, the pool keeps at most dotMaxIdle.
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if _, err := up.Exchange(context.Background(), query("example.org", dns.TypeA)); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := dot.idleCount(); n > dotMaxIdle {
		t.Fatalf("idle = %d > %d", n, dotMaxIdle)
	}

	// Idle connections expire.
	base := time.Now()
	dot.mu.Lock()
	dot.now = func() time.Time { return base.Add(dotIdleTimeout + time.Second) }
	dot.mu.Unlock()
	accepts := srv.accepts.Load()
	if _, err := up.Exchange(context.Background(), query("example.org", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	if srv.accepts.Load() != accepts+1 {
		t.Fatal("expired idle connection was reused")
	}

	if err := up.Close(); err != nil {
		t.Fatal(err)
	}
	if dot.idleCount() != 0 {
		t.Fatal("Close kept idle connections")
	}
}

func TestDoTServerClosedIdleConnection(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newTLSServer(t, cert, answerA("192.0.2.4", 60), 50*time.Millisecond)
	up, err := New("tls://127.0.0.1:"+port(srv.addr), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	if _, err := up.Exchange(context.Background(), query("a.example", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // server closes the idle connection
	resp, err := up.Exchange(context.Background(), query("b.example", dns.TypeA))
	if err != nil {
		t.Fatalf("retry on a fresh connection failed: %v", err)
	}
	if firstA(t, resp) != "192.0.2.4" {
		t.Fatal("wrong answer")
	}
	if srv.accepts.Load() != 2 {
		t.Fatalf("accepts = %d, want 2", srv.accepts.Load())
	}
}

func TestDoTCertificateChecked(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newTLSServer(t, cert, answerA("192.0.2.3", 60), 0)
	boot := bootstrapServer(t, 300)

	// Name not in the certificate.
	up, _ := New("tls://other.test:"+port(srv.addr), Options{Timeout: 2 * time.Second, Bootstrap: []string{boot.addr}})
	_, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "Zertifikat") {
		t.Fatalf("err = %v, want certificate error", err)
	}

	// Unknown authority.
	_, otherPool := selfSigned(t, "dns.test")
	testRootCAs = otherPool
	up2, _ := New("tls://dns.test:"+port(srv.addr), Options{Timeout: 2 * time.Second, Bootstrap: []string{boot.addr}})
	_, err = up2.Exchange(context.Background(), query("example.org", dns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "Zertifikat") {
		t.Fatalf("err = %v, want certificate error", err)
	}
}

// dohServer is an RFC 8484 test server.
type dohServer struct {
	*httptest.Server
	requests atomic.Int64
	http2    atomic.Bool
	status   atomic.Int64 // != 0: answer with this HTTP status
}

func newDoHServer(t *testing.T, ip string) *dohServer {
	t.Helper()
	d := &dohServer{}
	d.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.requests.Add(1)
		if r.ProtoMajor == 2 {
			d.http2.Store(true)
		}
		if s := d.status.Load(); s != 0 {
			http.Error(w, "nope", int(s))
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" ||
			r.Header.Get("Content-Type") != dohMediaType || r.Header.Get("Accept") != dohMediaType {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		m := new(dns.Msg)
		if err := m.Unpack(body); err != nil || m.Id != 0 {
			http.Error(w, "bad message", http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(m)
		rr, _ := dns.NewRR(m.Question[0].Name + " 60 IN A " + ip)
		resp.Answer = append(resp.Answer, rr)
		wire, _ := resp.Pack()
		w.Header().Set("Content-Type", dohMediaType)
		_, _ = w.Write(wire)
	}))
	d.EnableHTTP2 = true
	d.StartTLS()
	t.Cleanup(d.Close)
	pool := d.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	useRoots(t, pool)
	return d
}

func TestDoH(t *testing.T) {
	srv := newDoHServer(t, "192.0.2.5")
	p := port(strings.TrimPrefix(srv.URL, "https://"))

	t.Run("ip host", func(t *testing.T) {
		up, err := New("https://127.0.0.1:"+p+"/dns-query", Options{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		req := query("example.org", dns.TypeA)
		req.Id = 1234
		before := req.String()
		resp, err := up.Exchange(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Id != 1234 {
			t.Fatalf("id = %d, want 1234", resp.Id)
		}
		if req.String() != before || req.Id != 1234 {
			t.Fatal("request modified")
		}
		if firstA(t, resp) != "192.0.2.5" {
			t.Fatal("wrong answer")
		}
		if !srv.http2.Load() {
			t.Fatal("HTTP/2 not used")
		}
	})

	t.Run("host name via bootstrap", func(t *testing.T) {
		boot := bootstrapServer(t, 10)
		up, err := New("https://example.com:"+p+"/dns-query", Options{Timeout: 2 * time.Second, Bootstrap: []string{boot.addr}})
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		for range 3 {
			resp, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
			if err != nil {
				t.Fatal(err)
			}
			if firstA(t, resp) != "192.0.2.5" {
				t.Fatal("wrong answer")
			}
		}
		if n := boot.udpQueries.Load(); n != 2 {
			t.Fatalf("bootstrap queries = %d, want 2 (A+AAAA once)", n)
		}
	})

	t.Run("http error", func(t *testing.T) {
		srv.status.Store(http.StatusInternalServerError)
		defer srv.status.Store(0)
		up, _ := New("https://127.0.0.1:"+p+"/dns-query", Options{Timeout: 2 * time.Second})
		defer up.Close()
		_, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
		if err == nil || !strings.Contains(err.Error(), "HTTP-Status 500") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("wrong path", func(t *testing.T) {
		up, _ := New("https://127.0.0.1:"+p+"/other", Options{Timeout: 2 * time.Second})
		defer up.Close()
		_, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
		if err == nil || !strings.Contains(err.Error(), "HTTP-Status 400") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("bootstrap failure", func(t *testing.T) {
		boot := newTestServer(t, rcodeHandler(dns.RcodeNameError))
		up, _ := New("https://example.com:"+p+"/dns-query", Options{Timeout: time.Second, Bootstrap: []string{boot.addr}})
		defer up.Close()
		_, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
		if err == nil || !strings.Contains(err.Error(), "konnte nicht aufgelöst werden") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestResolverCache(t *testing.T) {
	boot := bootstrapServer(t, 10)
	r, err := newResolver([]string{boot.addr}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }

	addrs, err := r.lookup(context.Background(), "dns.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("addrs = %v", addrs)
	}
	// TTL 10 is raised to the minimum of 60 s.
	now = now.Add(50 * time.Second)
	if _, err := r.lookup(context.Background(), "DNS.test."); err != nil {
		t.Fatal(err)
	}
	if n := boot.udpQueries.Load(); n != 2 {
		t.Fatalf("queries = %d, want 2", n)
	}
	now = now.Add(11 * time.Second)
	if _, err := r.lookup(context.Background(), "dns.test"); err != nil {
		t.Fatal(err)
	}
	if n := boot.udpQueries.Load(); n != 4 {
		t.Fatalf("queries = %d, want 4 after expiry", n)
	}

	// IP literals need no lookup.
	if a, err := r.lookup(context.Background(), "::1"); err != nil || a[0] != netip.MustParseAddr("::1") {
		t.Fatalf("lookup(::1) = %v, %v", a, err)
	}
	if n := boot.udpQueries.Load(); n != 4 {
		t.Fatal("IP literal was resolved")
	}

	// Without bootstrap servers the system resolver is used.
	sys, _ := newResolver(nil, time.Second)
	var called atomic.Int64
	sys.lookupSystem = func(_ context.Context, host string) ([]netip.Addr, error) {
		called.Add(1)
		return []netip.Addr{netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.2")}, nil
	}
	got, err := sys.lookup(context.Background(), "host.test")
	if err != nil || len(got) != 2 || got[0] != netip.MustParseAddr("127.0.0.2") {
		t.Fatalf("system lookup = %v, %v (IPv4 first)", got, err)
	}
	_, _ = sys.lookup(context.Background(), "host.test")
	if called.Load() != 1 {
		t.Fatalf("system resolver called %d times", called.Load())
	}

	// Second bootstrap server is used when the first fails.
	dead := newTestServer(t, rcodeHandler(dns.RcodeServerFailure))
	r2, _ := newResolver([]string{dead.addr, boot.addr}, time.Second)
	if _, err := r2.lookup(context.Background(), "x.test"); err != nil {
		t.Fatalf("fallback to second bootstrap server: %v", err)
	}

	if _, err := newResolver([]string{"dns.google"}, time.Second); err == nil {
		t.Fatal("host name accepted as bootstrap")
	}
}

func TestNewInvalid(t *testing.T) {
	if _, err := New("sdns://x", Options{}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := New("tls://dns.test", Options{Bootstrap: []string{"nope"}}); err == nil {
		t.Fatal("expected bootstrap error")
	}
}

func TestTestFunction(t *testing.T) {
	srv := newTestServer(t, answerA("192.0.2.9", 60))
	rtt, err := Test(context.Background(), srv.addr, nil, time.Second)
	if err != nil || rtt <= 0 {
		t.Fatalf("Test = %v, %v", rtt, err)
	}
	last, _ := srv.last()
	if last.Question[0].Name != "example.org." || last.Question[0].Qtype != dns.TypeA {
		t.Fatalf("asked %v", last.Question)
	}

	bad := newTestServer(t, rcodeHandler(dns.RcodeServerFailure))
	if _, err := Test(context.Background(), bad.addr, nil, time.Second); err == nil || !strings.Contains(err.Error(), "SERVFAIL") {
		t.Fatalf("err = %v", err)
	}
	if _, err := Test(context.Background(), "kaputt", nil, time.Second); err == nil {
		t.Fatal("invalid address accepted")
	}

	// DoH with host name through the bootstrap server.
	doh := newDoHServer(t, "192.0.2.10")
	boot := bootstrapServer(t, 300)
	p := port(strings.TrimPrefix(doh.URL, "https://"))
	if _, err := Test(context.Background(), "https://example.com:"+p+"/dns-query", []string{boot.addr}, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if boot.udpQueries.Load() == 0 {
		t.Fatal("bootstrap not used")
	}
}
