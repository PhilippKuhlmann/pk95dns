package upstream

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// udpRelay forwards UDP between clients and target, one upstream socket per client
// address. kill silently drops every packet of the flows that exist at that moment (both
// directions), like a server that lost its connection state and sends neither
// CONNECTION_CLOSE nor a stateless reset. New flows (a fresh client socket) still work.
type udpRelay struct {
	pc     net.PacketConn
	target *net.UDPAddr

	mu    sync.Mutex
	flows map[string]*relayFlow
	total atomic.Int64 // flows ever created
}

type relayFlow struct {
	up   *net.UDPConn
	dead atomic.Bool
}

func newUDPRelay(t *testing.T, target string) *udpRelay {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ta, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	r := &udpRelay{pc: pc, target: ta, flows: map[string]*relayFlow{}}
	t.Cleanup(func() {
		_ = pc.Close()
		r.mu.Lock()
		for _, f := range r.flows {
			_ = f.up.Close()
		}
		r.mu.Unlock()
	})
	go r.serve()
	return r
}

func (r *udpRelay) addr() string { return r.pc.LocalAddr().String() }

func (r *udpRelay) serve() {
	buf := make([]byte, 65536)
	for {
		n, client, err := r.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		r.mu.Lock()
		f, ok := r.flows[client.String()]
		if !ok {
			up, err := net.DialUDP("udp", nil, r.target)
			if err != nil {
				r.mu.Unlock()
				continue
			}
			f = &relayFlow{up: up}
			r.flows[client.String()] = f
			r.total.Add(1)
			go r.back(f, client)
		}
		r.mu.Unlock()
		if !f.dead.Load() {
			_, _ = f.up.Write(buf[:n])
		}
	}
}

func (r *udpRelay) back(f *relayFlow, client net.Addr) {
	buf := make([]byte, 65536)
	for {
		n, err := f.up.Read(buf)
		if err != nil {
			return
		}
		if !f.dead.Load() {
			_, _ = r.pc.WriteTo(buf[:n], client)
		}
	}
}

func (r *udpRelay) kill() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.flows {
		f.dead.Store(true)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// --- Bootstrap cache ---

func TestResolverTTLCapped(t *testing.T) {
	// A forged bootstrap answer with the maximum TTL must not pin the address for decades.
	boot := bootstrapServer(t, 2147483647)
	r, err := newResolver([]string{boot.addr}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }
	if _, err := r.lookup(context.Background(), "dns.test"); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	exp := r.cache["dns.test"].expires
	r.mu.Unlock()
	if d := exp.Sub(now); d != bootstrapMaxTTL {
		t.Fatalf("cached for %v, want %v", d, bootstrapMaxTTL)
	}
	now = now.Add(bootstrapMaxTTL + time.Second)
	if _, err := r.lookup(context.Background(), "dns.test"); err != nil {
		t.Fatal(err)
	}
	if n := boot.udpQueries.Load(); n != 4 {
		t.Fatalf("bootstrap queries = %d, want 4 (resolved again after the cap)", n)
	}
	if bootstrapSystemTTL > bootstrapMaxTTL {
		t.Fatal("system resolver TTL above the cap")
	}
}

// closedPort returns a local port where nothing listens (TCP and UDP).
func closedPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := port(pc.LocalAddr().String())
	_ = pc.Close()
	return p
}

func TestResolverInvalidatedWhenDialFails(t *testing.T) {
	t.Run("DoT", func(t *testing.T) {
		boot := bootstrapServer(t, 3600)
		up, err := New("tls://dns.test:"+closedPort(t), Options{Timeout: time.Second, Bootstrap: []string{boot.addr}})
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		for i := range 2 {
			if _, err := up.Exchange(context.Background(), query("example.org", dns.TypeA)); err == nil {
				t.Fatal("exchange with a closed port succeeded")
			}
			if n, want := boot.udpQueries.Load(), int64(2*(i+1)); n != want {
				t.Fatalf("after exchange %d: bootstrap queries = %d, want %d (cache dropped after failed dial)", i+1, n, want)
			}
		}
	})

	t.Run("DoQ", func(t *testing.T) {
		boot := bootstrapServer(t, 3600)
		up, err := New("quic://dns.test:"+closedPort(t), Options{Timeout: 300 * time.Millisecond, Bootstrap: []string{boot.addr}})
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		doq := up.(*doqUpstream)
		dialDone := func() bool {
			doq.mu.Lock()
			defer doq.mu.Unlock()
			return doq.dialing == nil
		}
		for i := range 2 {
			if _, err := up.Exchange(context.Background(), query("example.org", dns.TypeA)); err == nil {
				t.Fatal("exchange with a closed port succeeded")
			}
			waitFor(t, "the dial to end", dialDone)
			if n, want := boot.udpQueries.Load(), int64(2*(i+1)); n != want {
				t.Fatalf("after exchange %d: bootstrap queries = %d, want %d", i+1, n, want)
			}
		}
	})

	t.Run("cancelled dial keeps the cache", func(t *testing.T) {
		boot := bootstrapServer(t, 3600)
		r, _ := newResolver([]string{boot.addr}, time.Second)
		addrs, err := r.lookup(context.Background(), "dns.test")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r.invalidate(ctx, "dns.test", addrs, ctx.Err())
		// A newer entry is not dropped for a failure on older addresses.
		r.invalidate(context.Background(), "dns.test", []netip.Addr{netip.MustParseAddr("192.0.2.1")}, net.ErrClosed)
		if _, err := r.lookup(context.Background(), "dns.test"); err != nil {
			t.Fatal(err)
		}
		if n := boot.udpQueries.Load(); n != 2 {
			t.Fatalf("bootstrap queries = %d, want 2 (still cached)", n)
		}
	})
}

// --- DoQ dial detached from the query ---

func TestDoQDialSurvivesCancelledQuery(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newDoQServer(t, cert, 0, doqAnswerA("192.0.2.30"))
	up, err := New("quic://127.0.0.1:"+port(srv.addr), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	doq := up.(*doqUpstream)

	// The query that starts the dial is cancelled at once: the handshake goes on.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := up.Exchange(ctx, query("example.org", dns.TypeA)); err == nil {
		t.Fatal("cancelled exchange succeeded")
	}
	waitFor(t, "the background dial", func() bool { return doq.dials.Load() == 1 })
	resp, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
	if err != nil || firstA(t, resp) != "192.0.2.30" {
		t.Fatalf("resp %v err %v", resp, err)
	}
	if n := srv.accepts.Load(); n != 1 || doq.dials.Load() != 1 {
		t.Fatalf("accepts = %d, dials = %d, want 1 (connection of the cancelled query reused)", n, doq.dials.Load())
	}
}

func TestRouterParallelUsesDoQ(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	plain := newTestServer(t, answerA("192.0.2.31", 60))
	srv := newDoQServer(t, cert, 0, doqAnswerA("192.0.2.32"))
	r := newRouter(t, Config{
		Upstreams: []string{plain.addr, "quic://127.0.0.1:" + port(srv.addr)},
		Mode:      "parallel",
		Timeout:   2 * time.Second,
	})
	doq := r.main[1].up.(*doqUpstream)
	for i := range 50 {
		if _, _, err := r.Resolve(context.Background(), query("example.org", dns.TypeA)); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	waitFor(t, "the DoQ dial", func() bool { return doq.dials.Load() >= 1 })
	if n := srv.accepts.Load(); n != 1 || doq.dials.Load() != 1 {
		t.Fatalf("accepts = %d, dials = %d, want one connection kept across cancelled queries", n, doq.dials.Load())
	}
}

// --- Silently dead QUIC connections ---

func TestDoQSilentlyDeadConnectionIsReplaced(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newDoQServer(t, cert, 0, doqAnswerA("192.0.2.33"))
	relay := newUDPRelay(t, srv.addr)
	up, err := New("quic://127.0.0.1:"+port(relay.addr()), Options{Timeout: 600 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	doq := up.(*doqUpstream)
	if _, err := up.Exchange(context.Background(), query("a.example", dns.TypeA)); err != nil {
		t.Fatal(err)
	}

	relay.kill() // the server forgets the connection without telling the client
	if _, err := up.Exchange(context.Background(), query("b.example", dns.TypeA)); err == nil || !strings.Contains(err.Error(), "Zeitüberschreitung") {
		t.Fatalf("err = %v, want Zeitüberschreitung", err)
	}
	doq.mu.Lock()
	detached := doq.conn == nil
	doq.mu.Unlock()
	if !detached {
		t.Fatal("silent connection still shared after a timeout without any data")
	}
	start := time.Now()
	resp, err := up.Exchange(context.Background(), query("c.example", dns.TypeA))
	if err != nil || firstA(t, resp) != "192.0.2.33" {
		t.Fatalf("next query must use a fresh connection: resp %v err %v", resp, err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("next query took %v", d)
	}
	if doq.dials.Load() != 2 || relay.total.Load() != 2 {
		t.Fatalf("dials = %d, flows = %d, want 2", doq.dials.Load(), relay.total.Load())
	}
}

func TestDoQSlowQueryKeepsLiveConnection(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newDoQServer(t, cert, 0, func(q *dns.Msg) []byte {
		if strings.HasPrefix(q.Question[0].Name, "slow.") {
			time.Sleep(1500 * time.Millisecond)
		}
		wire, _ := replyA(q, "192.0.2.34").Pack()
		return frame(wire)
	})
	up, err := New("quic://127.0.0.1:"+port(srv.addr), Options{Timeout: 600 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	doq := up.(*doqUpstream)
	if _, err := up.Exchange(context.Background(), query("a.example", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := up.Exchange(context.Background(), query("slow.example", dns.TypeA))
		done <- err
	}()
	// Other queries are answered on the same connection while the slow one waits.
	for waiting := true; waiting; {
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("slow query did not time out")
			}
			waiting = false
		case <-time.After(50 * time.Millisecond):
			if _, err := up.Exchange(context.Background(), query("b.example", dns.TypeA)); err != nil {
				t.Fatal(err)
			}
		}
	}
	doq.mu.Lock()
	kept := doq.conn != nil
	doq.mu.Unlock()
	if !kept || doq.dials.Load() != 1 {
		t.Fatalf("live connection dropped after one slow query: kept=%v dials=%d", kept, doq.dials.Load())
	}
}

func TestDoH3SilentlyDeadConnectionIsReplaced(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	rec := &dohRecord{}
	p := newH3Server(t, cert, dohAnswer(rec, func(w http.ResponseWriter, q *dns.Msg) { writeDNS(w, replyA(q, "192.0.2.35")) }))
	relay := newUDPRelay(t, "127.0.0.1:"+p)
	up, err := New("h3://127.0.0.1:"+port(relay.addr())+"/dns-query", Options{Timeout: 600 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	if _, err := up.Exchange(context.Background(), query("a.example", dns.TypeA)); err != nil {
		t.Fatal(err)
	}

	relay.kill()
	if _, err := up.Exchange(context.Background(), query("b.example", dns.TypeA)); err == nil {
		t.Fatal("exchange on a dead connection succeeded")
	}
	start := time.Now()
	resp, err := up.Exchange(context.Background(), query("c.example", dns.TypeA))
	if err != nil || firstA(t, resp) != "192.0.2.35" {
		t.Fatalf("next query must use a fresh connection: resp %v err %v", resp, err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("next query took %v", d)
	}
	if n := relay.total.Load(); n != 2 {
		t.Fatalf("flows = %d, want 2", n)
	}
}

// --- next address tried when the first one silently drops packets ---

// blackholeFirst returns a resolver whose host names resolve to an unreachable documentation
// address (packets are dropped, no error) followed by 127.0.0.1.
func blackholeFirst() *resolver {
	r, _ := newResolver(nil, time.Second)
	r.lookupSystem = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	return r
}

func TestDialTriesNextAddress(t *testing.T) {
	t.Run("TCP", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := blackholeFirst().dial(ctx, "dns.test", port(l.Addr().String()))
		if err != nil {
			t.Fatalf("second address not tried: %v", err)
		}
		_ = conn.Close()
	})

	t.Run("QUIC", func(t *testing.T) {
		cert, pool := selfSigned(t, "dns.test")
		useRoots(t, pool)
		srv := newDoQServer(t, cert, 0, doqAnswerA("192.0.2.31"))
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := dialQUIC(ctx, blackholeFirst(), "dns.test", port(srv.addr), newTLS13Config("dns.test", doqALPN), newQUICConfig(2*time.Second))
		if err != nil {
			t.Fatalf("second address not tried: %v", err)
		}
		_ = conn.CloseWithError(0, "")
	})
}
