package upstream

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// paddingOf returns the padding option of m, nil when there is none.
func paddingOf(m *dns.Msg) *dns.EDNS0_PADDING {
	opt := m.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if p, ok := o.(*dns.EDNS0_PADDING); ok {
			return p
		}
	}
	return nil
}

func TestPadQuery(t *testing.T) {
	for n := 1; n <= 200; n += 7 {
		name := strings.Repeat("a", n%60+1) + "." + strings.Repeat("b", min(n/3+1, 63)) + ".example."
		req := query(name, dns.TypeAAAA)
		req.Id = 777
		before := req.String()

		m, added := encryptedQuery(req, true)
		if !added {
			t.Fatal("OPT not reported as added")
		}
		wire, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if len(wire)%paddingBlock != 0 {
			t.Fatalf("%s: wire length %d is not a multiple of %d", name, len(wire), paddingBlock)
		}
		if m.Id != 0 || m.IsEdns0().UDPSize() != ednsUDPSize {
			t.Fatalf("id %d size %d", m.Id, m.IsEdns0().UDPSize())
		}
		if req.String() != before || req.IsEdns0() != nil || req.Id != 777 {
			t.Fatal("caller's message modified")
		}
	}

	// Existing OPT: options and DO bit are kept, old padding replaced, ID kept for DoT.
	req := query("example.org", dns.TypeA)
	req.Id = 42
	req.SetEdns0(4096, true)
	cookie := &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"}
	req.IsEdns0().Option = append(req.IsEdns0().Option, cookie, &dns.EDNS0_PADDING{Padding: make([]byte, 300)})
	before := req.String()
	m, added := encryptedQuery(req, false)
	if added {
		t.Fatal("OPT reported as added")
	}
	if req.String() != before || len(req.IsEdns0().Option) != 2 {
		t.Fatal("caller's message modified")
	}
	opt := m.IsEdns0()
	if m.Id != 42 || !opt.Do() || opt.UDPSize() != 4096 {
		t.Fatalf("id %d do %v size %d", m.Id, opt.Do(), opt.UDPSize())
	}
	var paddings, cookies int
	for _, o := range opt.Option {
		switch o.(type) {
		case *dns.EDNS0_PADDING:
			paddings++
		case *dns.EDNS0_COOKIE:
			cookies++
		}
	}
	if paddings != 1 || cookies != 1 {
		t.Fatalf("options %v", opt.Option)
	}
	if wire, _ := m.Pack(); len(wire)%paddingBlock != 0 {
		t.Fatalf("wire length %d", len(wire))
	}
}

func TestCleanAnswer(t *testing.T) {
	resp := replyA(func() *dns.Msg { q := query("example.org", dns.TypeA); q.SetEdns0(1232, false); return q }(), "192.0.2.1")
	cleanAnswer(resp, 9, false)
	if resp.Id != 9 || resp.IsEdns0() == nil || paddingOf(resp) != nil {
		t.Fatalf("padding not stripped: %v", resp)
	}
	resp2 := replyA(func() *dns.Msg { q := query("example.org", dns.TypeA); q.SetEdns0(1232, false); return q }(), "192.0.2.1")
	cleanAnswer(resp2, 10, true)
	if resp2.IsEdns0() != nil {
		t.Fatal("added OPT not removed")
	}
}

func TestPlainIsNotPadded(t *testing.T) {
	srv := newTestServer(t, answerA("192.0.2.1", 60))
	for _, addr := range []string{srv.addr, "tcp://" + srv.addr} {
		up, err := New(addr, Options{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		req := query("example.org", dns.TypeA)
		req.Id = 5
		if _, err := up.Exchange(context.Background(), req); err != nil {
			t.Fatal(err)
		}
		last, _ := srv.last()
		if paddingOf(last) != nil || last.Id != 5 {
			t.Fatalf("%s: plain query padded or ID changed: %v", addr, last)
		}
	}
}

func TestDoTIsPadded(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newTLSServer(t, cert, answerA("192.0.2.3", 60), 0)
	up, err := New("tls://127.0.0.1:"+port(srv.addr), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	req := query("example.org", dns.TypeA)
	req.Id = 31337
	resp, err := up.Exchange(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	last, _ := srv.last()
	if paddingOf(last) == nil || last.Len()%paddingBlock != 0 {
		t.Fatalf("DoT query not padded: len %d", last.Len())
	}
	if last.Id != 31337 || resp.Id != 31337 || resp.IsEdns0() != nil {
		t.Fatalf("ids %d/%d, OPT %v", last.Id, resp.Id, resp.IsEdns0())
	}
}

func TestPlainRejectsAnswerWithoutQR(t *testing.T) {
	srv := newTestServer(t, func(w dns.ResponseWriter, r *dns.Msg, _ string) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Response = false
		_ = w.WriteMsg(m)
	})
	up, _ := New("tcp://"+srv.addr, Options{Timeout: time.Second})
	_, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "QR-Bit") {
		t.Fatalf("err = %v", err)
	}
}

func TestTLSConfigs(t *testing.T) {
	spec, _ := ParseAddress("https://dns.test/dns-query")
	res, _ := newResolver(nil, time.Second)
	doh := newDoH(spec, Options{Timeout: time.Second}, res)
	if c := doh.transport.TLSClientConfig; c.MinVersion != tls.VersionTLS12 || c.InsecureSkipVerify || c.ServerName != "dns.test" {
		t.Fatalf("DoH TLS config %+v", c)
	}
	if doh.transport.Proxy != nil || !doh.transport.DisableCompression || doh.client.Jar != nil || doh.client.CheckRedirect == nil {
		t.Fatal("DoH transport not hardened")
	}
	if doh.transport.ResponseHeaderTimeout > time.Second || doh.transport.TLSHandshakeTimeout > time.Second {
		t.Fatal("DoH timeouts above the request timeout")
	}
	spec3, _ := ParseAddress("h3://dns.test/dns-query")
	h3 := newDoH3(spec3, Options{Timeout: time.Second}, res)
	if c := h3.transport.TLSClientConfig; c.MinVersion != tls.VersionTLS13 || c.InsecureSkipVerify || c.NextProtos[0] != "h3" {
		t.Fatalf("DoH3 TLS config %+v", c)
	}
	specQ, _ := ParseAddress("quic://dns.test")
	doq := newDoQ(specQ, Options{Timeout: time.Second}, res)
	if c := doq.tlsCfg; c.MinVersion != tls.VersionTLS13 || c.InsecureSkipVerify || len(c.NextProtos) != 1 || c.NextProtos[0] != "doq" {
		t.Fatalf("DoQ TLS config %+v", c)
	}
}

// --- DNS-over-QUIC ---

func TestDoQ(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newDoQServer(t, cert, 0, doqAnswerA("192.0.2.20"))
	boot := bootstrapServer(t, 300)

	up, err := New("quic://dns.test:"+port(srv.addr), Options{Timeout: 2 * time.Second, Bootstrap: []string{boot.addr}})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	doq := up.(*doqUpstream)

	req := query("example.org", dns.TypeA)
	req.Id = 4711
	before := req.String()
	for i := range 5 {
		resp, err := up.Exchange(context.Background(), req)
		if err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
		if resp.Id != 4711 || firstA(t, resp) != "192.0.2.20" {
			t.Fatalf("unexpected answer %v", resp)
		}
		if resp.IsEdns0() != nil {
			t.Fatal("OPT added for the upstream must be removed from the answer")
		}
	}
	if req.String() != before {
		t.Fatal("request modified")
	}
	if srv.nonZero.Load() != 0 || srv.unframed.Load() != 0 {
		t.Fatalf("non-zero IDs %d, unframed %d", srv.nonZero.Load(), srv.unframed.Load())
	}
	wire, last := srv.last()
	if len(wire)%paddingBlock != 0 || paddingOf(last) == nil {
		t.Fatalf("DoQ query not padded: %d bytes", len(wire))
	}
	if n := srv.accepts.Load(); n != 1 {
		t.Fatalf("connections = %d, want 1 (reuse)", n)
	}
	if n := boot.udpQueries.Load(); n != 2 {
		t.Fatalf("bootstrap queries = %d, want 2", n)
	}

	// Concurrent queries share the one connection (one stream each).
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if _, err := up.Exchange(context.Background(), query("example.org", dns.TypeA)); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := srv.accepts.Load(); n != 1 || doq.dials.Load() != 1 {
		t.Fatalf("connections = %d, dials = %d, want 1", n, doq.dials.Load())
	}

	// The server closes the connection: the next query reconnects.
	srv.closeConns()
	time.Sleep(100 * time.Millisecond)
	resp, err := up.Exchange(context.Background(), query("again.example", dns.TypeA))
	if err != nil {
		t.Fatalf("after server close: %v", err)
	}
	if firstA(t, resp) != "192.0.2.20" || srv.accepts.Load() != 2 {
		t.Fatalf("accepts = %d", srv.accepts.Load())
	}

	// After Close no more queries.
	if err := up.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := up.Exchange(context.Background(), req); err == nil {
		t.Fatal("exchange after Close succeeded")
	}
}

func TestDoQRetryOnClosedConnection(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newDoQServer(t, cert, 0, doqAnswerA("192.0.2.21"))
	up, err := New("quic://127.0.0.1:"+port(srv.addr), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	doq := up.(*doqUpstream)
	if _, err := up.Exchange(context.Background(), query("a.example", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	// Close the client side of the shared connection behind the upstream's back, as an
	// idle timeout would: the query must be answered on a fresh connection.
	doq.mu.Lock()
	conn := doq.conn.conn
	doq.mu.Unlock()
	_ = conn.CloseWithError(doqNoError, "")
	resp, err := up.Exchange(context.Background(), query("b.example", dns.TypeA))
	if err != nil {
		t.Fatalf("retry on a fresh connection failed: %v", err)
	}
	if firstA(t, resp) != "192.0.2.21" || doq.dials.Load() != 2 {
		t.Fatalf("dials = %d", doq.dials.Load())
	}
}

func TestDoQIdleTimeoutReconnects(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newDoQServer(t, cert, 150*time.Millisecond, doqAnswerA("192.0.2.22"))
	up, err := New("quic://127.0.0.1:"+port(srv.addr), Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	// quic-go accepts a peer idle timeout of 5 s at least, so shorten the local one too.
	up.(*doqUpstream).quicCfg.MaxIdleTimeout = 150 * time.Millisecond
	if _, err := up.Exchange(context.Background(), query("a.example", dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond) // idle timeout on both sides
	if _, err := up.Exchange(context.Background(), query("b.example", dns.TypeA)); err != nil {
		t.Fatalf("after idle timeout: %v", err)
	}
	if n := srv.accepts.Load(); n != 2 {
		t.Fatalf("accepts = %d, want 2", n)
	}
}

func TestDoQBadAnswers(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newDoQServer(t, cert, 0, doqAnswerA("192.0.2.23"))
	up, err := New("quic://127.0.0.1:"+port(srv.addr), Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()

	tests := []struct {
		name string
		h    doqHandler
		want string
	}{
		{"oversize", func(q *dns.Msg) []byte {
			wire, _ := replyA(q, "192.0.2.1").Pack()
			out := frame(wire)
			return append(out, make([]byte, 70000)...)
		}, "zu groß"},
		{"length mismatch", func(q *dns.Msg) []byte {
			wire, _ := replyA(q, "192.0.2.1").Pack()
			out := frame(wire)
			out[1]++ // prefix one byte longer than the message
			return out
		}, "Längenangabe"},
		{"two messages", func(q *dns.Msg) []byte {
			wire, _ := replyA(q, "192.0.2.1").Pack()
			return append(frame(wire), frame(wire)...)
		}, "Längenangabe"},
		{"id not zero", func(q *dns.Msg) []byte {
			m := replyA(q, "192.0.2.1")
			m.Id = 1234
			wire, _ := m.Pack()
			return frame(wire)
		}, "ID ist nicht 0"},
		{"question mismatch", func(q *dns.Msg) []byte {
			m := replyA(q, "192.0.2.1")
			m.Question[0].Name = "evil.example."
			wire, _ := m.Pack()
			return frame(wire)
		}, "passt nicht"},
		{"type mismatch", func(q *dns.Msg) []byte {
			m := replyA(q, "192.0.2.1")
			m.Question[0].Qtype = dns.TypeAAAA
			wire, _ := m.Pack()
			return frame(wire)
		}, "passt nicht"},
		{"empty stream", func(*dns.Msg) []byte { return []byte{} }, "zu kurz"},
		// A stream reset is reported in German with the DoQ code name.
		{"stream reset", func(*dns.Msg) []byte { return doqResetExcessiveLoad }, "Server hat die DoQ-Anfrage abgebrochen: DOQ_EXCESSIVE_LOAD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv.setHandler(tt.h)
			before := srv.queries.Load()
			_, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if n := srv.queries.Load() - before; n != 1 {
				t.Fatalf("server saw %d queries, want 1 (no retry after a bad answer)", n)
			}
		})
	}

	// Case-insensitive question match is fine; the upstream works again afterwards.
	srv.setHandler(func(q *dns.Msg) []byte {
		m := replyA(q, "192.0.2.24")
		m.Question[0].Name = strings.ToUpper(m.Question[0].Name)
		wire, _ := m.Pack()
		return frame(wire)
	})
	resp, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
	if err != nil || firstA(t, resp) != "192.0.2.24" {
		t.Fatalf("resp %v err %v", resp, err)
	}
}

func TestDoQTimeoutAndCertificate(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	srv := newDoQServer(t, cert, 0, func(*dns.Msg) []byte { time.Sleep(2 * time.Second); return nil })
	up, _ := New("quic://127.0.0.1:"+port(srv.addr), Options{Timeout: 300 * time.Millisecond})
	defer up.Close()
	start := time.Now()
	_, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "Zeitüberschreitung") {
		t.Fatalf("err = %v, want Zeitüberschreitung", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("timeout took %v", d)
	}

	// Name not in the certificate.
	boot := bootstrapServer(t, 300)
	bad, _ := New("quic://other.test:"+port(srv.addr), Options{Timeout: time.Second, Bootstrap: []string{boot.addr}})
	defer bad.Close()
	_, err = bad.Exchange(context.Background(), query("example.org", dns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "Zertifikat") {
		t.Fatalf("err = %v, want certificate error", err)
	}

	// Unknown authority.
	_, otherPool := selfSigned(t, "dns.test")
	testRootCAs = otherPool
	bad2, _ := New("quic://127.0.0.1:"+port(srv.addr), Options{Timeout: time.Second})
	defer bad2.Close()
	_, err = bad2.Exchange(context.Background(), query("example.org", dns.TypeA))
	if err == nil || !strings.Contains(err.Error(), "Zertifikat") {
		t.Fatalf("err = %v, want certificate error", err)
	}
}

// --- DNS-over-HTTPS hardening ---

func newHardeningServer(t *testing.T, rec *dohRecord, respond func(w http.ResponseWriter, q *dns.Msg)) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(dohAnswer(rec, respond))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	useRoots(t, srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs)
	return "https://127.0.0.1:" + port(strings.TrimPrefix(srv.URL, "https://"))
}

func TestDoHHardening(t *testing.T) {
	ok := func(w http.ResponseWriter, q *dns.Msg) { writeDNS(w, replyA(q, "192.0.2.30")) }

	t.Run("id 0 and padding on the wire", func(t *testing.T) {
		rec := &dohRecord{}
		base := newHardeningServer(t, rec, ok)
		up, _ := New(base+"/dns-query", Options{Timeout: 2 * time.Second})
		defer up.Close()
		req := query("example.org", dns.TypeA)
		req.Id = 999
		before := req.String()
		resp, err := up.Exchange(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		proto, wire, last := rec.last()
		if proto != 2 || last.Id != 0 || len(wire)%paddingBlock != 0 || paddingOf(last) == nil {
			t.Fatalf("proto %d id %d len %d", proto, last.Id, len(wire))
		}
		if resp.Id != 999 || req.String() != before || resp.IsEdns0() != nil {
			t.Fatalf("resp id %d, request modified %v", resp.Id, req.String() != before)
		}
	})

	t.Run("content type with parameters", func(t *testing.T) {
		rec := &dohRecord{}
		base := newHardeningServer(t, rec, func(w http.ResponseWriter, q *dns.Msg) {
			wire, _ := replyA(q, "192.0.2.31").Pack()
			w.Header().Set("Content-Type", "Application/DNS-Message; charset=binary")
			_, _ = w.Write(wire)
		})
		up, _ := New(base+"/dns-query", Options{Timeout: 2 * time.Second})
		defer up.Close()
		if _, err := up.Exchange(context.Background(), query("example.org", dns.TypeA)); err != nil {
			t.Fatal(err)
		}
	})

	tests := []struct {
		name    string
		respond func(w http.ResponseWriter, q *dns.Msg)
		want    string
	}{
		{"redirect refused", func(w http.ResponseWriter, q *dns.Msg) {
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}, "Weiterleitung"},
		{"wrong content type", func(w http.ResponseWriter, q *dns.Msg) {
			wire, _ := replyA(q, "192.0.2.1").Pack()
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write(wire)
		}, "Content-Type"},
		{"missing content type", func(w http.ResponseWriter, q *dns.Msg) {
			wire, _ := replyA(q, "192.0.2.1").Pack()
			w.Header()["Content-Type"] = nil // no sniffing either
			_, _ = w.Write(wire)
		}, "Content-Type"},
		{"oversize with length", func(w http.ResponseWriter, q *dns.Msg) {
			w.Header().Set("Content-Type", dohMediaType)
			w.Header().Set("Content-Length", "70000")
			_, _ = w.Write(make([]byte, 70000))
		}, "zu groß"},
		{"oversize streamed", func(w http.ResponseWriter, q *dns.Msg) {
			w.Header().Set("Content-Type", dohMediaType)
			for range 9 {
				_, _ = w.Write(make([]byte, 8000))
				w.(http.Flusher).Flush()
			}
		}, "zu groß"},
		{"question mismatch", func(w http.ResponseWriter, q *dns.Msg) {
			m := replyA(q, "192.0.2.1")
			m.Question[0].Name = "evil.example."
			writeDNS(w, m)
		}, "passt nicht"},
		{"class mismatch", func(w http.ResponseWriter, q *dns.Msg) {
			m := replyA(q, "192.0.2.1")
			m.Question[0].Qclass = dns.ClassCHAOS
			writeDNS(w, m)
		}, "passt nicht"},
		{"garbage", func(w http.ResponseWriter, q *dns.Msg) {
			w.Header().Set("Content-Type", dohMediaType)
			_, _ = w.Write([]byte("hello"))
		}, "Ungültige DNS-Antwort"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &dohRecord{}
			base := newHardeningServer(t, rec, tt.respond)
			up, _ := New(base+"/dns-query", Options{Timeout: 2 * time.Second})
			defer up.Close()
			_, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if n := rec.count(); n != 1 {
				t.Fatalf("server saw %d requests, want 1 (no redirect followed)", n)
			}
		})
	}
}

// --- DoH over HTTP/3 ---

func TestDoH3(t *testing.T) {
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	rec := &dohRecord{}
	p := newH3Server(t, cert, dohAnswer(rec, func(w http.ResponseWriter, q *dns.Msg) { writeDNS(w, replyA(q, "192.0.2.40")) }))

	t.Run("ip host", func(t *testing.T) {
		up, err := New("h3://127.0.0.1:"+p+"/dns-query", Options{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		req := query("example.org", dns.TypeA)
		req.Id = 4242
		before := req.String()
		for range 3 {
			resp, err := up.Exchange(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.Id != 4242 || firstA(t, resp) != "192.0.2.40" || resp.IsEdns0() != nil {
				t.Fatalf("unexpected answer %v", resp)
			}
		}
		if req.String() != before {
			t.Fatal("request modified")
		}
		proto, wire, last := rec.last()
		if proto != 3 {
			t.Fatalf("HTTP/%d used, want HTTP/3", proto)
		}
		if last.Id != 0 || len(wire)%paddingBlock != 0 {
			t.Fatalf("id %d len %d", last.Id, len(wire))
		}
	})

	t.Run("host name via bootstrap", func(t *testing.T) {
		boot := bootstrapServer(t, 300)
		up, err := New("h3://dns.test:"+p, Options{Timeout: 2 * time.Second, Bootstrap: []string{boot.addr}})
		if err != nil {
			t.Fatal(err)
		}
		defer up.Close()
		resp, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
		if err != nil || firstA(t, resp) != "192.0.2.40" {
			t.Fatalf("resp %v err %v", resp, err)
		}
		if boot.udpQueries.Load() != 2 {
			t.Fatalf("bootstrap queries = %d", boot.udpQueries.Load())
		}
	})

	t.Run("certificate checked", func(t *testing.T) {
		boot := bootstrapServer(t, 300)
		up, _ := New("h3://other.test:"+p+"/dns-query", Options{Timeout: time.Second, Bootstrap: []string{boot.addr}})
		defer up.Close()
		_, err := up.Exchange(context.Background(), query("example.org", dns.TypeA))
		if err == nil || !strings.Contains(err.Error(), "Zertifikat") {
			t.Fatalf("err = %v, want certificate error", err)
		}
	})

	t.Run("https stays on HTTP/2", func(t *testing.T) {
		// The h3 server does not listen on TCP: https:// must not switch to HTTP/3.
		up, _ := New("https://127.0.0.1:"+p+"/dns-query", Options{Timeout: 500 * time.Millisecond})
		defer up.Close()
		if _, err := up.Exchange(context.Background(), query("example.org", dns.TypeA)); err == nil {
			t.Fatal("https:// reached the HTTP/3-only server")
		}
	})
}

// --- Router and Test with the new transports ---

func TestRouterSecureTransports(t *testing.T) {
	resetHealth()
	t.Cleanup(resetHealth)
	cert, pool := selfSigned(t, "dns.test")
	useRoots(t, pool)
	doqSrv := newDoQServer(t, cert, 0, doqAnswerA("192.0.2.50"))
	rec := &dohRecord{}
	h3Port := newH3Server(t, cert, dohAnswer(rec, func(w http.ResponseWriter, q *dns.Msg) { writeDNS(w, replyA(q, "192.0.2.51")) }))
	deadQ := newDoQServer(t, cert, 0, func(q *dns.Msg) []byte {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeServerFailure)
		wire, _ := m.Pack()
		return frame(wire)
	})

	quicAddr := "quic://127.0.0.1:" + port(doqSrv.addr)
	h3Addr := "h3://127.0.0.1:" + h3Port + "/dns-query"
	deadAddr := "quic://127.0.0.1:" + port(deadQ.addr)

	for _, mode := range []string{"load_balance", "parallel", "sequential"} {
		t.Run(mode, func(t *testing.T) {
			r := newRouter(t, Config{Upstreams: []string{deadAddr, quicAddr, h3Addr}, Mode: mode, Timeout: 2 * time.Second})
			for range 5 {
				req := query("example.org", dns.TypeA)
				req.Id = 77
				resp, addr, err := r.Resolve(context.Background(), req)
				if err != nil {
					t.Fatal(err)
				}
				if resp.Id != 77 || (addr != quicAddr && addr != h3Addr) {
					t.Fatalf("answered by %q id %d", addr, resp.Id)
				}
			}
			h := r.Health()
			if len(h) != 3 || h[0].Address != deadAddr || h[1].Address != quicAddr || h[2].Address != h3Addr {
				t.Fatalf("health %+v", h)
			}
		})
	}

	// Fallback over DoQ when the main upstreams fail.
	r := newRouter(t, Config{Upstreams: []string{deadAddr}, Fallback: []string{quicAddr}, Timeout: 2 * time.Second})
	resp, addr, err := r.Resolve(context.Background(), query("example.org", dns.TypeA))
	if err != nil || addr != quicAddr || firstA(t, resp) != "192.0.2.50" {
		t.Fatalf("fallback: %v %q %v", resp, addr, err)
	}

	// Test() for the new schemes.
	for _, a := range []string{quicAddr, h3Addr} {
		if rtt, err := Test(context.Background(), a, nil, 2*time.Second); err != nil || rtt <= 0 {
			t.Fatalf("Test(%s) = %v, %v", a, rtt, err)
		}
	}
	if _, err := Test(context.Background(), deadAddr, nil, 2*time.Second); err == nil || !strings.Contains(err.Error(), "SERVFAIL") {
		t.Fatalf("Test(dead) err = %v", err)
	}
}
