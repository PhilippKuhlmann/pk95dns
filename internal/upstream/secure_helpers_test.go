package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// doqHandler returns the raw bytes written on the answer stream (length prefix included)
// for query q. A nil result closes the stream without answer.
type doqHandler func(q *dns.Msg) []byte

// doqServer is a minimal RFC 9250 server on 127.0.0.1.
type doqServer struct {
	addr     string
	accepts  atomic.Int64
	queries  atomic.Int64
	nonZero  atomic.Int64 // queries with ID != 0
	unframed atomic.Int64 // streams that were not exactly one length-prefixed message

	mu       sync.Mutex
	lastWire []byte
	lastReq  *dns.Msg
	conns    []*quic.Conn
	handler  doqHandler
}

func newDoQServer(t *testing.T, cert tls.Certificate, idle time.Duration, h doqHandler) *doqServer {
	t.Helper()
	s := &doqServer{handler: h}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{doqALPN}, MinVersion: tls.VersionTLS13}
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsCfg, &quic.Config{MaxIdleTimeout: idle})
	if err != nil {
		t.Fatal(err)
	}
	s.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		s.closeConns()
		_ = ln.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			s.accepts.Add(1)
			s.mu.Lock()
			s.conns = append(s.conns, conn)
			s.mu.Unlock()
			go s.serveConn(conn)
		}
	}()
	return s
}

func (s *doqServer) serveConn(conn *quic.Conn) {
	for {
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go s.serveStream(str)
	}
}

func (s *doqServer) serveStream(str *quic.Stream) {
	defer str.Close()
	raw, err := io.ReadAll(io.LimitReader(str, 2+dns.MaxMsgSize)) // client sends FIN
	if err != nil || len(raw) < 2 || int(binary.BigEndian.Uint16(raw)) != len(raw)-2 {
		s.unframed.Add(1)
		str.CancelWrite(doqProtocolError)
		return
	}
	q := new(dns.Msg)
	if err := q.Unpack(raw[2:]); err != nil {
		str.CancelWrite(doqProtocolError)
		return
	}
	s.queries.Add(1)
	if q.Id != 0 {
		s.nonZero.Add(1)
	}
	s.mu.Lock()
	s.lastWire = raw[2:]
	s.lastReq = q
	h := s.handler
	s.mu.Unlock()
	out := h(q)
	switch {
	case bytes.Equal(out, doqResetExcessiveLoad):
		str.CancelWrite(doqExcessiveLoad)
	case out != nil:
		_, _ = str.Write(out)
	}
}

// doqResetExcessiveLoad returned by a doqHandler resets the answer stream with
// DOQ_EXCESSIVE_LOAD instead of answering.
var doqResetExcessiveLoad = []byte("reset: excessive load")

func (s *doqServer) setHandler(h doqHandler) {
	s.mu.Lock()
	s.handler = h
	s.mu.Unlock()
}

func (s *doqServer) last() ([]byte, *dns.Msg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastWire, s.lastReq
}

// closeConns closes every server-side connection (DOQ_NO_ERROR).
func (s *doqServer) closeConns() {
	s.mu.Lock()
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.CloseWithError(doqNoError, "")
	}
}

// frame prefixes wire with its 2-byte length.
func frame(wire []byte) []byte {
	out := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(out, uint16(len(wire)))
	copy(out[2:], wire)
	return out
}

// replyA builds an answer to q with one A record (the ID is echoed, i.e. 0 for DoQ/DoH).
func replyA(q *dns.Msg, ip string) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	if q.Question[0].Qtype == dns.TypeA {
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A " + ip)
		m.Answer = append(m.Answer, rr)
	}
	if opt := q.IsEdns0(); opt != nil {
		m.SetEdns0(1232, opt.Do())
		// Servers pad answers too (RFC 8467: 468-octet blocks).
		m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_PADDING{Padding: make([]byte, 20)})
	}
	return m
}

func doqAnswerA(ip string) doqHandler {
	return func(q *dns.Msg) []byte {
		wire, _ := replyA(q, ip).Pack()
		return frame(wire)
	}
}

// dohRecord records what a DoH/DoH3 test server received.
type dohRecord struct {
	mu       sync.Mutex
	requests int
	proto    int // HTTP major version of the last request
	wire     []byte
	req      *dns.Msg
}

func (r *dohRecord) last() (int, []byte, *dns.Msg) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.proto, r.wire, r.req
}

func (r *dohRecord) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests
}

// dohAnswer is an RFC 8484 handler; respond writes the answer for the decoded query.
func dohAnswer(rec *dohRecord, respond func(w http.ResponseWriter, q *dns.Msg)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		err := q.Unpack(body)
		rec.mu.Lock()
		rec.requests++
		rec.proto = r.ProtoMajor
		rec.wire = body
		rec.req = q
		rec.mu.Unlock()
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != dohMediaType ||
			r.Header.Get("Accept") != dohMediaType || err != nil || q.Id != 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		respond(w, q)
	})
}

func writeDNS(w http.ResponseWriter, m *dns.Msg) {
	wire, _ := m.Pack()
	w.Header().Set("Content-Type", dohMediaType)
	_, _ = w.Write(wire)
}

// newH3Server starts an HTTP/3 server on 127.0.0.1 and returns its port.
func newH3Server(t *testing.T, cert tls.Certificate, h http.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		Handler:   h,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(pc); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			t.Logf("h3 server: %v", err)
		}
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		_ = pc.Close()
		<-done
	})
	return port(pc.LocalAddr().String())
}
