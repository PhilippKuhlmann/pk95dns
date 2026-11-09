package upstream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testServer is a local DNS server on 127.0.0.1 (UDP and TCP on the same port).
type testServer struct {
	addr       string
	udpQueries atomic.Int64
	tcpQueries atomic.Int64
	accepts    atomic.Int64 // TCP/TLS connections

	mu       sync.Mutex
	lastReq  *dns.Msg
	lastSize uint16 // EDNS0 UDP size of the last UDP request (0 = none)
}

type handlerFunc func(w dns.ResponseWriter, r *dns.Msg, proto string)

func (s *testServer) wrap(proto string, h handlerFunc) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if proto == "udp" {
			s.udpQueries.Add(1)
		} else {
			s.tcpQueries.Add(1)
		}
		s.mu.Lock()
		s.lastReq = r.Copy()
		if proto == "udp" {
			s.lastSize = 0
			if opt := r.IsEdns0(); opt != nil {
				s.lastSize = opt.UDPSize()
			}
		}
		s.mu.Unlock()
		h(w, r, proto)
	})
}

func (s *testServer) last() (*dns.Msg, uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReq, s.lastSize
}

// countingListener counts accepted connections.
type countingListener struct {
	net.Listener
	n *atomic.Int64
}

func (l countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func startServer(t *testing.T, srv *dns.Server) {
	t.Helper()
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("test server did not start")
	}
	t.Cleanup(func() { _ = srv.Shutdown() })
}

// newTestServer starts UDP and TCP listeners on the same 127.0.0.1 port.
func newTestServer(t *testing.T, h handlerFunc) *testServer {
	t.Helper()
	s := &testServer{}
	var (
		pc net.PacketConn
		l  net.Listener
	)
	for range 20 {
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l, err = net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			break
		}
		pc.Close()
		pc, l = nil, nil
	}
	if l == nil {
		t.Fatal("no free port for UDP and TCP")
	}
	s.addr = pc.LocalAddr().String()
	startServer(t, &dns.Server{PacketConn: pc, Handler: s.wrap("udp", h)})
	startServer(t, &dns.Server{Listener: countingListener{l, &s.accepts}, Handler: s.wrap("tcp", h)})
	return s
}

// newTLSServer starts a DNS-over-TLS server with cert.
func newTLSServer(t *testing.T, cert tls.Certificate, h handlerFunc, idle time.Duration) *testServer {
	t.Helper()
	s := &testServer{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.addr = l.Addr().String()
	tl := tls.NewListener(countingListener{l, &s.accepts}, &tls.Config{Certificates: []tls.Certificate{cert}})
	srv := &dns.Server{Listener: tl, Net: "tcp-tls", Handler: s.wrap("tls", h)}
	if idle > 0 {
		srv.IdleTimeout = func() time.Duration { return idle }
	}
	startServer(t, srv)
	return s
}

// answerA answers every A query with ip (TTL ttl), other types with an empty NOERROR.
func answerA(ip string, ttl uint32) handlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg, _ string) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(r.Question[0].Name + " " + itoa(ttl) + " IN A " + ip)
			m.Answer = append(m.Answer, rr)
		}
		if opt := r.IsEdns0(); opt != nil {
			m.SetEdns0(1232, opt.Do())
		}
		_ = w.WriteMsg(m)
	}
}

func rcodeHandler(rcode int) handlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg, _ string) {
		m := new(dns.Msg)
		m.SetRcode(r, rcode)
		_ = w.WriteMsg(m)
	}
}

func slowHandler(d time.Duration, h handlerFunc) handlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg, proto string) {
		time.Sleep(d)
		h(w, r, proto)
	}
}

// silentHandler never answers.
func silentHandler(dns.ResponseWriter, *dns.Msg, string) {}

func itoa(n uint32) string { return strconv.FormatUint(uint64(n), 10) }

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	return m
}

func firstA(t *testing.T, m *dns.Msg) string {
	t.Helper()
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String()
		}
	}
	t.Fatalf("no A record in %v", m)
	return ""
}

// selfSigned creates a certificate for the given names and 127.0.0.1 and a pool trusting it.
func selfSigned(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: strings.Join(names, ",")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              names,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// useRoots sets the test root CAs for upstreams created during the test.
func useRoots(t *testing.T, pool *x509.CertPool) {
	t.Helper()
	old := testRootCAs
	testRootCAs = pool
	t.Cleanup(func() { testRootCAs = old })
}

func port(addr string) string {
	_, p, _ := net.SplitHostPort(addr)
	return p
}
