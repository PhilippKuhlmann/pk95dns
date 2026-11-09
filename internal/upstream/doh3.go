package upstream

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// doh3Upstream is DNS-over-HTTPS over HTTP/3 (h3://host[:port]/path): the same RFC 8484
// exchange and checks as DoH, carried over QUIC with TLS 1.3. Host names are resolved
// through the bootstrap servers; no 0-RTT.
//
// http3.Transport shares one connection per host and dials it detached from the request
// context. It keeps that connection when a request merely times out, so a connection the
// server forgot without CONNECTION_CLOSE or stateless reset would be reused until the 30 s
// QUIC idle timeout. Therefore the upstream tracks the connections it dialed: when a
// request times out and nothing arrived on its connection since the request started, the
// connection is closed; the transport then dials a fresh one for the next request.
type doh3Upstream struct {
	spec      Spec
	url       string
	timeout   time.Duration
	transport *http3.Transport
	client    *http.Client

	mu    sync.Mutex
	conns map[string]*doh3Conn // by local address (every connection has its own socket)
}

// doh3Conn is one QUIC connection dialed for the transport.
type doh3Conn struct {
	conn     *quic.Conn
	lastRecv time.Time // handshake or last response header; guarded by doh3Upstream.mu
}

func newDoH3(spec Spec, opt Options, res *resolver) *doh3Upstream {
	timeout := timeoutOf(opt)
	u := &doh3Upstream{
		spec:    spec,
		url:     "https://" + net.JoinHostPort(spec.Host, spec.Port) + spec.Path,
		timeout: timeout,
		conns:   map[string]*doh3Conn{},
	}
	u.transport = &http3.Transport{
		TLSClientConfig:        newTLS13Config(spec.Host, http3.NextProtoH3),
		QUICConfig:             newQUICConfig(timeout),
		DisableCompression:     true,
		MaxResponseHeaderBytes: dohMaxHeaderBytes,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			// The URL host is resolved through the bootstrap servers; quic.DialEarly
			// (0-RTT) is never used.
			conn, err := dialQUIC(ctx, res, spec.Host, spec.Port, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			u.track(conn)
			return conn, nil
		},
	}
	u.client = newDoHClient(u.transport, timeout)
	return u
}

// track registers a dialed connection until it is closed.
func (u *doh3Upstream) track(conn *quic.Conn) {
	key := conn.LocalAddr().String()
	c := &doh3Conn{conn: conn, lastRecv: time.Now()}
	u.mu.Lock()
	u.conns[key] = c
	u.mu.Unlock()
	go func() {
		<-conn.Context().Done()
		u.mu.Lock()
		if u.conns[key] == c {
			delete(u.conns, key)
		}
		u.mu.Unlock()
	}()
}

func (u *doh3Upstream) lookupConn(info httptrace.GotConnInfo) *doh3Conn {
	if info.Conn == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conns[info.Conn.LocalAddr().String()]
}

func (u *doh3Upstream) Address() string { return u.spec.Raw }

func (u *doh3Upstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()

	var used atomic.Pointer[doh3Conn]
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if c := u.lookupConn(info); c != nil {
				used.Store(c)
			}
		},
		GotFirstResponseByte: func() {
			if c := used.Load(); c != nil {
				u.mu.Lock()
				c.lastRecv = time.Now()
				u.mu.Unlock()
			}
		},
	})
	start := time.Now()
	resp, err := dohExchange(ctx, u.client, u.url, u.spec, req)
	if err != nil {
		if c := used.Load(); c != nil && u.suspect(ctx, c, start) {
			// Requests still waiting on this connection received nothing either.
			_ = c.conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		}
		return nil, ctxError(ctx, err)
	}
	return resp, nil
}

// suspect reports whether a failed request hints at a silently dead connection: it ran
// into its deadline after waiting at least half the upstream timeout and nothing was
// received on c since it started.
func (u *doh3Upstream) suspect(ctx context.Context, c *doh3Conn, start time.Time) bool {
	if !timedOut(ctx) || time.Since(start) < u.timeout/2 {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return c.lastRecv.Before(start)
}

func (u *doh3Upstream) Close() error {
	u.transport.CloseIdleConnections()
	return nil
}
