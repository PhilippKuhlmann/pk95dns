package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// testRootCAs replaces the system roots in tests (nil = system roots).
var testRootCAs *x509.CertPool

const (
	dotMaxIdle     = 4
	dotIdleTimeout = 30 * time.Second
)

// newTLSConfig is the client TLS configuration of DoT and DoH: TLS 1.2 or newer, the
// system roots and the certificate verified against host (an IP host must be in the IP
// SANs). There is deliberately no option to skip the verification.
func newTLSConfig(host string) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            testRootCAs,
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
	}
}

// newTLS13Config is the client TLS configuration of the QUIC transports (DoQ, DoH3):
// TLS 1.3 only (QUIC requires it) and the given ALPN.
func newTLS13Config(host string, alpn ...string) *tls.Config {
	c := newTLSConfig(host)
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = alpn
	return c
}

// dotUpstream is DNS-over-TLS (RFC 7858) with a small pool of idle connections.
// Each connection carries one query at a time. Queries are padded (RFC 8467), answers must
// carry the query's ID and question.
type dotUpstream struct {
	spec    Spec
	timeout time.Duration
	res     *resolver
	tlsCfg  *tls.Config
	now     func() time.Time

	mu     sync.Mutex
	idle   []idleConn // most recently used last
	closed bool
}

type idleConn struct {
	conn  *dns.Conn
	since time.Time
}

func newDoT(spec Spec, opt Options, res *resolver) *dotUpstream {
	return &dotUpstream{
		spec:    spec,
		timeout: timeoutOf(opt),
		res:     res,
		tlsCfg:  newTLSConfig(spec.Host),
		now:     time.Now,
	}
}

func (u *dotUpstream) Address() string { return u.spec.Raw }

func (u *dotUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	m, addedOPT := encryptedQuery(req, false)

	// A pooled connection may have been closed by the server in the meantime: on error
	// retry once with a fresh connection.
	if conn := u.getIdle(); conn != nil {
		resp, err := u.exchangeOn(ctx, conn, m)
		if err == nil {
			cleanAnswer(resp, req.Id, addedOPT)
			return resp, nil
		}
		if ctx.Err() != nil {
			return nil, germanError(ctx.Err())
		}
	}
	conn, err := u.dial(ctx)
	if err != nil {
		return nil, ctxError(ctx, err)
	}
	resp, err := u.exchangeOn(ctx, conn, m)
	if err != nil {
		return nil, ctxError(ctx, err)
	}
	cleanAnswer(resp, req.Id, addedOPT)
	return resp, nil
}

// exchangeOn uses conn for one exchange and returns it to the pool when it is still usable.
func (u *dotUpstream) exchangeOn(ctx context.Context, conn *dns.Conn, m *dns.Msg) (*dns.Msg, error) {
	resp, err := exchangeConn(ctx, conn, m)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := checkAnswer(m, resp); err != nil {
		conn.Close()
		return nil, err
	}
	u.putIdle(conn)
	return resp, nil
}

func (u *dotUpstream) dial(ctx context.Context) (*dns.Conn, error) {
	raw, err := u.res.dial(ctx, u.spec.Host, u.spec.Port)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, u.tlsCfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return &dns.Conn{Conn: tc}, nil
}

func (u *dotUpstream) getIdle() *dns.Conn {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now()
	for len(u.idle) > 0 {
		ic := u.idle[len(u.idle)-1]
		u.idle = u.idle[:len(u.idle)-1]
		if now.Sub(ic.since) < dotIdleTimeout {
			return ic.conn
		}
		ic.conn.Close()
	}
	return nil
}

func (u *dotUpstream) putIdle(conn *dns.Conn) {
	_ = conn.SetDeadline(time.Time{})
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		conn.Close()
		return
	}
	now := u.now()
	// Drop expired connections (oldest first).
	kept := u.idle[:0]
	for _, ic := range u.idle {
		if now.Sub(ic.since) < dotIdleTimeout {
			kept = append(kept, ic)
		} else {
			ic.conn.Close()
		}
	}
	u.idle = kept
	if len(u.idle) >= dotMaxIdle {
		u.idle[0].conn.Close()
		u.idle = append(u.idle[:0], u.idle[1:]...)
	}
	u.idle = append(u.idle, idleConn{conn: conn, since: now})
}

func (u *dotUpstream) idleCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.idle)
}

func (u *dotUpstream) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
	for _, ic := range u.idle {
		ic.conn.Close()
	}
	u.idle = nil
	return nil
}
