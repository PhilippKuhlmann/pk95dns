package upstream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// doqALPN is the ALPN token of DNS-over-QUIC (RFC 9250 4.1).
const doqALPN = "doq"

// DoQ error codes (RFC 9250 4.3).
const (
	doqNoError          = 0x0
	doqInternalError    = 0x1
	doqProtocolError    = 0x2
	doqRequestCancelled = 0x3
	doqExcessiveLoad    = 0x4
	doqUnspecifiedError = 0x5
)

func doqCodeName(code uint64) string {
	switch code {
	case doqNoError:
		return "DOQ_NO_ERROR"
	case doqInternalError:
		return "DOQ_INTERNAL_ERROR"
	case doqProtocolError:
		return "DOQ_PROTOCOL_ERROR"
	case doqRequestCancelled:
		return "DOQ_REQUEST_CANCELLED"
	case doqExcessiveLoad:
		return "DOQ_EXCESSIVE_LOAD"
	case doqUnspecifiedError:
		return "DOQ_UNSPECIFIED_ERROR"
	}
	return fmt.Sprintf("Fehlercode %#x", code)
}

// doqProtocolErr marks a violation of RFC 9250 by the server; the connection is closed
// with DOQ_PROTOCOL_ERROR.
type doqProtocolErr struct{ msg string }

func (e *doqProtocolErr) Error() string { return e.msg }

// doqUpstream is DNS-over-QUIC (RFC 9250): one long-lived QUIC connection per upstream,
// one bidirectional stream per query. The connection is dialed on demand, reused by all
// queries and dialed again after it was closed (idle timeout, server restart, error) or
// stopped answering (see exchange).
//
// The dial is shared by all queries that wait for it and runs detached from their
// contexts: a query that is cancelled (e.g. the loser in parallel mode) stops waiting but
// does not abort the handshake, so the connection is ready for the next query.
type doqUpstream struct {
	spec    Spec
	timeout time.Duration
	res     *resolver
	tlsCfg  *tls.Config
	quicCfg *quic.Config

	dials atomic.Int64 // successful dials (tests)

	mu         sync.Mutex
	conn       *doqConn // shared connection, nil = none
	dialing    *doqDial // dial in progress, nil = none
	dialCancel context.CancelFunc
	closed     bool
}

// doqConn is one QUIC connection with its own count of queries in flight. A detached
// connection is no longer handed out and is closed by its last query.
type doqConn struct {
	conn *quic.Conn

	// Guarded by doqUpstream.mu.
	inflight int
	detached bool
	lastRecv time.Time // handshake or last data received on any stream
}

// doqDial is a dial in progress; done is closed when conn or err is set.
type doqDial struct {
	done chan struct{}
	conn *doqConn
	err  error
}

func newDoQ(spec Spec, opt Options, res *resolver) *doqUpstream {
	timeout := timeoutOf(opt)
	return &doqUpstream{
		spec:    spec,
		timeout: timeout,
		res:     res,
		tlsCfg:  newTLS13Config(spec.Host, doqALPN),
		quicCfg: newQUICConfig(timeout),
	}
}

func (u *doqUpstream) Address() string { return u.spec.Raw }

func (u *doqUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	m, addedOPT := encryptedQuery(req, true) // RFC 9250 4.2.1: ID 0
	wire, err := m.Pack()
	if err != nil {
		return nil, errorf("Anfrage konnte nicht kodiert werden: %v", err)
	}
	if len(wire) > dns.MaxMsgSize {
		return nil, errorf("Anfrage zu groß")
	}

	resp, err := u.exchange(ctx, m, wire)
	if err != nil {
		var pe *doqProtocolErr
		var ae *quic.ApplicationError
		var se *quic.StreamError
		switch {
		case errors.As(err, &pe):
			return nil, errorf("Ungültige DoQ-Antwort: %s", pe.msg)
		case ctx.Err() == nil && errors.As(err, &ae) && ae.Remote:
			return nil, &upstreamError{msg: "Server hat die DoQ-Verbindung beendet: " + doqCodeName(uint64(ae.ErrorCode)), err: err}
		case ctx.Err() == nil && errors.As(err, &se) && se.Remote:
			// The server reset the query stream (e.g. DOQ_EXCESSIVE_LOAD).
			return nil, &upstreamError{msg: "Server hat die DoQ-Anfrage abgebrochen: " + doqCodeName(uint64(se.ErrorCode)), err: err}
		}
		return nil, ctxError(ctx, err)
	}
	cleanAnswer(resp, req.Id, addedOPT)
	return resp, nil
}

// exchange runs the query on the shared connection. When that connection turns out to be
// closed (idle timeout, server restart), the query is sent once more on a fresh one.
//
// A connection can also die silently: the server lost its state without sending
// CONNECTION_CLOSE or a stateless reset, so locally it stays open until the 30 s idle
// timeout. When a query times out and nothing at all arrived on its connection since the
// query started, the connection is suspect: it is detached (new queries dial a fresh
// one) and closed once its last query in flight is done.
func (u *doqUpstream) exchange(ctx context.Context, m *dns.Msg, wire []byte) (*dns.Msg, error) {
	c, reused, err := u.acquire(ctx)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	resp, err := u.queryOn(ctx, c, m, wire)
	u.release(c, err != nil && u.suspect(ctx, c, start))
	if err == nil {
		return resp, nil
	}
	var pe *doqProtocolErr
	if errors.As(err, &pe) {
		return nil, err // the server broke the protocol: no retry
	}
	dead := connClosed(c.conn, err)
	if dead {
		u.drop(c, doqNoError)
	}
	if !dead || !reused || ctx.Err() != nil {
		return nil, err
	}
	c, _, err = u.acquire(ctx)
	if err != nil {
		return nil, err
	}
	resp, err = u.queryOn(ctx, c, m, wire)
	u.release(c, false)
	if err != nil && connClosed(c.conn, err) {
		u.drop(c, doqNoError)
	}
	return resp, err
}

// suspect reports whether a failed query hints at a silently dead connection: it ran
// into its deadline after waiting at least half the upstream timeout, and nothing was
// received on c since it started. A cancelled query (parallel mode, client gone) or a
// short deadline of the caller says nothing about the connection.
func (u *doqUpstream) suspect(ctx context.Context, c *doqConn, start time.Time) bool {
	if !timedOut(ctx) || time.Since(start) < u.timeout/2 {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return c.lastRecv.Before(start)
}

// connClosed reports whether err (or the state of conn) means the whole connection is
// gone. All connection-level QUIC errors (application close, idle timeout, stateless
// reset, transport errors) wrap net.ErrClosed.
func connClosed(conn *quic.Conn, err error) bool {
	return conn.Context().Err() != nil || errors.Is(err, net.ErrClosed)
}

// acquire returns the live shared connection (counted as in flight) or waits for a dial.
// reused is true when the connection existed before this call.
func (u *doqUpstream) acquire(ctx context.Context) (c *doqConn, reused bool, err error) {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil, false, errorf("Upstream wurde geschlossen")
	}
	if c := u.conn; c != nil && c.conn.Context().Err() == nil {
		c.inflight++
		u.mu.Unlock()
		return c, true, nil
	}
	d := u.dialing
	if d == nil {
		d = &doqDial{done: make(chan struct{})}
		u.dialing = d
		// Detached from the query: the handshake must survive a cancelled waiter.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), u.timeout)
		u.dialCancel = cancel
		go u.dial(dctx, cancel, d)
	}
	u.mu.Unlock()

	select {
	case <-d.done:
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
	if d.err != nil {
		return nil, false, d.err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil, false, errorf("Upstream wurde geschlossen")
	}
	d.conn.inflight++
	return d.conn, false, nil
}

// dial establishes a new shared connection and publishes it, also when every query that
// waited for it has given up in the meantime.
func (u *doqUpstream) dial(ctx context.Context, cancel context.CancelFunc, d *doqDial) {
	defer cancel()
	conn, err := dialQUIC(ctx, u.res, u.spec.Host, u.spec.Port, u.tlsCfg, u.quicCfg)
	if err == nil {
		if p := conn.ConnectionState().TLS.NegotiatedProtocol; p != doqALPN {
			_ = conn.CloseWithError(doqProtocolError, "")
			conn, err = nil, errorf("Server spricht kein DoQ (ALPN %q)", p)
		}
	}

	u.mu.Lock()
	u.dialing = nil
	u.dialCancel = nil
	switch {
	case err != nil:
		d.err = err
	case u.closed:
		_ = conn.CloseWithError(doqNoError, "")
		d.err = errorf("Upstream wurde geschlossen")
	default:
		u.dials.Add(1)
		c := &doqConn{conn: conn, lastRecv: time.Now()}
		if old := u.conn; old != nil {
			u.detachLocked(old)
		}
		u.conn = c
		d.conn = c
	}
	u.mu.Unlock()
	close(d.done)
}

// release ends a query on c. suspect detaches c (see exchange). A detached connection, or
// any connection after Close, is closed by its last query.
func (u *doqUpstream) release(c *doqConn, suspect bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	c.inflight--
	if suspect || u.closed || c.detached {
		u.detachLocked(c)
	}
}

// detachLocked stops handing out c and closes it when no query is in flight on it.
func (u *doqUpstream) detachLocked(c *doqConn) {
	if u.conn == c {
		u.conn = nil
	}
	c.detached = true
	if c.inflight == 0 {
		_ = c.conn.CloseWithError(doqNoError, "")
	}
}

// received notes that data arrived on c.
func (u *doqUpstream) received(c *doqConn) {
	u.mu.Lock()
	c.lastRecv = time.Now()
	u.mu.Unlock()
}

// drop closes c with code at once (queries still on it fail).
func (u *doqUpstream) drop(c *doqConn, code quic.ApplicationErrorCode) {
	u.mu.Lock()
	if u.conn == c {
		u.conn = nil
	}
	c.detached = true
	u.mu.Unlock()
	_ = c.conn.CloseWithError(code, "")
}

// queryOn sends one query on a new stream of conn (RFC 9250 4.2): 2-byte length prefix,
// message, STREAM FIN; the answer is read up to the server's FIN.
func (u *doqUpstream) queryOn(ctx context.Context, c *doqConn, m *dns.Msg, wire []byte) (*dns.Msg, error) {
	str, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = str.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() {
		str.CancelWrite(doqRequestCancelled)
		str.CancelRead(doqRequestCancelled)
	})
	defer stop()

	buf := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(buf, uint16(len(wire)))
	copy(buf[2:], wire)
	if _, err := str.Write(buf); err != nil {
		str.CancelRead(doqRequestCancelled)
		return nil, err
	}
	if err := str.Close(); err != nil { // STREAM FIN: no further queries on this stream
		str.CancelRead(doqRequestCancelled)
		return nil, err
	}

	raw, err := io.ReadAll(io.LimitReader(str, 2+dns.MaxMsgSize+1))
	if err == nil || len(raw) > 0 {
		u.received(c)
	}
	if err != nil {
		str.CancelRead(doqRequestCancelled)
		return nil, err
	}
	resp, perr := parseDoQAnswer(raw)
	if perr != nil {
		str.CancelRead(doqProtocolError)
		u.drop(c, doqProtocolError)
		return nil, perr
	}
	if err := checkAnswer(m, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// parseDoQAnswer checks the framing of a DoQ answer stream: exactly one length-prefixed
// message of at most 65535 bytes with ID 0.
func parseDoQAnswer(raw []byte) (*dns.Msg, error) {
	switch {
	case len(raw) > 2+dns.MaxMsgSize:
		return nil, &doqProtocolErr{"Antwort zu groß (mehr als 65535 Bytes)"}
	case len(raw) < 2+12:
		return nil, &doqProtocolErr{"Antwort zu kurz"}
	}
	n := int(binary.BigEndian.Uint16(raw))
	if n != len(raw)-2 {
		return nil, &doqProtocolErr{"Längenangabe passt nicht zur Antwort"}
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(raw[2:]); err != nil {
		return nil, &doqProtocolErr{"Ungültige DNS-Nachricht: " + err.Error()}
	}
	if resp.Id != 0 {
		return nil, &doqProtocolErr{"Nachrichten-ID ist nicht 0"}
	}
	return resp, nil
}

func (u *doqUpstream) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.closed = true
	if u.dialCancel != nil {
		u.dialCancel()
	}
	if u.conn != nil {
		u.detachLocked(u.conn)
	}
	return nil
}
