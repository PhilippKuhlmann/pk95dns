package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
)

// quicIdleTimeout closes an unused QUIC connection (DoQ, DoH3); the next query dials a
// fresh one. No keep-alives: an idle home resolver should not keep connections open.
const quicIdleTimeout = 30 * time.Second

// newQUICConfig is the QUIC configuration of the DoQ and DoH3 clients. The peer may not
// open streams towards us (neither protocol uses server-initiated bidirectional streams;
// HTTP/3 sets its own unidirectional stream limits).
func newQUICConfig(timeout time.Duration) *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       quicIdleTimeout,
		MaxIncomingStreams:   -1,
	}
}

// dialQUIC resolves host through the bootstrap resolver and dials host:port over QUIC,
// trying every address in order (each with a fair share of the remaining time). The TLS server name stays the configured host (SNI and
// certificate check). Always a full handshake, never 0-RTT (0-RTT data can be replayed).
func dialQUIC(ctx context.Context, res *resolver, host, port string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	addrs, err := res.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, errorf("Ungültiger Port: %s", port)
	}
	var lastErr error
	for i, a := range addrs {
		// A fair share of the time per address: a first address that drops QUIC Initials
		// (e.g. broken IPv4 while IPv6 works) must not keep the others from being tried.
		actx, cancel := shareContext(ctx, len(addrs)-i)
		conn, err := dialQUICAddr(actx, a, p, tlsCfg, cfg)
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	res.invalidate(ctx, host, addrs, lastErr)
	return nil, lastErr
}

// dialQUICAddr dials one address on its own UDP socket. The socket is closed together
// with the connection.
func dialQUICAddr(ctx context.Context, a netip.Addr, port int, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	a = a.Unmap()
	network := "udp6"
	if a.Is4() {
		network = "udp4"
	}
	udp, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: udp}
	closeAll := func() {
		_ = tr.Close()
		_ = udp.Close()
	}
	conn, err := tr.Dial(ctx, net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, uint16(port))), tlsCfg, cfg)
	if err != nil {
		closeAll()
		return nil, err
	}
	go func() {
		<-conn.Context().Done()
		closeAll()
	}()
	return conn, nil
}

// timedOut reports whether ctx reached its deadline without being cancelled before. The
// deadline is compared directly: a stream deadline set to the same time may fire just
// before the context's own timer.
func timedOut(ctx context.Context) bool {
	if errors.Is(ctx.Err(), context.Canceled) {
		return false
	}
	dl, ok := ctx.Deadline()
	return ok && !time.Now().Before(dl)
}
