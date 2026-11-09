package upstream

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// defaultTimeout is used when Options.Timeout is 0.
const defaultTimeout = 4 * time.Second

// ednsUDPSize is the EDNS0 buffer size announced when the request has none (DNS flag day 2020).
const ednsUDPSize = 1232

// plainUpstream is classic DNS over UDP (retry over TCP when truncated) or TCP only.
type plainUpstream struct {
	raw     string
	addr    string // ip:port
	tcpOnly bool
	timeout time.Duration
}

func newPlain(spec Spec, opt Options) *plainUpstream {
	return &plainUpstream{
		raw:     spec.Raw,
		addr:    net.JoinHostPort(spec.Host, spec.Port),
		tcpOnly: spec.Scheme == "tcp",
		timeout: timeoutOf(opt),
	}
}

func timeoutOf(opt Options) time.Duration {
	if opt.Timeout > 0 {
		return opt.Timeout
	}
	return defaultTimeout
}

func (u *plainUpstream) Address() string { return u.raw }

func (u *plainUpstream) Close() error { return nil }

func (u *plainUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	resp, err := exchangePlain(ctx, req, u.addr, u.tcpOnly)
	if err != nil {
		return nil, ctxError(ctx, err)
	}
	return resp, nil
}

// exchangePlain sends a copy of req to addr. Over UDP an EDNS0 OPT record is added when
// the request has none (and removed from the answer again); a truncated answer is
// retried over TCP.
func exchangePlain(ctx context.Context, req *dns.Msg, addr string, tcpOnly bool) (*dns.Msg, error) {
	m := req.Copy()
	if tcpOnly {
		return exchangeNet(ctx, "tcp", addr, m)
	}
	addedOPT := false
	if m.IsEdns0() == nil {
		m.SetEdns0(ednsUDPSize, false)
		addedOPT = true
	}
	resp, err := exchangeNet(ctx, "udp", addr, m)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		resp, err = exchangeNet(ctx, "tcp", addr, m)
		if err != nil {
			return nil, err
		}
	}
	if addedOPT {
		resp.Extra = withoutOPT(resp.Extra)
	}
	return resp, nil
}

func withoutOPT(rrs []dns.RR) []dns.RR {
	out := rrs[:0]
	for _, rr := range rrs {
		if _, ok := rr.(*dns.OPT); !ok {
			out = append(out, rr)
		}
	}
	return out
}

// exchangeNet dials network/addr and exchanges m on a fresh connection.
func exchangeNet(ctx context.Context, network, addr string, m *dns.Msg) (*dns.Msg, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	conn := &dns.Conn{Conn: raw}
	defer conn.Close()
	resp, err := exchangeConn(ctx, conn, m)
	if err != nil {
		return nil, err
	}
	if err := checkAnswer(m, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// exchangeConn writes m to conn and reads the answer, honouring the deadline and the
// cancellation of ctx. On error the connection must not be reused.
func exchangeConn(ctx context.Context, conn *dns.Conn, m *dns.Msg) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() {
		// Unblock reads and writes immediately.
		_ = conn.SetDeadline(time.Unix(1, 0))
	})
	defer stop()

	c := &dns.Client{Timeout: 24 * time.Hour} // the context deadline is the real limit
	resp, _, err := c.ExchangeWithConnContext(ctx, m, conn)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return resp, nil
}
