package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// upstreamError carries a German message for the API/UI and keeps the cause for errors.Is.
type upstreamError struct {
	msg string
	err error
}

func (e *upstreamError) Error() string { return e.msg }
func (e *upstreamError) Unwrap() error { return e.err }

// germanError translates a transport error into a German message. Errors that are
// already translated are returned unchanged.
func germanError(err error) error {
	if err == nil {
		return nil
	}
	var ue *upstreamError
	if errors.As(err, &ue) {
		return err
	}
	var msg string
	var netErr net.Error
	var certErr *tls.CertificateVerificationError
	var hostErr x509.HostnameError
	var unknownAuth x509.UnknownAuthorityError
	var invalidCert x509.CertificateInvalidError
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, context.Canceled):
		msg = "Abgebrochen"
	case errors.Is(err, context.DeadlineExceeded):
		msg = "Zeitüberschreitung"
	case errors.As(err, &hostErr), errors.As(err, &unknownAuth), errors.As(err, &invalidCert), errors.As(err, &certErr):
		msg = "Zertifikat ungültig: " + err.Error()
	case errors.Is(err, syscall.ECONNREFUSED):
		msg = "Verbindung abgelehnt"
	case errors.Is(err, syscall.ECONNRESET):
		msg = "Verbindung zurückgesetzt"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		msg = "Netzwerk nicht erreichbar"
	case errors.As(err, &dnsErr):
		msg = "Hostname konnte nicht aufgelöst werden: " + dnsErr.Name
	case errors.As(err, &netErr) && netErr.Timeout():
		msg = "Zeitüberschreitung"
	case errors.Is(err, dns.ErrId):
		msg = "Antwort mit falscher ID"
	default:
		msg = quicMessage(err)
	}
	return &upstreamError{msg: msg, err: err}
}

// quicMessage translates QUIC connection errors (DoQ, DoH3).
func quicMessage(err error) string {
	var (
		verErr   *quic.VersionNegotiationError
		resetErr *quic.StatelessResetError
		appErr   *quic.ApplicationError
		trErr    *quic.TransportError
		strErr   *quic.StreamError
	)
	switch {
	case errors.As(err, &verErr):
		return "Keine gemeinsame QUIC-Version mit dem Server"
	case errors.As(err, &resetErr):
		return "Verbindung zurückgesetzt (QUIC Stateless Reset)"
	case errors.As(err, &appErr) && appErr.Remote:
		return fmt.Sprintf("Verbindung vom Server beendet (Code %#x)", uint64(appErr.ErrorCode))
	case errors.As(err, &strErr) && strErr.Remote:
		return fmt.Sprintf("Anfrage vom Server abgebrochen (Code %#x)", uint64(strErr.ErrorCode))
	case errors.As(err, &trErr):
		return "QUIC-Fehler: " + err.Error()
	default:
		return "Fehler: " + err.Error()
	}
}

// ctxError prefers the context error (timeout, cancellation) over the transport error it caused.
func ctxError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		var ue *upstreamError
		if !errors.As(err, &ue) {
			return germanError(ctxErr)
		}
	}
	return germanError(err)
}

func errorf(format string, args ...any) error {
	return &upstreamError{msg: fmt.Sprintf(format, args...)}
}

// errBadRcode is returned by the router when an upstream answered SERVFAIL or REFUSED.
func errBadRcode(rcode int) error {
	return errorf("Upstream antwortete mit %s", dns.RcodeToString[rcode])
}

// checkAnswer verifies that resp is an answer (QR bit) to the question of req (name
// case-insensitive, type and class). Used by every transport against spoofed or confused
// answers.
func checkAnswer(req, resp *dns.Msg) error {
	if resp == nil {
		return errorf("Leere Antwort")
	}
	if !resp.Response {
		return errorf("Ungültige DNS-Antwort: QR-Bit fehlt")
	}
	if len(resp.Question) == 0 {
		// Some servers omit the question in error answers; accept those.
		if resp.Rcode != dns.RcodeSuccess {
			return nil
		}
		if len(req.Question) == 0 {
			return nil
		}
		return errorf("Antwort passt nicht zur Anfrage")
	}
	if len(req.Question) != len(resp.Question) {
		return errorf("Antwort passt nicht zur Anfrage")
	}
	for i, q := range req.Question {
		a := resp.Question[i]
		if q.Qtype != a.Qtype || q.Qclass != a.Qclass || !equalFoldASCII(q.Name, a.Name) {
			return errorf("Antwort passt nicht zur Anfrage")
		}
	}
	return nil
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
