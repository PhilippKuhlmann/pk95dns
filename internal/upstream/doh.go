package upstream

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

const dohMediaType = "application/dns-message"

// Limits of the DoH transports.
const (
	dohMaxIdleConns   = 4
	dohIdleTimeout    = 90 * time.Second
	dohMaxHeaderBytes = 64 << 10
)

// errRedirect is returned for any HTTP redirect: following one could downgrade the
// transport or send the query to a host the user did not configure.
var errRedirect = errorf("Weiterleitung (HTTP-Redirect) abgelehnt")

// dohUpstream is DNS-over-HTTPS (RFC 8484, POST) over HTTP/2 (HTTP/1.1 when the server
// offers nothing else). It never switches to HTTP/3 by itself (that is h3://).
//
// Hardening: TLS 1.2+, system roots, no way to skip the certificate check; no redirects,
// no cookies, no HTTP proxy (a proxy from the environment would see the target of every
// query and DNS must not depend on it); no compression; status 200 and Content-Type
// application/dns-message required; body at most 65535 bytes; the answer must answer the
// question of the query.
type dohUpstream struct {
	spec      Spec
	url       string
	timeout   time.Duration
	transport *http.Transport
	client    *http.Client
}

func newDoH(spec Spec, opt Options, res *resolver) *dohUpstream {
	timeout := timeoutOf(opt)
	tr := &http.Transport{
		Proxy:              nil, // deliberately: no proxy from the environment
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
		TLSClientConfig:    newTLSConfig(spec.Host),
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The URL host is resolved through the bootstrap servers, never the system
			// resolver (which may be this DNS server itself).
			return res.dial(ctx, spec.Host, spec.Port)
		},
		MaxIdleConns:           dohMaxIdleConns,
		MaxIdleConnsPerHost:    dohMaxIdleConns,
		IdleConnTimeout:        dohIdleTimeout,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: dohMaxHeaderBytes,
	}
	return &dohUpstream{
		spec:      spec,
		url:       "https://" + net.JoinHostPort(spec.Host, spec.Port) + spec.Path,
		timeout:   timeout,
		transport: tr,
		client:    newDoHClient(tr, timeout),
	}
}

// newDoHClient returns an http.Client that refuses redirects and has no cookie jar.
func newDoHClient(rt http.RoundTripper, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: rt,
		Timeout:   timeout,
		Jar:       nil,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		},
	}
}

func (u *dohUpstream) Address() string { return u.spec.Raw }

func (u *dohUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	resp, err := dohExchange(ctx, u.client, u.url, u.spec, req)
	if err != nil {
		return nil, ctxError(ctx, err)
	}
	return resp, nil
}

func (u *dohUpstream) Close() error {
	u.transport.CloseIdleConnections()
	return nil
}

// dohExchange sends req as an RFC 8484 POST to url and validates the answer. Shared by
// DoH (HTTP/2) and DoH3.
func dohExchange(ctx context.Context, client *http.Client, url string, spec Spec, req *dns.Msg) (*dns.Msg, error) {
	m, addedOPT := encryptedQuery(req, true) // RFC 8484 4.1: ID 0
	wire, err := m.Pack()
	if err != nil {
		return nil, errorf("Anfrage konnte nicht kodiert werden: %v", err)
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, errorf("Ungültige Adresse: %s", spec.Raw)
	}
	hreq.Header.Set("Content-Type", dohMediaType)
	hreq.Header.Set("Accept", dohMediaType)
	hreq.Header.Set("User-Agent", "pk95dns")

	hresp, err := client.Do(hreq)
	if err != nil {
		var ue *upstreamError
		if errors.As(err, &ue) {
			return nil, ue // e.g. the redirect refusal, without the URL prefix of url.Error
		}
		return nil, err
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(hresp.Body, 4<<10))
		return nil, errorf("HTTP-Status %d von %s", hresp.StatusCode, spec.Host)
	}
	ct := hresp.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != dohMediaType {
		return nil, errorf("Falscher Content-Type von %s: %q (erwartet %s)", spec.Host, ct, dohMediaType)
	}
	if hresp.ContentLength > dns.MaxMsgSize {
		return nil, errorf("Antwort zu groß (%d Bytes)", hresp.ContentLength)
	}
	body, err := io.ReadAll(io.LimitReader(hresp.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > dns.MaxMsgSize {
		return nil, errorf("Antwort zu groß (mehr als %d Bytes)", dns.MaxMsgSize)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, errorf("Ungültige DNS-Antwort: %v", err)
	}
	if err := checkAnswer(m, resp); err != nil {
		return nil, err
	}
	cleanAnswer(resp, req.Id, addedOPT)
	return resp, nil
}
