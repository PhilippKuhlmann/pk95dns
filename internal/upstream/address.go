package upstream

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Default ports per scheme.
const (
	portDNS   = "53"
	portTLS   = "853"
	portHTTPS = "443"
	portQUIC  = "853" // RFC 9250 4.1.1
)

// defaultDoHPath is used when an https:// or h3:// address has no path.
const defaultDoHPath = "/dns-query"

// ParseAddress parses "9.9.9.9", "9.9.9.9:53", "[2620:fe::fe]:53", "udp://…", "tcp://…",
// "tls://host[:port]", "https://host[:port]/path", "h3://host[:port]/path" (DoH over
// HTTP/3) and "quic://host[:port]" (DNS-over-QUIC). Plain and tcp:// need an IP address
// (no host names, they could not be resolved without a resolver). German error messages.
func ParseAddress(s string) (Spec, error) {
	if s == "" {
		return Spec{}, errors.New("Adresse fehlt")
	}
	if strings.TrimSpace(s) != s || strings.ContainsAny(s, " \t\r\n") {
		return Spec{}, invalidAddr(s)
	}

	scheme, rest := "udp", s
	if i := strings.Index(s, "://"); i >= 0 {
		scheme, rest = strings.ToLower(s[:i]), s[i+3:]
	}

	switch scheme {
	case "udp", "tcp":
		host, port, err := splitHostPort(rest, portDNS)
		if err != nil {
			return Spec{}, err
		}
		if host == "" {
			return Spec{}, invalidAddr(s)
		}
		ip, ok := parseIP(host)
		if !ok {
			return Spec{}, errors.New("Für DNS über UDP/TCP ist eine IP-Adresse nötig (kein Hostname): " + host)
		}
		return Spec{Raw: s, Scheme: scheme, Host: ip, Port: port}, nil

	case "tls", "quic":
		if strings.ContainsAny(rest, "/?#@") {
			return Spec{}, invalidAddr(s)
		}
		def := portTLS
		if scheme == "quic" {
			def = portQUIC
		}
		host, port, err := splitHostPort(rest, def)
		if err != nil {
			return Spec{}, err
		}
		host, err = checkTLSHost(host)
		if err != nil {
			return Spec{}, err
		}
		return Spec{Raw: s, Scheme: scheme, Host: host, Port: port}, nil

	case "https", "h3":
		u, err := url.Parse(s)
		if err != nil || u.Host == "" || u.Opaque != "" {
			return Spec{}, invalidAddr(s)
		}
		if u.User != nil || u.Fragment != "" {
			return Spec{}, invalidAddr(s)
		}
		host, port, err := splitHostPort(u.Host, portHTTPS)
		if err != nil {
			return Spec{}, err
		}
		host, err = checkTLSHost(host)
		if err != nil {
			return Spec{}, err
		}
		path := u.EscapedPath()
		if path == "" || path == "/" {
			path = defaultDoHPath
		}
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
		return Spec{Raw: s, Scheme: scheme, Host: host, Port: port, Path: path}, nil

	default:
		return Spec{}, errors.New("Unbekanntes Protokoll: " + scheme + " (erlaubt: udp, tcp, tls, https, h3, quic)")
	}
}

// ParseBootstrap accepts a plain IP with optional port and returns "ip:port".
func ParseBootstrap(s string) (string, error) {
	if s == "" {
		return "", errors.New("Adresse fehlt")
	}
	if strings.Contains(s, "://") || strings.ContainsAny(s, " \t\r\n/") {
		return "", errors.New("Bootstrap-Server müssen IP-Adressen sein (optional mit Port): " + s)
	}
	host, port, err := splitHostPort(s, portDNS)
	if err != nil {
		return "", err
	}
	ip, ok := parseIP(host)
	if !ok {
		return "", errors.New("Bootstrap-Server müssen IP-Adressen sein (optional mit Port): " + s)
	}
	return net.JoinHostPort(ip, port), nil
}

func invalidAddr(s string) error {
	return errors.New("Ungültige Adresse: " + s)
}

// splitHostPort splits "host", "host:port", "[v6]", "[v6]:port" or a bare IPv6 address.
// The host is returned without brackets.
func splitHostPort(s, defPort string) (host, port string, err error) {
	if s == "" {
		return "", defPort, nil
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return "", "", invalidAddr(s)
		}
		host = s[1:end]
		after := s[end+1:]
		switch {
		case after == "":
			port = defPort
		case strings.HasPrefix(after, ":"):
			port = after[1:]
		default:
			return "", "", invalidAddr(s)
		}
		if _, ok := parseIP(host); !ok || !strings.Contains(host, ":") {
			return "", "", invalidAddr(s)
		}
	} else if strings.Count(s, ":") > 1 {
		// Bare IPv6 address without port.
		if _, ok := parseIP(s); !ok {
			return "", "", invalidAddr(s)
		}
		host, port = s, defPort
	} else if i := strings.LastIndex(s, ":"); i >= 0 {
		host, port = s[:i], s[i+1:]
	} else {
		host, port = s, defPort
	}
	if err := checkPort(port); err != nil {
		return "", "", errors.New("Ungültiger Port in " + s)
	}
	return host, port, nil
}

func checkPort(p string) error {
	if p == "" || len(p) > 5 {
		return errors.New("bad port")
	}
	for _, c := range p {
		if c < '0' || c > '9' {
			return errors.New("bad port")
		}
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return errors.New("bad port")
	}
	return nil
}

// parseIP returns the canonical text form of an IP address (zone allowed for link-local).
func parseIP(s string) (string, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	return a.String(), true
}

// checkTLSHost validates the host of an encrypted address (DoT, DoH, DoH3, DoQ): an IP or
// a host name.
func checkTLSHost(host string) (string, error) {
	if host == "" {
		return "", errors.New("Für DoT/DoH/DoQ ist ein Hostname oder eine IP nötig")
	}
	if ip, ok := parseIP(host); ok {
		return ip, nil
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if !validHostname(h) {
		return "", errors.New("Ungültiger Hostname: " + host)
	}
	return h, nil
}

// validHostname checks a lowercase host name without trailing dot.
func validHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	// A name made of digits and dots only would be an (invalid) IPv4 address.
	if strings.Trim(h, "0123456789.") == "" {
		return false
	}
	return true
}
