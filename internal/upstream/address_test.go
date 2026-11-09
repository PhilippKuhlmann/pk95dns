package upstream

import (
	"strings"
	"testing"
)

func TestParseAddress(t *testing.T) {
	tests := []struct {
		in      string
		want    Spec
		wantErr string
	}{
		{in: "9.9.9.9", want: Spec{Scheme: "udp", Host: "9.9.9.9", Port: "53"}},
		{in: "9.9.9.9:5353", want: Spec{Scheme: "udp", Host: "9.9.9.9", Port: "5353"}},
		{in: "[2620:fe::fe]:53", want: Spec{Scheme: "udp", Host: "2620:fe::fe", Port: "53"}},
		{in: "[2620:fe::fe]", want: Spec{Scheme: "udp", Host: "2620:fe::fe", Port: "53"}},
		{in: "2620:fe::fe", want: Spec{Scheme: "udp", Host: "2620:fe::fe", Port: "53"}},
		{in: "udp://1.1.1.1", want: Spec{Scheme: "udp", Host: "1.1.1.1", Port: "53"}},
		{in: "UDP://1.1.1.1:54", want: Spec{Scheme: "udp", Host: "1.1.1.1", Port: "54"}},
		{in: "tcp://1.1.1.1", want: Spec{Scheme: "tcp", Host: "1.1.1.1", Port: "53"}},
		{in: "tcp://[::1]:5300", want: Spec{Scheme: "tcp", Host: "::1", Port: "5300"}},
		{in: "tls://dns.quad9.net", want: Spec{Scheme: "tls", Host: "dns.quad9.net", Port: "853"}},
		{in: "tls://Dns.Quad9.NET.:8853", want: Spec{Scheme: "tls", Host: "dns.quad9.net", Port: "8853"}},
		{in: "tls://9.9.9.9", want: Spec{Scheme: "tls", Host: "9.9.9.9", Port: "853"}},
		{in: "tls://[2620:fe::fe]:853", want: Spec{Scheme: "tls", Host: "2620:fe::fe", Port: "853"}},
		{in: "https://dns.quad9.net/dns-query", want: Spec{Scheme: "https", Host: "dns.quad9.net", Port: "443", Path: "/dns-query"}},
		{in: "https://dns.example:8443/custom/path", want: Spec{Scheme: "https", Host: "dns.example", Port: "8443", Path: "/custom/path"}},
		{in: "https://dns.example", want: Spec{Scheme: "https", Host: "dns.example", Port: "443", Path: "/dns-query"}},
		{in: "https://dns.example/", want: Spec{Scheme: "https", Host: "dns.example", Port: "443", Path: "/dns-query"}},
		{in: "https://[2606:4700::1111]/dns-query", want: Spec{Scheme: "https", Host: "2606:4700::1111", Port: "443", Path: "/dns-query"}},
		{in: "https://dns.example/q?x=1", want: Spec{Scheme: "https", Host: "dns.example", Port: "443", Path: "/q?x=1"}},

		{in: "", wantErr: "Adresse fehlt"},
		{in: " 9.9.9.9", wantErr: "Ungültige Adresse"},
		{in: "dns.google", wantErr: "IP-Adresse nötig"},
		{in: "tcp://dns.google", wantErr: "IP-Adresse nötig"},
		{in: "udp://", wantErr: "Ungültige Adresse"},
		{in: "9.9.9.9:0", wantErr: "Ungültiger Port"},
		{in: "9.9.9.9:65536", wantErr: "Ungültiger Port"},
		{in: "9.9.9.9:abc", wantErr: "Ungültiger Port"},
		{in: "9.9.9.9:", wantErr: "Ungültiger Port"},
		{in: "[2620:fe::fe", wantErr: "Ungültige Adresse"},
		{in: "[1.2.3.4]:53", wantErr: "Ungültige Adresse"},
		{in: "[::1]x", wantErr: "Ungültige Adresse"},
		{in: "1.2.3.4.5", wantErr: "IP-Adresse nötig"},
		{in: "tls://", wantErr: "Für DoT/DoH/DoQ ist ein Hostname oder eine IP nötig"},
		{in: "tls://:853", wantErr: "Für DoT/DoH/DoQ ist ein Hostname oder eine IP nötig"},
		{in: "tls://host/path", wantErr: "Ungültige Adresse"},
		{in: "tls://bad_-.example..org", wantErr: "Ungültiger Hostname"},
		{in: "https://", wantErr: "Ungültige Adresse"},
		{in: "https:///dns-query", wantErr: "Ungültige Adresse"},
		{in: "https://user:pw@dns.example/dns-query", wantErr: "Ungültige Adresse"},
		{in: "https://-bad.example/dns-query", wantErr: "Ungültiger Hostname"},
		{in: "https://999.1.1.1/dns-query", wantErr: "Ungültiger Hostname"},
		{in: "quic://dns.adguard-dns.com", want: Spec{Scheme: "quic", Host: "dns.adguard-dns.com", Port: "853"}},
		{in: "QUIC://94.140.14.14:784", want: Spec{Scheme: "quic", Host: "94.140.14.14", Port: "784"}},
		{in: "quic://[2a10:50c0::ad1:ff]", want: Spec{Scheme: "quic", Host: "2a10:50c0::ad1:ff", Port: "853"}},
		{in: "h3://cloudflare-dns.com/dns-query", want: Spec{Scheme: "h3", Host: "cloudflare-dns.com", Port: "443", Path: "/dns-query"}},
		{in: "h3://dns.example:8443", want: Spec{Scheme: "h3", Host: "dns.example", Port: "8443", Path: "/dns-query"}},
		{in: "h3://1.1.1.1/dns-query", want: Spec{Scheme: "h3", Host: "1.1.1.1", Port: "443", Path: "/dns-query"}},
		{in: "quic://dns.example/dns-query", wantErr: "Ungültige Adresse"},
		{in: "quic://user@dns.example", wantErr: "Ungültige Adresse"},
		{in: "quic://", wantErr: "Für DoT/DoH/DoQ ist ein Hostname oder eine IP nötig"},
		{in: "h3://", wantErr: "Ungültige Adresse"},
		{in: "h3://user:pw@dns.example/", wantErr: "Ungültige Adresse"},
		{in: "doq://dns.example", wantErr: "Unbekanntes Protokoll: doq (erlaubt: udp, tcp, tls, https, h3, quic)"},
		{in: "sdns://AQcAAAAAAAAA", wantErr: "Unbekanntes Protokoll"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseAddress(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseAddress(%q) = %+v, want error %q", tt.in, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAddress(%q): %v", tt.in, err)
			}
			tt.want.Raw = tt.in
			if got != tt.want {
				t.Fatalf("ParseAddress(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestProtocolAndEncrypted(t *testing.T) {
	tests := []struct {
		addr      string
		protocol  string
		encrypted bool
	}{
		{"9.9.9.9", "DNS", false},
		{"udp://9.9.9.9", "DNS", false},
		{"tcp://9.9.9.9", "DNS/TCP", false},
		{"tls://dns.quad9.net", "DoT", true},
		{"https://dns.quad9.net/dns-query", "DoH", true},
		{"h3://dns.quad9.net/dns-query", "DoH3", true},
		{"quic://dns.adguard-dns.com", "DoQ", true},
	}
	for _, tt := range tests {
		spec, err := ParseAddress(tt.addr)
		if err != nil {
			t.Fatal(err)
		}
		if spec.Protocol() != tt.protocol || spec.Encrypted() != tt.encrypted || Encrypted(tt.addr) != tt.encrypted {
			t.Fatalf("%s: protocol %q encrypted %v/%v", tt.addr, spec.Protocol(), spec.Encrypted(), Encrypted(tt.addr))
		}
	}
	for _, bad := range []string{"", "kaputt", "sdns://x", "tls://", "https://"} {
		if Encrypted(bad) {
			t.Fatalf("Encrypted(%q) = true", bad)
		}
	}
}

func TestLANOnly(t *testing.T) {
	lan := []string{"10.0.0.1", "172.31.255.254:53", "udp://192.168.178.1", "tcp://100.64.0.1", "100.127.255.255",
		"127.0.0.1:5353", "169.254.0.1", "fd00::1", "[fc00::53]:5353", "fe80::1%eth0", "[fe80::1%eth0]:53", "::1", "::ffff:192.168.1.1"}
	for _, a := range lan {
		if !LANOnly(a) {
			t.Errorf("LANOnly(%q) = false", a)
		}
	}
	public := []string{"8.8.8.8", "udp://1.1.1.1", "tcp://[2620:fe::fe]:53", "100.128.0.1", "172.32.0.1", "::ffff:8.8.8.8",
		"2001:db8::1", "tls://192.168.1.1", "https://10.0.0.1/dns-query", "quic://fd00::1", "", "router.lan", "sdns://x"}
	for _, a := range public {
		if LANOnly(a) {
			t.Errorf("LANOnly(%q) = true", a)
		}
	}
}

func TestParseBootstrap(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "9.9.9.9", want: "9.9.9.9:53"},
		{in: "9.9.9.9:5353", want: "9.9.9.9:5353"},
		{in: "2620:fe::fe", want: "[2620:fe::fe]:53"},
		{in: "[2620:fe::fe]:54", want: "[2620:fe::fe]:54"},
		{in: "", wantErr: true},
		{in: "dns.google", wantErr: true},
		{in: "udp://9.9.9.9", wantErr: true},
		{in: "tls://9.9.9.9", wantErr: true},
		{in: "https://9.9.9.9/dns-query", wantErr: true},
		{in: "9.9.9.9:0", wantErr: true},
		{in: "9.9.9.9 ", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseBootstrap(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseBootstrap(%q) = %q, want error", tt.in, got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ParseBootstrap(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
			}
		})
	}
}

func TestIsPrivatePTR(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"1.1.168.192.in-addr.arpa", true},
		{"168.192.in-addr.arpa", true},
		{"192.in-addr.arpa", false},
		{"5.0.0.10.in-addr.arpa", true},
		{"10.in-addr.arpa", true},
		{"1.0.16.172.in-addr.arpa", true},
		{"1.0.31.172.in-addr.arpa", true},
		{"1.0.32.172.in-addr.arpa", false},
		{"16.172.in-addr.arpa", true},
		{"172.in-addr.arpa", false},
		{"1.0.64.100.in-addr.arpa", true},
		{"1.0.128.100.in-addr.arpa", false},
		{"64.100.in-addr.arpa", true},
		{"100.in-addr.arpa", false},
		{"1.0.0.127.in-addr.arpa", true},
		{"1.1.254.169.in-addr.arpa", true},
		{"8.8.8.8.in-addr.arpa", false},
		{"1.1.1.1.in-addr.arpa", false},
		{"in-addr.arpa", false},
		{"1.2.3.4.5.in-addr.arpa", false},
		// Names below a private reverse zone stay private, whatever their leading labels.
		{"256.168.192.in-addr.arpa", true},
		{"x.168.192.in-addr.arpa", true},
		{"01.168.192.in-addr.arpa", true},
		{"1.1.1.168.192.in-addr.arpa", true},
		{"256.8.8.8.in-addr.arpa", false},
		{"x.8.8.in-addr.arpa", false},
		// DNS-SD browse domains (RFC 6763 11) sent by macOS, iOS and Avahi.
		{"lb._dns-sd._udp.0.1.168.192.in-addr.arpa", true},
		{"b._dns-sd._udp.0.0.10.in-addr.arpa", true},
		{"db._dns-sd._udp.0.0.16.172.in-addr.arpa", true},
		{"lb._dns-sd._udp.0.8.8.8.in-addr.arpa", false},
		{"lb._dns-sd._udp.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa", true},
		{"lb._dns-sd._udp.8.b.d.0.1.0.0.2.ip6.arpa", false},
		{"1.1.168.192.in-addr.arpa.", true},
		{"1.1.168.192.IN-ADDR.ARPA", true},
		// IPv6
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", true},
		{"2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", false},
		{"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", false},
		{"c.f.ip6.arpa", true},
		{"d.f.ip6.arpa", true},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa", true},
		{"f.ip6.arpa", false},
		{"e.f.ip6.arpa", false},
		{"8.e.f.ip6.arpa", true},
		{"b.e.f.ip6.arpa", true},
		{"c.e.f.ip6.arpa", false},
		{"8.b.d.0.1.0.0.2.ip6.arpa", false},
		{"ip6.arpa", false},
		{"g.f.ip6.arpa", false},
		{"cd.f.ip6.arpa", false},
		{"example.org", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPrivatePTR(tt.name); got != tt.want {
				t.Fatalf("IsPrivatePTR(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
