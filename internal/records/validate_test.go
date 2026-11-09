package records

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestValidateZone(t *testing.T) {
	existing := []Zone{{ID: 1, Name: "home.lan"}, {ID: 2, Name: "lab.lan"}}
	tests := []struct {
		name   string
		in     Zone
		want   Zone
		fields []string
	}{
		{"normalised and default ns", Zone{Name: " Office.LAN. ", TTL: 300},
			Zone{Name: "office.lan", TTL: 300, PrimaryNS: "ns.office.lan"}, nil},
		{"reverse zone", Zone{Name: "168.192.in-addr.arpa"},
			Zone{Name: "168.192.in-addr.arpa", PrimaryNS: "ns.168.192.in-addr.arpa"}, nil},
		{"own ns kept", Zone{Name: "x.lan", PrimaryNS: "DNS.Home.Lan."},
			Zone{Name: "x.lan", PrimaryNS: "dns.home.lan"}, nil},
		{"duplicate", Zone{Name: "HOME.lan"}, Zone{}, []string{"name"}},
		{"same zone itself", Zone{ID: 1, Name: "home.lan", TTL: 60},
			Zone{ID: 1, Name: "home.lan", TTL: 60, PrimaryNS: "ns.home.lan"}, nil},
		{"empty", Zone{}, Zone{}, []string{"name"}},
		{"wildcard", Zone{Name: "*.home.lan"}, Zone{}, []string{"name"}},
		{"ip", Zone{Name: "192.168.1.1"}, Zone{}, []string{"name"}},
		{"bad label", Zone{Name: "a..b"}, Zone{}, []string{"name"}},
		{"ttl", Zone{Name: "t.lan", TTL: MaxTTL + 1}, Zone{}, []string{"ttl"}},
		{"ttl max ok", Zone{Name: "t.lan", TTL: MaxTTL}, Zone{Name: "t.lan", TTL: MaxTTL, PrimaryNS: "ns.t.lan"}, nil},
		{"ns ip", Zone{Name: "t.lan", PrimaryNS: "10.0.0.1"}, Zone{}, []string{"primary_ns"}},
		{"ns invalid", Zone{Name: "t.lan", PrimaryNS: "a b"}, Zone{}, []string{"primary_ns"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := tt.in
			f := ValidateZone(&z, existing)
			if got := keys(f); !reflect.DeepEqual(got, sorted(tt.fields)) {
				t.Fatalf("fields = %v, want %v", f, tt.fields)
			}
			for _, msg := range f {
				if msg == "" {
					t.Fatal("empty message")
				}
			}
			if tt.fields == nil && z != tt.want {
				t.Fatalf("zone = %+v, want %+v", z, tt.want)
			}
		})
	}
}

func TestValidateRecord(t *testing.T) {
	zones := []Zone{
		{ID: 1, Name: "home.lan", Enabled: true},
		{ID: 2, Name: "lab.home.lan", Enabled: false},
		{ID: 3, Name: "168.192.in-addr.arpa", Enabled: true},
	}
	others := []Record{
		{ID: 10, Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"},
		{ID: 11, Name: "www.home.lan", Type: "CNAME", Value: "nas.home.lan"},
		{ID: 12, Name: "home.lan", Type: "MX", Value: "mail.home.lan", Priority: 10},
		{ID: 13, Name: "single.example", Type: "TXT", Value: "Hallo"},
	}
	long := strings.Repeat("ä", MaxTXTLength)
	tests := []struct {
		name   string
		in     Record
		want   *Record // checked when no fields
		fields []string
	}{
		{"A normalised", Record{Name: "Printer.Home.LAN.", Type: "a", Value: " 192.168.1.20 ", TTL: 300, Priority: 5, Weight: 1, Port: 2, PTR: true},
			&Record{ZoneID: 1, Name: "printer.home.lan", Type: "A", Value: "192.168.1.20", TTL: 300, PTR: true}, nil},
		{"A mapped v6 is unmapped", Record{Name: "x.home.lan", Type: "A", Value: "::ffff:10.0.0.1"},
			&Record{ZoneID: 1, Name: "x.home.lan", Type: "A", Value: "10.0.0.1"}, nil},
		{"A with v6", Record{Name: "x.home.lan", Type: "A", Value: "fd00::1"}, nil, []string{"value"}},
		{"A garbage", Record{Name: "x.home.lan", Type: "A", Value: "nas"}, nil, []string{"value"}},
		{"AAAA canonical", Record{Name: "x.home.lan", Type: "AAAA", Value: "FD00:0:0::0010", PTR: true},
			&Record{ZoneID: 1, Name: "x.home.lan", Type: "AAAA", Value: "fd00::10", PTR: true}, nil},
		{"AAAA with v4", Record{Name: "x.home.lan", Type: "AAAA", Value: "10.0.0.1"}, nil, []string{"value"}},
		{"AAAA zone", Record{Name: "x.home.lan", Type: "AAAA", Value: "fe80::1%eth0"}, nil, []string{"value"}},
		{"single record", Record{Name: "nas.lan", Type: "A", Value: "10.0.0.1"},
			&Record{ZoneID: 0, Name: "nas.lan", Type: "A", Value: "10.0.0.1"}, nil},
		{"disabled zone membership", Record{Name: "pc.lab.home.lan", Type: "A", Value: "10.0.0.1"},
			&Record{ZoneID: 2, Name: "pc.lab.home.lan", Type: "A", Value: "10.0.0.1"}, nil},
		{"CNAME to ip", Record{Name: "c.home.lan", Type: "CNAME", Value: "10.0.0.1"}, nil, []string{"value"}},
		{"CNAME to numeric label", Record{Name: "c.home.lan", Type: "CNAME", Value: "10.0.0"}, nil, []string{"value"}},
		{"CNAME self", Record{Name: "c.home.lan", Type: "CNAME", Value: "C.home.lan."}, nil, []string{"value"}},
		{"CNAME empty", Record{Name: "c.home.lan", Type: "CNAME"}, nil, []string{"value"}},
		{"CNAME external", Record{Name: "c.home.lan", Type: "CNAME", Value: "Example.COM."},
			&Record{ZoneID: 1, Name: "c.home.lan", Type: "CNAME", Value: "example.com"}, nil},
		{"CNAME at apex", Record{Name: "home.lan", Type: "CNAME", Value: "x.example"}, nil, []string{"name"}},
		{"CNAME next to A", Record{Name: "nas.home.lan", Type: "CNAME", Value: "x.example"}, nil, []string{"name"}},
		{"A next to CNAME", Record{Name: "www.home.lan", Type: "A", Value: "10.0.0.1"}, nil, []string{"name"}},
		{"second CNAME", Record{Name: "www.home.lan", Type: "CNAME", Value: "other.home.lan"}, nil, []string{"name"}},
		{"duplicate CNAME", Record{Name: "www.home.lan", Type: "CNAME", Value: "nas.home.lan"}, nil, []string{"name"}},
		{"update CNAME itself", Record{ID: 11, Name: "www.home.lan", Type: "CNAME", Value: "other.home.lan"},
			&Record{ID: 11, ZoneID: 1, Name: "www.home.lan", Type: "CNAME", Value: "other.home.lan"}, nil},
		{"duplicate A", Record{Name: "NAS.home.lan", Type: "A", Value: "192.168.1.10", TTL: 60}, nil, []string{"name"}},
		{"second A ok", Record{Name: "nas.home.lan", Type: "A", Value: "192.168.1.11"},
			&Record{ZoneID: 1, Name: "nas.home.lan", Type: "A", Value: "192.168.1.11"}, nil},
		{"MX", Record{Name: "home.lan", Type: "mx", Value: "mail2.home.lan", Priority: 20, Weight: 3},
			&Record{ZoneID: 1, Name: "home.lan", Type: "MX", Value: "mail2.home.lan", Priority: 20}, nil},
		{"MX duplicate", Record{Name: "home.lan", Type: "MX", Value: "mail.home.lan", Priority: 10}, nil, []string{"name"}},
		{"MX other priority", Record{Name: "home.lan", Type: "MX", Value: "mail.home.lan", Priority: 20},
			&Record{ZoneID: 1, Name: "home.lan", Type: "MX", Value: "mail.home.lan", Priority: 20}, nil},
		{"MX to ip", Record{Name: "home.lan", Type: "MX", Value: "192.168.1.1"}, nil, []string{"value"}},
		{"TXT", Record{Name: "home.lan", Type: "TXT", Value: "  v=spf1 -all ", PTR: true},
			&Record{ZoneID: 1, Name: "home.lan", Type: "TXT", Value: "v=spf1 -all"}, nil},
		{"TXT 4000 umlauts", Record{Name: "t.home.lan", Type: "TXT", Value: long},
			&Record{ZoneID: 1, Name: "t.home.lan", Type: "TXT", Value: long}, nil},
		{"TXT too long", Record{Name: "t.home.lan", Type: "TXT", Value: long + "a"}, nil, []string{"value"}},
		{"TXT empty", Record{Name: "t.home.lan", Type: "TXT", Value: "   "}, nil, []string{"value"}},
		{"TXT newline", Record{Name: "t.home.lan", Type: "TXT", Value: "a\nb"}, nil, []string{"value"}},
		{"TXT tab", Record{Name: "t.home.lan", Type: "TXT", Value: "a\tb"}, nil, []string{"value"}},
		{"TXT invalid utf8", Record{Name: "t.home.lan", Type: "TXT", Value: "a\xffb"}, nil, []string{"value"}},
		{"TXT wildcard", Record{Name: "*.home.lan", Type: "TXT", Value: "x"},
			&Record{ZoneID: 1, Name: "*.home.lan", Type: "TXT", Value: "x"}, nil},
		{"SRV", Record{Name: "_LDAP._tcp.home.lan", Type: "SRV", Value: "dc.home.lan", Priority: 1, Weight: 2, Port: 389, PTR: true},
			&Record{ZoneID: 1, Name: "_ldap._tcp.home.lan", Type: "SRV", Value: "dc.home.lan", Priority: 1, Weight: 2, Port: 389}, nil},
		{"SRV bad name", Record{Name: "ldap.tcp.home.lan", Type: "SRV", Value: "dc.home.lan", Port: 389}, nil, []string{"name"}},
		{"SRV too short", Record{Name: "_ldap._tcp", Type: "SRV", Value: "dc.home.lan", Port: 389}, nil, []string{"name"}},
		{"SRV port 0", Record{Name: "_ldap._tcp.home.lan", Type: "SRV", Value: "dc.home.lan"}, nil, []string{"port"}},
		{"SRV wildcard", Record{Name: "*.home.lan", Type: "SRV", Value: "dc.home.lan", Port: 1}, nil, []string{"name"}},
		{"PTR", Record{Name: "10.1.168.192.in-addr.arpa", Type: "PTR", Value: "nas.home.lan"},
			&Record{ZoneID: 3, Name: "10.1.168.192.in-addr.arpa", Type: "PTR", Value: "nas.home.lan"}, nil},
		{"PTR v6", Record{Name: "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa", Type: "PTR", Value: "x.lan"},
			&Record{Name: "0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa", Type: "PTR", Value: "x.lan"}, nil},
		{"PTR not reverse", Record{Name: "nas.home.lan", Type: "PTR", Value: "x.lan"}, nil, []string{"name"}},
		{"PTR wildcard", Record{Name: "*.168.192.in-addr.arpa", Type: "PTR", Value: "x.lan"}, nil, []string{"name"}},
		{"PTR to ip", Record{Name: "1.1.168.192.in-addr.arpa", Type: "PTR", Value: "192.168.1.1"}, nil, []string{"value"}},
		{"wildcard A", Record{Name: "*.Home.lan", Type: "A", Value: "10.0.0.1"},
			&Record{ZoneID: 1, Name: "*.home.lan", Type: "A", Value: "10.0.0.1"}, nil},
		{"wildcard ptr", Record{Name: "*.home.lan", Type: "A", Value: "10.0.0.1", PTR: true}, nil, []string{"ptr"}},
		{"wildcard in the middle", Record{Name: "a.*.home.lan", Type: "A", Value: "10.0.0.1"}, nil, []string{"name"}},
		{"empty name", Record{Type: "A", Value: "10.0.0.1"}, nil, []string{"name"}},
		{"invalid name", Record{Name: "a b.lan", Type: "A", Value: "10.0.0.1"}, nil, []string{"name"}},
		{"unknown type", Record{Name: "x.lan", Type: "NS", Value: "ns.lan"}, nil, []string{"type"}},
		{"ttl", Record{Name: "x.lan", Type: "A", Value: "10.0.0.1", TTL: MaxTTL + 1}, nil, []string{"ttl"}},
		{"managed_by core", Record{Name: "app.lan", Type: "A", Value: "10.0.0.1", ManagedBy: "core"},
			&Record{Name: "app.lan", Type: "A", Value: "10.0.0.1", ManagedBy: "core"}, nil},
		{"managed_by other", Record{Name: "app.lan", Type: "A", Value: "10.0.0.1", ManagedBy: "x"}, nil, []string{"managed_by"}},
		{"several", Record{Name: "", Type: "A", Value: "x", TTL: MaxTTL + 1}, nil, []string{"name", "ttl", "value"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.in
			f := ValidateRecord(&r, zones, others)
			if got := keys(f); !reflect.DeepEqual(got, sorted(tt.fields)) {
				t.Fatalf("fields = %v, want %v", f, tt.fields)
			}
			if tt.want != nil && r != *tt.want {
				t.Fatalf("record = %+v\nwant     %+v", r, *tt.want)
			}
		})
	}
}

func TestValidateRecordMax(t *testing.T) {
	others := make([]Record, MaxRecords)
	for i := range others {
		others[i] = Record{ID: int64(i + 1), Name: "x.lan", Type: "TXT", Value: "v"}
	}
	r := Record{Name: "y.lan", Type: "A", Value: "10.0.0.1"}
	if f := ValidateRecord(&r, nil, others); f["name"] == "" {
		t.Fatalf("fields = %v, want name", f)
	}
	r = Record{ID: 5, Name: "y.lan", Type: "A", Value: "10.0.0.1"}
	if f := ValidateRecord(&r, nil, others); len(f) != 0 {
		t.Fatalf("update: fields = %v", f)
	}
}

func TestZoneFor(t *testing.T) {
	zones := []Zone{{ID: 1, Name: "lan"}, {ID: 2, Name: "home.lan"}, {ID: 3, Name: "lab.home.lan", Enabled: false}}
	tests := map[string]int64{
		"lan":                1,
		"x.lan":              1,
		"home.lan":           2,
		"NAS.Home.Lan.":      2,
		"*.home.lan":         2,
		"pc.lab.home.lan":    3,
		"xhome.lan":          1,
		"example.com":        0,
		"lanx":               0,
		"a.b.c.lab.home.lan": 3,
	}
	for name, want := range tests {
		if got := ZoneFor(name, zones); got != want {
			t.Errorf("ZoneFor(%q) = %d, want %d", name, got, want)
		}
	}
	if ZoneFor("x.lan", nil) != 0 {
		t.Error("no zones")
	}
}

func TestTypeForAnswer(t *testing.T) {
	for answer, want := range map[string]string{
		"192.168.1.10":    TypeA,
		"::ffff:10.0.0.1": TypeA,
		"fd00::1":         TypeAAAA,
		"nas.home.lan":    TypeCNAME,
		" 10.0.0.1 ":      TypeA,
	} {
		if got := TypeForAnswer(answer); got != want {
			t.Errorf("TypeForAnswer(%q) = %s, want %s", answer, got, want)
		}
	}
	for _, typ := range Types {
		if IsRewriteType(typ) != (typ == "A" || typ == "AAAA" || typ == "CNAME") {
			t.Errorf("IsRewriteType(%s)", typ)
		}
	}
}

func TestRewriteFields(t *testing.T) {
	got := RewriteFields(map[string]string{"name": "n", "type": "t", "value": "v", "ttl": "x"})
	want := map[string]string{"domain": "n", "answer": "v", "ttl": "x"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if got := RewriteFields(map[string]string{"type": "t"}); got["answer"] != "t" {
		t.Fatalf("got %v", got)
	}
}

func TestNextSerial(t *testing.T) {
	day := time.Date(2026, 11, 9, 13, 0, 0, 0, time.UTC)
	tests := []struct {
		old  uint32
		now  time.Time
		want uint32
	}{
		{0, day, 2026110901},
		{2026110901, day, 2026110902},
		{2026110801, day, 2026110901},
		{2026110999, day, 2026111000}, // more than 99 changes: keeps counting up
		{2026111005, day, 2026111006}, // clock went back: never decreases
		{2026110950, day.AddDate(0, 0, 1), 2026111001},
		{2026123105, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), 2027010101},
	}
	for _, tt := range tests {
		if got := NextSerial(tt.old, tt.now); got != tt.want {
			t.Errorf("NextSerial(%d, %s) = %d, want %d", tt.old, tt.now, got, tt.want)
		}
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return sorted(out)
}

func sorted(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
