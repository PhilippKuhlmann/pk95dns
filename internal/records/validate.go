package records

import (
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"pk95dns/internal/filter"
)

// German validation messages (docs/api.md → 422 fields.<key>).
const (
	msgZoneName        = "Bitte einen gültigen Zonennamen angeben (z. B. home.lan oder 168.192.in-addr.arpa)."
	msgZoneNameEmpty   = "Bitte einen Zonennamen angeben."
	msgZoneWildcard    = "Ein Zonenname darf keinen Platzhalter (*) enthalten."
	msgZoneDuplicate   = "Diese Zone gibt es schon."
	msgTTL             = "Die TTL muss zwischen 0 und 604800 Sekunden liegen."
	msgPrimaryNS       = "Bitte einen gültigen Hostnamen für den Nameserver angeben (z. B. ns.home.lan)."
	msgNameEmpty       = "Bitte einen Namen angeben."
	msgName            = "Bitte einen gültigen Namen angeben (z. B. nas.home.lan oder *.home.lan)."
	msgWildcardType    = "Platzhalter (*.) sind nur für A, AAAA, CNAME, TXT und MX erlaubt."
	msgSRVName         = "SRV-Namen haben die Form _dienst._protokoll.domain (z. B. _ldap._tcp.home.lan)."
	msgPTRName         = "PTR-Einträge brauchen einen Reverse-Namen (…in-addr.arpa oder …ip6.arpa)."
	msgType            = "Unbekannter Typ (erlaubt: A, AAAA, CNAME, MX, TXT, SRV, PTR)."
	msgIPv4            = "Bitte eine gültige IPv4-Adresse angeben (z. B. 192.168.1.10)."
	msgIPv6            = "Bitte eine gültige IPv6-Adresse angeben (z. B. fd00::10)."
	msgHostEmpty       = "Bitte einen Hostnamen angeben."
	msgHostIP          = "Bitte einen Hostnamen angeben, keine IP-Adresse."
	msgHost            = "Bitte einen gültigen Hostnamen angeben (z. B. server.home.lan)."
	msgCNAMESelf       = "Ein CNAME darf nicht auf sich selbst zeigen."
	msgTXTEmpty        = "Bitte einen Text angeben."
	msgTXTLength       = "Der Text darf höchstens 4000 Zeichen lang sein."
	msgTXTChars        = "Der Text darf nur druckbare Zeichen enthalten (keine Zeilenumbrüche oder Tabulatoren)."
	msgSRVPort         = "Bitte einen Port zwischen 1 und 65535 angeben."
	msgPTRWildcard     = "Für Platzhalter-Namen (*.) kann keine Rückwärtsauflösung erzeugt werden."
	msgManagedBy       = `Ungültiger Wert (erlaubt: "" oder "core").`
	msgCNAMEApex       = "Am Zonen-Apex ist kein CNAME erlaubt (dort stehen SOA und NS)."
	msgCNAMEExclusive  = "Neben einem CNAME darf es keine anderen Einträge mit diesem Namen geben."
	msgCNAMEExists     = "Für diesen Namen gibt es schon einen CNAME; daneben sind keine anderen Einträge erlaubt."
	msgRecordDuplicate = "Diesen Eintrag gibt es schon."
	msgTooMany         = "Es sind höchstens 50 000 Einträge möglich."
)

// MsgRecordDuplicate is the message for store.ErrDuplicate on records (field "name").
const MsgRecordDuplicate = msgRecordDuplicate

// MsgZoneDuplicate is the message for store.ErrDuplicate on zones (field "name").
const MsgZoneDuplicate = msgZoneDuplicate

// wildcardTypes may have a "*." name.
var wildcardTypes = map[string]bool{TypeA: true, TypeAAAA: true, TypeCNAME: true, TypeTXT: true, TypeMX: true}

// ValidateZone normalises z in place (name and primary_ns lowercased without trailing dot,
// primary_ns default "ns.<name>") and validates it against the existing zones (z itself is
// skipped by ID). It returns the German messages per JSON field (name, ttl, primary_ns);
// empty when z is valid. Defaults for fields missing in a request body (ttl 300,
// enabled true) are the caller's business, as TTL 0 is a valid value.
func ValidateZone(z *Zone, existing []Zone) map[string]string {
	fields := map[string]string{}
	z.Name = NormalizeName(z.Name)
	z.PrimaryNS = NormalizeName(z.PrimaryNS)
	nameOK := false
	switch {
	case z.Name == "":
		fields["name"] = msgZoneNameEmpty
	case strings.Contains(z.Name, "*"):
		fields["name"] = msgZoneWildcard
	case !filter.ValidDomain(z.Name, false) || lastLabelNumeric(z.Name) || isIP(z.Name):
		fields["name"] = msgZoneName
	default:
		nameOK = true
		for _, o := range existing {
			if o.ID != z.ID && NormalizeName(o.Name) == z.Name {
				fields["name"] = msgZoneDuplicate
				break
			}
		}
	}
	if z.TTL > MaxTTL {
		fields["ttl"] = msgTTL
	}
	if z.PrimaryNS == "" && nameOK {
		z.PrimaryNS = "ns." + z.Name
	}
	if z.PrimaryNS != "" {
		switch msg := checkHost(z.PrimaryNS); msg {
		case "":
		case msgHostIP:
			fields["primary_ns"] = msg
		default:
			fields["primary_ns"] = msgPrimaryNS
		}
	}
	return fields
}

// ValidateRecord normalises r in place and validates it (docs/api.md → Records). zones are
// all zones (disabled ones too), others all existing records (r itself is skipped by ID; a
// new record has ID 0). Normalisation: name and host name values lowercased without
// trailing dot, type uppercased, IPs in canonical form, TXT trimmed, fields that do not
// belong to the type set to 0/false, ZoneID derived from the name (ZoneFor). It returns the
// German messages per JSON field (name, type, value, ttl, priority, weight, port, ptr,
// managed_by); empty when r is valid. Exact duplicates and CNAME conflicts are reported on
// "name". The store's unique index stays the last guard (store.ErrDuplicate →
// MsgRecordDuplicate).
func ValidateRecord(r *Record, zones []Zone, others []Record) map[string]string {
	fields := map[string]string{}
	r.Name = NormalizeName(r.Name)
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.ManagedBy = strings.TrimSpace(r.ManagedBy)

	typeOK := false
	switch r.Type {
	case TypeA, TypeAAAA, TypeCNAME, TypeMX, TypeTXT, TypeSRV, TypePTR:
		typeOK = true
	default:
		fields["type"] = msgType
	}

	// Fields that do not belong to the type are stored as 0/false.
	if r.Type != TypeMX && r.Type != TypeSRV {
		r.Priority = 0
	}
	if r.Type != TypeSRV {
		r.Weight, r.Port = 0, 0
	}
	if r.Type != TypeA && r.Type != TypeAAAA {
		r.PTR = false
	}

	wildcard := strings.HasPrefix(r.Name, "*.")
	nameOK := false
	switch {
	case r.Name == "":
		fields["name"] = msgNameEmpty
	case !filter.ValidDomain(r.Name, true):
		fields["name"] = msgName
	case wildcard && typeOK && !wildcardTypes[r.Type]:
		fields["name"] = msgWildcardType
	case r.Type == TypeSRV && !srvName(r.Name):
		fields["name"] = msgSRVName
	case r.Type == TypePTR && !IsReverseName(r.Name):
		fields["name"] = msgPTRName
	default:
		nameOK = true
	}

	if typeOK {
		if msg := normalizeValue(r); msg != "" {
			fields["value"] = msg
		}
	}
	if r.TTL > MaxTTL {
		fields["ttl"] = msgTTL
	}
	if r.Type == TypeSRV && r.Port == 0 {
		fields["port"] = msgSRVPort
	}
	if r.PTR && wildcard {
		fields["ptr"] = msgPTRWildcard
	}
	if r.ManagedBy != "" && r.ManagedBy != ManagedByCore {
		fields["managed_by"] = msgManagedBy
	}

	r.ZoneID = 0
	if nameOK {
		r.ZoneID = ZoneFor(r.Name, zones)
	}
	if !nameOK || !typeOK {
		return fields
	}
	if r.Type == TypeCNAME && r.ZoneID != 0 {
		for _, z := range zones {
			if z.ID == r.ZoneID && NormalizeName(z.Name) == r.Name {
				fields["name"] = msgCNAMEApex
				return fields
			}
		}
	}

	count := 0
	conflict := ""
	for i := range others {
		o := &others[i]
		if r.ID != 0 && o.ID == r.ID {
			continue
		}
		count++
		if conflict != "" || NormalizeName(o.Name) != r.Name {
			continue
		}
		oType := strings.ToUpper(o.Type)
		switch {
		case r.Type == TypeCNAME && oType == TypeCNAME && o.Value == r.Value:
			conflict = msgRecordDuplicate
		case r.Type == TypeCNAME:
			conflict = msgCNAMEExclusive
		case oType == TypeCNAME:
			conflict = msgCNAMEExists
		case oType == r.Type && o.Value == r.Value && o.Priority == r.Priority && o.Weight == r.Weight && o.Port == r.Port:
			conflict = msgRecordDuplicate
		}
	}
	switch {
	case conflict != "":
		fields["name"] = conflict
	case r.ID == 0 && count >= MaxRecords:
		fields["name"] = msgTooMany
	}
	return fields
}

// normalizeValue normalises r.Value for its (valid) type and returns a message when it is
// invalid.
func normalizeValue(r *Record) string {
	switch r.Type {
	case TypeA:
		ip, err := netip.ParseAddr(strings.TrimSpace(r.Value))
		if err != nil || !(ip.Is4() || ip.Is4In6()) {
			return msgIPv4
		}
		r.Value = ip.Unmap().String()
	case TypeAAAA:
		ip, err := netip.ParseAddr(strings.TrimSpace(r.Value))
		if err != nil || !ip.Is6() || ip.Is4In6() || ip.Zone() != "" {
			return msgIPv6
		}
		r.Value = ip.String()
	case TypeCNAME, TypeMX, TypeSRV, TypePTR:
		r.Value = NormalizeName(r.Value)
		if msg := checkHost(r.Value); msg != "" {
			return msg
		}
		if r.Type == TypeCNAME && r.Value == r.Name {
			return msgCNAMESelf
		}
	case TypeTXT:
		r.Value = strings.TrimSpace(r.Value)
		switch {
		case r.Value == "":
			return msgTXTEmpty
		case !utf8.ValidString(r.Value):
			return msgTXTChars
		case utf8.RuneCountInString(r.Value) > MaxTXTLength:
			return msgTXTLength
		}
		for _, c := range r.Value {
			if !unicode.IsPrint(c) {
				return msgTXTChars
			}
		}
	}
	return ""
}

// checkHost validates a normalised host name target (CNAME, MX, SRV, PTR, primary NS).
func checkHost(v string) string {
	switch {
	case v == "":
		return msgHostEmpty
	case isIP(v):
		return msgHostIP
	case !filter.ValidDomain(v, false) || lastLabelNumeric(v):
		return msgHost
	}
	return ""
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// lastLabelNumeric reports whether the last label of name is all digits (an IP address or
// a part of one, never a host name).
func lastLabelNumeric(name string) bool {
	label := name[strings.LastIndexByte(name, '.')+1:]
	if label == "" {
		return false
	}
	for i := 0; i < len(label); i++ {
		if label[i] < '0' || label[i] > '9' {
			return false
		}
	}
	return true
}

// srvName reports whether name has the form _service._proto.domain.
func srvName(name string) bool {
	labels := strings.SplitN(name, ".", 3)
	return len(labels) == 3 && len(labels[0]) > 1 && labels[0][0] == '_' &&
		len(labels[1]) > 1 && labels[1][0] == '_' && labels[2] != ""
}

// IsReverseName reports whether the normalised name lies below in-addr.arpa or ip6.arpa.
func IsReverseName(name string) bool {
	return strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa")
}
