package filter

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

// maxRegexPerSource limits the rules of one source that compile to a regular expression
// (/regex/ and * wildcards inside a pattern); further ones are invalid.
const maxRegexPerSource = 1000

// maxRegexTotal limits such rules across all sources of one Compile: every unmatched query
// scans them linearly and each costs memory.
const maxRegexTotal = 20000

// maxErrorText caps the line text reported in a ParseError.
const maxErrorText = 300

// German error messages for invalid lines.
const (
	errCosmetic    = "Kosmetische Regeln werden nicht unterstützt"
	errPath        = "Regeln mit Pfad werden nicht unterstützt"
	errIP          = "IP-Regeln werden nicht unterstützt"
	errEmpty       = "Leere Regel"
	errEmptyOption = "Leere Option"
	errRegex       = "Ungültiger regulärer Ausdruck"
	errEmptyRegex  = "Leerer regulärer Ausdruck"
	errTooManyRe   = "Zu viele Regex- oder Wildcard-Regeln (max. 1000 pro Liste)"
	errHostsNoName = "Hosts-Zeile ohne Namen"
	errNoDNSType   = "$dnstype ohne DNS-Typ"
	errMatchAll    = "Regel würde alle Domains erfassen"
	errInvalid     = "Ungültige Regel"
)

func errUnknownOption(name string) string { return "Unbekannte Option: " + name }
func errDomain(d string) string           { return "Ungültige Domain: " + d }
func errDNSType(t string) string          { return "Unbekannter DNS-Typ: " + t }

type ruleKind uint8

const (
	kindExact    ruleKind = iota + 1 // "example.org", "|example.org^"
	kindSubtree                      // "||example.org^"
	kindSubOnly                      // "*.example.org"
	kindRegex                        // "/regex/"
	kindWildcard                     // "||ads*.example.org^"
	kindHosts                        // "0.0.0.0 a.example b.example"
)

type lineResult uint8

const (
	lineSkip lineResult = iota // comment, empty, or only skipped hosts names
	lineOK
	lineInvalid
)

// parsedRule is one parsed line. For kindHosts the names are in hostsRest and are
// iterated with forEachHostsName.
type parsedRule struct {
	kind      ruleKind
	allow     bool // "@@"
	important bool
	types     *typeFilter // nil = all query types
	domain    string      // exact/subtree/subOnly: domain; regex/wildcard: canonical pattern
	re        *regexp.Regexp
	lit       string // wildcard: literal that must be contained in a matching name
	hostsIP   netip.Addr
	hostsRest string
}

// typeFilter is a parsed $dnstype value.
type typeFilter struct {
	include []uint16
	exclude []uint16
	text    string // normalized value, e.g. "A|AAAA|~HTTPS"
}

func (t *typeFilter) match(q uint16) bool {
	for _, x := range t.exclude {
		if x == q {
			return false
		}
	}
	if len(t.include) == 0 {
		return true
	}
	for _, x := range t.include {
		if x == q {
			return true
		}
	}
	return false
}

// parseLine parses one line. regexOK false makes rules that need a regular expression
// (/regex/, * wildcards) invalid (limit reached).
func parseLine(raw string, regexOK bool) (parsedRule, lineResult, string) {
	var p parsedRule
	line := strings.TrimSpace(raw)
	if line == "" || line[0] == '!' || line[0] == '#' {
		return p, lineSkip, ""
	}
	if line[0] == '[' && line[len(line)-1] == ']' {
		return p, lineSkip, ""
	}

	// Hosts syntax: the first field is an IP address.
	first, rest := cutField(line)
	if addr, err := netip.ParseAddr(first); err == nil {
		if rest == "" {
			return p, lineInvalid, errIP
		}
		return parseHosts(addr, rest)
	}

	if isCosmetic(line) {
		return p, lineInvalid, errCosmetic
	}
	if after, ok := strings.CutPrefix(line, "@@"); ok {
		p.allow = true
		line = after
	}
	if line == "" {
		return p, lineInvalid, errEmpty
	}
	if line[0] == '/' {
		return parseRegexRule(line, p, regexOK)
	}

	pattern := line
	if i := strings.LastIndexByte(line, '$'); i >= 0 {
		pattern = line[:i]
		if msg := parseOptions(line[i+1:], &p); msg != "" {
			return p, lineInvalid, msg
		}
	}
	if msg := parsePattern(pattern, &p, regexOK); msg != "" {
		return p, lineInvalid, msg
	}
	return p, lineOK, ""
}

// cutField splits s at the first space or tab.
func cutField(s string) (first, rest string) {
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimSpace(s[i+1:])
}

func isCosmetic(line string) bool {
	for _, m := range [...]string{"##", "#@#", "#$#", "#?#", "#%#", "#@$#", "#@?#", "#@%#"} {
		if strings.Contains(line, m) {
			return true
		}
	}
	return false
}

// hostsSkipName reports names in hosts files that are skipped silently.
func hostsSkipName(n string) bool {
	switch n {
	case "localhost", "localhost.localdomain", "local", "broadcasthost":
		return true
	}
	if strings.HasPrefix(n, "ip6-") {
		return true
	}
	_, err := netip.ParseAddr(n) // e.g. "0.0.0.0 0.0.0.0"
	return err == nil
}

// forEachHostsName calls fn for every normalized name of a hosts line (after the address,
// inline comment removed). Skipped names are passed with skip true.
func forEachHostsName(rest string, fn func(name string, skip bool) bool) {
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	for rest != "" {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			return
		}
		var f string
		if i := strings.IndexAny(rest, " \t"); i >= 0 {
			f, rest = rest[:i], rest[i:]
		} else {
			f, rest = rest, ""
		}
		n := NormalizeName(f)
		if !fn(n, hostsSkipName(n)) {
			return
		}
	}
}

func parseHosts(addr netip.Addr, rest string) (parsedRule, lineResult, string) {
	p := parsedRule{kind: kindHosts, hostsIP: addr.WithZone("").Unmap(), hostsRest: rest}
	names, valid := 0, 0
	msg := ""
	forEachHostsName(rest, func(n string, skip bool) bool {
		names++
		if skip {
			return true
		}
		if !ValidDomain(n, false) {
			msg = errDomain(n)
			return false
		}
		valid++
		return true
	})
	switch {
	case msg != "":
		return p, lineInvalid, msg
	case names == 0:
		return p, lineInvalid, errHostsNoName
	case valid == 0:
		return p, lineSkip, ""
	}
	return p, lineOK, ""
}

// hostsNullIndex returns the 1-based index of addr in hostsNullAddrs (a blocking hosts
// address) or 0 for any other address.
func hostsNullIndex(addr netip.Addr) uint8 {
	for i, a := range hostsNullAddrs {
		if i > 0 && a == addr {
			return uint8(i)
		}
	}
	return 0
}

var hostsNullAddrs = [...]netip.Addr{
	{},
	netip.MustParseAddr("0.0.0.0"),
	netip.MustParseAddr("127.0.0.1"),
	netip.MustParseAddr("::"),
	netip.MustParseAddr("::1"),
}

func parseRegexRule(line string, p parsedRule, regexOK bool) (parsedRule, lineResult, string) {
	end := strings.LastIndexByte(line, '/')
	if end == 0 {
		return p, lineInvalid, errInvalid
	}
	body, rest := line[1:end], line[end+1:]
	if rest != "" {
		if rest[0] != '$' {
			return p, lineInvalid, errPath
		}
		if msg := parseOptions(rest[1:], &p); msg != "" {
			return p, lineInvalid, msg
		}
	}
	if body == "" {
		return p, lineInvalid, errEmptyRegex
	}
	if !regexOK {
		return p, lineInvalid, errTooManyRe
	}
	re, err := regexp.Compile(body)
	if err != nil {
		return p, lineInvalid, errRegex
	}
	p.kind = kindRegex
	p.re = re
	p.domain = "/" + body + "/"
	return p, lineOK, ""
}

func parseOptions(s string, p *parsedRule) string {
	if s == "" {
		return errEmptyOption
	}
	for o := range strings.SplitSeq(s, ",") {
		name, val, hasVal := strings.Cut(o, "=")
		switch {
		case name == "":
			return errEmptyOption
		case name == "important" && !hasVal:
			p.important = true
		case name == "dnstype" && hasVal:
			tf, msg := parseDNSType(val)
			if msg != "" {
				return msg
			}
			p.types = tf
		default:
			return errUnknownOption(name)
		}
	}
	return ""
}

func parseDNSType(val string) (*typeFilter, string) {
	if val == "" {
		return nil, errNoDNSType
	}
	tf := &typeFilter{}
	var b strings.Builder
	for tok := range strings.SplitSeq(val, "|") {
		neg := false
		name := tok
		if after, ok := strings.CutPrefix(tok, "~"); ok {
			neg, name = true, after
		}
		name = strings.ToUpper(name)
		code, ok := dns.StringToType[name]
		if !ok || name == "" {
			return nil, errDNSType(tok)
		}
		if b.Len() > 0 {
			b.WriteByte('|')
		}
		if neg {
			b.WriteByte('~')
			tf.exclude = append(tf.exclude, code)
		} else {
			tf.include = append(tf.include, code)
		}
		b.WriteString(name)
	}
	tf.text = b.String()
	return tf, ""
}

// parsePattern parses the domain part of an adblock-style rule (options already removed).
func parsePattern(pat string, p *parsedRule, regexOK bool) string {
	const (
		anchorNone = iota
		anchorStart
		anchorDomain
	)
	anchor := anchorNone
	if after, ok := strings.CutPrefix(pat, "||"); ok {
		anchor, pat = anchorDomain, after
	} else if after, ok := strings.CutPrefix(pat, "|"); ok {
		anchor, pat = anchorStart, after
	}
	caret := false
	switch {
	case strings.HasSuffix(pat, "^|"):
		pat, caret = pat[:len(pat)-2], true
	case strings.HasSuffix(pat, "^"):
		pat, caret = pat[:len(pat)-1], true
	case strings.HasSuffix(pat, "|"):
		pat = pat[:len(pat)-1]
	}
	if pat == "" {
		return errEmpty
	}
	// "example.org^" without "||" blocks the domain and its subdomains, like "||example.org^".
	if anchor == anchorNone && caret {
		anchor = anchorDomain
	}
	if strings.ContainsAny(pat, " \t") {
		return errInvalid
	}
	if strings.ContainsAny(pat, "/?") {
		return errPath
	}
	if strings.ContainsAny(pat, "^|") {
		return errDomain(pat)
	}
	pat = NormalizeName(pat)
	if strings.HasPrefix(pat, "[") || strings.Contains(pat, ":") {
		if _, err := netip.ParseAddr(strings.Trim(pat, "[]")); err == nil {
			return errIP
		}
		return errDomain(pat)
	}
	if lastLabelNumeric(pat) {
		return errIP
	}

	if strings.Contains(pat, "*") {
		if rest, ok := strings.CutPrefix(pat, "*."); ok && !strings.Contains(rest, "*") {
			if !ValidDomain(rest, false) {
				return errDomain(pat)
			}
			p.kind, p.domain = kindSubOnly, rest
			return ""
		}
		if strings.Trim(pat, "*.") == "" {
			return errMatchAll
		}
		if !ValidDomain(strings.ReplaceAll(pat, "*", "a"), false) {
			return errDomain(pat)
		}
		if !regexOK {
			return errTooManyRe
		}
		parts := strings.Split(pat, "*")
		var re strings.Builder
		if anchor == anchorDomain {
			re.WriteString(`(?:^|\.)`)
		} else {
			re.WriteString(`^`)
		}
		for i, part := range parts {
			if i > 0 {
				re.WriteString(`.*`)
			}
			re.WriteString(regexp.QuoteMeta(part))
			if len(part) > len(p.lit) {
				p.lit = part
			}
		}
		re.WriteString(`$`)
		compiled, err := regexp.Compile(re.String())
		if err != nil {
			return errDomain(pat)
		}
		p.kind, p.re = kindWildcard, compiled
		switch anchor {
		case anchorDomain:
			p.domain = "||" + pat + "^"
		case anchorStart:
			p.domain = "|" + pat + "^"
		default:
			p.domain = pat
		}
		return ""
	}

	if !ValidDomain(pat, false) {
		return errDomain(pat)
	}
	p.domain = pat
	if anchor == anchorDomain {
		p.kind = kindSubtree
	} else {
		p.kind = kindExact
	}
	return ""
}

// usesRegex reports whether the rule is matched by a regular expression (counts against
// maxRegexPerSource).
func (p *parsedRule) usesRegex() bool { return p.kind == kindRegex || p.kind == kindWildcard }

// forEachLine iterates over the lines of data with 1-based numbers (\n or \r\n line ends).
func forEachLine(data string, fn func(no int, line string)) {
	data = strings.TrimPrefix(data, "\ufeff")
	no := 0
	for data != "" {
		no++
		var line string
		if i := strings.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, ""
		}
		fn(no, strings.TrimSuffix(line, "\r"))
	}
}

// ParseRules validates rule text (custom rules): number of valid rules and invalid lines
// (at most 100 reported).
func ParseRules(data []byte) (count int, invalid []ParseError) {
	regexes := 0
	forEachLine(string(data), func(no int, line string) {
		p, res, msg := parseLine(line, regexes < maxRegexPerSource)
		switch res {
		case lineOK:
			count++
			if p.usesRegex() {
				regexes++
			}
		case lineInvalid:
			if len(invalid) < 100 {
				invalid = append(invalid, ParseError{Line: no, Text: truncateText(strings.TrimSpace(line)), Error: msg})
			}
		}
	})
	return count, invalid
}

func truncateText(s string) string {
	if len(s) <= maxErrorText {
		return s
	}
	cut := maxErrorText
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
