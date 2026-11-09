// Package filter parses block/allow rules (adblock, hosts and domain-list syntax), compiles
// them into immutable RuleSets and decides per query (docs/design.md → Filtering).
// It must not import internal/upstream, internal/store or internal/dnsserver.
package filter

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"

	"pk95dns/internal/config"
)

// Action of a filter decision.
type Action uint8

const (
	None    Action = iota // no rule matched
	Block                 // answer with the blocked answer of the blocking mode
	Allow                 // an allow rule matched, forward normally
	Rewrite               // answer with IPs (hosts rule) or CNAME (SafeSearch)
)

// Reasons (also the "reason" field of the query log).
const (
	ReasonCustom     = "custom"
	ReasonList       = "list"
	ReasonService    = "service"
	ReasonSafeSearch = "safesearch"
)

// Result of Engine.Check.
type Result struct {
	Action  Action
	Reason  string       // ReasonCustom, ReasonList, ReasonService, ReasonSafeSearch; "" for None
	Rule    string       // rule text: original line (custom) or canonical form (lists), service rule
	ListID  int64        // list id when Reason == ReasonList
	Service string       // service id when Reason == ReasonService
	IPs     []netip.Addr // Rewrite from a hosts rule ("192.168.1.5 nas.lan"), all addresses for that name
	CNAME   string       // Rewrite from SafeSearch (target host, no trailing dot)
}

// Source is the content of one list or of the custom rules (ID 0).
type Source struct {
	ID    int64
	Allow bool // allow list: every rule in it allows (also "||x^" and bare domains)
	// NoRewrite: hosts lines with a non-null address block the names instead of answering
	// with that address (lists downloaded without TLS, whose content may be altered).
	NoRewrite bool
	Data      []byte
}

// ParseError describes an invalid line (1-based line number). Error is German.
type ParseError struct {
	Line  int    `json:"line"`
	Text  string `json:"text"`
	Error string `json:"error"`
}

// Map kinds of a RuleSet.
const (
	mExact   = iota // the name itself (bare domains, "|d^", hosts lines)
	mSubtree        // the name and its subdomains ("||d^")
	mSubOnly        // only the subdomains ("*.d")
	mapKinds
)

// Entry flags. Bits 4–6 hold the 1-based index into hostsNullAddrs of a blocking hosts line.
const (
	fAllow uint8 = 1 << iota
	fImportant
	fAt        // written with "@@" (for the rule text)
	fRewrite   // hosts line with a non-blocking address (addresses in RuleSet.ips)
	hostsShift = 4
	hostsMask  = 7 << hostsShift
)

// entry is the compact form of one rule, stored under its domain. It never holds the
// rule text of list sources (see RuleSet.ruleText).
type entry struct {
	src   uint32 // index into RuleSet.srcIDs
	text  uint32 // 1-based index into RuleSet.texts (custom source), 0 = canonical form
	types uint16 // 1-based index into RuleSet.types, 0 = all query types
	flags uint8
}

// Precedence classes inside one RuleSet (higher wins).
const (
	classBlock = iota + 1
	classAllow
	classImportantBlock
	classImportantAllow
)

func (e entry) class() uint8 {
	switch e.flags & (fAllow | fImportant) {
	case fAllow | fImportant:
		return classImportantAllow
	case fImportant:
		return classImportantBlock
	case fAllow:
		return classAllow
	}
	return classBlock
}

// regexRule is a /regex/ rule or an adblock pattern with "*" wildcards.
type regexRule struct {
	re   *regexp.Regexp
	lit  string // wildcard patterns: a literal every matching name contains
	text string // canonical rule text
	e    entry
}

// RuleSet is an immutable compiled set of rules from one or more sources. Safe for
// concurrent use.
type RuleSet struct {
	maps     [mapKinds]map[string]entry
	extra    [mapKinds]map[string][]entry // further rules for a key with other flags/types
	ips      map[string][]netip.Addr      // hosts rewrites: all addresses per name
	regexes  []regexRule
	maxRegex uint8 // highest class among regexes (0 = none)
	srcIDs   []int64
	texts    []string
	types    []*typeFilter
	count    int
}

func newRuleSet() *RuleSet {
	rs := &RuleSet{ips: make(map[string][]netip.Addr)}
	for i := range rs.maps {
		rs.maps[i] = make(map[string]entry)
		rs.extra[i] = make(map[string][]entry)
	}
	return rs
}

// CompileStats: valid and invalid rule counts per source id.
type CompileStats struct {
	Rules   map[int64]int
	Invalid map[int64]int
}

// Compile parses and compiles the sources. Invalid lines are skipped and counted.
func Compile(sources []Source) (*RuleSet, CompileStats) {
	rs := newRuleSet()
	b := builder{rs: rs, typeIdx: make(map[string]uint16)}
	stats := CompileStats{Rules: make(map[int64]int), Invalid: make(map[int64]int)}
	totalRegexes := 0
	for _, src := range sources {
		si := uint32(len(rs.srcIDs))
		rs.srcIDs = append(rs.srcIDs, src.ID)
		valid, invalid, regexes := 0, 0, 0
		forEachLine(string(src.Data), func(_ int, line string) {
			p, res, _ := parseLine(line, regexes < maxRegexPerSource && totalRegexes < maxRegexTotal)
			switch res {
			case lineInvalid:
				invalid++
			case lineOK:
				if p.usesRegex() {
					regexes++
					totalRegexes++
				}
				b.add(si, src, line, &p)
				valid++
			}
		})
		stats.Rules[src.ID] += valid
		stats.Invalid[src.ID] += invalid
		rs.count += valid
	}
	return rs, stats
}

type builder struct {
	rs      *RuleSet
	typeIdx map[string]uint16
}

func (b *builder) add(si uint32, src Source, line string, p *parsedRule) {
	rs := b.rs
	e := entry{src: si}
	if src.ID == 0 {
		rs.texts = append(rs.texts, strings.Clone(strings.TrimSpace(line)))
		e.text = uint32(len(rs.texts))
	}
	if p.allow {
		e.flags |= fAllow | fAt
	}
	if src.Allow {
		e.flags |= fAllow
	}
	if p.important {
		e.flags |= fImportant
	}
	if p.types != nil {
		e.types = b.typeIndex(p.types)
	}

	switch p.kind {
	case kindExact:
		b.addEntry(mExact, p.domain, e)
	case kindSubtree:
		b.addEntry(mSubtree, p.domain, e)
	case kindSubOnly:
		b.addEntry(mSubOnly, p.domain, e)
	case kindRegex, kindWildcard:
		rs.regexes = append(rs.regexes, regexRule{
			re:   p.re,
			lit:  strings.Clone(p.lit),
			text: decorate(p.domain, e.flags, typeText(p.types)),
			e:    e,
		})
		rs.maxRegex = max(rs.maxRegex, e.class())
	case kindHosts:
		null := hostsNullIndex(p.hostsIP)
		forEachHostsName(p.hostsRest, func(n string, skip bool) bool {
			if skip {
				return true
			}
			he := e
			switch {
			case null > 0:
				he.flags |= null << hostsShift
			case he.flags&fAllow == 0 && !src.NoRewrite:
				he.flags |= fRewrite
				b.addEntry(mExact, n, he)
				if ips := rs.ips[n]; !slices.Contains(ips, p.hostsIP) {
					// Clone: assigning replaces the stored key, n points into the list data.
					rs.ips[strings.Clone(n)] = append(ips, p.hostsIP)
				}
				return true
			}
			b.addEntry(mExact, n, he)
			return true
		})
	}
}

// addEntry stores e under key unless an equal rule (same flags and types) is already
// there; the first source wins. Keys are cloned so they do not pin the list data.
func (b *builder) addEntry(m int, key string, e entry) {
	rs := b.rs
	if old, ok := rs.maps[m][key]; ok {
		if old.flags == e.flags && old.types == e.types {
			return
		}
		for _, x := range rs.extra[m][key] {
			if x.flags == e.flags && x.types == e.types {
				return
			}
		}
		// Assigning to an existing string key replaces the stored key, so always clone.
		k := strings.Clone(key)
		rs.extra[m][k] = append(rs.extra[m][k], e)
		return
	}
	rs.maps[m][strings.Clone(key)] = e
}

func (b *builder) typeIndex(tf *typeFilter) uint16 {
	if i, ok := b.typeIdx[tf.text]; ok {
		return i
	}
	if len(b.rs.types) >= 0xFFFF {
		return 0
	}
	b.rs.types = append(b.rs.types, tf)
	i := uint16(len(b.rs.types))
	b.typeIdx[tf.text] = i
	return i
}

func typeText(tf *typeFilter) string {
	if tf == nil {
		return ""
	}
	return tf.text
}

// decorate adds "@@" and the options to a canonical rule.
func decorate(s string, flags uint8, types string) string {
	if flags&fAt != 0 {
		s = "@@" + s
	}
	var opts []string
	if flags&fImportant != 0 {
		opts = append(opts, "important")
	}
	if types != "" {
		opts = append(opts, "dnstype="+types)
	}
	if len(opts) > 0 {
		s += "$" + strings.Join(opts, ",")
	}
	return s
}

// ruleText returns the original line (custom source) or the canonical form of a rule.
func (rs *RuleSet) ruleText(m int, key string, e entry) string {
	if e.text > 0 {
		return rs.texts[e.text-1]
	}
	var s string
	switch {
	case e.flags&fRewrite != 0:
		addr := "0.0.0.0"
		if ips := rs.ips[key]; len(ips) > 0 {
			addr = ips[0].String()
		}
		return addr + " " + key
	case e.flags&hostsMask != 0:
		return hostsNullAddrs[(e.flags&hostsMask)>>hostsShift].String() + " " + key
	case m == mSubtree:
		s = "||" + key + "^"
	case m == mSubOnly:
		s = "*." + key
	default:
		s = key
	}
	types := ""
	if e.types > 0 {
		types = rs.types[e.types-1].text
	}
	return decorate(s, e.flags, types)
}

// Count returns the number of rules in the set.
func (rs *RuleSet) Count() int {
	if rs == nil {
		return 0
	}
	return rs.count
}

// hit is the best matching rule of a RuleSet for one name.
type hit struct {
	ok    bool
	class uint8
	spec  int   // length of the matched domain (0 for regex rules)
	tie   uint8 // equal class and length: hosts rewrite > exact > subtree/subdomains > regex
	m     int   // map kind, -1 for a regex rule
	key   string
	e     entry
	rx    *regexRule
}

func (h *hit) better(c *hit) bool {
	if !h.ok {
		return true
	}
	if c.class != h.class {
		return c.class > h.class
	}
	if c.spec != h.spec {
		return c.spec > h.spec
	}
	if c.tie != h.tie {
		return c.tie > h.tie
	}
	return c.e.src < h.e.src
}

// consider offers the rules stored under key in map m.
func (rs *RuleSet) consider(h *hit, m int, key string, qtype uint16, cname bool) {
	if e, ok := rs.maps[m][key]; ok {
		rs.offer(h, m, key, e, qtype, cname)
		if xs, ok := rs.extra[m][key]; ok {
			for _, x := range xs {
				rs.offer(h, m, key, x, qtype, cname)
			}
		}
	}
}

func (rs *RuleSet) offer(h *hit, m int, key string, e entry, qtype uint16, cname bool) {
	if cname && e.flags&fRewrite != 0 {
		return
	}
	if e.types > 0 && !rs.types[e.types-1].match(qtype) {
		return
	}
	c := hit{ok: true, class: e.class(), spec: len(key), m: m, key: key, e: e}
	switch {
	case e.flags&fRewrite != 0:
		c.tie = 3
	case m == mExact:
		c.tie = 2
	default:
		c.tie = 1
	}
	if h.better(&c) {
		*h = c
	}
}

// match returns the best rule for name: highest class, then the most specific domain.
// cname true ignores hosts rewrites (CNAME cloaking check).
func (rs *RuleSet) match(name string, qtype uint16, cname bool) hit {
	var h hit
	if rs == nil || name == "" {
		return h
	}
	rs.consider(&h, mExact, name, qtype, cname)
	rs.consider(&h, mSubtree, name, qtype, cname)
	for p, ok := parentDomain(name); ok; p, ok = parentDomain(p) {
		rs.consider(&h, mSubtree, p, qtype, cname)
		rs.consider(&h, mSubOnly, p, qtype, cname)
	}
	// Regex rules lose ties against domain rules, so they only matter when they can
	// reach a higher class.
	if len(rs.regexes) == 0 || (h.ok && h.class >= rs.maxRegex) {
		return h
	}
	for i := range rs.regexes {
		r := &rs.regexes[i]
		cls := r.e.class()
		if h.ok && (cls < h.class || cls == h.class && r.e.src >= h.e.src) {
			continue
		}
		if r.e.types > 0 && !rs.types[r.e.types-1].match(qtype) {
			continue
		}
		if r.lit != "" && !strings.Contains(name, r.lit) {
			continue
		}
		if !r.re.MatchString(name) {
			continue
		}
		c := hit{ok: true, class: cls, m: -1, e: r.e, rx: r}
		if h.better(&c) {
			h = c
		}
	}
	return h
}

// result turns a hit into a Result.
func (rs *RuleSet) result(h hit, reason string) Result {
	r := Result{Reason: reason}
	if h.rx != nil {
		r.Rule = h.rx.text
		if h.e.text > 0 {
			r.Rule = rs.texts[h.e.text-1]
		}
	} else {
		r.Rule = rs.ruleText(h.m, h.key, h.e)
	}
	if reason == ReasonList {
		r.ListID = rs.srcIDs[h.e.src]
	}
	switch {
	case h.e.flags&fAllow != 0:
		r.Action = Allow
	case h.e.flags&fRewrite != 0:
		r.Action = Rewrite
		r.IPs = slices.Clone(rs.ips[h.key])
	default:
		r.Action = Block
	}
	return r
}

// Request is one decision request. Name is lowercase without trailing dot.
type Request struct {
	Name       string
	QType      uint16
	SafeSearch config.SafeSearch // effective SafeSearch settings of the client
	Services   []string          // effective blocked service ids of the client
}

// Engine holds the current list and custom RuleSets (swapped atomically) and the compiled
// services catalog. All methods are safe for concurrent use.
type Engine struct {
	lists    atomic.Pointer[RuleSet]
	custom   atomic.Pointer[RuleSet]
	services serviceIndex
}

// NewEngine returns an engine with empty rule sets.
func NewEngine() *Engine {
	e := &Engine{services: newServiceIndex()}
	e.lists.Store(newRuleSet())
	e.custom.Store(newRuleSet())
	return e
}

// SetLists replaces the rule set compiled from all enabled block and allow lists.
func (e *Engine) SetLists(rs *RuleSet) {
	if rs == nil {
		rs = newRuleSet()
	}
	e.lists.Store(rs)
}

// SetCustom replaces the custom rules (source id 0).
func (e *Engine) SetCustom(rs *RuleSet) {
	if rs == nil {
		rs = newRuleSet()
	}
	e.custom.Store(rs)
}

// Check decides for one query in the order of docs/design.md → Decision order.
func (e *Engine) Check(req Request) Result {
	return e.check(NormalizeName(req.Name), req.QType, &req.SafeSearch, req.Services, false)
}

// CheckCNAME checks a CNAME target of an upstream answer (CNAME cloaking): only block
// decisions count (custom, services, lists incl. allow overrides), no SafeSearch, no rewrites.
// Returns Result{Action: None} unless the target is blocked.
func (e *Engine) CheckCNAME(name string, qtype uint16, services []string) Result {
	r := e.check(NormalizeName(name), qtype, nil, services, true)
	if r.Action != Block {
		return Result{}
	}
	return r
}

// check implements the decision order. ss nil skips SafeSearch; cname ignores rewrites.
func (e *Engine) check(name string, qtype uint16, ss *config.SafeSearch, services []string, cname bool) Result {
	if name == "" {
		return Result{}
	}
	custom := e.custom.Load()
	ch := custom.match(name, qtype, cname)
	// 1. custom $important block (an important allow beats it), 2. custom allow.
	if ch.ok && ch.class >= classAllow {
		return custom.result(ch, ReasonCustom)
	}
	// 3. SafeSearch.
	if ss != nil {
		if target, ok := SafeSearchTarget(name, *ss); ok {
			return Result{Action: Rewrite, Reason: ReasonSafeSearch, CNAME: target}
		}
	}
	// 4. custom block / hosts rewrite.
	if ch.ok {
		return custom.result(ch, ReasonCustom)
	}
	// 5. blocked services.
	if r, ok := e.services.check(name, services); ok {
		return r
	}
	// 6.–8. lists: $important block, allow, block / hosts rewrite.
	lists := e.lists.Load()
	if lh := lists.match(name, qtype, cname); lh.ok {
		return lists.result(lh, ReasonList)
	}
	return Result{}
}
