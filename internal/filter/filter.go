// Package filter parses block/allow rules (adblock, hosts and domain-list syntax), compiles
// them into immutable RuleSets and decides per query (docs/design.md → Filtering).
// It must not import internal/upstream, internal/store or internal/dnsserver.
package filter

import (
	"net/netip"

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
	Data  []byte
}

// ParseError describes an invalid line (1-based line number). Error is German.
type ParseError struct {
	Line  int    `json:"line"`
	Text  string `json:"text"`
	Error string `json:"error"`
}

// RuleSet is an immutable compiled set of rules from one or more sources. Safe for
// concurrent use.
type RuleSet struct {
	// unexported fields
}

// CompileStats: valid and invalid rule counts per source id.
type CompileStats struct {
	Rules   map[int64]int
	Invalid map[int64]int
}

// Compile parses and compiles the sources. Invalid lines are skipped and counted.
func Compile(sources []Source) (*RuleSet, CompileStats) {
	panic("not implemented")
}

// ParseRules validates rule text (custom rules): number of valid rules and invalid lines
// (at most 100 reported).
func ParseRules(data []byte) (count int, invalid []ParseError) {
	panic("not implemented")
}

// Count returns the number of rules in the set.
func (rs *RuleSet) Count() int {
	panic("not implemented")
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
	// unexported fields
}

// NewEngine returns an engine with empty rule sets.
func NewEngine() *Engine {
	panic("not implemented")
}

// SetLists replaces the rule set compiled from all enabled block and allow lists.
func (e *Engine) SetLists(rs *RuleSet) {
	panic("not implemented")
}

// SetCustom replaces the custom rules (source id 0).
func (e *Engine) SetCustom(rs *RuleSet) {
	panic("not implemented")
}

// Check decides for one query in the order of docs/design.md → Decision order.
func (e *Engine) Check(req Request) Result {
	panic("not implemented")
}

// CheckCNAME checks a CNAME target of an upstream answer (CNAME cloaking): only block
// decisions count (custom, services, lists incl. allow overrides), no SafeSearch, no rewrites.
// Returns Result{Action: None} unless the target is blocked.
func (e *Engine) CheckCNAME(name string, qtype uint16, services []string) Result {
	panic("not implemented")
}
