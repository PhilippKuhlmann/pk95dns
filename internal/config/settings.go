// Package config holds the runtime settings of PK95 DNS (docs/api.md → Settings).
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

// SafeSearch selects the search engines whose safe mode is enforced.
type SafeSearch struct {
	Enabled    bool `json:"enabled"`
	Google     bool `json:"google"`
	Bing       bool `json:"bing"`
	DuckDuckGo bool `json:"duckduckgo"`
	YouTube    bool `json:"youtube"`
	Yandex     bool `json:"yandex"`
	Pixabay    bool `json:"pixabay"`
}

// Conditional sends queries for Domain and its subdomains to Upstream.
type Conditional struct {
	Domain   string `json:"domain"`
	Upstream string `json:"upstream"`
}

// Settings is the object of GET/PUT /api/settings. The fields tagged json:"-" are stored
// with the settings but have their own API routes (services, protection).
type Settings struct {
	Upstreams         []string      `json:"upstreams"`
	Fallback          []string      `json:"fallback"`
	Bootstrap         []string      `json:"bootstrap"`
	UpstreamMode      string        `json:"upstream_mode"`
	UpstreamTimeoutMS int           `json:"upstream_timeout_ms"`
	Conditional       []Conditional `json:"conditional"`
	PrivatePTR        bool          `json:"private_ptr"`
	PrivateUpstreams  []string      `json:"private_upstreams"`

	CacheEnabled bool   `json:"cache_enabled"`
	CacheSize    int    `json:"cache_size"`
	CacheMinTTL  uint32 `json:"cache_min_ttl"`
	CacheMaxTTL  uint32 `json:"cache_max_ttl"`

	BlockingMode string `json:"blocking_mode"`
	BlockingIPv4 string `json:"blocking_ipv4"`
	BlockingIPv6 string `json:"blocking_ipv6"`
	BlockedTTL   uint32 `json:"blocked_ttl"`

	Ratelimit   int  `json:"ratelimit"`
	RefuseAny   bool `json:"refuse_any"`
	DNSSEC      bool `json:"dnssec"`
	DisableIPv6 bool `json:"disable_ipv6"`

	AllowedClients    []string `json:"allowed_clients"`
	DisallowedClients []string `json:"disallowed_clients"`

	QuerylogEnabled bool `json:"querylog_enabled"`
	QuerylogHours   int  `json:"querylog_hours"`
	AnonymizeIP     bool `json:"anonymize_ip"`
	StatsDays       int  `json:"stats_days"`

	ListsUpdateHours int `json:"lists_update_hours"`

	SafeSearch SafeSearch `json:"safesearch"`

	BlockedServices       []string `json:"-"`
	ProtectionEnabled     bool     `json:"-"`
	ProtectionPausedUntil int64    `json:"-"` // unix ms, 0 = not paused
}

// Upstream modes.
const (
	ModeLoadBalance = "load_balance"
	ModeParallel    = "parallel"
	ModeSequential  = "sequential"
)

// Blocking modes.
const (
	BlockNullIP   = "null_ip"
	BlockNXDomain = "nxdomain"
	BlockRefused  = "refused"
	BlockCustomIP = "custom_ip"
)

// PrivateNets are the default allowed_clients: private, CGNAT, loopback and link-local ranges.
var PrivateNets = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
}

// Defaults are the settings of a fresh installation.
func Defaults() Settings {
	return Settings{
		Upstreams:         []string{"https://dns.quad9.net/dns-query", "https://cloudflare-dns.com/dns-query"},
		Fallback:          []string{"9.9.9.9", "1.1.1.1"},
		Bootstrap:         []string{"9.9.9.9", "1.1.1.1"},
		UpstreamMode:      ModeLoadBalance,
		UpstreamTimeoutMS: 4000,
		Conditional:       []Conditional{},
		PrivatePTR:        true,
		PrivateUpstreams:  []string{},
		CacheEnabled:      true,
		CacheSize:         10000,
		CacheMinTTL:       0,
		CacheMaxTTL:       86400,
		BlockingMode:      BlockNullIP,
		BlockedTTL:        10,
		Ratelimit:         50,
		RefuseAny:         true,
		AllowedClients:    append([]string(nil), PrivateNets...),
		DisallowedClients: []string{},
		QuerylogEnabled:   true,
		QuerylogHours:     168,
		StatsDays:         30,
		ListsUpdateHours:  24,
		SafeSearch: SafeSearch{
			Google: true, Bing: true, DuckDuckGo: true, YouTube: true, Yandex: true, Pixabay: true,
		},
		BlockedServices:   []string{},
		ProtectionEnabled: true,
	}
}

// Merge applies a partial JSON object (PUT /api/settings) to base. Keys that are not
// present keep their value; nested objects (safesearch) merge key by key. The json:"-"
// fields can not be changed this way.
func Merge(base Settings, patch []byte) (Settings, error) {
	out := base.Clone()
	dec := json.NewDecoder(bytes.NewReader(patch))
	if err := dec.Decode(&out); err != nil {
		return base, errors.New("Ungültiges JSON: " + err.Error())
	}
	out.BlockedServices = base.BlockedServices
	out.ProtectionEnabled = base.ProtectionEnabled
	out.ProtectionPausedUntil = base.ProtectionPausedUntil
	out.normalize()
	return out, nil
}

// Clone returns a deep copy (slices are not shared).
func (s Settings) Clone() Settings {
	c := s
	c.Upstreams = cloneStrings(s.Upstreams)
	c.Fallback = cloneStrings(s.Fallback)
	c.Bootstrap = cloneStrings(s.Bootstrap)
	c.Conditional = append([]Conditional{}, s.Conditional...)
	c.PrivateUpstreams = cloneStrings(s.PrivateUpstreams)
	c.AllowedClients = cloneStrings(s.AllowedClients)
	c.DisallowedClients = cloneStrings(s.DisallowedClients)
	c.BlockedServices = cloneStrings(s.BlockedServices)
	return c
}

// normalize replaces nil slices by empty ones so the JSON answer has [] instead of null.
func (s *Settings) normalize() {
	for _, p := range []*[]string{&s.Upstreams, &s.Fallback, &s.Bootstrap, &s.PrivateUpstreams, &s.AllowedClients, &s.DisallowedClients, &s.BlockedServices} {
		if *p == nil {
			*p = []string{}
		}
	}
	if s.Conditional == nil {
		s.Conditional = []Conditional{}
	}
}

// Normalized returns s with nil slices replaced by empty ones.
func (s Settings) Normalized() Settings {
	s.normalize()
	return s
}

// ProtectionActive reports whether filtering is on at time now (switched on and not paused).
func (s Settings) ProtectionActive(now time.Time) bool {
	if s.ProtectionPausedUntil > 0 {
		return now.UnixMilli() >= s.ProtectionPausedUntil
	}
	return s.ProtectionEnabled
}

// UpstreamTimeout as a duration.
func (s Settings) UpstreamTimeout() time.Duration {
	return time.Duration(s.UpstreamTimeoutMS) * time.Millisecond
}

func cloneStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return append([]string{}, in...)
}
