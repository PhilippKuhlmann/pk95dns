package api

import (
	"net/http"
	"strconv"
	"time"

	"pk95dns/internal/config"
	"pk95dns/internal/dnsserver"
	"pk95dns/internal/filter"
	"pk95dns/internal/store"
	"pk95dns/internal/upstream"
)

type protectionJSON struct {
	Enabled     bool  `json:"enabled"`
	PausedUntil int64 `json:"paused_until"`
}

func protectionOf(s config.Settings, now time.Time) protectionJSON {
	paused := s.ProtectionPausedUntil
	if paused > 0 && now.UnixMilli() >= paused {
		paused = 0 // expired, the app switches protection on again
	}
	return protectionJSON{Enabled: s.ProtectionActive(now), PausedUntil: paused}
}

type rulesJSON struct {
	Lists       int `json:"lists"`
	ListRules   int `json:"list_rules"`
	CustomRules int `json:"custom_rules"`
	Rewrites    int `json:"rewrites"`
	Services    int `json:"services"`
}

type cacheJSON struct {
	Enabled bool  `json:"enabled"`
	Entries int   `json:"entries"`
	Hits    int64 `json:"hits"`
	Misses  int64 `json:"misses"`
}

type statusJSON struct {
	Version    string                 `json:"version"`
	CoreMode   bool                   `json:"core_mode"`
	StartedAt  int64                  `json:"started_at"`
	DNS        dnsserver.ListenStatus `json:"dns"`
	Protection protectionJSON         `json:"protection"`
	Rules      rulesJSON              `json:"rules"`
	Cache      cacheJSON              `json:"cache"`
	Upstreams  []upstream.Health      `json:"upstreams"`
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	s := a.d.Settings()
	now := a.d.Now()
	st := statusJSON{
		Version:    a.d.Version,
		CoreMode:   a.d.CoreMode,
		StartedAt:  a.d.StartedAt.UnixMilli(),
		Protection: protectionOf(s, now),
		Upstreams:  []upstream.Health{},
	}
	if a.d.StartedAt.IsZero() {
		st.StartedAt = 0
	}
	if a.d.DNS != nil {
		st.DNS = a.d.DNS.Status()
	}
	ls, err := a.d.Store.Lists()
	if err != nil {
		internalError(w, r, err)
		return
	}
	for _, l := range ls {
		if l.Enabled {
			st.Rules.Lists++
			st.Rules.ListRules += l.RuleCount
		}
	}
	custom, err := a.customCount()
	if err != nil {
		internalError(w, r, err)
		return
	}
	st.Rules.CustomRules = custom
	rws, err := a.d.Store.Rewrites()
	if err != nil {
		internalError(w, r, err)
		return
	}
	for _, rw := range rws {
		if rw.Enabled {
			st.Rules.Rewrites++
		}
	}
	st.Rules.Services = len(s.BlockedServices)
	st.Cache.Enabled = s.CacheEnabled
	if a.d.Cache != nil {
		cs := a.d.Cache.Stats()
		st.Cache.Entries, st.Cache.Hits, st.Cache.Misses = cs.Entries, cs.Hits, cs.Misses
	}
	if a.d.Upstreams != nil {
		if h := a.d.Upstreams(); h != nil {
			st.Upstreams = h
		}
	}
	writeJSON(w, http.StatusOK, st)
}

// customCount returns the number of valid custom rules (cached until the rules change).
func (a *API) customCount() (int, error) {
	a.rulesMu.Lock()
	defer a.rulesMu.Unlock()
	if a.customN >= 0 {
		return a.customN, nil
	}
	text, err := a.d.Store.CustomRules()
	if err != nil {
		return 0, err
	}
	n, _ := filter.ParseRules([]byte(text))
	a.customN = n
	return n, nil
}

func (a *API) handleProtection(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled *bool `json:"enabled"`
		Minutes int   `json:"minutes"`
	}
	if !decode(w, r, &body) {
		return
	}
	fields := map[string]string{}
	if body.Enabled == nil {
		fields["enabled"] = "Bitte angeben, ob der Schutz an oder aus sein soll."
	}
	if body.Minutes < 0 || body.Minutes > maxPauseMinutes {
		fields["minutes"] = "Erlaubt sind 0 bis " + strconv.Itoa(maxPauseMinutes) + " Minuten."
	}
	if len(fields) > 0 {
		writeFields(w, fields)
		return
	}
	now := a.d.Now()
	err := a.d.UpdateSettings(func(s *config.Settings) error {
		switch {
		case *body.Enabled:
			s.ProtectionEnabled = true
			s.ProtectionPausedUntil = 0
		case body.Minutes > 0:
			s.ProtectionEnabled = false
			s.ProtectionPausedUntil = now.Add(time.Duration(body.Minutes) * time.Minute).UnixMilli()
		default:
			s.ProtectionEnabled = false
			s.ProtectionPausedUntil = 0
		}
		return nil
	})
	if err != nil {
		writeUpdateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, protectionOf(a.d.Settings(), now))
}

// maxPauseMinutes: a pause lasts at most one day.
const maxPauseMinutes = 1440

// --- Statistics ---------------------------------------------------------------

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	sum, err := a.d.Stats.Summary(hours, a.d.Now())
	if err != nil {
		internalError(w, r, err)
		return
	}
	if len(sum.TopClients) > 0 {
		m, err := a.clientMatcher()
		if err != nil {
			internalError(w, r, err)
			return
		}
		for i := range sum.TopClients {
			sum.TopClients[i].Name = a.displayName(m, sum.TopClients[i].IP)
		}
	}
	writeJSON(w, http.StatusOK, sum)
}

// displayName is the configured client name, else the reverse-DNS host name, else "".
func (a *API) displayName(m *clientMatcher, ip string) string {
	if c, ok := m.match(ip); ok {
		return c.Name
	}
	return a.hostname(ip)
}

func (a *API) hostname(ip string) string {
	if a.d.DNS == nil {
		return ""
	}
	return a.d.DNS.Hostname(ip)
}

func (a *API) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	if err := a.d.Stats.Reset(); err != nil {
		internalError(w, r, err)
		return
	}
	writeNoContent(w)
}

// --- Query log ----------------------------------------------------------------

var statusGroups = map[string][]string{
	"all":       nil,
	"":          nil,
	"blocked":   {"blocked", "blocked_service"},
	"allowed":   {"ok", "allowed"},
	"rewritten": {"rewrite", "safesearch"},
	"failed":    {"error", "refused"},
}

const (
	defaultLogLimit = 50
	maxLogLimit     = 500
)

type querylogJSON struct {
	Items      []store.Query `json:"items"`
	NextBefore int64         `json:"next_before"`
}

func (a *API) handleQuerylog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	statuses, ok := statusGroups[q.Get("status")]
	if !ok {
		writeFields(w, map[string]string{"status": "Unbekannter Filter. Erlaubt: all, blocked, allowed, rewritten, failed."})
		return
	}
	limit := defaultLogLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeFields(w, map[string]string{"limit": "Keine Zahl."})
			return
		}
		limit = min(max(n, 1), maxLogLimit)
	}
	var before int64
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeFields(w, map[string]string{"before": "Keine gültige ID."})
			return
		}
		before = n
	}
	if a.d.QueryLog != nil {
		a.d.QueryLog.Flush()
	}
	// One row more than the page: next_before is set only when another entry follows.
	items, err := a.d.Store.Queries(store.QueryFilter{
		Limit:    limit + 1,
		Before:   before,
		Search:   q.Get("search"),
		Client:   q.Get("client"),
		Statuses: statuses,
	})
	if err != nil {
		internalError(w, r, err)
		return
	}
	if items == nil {
		items = []store.Query{}
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	names, err := a.listNames()
	if err != nil {
		internalError(w, r, err)
		return
	}
	for i := range items {
		if items[i].ListID > 0 {
			items[i].ListName = names[items[i].ListID]
		}
	}
	out := querylogJSON{Items: items}
	if more {
		out.NextBefore = items[len(items)-1].ID
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleQuerylogClear(w http.ResponseWriter, r *http.Request) {
	if a.d.QueryLog != nil {
		a.d.QueryLog.Flush()
	}
	if err := a.d.Store.ClearQueries(); err != nil {
		internalError(w, r, err)
		return
	}
	writeNoContent(w)
}

// --- Cache ----------------------------------------------------------------------

func (a *API) handleCacheClear(w http.ResponseWriter, _ *http.Request) {
	if a.d.Cache != nil {
		a.d.Cache.Flush()
	}
	writeNoContent(w)
}
