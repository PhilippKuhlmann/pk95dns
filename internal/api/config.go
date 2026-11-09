package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"pk95dns/internal/config"
	"pk95dns/internal/filter"
	"pk95dns/internal/store"
	"pk95dns/internal/upstream"
)

// --- Blocked services ------------------------------------------------------------

type servicesJSON struct {
	Services []filter.Service `json:"services"`
	Blocked  []string         `json:"blocked"`
}

func (a *API) servicesOut() servicesJSON {
	blocked := a.d.Settings().BlockedServices
	if blocked == nil {
		blocked = []string{}
	}
	return servicesJSON{Services: filter.Services(), Blocked: blocked}
}

func (a *API) handleServices(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.servicesOut())
}

// cleanServices dedupes ids and reports the unknown ones.
func cleanServices(ids []string) ([]string, string) {
	out := []string{}
	seen := map[string]bool{}
	var unknown []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if seen[id] {
			continue
		}
		seen[id] = true
		if !filter.KnownService(id) {
			unknown = append(unknown, id)
			continue
		}
		out = append(out, id)
	}
	if len(unknown) > 0 {
		return nil, "Unbekannte Dienste: " + strings.Join(unknown, ", ")
	}
	return out, ""
}

func (a *API) handleServicesSave(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Blocked []string `json:"blocked"`
	}
	if !decode(w, r, &b) {
		return
	}
	ids, msg := cleanServices(b.Blocked)
	if msg != "" {
		writeFields(w, map[string]string{"blocked": msg})
		return
	}
	err := a.d.UpdateSettings(func(s *config.Settings) error {
		s.BlockedServices = ids
		return nil
	})
	if err != nil {
		writeUpdateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.servicesOut())
}

// --- Clients -----------------------------------------------------------------------

const maxClientIDs = 50

// clientMatcher finds the most specific configured client of an IP (single IP before the
// narrowest CIDR).
type clientMatcher struct {
	clients  []store.Client
	ips      map[netip.Addr]int
	prefixes []prefixRef
}

type prefixRef struct {
	p netip.Prefix
	i int
}

func newClientMatcher(clients []store.Client) *clientMatcher {
	m := &clientMatcher{clients: clients, ips: map[netip.Addr]int{}}
	for i, c := range clients {
		for _, id := range c.IDs {
			if ip, err := netip.ParseAddr(id); err == nil {
				m.ips[ip.Unmap()] = i
			} else if p, err := netip.ParsePrefix(id); err == nil {
				m.prefixes = append(m.prefixes, prefixRef{p: p.Masked(), i: i})
			}
		}
	}
	return m
}

func (m *clientMatcher) match(ipStr string) (store.Client, bool) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return store.Client{}, false
	}
	ip = ip.Unmap().WithZone("")
	if i, ok := m.ips[ip]; ok {
		return m.clients[i], true
	}
	best := -1
	bits := -1
	for _, pr := range m.prefixes {
		if pr.p.Contains(ip) && pr.p.Bits() > bits {
			best, bits = pr.i, pr.p.Bits()
		}
	}
	if best < 0 {
		return store.Client{}, false
	}
	return m.clients[best], true
}

func (a *API) clientMatcher() (*clientMatcher, error) {
	cs, err := a.d.Store.Clients()
	if err != nil {
		return nil, err
	}
	return newClientMatcher(cs), nil
}

type recentClient struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	ClientID int64  `json:"client_id"`
	Name     string `json:"name"`
	Queries  int64  `json:"queries"`
	Blocked  int64  `json:"blocked"`
	LastSeen int64  `json:"last_seen"`
}

type clientsJSON struct {
	Clients []store.Client `json:"clients"`
	Recent  []recentClient `json:"recent"`
}

func (a *API) handleClients(w http.ResponseWriter, r *http.Request) {
	cs, err := a.d.Store.Clients()
	if err != nil {
		internalError(w, r, err)
		return
	}
	if cs == nil {
		cs = []store.Client{}
	}
	out := clientsJSON{Clients: cs, Recent: []recentClient{}}
	if a.d.Stats != nil {
		recent, err := a.d.Stats.RecentClients(a.d.Now().Add(-24*time.Hour), 100)
		if err != nil {
			internalError(w, r, err)
			return
		}
		m := newClientMatcher(cs)
		for _, rc := range recent {
			item := recentClient{IP: rc.IP, Hostname: a.hostname(rc.IP), Queries: rc.Count, Blocked: rc.Blocked, LastSeen: rc.LastSeen}
			if c, ok := m.match(rc.IP); ok {
				item.ClientID, item.Name = c.ID, c.Name
			}
			out.Recent = append(out.Recent, item)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type clientBody struct {
	Name              string          `json:"name"`
	IDs               []string        `json:"ids"`
	UseGlobalSettings *bool           `json:"use_global_settings"`
	FilteringEnabled  *bool           `json:"filtering_enabled"`
	SafeSearch        json.RawMessage `json:"safesearch"`
	UseGlobalServices *bool           `json:"use_global_services"`
	BlockedServices   []string        `json:"blocked_services"`
}

// apply validates b against the other clients and merges it into c (the existing client,
// or the defaults for a new one).
func (b *clientBody) apply(c *store.Client, others []store.Client) map[string]string {
	fields := map[string]string{}
	c.Name = strings.TrimSpace(b.Name)
	if n := utf8.RuneCountInString(c.Name); n == 0 {
		fields["name"] = "Bitte einen Namen angeben."
	} else if n > maxNameLen {
		fields["name"] = "Der Name darf höchstens 80 Zeichen lang sein."
	} else {
		for _, o := range others {
			if strings.EqualFold(o.Name, c.Name) {
				fields["name"] = msgDuplicateClient
			}
		}
	}

	used := map[string]string{}
	for _, o := range others {
		for _, id := range o.IDs {
			used[canonicalClientID(id)] = o.Name
		}
	}
	switch {
	case len(b.IDs) == 0:
		fields["ids"] = "Bitte mindestens eine IP-Adresse oder ein Netz angeben."
	case len(b.IDs) > maxClientIDs:
		fields["ids"] = fmt.Sprintf("Höchstens %d Einträge sind erlaubt.", maxClientIDs)
	default:
		ids := make([]string, 0, len(b.IDs))
		seen := map[string]bool{}
		for i, raw := range b.IDs {
			key := "ids." + strconv.Itoa(i)
			id := canonicalClientID(strings.TrimSpace(raw))
			switch {
			case id == "":
				fields[key] = "Keine gültige IP-Adresse oder kein gültiges Netz (CIDR): " + raw
			case seen[id]:
				fields[key] = "Dieser Eintrag ist doppelt."
			case used[id] != "":
				fields[key] = "Wird schon vom Client „" + used[id] + "“ verwendet."
			}
			seen[id] = true
			ids = append(ids, id)
		}
		c.IDs = ids
	}

	if b.UseGlobalSettings != nil {
		c.UseGlobalSettings = *b.UseGlobalSettings
	}
	if b.FilteringEnabled != nil {
		c.FilteringEnabled = *b.FilteringEnabled
	}
	if len(b.SafeSearch) > 0 && string(b.SafeSearch) != "null" {
		ss := c.SafeSearch
		if err := json.Unmarshal(b.SafeSearch, &ss); err != nil {
			fields["safesearch"] = "Ungültige Angaben zu SafeSearch."
		} else {
			c.SafeSearch = ss
		}
	}
	if b.UseGlobalServices != nil {
		c.UseGlobalServices = *b.UseGlobalServices
	}
	if b.BlockedServices != nil {
		ids, msg := cleanServices(b.BlockedServices)
		if msg != "" {
			fields["blocked_services"] = msg
		} else {
			c.BlockedServices = ids
		}
	}
	if c.BlockedServices == nil {
		c.BlockedServices = []string{}
	}
	return fields
}

const msgDuplicateClient = "Ein Client mit diesem Namen existiert schon."

// canonicalClientID returns the canonical form of an IP or CIDR, "" when invalid.
func canonicalClientID(s string) string {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return ""
		}
		return p.Masked().String()
	}
	ip, err := netip.ParseAddr(s)
	if err != nil || ip.Zone() != "" {
		return ""
	}
	return ip.Unmap().String()
}

func otherClients(all []store.Client, id int64) []store.Client {
	out := make([]store.Client, 0, len(all))
	for _, c := range all {
		if c.ID != id {
			out = append(out, c)
		}
	}
	return out
}

func (a *API) handleClientCreate(w http.ResponseWriter, r *http.Request) {
	var b clientBody
	if !decode(w, r, &b) {
		return
	}
	all, err := a.d.Store.Clients()
	if err != nil {
		internalError(w, r, err)
		return
	}
	c := store.Client{
		UseGlobalSettings: true,
		FilteringEnabled:  true,
		SafeSearch:        config.Defaults().SafeSearch,
		UseGlobalServices: true,
		BlockedServices:   []string{},
	}
	if fields := b.apply(&c, all); len(fields) > 0 {
		writeFields(w, fields)
		return
	}
	c, err = a.d.Store.CreateClient(c)
	if errors.Is(err, store.ErrDuplicate) {
		writeFields(w, map[string]string{"name": msgDuplicateClient})
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	if !a.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (a *API) handleClientUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b clientBody
	if !decode(w, r, &b) {
		return
	}
	c, err := a.d.Store.GetClient(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, msgNotFound)
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	all, err := a.d.Store.Clients()
	if err != nil {
		internalError(w, r, err)
		return
	}
	if fields := b.apply(&c, otherClients(all, id)); len(fields) > 0 {
		writeFields(w, fields)
		return
	}
	err = a.d.Store.UpdateClient(c)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, msgNotFound)
		return
	case errors.Is(err, store.ErrDuplicate):
		writeFields(w, map[string]string{"name": msgDuplicateClient})
		return
	case err != nil:
		internalError(w, r, err)
		return
	}
	if !a.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (a *API) handleClientDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	err := a.d.Store.DeleteClient(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, msgNotFound)
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	if !a.reload(w, r) {
		return
	}
	writeNoContent(w)
}

// --- Settings ------------------------------------------------------------------------

func (a *API) handleSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.d.Settings().Normalized())
}

func (a *API) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r)
	if !ok {
		return
	}
	trimmed := bytes.TrimSpace(body)
	if !json.Valid(trimmed) || len(trimmed) == 0 || trimmed[0] != '{' {
		writeError(w, http.StatusBadRequest, msgBadJSON+" Erwartet wird ein Objekt mit Einstellungen.")
		return
	}
	err := a.d.UpdateSettings(func(s *config.Settings) error {
		merged, err := config.Merge(*s, trimmed)
		if err != nil {
			var te *json.UnmarshalTypeError
			var probe config.Settings
			if errors.As(json.Unmarshal(trimmed, &probe), &te) && te.Field != "" {
				return &validationError{fields: map[string]string{te.Field: "Falscher Datentyp."}}
			}
			return &InvalidError{Msg: err.Error()}
		}
		if fields := merged.Validate(); len(fields) > 0 {
			return &validationError{fields: fields}
		}
		*s = merged
		return nil
	})
	if err != nil {
		writeUpdateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.d.Settings().Normalized())
}

// --- Upstream test -----------------------------------------------------------------------

const (
	maxTestTargets = 20
	maxTestBoot    = 10
)

// Upstream test timeouts (variables for tests).
var (
	testTimeout    = 4 * time.Second
	testAllTimeout = 6 * time.Second
)

type upstreamResult struct {
	Upstream string  `json:"upstream"`
	OK       bool    `json:"ok"`
	MS       float64 `json:"ms"`
	Error    string  `json:"error"`
}

// testUpstream is upstream.Test (replaced in tests).
var testUpstream = upstream.Test

func (a *API) handleUpstreamsTest(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Upstreams []string `json:"upstreams"`
		Bootstrap []string `json:"bootstrap"`
	}
	if !decode(w, r, &b) {
		return
	}
	fields := map[string]string{}
	if len(b.Upstreams) == 0 {
		fields["upstreams"] = "Mindestens ein Upstream ist nötig."
	} else if len(b.Upstreams) > maxTestTargets {
		fields["upstreams"] = fmt.Sprintf("Höchstens %d Einträge sind erlaubt.", maxTestTargets)
	}
	if len(b.Bootstrap) > maxTestBoot {
		fields["bootstrap"] = fmt.Sprintf("Höchstens %d Einträge sind erlaubt.", maxTestBoot)
	}
	if len(fields) > 0 {
		writeFields(w, fields)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), testAllTimeout)
	defer cancel()
	test := testUpstream
	results := make([]upstreamResult, len(b.Upstreams))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, addr := range b.Upstreams {
		results[i] = upstreamResult{Upstream: addr, Error: "Keine Antwort innerhalb von 6 Sekunden."}
		wg.Add(1)
		go func() {
			defer wg.Done()
			tctx, tcancel := context.WithTimeout(ctx, testTimeout)
			defer tcancel()
			rtt, err := test(tctx, strings.TrimSpace(addr), b.Bootstrap, testTimeout)
			res := upstreamResult{Upstream: addr, OK: err == nil}
			if err != nil {
				res.Error = err.Error()
			} else {
				res.MS = math.Round(float64(rtt.Microseconds())/100) / 10
			}
			mu.Lock()
			results[i] = res
			mu.Unlock()
		}()
	}
	finished := make(chan struct{})
	go func() { wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
	}
	mu.Lock()
	out := append([]upstreamResult(nil), results...)
	mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}
