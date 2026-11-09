package api

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/miekg/dns"

	"pk95dns/internal/filter"
	"pk95dns/internal/lists"
	"pk95dns/internal/store"
)

const (
	maxNameLen   = 80
	maxURLLen    = 2000
	maxRulesSize = 1 << 20
)

// listJSON is the list object of docs/api.md.
type listJSON struct {
	store.List
	Updating bool `json:"updating"`
}

func (a *API) listOut(l store.List) listJSON {
	return listJSON{List: l, Updating: a.d.Lists.Updating(l.ID)}
}

// pathID parses the {id} path value; 404 when it is not a positive integer.
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusNotFound, msgNotFound)
		return 0, false
	}
	return id, true
}

// listNames returns list id → name (cached until a list changes).
func (a *API) listNames() (map[int64]string, error) {
	a.namesMu.Lock()
	defer a.namesMu.Unlock()
	if a.names != nil {
		return a.names, nil
	}
	ls, err := a.d.Store.Lists()
	if err != nil {
		return nil, err
	}
	names := make(map[int64]string, len(ls))
	for _, l := range ls {
		names[l.ID] = l.Name
	}
	a.names = names
	return names, nil
}

func (a *API) forgetListNames() {
	a.namesMu.Lock()
	a.names = nil
	a.namesMu.Unlock()
}

func (a *API) handleLists(w http.ResponseWriter, r *http.Request) {
	ls, err := a.d.Store.Lists()
	if err != nil {
		internalError(w, r, err)
		return
	}
	out := make([]listJSON, 0, len(ls))
	for _, l := range ls {
		out = append(out, a.listOut(l))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, lists.Catalog())
}

type listBody struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Kind    string `json:"kind"`
	Enabled *bool  `json:"enabled"`
}

// validate normalizes b and returns the field errors.
func (b *listBody) validate() map[string]string {
	fields := map[string]string{}
	b.Name = strings.TrimSpace(b.Name)
	b.URL = strings.TrimSpace(b.URL)
	b.Kind = strings.TrimSpace(b.Kind)
	if n := utf8.RuneCountInString(b.Name); n == 0 {
		fields["name"] = "Bitte einen Namen angeben."
	} else if n > maxNameLen {
		fields["name"] = "Der Name darf höchstens 80 Zeichen lang sein."
	}
	switch {
	case b.URL == "":
		fields["url"] = "Bitte eine Adresse angeben."
	case len(b.URL) > maxURLLen:
		fields["url"] = "Die Adresse darf höchstens 2000 Zeichen lang sein."
	default:
		u, err := url.Parse(b.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			fields["url"] = "Bitte eine Adresse mit http:// oder https:// angeben."
		}
	}
	if b.Kind == "" {
		b.Kind = "block"
	}
	if b.Kind != "block" && b.Kind != "allow" {
		fields["kind"] = "Erlaubt sind block und allow."
	}
	return fields
}

const msgDuplicateURL = "Diese Liste ist schon eingetragen."

func (a *API) handleListCreate(w http.ResponseWriter, r *http.Request) {
	var b listBody
	if !decode(w, r, &b) {
		return
	}
	if fields := b.validate(); len(fields) > 0 {
		writeFields(w, fields)
		return
	}
	enabled := b.Enabled == nil || *b.Enabled
	l, err := a.d.Store.CreateList(store.List{Name: b.Name, URL: b.URL, Kind: b.Kind, Enabled: enabled})
	if errors.Is(err, store.ErrDuplicate) {
		writeFields(w, map[string]string{"url": msgDuplicateURL})
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	a.forgetListNames()
	if l.Enabled {
		a.d.Lists.Refresh(l.ID)
	}
	writeJSON(w, http.StatusCreated, a.listOut(l))
}

func (a *API) handleListUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b listBody
	if !decode(w, r, &b) {
		return
	}
	old, err := a.d.Store.GetList(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, msgNotFound)
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	if b.Kind == "" {
		b.Kind = old.Kind
	}
	if fields := b.validate(); len(fields) > 0 {
		writeFields(w, fields)
		return
	}
	l := old
	l.Name, l.URL, l.Kind = b.Name, b.URL, b.Kind
	if b.Enabled != nil {
		l.Enabled = *b.Enabled
	}
	err = a.d.Store.UpdateList(l)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, msgNotFound)
		return
	case errors.Is(err, store.ErrDuplicate):
		writeFields(w, map[string]string{"url": msgDuplicateURL})
		return
	case err != nil:
		internalError(w, r, err)
		return
	}
	a.forgetListNames()

	urlChanged := l.URL != old.URL
	switch {
	case urlChanged:
		// The local copy belongs to the old address.
		if err := a.d.Store.SetListStatus(id, 0, 0, "", "", ""); err != nil {
			internalError(w, r, err)
			return
		}
		if err := a.d.Lists.Forget(id); err != nil {
			internalError(w, r, err)
			return
		}
	case l.Enabled != old.Enabled || l.Kind != old.Kind:
		if err := a.d.Lists.Rebuild(); err != nil {
			internalError(w, r, err)
			return
		}
	}
	switch {
	case l.Enabled && urlChanged:
		// A download of the old address may be running: Reload fetches the new one after it.
		a.d.Lists.Reload(id)
	case l.Enabled && !old.Enabled:
		a.d.Lists.Refresh(id)
	}
	l, err = a.d.Store.GetList(id)
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.listOut(l))
}

func (a *API) handleListDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	err := a.d.Store.DeleteList(id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, msgNotFound)
		return
	}
	if err != nil {
		internalError(w, r, err)
		return
	}
	a.forgetListNames()
	if err := a.d.Lists.Forget(id); err != nil {
		internalError(w, r, err)
		return
	}
	writeNoContent(w)
}

func (a *API) handleListsRefresh(w http.ResponseWriter, _ *http.Request) {
	a.d.Lists.Refresh()
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

func (a *API) handleListRefresh(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := a.d.Store.GetList(id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, msgNotFound)
		return
	} else if err != nil {
		internalError(w, r, err)
		return
	}
	a.d.Lists.Refresh(id)
	writeJSON(w, http.StatusAccepted, map[string]bool{"ok": true})
}

// --- Custom rules ------------------------------------------------------------

type rulesOut struct {
	Text      string              `json:"text"`
	RuleCount int                 `json:"rule_count"`
	Invalid   []filter.ParseError `json:"invalid"`
}

func rulesResponse(text string) rulesOut {
	n, invalid := filter.ParseRules([]byte(text))
	if invalid == nil {
		invalid = []filter.ParseError{}
	}
	return rulesOut{Text: text, RuleCount: n, Invalid: invalid}
}

func (a *API) handleRules(w http.ResponseWriter, r *http.Request) {
	text, err := a.d.Store.CustomRules()
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rulesResponse(text))
}

// saveRules stores and activates the custom rules. Callers hold rulesMu.
func (a *API) saveRules(text string) error {
	if err := a.d.Store.SaveCustomRules(text); err != nil {
		return err
	}
	rs, st := filter.Compile([]filter.Source{{ID: 0, Data: []byte(text)}})
	a.d.Filter.SetCustom(rs)
	a.customN = st.Rules[0]
	return nil
}

func (a *API) handleRulesSave(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Text *string `json:"text"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.Text == nil {
		writeFields(w, map[string]string{"text": "Bitte den Regeltext angeben."})
		return
	}
	if len(*b.Text) > maxRulesSize {
		writeFields(w, map[string]string{"text": "Die Regeln dürfen höchstens 1 MiB groß sein."})
		return
	}
	a.rulesMu.Lock()
	defer a.rulesMu.Unlock()
	if err := a.saveRules(*b.Text); err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rulesResponse(*b.Text))
}

func (a *API) handleRulesQuick(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Domain string `json:"domain"`
		Action string `json:"action"`
	}
	if !decode(w, r, &b) {
		return
	}
	domain := filter.NormalizeName(strings.TrimSpace(b.Domain))
	fields := map[string]string{}
	if !filter.ValidDomain(domain, false) {
		fields["domain"] = "Bitte eine gültige Domain angeben (z. B. ads.example.com)."
	}
	var add string
	switch b.Action {
	case "block":
		add = "||" + domain + "^"
	case "allow":
		add = "@@||" + domain + "^"
	case "remove":
	default:
		fields["action"] = "Erlaubt sind block, allow und remove."
	}
	if len(fields) > 0 {
		writeFields(w, fields)
		return
	}
	a.rulesMu.Lock()
	defer a.rulesMu.Unlock()
	text, err := a.d.Store.CustomRules()
	if err != nil {
		internalError(w, r, err)
		return
	}
	text = quickEdit(text, domain, add)
	if len(text) > maxRulesSize {
		writeFields(w, map[string]string{"domain": "Die Regeln dürfen höchstens 1 MiB groß sein."})
		return
	}
	if err := a.saveRules(text); err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rulesResponse(text))
}

// quickEdit removes the block and allow rule of exactly domain from text and appends add
// ("" = only remove).
func quickEdit(text, domain, add string) string {
	blockRule, allowRule := "||"+domain+"^", "@@||"+domain+"^"
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == blockRule || t == allowRule {
			continue
		}
		out = append(out, line)
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	if add != "" {
		out = append(out, add)
	}
	return strings.Join(out, "\n")
}

// --- Check ----------------------------------------------------------------------

func (a *API) handleCheck(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name := filter.NormalizeName(strings.TrimSpace(q.Get("name")))
	fields := map[string]string{}
	if !filter.ValidDomain(name, false) {
		fields["name"] = "Bitte eine gültige Domain angeben (z. B. ads.example.com)."
	}
	typ := strings.ToUpper(strings.TrimSpace(q.Get("type")))
	if typ == "" {
		typ = "A"
	}
	qtype, ok := dns.StringToType[typ]
	if !ok {
		fields["type"] = "Unbekannter Abfragetyp."
	}
	client := strings.TrimSpace(q.Get("client"))
	if client != "" {
		if ip, err := netip.ParseAddr(client); err != nil || ip.Zone() != "" {
			fields["client"] = "Keine gültige IP-Adresse."
		} else {
			client = ip.Unmap().String()
		}
	}
	if len(fields) > 0 {
		writeFields(w, fields)
		return
	}
	if a.d.DNS == nil {
		writeError(w, http.StatusServiceUnavailable, "Der DNS-Server ist noch nicht bereit.")
		return
	}
	res := a.d.DNS.Check(name, qtype, client)
	if res.ListID > 0 {
		names, err := a.listNames()
		if err != nil {
			internalError(w, r, err)
			return
		}
		res.ListName = names[res.ListID]
	}
	writeJSON(w, http.StatusOK, res)
}
