package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"pk95dns/internal/config"
	"pk95dns/internal/geo"
)

// geoOut is the answer of GET/PUT /api/geo.
type geoOut struct {
	Mode           string   `json:"mode"`
	Countries      []string `json:"countries"`
	ResolveBlocked bool     `json:"resolve_blocked"`
	Available      bool     `json:"available"`
	DBDate         string   `json:"db_date"`
	Attribution    string   `json:"attribution"`
}

func (a *API) geoOut() geoOut {
	g := a.d.Settings().Geo
	countries := g.Countries
	if countries == nil {
		countries = []string{}
	}
	return geoOut{Mode: g.Mode, Countries: countries, ResolveBlocked: g.ResolveBlocked, Available: a.d.Geo.Available(),
		DBDate: a.d.Geo.Date(), Attribution: geo.Attribution}
}

func (a *API) handleGeo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.geoOut())
}

// handleGeoSave: PUT /api/geo {"mode", "countries"}. Codes are trimmed and upper-cased,
// duplicates removed; "allow" needs at least one country (it would block every country).
func (a *API) handleGeoSave(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Mode           *string         `json:"mode"`
		Countries      json.RawMessage `json:"countries"`
		ResolveBlocked json.RawMessage `json:"resolve_blocked"`
	}
	if !decode(w, r, &b) {
		return
	}
	cur := a.d.Settings().Geo
	g, fields := cleanGeo(b.Mode, b.Countries, cur)
	if len(b.ResolveBlocked) > 0 && string(b.ResolveBlocked) != "null" {
		if err := json.Unmarshal(b.ResolveBlocked, &g.ResolveBlocked); err != nil {
			fields["resolve_blocked"] = "true oder false erwartet."
		}
	}
	if len(fields) > 0 {
		writeFields(w, fields)
		return
	}
	if err := a.d.UpdateSettings(func(s *config.Settings) error {
		s.Geo = g
		return nil
	}); err != nil {
		writeUpdateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.geoOut())
}

// cleanGeo validates a geo setting; missing keys keep the current values.
func cleanGeo(mode *string, raw json.RawMessage, cur config.Geo) (config.Geo, map[string]string) {
	fields := map[string]string{}
	g := config.Geo{Mode: cur.Mode, Countries: append([]string{}, cur.Countries...), ResolveBlocked: cur.ResolveBlocked}
	if mode != nil {
		switch *mode {
		case config.GeoOff, config.GeoBlock, config.GeoAllow:
			g.Mode = *mode
		default:
			fields["mode"] = `Erlaubt sind "off", "block" und "allow".`
		}
	}
	if len(raw) > 0 && string(raw) != "null" {
		var list []json.RawMessage
		if err := json.Unmarshal(raw, &list); err != nil {
			fields["countries"] = "Eine Liste von Ländercodes erwartet."
			return g, fields
		}
		if len(list) > geo.MaxCountries {
			fields["countries"] = fmt.Sprintf("Höchstens %d Länder.", geo.MaxCountries)
			return g, fields
		}
		seen := map[string]bool{}
		g.Countries = []string{}
		for i, item := range list {
			var code string
			if err := json.Unmarshal(item, &code); err != nil {
				fields["countries."+strconv.Itoa(i)] = "Ländercode als Text erwartet."
				continue
			}
			code = strings.ToUpper(strings.TrimSpace(code))
			if !geo.Valid(code) {
				fields["countries."+strconv.Itoa(i)] = fmt.Sprintf("Unbekannter Ländercode: %q.", code)
				continue
			}
			if !seen[code] {
				seen[code] = true
				g.Countries = append(g.Countries, code)
			}
		}
	}
	if len(fields) == 0 && g.Mode == config.GeoAllow && len(g.Countries) == 0 {
		fields["countries"] = "Für „Nur erlauben“ mindestens ein Land wählen, sonst wäre jedes Land gesperrt."
	}
	return g, fields
}

// handleCountries: GET /api/countries?hours=24 – all countries of the period.
func (a *API) handleCountries(w http.ResponseWriter, r *http.Request) {
	hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
	out, err := a.d.Stats.Countries(hours, a.d.Now())
	if err != nil {
		internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
