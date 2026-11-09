package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"pk95dns/internal/records"
	"pk95dns/internal/store"
)

// Zones, records and the deprecated /api/rewrites view (docs/api.md → DNS zones and
// records). Every change reloads the DNS server (the records index is recompiled).

const (
	msgTTLRange      = "Die TTL muss zwischen 0 und 604800 Sekunden liegen."
	msgUint16Range   = "Bitte einen Wert zwischen 0 und 65535 angeben."
	msgPortRange     = "Bitte einen Port zwischen 1 und 65535 angeben."
	msgZoneIDFilter  = "Bitte eine gültige Zonen-ID angeben (0 = Einträge ohne Zone)."
	msgRewriteAnswer = "Bitte eine IP-Adresse oder einen Namen angeben."
)

// reload applies zones, records and clients to the DNS server.
func (a *API) reload(w http.ResponseWriter, r *http.Request) bool {
	if a.d.Reload == nil {
		return true
	}
	if err := a.d.Reload(); err != nil {
		writeUpdateError(w, r, err)
		return false
	}
	return true
}

// writeRecordStoreError answers an error of a zone or record write: 404, 422 on dupField
// for store.ErrDuplicate (message dupMsg), 422 for a *store.FieldError, else 500. It
// returns false when err is nil.
func writeRecordStoreError(w http.ResponseWriter, r *http.Request, err error, dupField, dupMsg string) bool {
	var fe *store.FieldError
	switch {
	case err == nil:
		return false
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, msgNotFound)
	case errors.Is(err, store.ErrDuplicate):
		writeFields(w, map[string]string{dupField: dupMsg})
	case errors.As(err, &fe):
		writeFields(w, map[string]string{fe.Field: fe.Message})
	default:
		internalError(w, r, err)
	}
	return true
}

// mergeFields adds the entries of extra to fields unless the key is already set.
func mergeFields(fields, extra map[string]string) map[string]string {
	if fields == nil {
		fields = map[string]string{}
	}
	for k, v := range extra {
		if _, ok := fields[k]; !ok {
			fields[k] = v
		}
	}
	return fields
}

// ttlOf checks a TTL from a request body (0–604800).
func ttlOf(v int64) (uint32, bool) {
	if v < 0 || v > records.MaxTTL {
		return 0, false
	}
	return uint32(v), true
}

// --- Zones ----------------------------------------------------------------------

// zoneBody is the request body of POST/PUT /api/zones. Missing fields keep their value
// (PUT) or default (POST: ttl 300, enabled true); id, serial, record_count and created_at
// are read-only and ignored.
type zoneBody struct {
	Name      *string `json:"name"`
	TTL       *int64  `json:"ttl"`
	PrimaryNS *string `json:"primary_ns"`
	Enabled   *bool   `json:"enabled"`
}

// apply copies the given fields into z and returns range errors.
func (b *zoneBody) apply(z *records.Zone) map[string]string {
	fields := map[string]string{}
	if b.Name != nil {
		z.Name = *b.Name
	}
	if b.TTL != nil {
		if ttl, ok := ttlOf(*b.TTL); ok {
			z.TTL = ttl
		} else {
			fields["ttl"] = msgTTLRange
		}
	}
	if b.PrimaryNS != nil {
		z.PrimaryNS = *b.PrimaryNS
	}
	if b.Enabled != nil {
		z.Enabled = *b.Enabled
	}
	return fields
}

func (a *API) handleZones(w http.ResponseWriter, r *http.Request) {
	zs, err := a.d.Store.Zones()
	if err != nil {
		internalError(w, r, err)
		return
	}
	if zs == nil {
		zs = []records.Zone{}
	}
	writeJSON(w, http.StatusOK, zs)
}

func (a *API) handleZoneCreate(w http.ResponseWriter, r *http.Request) {
	var b zoneBody
	if !decode(w, r, &b) {
		return
	}
	z := records.Zone{TTL: records.DefaultTTL, Enabled: true}
	out, ok := a.saveZone(w, r, &b, z, false)
	if !ok || !a.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (a *API) handleZoneUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b zoneBody
	if !decode(w, r, &b) {
		return
	}
	out, ok := a.saveZone(w, r, &b, records.Zone{ID: id}, true)
	if !ok || !a.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// saveZone validates b on top of z (update: the stored zone with z.ID) and creates or
// updates it. On failure it has answered.
func (a *API) saveZone(w http.ResponseWriter, r *http.Request, b *zoneBody, z records.Zone, update bool) (records.Zone, bool) {
	a.recordsMu.Lock()
	defer a.recordsMu.Unlock()
	if update {
		old, err := a.d.Store.GetZone(z.ID)
		if writeRecordStoreError(w, r, err, "name", records.MsgZoneDuplicate) {
			return records.Zone{}, false
		}
		z = old
	}
	rangeErr := b.apply(&z)
	existing, err := a.d.Store.Zones()
	if err != nil {
		internalError(w, r, err)
		return records.Zone{}, false
	}
	if fields := mergeFields(rangeErr, records.ValidateZone(&z, existing)); len(fields) > 0 {
		writeFields(w, fields)
		return records.Zone{}, false
	}
	var out records.Zone
	if update {
		out, err = a.d.Store.UpdateZone(z)
	} else {
		out, err = a.d.Store.CreateZone(z)
	}
	if writeRecordStoreError(w, r, err, "name", records.MsgZoneDuplicate) {
		return records.Zone{}, false
	}
	return out, true
}

func (a *API) handleZoneDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	a.recordsMu.Lock()
	err := a.d.Store.DeleteZone(id)
	a.recordsMu.Unlock()
	if writeRecordStoreError(w, r, err, "name", records.MsgZoneDuplicate) || !a.reload(w, r) {
		return
	}
	writeNoContent(w)
}

// --- Records --------------------------------------------------------------------

// recordBody is the request body of POST/PUT /api/records. Missing fields keep their value
// (PUT) or default (POST: ttl 300, enabled true, others empty); id, zone_id and created_at
// are read-only and ignored. Numbers are decoded as int64 so that negative or too large
// values get a field message instead of wrapping around.
type recordBody struct {
	Name      *string `json:"name"`
	Type      *string `json:"type"`
	Value     *string `json:"value"`
	TTL       *int64  `json:"ttl"`
	Priority  *int64  `json:"priority"`
	Weight    *int64  `json:"weight"`
	Port      *int64  `json:"port"`
	PTR       *bool   `json:"ptr"`
	Enabled   *bool   `json:"enabled"`
	ManagedBy *string `json:"managed_by"`
}

// apply copies the given fields into rec and returns range errors (priority, weight and
// port are checked later against the type, see rangeFields).
func (b *recordBody) apply(rec *records.Record) map[string]string {
	fields := map[string]string{}
	if b.Name != nil {
		rec.Name = *b.Name
	}
	if b.Type != nil {
		rec.Type = *b.Type
	}
	if b.Value != nil {
		rec.Value = *b.Value
	}
	if b.TTL != nil {
		if ttl, ok := ttlOf(*b.TTL); ok {
			rec.TTL = ttl
		} else {
			fields["ttl"] = msgTTLRange
		}
	}
	set16 := func(key string, v *int64, dst *uint16) {
		if v == nil {
			return
		}
		if *v < 0 || *v > 65535 {
			fields[key] = msgUint16Range
			return
		}
		*dst = uint16(*v)
	}
	set16("priority", b.Priority, &rec.Priority)
	set16("weight", b.Weight, &rec.Weight)
	set16("port", b.Port, &rec.Port)
	if b.PTR != nil {
		rec.PTR = *b.PTR
	}
	if b.Enabled != nil {
		rec.Enabled = *b.Enabled
	}
	if b.ManagedBy != nil {
		rec.ManagedBy = *b.ManagedBy
	}
	return fields
}

// rangeFields keeps the range errors that matter for the (normalised) type: priority for
// MX and SRV, weight and port for SRV (other types store them as 0).
func rangeFields(rangeErr map[string]string, typ string) map[string]string {
	out := map[string]string{}
	for k, v := range rangeErr {
		switch k {
		case "priority":
			if typ != records.TypeMX && typ != records.TypeSRV {
				continue
			}
		case "weight":
			if typ != records.TypeSRV {
				continue
			}
		case "port":
			if typ != records.TypeSRV {
				continue
			}
			v = msgPortRange
		}
		out[k] = v
	}
	return out
}

func (a *API) handleRecords(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var f store.RecordFilter
	if v := strings.TrimSpace(q.Get("zone_id")); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id < 0 {
			writeFields(w, map[string]string{"zone_id": msgZoneIDFilter})
			return
		}
		f.ZoneID = &id
	}
	f.Type = strings.TrimSpace(q.Get("type"))
	f.Name = strings.TrimSpace(q.Get("name"))
	f.Q = strings.TrimSpace(q.Get("q"))
	recs, err := a.d.Store.Records(f)
	if err != nil {
		internalError(w, r, err)
		return
	}
	if recs == nil {
		recs = []records.Record{}
	}
	writeJSON(w, http.StatusOK, recs)
}

func (a *API) handleRecordCreate(w http.ResponseWriter, r *http.Request) {
	var b recordBody
	if !decode(w, r, &b) {
		return
	}
	rec := records.Record{TTL: records.DefaultTTL, Enabled: true}
	out, fields, ok := a.saveRecord(w, r, rec, false, b.apply)
	if fields != nil {
		writeFields(w, fields)
		return
	}
	if !ok || !a.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (a *API) handleRecordUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b recordBody
	if !decode(w, r, &b) {
		return
	}
	out, fields, ok := a.saveRecord(w, r, records.Record{ID: id}, true, b.apply)
	if fields != nil {
		writeFields(w, fields)
		return
	}
	if !ok || !a.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// saveRecord applies a body to rec (update: the stored record with rec.ID, which must pass
// accept) and validates and stores it. It returns the stored record; or the validation
// fields (record field names, nothing written) together with the normalised record that
// failed; or ok false when it has answered (404, 500). Store duplicates are returned as
// fields too.
func (a *API) saveRecord(w http.ResponseWriter, r *http.Request, rec records.Record, update bool,
	apply func(*records.Record) map[string]string, accept ...func(records.Record) bool) (records.Record, map[string]string, bool) {
	a.recordsMu.Lock()
	defer a.recordsMu.Unlock()
	if update {
		old, err := a.d.Store.GetRecord(rec.ID)
		if err == nil {
			for _, ok := range accept {
				if !ok(old) {
					err = store.ErrNotFound
				}
			}
		}
		if writeRecordStoreError(w, r, err, "name", records.MsgRecordDuplicate) {
			return records.Record{}, nil, false
		}
		rec = old
	}
	rangeErr := apply(&rec)
	zones, err := a.d.Store.Zones()
	if err != nil {
		internalError(w, r, err)
		return records.Record{}, nil, false
	}
	others, err := a.d.Store.Records(store.RecordFilter{})
	if err != nil {
		internalError(w, r, err)
		return records.Record{}, nil, false
	}
	fields := records.ValidateRecord(&rec, zones, others)
	for k, v := range rangeFields(rangeErr, rec.Type) {
		fields[k] = v // the range message is more precise than "port missing"
	}
	if len(fields) > 0 {
		return rec, fields, false
	}
	var out records.Record
	if update {
		out, err = a.d.Store.UpdateRecord(rec)
	} else {
		out, err = a.d.Store.CreateRecord(rec)
	}
	if errors.Is(err, store.ErrDuplicate) {
		return rec, map[string]string{"name": records.MsgRecordDuplicate}, false
	}
	if writeRecordStoreError(w, r, err, "name", records.MsgRecordDuplicate) {
		return records.Record{}, nil, false
	}
	return out, nil, true
}

func (a *API) handleRecordDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	a.recordsMu.Lock()
	err := a.d.Store.DeleteRecord(id)
	a.recordsMu.Unlock()
	if writeRecordStoreError(w, r, err, "name", records.MsgRecordDuplicate) || !a.reload(w, r) {
		return
	}
	writeNoContent(w)
}

// --- /api/rewrites (deprecated view on A, AAAA and CNAME records) ------------------

type rewriteJSON struct {
	ID        int64  `json:"id"`
	Domain    string `json:"domain"`
	Answer    string `json:"answer"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
}

func rewriteOf(r records.Record) rewriteJSON {
	return rewriteJSON{ID: r.ID, Domain: r.Name, Answer: r.Value, Enabled: r.Enabled, CreatedAt: r.CreatedAt}
}

func isRewrite(r records.Record) bool { return records.IsRewriteType(r.Type) }

// rewriteBody is the request body of POST/PUT /api/rewrites. The record type follows the
// answer (IPv4 → A, IPv6 → AAAA, host name → CNAME).
type rewriteBody struct {
	Domain  *string `json:"domain"`
	Answer  *string `json:"answer"`
	Enabled *bool   `json:"enabled"`
}

func (b *rewriteBody) apply(rec *records.Record) map[string]string {
	if b.Domain != nil {
		rec.Name = *b.Domain
	}
	if b.Answer != nil {
		rec.Value = strings.TrimSpace(*b.Answer)
		rec.Type = records.TypeForAnswer(rec.Value)
	}
	if b.Enabled != nil {
		rec.Enabled = *b.Enabled
	}
	return nil
}

// rewriteFields maps record validation fields to the field names of /api/rewrites.
func rewriteFields(fields map[string]string, rec records.Record) map[string]string {
	out := records.RewriteFields(fields)
	if strings.TrimSpace(rec.Value) == "" {
		out["answer"] = msgRewriteAnswer
	}
	return out
}

func (a *API) handleRewrites(w http.ResponseWriter, r *http.Request) {
	recs, err := a.d.Store.Records(store.RecordFilter{})
	if err != nil {
		internalError(w, r, err)
		return
	}
	out := []rewriteJSON{}
	for _, rec := range recs {
		if isRewrite(rec) {
			out = append(out, rewriteOf(rec))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleRewriteCreate(w http.ResponseWriter, r *http.Request) {
	var b rewriteBody
	if !decode(w, r, &b) {
		return
	}
	rec := records.Record{TTL: records.RewriteTTL, Enabled: true, Type: records.TypeCNAME}
	out, fields, ok := a.saveRecord(w, r, rec, false, b.apply)
	if fields != nil {
		writeFields(w, rewriteFields(fields, out))
		return
	}
	if !ok || !a.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusCreated, rewriteOf(out))
}

func (a *API) handleRewriteUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b rewriteBody
	if !decode(w, r, &b) {
		return
	}
	out, fields, ok := a.saveRecord(w, r, records.Record{ID: id}, true, b.apply, isRewrite)
	if fields != nil {
		writeFields(w, rewriteFields(fields, out))
		return
	}
	if !ok || !a.reload(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, rewriteOf(out))
}

func (a *API) handleRewriteDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	a.recordsMu.Lock()
	rec, err := a.d.Store.GetRecord(id)
	if err == nil && !isRewrite(rec) {
		err = store.ErrNotFound
	}
	if err == nil {
		err = a.d.Store.DeleteRecord(id)
	}
	a.recordsMu.Unlock()
	if writeRecordStoreError(w, r, err, "domain", records.MsgRecordDuplicate) || !a.reload(w, r) {
		return
	}
	writeNoContent(w)
}
