package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"pk95dns/internal/records"
)

// FieldError is a rejected change that belongs to one request field; the API answers
// 422 {"fields": {Field: Message}}. Compare with errors.Is against the variables below or
// use errors.As to map any of them.
type FieldError struct {
	Field   string
	Message string
}

func (e *FieldError) Error() string { return e.Message }

var (
	// ErrZoneHasRecords: UpdateZone was asked to rename a zone that has records (renaming
	// moves nothing).
	ErrZoneHasRecords = &FieldError{Field: "name",
		Message: "Eine Zone mit Einträgen kann nicht umbenannt werden. Bitte eine neue Zone anlegen oder zuerst die Einträge löschen."}
	// ErrZoneApexCNAME: creating or renaming the zone would put an existing CNAME record at
	// its apex.
	ErrZoneApexCNAME = &FieldError{Field: "name",
		Message: "Für diesen Namen gibt es einen CNAME-Eintrag; am Zonen-Apex ist kein CNAME erlaubt."}
)

// RecordFilter selects records (all fields optional). ZoneID 0 = single records only.
// Type and Name are exact (case-insensitive); Q is a case-insensitive substring of name or
// value.
type RecordFilter struct {
	ZoneID *int64
	Type   string
	Name   string
	Q      string
}

const zoneColumns = `id, name, ttl, primary_ns, enabled, serial, created_at,
	(SELECT COUNT(*) FROM records r WHERE r.zone_id = zones.id)`

const recordColumns = `id, zone_id, name, type, value, ttl, priority, weight, port, ptr, enabled, managed_by, created_at`

// querier is *sql.DB or *sql.Tx.
type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func scanZone(sc scanner) (records.Zone, error) {
	var z records.Zone
	err := sc.Scan(&z.ID, &z.Name, &z.TTL, &z.PrimaryNS, &z.Enabled, &z.Serial, &z.CreatedAt, &z.RecordCount)
	return z, err
}

func scanRecord(sc scanner) (records.Record, error) {
	var r records.Record
	err := sc.Scan(&r.ID, &r.ZoneID, &r.Name, &r.Type, &r.Value, &r.TTL, &r.Priority, &r.Weight, &r.Port,
		&r.PTR, &r.Enabled, &r.ManagedBy, &r.CreatedAt)
	return r, err
}

// serialNow is the time used for zone serials (the date part of YYYYMMDDnn, local time).
func serialNow() time.Time { return time.UnixMilli(nowMS()) }

// Zones returns all zones ordered by name, with RecordCount.
func (s *Store) Zones() ([]records.Zone, error) { return zones(s.DB) }

func zones(q querier) ([]records.Zone, error) {
	rows, err := q.Query(`SELECT ` + zoneColumns + ` FROM zones ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []records.Zone{}
	for rows.Next() {
		z, err := scanZone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// GetZone returns one zone (with RecordCount) or ErrNotFound.
func (s *Store) GetZone(id int64) (records.Zone, error) { return getZone(s.DB, id) }

func getZone(q querier, id int64) (records.Zone, error) {
	z, err := scanZone(q.QueryRow(`SELECT `+zoneColumns+` FROM zones WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return records.Zone{}, ErrNotFound
	}
	return z, err
}

// CreateZone inserts z (validated and normalised by records.ValidateZone) and returns it with
// ID, Serial (first of the day: YYYYMMDD01), CreatedAt and RecordCount. Existing records
// whose name now belongs to the new zone (single records, or records of a parent zone) move
// into it; the zones they leave get a new serial. ErrDuplicate when the name exists,
// ErrZoneApexCNAME when a CNAME record has the zone name.
func (s *Store) CreateZone(z records.Zone) (records.Zone, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return records.Zone{}, err
	}
	defer tx.Rollback()
	z.CreatedAt = nowMS()
	z.Serial = records.NextSerial(0, serialNow())
	res, err := tx.Exec(`INSERT INTO zones (name, ttl, primary_ns, enabled, serial, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		z.Name, z.TTL, z.PrimaryNS, boolInt(z.Enabled), z.Serial, z.CreatedAt)
	if err != nil {
		return records.Zone{}, mapErr(err)
	}
	if z.ID, err = res.LastInsertId(); err != nil {
		return records.Zone{}, err
	}
	if err := rederiveZones(tx, z.ID); err != nil {
		return records.Zone{}, err
	}
	out, err := getZone(tx, z.ID)
	if err != nil {
		return records.Zone{}, err
	}
	return out, tx.Commit()
}

// UpdateZone stores name, ttl, primary_ns and enabled of z (validated by
// records.ValidateZone) and bumps its serial; it returns the stored zone. A new name is only
// accepted while the zone has no records (ErrZoneHasRecords); records that then belong to
// the renamed zone move into it like in CreateZone. ErrNotFound, ErrDuplicate (name),
// ErrZoneApexCNAME.
func (s *Store) UpdateZone(z records.Zone) (records.Zone, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return records.Zone{}, err
	}
	defer tx.Rollback()
	old, err := getZone(tx, z.ID)
	if err != nil {
		return records.Zone{}, err
	}
	renamed := old.Name != z.Name
	if renamed && old.RecordCount > 0 {
		return records.Zone{}, ErrZoneHasRecords
	}
	if _, err := tx.Exec(`UPDATE zones SET name = ?, ttl = ?, primary_ns = ?, enabled = ?, serial = ? WHERE id = ?`,
		z.Name, z.TTL, z.PrimaryNS, boolInt(z.Enabled), records.NextSerial(old.Serial, serialNow()), z.ID); err != nil {
		return records.Zone{}, mapErr(err)
	}
	if renamed {
		if err := rederiveZones(tx, z.ID); err != nil {
			return records.Zone{}, err
		}
	}
	out, err := getZone(tx, z.ID)
	if err != nil {
		return records.Zone{}, err
	}
	return out, tx.Commit()
}

// DeleteZone removes the zone and its records. ErrNotFound.
func (s *Store) DeleteZone(id int64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM records WHERE zone_id = ?`, id); err != nil {
		return err
	}
	if err := affected(tx.Exec(`DELETE FROM zones WHERE id = ?`, id)); err != nil {
		return err
	}
	return tx.Commit()
}

// rederiveZones sets zone_id of every record to records.ZoneFor(name) after the zone set
// changed, bumps the serials of the zones records left or entered (except skip, whose
// serial was just set), and rejects a CNAME at a zone apex.
func rederiveZones(tx *sql.Tx, skip int64) error {
	zs, err := zones(tx)
	if err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT id, name, zone_id FROM records`)
	if err != nil {
		return err
	}
	type move struct{ id, zone int64 }
	var moves []move
	touched := map[int64]bool{}
	for rows.Next() {
		var id, zoneID int64
		var name string
		if err := rows.Scan(&id, &name, &zoneID); err != nil {
			rows.Close()
			return err
		}
		if want := records.ZoneFor(name, zs); want != zoneID {
			moves = append(moves, move{id, want})
			touched[zoneID], touched[want] = true, true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, m := range moves {
		if _, err := tx.Exec(`UPDATE records SET zone_id = ? WHERE id = ?`, m.zone, m.id); err != nil {
			return err
		}
	}
	delete(touched, skip)
	for id := range touched {
		if err := bumpSerials(tx, id); err != nil {
			return err
		}
	}
	var apex int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM records r JOIN zones z ON z.id = r.zone_id
		WHERE r.type = 'CNAME' AND r.name = z.name`).Scan(&apex); err != nil {
		return err
	}
	if apex > 0 {
		return ErrZoneApexCNAME
	}
	return nil
}

// bumpSerials gives each zone (0 and duplicates skipped) its next serial.
func bumpSerials(tx *sql.Tx, ids ...int64) error {
	done := map[int64]bool{0: true}
	for _, id := range ids {
		if done[id] {
			continue
		}
		done[id] = true
		var serial uint32
		err := tx.QueryRow(`SELECT serial FROM zones WHERE id = ?`, id).Scan(&serial)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE zones SET serial = ? WHERE id = ?`, records.NextSerial(serial, serialNow()), id); err != nil {
			return err
		}
	}
	return nil
}

// Records returns the records matching f ordered by name, type, priority, value.
func (s *Store) Records(f RecordFilter) ([]records.Record, error) {
	var where []string
	var args []any
	if f.ZoneID != nil {
		where = append(where, `zone_id = ?`)
		args = append(args, *f.ZoneID)
	}
	if f.Type != "" {
		where = append(where, `type = ?`)
		args = append(args, strings.ToUpper(strings.TrimSpace(f.Type)))
	}
	if f.Name != "" {
		where = append(where, `name = ?`)
		args = append(args, records.NormalizeName(f.Name))
	}
	if f.Q != "" {
		like := "%" + escapeLike(strings.ToLower(f.Q)) + "%"
		where = append(where, `(lower(name) LIKE ? ESCAPE '\' OR lower(value) LIKE ? ESCAPE '\')`)
		args = append(args, like, like)
	}
	q := `SELECT ` + recordColumns + ` FROM records`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, ` AND `)
	}
	q += ` ORDER BY name, type, priority, value, id`
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []records.Record{}
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRecord returns one record or ErrNotFound.
func (s *Store) GetRecord(id int64) (records.Record, error) { return getRecord(s.DB, id) }

func getRecord(q querier, id int64) (records.Record, error) {
	r, err := scanRecord(q.QueryRow(`SELECT `+recordColumns+` FROM records WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return records.Record{}, ErrNotFound
	}
	return r, err
}

// CreateRecord inserts r (validated and normalised by records.ValidateRecord; ID and
// CreatedAt are set here, ZoneID is derived from the name again inside the transaction)
// and bumps the serial of its zone. ErrDuplicate for the same name, type, value, priority,
// weight and port.
func (s *Store) CreateRecord(r records.Record) (records.Record, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return records.Record{}, err
	}
	defer tx.Rollback()
	zs, err := zones(tx)
	if err != nil {
		return records.Record{}, err
	}
	r.ZoneID = records.ZoneFor(r.Name, zs)
	r.CreatedAt = nowMS()
	res, err := tx.Exec(`INSERT INTO records (zone_id, name, type, value, ttl, priority, weight, port, ptr, enabled,
		managed_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ZoneID, r.Name, r.Type, r.Value, r.TTL, r.Priority, r.Weight, r.Port, boolInt(r.PTR), boolInt(r.Enabled),
		r.ManagedBy, r.CreatedAt)
	if err != nil {
		return records.Record{}, mapErr(err)
	}
	if r.ID, err = res.LastInsertId(); err != nil {
		return records.Record{}, err
	}
	if err := bumpSerials(tx, r.ZoneID); err != nil {
		return records.Record{}, err
	}
	return r, tx.Commit()
}

// UpdateRecord stores all fields of r except CreatedAt (ZoneID derived from the name) and
// returns the stored record. The serials of the old and the new zone are bumped (a record
// can move between zones by its name). ErrNotFound / ErrDuplicate.
func (s *Store) UpdateRecord(r records.Record) (records.Record, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return records.Record{}, err
	}
	defer tx.Rollback()
	old, err := getRecord(tx, r.ID)
	if err != nil {
		return records.Record{}, err
	}
	zs, err := zones(tx)
	if err != nil {
		return records.Record{}, err
	}
	r.ZoneID = records.ZoneFor(r.Name, zs)
	r.CreatedAt = old.CreatedAt
	if _, err := tx.Exec(`UPDATE records SET zone_id = ?, name = ?, type = ?, value = ?, ttl = ?, priority = ?,
		weight = ?, port = ?, ptr = ?, enabled = ?, managed_by = ? WHERE id = ?`,
		r.ZoneID, r.Name, r.Type, r.Value, r.TTL, r.Priority, r.Weight, r.Port, boolInt(r.PTR), boolInt(r.Enabled),
		r.ManagedBy, r.ID); err != nil {
		return records.Record{}, mapErr(err)
	}
	if err := bumpSerials(tx, old.ZoneID, r.ZoneID); err != nil {
		return records.Record{}, err
	}
	return r, tx.Commit()
}

// DeleteRecord removes a record and bumps the serial of its zone. ErrNotFound.
func (s *Store) DeleteRecord(id int64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	old, err := getRecord(tx, id)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM records WHERE id = ?`, id); err != nil {
		return err
	}
	if err := bumpSerials(tx, old.ZoneID); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordCounts returns the number of records per zone id (0 = single records); zones
// without records are missing.
func (s *Store) RecordCounts() (map[int64]int, error) {
	rows, err := s.DB.Query(`SELECT zone_id, COUNT(*) FROM records GROUP BY zone_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
