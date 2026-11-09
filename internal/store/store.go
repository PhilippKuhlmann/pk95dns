// Package store is the SQLite storage of PK95 DNS (modernc.org/sqlite, WAL, busy_timeout):
// settings, lists, custom rules, DNS zones and records, clients, users, sessions, query log
// and statistics (docs/design.md → Storage). Times are unix milliseconds unless noted.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"pk95dns/internal/config"
)

var (
	ErrNotFound  = errors.New("nicht gefunden")
	ErrDuplicate = errors.New("existiert bereits")
)

// Store wraps the database. Safe for concurrent use.
type Store struct {
	DB *sql.DB
}

// nowMS is the clock for created_at values (replaced in tests).
var nowMS = func() int64 { return time.Now().UnixMilli() }

// Settings keys.
const (
	keySettings        = "settings"
	keyBlockedServices = "blocked_services"
	keyProtection      = "protection"
)

type protectionJSON struct {
	Enabled     bool  `json:"enabled"`
	PausedUntil int64 `json:"paused_until"`
}

// LoadSettings returns the stored settings; keys that were never stored have their default
// (config.Defaults), so new settings fields work with old databases. Includes the json:"-"
// fields (blocked services, protection), which are stored separately.
func (s *Store) LoadSettings() (config.Settings, error) {
	st := config.Defaults()
	rows, err := s.DB.Query(`SELECT key, value FROM settings WHERE key IN (?, ?, ?)`,
		keySettings, keyBlockedServices, keyProtection)
	if err != nil {
		return config.Settings{}, err
	}
	defer rows.Close()
	values := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return config.Settings{}, err
		}
		values[k] = v
	}
	if err := rows.Err(); err != nil {
		return config.Settings{}, err
	}
	if v, ok := values[keySettings]; ok {
		if err := json.Unmarshal([]byte(v), &st); err != nil {
			return config.Settings{}, fmt.Errorf("Gespeicherte Einstellungen sind ungültig: %w", err)
		}
	}
	if v, ok := values[keyBlockedServices]; ok {
		var bs []string
		if err := json.Unmarshal([]byte(v), &bs); err != nil {
			return config.Settings{}, fmt.Errorf("Gespeicherte Dienste sind ungültig: %w", err)
		}
		st.BlockedServices = bs
	}
	if v, ok := values[keyProtection]; ok {
		p := protectionJSON{Enabled: st.ProtectionEnabled, PausedUntil: st.ProtectionPausedUntil}
		if err := json.Unmarshal([]byte(v), &p); err != nil {
			return config.Settings{}, fmt.Errorf("Gespeicherter Schutzstatus ist ungültig: %w", err)
		}
		st.ProtectionEnabled = p.Enabled
		st.ProtectionPausedUntil = p.PausedUntil
	}
	return st.Normalized(), nil
}

// SaveSettings stores all settings including the json:"-" fields.
func (s *Store) SaveSettings(st config.Settings) error {
	st = st.Normalized()
	pub, err := json.Marshal(st)
	if err != nil {
		return err
	}
	bs, err := json.Marshal(st.BlockedServices)
	if err != nil {
		return err
	}
	prot, err := json.Marshal(protectionJSON{Enabled: st.ProtectionEnabled, PausedUntil: st.ProtectionPausedUntil})
	if err != nil {
		return err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, kv := range [][2]string{{keySettings, string(pub)}, {keyBlockedServices, string(bs)}, {keyProtection, string(prot)}} {
		if _, err := tx.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value`, kv[0], kv[1]); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// List is a block or allow list.
type List struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	URL          string `json:"url"`
	Kind         string `json:"kind"` // "block" or "allow"
	Enabled      bool   `json:"enabled"`
	RuleCount    int    `json:"rule_count"`
	UpdatedAt    int64  `json:"updated_at"`
	LastError    string `json:"last_error"`
	ETag         string `json:"-"`
	LastModified string `json:"-"`
	CreatedAt    int64  `json:"-"`
}

const listColumns = `id, name, url, kind, enabled, rule_count, updated_at, last_error, etag, last_modified, created_at`

type scanner interface{ Scan(dest ...any) error }

func scanList(sc scanner) (List, error) {
	var l List
	err := sc.Scan(&l.ID, &l.Name, &l.URL, &l.Kind, &l.Enabled, &l.RuleCount, &l.UpdatedAt,
		&l.LastError, &l.ETag, &l.LastModified, &l.CreatedAt)
	return l, err
}

// Lists returns all lists ordered by kind ("block" first), then name (case-insensitive).
func (s *Store) Lists() ([]List, error) {
	rows, err := s.DB.Query(`SELECT ` + listColumns + ` FROM lists
		ORDER BY CASE kind WHEN 'block' THEN 0 ELSE 1 END, kind, name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []List{}
	for rows.Next() {
		l, err := scanList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// GetList returns one list or ErrNotFound.
func (s *Store) GetList(id int64) (List, error) {
	l, err := scanList(s.DB.QueryRow(`SELECT `+listColumns+` FROM lists WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return List{}, ErrNotFound
	}
	return l, err
}

// CreateList inserts l (ID, CreatedAt set). ErrDuplicate when the URL exists.
func (s *Store) CreateList(l List) (List, error) {
	l.CreatedAt = nowMS()
	res, err := s.DB.Exec(`INSERT INTO lists (name, url, kind, enabled, rule_count, updated_at, last_error, etag, last_modified, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.Name, l.URL, l.Kind, boolInt(l.Enabled), l.RuleCount, l.UpdatedAt, l.LastError, l.ETag, l.LastModified, l.CreatedAt)
	if err != nil {
		return List{}, mapErr(err)
	}
	l.ID, err = res.LastInsertId()
	return l, err
}

// UpdateList stores name, url, kind, enabled. ErrNotFound / ErrDuplicate (URL).
func (s *Store) UpdateList(l List) error {
	return affected(s.DB.Exec(`UPDATE lists SET name = ?, url = ?, kind = ?, enabled = ? WHERE id = ?`,
		l.Name, l.URL, l.Kind, boolInt(l.Enabled), l.ID))
}

// DeleteList removes a list. ErrNotFound.
func (s *Store) DeleteList(id int64) error {
	return affected(s.DB.Exec(`DELETE FROM lists WHERE id = ?`, id))
}

// SetListStatus stores the result of a download. updatedAt 0 keeps the old value (failed
// download); etag/lastModified "" keep the old values only when updatedAt is 0.
// ruleCount and lastError are always stored. ErrNotFound when the list does not exist.
func (s *Store) SetListStatus(id int64, ruleCount int, updatedAt int64, lastError, etag, lastModified string) error {
	if updatedAt != 0 {
		return affected(s.DB.Exec(`UPDATE lists SET rule_count = ?, updated_at = ?, last_error = ?, etag = ?,
			last_modified = ? WHERE id = ?`, ruleCount, updatedAt, lastError, etag, lastModified, id))
	}
	return affected(s.DB.Exec(`UPDATE lists SET rule_count = ?, last_error = ?,
		etag = COALESCE(NULLIF(?, ''), etag), last_modified = COALESCE(NULLIF(?, ''), last_modified)
		WHERE id = ?`, ruleCount, lastError, etag, lastModified, id))
}

// CustomRules returns the custom rules text ("" when never saved).
func (s *Store) CustomRules() (string, error) {
	var text string
	err := s.DB.QueryRow(`SELECT text FROM custom_rules WHERE id = 1`).Scan(&text)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return text, err
}

// SaveCustomRules replaces the custom rules text.
func (s *Store) SaveCustomRules(text string) error {
	_, err := s.DB.Exec(`INSERT INTO custom_rules (id, text, updated_at) VALUES (1, ?, ?)
		ON CONFLICT (id) DO UPDATE SET text = excluded.text, updated_at = excluded.updated_at`, text, nowMS())
	return err
}

// Client is a configured client.
type Client struct {
	ID                int64             `json:"id"`
	Name              string            `json:"name"`
	IDs               []string          `json:"ids"`
	UseGlobalSettings bool              `json:"use_global_settings"`
	FilteringEnabled  bool              `json:"filtering_enabled"`
	SafeSearch        config.SafeSearch `json:"safesearch"`
	UseGlobalServices bool              `json:"use_global_services"`
	BlockedServices   []string          `json:"blocked_services"`
	CreatedAt         int64             `json:"created_at"`
}

const clientColumns = `id, name, ids, use_global_settings, filtering_enabled, safesearch, use_global_services, blocked_services, created_at`

func scanClient(sc scanner) (Client, error) {
	var c Client
	var ids, ss, bs string
	if err := sc.Scan(&c.ID, &c.Name, &ids, &c.UseGlobalSettings, &c.FilteringEnabled, &ss,
		&c.UseGlobalServices, &bs, &c.CreatedAt); err != nil {
		return Client{}, err
	}
	if err := json.Unmarshal([]byte(ids), &c.IDs); err != nil {
		return Client{}, fmt.Errorf("client %d: ids: %w", c.ID, err)
	}
	if err := json.Unmarshal([]byte(ss), &c.SafeSearch); err != nil {
		return Client{}, fmt.Errorf("client %d: safesearch: %w", c.ID, err)
	}
	if err := json.Unmarshal([]byte(bs), &c.BlockedServices); err != nil {
		return Client{}, fmt.Errorf("client %d: blocked_services: %w", c.ID, err)
	}
	c.IDs = nonNil(c.IDs)
	c.BlockedServices = nonNil(c.BlockedServices)
	return c, nil
}

// clientJSON encodes the JSON columns of c.
func clientJSON(c Client) (ids, ss, bs string, err error) {
	b1, err := json.Marshal(nonNil(c.IDs))
	if err != nil {
		return "", "", "", err
	}
	b2, err := json.Marshal(c.SafeSearch)
	if err != nil {
		return "", "", "", err
	}
	b3, err := json.Marshal(nonNil(c.BlockedServices))
	if err != nil {
		return "", "", "", err
	}
	return string(b1), string(b2), string(b3), nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Clients returns all clients ordered by name (case-insensitive). Slices are never nil.
func (s *Store) Clients() ([]Client, error) {
	rows, err := s.DB.Query(`SELECT ` + clientColumns + ` FROM clients ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetClient returns one client or ErrNotFound.
func (s *Store) GetClient(id int64) (Client, error) {
	c, err := scanClient(s.DB.QueryRow(`SELECT `+clientColumns+` FROM clients WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	return c, err
}

// CreateClient inserts c. ErrDuplicate when the name exists (case-insensitive).
func (s *Store) CreateClient(c Client) (Client, error) {
	ids, ss, bs, err := clientJSON(c)
	if err != nil {
		return Client{}, err
	}
	c.CreatedAt = nowMS()
	res, err := s.DB.Exec(`INSERT INTO clients (name, ids, use_global_settings, filtering_enabled, safesearch,
		use_global_services, blocked_services, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Name, ids, boolInt(c.UseGlobalSettings), boolInt(c.FilteringEnabled), ss,
		boolInt(c.UseGlobalServices), bs, c.CreatedAt)
	if err != nil {
		return Client{}, mapErr(err)
	}
	c.ID, err = res.LastInsertId()
	c.IDs = nonNil(c.IDs)
	c.BlockedServices = nonNil(c.BlockedServices)
	return c, err
}

// UpdateClient stores all fields except CreatedAt. ErrNotFound / ErrDuplicate.
func (s *Store) UpdateClient(c Client) error {
	ids, ss, bs, err := clientJSON(c)
	if err != nil {
		return err
	}
	return affected(s.DB.Exec(`UPDATE clients SET name = ?, ids = ?, use_global_settings = ?, filtering_enabled = ?,
		safesearch = ?, use_global_services = ?, blocked_services = ? WHERE id = ?`,
		c.Name, ids, boolInt(c.UseGlobalSettings), boolInt(c.FilteringEnabled), ss,
		boolInt(c.UseGlobalServices), bs, c.ID))
}

// DeleteClient removes a client. ErrNotFound.
func (s *Store) DeleteClient(id int64) error {
	return affected(s.DB.Exec(`DELETE FROM clients WHERE id = ?`, id))
}

// User is an account of the standalone web UI.
type User struct {
	ID           int64
	Username     string
	PasswordHash string // bcrypt
}

// UserCount returns the number of users.
func (s *Store) UserCount() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CreateUser inserts a user. ErrDuplicate.
func (s *Store) CreateUser(username, passwordHash string) (User, error) {
	res, err := s.DB.Exec(`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)`,
		username, passwordHash, nowMS())
	if err != nil {
		return User{}, mapErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, err
	}
	return User{ID: id, Username: username, PasswordHash: passwordHash}, nil
}

// UserByName returns the user (case-sensitive) or ErrNotFound.
func (s *Store) UserByName(username string) (User, error) {
	var u User
	err := s.DB.QueryRow(`SELECT id, username, password_hash FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &u.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// SetPasswordHash replaces the password hash. ErrNotFound for an unknown user.
func (s *Store) SetPasswordHash(userID int64, hash string) error {
	return affected(s.DB.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, userID))
}

// CreateSession stores a session by the SHA-256 hex hash of its token.
func (s *Store) CreateSession(tokenHash string, userID int64, expiresAt int64) error {
	_, err := s.DB.Exec(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		tokenHash, userID, expiresAt)
	return mapErr(err)
}

// SessionUser returns the user of a session that has not expired at now, or ErrNotFound.
func (s *Store) SessionUser(tokenHash string, now int64) (User, error) {
	var u User
	err := s.DB.QueryRow(`SELECT u.id, u.username, u.password_hash FROM sessions s
		JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, now).
		Scan(&u.ID, &u.Username, &u.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// DeleteUserSessions removes all sessions of a user except keepHash ("" = all).
func (s *Store) DeleteUserSessions(userID int64, keepHash string) error {
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?`, userID, keepHash)
	return err
}

// PruneSessions removes expired sessions.
func (s *Store) PruneSessions(now int64) error {
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE expires_at <= ?`, now)
	return err
}

// Query is one query log entry (docs/api.md → Query log). ListName is not stored; the API
// fills it from the list id.
type Query struct {
	ID         int64   `json:"id"`
	TS         int64   `json:"ts"`
	ClientIP   string  `json:"client_ip"`
	ClientName string  `json:"client_name"`
	Name       string  `json:"name"`
	QType      string  `json:"qtype"`
	Status     string  `json:"status"`
	Reason     string  `json:"reason"`
	Rule       string  `json:"rule"`
	ListID     int64   `json:"list_id"`
	ListName   string  `json:"list_name"`
	Service    string  `json:"service"`
	Upstream   string  `json:"upstream"`
	Rcode      string  `json:"rcode"`
	Answer     string  `json:"answer"`
	ElapsedMS  float64 `json:"elapsed_ms"`
	Cached     bool    `json:"cached"`
}

// QueryFilter for Queries. Statuses empty = all. Client matches client_ip or client_name
// exactly. Search is a case-insensitive substring of name (LIKE with escaped % and _).
type QueryFilter struct {
	Limit    int
	Before   int64
	Search   string
	Client   string
	Statuses []string
}

// Query log limits.
const (
	defaultQueryLimit = 50
	maxQueryLimit     = 500
	pruneChunk        = 5000
)

// InsertQueries writes a batch in one transaction.
func (s *Store) InsertQueries(qs []Query) error {
	if len(qs) == 0 {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO queries (ts, client_ip, client_name, name, qtype, status, reason, rule,
		list_id, service, upstream, rcode, answer, elapsed_ms, cached) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, q := range qs {
		if _, err := stmt.Exec(q.TS, q.ClientIP, q.ClientName, q.Name, q.QType, q.Status, q.Reason, q.Rule,
			q.ListID, q.Service, q.Upstream, q.Rcode, q.Answer, q.ElapsedMS, boolInt(q.Cached)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// escapeLike escapes the LIKE wildcards with backslash (used with ESCAPE '\').
func escapeLike(s string) string { return likeEscaper.Replace(s) }

// Queries returns entries newest first (id descending).
func (s *Store) Queries(f QueryFilter) ([]Query, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = defaultQueryLimit
	}
	// One row more than the largest page is allowed: callers fetch limit+1 rows to know
	// whether another page follows.
	if limit > maxQueryLimit+1 {
		limit = maxQueryLimit + 1
	}
	var where []string
	var args []any
	if f.Before > 0 {
		where = append(where, `id < ?`)
		args = append(args, f.Before)
	}
	if f.Search != "" {
		where = append(where, `lower(name) LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(strings.ToLower(f.Search))+"%")
	}
	if f.Client != "" {
		where = append(where, `(client_ip = ? OR client_name = ?)`)
		args = append(args, f.Client, f.Client)
	}
	if len(f.Statuses) > 0 {
		where = append(where, `status IN (?`+strings.Repeat(`, ?`, len(f.Statuses)-1)+`)`)
		for _, st := range f.Statuses {
			args = append(args, st)
		}
	}
	q := `SELECT id, ts, client_ip, client_name, name, qtype, status, reason, rule, list_id, service, upstream,
		rcode, answer, elapsed_ms, cached FROM queries`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, ` AND `)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Query{}
	for rows.Next() {
		var e Query
		if err := rows.Scan(&e.ID, &e.TS, &e.ClientIP, &e.ClientName, &e.Name, &e.QType, &e.Status, &e.Reason,
			&e.Rule, &e.ListID, &e.Service, &e.Upstream, &e.Rcode, &e.Answer, &e.ElapsedMS, &e.Cached); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ClearQueries empties the whole query log.
func (s *Store) ClearQueries() error {
	_, err := s.DB.Exec(`DELETE FROM queries`)
	return err
}

// PruneQueries removes entries with ts < before, in chunks; returns the number removed.
func (s *Store) PruneQueries(before int64) (int64, error) {
	var total int64
	for {
		res, err := s.DB.Exec(`DELETE FROM queries WHERE id IN (SELECT id FROM queries WHERE ts < ? LIMIT ?)`,
			before, pruneChunk)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
		if n < pruneChunk {
			return total, nil
		}
	}
}

// HourStats are the totals of one UTC hour. Hour is unix SECONDS of the hour start.
type HourStats struct {
	Hour       int64
	Queries    int64
	Blocked    int64
	Cached     int64
	SafeSearch int64
	Services   int64
	ElapsedMS  float64 // sum over all queries of the hour
}

// TopEntry is a counter of one key in one hour (stats_top). Kinds are chosen by the stats
// package ("domain", "blocked", "client", "client_blocked", "upstream").
type TopEntry struct {
	Kind  string
	Key   string
	Count int64
	Sum   float64 // e.g. summed response time for "upstream"
	Last  int64   // LoadTop only: latest hour (unix seconds) the key appeared in
}

// SaveHour replaces totals and top entries of h.Hour (idempotent, one transaction).
// Entries with the same kind and key in top are added up.
func (s *Store) SaveHour(h HourStats, top []TopEntry) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT OR REPLACE INTO stats_hours (hour, queries, blocked, cached, safesearch, services, elapsed_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, h.Hour, h.Queries, h.Blocked, h.Cached, h.SafeSearch, h.Services, h.ElapsedMS); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM stats_top WHERE hour = ?`, h.Hour); err != nil {
		return err
	}
	if len(top) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO stats_top (hour, kind, key, count, sum) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (hour, kind, key) DO UPDATE SET count = count + excluded.count, sum = sum + excluded.sum`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, t := range top {
			if _, err := stmt.Exec(h.Hour, t.Kind, t.Key, t.Count, t.Sum); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// LoadHours returns the stored hours with from <= Hour < to, ascending.
func (s *Store) LoadHours(from, to int64) ([]HourStats, error) {
	rows, err := s.DB.Query(`SELECT hour, queries, blocked, cached, safesearch, services, elapsed_ms
		FROM stats_hours WHERE hour >= ? AND hour < ? ORDER BY hour`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HourStats{}
	for rows.Next() {
		var h HourStats
		if err := rows.Scan(&h.Hour, &h.Queries, &h.Blocked, &h.Cached, &h.SafeSearch, &h.Services, &h.ElapsedMS); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// LoadTop sums Count and Sum per key of one kind over from <= hour < to, highest Count first,
// at most limit entries (limit <= 0: all); Last is the latest hour of the key.
func (s *Store) LoadTop(kind string, from, to int64, limit int) ([]TopEntry, error) {
	if limit <= 0 {
		limit = -1 // SQLite: no limit
	}
	rows, err := s.DB.Query(`SELECT key, SUM(count) AS c, SUM(sum), MAX(hour) FROM stats_top
		WHERE kind = ? AND hour >= ? AND hour < ? GROUP BY key ORDER BY c DESC, key LIMIT ?`, kind, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TopEntry{}
	for rows.Next() {
		e := TopEntry{Kind: kind}
		if err := rows.Scan(&e.Key, &e.Count, &e.Sum, &e.Last); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ClearStats empties all statistics.
func (s *Store) ClearStats() error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM stats_top`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM stats_hours`); err != nil {
		return err
	}
	return tx.Commit()
}

// PruneStats removes hours < beforeHour (unix seconds).
func (s *Store) PruneStats(beforeHour int64) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM stats_top WHERE hour < ?`, beforeHour); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM stats_hours WHERE hour < ?`, beforeHour); err != nil {
		return err
	}
	return tx.Commit()
}
