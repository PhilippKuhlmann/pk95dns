// Package store is the SQLite storage of PK95 DNS (modernc.org/sqlite, WAL, busy_timeout):
// settings, lists, custom rules, local records, clients, users, sessions, query log and
// statistics (docs/design.md → Storage). Times are unix milliseconds unless noted.
package store

import (
	"database/sql"
	"errors"

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

// Open opens (creates) the database and runs the migrations.
func Open(path string) (*Store, error) { panic("not implemented") }

// Close closes the database.
func (s *Store) Close() error { panic("not implemented") }

// Checkpoint runs PRAGMA wal_checkpoint(TRUNCATE) (backup prepare).
func (s *Store) Checkpoint() error { panic("not implemented") }

// Ping checks the database (health).
func (s *Store) Ping() error { panic("not implemented") }

// LoadSettings returns the stored settings; keys that were never stored have their default
// (config.Defaults), so new settings fields work with old databases. Includes the json:"-"
// fields (blocked services, protection), which are stored separately.
func (s *Store) LoadSettings() (config.Settings, error) { panic("not implemented") }

// SaveSettings stores all settings including the json:"-" fields.
func (s *Store) SaveSettings(st config.Settings) error { panic("not implemented") }

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

// Lists returns all lists ordered by kind ("block" first), then name (case-insensitive).
func (s *Store) Lists() ([]List, error) { panic("not implemented") }

// GetList returns one list or ErrNotFound.
func (s *Store) GetList(id int64) (List, error) { panic("not implemented") }

// CreateList inserts l (ID, CreatedAt set). ErrDuplicate when the URL exists.
func (s *Store) CreateList(l List) (List, error) { panic("not implemented") }

// UpdateList stores name, url, kind, enabled. ErrNotFound / ErrDuplicate (URL).
func (s *Store) UpdateList(l List) error { panic("not implemented") }

// DeleteList removes a list. ErrNotFound.
func (s *Store) DeleteList(id int64) error { panic("not implemented") }

// SetListStatus stores the result of a download. updatedAt 0 keeps the old value (failed
// download); etag/lastModified "" keep the old values only when updatedAt is 0.
func (s *Store) SetListStatus(id int64, ruleCount int, updatedAt int64, lastError, etag, lastModified string) error {
	panic("not implemented")
}

// CustomRules returns the custom rules text ("" when never saved).
func (s *Store) CustomRules() (string, error) { panic("not implemented") }

// SaveCustomRules replaces the custom rules text.
func (s *Store) SaveCustomRules(text string) error { panic("not implemented") }

// Rewrite is a local DNS record.
type Rewrite struct {
	ID        int64  `json:"id"`
	Domain    string `json:"domain"`
	Answer    string `json:"answer"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
}

// Rewrites returns all records ordered by domain, then answer.
func (s *Store) Rewrites() ([]Rewrite, error) { panic("not implemented") }

// CreateRewrite inserts r. ErrDuplicate for the same domain+answer.
func (s *Store) CreateRewrite(r Rewrite) (Rewrite, error) { panic("not implemented") }

// UpdateRewrite stores domain, answer, enabled. ErrNotFound / ErrDuplicate.
func (s *Store) UpdateRewrite(r Rewrite) error { panic("not implemented") }

// DeleteRewrite removes a record. ErrNotFound.
func (s *Store) DeleteRewrite(id int64) error { panic("not implemented") }

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

// Clients returns all clients ordered by name (case-insensitive). Slices are never nil.
func (s *Store) Clients() ([]Client, error) { panic("not implemented") }

// GetClient returns one client or ErrNotFound.
func (s *Store) GetClient(id int64) (Client, error) { panic("not implemented") }

// CreateClient inserts c. ErrDuplicate when the name exists (case-insensitive).
func (s *Store) CreateClient(c Client) (Client, error) { panic("not implemented") }

// UpdateClient stores all fields except CreatedAt. ErrNotFound / ErrDuplicate.
func (s *Store) UpdateClient(c Client) error { panic("not implemented") }

// DeleteClient removes a client. ErrNotFound.
func (s *Store) DeleteClient(id int64) error { panic("not implemented") }

// User is an account of the standalone web UI.
type User struct {
	ID           int64
	Username     string
	PasswordHash string // bcrypt
}

// UserCount returns the number of users.
func (s *Store) UserCount() (int, error) { panic("not implemented") }

// CreateUser inserts a user. ErrDuplicate.
func (s *Store) CreateUser(username, passwordHash string) (User, error) { panic("not implemented") }

// UserByName returns the user (case-sensitive) or ErrNotFound.
func (s *Store) UserByName(username string) (User, error) { panic("not implemented") }

// SetPasswordHash replaces the password hash.
func (s *Store) SetPasswordHash(userID int64, hash string) error { panic("not implemented") }

// CreateSession stores a session by the SHA-256 hex hash of its token.
func (s *Store) CreateSession(tokenHash string, userID int64, expiresAt int64) error {
	panic("not implemented")
}

// SessionUser returns the user of a session that has not expired at now, or ErrNotFound.
func (s *Store) SessionUser(tokenHash string, now int64) (User, error) { panic("not implemented") }

// DeleteSession removes one session.
func (s *Store) DeleteSession(tokenHash string) error { panic("not implemented") }

// DeleteUserSessions removes all sessions of a user except keepHash ("" = all).
func (s *Store) DeleteUserSessions(userID int64, keepHash string) error { panic("not implemented") }

// PruneSessions removes expired sessions.
func (s *Store) PruneSessions(now int64) error { panic("not implemented") }

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

// InsertQueries writes a batch in one transaction.
func (s *Store) InsertQueries(qs []Query) error { panic("not implemented") }

// Queries returns entries newest first (id descending).
func (s *Store) Queries(f QueryFilter) ([]Query, error) { panic("not implemented") }

// ClearQueries empties the whole query log.
func (s *Store) ClearQueries() error { panic("not implemented") }

// PruneQueries removes entries with ts < before, in chunks; returns the number removed.
func (s *Store) PruneQueries(before int64) (int64, error) { panic("not implemented") }

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
func (s *Store) SaveHour(h HourStats, top []TopEntry) error { panic("not implemented") }

// LoadHours returns the stored hours with from <= Hour < to, ascending.
func (s *Store) LoadHours(from, to int64) ([]HourStats, error) { panic("not implemented") }

// LoadTop sums Count and Sum per key of one kind over from <= hour < to, highest Count first,
// at most limit entries; Last is the latest hour of the key.
func (s *Store) LoadTop(kind string, from, to int64, limit int) ([]TopEntry, error) {
	panic("not implemented")
}

// ClearStats empties all statistics.
func (s *Store) ClearStats() error { panic("not implemented") }

// PruneStats removes hours < beforeHour (unix seconds).
func (s *Store) PruneStats(beforeHour int64) error { panic("not implemented") }
