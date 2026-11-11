package store

import (
	"database/sql"
	"errors"
	"fmt"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"pk95dns/internal/records"
)

// dsnOptions are appended to the database path. _txlock=immediate makes every transaction
// take the write lock at BEGIN (all our transactions write), so busy_timeout applies instead
// of failing with SQLITE_BUSY when a read transaction would have to be upgraded.
const dsnOptions = "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)" +
	"&_pragma=synchronous(NORMAL)&_txlock=immediate"

// maxOpenConns: WAL allows concurrent readers, writers serialize via busy_timeout.
const maxOpenConns = 4

// migration changes the schema by one version inside the migration transaction.
type migration func(tx *sql.Tx) error

// migrations are applied in order; PRAGMA user_version holds the number of applied ones.
var migrations = []migration{
	execMigration(schemaV1), // 1: initial schema
	migrateV2,               // 2: zones and records replace rewrites
	execMigration(`ALTER TABLE stats_hours ADD COLUMN local INTEGER NOT NULL DEFAULT 0`), // 3: answers from own zones and records per hour
}

func execMigration(ddl string) migration {
	return func(tx *sql.Tx) error {
		_, err := tx.Exec(ddl)
		return err
	}
}

// schemaV1 is the initial schema (version 1.0). Its rewrites table is replaced by version 2.
const schemaV1 = `
CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE lists (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	name          TEXT    NOT NULL,
	url           TEXT    NOT NULL UNIQUE,
	kind          TEXT    NOT NULL,
	enabled       INTEGER NOT NULL DEFAULT 1,
	rule_count    INTEGER NOT NULL DEFAULT 0,
	updated_at    INTEGER NOT NULL DEFAULT 0,
	last_error    TEXT    NOT NULL DEFAULT '',
	etag          TEXT    NOT NULL DEFAULT '',
	last_modified TEXT    NOT NULL DEFAULT '',
	created_at    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE custom_rules (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	text       TEXT    NOT NULL,
	updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE rewrites (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	domain     TEXT    NOT NULL,
	answer     TEXT    NOT NULL,
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL DEFAULT 0,
	UNIQUE (domain, answer)
);

CREATE TABLE clients (
	id                  INTEGER PRIMARY KEY AUTOINCREMENT,
	name                TEXT    NOT NULL COLLATE NOCASE UNIQUE,
	ids                 TEXT    NOT NULL DEFAULT '[]',
	use_global_settings INTEGER NOT NULL DEFAULT 1,
	filtering_enabled   INTEGER NOT NULL DEFAULT 1,
	safesearch          TEXT    NOT NULL DEFAULT '{}',
	use_global_services INTEGER NOT NULL DEFAULT 1,
	blocked_services    TEXT    NOT NULL DEFAULT '[]',
	created_at          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT    NOT NULL UNIQUE,
	password_hash TEXT    NOT NULL,
	created_at    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE sessions (
	token_hash TEXT    PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE TABLE queries (
	id          INTEGER PRIMARY KEY,
	ts          INTEGER NOT NULL,
	client_ip   TEXT    NOT NULL DEFAULT '',
	client_name TEXT    NOT NULL DEFAULT '',
	name        TEXT    NOT NULL DEFAULT '',
	qtype       TEXT    NOT NULL DEFAULT '',
	status      TEXT    NOT NULL DEFAULT '',
	reason      TEXT    NOT NULL DEFAULT '',
	rule        TEXT    NOT NULL DEFAULT '',
	list_id     INTEGER NOT NULL DEFAULT 0,
	service     TEXT    NOT NULL DEFAULT '',
	upstream    TEXT    NOT NULL DEFAULT '',
	rcode       TEXT    NOT NULL DEFAULT '',
	answer      TEXT    NOT NULL DEFAULT '',
	elapsed_ms  REAL    NOT NULL DEFAULT 0,
	cached      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX queries_ts ON queries (ts);
CREATE INDEX queries_name ON queries (name);
CREATE INDEX queries_client_ip ON queries (client_ip);

CREATE TABLE stats_hours (
	hour       INTEGER PRIMARY KEY,
	queries    INTEGER NOT NULL DEFAULT 0,
	blocked    INTEGER NOT NULL DEFAULT 0,
	cached     INTEGER NOT NULL DEFAULT 0,
	safesearch INTEGER NOT NULL DEFAULT 0,
	services   INTEGER NOT NULL DEFAULT 0,
	elapsed_ms REAL    NOT NULL DEFAULT 0
);

CREATE TABLE stats_top (
	hour  INTEGER NOT NULL,
	kind  TEXT    NOT NULL,
	key   TEXT    NOT NULL,
	count INTEGER NOT NULL DEFAULT 0,
	sum   REAL    NOT NULL DEFAULT 0,
	PRIMARY KEY (hour, kind, key)
) WITHOUT ROWID;
CREATE INDEX stats_top_kind_hour ON stats_top (kind, hour);
`

// schemaV2 adds authoritative zones and DNS records (docs/api.md → DNS zones and records).
// records.zone_id is 0 for single records; it is kept equal to records.ZoneFor(name) by the
// store (no foreign key: 0 is not a zone).
const schemaV2 = `
CREATE TABLE zones (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT    NOT NULL UNIQUE,
	ttl        INTEGER NOT NULL DEFAULT 300,
	primary_ns TEXT    NOT NULL DEFAULT '',
	enabled    INTEGER NOT NULL DEFAULT 1,
	serial     INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE records (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	zone_id    INTEGER NOT NULL DEFAULT 0,
	name       TEXT    NOT NULL,
	type       TEXT    NOT NULL,
	value      TEXT    NOT NULL,
	ttl        INTEGER NOT NULL DEFAULT 300,
	priority   INTEGER NOT NULL DEFAULT 0,
	weight     INTEGER NOT NULL DEFAULT 0,
	port       INTEGER NOT NULL DEFAULT 0,
	ptr        INTEGER NOT NULL DEFAULT 0,
	enabled    INTEGER NOT NULL DEFAULT 1,
	managed_by TEXT    NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT 0,
	UNIQUE (name, type, value, priority, weight, port)
);
CREATE INDEX records_name ON records (name);
CREATE INDEX records_zone ON records (zone_id);
`

// migrateV2 creates zones and records and turns every v1 rewrite into a record with the
// same id (IP → A/AAAA, host name → CNAME, TTL 60, single record). The AUTOINCREMENT
// sequence of records continues after the highest id rewrites ever used, so ids of deleted
// rewrites are never handed out again. Then rewrites is dropped.
func migrateV2(tx *sql.Tx) error {
	if _, err := tx.Exec(schemaV2); err != nil {
		return err
	}
	type rewrite struct {
		id, createdAt  int64
		domain, answer string
		enabled        bool
	}
	rows, err := tx.Query(`SELECT id, domain, answer, enabled, created_at FROM rewrites ORDER BY id`)
	if err != nil {
		return err
	}
	var rws []rewrite
	for rows.Next() {
		var rw rewrite
		if err := rows.Scan(&rw.id, &rw.domain, &rw.answer, &rw.enabled, &rw.createdAt); err != nil {
			rows.Close()
			return err
		}
		rws = append(rws, rw)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, rw := range rws {
		if _, err := tx.Exec(`INSERT INTO records (id, zone_id, name, type, value, ttl, enabled, created_at)
			VALUES (?, 0, ?, ?, ?, ?, ?, ?)`, rw.id, rw.domain, records.TypeForAnswer(rw.answer), rw.answer,
			records.RewriteTTL, boolInt(rw.enabled), rw.createdAt); err != nil {
			return fmt.Errorf("rewrite %d: %w", rw.id, err)
		}
	}
	var seq int64
	if err := tx.QueryRow(`SELECT MAX(COALESCE((SELECT MAX(seq) FROM sqlite_sequence WHERE name = 'rewrites'), 0),
		COALESCE((SELECT MAX(id) FROM records), 0))`).Scan(&seq); err != nil {
		return err
	}
	if seq > 0 {
		res, err := tx.Exec(`UPDATE sqlite_sequence SET seq = ? WHERE name = 'records'`, seq)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil {
			return err
		} else if n == 0 {
			if _, err := tx.Exec(`INSERT INTO sqlite_sequence (name, seq) VALUES ('records', ?)`, seq); err != nil {
				return err
			}
		}
	}
	_, err = tx.Exec(`DROP TABLE rewrites`)
	return err
}

// Open opens (creates) the database and runs the migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?"+dsnOptions)
	if err != nil {
		return nil, fmt.Errorf("Datenbank kann nicht geöffnet werden: %w", err)
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxOpenConns)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("Datenbank kann nicht geöffnet werden: %w", err)
	}
	s := &Store{DB: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("Datenbank-Migration fehlgeschlagen: %w", err)
	}
	return s, nil
}

// migrate applies all migrations newer than PRAGMA user_version in ONE transaction together
// with the version bump: a fresh database goes straight to the newest version, and a failed
// migration leaves the database as it was. Running it again is a no-op.
func (s *Store) migrate() error {
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version >= len(migrations) {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i := version; i < len(migrations); i++ {
		if err := migrations[i](tx); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations))); err != nil {
		return err
	}
	return tx.Commit()
}

// Close closes the database.
func (s *Store) Close() error { return s.DB.Close() }

// Checkpoint runs PRAGMA wal_checkpoint(TRUNCATE) (backup prepare).
func (s *Store) Checkpoint() error {
	var busy, logFrames, checkpointed int
	if err := s.DB.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil {
		return err
	}
	if busy != 0 {
		return errors.New("Datenbank ist beschäftigt, Checkpoint unvollständig")
	}
	return nil
}

// Ping checks the database (health).
func (s *Store) Ping() error {
	var one int
	return s.DB.QueryRow(`SELECT 1`).Scan(&one)
}

// isConstraint reports a UNIQUE or PRIMARY KEY violation.
func isConstraint(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() {
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return true
	}
	return false
}

// mapErr turns constraint violations into ErrDuplicate.
func mapErr(err error) error {
	if err != nil && isConstraint(err) {
		return ErrDuplicate
	}
	return err
}

// affected returns ErrNotFound when res changed no row.
func affected(res sql.Result, err error) error {
	if err != nil {
		return mapErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
