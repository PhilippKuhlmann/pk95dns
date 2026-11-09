package store

import (
	"database/sql"
	"errors"
	"fmt"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// dsnOptions are appended to the database path. _txlock=immediate makes every transaction
// take the write lock at BEGIN (all our transactions write), so busy_timeout applies instead
// of failing with SQLITE_BUSY when a read transaction would have to be upgraded.
const dsnOptions = "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)" +
	"&_pragma=synchronous(NORMAL)&_txlock=immediate"

// maxOpenConns: WAL allows concurrent readers, writers serialize via busy_timeout.
const maxOpenConns = 4

// migrations are applied in order; PRAGMA user_version holds the number of applied ones.
var migrations = []string{
	// 1: initial schema.
	`
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
`,
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

// migrate applies all migrations newer than PRAGMA user_version, each in its own
// transaction together with the version bump. Running it again is a no-op.
func (s *Store) migrate() error {
	var version int
	if err := s.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.DB.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	return nil
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
