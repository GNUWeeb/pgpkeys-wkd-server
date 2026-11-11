// Package store keeps matcha's state in one SQLite database.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Store is the database. It is safe for concurrent use.
type Store struct {
	db *sql.DB
}

// migrations are applied in order; the database's user_version is the
// number of migrations already applied. Never edit an entry once it has
// been released; append a new one.
var migrations = []string{
	`CREATE TABLE keys (
		id          INTEGER PRIMARY KEY,
		address     TEXT    NOT NULL,
		wkd_hash    TEXT    NOT NULL,
		fingerprint TEXT    NOT NULL,
		created_at  INTEGER NOT NULL,
		uploaded_at INTEGER NOT NULL,
		data        BLOB    NOT NULL,
		wkd         BLOB    NOT NULL,
		UNIQUE (address, fingerprint)
	);
	CREATE INDEX keys_wkd_hash ON keys (wkd_hash);`,
	`CREATE TABLE login_tokens (
		hash       BLOB    PRIMARY KEY,
		address    TEXT    NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		used_at    INTEGER
	);
	CREATE INDEX login_tokens_address ON login_tokens (address, created_at);
	CREATE TABLE sessions (
		hash       BLOB    PRIMARY KEY,
		address    TEXT    NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);`,
	`CREATE TABLE expiry_reminders (
		key_id     INTEGER PRIMARY KEY REFERENCES keys (id) ON DELETE CASCADE,
		expires_at INTEGER NOT NULL,
		days       INTEGER NOT NULL,
		sent_at    INTEGER NOT NULL
	);`,
	`CREATE TABLE certifications (
		id           INTEGER PRIMARY KEY,
		fingerprint  TEXT    NOT NULL,
		user_id      TEXT    NOT NULL,
		signer       TEXT    NOT NULL,
		submitted_by TEXT    NOT NULL,
		created_at   INTEGER NOT NULL,
		submitted_at INTEGER NOT NULL,
		accepted_at  INTEGER,
		packet       BLOB    NOT NULL,
		UNIQUE (fingerprint, user_id, signer)
	);
	CREATE INDEX certifications_submitted_by ON certifications (submitted_by);`,
}

// Open opens or creates the database at path and brings its schema up to
// date.
func Open(ctx context.Context, path string) (*Store, error) {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(1)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	// One connection: writes are rare and small, and a single connection
	// rules out SQLITE_BUSY between this process's own connections.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database %s: %w", path, err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("schema version %d is newer than this binary (%d)", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", len(migrations))); err != nil {
		return err
	}
	return tx.Commit()
}
