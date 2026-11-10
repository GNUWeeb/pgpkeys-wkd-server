package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Login tokens and sessions are stored by the SHA-256 of their secret
// value; callers hash before calling, so a database leak does not hand
// out working links or sessions.

// AddLoginToken stores a login token for address valid until expires.
func (s *Store) AddLoginToken(ctx context.Context, hash []byte, address string, now, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO login_tokens (hash, address, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		hash, address, now.Unix(), expires.Unix())
	return err
}

// CountLoginTokens returns how many login tokens were issued for address
// after the given time.
func (s *Store) CountLoginTokens(ctx context.Context, address string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM login_tokens WHERE address = ? AND created_at > ?`,
		address, since.Unix()).Scan(&n)
	return n, err
}

// LoginTokenAddress returns the address of an unused, unexpired login
// token without using it up.
func (s *Store) LoginTokenAddress(ctx context.Context, hash []byte, now time.Time) (string, bool, error) {
	var addr string
	err := s.db.QueryRowContext(ctx, `
		SELECT address FROM login_tokens WHERE hash = ? AND used_at IS NULL AND expires_at > ?`,
		hash, now.Unix()).Scan(&addr)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return addr, err == nil, err
}

// UseLoginToken marks an unused, unexpired login token as used and
// returns its address. Of two concurrent calls with the same token, only
// one succeeds.
func (s *Store) UseLoginToken(ctx context.Context, hash []byte, now time.Time) (string, bool, error) {
	var addr string
	err := s.db.QueryRowContext(ctx, `
		UPDATE login_tokens SET used_at = ?
		WHERE hash = ? AND used_at IS NULL AND expires_at > ?
		RETURNING address`,
		now.Unix(), hash, now.Unix()).Scan(&addr)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return addr, err == nil, err
}

// AddSession stores a session for address valid until expires.
func (s *Store) AddSession(ctx context.Context, hash []byte, address string, now, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (hash, address, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		hash, address, now.Unix(), expires.Unix())
	return err
}

// SessionAddress returns the address of an unexpired session.
func (s *Store) SessionAddress(ctx context.Context, hash []byte, now time.Time) (string, bool, error) {
	var addr string
	err := s.db.QueryRowContext(ctx, `
		SELECT address FROM sessions WHERE hash = ? AND expires_at > ?`,
		hash, now.Unix()).Scan(&addr)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return addr, err == nil, err
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, hash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE hash = ?`, hash)
	return err
}

// Purge deletes expired sessions and the login tokens created before
// tokensBefore; tokens are kept past their expiry for as long as the
// per-address rate limit counts them.
func (s *Store) Purge(ctx context.Context, now, tokensBefore time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM login_tokens WHERE created_at < ?`, tokensBefore.Unix())
	return err
}
