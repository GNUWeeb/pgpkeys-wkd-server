package store

import (
	"context"
	"strings"
	"time"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/wkd"
)

// StoredKey is a key as the store holds it for one address.
type StoredKey struct {
	// ID identifies the key for this address; it stays when the key is
	// uploaded again.
	ID          int64
	Address     string
	Fingerprint string
	Created     time.Time
	Uploaded    time.Time
	Data        []byte
}

// PutKey stores k for address, replacing an earlier upload of the same
// key for that address (an update, such as a new expiry date). The
// certifications accepted for the key are added to it again, so that an
// upload without them does not drop them. address must already be
// normalized; its WKD hash is derived from it here so the two cannot
// disagree.
func (s *Store) PutKey(ctx context.Context, address string, k *keys.Key, now time.Time) error {
	local, _, _ := strings.Cut(address, "@")
	data := k.Data
	accepted, err := acceptedFor(ctx, s.db, k.Fingerprint)
	if err != nil {
		return err
	}
	if len(accepted) > 0 {
		if data, err = keys.AddCertifications(data, accepted); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO keys (address, wkd_hash, fingerprint, created_at, uploaded_at, data, wkd)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (address, fingerprint) DO UPDATE SET
			created_at = excluded.created_at,
			uploaded_at = excluded.uploaded_at,
			data = excluded.data,
			wkd = excluded.wkd`,
		address, wkd.Hash(local), k.Fingerprint, k.Created.Unix(), now.Unix(), data, k.WKD)
	return err
}

// Keys returns the keys stored for address, newest first.
func (s *Store) Keys(ctx context.Context, address string) ([]StoredKey, error) {
	return s.queryKeys(ctx, `
		SELECT id, address, fingerprint, created_at, uploaded_at, data FROM keys
		WHERE address = ? ORDER BY created_at DESC, id DESC`, address)
}

// AllKeys returns every stored key, by address and then newest first.
func (s *Store) AllKeys(ctx context.Context) ([]StoredKey, error) {
	return s.queryKeys(ctx, `
		SELECT id, address, fingerprint, created_at, uploaded_at, data FROM keys
		ORDER BY address, created_at DESC, id DESC`)
}

func (s *Store) queryKeys(ctx context.Context, query string, args ...any) ([]StoredKey, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredKey
	for rows.Next() {
		var k StoredKey
		var created, uploaded int64
		if err := rows.Scan(&k.ID, &k.Address, &k.Fingerprint, &created, &uploaded, &k.Data); err != nil {
			return nil, err
		}
		k.Created, k.Uploaded = time.Unix(created, 0), time.Unix(uploaded, 0)
		out = append(out, k)
	}
	return out, rows.Err()
}

// DeleteKey removes the key with fingerprint from address and reports
// whether there was one. When no address keeps the key, the
// certifications submitted for it go too.
func (s *Store) DeleteKey(ctx context.Context, address, fingerprint string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `DELETE FROM keys WHERE address = ? AND fingerprint = ?`, address, fingerprint)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM certifications
		WHERE fingerprint = ? AND NOT EXISTS (SELECT 1 FROM keys WHERE fingerprint = ?)`, fingerprint, fingerprint); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// WKDKeys returns the WKD views of every key stored under the WKD hash,
// newest first.
func (s *Store) WKDKeys(ctx context.Context, hash string) ([][]byte, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT wkd FROM keys WHERE wkd_hash = ? ORDER BY created_at DESC, id DESC`, hash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
