package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
)

// CertRequest is a certification a member submitted for a stored key. It
// waits for the key's owner until Accepted is set; once accepted, it is
// part of every stored copy of the key, also after the owner uploads the
// key again.
type CertRequest struct {
	ID          int64
	Fingerprint string // the certified key
	UserID      string
	Signer      string // the certifying key
	SubmittedBy string // the address of the member who submitted it
	Created     time.Time
	Submitted   time.Time
	Accepted    time.Time // zero while it waits
	Packet      []byte
}

// SubmitCertification records sub, made on the key fingerprint and
// submitted by the member with the address by. A newer submission for the
// same User ID and signer replaces one that still waits; one that was
// accepted stays as it is. It reports whether the request is new, so that
// the owner is told only once.
func (s *Store) SubmitCertification(ctx context.Context, fingerprint string, sub keys.Submission, by string, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var accepted sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT accepted_at FROM certifications WHERE fingerprint = ? AND user_id = ? AND signer = ?`,
		fingerprint, sub.UserID, sub.Signer).Scan(&accepted)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.ExecContext(ctx, `
			INSERT INTO certifications (fingerprint, user_id, signer, submitted_by, created_at, submitted_at, packet)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			fingerprint, sub.UserID, sub.Signer, by, sub.Created.Unix(), now.Unix(), sub.Packet)
		if err != nil {
			return false, err
		}
		return true, tx.Commit()
	case err != nil:
		return false, err
	case accepted.Valid:
		return false, nil
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE certifications SET submitted_by = ?, created_at = ?, submitted_at = ?, packet = ?
		WHERE fingerprint = ? AND user_id = ? AND signer = ? AND created_at <= ?`,
		by, sub.Created.Unix(), now.Unix(), sub.Packet, fingerprint, sub.UserID, sub.Signer, sub.Created.Unix())
	if err != nil {
		return false, err
	}
	return false, tx.Commit()
}

// PendingFor returns the requests that wait for the member with address:
// those on keys stored for that address, oldest first.
func (s *Store) PendingFor(ctx context.Context, address string) ([]CertRequest, error) {
	return s.queryCerts(ctx, `
		SELECT `+certColumns+` FROM certifications
		WHERE accepted_at IS NULL AND fingerprint IN (SELECT fingerprint FROM keys WHERE address = ?)
		ORDER BY submitted_at, id`, address)
}

// PendingBy returns the requests the member with address submitted that
// still wait, oldest first.
func (s *Store) PendingBy(ctx context.Context, address string) ([]CertRequest, error) {
	return s.queryCerts(ctx, `
		SELECT `+certColumns+` FROM certifications
		WHERE accepted_at IS NULL AND submitted_by = ?
		ORDER BY submitted_at, id`, address)
}

// AcceptCertification adds the waiting request id to every stored copy of
// its key, when the key is stored for address, and reports whether it
// was.
func (s *Store) AcceptCertification(ctx context.Context, id int64, address string, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var c CertRequest
	err = tx.QueryRowContext(ctx, `
		SELECT fingerprint, user_id, packet FROM certifications
		WHERE id = ? AND accepted_at IS NULL
			AND fingerprint IN (SELECT fingerprint FROM keys WHERE address = ?)`, id, address).
		Scan(&c.Fingerprint, &c.UserID, &c.Packet)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	add := []keys.Submission{{Certification: keys.Certification{UserID: c.UserID}, Packet: c.Packet}}
	if err := mergeInto(ctx, tx, c.Fingerprint, add); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE certifications SET accepted_at = ? WHERE id = ?`, now.Unix(), id); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// RejectCertification drops the waiting request id on a key stored for
// address and reports whether there was one.
func (s *Store) RejectCertification(ctx context.Context, id int64, address string) (bool, error) {
	return s.deleteCert(ctx, `
		DELETE FROM certifications WHERE id = ? AND accepted_at IS NULL
			AND fingerprint IN (SELECT fingerprint FROM keys WHERE address = ?)`, id, address)
}

// WithdrawCertification drops the waiting request id that address
// submitted and reports whether there was one.
func (s *Store) WithdrawCertification(ctx context.Context, id int64, address string) (bool, error) {
	return s.deleteCert(ctx, `
		DELETE FROM certifications WHERE id = ? AND accepted_at IS NULL AND submitted_by = ?`, id, address)
}

func (s *Store) deleteCert(ctx context.Context, query string, args ...any) (bool, error) {
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

const certColumns = `id, fingerprint, user_id, signer, submitted_by, created_at, submitted_at, accepted_at, packet`

func (s *Store) queryCerts(ctx context.Context, query string, args ...any) ([]CertRequest, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertRequest
	for rows.Next() {
		var c CertRequest
		var created, submitted int64
		var accepted sql.NullInt64
		if err := rows.Scan(&c.ID, &c.Fingerprint, &c.UserID, &c.Signer, &c.SubmittedBy, &created, &submitted, &accepted, &c.Packet); err != nil {
			return nil, err
		}
		c.Created, c.Submitted = time.Unix(created, 0), time.Unix(submitted, 0)
		if accepted.Valid {
			c.Accepted = time.Unix(accepted.Int64, 0)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// acceptedFor returns the accepted certifications of the key fingerprint.
func acceptedFor(ctx context.Context, q querier, fingerprint string) ([]keys.Submission, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT user_id, packet FROM certifications
		WHERE fingerprint = ? AND accepted_at IS NOT NULL ORDER BY id`, fingerprint)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keys.Submission
	for rows.Next() {
		var sub keys.Submission
		if err := rows.Scan(&sub.UserID, &sub.Packet); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// mergeInto adds the certifications in add to every stored copy of the
// key fingerprint.
func mergeInto(ctx context.Context, tx *sql.Tx, fingerprint string, add []keys.Submission) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, data FROM keys WHERE fingerprint = ?`, fingerprint)
	if err != nil {
		return err
	}
	type copyOf struct {
		id   int64
		data []byte
	}
	var copies []copyOf
	for rows.Next() {
		var c copyOf
		if err := rows.Scan(&c.id, &c.data); err != nil {
			rows.Close()
			return err
		}
		copies = append(copies, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range copies {
		data, err := keys.AddCertifications(c.data, add)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE keys SET data = ? WHERE id = ?`, data, c.id); err != nil {
			return err
		}
	}
	return nil
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}
