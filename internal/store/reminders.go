package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Reminder is the last expiry reminder mailed for a stored key: the date
// the key stopped signing by then, and how many days before it the mail
// went out.
type Reminder struct {
	Expires time.Time
	Days    int
}

// LastReminder returns the reminder last mailed for the key keyID, if
// there is one.
func (s *Store) LastReminder(ctx context.Context, keyID int64) (Reminder, bool, error) {
	var expires int64
	var r Reminder
	err := s.db.QueryRowContext(ctx, `
		SELECT expires_at, days FROM expiry_reminders WHERE key_id = ?`, keyID).Scan(&expires, &r.Days)
	if errors.Is(err, sql.ErrNoRows) {
		return Reminder{}, false, nil
	}
	if err != nil {
		return Reminder{}, false, err
	}
	r.Expires = time.Unix(expires, 0)
	return r, true, nil
}

// SetReminder records that r was mailed for the key keyID at now.
func (s *Store) SetReminder(ctx context.Context, keyID int64, r Reminder, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO expiry_reminders (key_id, expires_at, days, sent_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (key_id) DO UPDATE SET
			expires_at = excluded.expires_at,
			days = excluded.days,
			sent_at = excluded.sent_at`,
		keyID, r.Expires.Unix(), r.Days, now.Unix())
	return err
}

// ClearReminder forgets the reminders for the key keyID, so that a key
// that comes close to expiring again is reminded from the start.
func (s *Store) ClearReminder(ctx context.Context, keyID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM expiry_reminders WHERE key_id = ?`, keyID)
	return err
}
