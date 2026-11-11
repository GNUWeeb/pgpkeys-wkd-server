// Package reminder mails members before their keys stop being usable, as
// kernel.org does for its account holders.
package reminder

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/store"
)

const (
	day = 24 * time.Hour
	// Interval is how often Loop checks the keys.
	Interval = day
	// mailTimeout bounds one SMTP conversation.
	mailTimeout = 30 * time.Second
)

// thresholds are how long before a key stops signing a reminder goes
// out, shortest first. The longest is when the dashboard starts to warn.
var thresholds = []time.Duration{3 * day, 10 * day, keys.ExpiryNotice}

// Mailer sends one plain-text message.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// Reminder checks the stored keys and mails their owners.
type Reminder struct {
	store   *store.Store
	mailer  Mailer
	baseURL string
	log     *slog.Logger
}

// New returns a Reminder whose mails point to the dashboard at baseURL.
func New(st *store.Store, mailer Mailer, baseURL string, log *slog.Logger) *Reminder {
	return &Reminder{store: st, mailer: mailer, baseURL: baseURL, log: log}
}

// Loop runs Run at once and then every Interval until ctx ends.
func (r *Reminder) Loop(ctx context.Context, now func() time.Time) {
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		if err := r.Run(ctx, now()); err != nil {
			r.log.Error("key check", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Run checks every stored key at now. It mails a reminder when a usable
// key stops signing within one of the thresholds and no reminder for that
// date and threshold went out yet, and it logs the keys that cannot sign.
// Keys that already cannot sign get no mail: the dashboard says so, and
// mailing them daily would repeat the same news. A mail that fails is
// tried again on the next run.
func (r *Reminder) Run(ctx context.Context, now time.Time) error {
	all, err := r.store.AllKeys(ctx)
	if err != nil {
		return err
	}
	failed := 0
	for _, k := range all {
		if err := r.check(ctx, k, now); err != nil {
			r.log.Error("expiry reminder", "address", k.Address, "fingerprint", k.Fingerprint, "err", err)
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d keys failed", failed, len(all))
	}
	return nil
}

func (r *Reminder) check(ctx context.Context, k store.StoredKey, now time.Time) error {
	h, err := keys.Check(k.Data, now)
	if err != nil {
		return err
	}
	if !h.Usable {
		r.log.Warn("key cannot sign", "address", k.Address, "fingerprint", k.Fingerprint, "reason", h.Problems[0].Text)
	}
	due := 0
	if h.Usable && !h.SigningUntil.IsZero() {
		due = dueDays(h.SigningUntil.Sub(now))
	}
	if due == 0 {
		return r.store.ClearReminder(ctx, k.ID)
	}
	last, ok, err := r.store.LastReminder(ctx, k.ID)
	if err != nil {
		return err
	}
	// A new date means the key was extended and may come close again.
	if ok && last.Expires.Equal(h.SigningUntil) && last.Days <= due {
		return nil
	}
	mctx, cancel := context.WithTimeout(ctx, mailTimeout)
	defer cancel()
	subject, body := r.message(k, h.SigningUntil)
	if err := r.mailer.Send(mctx, k.Address, subject, body); err != nil {
		return err
	}
	r.log.Info("expiry reminder sent", "address", k.Address, "fingerprint", k.Fingerprint, "days", due)
	return r.store.SetReminder(ctx, k.ID, store.Reminder{Expires: h.SigningUntil, Days: due}, now)
}

// dueDays returns the shortest threshold, in days, that left is within,
// or 0 when it is within none.
func dueDays(left time.Duration) int {
	for _, t := range thresholds {
		if left <= t {
			return int(t / day)
		}
	}
	return 0
}

func (r *Reminder) message(k store.StoredKey, until time.Time) (subject, body string) {
	date := until.UTC().Format("2006-01-02")
	subject = "Your OpenPGP key stops signing on " + date
	body = fmt.Sprintf(`Hello,

This is an automated reminder. The OpenPGP key published for
%[1]s stops working for signing on %[2]s:

    %[3]s

After that date, tools like git, b4 and sq no longer accept signatures
made with it. Extend its expiry date; nobody needs to sign the key
again:

    gpg --quick-set-expire %[3]s 5y
    gpg --quick-set-expire %[3]s 5y '*'

Then upload the key again at:

    %[4]s/keys/new

This reminder is sent 30, 10 and 3 days before the key stops signing.
It stops once the uploaded key has a new expiry date.
`, k.Address, date, k.Fingerprint, r.baseURL)
	return subject, body
}
