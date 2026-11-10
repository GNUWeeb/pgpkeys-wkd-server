package reminder

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/store"
)

type sent struct{ to, subject, body string }

type fakeMailer struct {
	sent []sent
	fail bool
}

func (m *fakeMailer) Send(_ context.Context, to, subject, body string) error {
	if m.fail {
		return errors.New("smtp down")
	}
	m.sent = append(m.sent, sent{to, subject, body})
	return nil
}

var created = time.Unix(1_800_000_000, 0)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// newEntity makes a key for alice created at created that expires after
// lifetime.
func newEntity(t *testing.T, lifetime time.Duration) (*openpgp.Entity, *packet.Config) {
	t.Helper()
	cfg := &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		KeyLifetimeSecs: uint32(lifetime / time.Second),
		Time:            func() time.Time { return created },
	}
	e, err := openpgp.NewEntity("Alice", "", "alice@gnuweeb.org", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e, cfg
}

// put stores e for alice as an upload at now.
func put(t *testing.T, st *store.Store, e *openpgp.Entity, now time.Time) *keys.Key {
	t.Helper()
	var b bytes.Buffer
	if err := e.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	k, err := keys.Parse(b.Bytes(), "alice@gnuweeb.org", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutKey(context.Background(), "alice@gnuweeb.org", k, now); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRemindersAtThresholds(t *testing.T) {
	st := newStore(t)
	m := &fakeMailer{}
	r := New(st, m, "https://pgp.gnuweeb.org", slog.New(slog.DiscardHandler))
	end := created.Add(100 * day)
	e, _ := newEntity(t, 100*day)
	k := put(t, st, e, created)

	// Daily runs from creation to after expiry: one mail at each of
	// 30, 10 and 3 days before the end, none after it.
	var at []int
	for now := created; now.Before(end.Add(5 * day)); now = now.Add(day) {
		before := len(m.sent)
		if err := r.Run(context.Background(), now); err != nil {
			t.Fatal(err)
		}
		if len(m.sent) > before {
			at = append(at, int(end.Sub(now)/day))
		}
	}
	if want := []int{30, 10, 3}; len(at) != 3 || at[0] != want[0] || at[1] != want[1] || at[2] != want[2] {
		t.Fatalf("reminders went out %v days before the end, want %v", at, want)
	}
	msg := m.sent[0]
	if msg.to != "alice@gnuweeb.org" || !strings.Contains(msg.subject, "2027-04-25") {
		t.Errorf("mail to %q with subject %q", msg.to, msg.subject)
	}
	for _, want := range []string{"gpg --quick-set-expire " + k.Fingerprint + " 5y '*'", "https://pgp.gnuweeb.org/keys/new"} {
		if !strings.Contains(msg.body, want) {
			t.Errorf("mail body lacks %q", want)
		}
	}
}

func TestRemindersStartOverAfterExtension(t *testing.T) {
	st := newStore(t)
	m := &fakeMailer{}
	r := New(st, m, "https://pgp.gnuweeb.org", slog.New(slog.DiscardHandler))
	e, cfg := newEntity(t, 100*day)
	put(t, st, e, created)

	now := created.Add(75 * day) // 25 days left
	for range 2 {
		if err := r.Run(context.Background(), now); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.sent) != 1 {
		t.Fatalf("%d mails in two runs on one day, want 1", len(m.sent))
	}

	// The member extends the key by 20 days and uploads it again: 25+20
	// days left is outside every threshold, so nothing goes out until
	// 30 days before the new end.
	for _, id := range e.Identities {
		sig := id.SelfCertifications[0].Packet
		life := uint32(120 * day / time.Second)
		sig.KeyLifetimeSecs = &life
		if err := id.ReSign(cfg); err != nil {
			t.Fatal(err)
		}
	}
	put(t, st, e, now)
	if err := r.Run(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(m.sent) != 1 {
		t.Fatalf("mail sent right after the extension")
	}
	if err := r.Run(context.Background(), created.Add(90*day)); err != nil {
		t.Fatal(err)
	}
	if len(m.sent) != 2 || !strings.Contains(m.sent[1].subject, created.Add(120*day).UTC().Format("2006-01-02")) {
		t.Fatalf("after the extension: %d mails, last %q", len(m.sent), m.sent[len(m.sent)-1].subject)
	}
}

func TestRemindersRetryAndSkip(t *testing.T) {
	st := newStore(t)
	m := &fakeMailer{fail: true}
	r := New(st, m, "https://pgp.gnuweeb.org", slog.New(slog.DiscardHandler))
	e, _ := newEntity(t, 100*day)
	put(t, st, e, created)

	now := created.Add(80 * day)
	if err := r.Run(context.Background(), now); err == nil {
		t.Error("Run reports no error when the mail failed")
	}
	m.fail = false
	if err := r.Run(context.Background(), now.Add(day)); err != nil || len(m.sent) != 1 {
		t.Fatalf("retry: err %v, %d mails", err, len(m.sent))
	}

	// A key that never expires and an expired key get no mail.
	forever, _ := newEntity(t, 0)
	m.sent = nil
	st2 := newStore(t)
	put(t, st2, forever, created)
	r2 := New(st2, m, "https://pgp.gnuweeb.org", slog.New(slog.DiscardHandler))
	if err := r2.Run(context.Background(), created.Add(1000*day)); err != nil || len(m.sent) != 0 {
		t.Errorf("key without expiry: err %v, %d mails", err, len(m.sent))
	}
	if err := r.Run(context.Background(), created.Add(101*day)); err != nil || len(m.sent) != 0 {
		t.Errorf("expired key: err %v, %d mails", err, len(m.sent))
	}
}
