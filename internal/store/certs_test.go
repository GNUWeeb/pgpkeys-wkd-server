package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
)

func TestCertificationRequests(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	newKey := func(name string) *openpgp.Entity {
		e, err := openpgp.NewEntity(name, "", name+"@gnuweeb.org", cfg)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	serialize := func(e *openpgp.Entity) []byte {
		var b bytes.Buffer
		if err := e.Serialize(&b); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	put := func(address string, data []byte) *keys.Key {
		k, err := keys.Parse(data, address, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.PutKey(ctx, address, k, now); err != nil {
			t.Fatal(err)
		}
		return k
	}
	alice, bob := newKey("alice"), newKey("bob")
	plain := serialize(alice)
	ak := put("alice@gnuweeb.org", plain)
	bk := put("bob@gnuweeb.org", serialize(bob))
	uid := "alice <alice@gnuweeb.org>"
	if err := alice.SignIdentity(uid, bob, cfg); err != nil {
		t.Fatal(err)
	}
	bobs := []keys.Signer{{Fingerprint: bk.Fingerprint, Data: bk.Data}}
	subs, err := keys.Submitted(serialize(alice), ak.Data, bobs, now)
	if err != nil || len(subs) != 1 {
		t.Fatalf("submitted = %+v, %v", subs, err)
	}

	if isNew, err := st.SubmitCertification(ctx, ak.Fingerprint, subs[0], "bob@gnuweeb.org", now); err != nil || !isNew {
		t.Fatalf("first submission: new %v, %v", isNew, err)
	}
	if isNew, err := st.SubmitCertification(ctx, ak.Fingerprint, subs[0], "bob@gnuweeb.org", now); err != nil || isNew {
		t.Fatalf("second submission: new %v, %v", isNew, err)
	}
	pending, err := st.PendingFor(ctx, "alice@gnuweeb.org")
	if err != nil || len(pending) != 1 || pending[0].Signer != bk.Fingerprint {
		t.Fatalf("pending for alice = %+v, %v", pending, err)
	}
	if by, _ := st.PendingBy(ctx, "bob@gnuweeb.org"); len(by) != 1 {
		t.Fatalf("pending by bob = %+v", by)
	}
	id := pending[0].ID

	// Only the owner accepts or rejects, only the submitter withdraws.
	for name, f := range map[string]func() (bool, error){
		"bob accepts":     func() (bool, error) { return st.AcceptCertification(ctx, id, "bob@gnuweeb.org", now) },
		"bob rejects":     func() (bool, error) { return st.RejectCertification(ctx, id, "bob@gnuweeb.org") },
		"alice withdraws": func() (bool, error) { return st.WithdrawCertification(ctx, id, "alice@gnuweeb.org") },
	} {
		if ok, err := f(); err != nil || ok {
			t.Errorf("%s: %v, %v", name, ok, err)
		}
	}

	certified := func() int {
		t.Helper()
		ks, err := st.Keys(ctx, "alice@gnuweeb.org")
		if err != nil {
			t.Fatal(err)
		}
		certs, _, err := keys.Certifications(ks[0].Data, bobs, now)
		if err != nil {
			t.Fatal(err)
		}
		return len(certs)
	}
	if n := certified(); n != 0 {
		t.Fatalf("certified before acceptance: %d", n)
	}
	if ok, err := st.AcceptCertification(ctx, id, "alice@gnuweeb.org", now); err != nil || !ok {
		t.Fatalf("alice accepts: %v, %v", ok, err)
	}
	if n := certified(); n != 1 {
		t.Fatalf("certifications after acceptance: %d, want 1", n)
	}
	if p, _ := st.PendingFor(ctx, "alice@gnuweeb.org"); len(p) != 0 {
		t.Errorf("still pending after acceptance: %+v", p)
	}
	// An upload without the certification keeps it.
	put("alice@gnuweeb.org", plain)
	if n := certified(); n != 1 {
		t.Errorf("certifications after uploading again: %d, want 1", n)
	}
	// Submitting it again asks nobody.
	if isNew, err := st.SubmitCertification(ctx, ak.Fingerprint, subs[0], "bob@gnuweeb.org", now); err != nil || isNew {
		t.Errorf("submission after acceptance: new %v, %v", isNew, err)
	}

	// Removing the key drops its certifications.
	if ok, err := st.DeleteKey(ctx, "alice@gnuweeb.org", ak.Fingerprint); err != nil || !ok {
		t.Fatal(ok, err)
	}
	var n int
	if err := st.db.QueryRowContext(ctx, `SELECT count(*) FROM certifications`).Scan(&n); err != nil || n != 0 {
		t.Errorf("certifications left after removing the key: %d, %v", n, err)
	}
}
