package keys

import (
	"bytes"
	"crypto"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func TestSubmittedAndAddCertifications(t *testing.T) {
	cfg := keyConfig(0, crypto.SHA256)
	newKey := func(name string) *openpgp.Entity {
		e, err := openpgp.NewEntity(name, "", name+"@gnuweeb.org", cfg)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	alice, bob, carol := newKey("alice"), newKey("bob"), newKey("carol")
	uid := "alice <alice@gnuweeb.org>"
	stored := public(t, alice)
	for _, signer := range []*openpgp.Entity{bob, carol} {
		if err := alice.SignIdentity(uid, signer, cfg); err != nil {
			t.Fatal(err)
		}
	}
	var armored bytes.Buffer
	w, err := armor.Encode(&armored, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(public(t, alice)); err != nil {
		t.Fatal(err)
	}
	w.Close()

	data, fpr, err := ReadSubmitted(armored.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if want := signerOf(t, alice).Fingerprint; fpr != want {
		t.Fatalf("fingerprint %s, want %s", fpr, want)
	}
	// Only bob's key is the submitter's; carol's certification is not his
	// to submit, and alice's own self-signature is no certification.
	now := created.Add(time.Hour)
	bobs := []Signer{signerOf(t, bob)}
	subs, err := Submitted(data, stored, bobs, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0].Signer != bobs[0].Fingerprint || subs[0].UserID != uid {
		t.Fatalf("submitted = %+v, want bob's certification alone", subs)
	}

	merged, err := AddCertifications(stored, subs)
	if err != nil {
		t.Fatal(err)
	}
	certs, _, err := Certifications(merged, []Signer{signerOf(t, bob), signerOf(t, carol)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].Signer != bobs[0].Fingerprint {
		t.Errorf("certifications after merging = %+v, want bob's alone", certs)
	}
	if _, err := Check(merged, now); err != nil {
		t.Errorf("merged key does not read: %v", err)
	}
	// Merging again changes nothing, and the merged key has nothing left
	// to submit.
	again, err := AddCertifications(merged, subs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, merged) {
		t.Error("merging the same certification twice adds it twice")
	}
	if subs, err := Submitted(data, merged, bobs, now); err != nil || len(subs) != 0 {
		t.Errorf("submitting a certification the key has: %+v, %v", subs, err)
	}

	// The same certification on another key with the same User ID does
	// not verify there.
	other := public(t, newKey("alice"))
	if subs, err := Submitted(data, other, bobs, now); err != nil || len(subs) != 0 {
		t.Errorf("certification of another key accepted: %+v, %v", subs, err)
	}
}

func TestReadSubmittedRefusesSecretKeys(t *testing.T) {
	e, err := openpgp.NewEntity("alice", "", "alice@gnuweeb.org", keyConfig(0, crypto.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := e.SerializePrivateWithoutSigning(&b, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadSubmitted(b.Bytes()); err == nil {
		t.Error("secret key accepted")
	}
}
