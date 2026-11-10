package keys

import (
	"crypto"
	"fmt"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func signerOf(t *testing.T, e *openpgp.Entity) Signer {
	t.Helper()
	return Signer{Fingerprint: fmt.Sprintf("%X", e.PrimaryKey.Fingerprint), Data: public(t, e)}
}

func TestCertifications(t *testing.T) {
	cfg := keyConfig(0, crypto.SHA256)
	later := keyConfig(0, crypto.SHA256)
	later.Time = func() time.Time { return created.Add(time.Hour) }
	newKey := func(name string) *openpgp.Entity {
		e, err := openpgp.NewEntity(name, "", name+"@gnuweeb.org", cfg)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	alice, bob, carol, dave := newKey("alice"), newKey("bob"), newKey("carol"), newKey("dave")
	uid := "alice <alice@gnuweeb.org>"
	for _, signer := range []*openpgp.Entity{bob, carol, dave} {
		if err := alice.SignIdentity(uid, signer, cfg); err != nil {
			t.Fatal(err)
		}
	}
	// Dave revokes his certification an hour later.
	rev := &packet.Signature{
		Version:      dave.PrimaryKey.Version,
		SigType:      packet.SigTypeCertificationRevocation,
		PubKeyAlgo:   dave.PrimaryKey.PubKeyAlgo,
		Hash:         crypto.SHA256,
		CreationTime: created.Add(time.Hour),
		IssuerKeyId:  &dave.PrimaryKey.KeyId,
	}
	if err := rev.SignUserId(uid, alice.PrimaryKey, dave.PrivateKey, later); err != nil {
		t.Fatal(err)
	}
	id := alice.Identities[uid]
	id.OtherCertifications = append(id.OtherCertifications, packet.NewVerifiableSig(rev))

	// Carol's key is not stored; alice's own key is among the signers.
	signers := []Signer{signerOf(t, alice), signerOf(t, bob), signerOf(t, dave)}
	certs, others, err := Certifications(public(t, alice), signers, created.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].Signer != signers[1].Fingerprint || certs[0].UserID != uid || !certs[0].Created.Equal(created) {
		t.Errorf("certifications = %+v, want bob's alone", certs)
	}
	if others != 1 {
		t.Errorf("others = %d, want 1 (carol's)", others)
	}

	// Bob's certification of alice's User ID, copied onto another key
	// with the same User ID: it names bob but does not verify there.
	forged := newKey("alice")
	var bobs *packet.VerifiableSignature
	for _, vs := range id.OtherCertifications {
		if vs.Packet.CheckKeyIdOrFingerprint(bob.PrimaryKey) {
			bobs = vs
		}
	}
	forged.Identities[uid].OtherCertifications = []*packet.VerifiableSignature{packet.NewVerifiableSig(bobs.Packet)}
	certs, others, err = Certifications(public(t, forged), signers, created.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 0 || others != 0 {
		t.Errorf("forged certification: %+v, %d others; want neither shown nor counted", certs, others)
	}
}
