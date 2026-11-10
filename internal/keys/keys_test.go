package keys

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var testConfig = &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}

func newEntity(t *testing.T, name, email string) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", email, testConfig)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func public(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := e.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func armored(t *testing.T, blockType string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := armor.Encode(&b, blockType, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(data)
	w.Close()
	return b.Bytes()
}

// signaturesBy counts the signature packets in data issued by key.
func signaturesBy(t *testing.T, data []byte, key *packet.PublicKey) int {
	t.Helper()
	pkts, err := splitPackets(data)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range pkts {
		if p.tag != tagSignature {
			continue
		}
		parsed, err := packet.Read(bytes.NewReader(p.raw))
		if err != nil {
			t.Fatal(err)
		}
		if parsed.(*packet.Signature).CheckKeyIdOrFingerprint(key) {
			n++
		}
	}
	return n
}

func TestParseStripsThirdPartyCertifications(t *testing.T) {
	alice := newEntity(t, "Alice", "alice@gnuweeb.org")
	if err := alice.AddUserId("Alice", "", "alice@example.org", testConfig); err != nil {
		t.Fatal(err)
	}
	bob := newEntity(t, "Bob", "bob@gnuweeb.org")
	if err := alice.SignIdentity("Alice <alice@gnuweeb.org>", bob, testConfig); err != nil {
		t.Fatal(err)
	}
	upload := public(t, alice)
	if n := signaturesBy(t, upload, bob.PrimaryKey); n != 1 {
		t.Fatalf("test setup: upload has %d signatures by bob, want 1", n)
	}

	k, err := Parse(upload, "alice@gnuweeb.org")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.Data, upload) {
		t.Error("Data differs from the upload")
	}
	if n := signaturesBy(t, k.WKD, bob.PrimaryKey); n != 0 {
		t.Errorf("WKD view has %d signatures by bob, want 0", n)
	}
	if got, want := signaturesBy(t, k.WKD, alice.PrimaryKey), signaturesBy(t, upload, alice.PrimaryKey); got != want {
		t.Errorf("WKD view has %d self-signatures, upload has %d", got, want)
	}

	ents, err := openpgp.ReadKeyRing(bytes.NewReader(k.WKD))
	if err != nil {
		t.Fatalf("WKD view does not parse: %v", err)
	}
	ids := ents[0].Identities
	if len(ids) != 2 || ids["Alice <alice@gnuweeb.org>"] == nil || ids["Alice <alice@example.org>"] == nil {
		t.Errorf("WKD view identities = %v, want both User IDs", ids)
	}
	if len(ents[0].Subkeys) != 1 {
		t.Errorf("WKD view has %d subkeys, want 1", len(ents[0].Subkeys))
	}
}

func TestParseDropsUserIDWithOnlyThirdPartyCertifications(t *testing.T) {
	alice := newEntity(t, "Alice", "alice@gnuweeb.org")
	bob := newEntity(t, "Bob", "bob@gnuweeb.org")
	// A User ID that only bob certified: append it by hand after the key.
	uid := packet.NewUserId("Mallory", "", "mallory@gnuweeb.org")
	sig := userIDSig(t, bob, alice, uid.Id, packet.SigTypeGenericCert)
	var b bytes.Buffer
	b.Write(public(t, alice))
	uid.Serialize(&b)
	sig.Serialize(&b)

	k, err := Parse(b.Bytes(), "alice@gnuweeb.org")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(k.WKD, []byte("mallory@gnuweeb.org")) {
		t.Error("WKD view keeps a User ID without a self-signature")
	}
}

func TestParseAccepts(t *testing.T) {
	alice := newEntity(t, "Alice", "Alice@GNUWeeb.org")
	bin := public(t, alice)
	for name, input := range map[string][]byte{
		"binary":  bin,
		"armored": armored(t, openpgp.PublicKeyType, bin),
	} {
		t.Run(name, func(t *testing.T) {
			k, err := Parse(input, "alice@gnuweeb.org")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(k.Data, bin) {
				t.Error("Data is not the binary key")
			}
			if want := strings.ToUpper(alice.PrimaryKey.KeyIdString()); !strings.HasSuffix(k.Fingerprint, want) {
				t.Errorf("Fingerprint = %s, want suffix %s", k.Fingerprint, want)
			}
			if !k.Created.Equal(alice.PrimaryKey.CreationTime) {
				t.Errorf("Created = %v, want %v", k.Created, alice.PrimaryKey.CreationTime)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	alice := newEntity(t, "Alice", "alice@gnuweeb.org")
	bob := newEntity(t, "Bob", "bob@gnuweeb.org")
	var secret bytes.Buffer
	if err := alice.SerializePrivate(&secret, testConfig); err != nil {
		t.Fatal(err)
	}
	revoked := newEntity(t, "Alice", "alice@gnuweeb.org")
	ident := revoked.Identities["Alice <alice@gnuweeb.org>"]
	ident.Signatures = append(ident.Signatures,
		userIDSig(t, revoked, revoked, ident.Name, packet.SigTypeCertificationRevocation))

	tests := map[string]struct {
		input []byte
		want  string
	}{
		"other address":  {public(t, bob), "no valid, unrevoked User ID"},
		"revoked uid":    {public(t, revoked), "no valid, unrevoked User ID"},
		"two keys":       {append(public(t, alice), public(t, bob)...), "one key at a time"},
		"secret binary":  {secret.Bytes(), "secret key"},
		"secret armored": {armored(t, openpgp.PrivateKeyType, secret.Bytes()), "secret key"},
		"wrong armor":    {armored(t, "PGP MESSAGE", public(t, alice)), "expected"},
		"garbage":        {[]byte("hello"), "malformed"},
		"empty":          {nil, "no public key"},
		"truncated":      {public(t, alice)[:40], "malformed"},
		"too large":      {make([]byte, MaxSize+1), "larger than"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(tc.input, "alice@gnuweeb.org")
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// userIDSig makes a signature of sigType by signer over the User ID uid
// of target.
func userIDSig(t *testing.T, signer, target *openpgp.Entity, uid string, sigType packet.SignatureType) *packet.Signature {
	t.Helper()
	sig := &packet.Signature{
		Version:      signer.PrimaryKey.Version,
		SigType:      sigType,
		PubKeyAlgo:   signer.PrimaryKey.PubKeyAlgo,
		Hash:         testConfig.Hash(),
		CreationTime: testConfig.Now(),
		IssuerKeyId:  &signer.PrimaryKey.KeyId,
	}
	if err := sig.SignUserId(uid, target.PrimaryKey, signer.PrivateKey, testConfig); err != nil {
		t.Fatal(err)
	}
	return sig
}
