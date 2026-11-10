package keys

import (
	"crypto"
	_ "embed"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// dsaKey is a DSA-2048 key made with GnuPG 2.4: gpg --quick-gen-key
// 'Dave <dave@gnuweeb.org>' dsa2048 sign 0.
//
//go:embed testdata/dsa.asc
var dsaKey []byte

var created = time.Unix(1_800_000_000, 0)

// keyConfig makes keys at created that live for lifetime (0: forever),
// with self-signatures made with hash.
func keyConfig(lifetime time.Duration, hash crypto.Hash) *packet.Config {
	return &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		DefaultHash:     hash,
		KeyLifetimeSecs: uint32(lifetime / time.Second),
		Time:            func() time.Time { return created },
	}
}

func checkKey(t *testing.T, data []byte, now time.Time) Health {
	t.Helper()
	h, err := Check(data, now)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// wantProblem fails unless h has a problem whose text contains text, with
// the given severity.
func wantProblem(t *testing.T, h Health, text string, severe bool) Problem {
	t.Helper()
	for _, p := range h.Problems {
		if strings.Contains(p.Text, text) {
			if p.Severe != severe {
				t.Errorf("problem %q: Severe = %v, want %v", p.Text, p.Severe, severe)
			}
			return p
		}
	}
	t.Fatalf("no problem mentions %q: %+v", text, h.Problems)
	return Problem{}
}

// certifyOnly makes e's primary key a certification-only key, as GnuPG
// does with "cert" keys and most keys that have a signing subkey.
func certifyOnly(t *testing.T, e *openpgp.Entity, cfg *packet.Config) {
	t.Helper()
	for _, id := range e.Identities {
		sig := id.SelfCertifications[len(id.SelfCertifications)-1].Packet
		sig.FlagSign = false
		if err := id.ReSign(cfg); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCheckUsable(t *testing.T) {
	e, err := openpgp.NewEntity("Alice", "", "alice@gnuweeb.org", keyConfig(0, crypto.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	h := checkKey(t, public(t, e), created.Add(time.Hour))
	if !h.Usable || !h.SigningUntil.IsZero() || len(h.Problems) != 0 {
		t.Errorf("Check = %+v, want usable without expiry or problems", h)
	}
}

func TestCheckExpiry(t *testing.T) {
	life := 100 * 24 * time.Hour
	e, err := openpgp.NewEntity("Alice", "", "alice@gnuweeb.org", keyConfig(life, crypto.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	data := public(t, e)
	end := created.Add(life)

	h := checkKey(t, data, end.Add(-ExpiryNotice-time.Hour))
	if !h.Usable || !h.SigningUntil.Equal(end) || len(h.Problems) != 0 {
		t.Errorf("before the notice: %+v, want usable until %v without problems", h, end)
	}
	h = checkKey(t, data, end.Add(-ExpiryNotice+time.Hour))
	if !h.Usable || !h.SigningUntil.Equal(end) {
		t.Errorf("within the notice: %+v, want usable until %v", h, end)
	}
	p := wantProblem(t, h, "stops on "+day(end), true)
	if len(p.Commands) != 2 || !strings.HasPrefix(p.Commands[0], "gpg --quick-set-expire ") {
		t.Errorf("commands = %q, want the two that extend the key", p.Commands)
	}
	h = checkKey(t, data, end.Add(time.Hour))
	if h.Usable {
		t.Error("expired key is usable")
	}
	wantProblem(t, h, "expired on "+day(end), true)
}

func TestCheckSigningSubkey(t *testing.T) {
	cfg := keyConfig(0, crypto.SHA256)
	e, err := openpgp.NewEntity("Alice", "", "alice@gnuweeb.org", cfg)
	if err != nil {
		t.Fatal(err)
	}
	certifyOnly(t, e, cfg)
	now := created.Add(time.Hour)

	h := checkKey(t, public(t, e), now)
	if h.Usable {
		t.Error("key without a signing key is usable")
	}
	p := wantProblem(t, h, "no key that may sign", true)
	if len(p.Commands) != 1 || !strings.HasPrefix(p.Commands[0], "gpg --quick-add-key ") {
		t.Errorf("commands = %q, want the one that adds a signing subkey", p.Commands)
	}

	// A signing subkey that expires first: the key signs until then.
	life := 50 * 24 * time.Hour
	if err := e.AddSigningSubkey(keyConfig(life, crypto.SHA256)); err != nil {
		t.Fatal(err)
	}
	h = checkKey(t, public(t, e), now)
	if !h.Usable || !h.SigningUntil.Equal(created.Add(life)) {
		t.Errorf("with a signing subkey: %+v, want usable until %v", h, created.Add(life))
	}
	h = checkKey(t, public(t, e), created.Add(life+time.Hour))
	if h.Usable {
		t.Error("key whose only signing subkey expired is usable")
	}
	p = wantProblem(t, h, "signing subkey has expired", true)
	sub := e.Subkeys[len(e.Subkeys)-1].PublicKey
	if len(p.Commands) != 1 || !strings.HasSuffix(p.Commands[0], strings.ToUpper(fingerprintHex(sub.Fingerprint))) {
		t.Errorf("commands = %q, want one that extends the subkey", p.Commands)
	}
}

func TestCheckRevoked(t *testing.T) {
	cfg := keyConfig(0, crypto.SHA256)
	e, err := openpgp.NewEntity("Alice", "", "alice@gnuweeb.org", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Revoke(packet.KeyRetired, "", cfg); err != nil {
		t.Fatal(err)
	}
	h := checkKey(t, public(t, e), created.Add(time.Hour))
	if h.Usable || len(h.Problems) != 1 {
		t.Errorf("Check = %+v, want unusable with one problem", h)
	}
	wantProblem(t, h, "revoked", true)
}

// sha1Only replaces the self-signature of e's User ID uid with one made
// with SHA-1; go-crypto refuses to make such keys itself.
func sha1Only(t *testing.T, e *openpgp.Entity, uid string) {
	t.Helper()
	id := e.Identities[uid]
	sig := *id.SelfCertifications[len(id.SelfCertifications)-1].Packet
	sig.Hash = crypto.SHA1
	noSalt := false // go-crypto's salt notation has no salt length for SHA-1
	if err := sig.SignUserId(uid, e.PrimaryKey, e.PrivateKey, &packet.Config{NonDeterministicSignaturesViaNotation: &noSalt}); err != nil {
		t.Fatal(err)
	}
	id.SelfCertifications = []*packet.VerifiableSignature{packet.NewVerifiableSig(&sig)}
}

func TestCheckWeakHash(t *testing.T) {
	now := created.Add(time.Hour)
	sha1Key, err := openpgp.NewEntity("Alice", "", "alice@gnuweeb.org", keyConfig(0, crypto.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	sha1Only(t, sha1Key, "Alice <alice@gnuweeb.org>")
	h := checkKey(t, public(t, sha1Key), now)
	if h.Usable {
		t.Error("key self-signed only with SHA-1 is usable")
	}
	p := wantProblem(t, h, "SHA-1", true)
	if len(p.Commands) != 2 {
		t.Errorf("commands = %q, want the two that re-sign the key", p.Commands)
	}

	// One User ID bound with SHA-1 on an otherwise sound key: a warning.
	e, err := openpgp.NewEntity("Alice", "", "alice@gnuweeb.org", keyConfig(0, crypto.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.AddUserId("Alice", "", "alice@example.org", keyConfig(0, crypto.SHA256)); err != nil {
		t.Fatal(err)
	}
	sha1Only(t, e, "Alice <alice@example.org>")
	h = checkKey(t, public(t, e), now)
	if !h.Usable {
		t.Error("sound key with one SHA-1 User ID is not usable")
	}
	wantProblem(t, h, "SHA-1", false)
}

func TestCheckDSA(t *testing.T) {
	data, err := dearmor(dsaKey)
	if err != nil {
		t.Fatal(err)
	}
	h := checkKey(t, data, time.Now())
	if h.Usable {
		t.Error("DSA key is usable")
	}
	wantProblem(t, h, "uses DSA", true)
}

func fingerprintHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
