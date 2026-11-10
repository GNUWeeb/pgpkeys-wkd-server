package keys

import (
	"crypto"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// ExpiryNotice is how long before a key stops being usable the dashboard
// starts to warn about it; the first reminder mail goes out then too.
const ExpiryNotice = 30 * 24 * time.Hour

// policy is the usability rule kernel.org applies with sq, in go-crypto
// terms: self-signatures made with MD5, SHA-1 or RIPEMD-160 do not count,
// and DSA and ElGamal keys, RSA keys under 2048 bits and the curves
// go-crypto refuses by default cannot be used.
var policy = &packet.Config{
	RejectHashAlgorithms: map[crypto.Hash]bool{
		crypto.MD5:       true,
		crypto.SHA1:      true,
		crypto.RIPEMD160: true,
	},
	RejectPublicKeyAlgorithms: map[packet.PublicKeyAlgorithm]bool{
		packet.PubKeyAlgoDSA:     true,
		packet.PubKeyAlgoElGamal: true,
	},
}

// Health is a key judged by the usability rule: a key is usable when its
// primary key is valid and at least one of its keys may make signatures,
// all under the policy above.
type Health struct {
	Usable bool
	// SigningUntil is when the last usable signing key stops being
	// usable: the zero time when one of them does not expire, or when
	// the key is not usable.
	SigningUntil time.Time
	// Problems say what is wrong and how to fix it, most serious first.
	Problems []Problem
}

// Problem is one thing about a key that its owner should fix.
type Problem struct {
	// Severe problems make the key unusable or are about to; the
	// others only warn.
	Severe bool
	Text   string
	Fix    string
	// Commands carry out Fix with GnuPG.
	Commands []string
}

// Check judges the key stored by Parse in data at the time now.
func Check(data []byte, now time.Time) (Health, error) {
	// go-crypto caches each signature's verdict, including whether it
	// had expired at the time asked about. Each copy is therefore only
	// asked one kind of question: strict about now under the policy,
	// anyTime under the policy without a time, loose without either.
	var copies [3]*openpgp.Entity
	for i := range copies {
		ent, err := readKey(data)
		if err != nil {
			return Health{}, err
		}
		copies[i] = ent
	}
	strict, anyTime, loose := copies[0], copies[1], copies[2]
	fpr := fmt.Sprintf("%X", strict.PrimaryKey.Fingerprint)
	extend := []string{
		"gpg --quick-set-expire " + fpr + " 5y",
		"gpg --quick-set-expire " + fpr + " 5y '*'",
	}
	resign := resignCommands(fpr)
	addSigning := []string{"gpg --quick-add-key " + fpr + " ed25519 sign 5y"}

	var h Health
	if strict.Revoked(now) {
		h.Problems = append(h.Problems, Problem{
			Severe: true,
			Text:   "The key is revoked.",
			Fix:    "A revoked key stays revoked. Create a new key and add it here; keep this one listed so that signatures made before the revocation can still be checked.",
		})
		return h, nil
	}

	if weak := weakHashes(anyTime, loose); weak != "" {
		h.Problems = append(h.Problems, Problem{
			Text:     "Some of the key's self-signatures use " + weak + ", which is no longer accepted.",
			Fix:      weakHashFix,
			Commands: resign,
		})
	}
	if alg := weakAlgorithm(strict.PrimaryKey); alg != "" {
		h.Problems = append(h.Problems, Problem{
			Severe: true,
			Text:   "The primary key uses " + alg + ", which is no longer accepted.",
			Fix:    "Create a new key with a current algorithm such as Ed25519 and add it here.",
		})
	}

	primarySig, err := strict.VerifyPrimaryKey(now, policy)
	primaryOK := err == nil && weakAlgorithm(strict.PrimaryKey) == ""
	if errors.Is(err, pgperrors.ErrKeyExpired) {
		h.Problems = append(h.Problems, Problem{
			Severe:   true,
			Text:     "The key expired on " + day(primaryEnd(anyTime, primarySig)) + ".",
			Fix:      "Extend its expiry date, then upload the key again. Nobody needs to sign it again.",
			Commands: extend,
		})
	}

	var ends []time.Time
	if primaryOK {
		end := primaryEnd(anyTime, primarySig)
		if primarySig.FlagsValid && primarySig.FlagSign {
			ends = append(ends, end)
		}
		for i := range strict.Subkeys {
			sub := &strict.Subkeys[i]
			sig, err := sub.Verify(now, policy)
			if err != nil || !canSign(sub.PublicKey, sig) {
				continue
			}
			ends = append(ends, earliest(subkeyEnd(sub.PublicKey, sig), end))
		}
	}
	h.Usable = len(ends) > 0
	switch {
	case h.Usable:
		if slices.ContainsFunc(ends, time.Time.IsZero) {
			break
		}
		h.SigningUntil = slices.MaxFunc(ends, time.Time.Compare)
		if !h.SigningUntil.After(now.Add(ExpiryNotice)) {
			h.Problems = append(h.Problems, Problem{
				Severe:   true,
				Text:     "Signing with this key stops on " + day(h.SigningUntil) + ".",
				Fix:      "Extend its expiry date before then, then upload the key again. Nobody needs to sign it again.",
				Commands: extend,
			})
		}
	case primaryOK:
		if p, ok := signingProblem(anyTime, loose, now, fpr, addSigning); ok {
			h.Problems = append(h.Problems, p)
		}
	}
	if !h.Usable {
		// A weak hash that a usable key can live with may be what
		// makes this one unusable.
		for i := range h.Problems {
			h.Problems[i].Severe = true
		}
		if len(h.Problems) == 0 {
			h.Problems = append(h.Problems, Problem{
				Severe:   true,
				Text:     "None of the key's self-signatures is valid.",
				Fix:      "Make new self-signatures, then upload the key again. Extending the expiry date makes them.",
				Commands: resign,
			})
		}
	}
	slices.SortStableFunc(h.Problems, func(a, b Problem) int {
		switch {
		case a.Severe == b.Severe:
			return 0
		case a.Severe:
			return -1
		}
		return 1
	})
	return h, nil
}

// signingProblem explains why a key whose primary key is valid has no
// usable signing key. It reports false when a weak hash, which Check
// reports on its own, is the reason.
func signingProblem(strict, loose *openpgp.Entity, now time.Time, fpr string, addSigning []string) (Problem, bool) {
	var expired []*packet.PublicKey
	var weakAlg []string
	weakHash := false
	for i := range loose.Subkeys {
		sub := &loose.Subkeys[i]
		sig, err := sub.LatestValidBindingSignature(time.Time{}, permissive)
		if err != nil || !sub.PublicKey.PubKeyAlgo.CanSign() || !sig.FlagsValid || !sig.FlagSign || sub.Revoked(sig, now) {
			continue
		}
		if alg := weakAlgorithm(sub.PublicKey); alg != "" {
			weakAlg = append(weakAlg, alg)
			continue
		}
		if strictSig, err := strict.Subkeys[i].LatestValidBindingSignature(time.Time{}, policy); err != nil || !canSign(sub.PublicKey, strictSig) {
			weakHash = true
			continue
		}
		if sub.Expired(sig, now) {
			expired = append(expired, sub.PublicKey)
		}
	}
	switch {
	case len(expired) > 0:
		var cmds []string
		for _, pk := range expired {
			cmds = append(cmds, fmt.Sprintf("gpg --quick-set-expire %s 5y %X", fpr, pk.Fingerprint))
		}
		return Problem{
			Severe:   true,
			Text:     "The key's signing subkey has expired, so the key cannot sign.",
			Fix:      "Extend the signing subkey's expiry date, then upload the key again. Nobody needs to sign it again.",
			Commands: cmds,
		}, true
	case len(weakAlg) > 0:
		return Problem{
			Severe:   true,
			Text:     "The key's signing subkey uses " + strings.Join(weakAlg, " and ") + ", which is no longer accepted.",
			Fix:      "Add a signing subkey with a current algorithm, then upload the key again.",
			Commands: addSigning,
		}, true
	case weakHash:
		return Problem{}, false
	}
	return Problem{
		Severe:   true,
		Text:     "The key has no key that may sign.",
		Fix:      "Add a signing subkey, then upload the key again.",
		Commands: addSigning,
	}, true
}

// weakHashes names the refused hash algorithms of self-signatures that
// the policy throws out where they would count: a User ID or subkey whose
// binding holds only by such a signature, or a signing subkey's back
// signature. strict and loose are two readings of the same key.
func weakHashes(strict, loose *openpgp.Entity) string {
	var names []string
	add := func(h crypto.Hash) {
		if policy.RejectHashAlgorithm(h) && !slices.Contains(names, hashName(h)) {
			names = append(names, hashName(h))
		}
	}
	for name, id := range strict.Identities {
		if _, err := id.LatestValidSelfCertification(time.Time{}, policy); err == nil {
			continue
		}
		if sig, err := loose.Identities[name].LatestValidSelfCertification(time.Time{}, permissive); err == nil {
			add(sig.Hash)
		}
	}
	for i := range strict.Subkeys {
		if sig, err := strict.Subkeys[i].LatestValidBindingSignature(time.Time{}, policy); err == nil {
			if sig.EmbeddedSignature != nil {
				add(sig.EmbeddedSignature.Hash)
			}
			continue
		}
		if sig, err := loose.Subkeys[i].LatestValidBindingSignature(time.Time{}, permissive); err == nil {
			add(sig.Hash)
			if sig.EmbeddedSignature != nil {
				add(sig.EmbeddedSignature.Hash)
			}
		}
	}
	return strings.Join(names, " and ")
}

func hashName(h crypto.Hash) string {
	switch h {
	case crypto.MD5:
		return "MD5"
	case crypto.SHA1:
		return "SHA-1"
	case crypto.RIPEMD160:
		return "RIPEMD-160"
	}
	return h.String()
}

// weakAlgorithm names the public key algorithm of pk when the policy
// refuses it.
func weakAlgorithm(pk *packet.PublicKey) string {
	switch alg := pk.PubKeyAlgo; {
	case alg == packet.PubKeyAlgoDSA:
		return "DSA"
	case alg == packet.PubKeyAlgoElGamal:
		return "ElGamal"
	case policy.RejectPublicKeyAlgorithm(alg):
		return fmt.Sprintf("public key algorithm %d", alg)
	case alg == packet.PubKeyAlgoRSA || alg == packet.PubKeyAlgoRSASignOnly:
		if bits, err := pk.BitLength(); err != nil || bits < policy.MinimumRSABits() {
			return fmt.Sprintf("RSA with %d bits", bits)
		}
	case alg == packet.PubKeyAlgoECDH || alg == packet.PubKeyAlgoECDSA || alg == packet.PubKeyAlgoEdDSA:
		if curve, err := pk.Curve(); err != nil || policy.RejectCurve(curve) {
			return "the curve " + string(curve)
		}
	}
	return ""
}

// canSign reports whether the subkey pk, bound by sig, may sign under the
// policy. A signing subkey's binding carries a back signature by the
// subkey, whose hash must pass too.
func canSign(pk *packet.PublicKey, sig *packet.Signature) bool {
	return pk.PubKeyAlgo.CanSign() && sig.FlagsValid && sig.FlagSign &&
		weakAlgorithm(pk) == "" &&
		(sig.EmbeddedSignature == nil || !policy.RejectHashAlgorithm(sig.EmbeddedSignature.Hash))
}

// primaryEnd is when the primary key expires by its self-signature and
// direct-key signature, or the zero time.
func primaryEnd(ent *openpgp.Entity, sig *packet.Signature) time.Time {
	var end time.Time
	if sig != nil {
		end = subkeyEnd(ent.PrimaryKey, sig)
	}
	if direct, err := ent.LatestValidDirectSignature(time.Time{}, policy); err == nil {
		end = earliest(end, subkeyEnd(ent.PrimaryKey, direct))
	}
	return end
}

// subkeyEnd is when pk expires by the lifetime in sig, or the zero time.
func subkeyEnd(pk *packet.PublicKey, sig *packet.Signature) time.Time {
	if sig.KeyLifetimeSecs == nil || *sig.KeyLifetimeSecs == 0 {
		return time.Time{}
	}
	return pk.CreationTime.Add(time.Duration(*sig.KeyLifetimeSecs) * time.Second)
}

// earliest returns the earlier of a and b, where the zero time is never.
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero() || a.Before(b):
		return a
	}
	return b
}

const weakHashFix = "Make new self-signatures with a current hash, then upload the key again. The commands below do that: they extend the expiry date and sign with SHA-512."

// resignCommands make new self-signatures on the key fpr. GnuPG 2.4 keeps
// the hash of a self-signature it replaces, so they name a current one.
func resignCommands(fpr string) []string {
	return []string{
		"gpg --cert-digest-algo SHA512 --quick-set-expire " + fpr + " 5y",
		"gpg --cert-digest-algo SHA512 --quick-set-expire " + fpr + " 5y '*'",
	}
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }
