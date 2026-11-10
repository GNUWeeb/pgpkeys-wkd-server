package keys

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// Signer is a stored key that may have certified other keys.
type Signer struct {
	Fingerprint string
	Data        []byte
}

// Certification is one of a key's User IDs certified by a signer.
type Certification struct {
	UserID  string
	Signer  string // the signer's fingerprint
	Created time.Time
}

// Certifications returns the certifications on the User IDs of the key
// stored in data that a key among signers made: verified, made with a
// hash the policy accepts, unexpired at now and not revoked by a later
// revocation from the same signer. The certifications a key makes on
// itself and those by keys not among signers are left out; the latter
// are counted in others.
func Certifications(data []byte, signers []Signer, now time.Time) (certs []Certification, others int, err error) {
	ent, err := readKey(data)
	if err != nil {
		return nil, 0, err
	}
	self := fmt.Sprintf("%X", ent.PrimaryKey.Fingerprint)
	parsed := map[string]*openpgp.Entity{}
	// signer finds the signer that issued sig, reading each candidate's
	// key only once.
	signer := func(sig *packet.Signature) (string, *openpgp.Entity) {
		for _, s := range signers {
			if s.Fingerprint == self || !mayHaveIssued(s.Fingerprint, sig) {
				continue
			}
			e, ok := parsed[s.Fingerprint]
			if !ok {
				e, _ = readKey(s.Data)
				parsed[s.Fingerprint] = e
			}
			if e != nil && sig.CheckKeyIdOrFingerprint(e.PrimaryKey) {
				return s.Fingerprint, e
			}
		}
		return "", nil
	}

	type pair struct{ uid, signer string }
	type state struct {
		cert, revoked *packet.Signature
	}
	found := map[pair]*state{}
	var order []pair
	for _, id := range ent.Identities {
		for _, vs := range id.OtherCertifications {
			sig := vs.Packet
			fpr, e := signer(sig)
			if e == nil {
				if sig.SigType != packet.SigTypeCertificationRevocation {
					others++
				}
				continue
			}
			if policy.RejectHashAlgorithm(sig.Hash) || e.PrimaryKey.VerifyUserIdSignature(id.Name, ent.PrimaryKey, sig) != nil {
				continue
			}
			p := pair{id.Name, fpr}
			st := found[p]
			if st == nil {
				st = &state{}
				found[p] = st
				order = append(order, p)
			}
			if sig.SigType == packet.SigTypeCertificationRevocation {
				if st.revoked == nil || sig.CreationTime.After(st.revoked.CreationTime) {
					st.revoked = sig
				}
			} else if !sig.SigExpired(now) && (st.cert == nil || sig.CreationTime.After(st.cert.CreationTime)) {
				st.cert = sig
			}
		}
	}
	for _, p := range order {
		st := found[p]
		if st.cert == nil || (st.revoked != nil && !st.revoked.CreationTime.Before(st.cert.CreationTime)) {
			continue
		}
		certs = append(certs, Certification{UserID: p.uid, Signer: p.signer, Created: st.cert.CreationTime})
	}
	slices.SortFunc(certs, func(a, b Certification) int {
		return cmp.Or(cmp.Compare(a.Signer, b.Signer), cmp.Compare(a.UserID, b.UserID))
	})
	return certs, others, nil
}

// mayHaveIssued reports whether the key with the fingerprint fpr can be
// the issuer sig names, judged by the fingerprint alone: the issuer
// fingerprint when sig has one, else the key ID, which is the last 16
// digits of a v4 fingerprint and the first 16 of a v6 one.
func mayHaveIssued(fpr string, sig *packet.Signature) bool {
	if len(sig.IssuerFingerprint) >= 20 {
		return strings.EqualFold(fmt.Sprintf("%X", sig.IssuerFingerprint), fpr)
	}
	if sig.IssuerKeyId == nil {
		return false
	}
	id := fmt.Sprintf("%016X", *sig.IssuerKeyId)
	switch len(fpr) {
	case 40:
		return strings.HasSuffix(fpr, id)
	case 64:
		return strings.HasPrefix(fpr, id)
	}
	return false
}
