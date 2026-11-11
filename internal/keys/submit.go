package keys

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Submission is a certification a member submitted for another member's
// key, with its signature packet as it was submitted.
type Submission struct {
	Certification
	Packet []byte
}

// ReadSubmitted reads a key a member submitted to certify it: one public
// key, ASCII-armored or binary, without secret key material. It returns
// the binary key and its fingerprint. The errors are meant to be shown to
// the member.
func ReadSubmitted(input []byte) (data []byte, fingerprint string, err error) {
	if len(input) > MaxSize {
		return nil, "", fmt.Errorf("the key is larger than %d KiB", MaxSize>>10)
	}
	if data, err = dearmor(input); err != nil {
		return nil, "", err
	}
	pkts, err := splitPackets(data)
	if err != nil {
		return nil, "", err
	}
	primaries := 0
	for _, p := range pkts {
		switch p.tag {
		case tagSecretKey, tagSecretSubkey:
			return nil, "", errors.New("this is a secret key; submit only the public key (gpg --export)")
		case tagPublicKey:
			primaries++
		}
	}
	if primaries != 1 || pkts[0].tag != tagPublicKey {
		return nil, "", errors.New("submit exactly one public key")
	}
	pk, err := packet.Read(bytes.NewReader(pkts[0].raw))
	if err != nil {
		return nil, "", fmt.Errorf("the key cannot be read: %w", err)
	}
	pub, ok := pk.(*packet.PublicKey)
	if !ok {
		return nil, "", errors.New("the data does not start with a public key")
	}
	return data, fmt.Sprintf("%X", pub.Fingerprint), nil
}

// Submitted returns the certifications in data, a copy of the key stored
// in stored, that a key among signers made on a User ID the stored key
// has: verified against the stored key, made with a hash the policy
// accepts and unexpired at now, the latest per User ID and signer.
// Certifications already in stored and everything else in data are left
// out, so a submission can add certifications and nothing more.
func Submitted(data, stored []byte, signers []Signer, now time.Time) ([]Submission, error) {
	ent, err := readKey(stored)
	if err != nil {
		return nil, err
	}
	pkts, err := splitPackets(data)
	if err != nil {
		return nil, err
	}
	storedPkts, err := splitPackets(stored)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, p := range storedPkts {
		if p.tag == tagSignature {
			have[string(p.raw)] = true
		}
	}
	self := fmt.Sprintf("%X", ent.PrimaryKey.Fingerprint)

	type pair struct{ uid, signer string }
	found := map[pair]int{}
	var out []Submission
	uid := ""
	for _, p := range pkts {
		switch p.tag {
		case tagUserID:
			uid = string(p.raw[p.hdr:])
			continue
		case tagSignature:
		default:
			uid = ""
			continue
		}
		if uid == "" || ent.Identities[uid] == nil || have[string(p.raw)] {
			continue
		}
		parsed, err := packet.Read(bytes.NewReader(p.raw))
		if err != nil {
			continue
		}
		sig, ok := parsed.(*packet.Signature)
		if !ok || !isCertification(sig.SigType) || policy.RejectHashAlgorithm(sig.Hash) || sig.SigExpired(now) {
			continue
		}
		for _, s := range signers {
			if s.Fingerprint == self || !mayHaveIssued(s.Fingerprint, sig) {
				continue
			}
			signer, err := readKey(s.Data)
			if err != nil || !sig.CheckKeyIdOrFingerprint(signer.PrimaryKey) ||
				signer.PrimaryKey.VerifyUserIdSignature(uid, ent.PrimaryKey, sig) != nil {
				continue
			}
			sub := Submission{Certification{UserID: uid, Signer: s.Fingerprint, Created: sig.CreationTime}, p.raw}
			k := pair{uid, s.Fingerprint}
			if i, ok := found[k]; !ok {
				found[k] = len(out)
				out = append(out, sub)
			} else if sig.CreationTime.After(out[i].Created) {
				out[i] = sub
			}
			break
		}
	}
	return out, nil
}

func isCertification(t packet.SignatureType) bool {
	switch t {
	case packet.SigTypeGenericCert, packet.SigTypePersonaCert, packet.SigTypeCasualCert, packet.SigTypePositiveCert:
		return true
	}
	return false
}

// AddCertifications returns the key in data with each signature packet in
// add placed after the other signatures on its User ID. Packets the key
// already has, and those for User IDs it does not have, are left out.
func AddCertifications(data []byte, add []Submission) ([]byte, error) {
	pkts, err := splitPackets(data)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, p := range pkts {
		if p.tag == tagSignature {
			have[string(p.raw)] = true
		}
	}
	var out bytes.Buffer
	uid := ""
	flush := func() {
		for _, a := range add {
			if uid != "" && a.UserID == uid && !have[string(a.Packet)] {
				have[string(a.Packet)] = true
				out.Write(a.Packet)
			}
		}
		uid = ""
	}
	for _, p := range pkts {
		if p.tag != tagSignature {
			flush()
		}
		if p.tag == tagUserID {
			uid = string(p.raw[p.hdr:])
		}
		out.Write(p.raw)
	}
	flush()
	return out.Bytes(), nil
}
