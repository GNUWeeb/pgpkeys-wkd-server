// Package keys checks uploaded OpenPGP public keys and derives the form
// in which Web Key Directory serves them.
package keys

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

// MaxSize caps an uploaded key, armored or binary.
const MaxSize = 1 << 20

// OpenPGP packet tags (RFC 9580, section 5).
const (
	tagSignature     = 2
	tagSecretKey     = 5
	tagPublicKey     = 6
	tagSecretSubkey  = 7
	tagUserID        = 13
	tagPublicSubkey  = 14
	tagUserAttribute = 17
)

// Key is an uploaded public key that passed the checks of Parse.
type Key struct {
	// Fingerprint is the primary key's fingerprint in upper-case hex.
	Fingerprint string
	// Created is the primary key's creation time.
	Created time.Time
	// Data is the key as uploaded, in binary form.
	Data []byte
	// WKD is the key as Web Key Directory serves it: Data without
	// third-party certifications.
	WKD []byte
}

// Unusable is the error Parse returns for a key that the usability rule
// refuses; Problem says why and how to fix it.
type Unusable struct {
	Problem Problem
}

func (e *Unusable) Error() string { return strings.TrimSuffix(e.Problem.Text, ".") }

// Parse checks an uploaded key for the member with the given address and
// returns it with its WKD view. The input may be ASCII-armored or binary.
// It must hold exactly one public key, no secret key material, and a
// User ID with the address that is self-signed and not revoked. The key
// must be usable at the time now (see Check), with the address's User ID
// self-signed with an accepted hash; a revoked key is accepted so that
// the revocation reaches those who fetch it. The errors are meant to be
// shown to the member.
func Parse(input []byte, address string, now time.Time) (*Key, error) {
	if len(input) > MaxSize {
		return nil, fmt.Errorf("the key is larger than %d KiB", MaxSize>>10)
	}
	data, err := dearmor(input)
	if err != nil {
		return nil, err
	}
	pkts, err := splitPackets(data)
	if err != nil {
		return nil, err
	}
	primaries := 0
	for _, p := range pkts {
		switch p.tag {
		case tagSecretKey, tagSecretSubkey:
			return nil, errors.New("this is a secret key; upload only the public key (gpg --export)")
		case tagPublicKey:
			primaries++
		}
	}
	switch {
	case primaries == 0:
		return nil, errors.New("no public key found")
	case primaries > 1:
		return nil, errors.New("upload one key at a time")
	case pkts[0].tag != tagPublicKey:
		return nil, errors.New("the data does not start with a public key")
	}

	ent, err := readKey(data)
	if err != nil {
		if alg := unsupportedHash(pkts); alg != "" {
			return nil, fmt.Errorf("the key's signatures use %s, which is no longer accepted; create a new key", alg)
		}
		return nil, fmt.Errorf("the key cannot be read: %w", err)
	}
	if !hasAddress(ent, address, permissive) {
		return nil, fmt.Errorf("the key has no valid, unrevoked User ID with the address %s", address)
	}
	fpr := fmt.Sprintf("%X", ent.PrimaryKey.Fingerprint)
	h, err := Check(data, now)
	if err != nil {
		return nil, fmt.Errorf("the key cannot be read: %w", err)
	}
	if !h.Usable && !ent.Revoked(now) {
		return nil, &Unusable{h.Problems[0]}
	}
	strict, err := readKey(data)
	if err != nil {
		return nil, fmt.Errorf("the key cannot be read: %w", err)
	}
	if !ent.Revoked(now) && !hasAddress(strict, address, policy) {
		return nil, &Unusable{Problem{
			Severe:   true,
			Text:     "The User ID with " + address + " is self-signed only with a hash that is no longer accepted.",
			Fix:      weakHashFix,
			Commands: resignCommands(fpr),
		}}
	}

	view := wkdView(pkts, ent.PrimaryKey)
	return &Key{
		Fingerprint: fpr,
		Created:     ent.PrimaryKey.CreationTime,
		Data:        data,
		WKD:         view,
	}, nil
}

// unsupportedHash names MD5 or RIPEMD-160 when a signature in pkts uses
// it. go-crypto does not read such signatures at all, so a key that has
// only those cannot be read.
func unsupportedHash(pkts []rawPacket) string {
	for _, p := range pkts {
		body := p.raw[p.hdr:]
		// A v4 signature starts with version, type, public key algorithm
		// and hash algorithm (RFC 9580, section 5.2.3).
		if p.tag != tagSignature || len(body) < 4 || body[0] != 4 {
			continue
		}
		switch body[3] {
		case 1:
			return "MD5"
		case 3:
			return "RIPEMD-160"
		}
	}
	return ""
}

func dearmor(input []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(input)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return input, nil
	}
	block, err := armor.Decode(bytes.NewReader(trimmed))
	if err != nil {
		return nil, fmt.Errorf("the armor cannot be decoded: %w", err)
	}
	switch block.Type {
	case openpgp.PublicKeyType:
	case openpgp.PrivateKeyType:
		return nil, errors.New("this is a secret key; upload only the public key (gpg --export)")
	default:
		return nil, fmt.Errorf("expected a %q block, got %q", openpgp.PublicKeyType, block.Type)
	}
	data, err := io.ReadAll(io.LimitReader(block.Body, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("the armor cannot be decoded: %w", err)
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("the key is larger than %d KiB", MaxSize>>10)
	}
	return data, nil
}

// permissive judges signatures by their cryptography alone: no hash or
// public key algorithm is refused. go-crypto caches the outcome of each
// signature check in the parsed key, so a key read for one config must not
// be checked with another.
var permissive = &packet.Config{
	RejectHashAlgorithms:      map[crypto.Hash]bool{},
	RejectPublicKeyAlgorithms: map[packet.PublicKeyAlgorithm]bool{},
	RejectCurves:              map[packet.Curve]bool{},
	MinRSABits:                1,
}

// readKey parses the one key in data.
func readKey(data []byte) (*openpgp.Entity, error) {
	ents, err := openpgp.ReadKeyRing(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if len(ents) != 1 {
		return nil, errors.New("not exactly one key")
	}
	return ents[0], nil
}

// hasAddress reports whether ent has a User ID whose mail address is
// address, compared case-insensitively, that is self-signed and not
// revoked when judged by cfg.
func hasAddress(ent *openpgp.Entity, address string, cfg *packet.Config) bool {
	for _, id := range ent.Identities {
		if !strings.EqualFold(userIDAddress(id.UserId), address) {
			continue
		}
		if _, err := id.Verify(time.Time{}, cfg); err == nil {
			return true
		}
	}
	return false
}

// userIDAddress returns the mail address of a User ID: the part in angle
// brackets, or the whole User ID when it is a bare address.
func userIDAddress(id *packet.UserId) string {
	if id.Email != "" {
		return id.Email
	}
	if s := strings.TrimSpace(id.Id); strings.Contains(s, "@") && !strings.ContainsAny(s, " <>") {
		return s
	}
	return ""
}

// wkdView rebuilds the packet stream without third-party certifications:
// a signature after a User ID or User Attribute is kept only when the
// primary key issued it, and a User ID or User Attribute left without
// signatures is dropped. Signatures on the primary key and on subkeys are
// kept, so revocations by a designated revoker still reach clients.
// Packets other than keys, User IDs, User Attributes and signatures (trust,
// marker, padding) are dropped.
func wkdView(pkts []rawPacket, primary *packet.PublicKey) []byte {
	var out bytes.Buffer
	var section []rawPacket // a User ID or User Attribute and its kept signatures
	inIdentity := false
	flush := func() {
		if len(section) > 1 {
			for _, p := range section {
				out.Write(p.raw)
			}
		}
		section = section[:0]
	}

	for _, p := range pkts {
		switch p.tag {
		case tagPublicKey, tagPublicSubkey:
			flush()
			inIdentity = false
			out.Write(p.raw)
		case tagUserID, tagUserAttribute:
			flush()
			inIdentity = true
			section = append(section, p)
		case tagSignature:
			if !inIdentity {
				out.Write(p.raw)
				continue
			}
			parsed, err := packet.Read(bytes.NewReader(p.raw))
			if err != nil {
				continue
			}
			if sig, ok := parsed.(*packet.Signature); ok && sig.CheckKeyIdOrFingerprint(primary) {
				section = append(section, p)
			}
		}
	}
	flush()
	return out.Bytes()
}
