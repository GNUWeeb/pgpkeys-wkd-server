// Package wkd implements the key discovery part of the OpenPGP Web Key
// Directory (draft-koch-openpgp-webkey-service, direct method).
package wkd

import (
	"crypto/sha1" // #nosec G505 -- SHA-1 is mandated by the WKD draft.
	"strings"
)

// zbase32 is the alphabet of z-base-32 (RFC 6189, section 5.1.6).
const zbase32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

// HashLen is the length of a WKD hash: 160 bits in 5-bit characters.
const HashLen = 32

// Hash returns the WKD hash of the local-part of a mail address: ASCII
// upper case mapped to lower case, SHA-1, z-base-32. Other characters are
// hashed as they are, as the draft requires.
func Hash(local string) string {
	b := []byte(local)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	sum := sha1.Sum(b)

	out := make([]byte, 0, HashLen)
	var acc uint32
	bits := 0
	for _, c := range sum {
		acc = acc<<8 | uint32(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, zbase32[acc>>bits&31])
		}
	}
	return string(out)
}

// ValidHash reports whether s has the form of a WKD hash.
func ValidHash(s string) bool {
	if len(s) != HashLen {
		return false
	}
	for _, c := range []byte(s) {
		if strings.IndexByte(zbase32, c) < 0 {
			return false
		}
	}
	return true
}
