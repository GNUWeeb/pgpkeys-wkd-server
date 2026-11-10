package keys

import (
	"encoding/binary"
	"errors"
)

// rawPacket is one OpenPGP packet, header included, as it appeared in the
// input.
type rawPacket struct {
	tag int
	raw []byte
}

var errMalformed = errors.New("the key data is malformed")

// splitPackets splits data into packets without interpreting their
// bodies (RFC 9580, section 4.2). Partial and indeterminate lengths only
// occur in data packets, never in keys, and are rejected.
func splitPackets(data []byte) ([]rawPacket, error) {
	var pkts []rawPacket
	for len(data) > 0 {
		hdr := data[0]
		if hdr&0x80 == 0 {
			return nil, errMalformed
		}
		var tag, hlen, blen int
		if hdr&0x40 != 0 {
			tag = int(hdr & 0x3f)
			if len(data) < 2 {
				return nil, errMalformed
			}
			switch o := data[1]; {
			case o < 192:
				hlen, blen = 2, int(o)
			case o < 224:
				if len(data) < 3 {
					return nil, errMalformed
				}
				hlen, blen = 3, (int(o)-192)<<8+int(data[2])+192
			case o == 255:
				if len(data) < 6 {
					return nil, errMalformed
				}
				hlen, blen = 6, int(binary.BigEndian.Uint32(data[2:6]))
			default:
				return nil, errMalformed
			}
		} else {
			tag = int(hdr>>2) & 0xf
			switch hdr & 3 {
			case 0:
				if len(data) < 2 {
					return nil, errMalformed
				}
				hlen, blen = 2, int(data[1])
			case 1:
				if len(data) < 3 {
					return nil, errMalformed
				}
				hlen, blen = 3, int(binary.BigEndian.Uint16(data[1:3]))
			case 2:
				if len(data) < 5 {
					return nil, errMalformed
				}
				hlen, blen = 5, int(binary.BigEndian.Uint32(data[1:5]))
			default:
				return nil, errMalformed
			}
		}
		if blen < 0 || blen > len(data)-hlen {
			return nil, errMalformed
		}
		n := hlen + blen
		pkts = append(pkts, rawPacket{tag: tag, raw: data[:n:n]})
		data = data[n:]
	}
	if len(pkts) == 0 {
		return nil, errors.New("no public key found")
	}
	return pkts, nil
}
