package keys

import (
	"fmt"
	"time"
)

// Info is what the dashboard shows about a stored key.
type Info struct {
	Fingerprint string
	// UserIDs are the self-signed User IDs in the order of the key.
	UserIDs []string
	Created time.Time
	// Expires is the zero time for a key that does not expire.
	Expires time.Time
	Expired bool
	Revoked bool
}

// Describe reads a key stored by Parse.
func Describe(data []byte, now time.Time) (Info, error) {
	ent, err := readKey(data)
	if err != nil {
		return Info{}, err
	}
	info := Info{
		Fingerprint: fmt.Sprintf("%X", ent.PrimaryKey.Fingerprint),
		Created:     ent.PrimaryKey.CreationTime,
		Revoked:     ent.Revoked(now),
	}
	// Identities is a map; the packets give the order the owner chose.
	pkts, err := splitPackets(data)
	if err != nil {
		return Info{}, err
	}
	for _, p := range pkts {
		if p.tag != tagUserID {
			continue
		}
		id := ent.Identities[string(p.raw[p.hdr:])]
		if id == nil {
			continue
		}
		if _, err := id.LatestValidSelfCertification(time.Time{}, permissive); err == nil {
			info.UserIDs = append(info.UserIDs, id.Name)
		}
	}
	if sig, _ := ent.PrimarySelfSignature(time.Time{}, permissive); sig != nil && sig.KeyLifetimeSecs != nil && *sig.KeyLifetimeSecs > 0 {
		info.Expires = info.Created.Add(time.Duration(*sig.KeyLifetimeSecs) * time.Second)
		info.Expired = now.After(info.Expires)
	}
	return info, nil
}
