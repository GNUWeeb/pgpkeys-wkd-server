package keys

import (
	"slices"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestDescribe(t *testing.T) {
	created := time.Unix(1_800_000_000, 0)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, KeyLifetimeSecs: 86400, Time: func() time.Time { return created }}
	e, err := openpgp.NewEntity("Alice", "", "alice@gnuweeb.org", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.AddUserId("Alice", "", "alice@example.org", cfg); err != nil {
		t.Fatal(err)
	}
	data := public(t, e)

	info, err := Describe(data, created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"Alice <alice@gnuweeb.org>", "Alice <alice@example.org>"}; !slices.Equal(info.UserIDs, want) {
		t.Errorf("UserIDs = %q, want %q", info.UserIDs, want)
	}
	if !info.Created.Equal(created) || !info.Expires.Equal(created.Add(24*time.Hour)) || info.Expired || info.Revoked {
		t.Errorf("before expiry: %+v", info)
	}
	if info, _ := Describe(data, created.Add(25*time.Hour)); !info.Expired {
		t.Error("not expired after its lifetime")
	}

	if err := e.RevokeKey(packet.KeyCompromised, "", cfg); err != nil {
		t.Fatal(err)
	}
	if info, _ := Describe(public(t, e), created.Add(time.Hour)); !info.Revoked {
		t.Error("revoked key not shown as revoked")
	}
}
