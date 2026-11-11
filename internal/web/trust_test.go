package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func TestTrustShowsDirectLinks(t *testing.T) {
	h := newHarness(t)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	newKey := func(email string) *openpgp.Entity {
		e, err := openpgp.NewEntity("Test", "", email, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	alice, alice2 := newKey("alice@gnuweeb.org"), newKey("alice@gnuweeb.org")
	bob, carol, dave := newKey("bob@gnuweeb.org"), newKey("carol@gnuweeb.org"), newKey("dave@example.org")
	sign := func(e *openpgp.Entity, uid string, signers ...*openpgp.Entity) {
		for _, s := range signers {
			if err := e.SignIdentity(uid, s, cfg); err != nil {
				t.Fatal(err)
			}
		}
	}
	// bob and dave (outside) certify alice, alice's second key certifies
	// her first, and alice certifies carol.
	sign(alice, "Test <alice@gnuweeb.org>", bob, dave, alice2)
	sign(carol, "Test <carol@gnuweeb.org>", alice)
	upload := func(address string, keys ...*openpgp.Entity) {
		c := h.loginAs(address)
		for _, k := range keys {
			if resp, _ := h.post(c, "/keys", url.Values{"key": {armoredEntity(t, k)}}); resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("%s's upload: status %d", address, resp.StatusCode)
			}
		}
	}
	upload("bob@gnuweeb.org", bob)
	upload("carol@gnuweeb.org", carol)
	upload("alice@gnuweeb.org", alice, alice2)

	sections := func(address string) (in, out string) {
		resp, body := h.get(h.loginAs(address), "/trust")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", address, resp.StatusCode)
		}
		in, out, ok := strings.Cut(body, "Certified by your keys")
		if !ok {
			t.Fatalf("%s: no outgoing section", address)
		}
		return in, out
	}

	in, out := sections("alice@gnuweeb.org")
	if !strings.Contains(in, ">bob@gnuweeb.org</a>") || strings.Contains(in, "carol@") {
		t.Error("alice's certifiers are not just bob")
	}
	if !strings.Contains(in, "Also certified by 1 key not in this directory") {
		t.Error("dave's certification is not counted")
	}
	if !strings.Contains(out, ">carol@gnuweeb.org</a>") || strings.Contains(out, "bob@") {
		t.Error("the members alice certified are not just carol")
	}
	// Her own second key is no link to another member.
	if strings.Contains(in, ">alice@gnuweeb.org</a>") || strings.Contains(out, ">alice@gnuweeb.org</a>") {
		t.Error("alice is listed as linked to herself")
	}

	in, out = sections("bob@gnuweeb.org")
	if !strings.Contains(in, "has certified yours yet") {
		t.Error("bob's certifiers are not empty")
	}
	if !strings.Contains(out, ">alice@gnuweeb.org</a>") || !strings.Contains(out, "Test &lt;alice@gnuweeb.org&gt;") {
		t.Error("bob's certification of alice is missing")
	}
}
