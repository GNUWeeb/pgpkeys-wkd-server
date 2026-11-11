package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func TestRootPaths(t *testing.T) {
	h := newHarness(t)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	names := map[*openpgp.Entity]string{}
	newKey := func(name string) *openpgp.Entity {
		e, err := openpgp.NewEntity(name, "", name+"@gnuweeb.org", cfg)
		if err != nil {
			t.Fatal(err)
		}
		names[e] = name
		return e
	}
	root, alice, bob, carol, dave := newKey("root"), newKey("alice"), newKey("bob"), newKey("carol"), newKey("dave")
	sign := func(e, by *openpgp.Entity) {
		if err := e.SignIdentity(names[e]+" <"+names[e]+"@gnuweeb.org>", by, cfg); err != nil {
			t.Fatal(err)
		}
	}
	// root -> alice -> bob, and bob also by carol; dave certified the
	// root, which does not connect dave; carol is certified by no one
	// connected.
	sign(alice, root)
	sign(bob, alice)
	sign(bob, carol)
	sign(root, dave)
	for _, e := range []*openpgp.Entity{root, alice, bob, carol, dave} {
		addr := names[e] + "@gnuweeb.org"
		if resp, _ := h.post(h.loginAs(addr), "/keys", url.Values{"key": {armoredEntity(t, e)}}); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("%s's upload: status %d", addr, resp.StatusCode)
		}
	}
	c := h.loginAs("bob@gnuweeb.org")

	// Without a root key, nothing is said about one.
	if _, body := h.get(c, "/members/bob@gnuweeb.org"); strings.Contains(body, "root key") {
		t.Error("member page mentions a root key while none is set")
	}

	h.srv.opts.RootKey = strings.ToUpper(fingerprintHex(root.PrimaryKey.Fingerprint))
	_, body := h.get(c, "/members/bob@gnuweeb.org")
	path := body[strings.Index(body, `class="path"`):]
	path = path[:strings.Index(path, "</ol>")]
	r, a, b := strings.Index(path, "root@gnuweeb.org"), strings.Index(path, "alice@gnuweeb.org"), strings.Index(path, "bob@gnuweeb.org")
	if r < 0 || r > a || a > b || strings.Contains(path, "carol@") {
		t.Errorf("bob's path is not root, alice, bob: %s", path)
	}

	_, list := h.get(c, "/members")
	for addr, want := range map[string]string{
		"root": "Root key", "alice": "1 step", "bob": "2 steps", "carol": "Not connected", "dave": "Not connected",
	} {
		row := list[strings.Index(list, `href="/members/`+addr+`@gnuweeb.org"`):]
		row = row[:strings.Index(row, "</tr>")]
		if !strings.Contains(row, want) {
			t.Errorf("%s's row lacks %q", addr, want)
		}
	}
	if _, body := h.get(h.loginAs("dave@gnuweeb.org"), "/trust"); !strings.Contains(body, "Not connected.") {
		t.Error("dave's web of trust page does not say he is not connected")
	}

	// A root key that is not stored connects no one.
	h.srv.opts.RootKey = strings.Repeat("A", 40)
	if _, list := h.get(c, "/members"); strings.Contains(list, "Root key</span>") || strings.Contains(list, "step") {
		t.Error("an unknown root key connects members")
	}
}
