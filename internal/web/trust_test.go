package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func TestSubmitAndAcceptCertification(t *testing.T) {
	h := newHarness(t)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	newKey := func(email string) *openpgp.Entity {
		e, err := openpgp.NewEntity("Test", "", email, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	alice, bob := newKey("alice@gnuweeb.org"), newKey("bob@gnuweeb.org")
	aliceClient, bobClient, carolClient := h.loginAs("alice@gnuweeb.org"), h.loginAs("bob@gnuweeb.org"), h.loginAs("carol@gnuweeb.org")
	for c, k := range map[*http.Client]*openpgp.Entity{aliceClient: alice, bobClient: bob} {
		if resp, _ := h.post(c, "/keys", url.Values{"key": {armoredEntity(t, k)}}); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("upload: status %d", resp.StatusCode)
		}
	}
	unknown, _ := armoredKey(t, "dave@gnuweeb.org")
	if err := alice.SignIdentity("Test <alice@gnuweeb.org>", bob, cfg); err != nil {
		t.Fatal(err)
	}
	certified := armoredEntity(t, alice)

	refused := func(c *http.Client, key, want string) {
		t.Helper()
		resp, body := h.post(c, "/trust/certify", url.Values{"key": {key}})
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, want) {
			t.Errorf("submission: status %d, want 422 with %q", resp.StatusCode, want)
		}
	}
	refused(carolClient, certified, "Add your own key first")
	refused(bobClient, armoredEntity(t, bob), "This is your own key")
	refused(bobClient, unknown, "not in the directory")
	refused(aliceClient, certified, "This is your own key")

	resp, _ := h.post(bobClient, "/trust/certify", url.Values{"key": {certified}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/trust?done=submitted" {
		t.Fatalf("submission: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	h.srv.Wait()
	asked := 0
	for _, m := range h.mailer.all() {
		if strings.Contains(m.subject, "certified your OpenPGP key") {
			asked++
			if m.to != "alice@gnuweeb.org" || !strings.Contains(m.body, "https://pgp.gnuweeb.org/trust") {
				t.Errorf("request mail to %s: %q", m.to, m.body)
			}
		}
	}
	if asked != 1 {
		t.Errorf("%d request mails, want 1", asked)
	}
	// Until alice accepts, the certification only waits.
	if _, body := h.get(bobClient, "/trust"); !strings.Contains(body, "Sent, waiting for approval") {
		t.Error("bob's page does not show the request he sent")
	}
	_, body := h.get(aliceClient, "/trust")
	m := regexp.MustCompile(`/trust/requests/(\d+)/accept`).FindStringSubmatch(body)
	if m == nil || !strings.Contains(body, "No member") {
		t.Fatal("alice's page does not show the request as waiting")
	}
	if resp, _ := h.post(bobClient, "/trust/requests/"+m[1]+"/accept", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("bob accepts his own request: status %d", resp.StatusCode)
	}
	if resp, _ := h.post(aliceClient, "/trust/requests/"+m[1]+"/accept", nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("alice accepts: status %d", resp.StatusCode)
	}
	in, _ := sectionsOf(t, h, aliceClient)
	if !strings.Contains(in, ">bob@gnuweeb.org</a>") || strings.Contains(in, "Waiting for your approval") {
		t.Error("alice's page does not show bob's accepted certification")
	}
	if _, out := sectionsOf(t, h, bobClient); !strings.Contains(out, ">alice@gnuweeb.org</a>") || strings.Contains(out, "Sent, waiting") {
		t.Error("bob's page does not show his accepted certification")
	}
	refused(bobClient, certified, "does not have already")
}

// sectionsOf splits the client's web of trust page at the list of keys
// its keys certified.
func sectionsOf(t *testing.T, h *harness, c *http.Client) (in, out string) {
	t.Helper()
	resp, body := h.get(c, "/trust")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	in, out, ok := strings.Cut(body, "Certified by your keys")
	if !ok {
		t.Fatal("no outgoing section")
	}
	return in, out
}

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
