package web

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/wkd"
)

func TestMemberPage(t *testing.T) {
	h := newHarness(t)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	alice, err := openpgp.NewEntity("Alice Liddell", "", "alice@gnuweeb.org", cfg)
	if err != nil {
		t.Fatal(err)
	}
	carol, err := openpgp.NewEntity("Carol", "", "carol@example.org", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.SignIdentity("Alice Liddell <alice@gnuweeb.org>", carol, cfg); err != nil {
		t.Fatal(err)
	}
	if resp, _ := h.post(h.loginAs("alice@gnuweeb.org"), "/keys", url.Values{"key": {armoredEntity(t, alice)}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("upload: status %d", resp.StatusCode)
	}
	bob := h.loginAs("bob@gnuweeb.org")

	resp, body := h.get(bob, "/members/alice@gnuweeb.org")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("member page: status %d", resp.StatusCode)
	}
	fpr := strings.ToUpper(fingerprintHex(alice.PrimaryKey.Fingerprint))
	for _, want := range []string{"Alice Liddell", ">AL<", groupedFpr(fpr), "gpg --locate-keys alice@gnuweeb.org"} {
		if !strings.Contains(body, want) {
			t.Errorf("member page lacks %q", want)
		}
	}
	// Who certified a key stays off other members' pages.
	if strings.Contains(body, "arol") || strings.Contains(body, "ertified by") {
		t.Error("member page names a certifier")
	}
	if resp, _ := h.get(bob, "/members/nobody@gnuweeb.org"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("member without keys: status %d", resp.StatusCode)
	}

	resp, err = bob.Get(h.ts.URL + "/members/alice@gnuweeb.org/keys.asc")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/pgp-keys" {
		t.Fatalf("download: status %d, %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	block, err := armor.Decode(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(block.Body)
	if err != nil {
		t.Fatal(err)
	}
	views, err := h.srv.store.WKDKeys(context.Background(), wkd.Hash("alice"))
	if err != nil || len(views) != 1 || !bytes.Equal(got, views[0]) {
		t.Errorf("download is not what WKD serves (%v)", err)
	}
	if certs, others, err := keys.Certifications(got, nil, h.now); err != nil || len(certs)+others != 0 {
		t.Errorf("download carries certifications: %d, %d, %v", len(certs), others, err)
	}
}

func TestInitials(t *testing.T) {
	for name, want := range map[string]string{
		"Alice Liddell":           "AL",
		"Hazmi Alfarizqi Second":  "HS",
		"hzmi":                    "H",
		"alice@gnuweeb.org":       "A",
		"ammar.faizi@gnuweeb.org": "AF",
		"élodie dupont":           "ÉD",
		"--":                      "?",
	} {
		if got := initials(name); got != want {
			t.Errorf("initials(%q) = %q, want %q", name, got, want)
		}
	}
}
