package web

import (
	"bytes"
	"context"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/gravatar"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/wkd"
)

func TestMemberPhoto(t *testing.T) {
	h := newHarness(t)
	var photo bytes.Buffer
	if err := jpeg.Encode(&photo, image.NewRGBA(image.Rect(0, 0, 64, 64)), nil); err != nil {
		t.Fatal(err)
	}
	var asked atomic.Int32
	fake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		if r.URL.Path != "/avatar/"+gravatar.Hash("alice@gnuweeb.org") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Write(photo.Bytes())
	}))
	defer fake.Close()
	g, err := gravatar.NewAt(fake.URL, fake.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.opts.Gravatar = g

	for _, addr := range []string{"alice@gnuweeb.org", "bob@gnuweeb.org"} {
		key, _ := armoredKey(t, addr)
		if resp, _ := h.post(h.loginAs(addr), "/keys", url.Values{"key": {key}}); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("%s's upload: status %d", addr, resp.StatusCode)
		}
	}
	c := h.loginAs("carol@gnuweeb.org")
	if _, body := h.get(c, "/members/alice@gnuweeb.org"); !strings.Contains(body, `<img src="/members/alice@gnuweeb.org/avatar.png"`) {
		t.Error("member page has no photo")
	}
	decode := func(path string) image.Image {
		t.Helper()
		resp, err := c.Get(h.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "image/png" ||
			!strings.HasPrefix(resp.Header.Get("Cache-Control"), "private, max-age=") {
			t.Fatalf("%s: status %d, %q, %q", path, resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control"))
		}
		img, err := png.Decode(resp.Body)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		return img
	}
	if b := decode("/members/alice@gnuweeb.org/avatar.png").Bounds(); b.Dx() != 64 {
		t.Errorf("alice's photo is %v, want her 64x64 Gravatar", b)
	}
	// Bob has no Gravatar: a transparent pixel, over which his initials
	// show.
	if _, _, _, a := decode("/members/bob@gnuweeb.org/avatar.png").At(0, 0).RGBA(); a != 0 {
		t.Error("the photo of a member without one is not transparent")
	}
	before := asked.Load()
	if resp, _ := h.get(c, "/members/nobody@gnuweeb.org/avatar.png"); resp.StatusCode != http.StatusNotFound || asked.Load() != before {
		t.Errorf("address without keys: status %d, Gravatar asked %d times", resp.StatusCode, asked.Load()-before)
	}

	h.srv.opts.Gravatar = nil
	if _, body := h.get(c, "/members/alice@gnuweeb.org"); strings.Contains(body, "<img") {
		t.Error("member page shows a photo with Gravatar off")
	}
	if resp, _ := h.get(c, "/members/alice@gnuweeb.org/avatar.png"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("photo with Gravatar off: status %d", resp.StatusCode)
	}
}

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

	// The list names Alice, who has a key, and not Bob, who has none.
	_, list := h.get(bob, "/members")
	if !strings.Contains(list, `href="/members/alice@gnuweeb.org"`) || !strings.Contains(list, "Alice Liddell") || strings.Contains(list, `href="/members/bob@gnuweeb.org"`) {
		t.Error("members list does not show alice alone")
	}

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
