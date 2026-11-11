package web

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/wkd"
)

// loginAs logs a new client in as address.
func (h *harness) loginAs(address string) *http.Client {
	h.t.Helper()
	c := h.newClient()
	_, token := h.requestLink(c, address)
	if resp, _ := h.post(c, "/login/confirm", url.Values{"token": {token}}); resp.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("login as %s: status %d", address, resp.StatusCode)
	}
	return c
}

// armoredKey makes a key with a User ID for email and returns it armored
// with its fingerprint.
func armoredKey(t *testing.T, email string) (string, string) {
	t.Helper()
	return armoredKeyWith(t, email, &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
}

func armoredKeyWith(t *testing.T, email string, cfg *packet.Config) (string, string) {
	t.Helper()
	e, err := openpgp.NewEntity("Test", "", email, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return armoredEntity(t, e), strings.ToUpper(fingerprintHex(e.PrimaryKey.Fingerprint))
}

func armoredEntity(t *testing.T, e *openpgp.Entity) string {
	t.Helper()
	var b bytes.Buffer
	w, _ := armor.Encode(&b, openpgp.PublicKeyType, nil)
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return b.String()
}

func TestKeyListShowsCertifiers(t *testing.T) {
	h := newHarness(t)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	newKey := func(email string) *openpgp.Entity {
		e, err := openpgp.NewEntity("Test", "", email, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	alice, bob, carol := newKey("alice@gnuweeb.org"), newKey("bob@gnuweeb.org"), newKey("carol@example.org")
	for _, signer := range []*openpgp.Entity{bob, carol} {
		if err := alice.SignIdentity("Test <alice@gnuweeb.org>", signer, cfg); err != nil {
			t.Fatal(err)
		}
	}
	if resp, _ := h.post(h.loginAs("bob@gnuweeb.org"), "/keys", url.Values{"key": {armoredEntity(t, bob)}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("bob's upload: status %d", resp.StatusCode)
	}
	aliceClient := h.loginAs("alice@gnuweeb.org")
	if resp, _ := h.post(aliceClient, "/keys", url.Values{"key": {armoredEntity(t, alice)}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("alice's upload: status %d", resp.StatusCode)
	}
	_, body := h.get(aliceClient, "/")
	bobKeys := `href="https://gnuweeb.org/.well-known/openpgpkey/hu/` + wkd.Hash("bob") + `?l=bob"`
	for _, want := range []string{"Certified by", "bob@gnuweeb.org", bobKeys, "Also certified by 1 key not in this directory"} {
		if !strings.Contains(body, want) {
			t.Errorf("alice's list lacks %q", want)
		}
	}
	// Bob's own key was certified by no one.
	if _, body := h.get(h.loginAs("bob@gnuweeb.org"), "/"); strings.Contains(body, "ertified by") {
		t.Error("bob's list shows certifications his key does not have")
	}
}

func fingerprintHex(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&15])
	}
	return string(out)
}

func (h *harness) wkdKeys(local string) int {
	h.t.Helper()
	blobs, err := h.srv.store.WKDKeys(context.Background(), wkd.Hash(local))
	if err != nil {
		h.t.Fatal(err)
	}
	return len(blobs)
}

func TestAddAndRemoveKey(t *testing.T) {
	h := newHarness(t)
	alice := h.loginAs("alice@gnuweeb.org")

	if _, body := h.get(alice, "/"); !strings.Contains(body, "No keys yet") {
		t.Error("empty list does not say so")
	}

	key, fpr := armoredKey(t, "alice@gnuweeb.org")
	resp, _ := h.post(alice, "/keys", url.Values{"key": {key}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?added="+fpr {
		t.Fatalf("add: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body := h.get(alice, "/?added="+fpr)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, groupedFpr(fpr)) || !strings.Contains(body, "saved") {
		t.Fatalf("list after add: status %d", resp.StatusCode)
	}
	if n := h.wkdKeys("alice"); n != 1 {
		t.Fatalf("WKD serves %d keys, want 1", n)
	}

	if resp, body := h.get(alice, "/keys/"+fpr+"/remove"); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Remove key?") {
		t.Fatalf("remove confirmation: status %d", resp.StatusCode)
	}
	if n := h.wkdKeys("alice"); n != 1 {
		t.Fatal("opening the confirmation removed the key")
	}
	resp, _ = h.post(alice, "/keys/"+fpr+"/remove", nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?removed="+fpr {
		t.Fatalf("remove: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if n := h.wkdKeys("alice"); n != 0 {
		t.Errorf("WKD serves %d keys after removal", n)
	}
}

func TestKeyListSaysWhatToFix(t *testing.T) {
	h := newHarness(t)
	start := h.now
	key, fpr := armoredKeyWith(t, "alice@gnuweeb.org", &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		KeyLifetimeSecs: 40 * 86400,
		Time:            func() time.Time { return start },
	})
	if resp, _ := h.post(h.loginAs("alice@gnuweeb.org"), "/keys", url.Values{"key": {key}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("add: status %d", resp.StatusCode)
	}
	if _, body := h.get(h.loginAs("alice@gnuweeb.org"), "/"); strings.Contains(body, "What to fix") || !strings.Contains(body, ">Valid<") {
		t.Error("a key with 40 days left is not shown as valid without anything to fix")
	}

	h.now = start.Add(20 * 24 * time.Hour)
	_, body := h.get(h.loginAs("alice@gnuweeb.org"), "/")
	for _, want := range []string{">Signing ends soon<", "What to fix", "Signing with this key stops on 2027-02-24.", "gpg --quick-set-expire " + fpr + " 5y"} {
		if !strings.Contains(body, want) {
			t.Errorf("20 days before expiry, the list lacks %q", want)
		}
	}

	h.now = start.Add(41 * 24 * time.Hour)
	_, body = h.get(h.loginAs("alice@gnuweeb.org"), "/")
	for _, want := range []string{">Expired<", "The key expired on 2027-02-24."} {
		if !strings.Contains(body, want) {
			t.Errorf("after expiry, the list lacks %q", want)
		}
	}
	if n := h.wkdKeys("alice"); n != 1 {
		t.Errorf("WKD serves %d keys after expiry, want the expired one still", n)
	}
}

func groupedFpr(fpr string) string {
	var parts []string
	for i := 0; i < len(fpr); i += 4 {
		parts = append(parts, fpr[i:i+4])
	}
	return strings.Join(parts, " ")
}

func TestAddKeyFromFile(t *testing.T) {
	h := newHarness(t)
	alice := h.loginAs("alice@gnuweeb.org")
	key, fpr := armoredKey(t, "alice@gnuweeb.org")

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("csrf_token", h.cookie(alice, csrfCookie))
	mw.WriteField("key", "")
	fw, _ := mw.CreateFormFile("file", "alice.asc")
	io.WriteString(fw, key)
	mw.Close()
	resp, err := alice.Post(h.ts.URL+"/keys", mw.FormDataContentType(), &body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?added="+fpr {
		t.Fatalf("upload: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestAddKeyRejects(t *testing.T) {
	h := newHarness(t)
	alice := h.loginAs("alice@gnuweeb.org")
	bobKey, _ := armoredKey(t, "bob@gnuweeb.org")
	expired, fpr := armoredKeyWith(t, "alice@gnuweeb.org", &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		KeyLifetimeSecs: 86400,
		Time:            func() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) },
	})
	for name, tc := range map[string]struct {
		key, want string
	}{
		"empty":         {"  ", "Paste a key or choose a file"},
		"garbage":       {"hello", "malformed"},
		"other address": {bobKey, "no valid, unrevoked User ID with the address alice@gnuweeb.org"},
		"expired":       {expired, "The key expired on 2020-01-02.</p><p>Extend its expiry date"},
		"expired fix":   {expired, "gpg --quick-set-expire " + fpr + " 5y"},
	} {
		resp, body := h.post(alice, "/keys", url.Values{"key": {tc.key}})
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, tc.want) {
			t.Errorf("%s: status %d, body lacks %q", name, resp.StatusCode, tc.want)
		}
	}
	if n := h.wkdKeys("alice") + h.wkdKeys("bob"); n != 0 {
		t.Errorf("%d keys stored", n)
	}

	big := strings.Repeat("x", maxBody+1)
	if resp, _ := h.post(alice, "/keys", url.Values{"key": {big}}); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized form: status %d, want 413", resp.StatusCode)
	}
}

func TestMembersSeeOnlyTheirOwnKeys(t *testing.T) {
	h := newHarness(t)
	alice := h.loginAs("alice@gnuweeb.org")
	bob := h.loginAs("bob@gnuweeb.org")
	key, fpr := armoredKey(t, "alice@gnuweeb.org")
	h.post(alice, "/keys", url.Values{"key": {key}})

	if _, body := h.get(bob, "/"); strings.Contains(body, groupedFpr(fpr)) {
		t.Error("bob's list shows alice's key")
	}
	if resp, _ := h.get(bob, "/keys/"+fpr+"/remove"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("bob opens removal of alice's key: status %d, want 404", resp.StatusCode)
	}
	if resp, _ := h.post(bob, "/keys/"+fpr+"/remove", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("bob removes alice's key: status %d, want 404", resp.StatusCode)
	}
	// Bob cannot publish a key for alice's address either.
	if resp, _ := h.post(bob, "/keys", url.Values{"key": {key}}); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("bob uploads alice's key: status %d, want 422", resp.StatusCode)
	}
	if n := h.wkdKeys("alice"); n != 1 {
		t.Errorf("WKD serves %d keys for alice, want 1", n)
	}
	if n := h.wkdKeys("bob"); n != 0 {
		t.Errorf("WKD serves %d keys for bob, want 0", n)
	}
}

func TestKeyPagesNeedLogin(t *testing.T) {
	h := newHarness(t)
	c := h.newClient()
	for _, path := range []string{"/", "/keys/new", "/keys/" + strings.Repeat("A", 40) + "/remove", "/trust", "/trust/certify"} {
		if resp, _ := h.get(c, path); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
			t.Errorf("GET %s: %d to %q", path, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	key, _ := armoredKey(t, "alice@gnuweeb.org")
	if resp, _ := h.post(c, "/keys", url.Values{"key": {key}}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("POST /keys: status %d", resp.StatusCode)
	}
	if n := h.wkdKeys("alice"); n != 0 {
		t.Error("a key was stored without login")
	}
}

func TestStaticAssets(t *testing.T) {
	h := newHarness(t)
	_, page := h.get(h.client, "/login")
	for _, name := range []string{"matcha.css", "htmx.min.js", "inter.woff2"} {
		u := h.srv.assets.url(name)
		if !strings.Contains(page, u) {
			t.Errorf("login page does not reference %s", u)
		}
		resp, _ := h.get(h.client, u)
		if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") ||
			resp.Header.Get("Set-Cookie") != "" {
			t.Errorf("GET %s: status %d, Cache-Control %q, Set-Cookie %q", u, resp.StatusCode,
				resp.Header.Get("Cache-Control"), resp.Header.Get("Set-Cookie"))
		}
	}
	for _, path := range []string{"/static/", "/static/nope.css", "/static/../web.go"} {
		if resp, _ := h.get(h.client, path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, resp.StatusCode)
		}
	}
}
