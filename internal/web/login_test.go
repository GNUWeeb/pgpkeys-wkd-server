package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/store"
)

type sentMail struct{ to, subject, body string }

type fakeMailer struct {
	mu   sync.Mutex
	sent []sentMail
}

func (m *fakeMailer) Send(_ context.Context, to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentMail{to, subject, body})
	return nil
}

func (m *fakeMailer) all() []sentMail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sentMail(nil), m.sent...)
}

type harness struct {
	t      *testing.T
	srv    *Server
	ts     *httptest.Server
	client *http.Client
	mailer *fakeMailer
	now    time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := &harness{t: t, mailer: &fakeMailer{}, now: time.Unix(1_800_000_000, 0)}
	h.srv = New(Options{Domain: "gnuweeb.org", BaseURL: "https://pgp.gnuweeb.org"}, st, h.mailer,
		slog.New(slog.DiscardHandler))
	h.srv.now = func() time.Time { return h.now }
	// TLS, because the __Host- cookies are Secure.
	h.ts = httptest.NewTLSServer(h.srv)
	t.Cleanup(h.ts.Close)
	h.client = h.newClient()
	return h
}

// newClient is a browser of its own: a cookie jar, no redirects followed.
func (h *harness) newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	// ts.Client returns one shared client; copy it so each has its jar.
	c := *h.ts.Client()
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func (h *harness) cookie(c *http.Client, name string) string {
	u, _ := url.Parse(h.ts.URL)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

func (h *harness) get(c *http.Client, path string) (*http.Response, string) {
	h.t.Helper()
	resp, err := c.Get(h.ts.URL + path)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp, readBody(h.t, resp)
}

// post sends a form with the client's CSRF token, unless form already
// has a csrf_token entry.
func (h *harness) post(c *http.Client, path string, form url.Values) (*http.Response, string) {
	h.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if _, ok := form["csrf_token"]; !ok {
		if h.cookie(c, csrfCookie) == "" {
			h.get(c, "/login")
		}
		form.Set("csrf_token", h.cookie(c, csrfCookie))
	}
	resp, err := c.PostForm(h.ts.URL+path, form)
	if err != nil {
		h.t.Fatal(err)
	}
	body := readBody(h.t, resp)
	h.srv.Wait()
	return resp, body
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var linkRE = regexp.MustCompile(`https://pgp\.gnuweeb\.org(/login/confirm\?token=([A-Za-z0-9_-]+))`)

// requestLink asks for a login link for address and returns the path of
// the mailed link and its token.
func (h *harness) requestLink(c *http.Client, address string) (path, token string) {
	h.t.Helper()
	before := len(h.mailer.all())
	resp, _ := h.post(c, "/login", url.Values{"address": {address}})
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("POST /login: status %d", resp.StatusCode)
	}
	mails := h.mailer.all()
	if len(mails) != before+1 {
		h.t.Fatalf("%d mails sent, want 1", len(mails)-before)
	}
	m := linkRE.FindStringSubmatch(mails[len(mails)-1].body)
	if m == nil {
		h.t.Fatalf("no login link in mail:\n%s", mails[len(mails)-1].body)
	}
	return m[1], m[2]
}

func TestLoginRoundTrip(t *testing.T) {
	h := newHarness(t)
	c := h.client

	if resp, _ := h.get(c, "/"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("GET / before login: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	path, _ := h.requestLink(c, " Alice@GNUWeeb.org ")
	if to := h.mailer.all()[0].to; to != "alice@gnuweeb.org" {
		t.Errorf("mail sent to %q", to)
	}

	// Opening the link, as a mail scanner would, does not use it up.
	for range 2 {
		resp, body := h.get(c, path)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "alice@gnuweeb.org") {
			t.Fatalf("GET confirm: status %d", resp.StatusCode)
		}
	}

	u, _ := url.Parse(path)
	resp, _ := h.post(c, "/login/confirm", url.Values{"token": {u.Query().Get("token")}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("POST confirm: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	var session *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == sessionCookie {
			session = ck
		}
	}
	if session == nil {
		t.Fatal("no session cookie")
	}
	if !strings.HasPrefix(session.Name, "__Host-") || !session.Secure || !session.HttpOnly ||
		session.SameSite != http.SameSiteLaxMode || session.Path != "/" || session.Domain != "" {
		t.Errorf("session cookie attributes: %+v", session)
	}

	resp, body := h.get(c, "/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "alice@gnuweeb.org") {
		t.Fatalf("GET / after login: status %d", resp.StatusCode)
	}

	resp, _ = h.post(c, "/logout", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: status %d", resp.StatusCode)
	}
	// The old session ID is dead on the server, not only in the browser.
	other := h.newClient()
	other.Jar.SetCookies(mustURL(h.ts.URL), []*http.Cookie{{Name: sessionCookie, Value: session.Value}})
	if resp, _ := h.get(other, "/"); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("GET / with the logged-out session: status %d", resp.StatusCode)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestTokensRejected(t *testing.T) {
	h := newHarness(t)

	confirm := func(token string) int {
		resp, _ := h.post(h.newClient(), "/login/confirm", url.Values{"token": {token}})
		return resp.StatusCode
	}
	open := func(token string) int {
		resp, _ := h.get(h.client, "/login/confirm?token="+url.QueryEscape(token))
		return resp.StatusCode
	}

	t.Run("reused", func(t *testing.T) {
		_, token := h.requestLink(h.client, "alice@gnuweeb.org")
		if got := confirm(token); got != http.StatusSeeOther {
			t.Fatalf("first use: status %d", got)
		}
		if got := confirm(token); got != http.StatusBadRequest {
			t.Errorf("second use: status %d, want 400", got)
		}
		if got := open(token); got != http.StatusBadRequest {
			t.Errorf("opening a used link: status %d, want 400", got)
		}
	})
	t.Run("expired", func(t *testing.T) {
		_, token := h.requestLink(h.client, "bob@gnuweeb.org")
		h.now = h.now.Add(tokenTTL)
		defer func() { h.now = h.now.Add(-tokenTTL) }()
		if got := open(token); got != http.StatusBadRequest {
			t.Errorf("open: status %d, want 400", got)
		}
		if got := confirm(token); got != http.StatusBadRequest {
			t.Errorf("confirm: status %d, want 400", got)
		}
	})
	t.Run("forged", func(t *testing.T) {
		for _, token := range []string{newSecret(), "", "x"} {
			if got := open(token); got != http.StatusBadRequest {
				t.Errorf("open %q: status %d, want 400", token, got)
			}
			if got := confirm(token); got != http.StatusBadRequest {
				t.Errorf("confirm %q: status %d, want 400", token, got)
			}
		}
	})
}

func TestSessionExpires(t *testing.T) {
	h := newHarness(t)
	_, token := h.requestLink(h.client, "alice@gnuweeb.org")
	h.post(h.client, "/login/confirm", url.Values{"token": {token}})
	h.now = h.now.Add(sessionTTL)
	if resp, _ := h.get(h.client, "/"); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("GET / after the session lifetime: status %d", resp.StatusCode)
	}
}

func TestCSRFRequired(t *testing.T) {
	h := newHarness(t)
	for name, token := range map[string]string{"missing": "", "wrong": newSecret()} {
		c := h.newClient()
		h.get(c, "/login")
		resp, _ := h.post(c, "/login", url.Values{"address": {"alice@gnuweeb.org"}, "csrf_token": {token}})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s token: status %d, want 403", name, resp.StatusCode)
		}
	}
	// A cookie-less client cannot pass by sending an empty token either.
	resp, _ := h.post(h.newClient(), "/login", url.Values{"address": {"alice@gnuweeb.org"}, "csrf_token": {""}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("no cookie: status %d, want 403", resp.StatusCode)
	}
	if n := len(h.mailer.all()); n != 0 {
		t.Errorf("%d mails sent", n)
	}
}

func TestLoginRequestAnswers(t *testing.T) {
	h := newHarness(t)
	for _, addr := range []string{"bob@example.org", "bob", "a..b@gnuweeb.org", "\"a b\"@gnuweeb.org", ""} {
		if resp, _ := h.post(h.client, "/login", url.Values{"address": {addr}}); resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%q: status %d, want 422", addr, resp.StatusCode)
		}
	}
	if n := len(h.mailer.all()); n != 0 {
		t.Errorf("%d mails sent for invalid addresses", n)
	}

	// Past the per-address limit the answer stays the same; only the mail
	// is held back.
	var first string
	for i := range addressLimit + 2 {
		resp, body := h.post(h.client, "/login", url.Values{"address": {"carol@gnuweeb.org"}})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i+1, resp.StatusCode)
		}
		if i == 0 {
			first = body
		} else if stripCSRF(body) != stripCSRF(first) {
			t.Errorf("request %d answered differently", i+1)
		}
	}
	if n := len(h.mailer.all()); n != addressLimit {
		t.Errorf("%d mails sent, want %d", n, addressLimit)
	}
	// The window slides.
	h.now = h.now.Add(rateWindow)
	h.requestLink(h.client, "carol@gnuweeb.org")
}

var csrfValueRE = regexp.MustCompile(`value="[A-Za-z0-9_-]{43}"`)

func stripCSRF(s string) string { return csrfValueRE.ReplaceAllString(s, "") }

func TestClientRateLimit(t *testing.T) {
	h := newHarness(t)
	for i := range clientLimit {
		if resp, _ := h.post(h.client, "/login", url.Values{"address": {"u" + string(rune('a'+i)) + "@gnuweeb.org"}}); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i+1, resp.StatusCode)
		}
	}
	if resp, _ := h.post(h.client, "/login", url.Values{"address": {"zz@gnuweeb.org"}}); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("request past the limit: status %d, want 429", resp.StatusCode)
	}
}

func TestNormalizeAddress(t *testing.T) {
	for in, want := range map[string]string{
		"Alice@gnuweeb.org":                      "alice@gnuweeb.org",
		"a.b+c@GNUWEEB.ORG":                      "a.b+c@gnuweeb.org",
		"alice@gnuweeb.org.evil":                 "",
		"alice@sub.gnuweeb.org":                  "",
		".alice@gnuweeb.org":                     "",
		"alice.@gnuweeb.org":                     "",
		"al ice@gnuweeb.org":                     "",
		"älice@gnuweeb.org":                      "",
		"alice@gnuweeb.org@x.org":                "",
		strings.Repeat("a", 65) + "@gnuweeb.org": "",
	} {
		got, err := normalizeAddress(in, "gnuweeb.org")
		if want == "" {
			if err == nil {
				t.Errorf("%q accepted as %q", in, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", in, got, err, want)
		}
	}
}
