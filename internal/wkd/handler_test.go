package wkd_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/store"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/wkd"
)

// newKey makes a key for email created at the given time and checks it
// as an upload for address.
func newKey(t *testing.T, email, address string, created time.Time) *keys.Key {
	t.Helper()
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return created }}
	e, err := openpgp.NewEntity("Test", "", email, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := e.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	k, err := keys.Parse(b.Bytes(), address)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newServer(t *testing.T) (*store.Store, *httptest.Server) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(wkd.NewHandler(st, slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	return st, srv
}

func do(t *testing.T, method, url string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func TestServesAllKeysOfAddressNewestFirst(t *testing.T) {
	st, srv := newServer(t)
	ctx := context.Background()
	now := time.Now()
	older := newKey(t, "alice@gnuweeb.org", "alice@gnuweeb.org", now.Add(-48*time.Hour))
	newer := newKey(t, "alice@gnuweeb.org", "alice@gnuweeb.org", now.Add(-time.Hour))
	other := newKey(t, "bob@gnuweeb.org", "bob@gnuweeb.org", now)
	for _, put := range []struct {
		addr string
		k    *keys.Key
	}{{"alice@gnuweeb.org", older}, {"bob@gnuweeb.org", other}, {"alice@gnuweeb.org", newer}} {
		if err := st.PutKey(ctx, put.addr, put.k, now); err != nil {
			t.Fatal(err)
		}
	}

	url := srv.URL + "/.well-known/openpgpkey/hu/" + wkd.Hash("alice") + "?l=alice"
	resp, body := do(t, http.MethodGet, url)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type %q", ct)
	}
	if want := append(append([]byte{}, newer.WKD...), older.WKD...); !bytes.Equal(body, want) {
		t.Error("body is not the WKD views of alice's keys, newest first")
	}

	resp, body = do(t, http.MethodHead, url)
	if resp.StatusCode != http.StatusOK || len(body) != 0 {
		t.Errorf("HEAD status %d with %d body bytes", resp.StatusCode, len(body))
	}
	if resp.ContentLength != int64(len(newer.WKD)+len(older.WKD)) {
		t.Errorf("HEAD Content-Length %d", resp.ContentLength)
	}
}

func TestNotFound(t *testing.T) {
	st, srv := newServer(t)
	k := newKey(t, "alice@gnuweeb.org", "alice@gnuweeb.org", time.Now())
	if err := st.PutKey(context.Background(), "alice@gnuweeb.org", k, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/.well-known/openpgpkey/hu/" + wkd.Hash("carol"),
		"/.well-known/openpgpkey/hu/not-a-hash",
		"/.well-known/openpgpkey/gnuweeb.org/hu/" + wkd.Hash("alice"), // advanced method
		"/",
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			if resp, _ := do(t, method, srv.URL+path); resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s %s: status %d, want 404", method, path, resp.StatusCode)
			}
		}
	}
	if resp, _ := do(t, http.MethodPost, srv.URL+"/.well-known/openpgpkey/hu/"+wkd.Hash("alice")); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST status %d, want 405", resp.StatusCode)
	}
}

func TestPolicy(t *testing.T) {
	_, srv := newServer(t)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		if resp, _ := do(t, method, srv.URL+"/.well-known/openpgpkey/policy"); resp.StatusCode != http.StatusOK {
			t.Errorf("%s policy: status %d", method, resp.StatusCode)
		}
	}
}

func TestReuploadReplacesAndDeleteRemoves(t *testing.T) {
	st, srv := newServer(t)
	ctx := context.Background()
	k := newKey(t, "alice@gnuweeb.org", "alice@gnuweeb.org", time.Now())
	if err := st.PutKey(ctx, "alice@gnuweeb.org", k, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.PutKey(ctx, "alice@gnuweeb.org", k, time.Now()); err != nil {
		t.Fatal(err)
	}
	url := srv.URL + "/.well-known/openpgpkey/hu/" + wkd.Hash("alice")
	if _, body := do(t, http.MethodGet, url); !bytes.Equal(body, k.WKD) {
		t.Error("the same key uploaded twice is served twice")
	}
	ok, err := st.DeleteKey(ctx, "alice@gnuweeb.org", k.Fingerprint)
	if err != nil || !ok {
		t.Fatalf("DeleteKey = %v, %v", ok, err)
	}
	if resp, _ := do(t, http.MethodGet, url); resp.StatusCode != http.StatusNotFound {
		t.Errorf("status %d after delete, want 404", resp.StatusCode)
	}
}
