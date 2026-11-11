package gravatar

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHash(t *testing.T) {
	// Gravatar's own example: https://docs.gravatar.com/api/avatars/hash/
	if got, want := Hash(" MyEmailAddress@example.com "), "84059b07d4be67b806386c0aad8070a23f18836bbaae342275dc0a83414c32ee"; got != want {
		t.Errorf("Hash = %s, want %s", got, want)
	}
}

func jpegOf(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := range w {
		for y := range h {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 200, 255})
		}
	}
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, nil); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestPhoto(t *testing.T) {
	photo := jpegOf(t, 120, 80)
	var asked atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		if r.URL.Query().Get("d") != "404" || r.Header.Get("Cookie") != "" {
			t.Errorf("request %s with cookie %q", r.URL, r.Header.Get("Cookie"))
		}
		switch strings.TrimPrefix(r.URL.Path, "/avatar/") {
		case Hash("photo@gnuweeb.org"):
			w.Header().Set("Content-Type", "image/jpeg")
			w.Write(photo)
		case Hash("html@gnuweeb.org"):
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<p>no"))
		case Hash("huge@gnuweeb.org"):
			w.Header().Set("Content-Type", "image/jpeg")
			w.Write(jpegOf(t, maxSide+1, 10))
		case Hash("away@gnuweeb.org"):
			http.Redirect(w, r, "https://example.org/x.jpg", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := NewAt(srv.URL, srv.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { return now }
	ctx := context.Background()

	got, maxAge, err := c.Photo(ctx, "Photo@GNUWeeb.org")
	if err != nil || maxAge != keepPhoto {
		t.Fatalf("photo: %v, kept %v", err, maxAge)
	}
	img, err := png.Decode(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("photo is not a PNG: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 80 || b.Dy() != 80 {
		t.Errorf("photo is %v, want the 80x80 square in the middle", b)
	}

	if got, maxAge, err := c.Photo(ctx, "none@gnuweeb.org"); got != nil || err != nil || maxAge != keepNone {
		t.Errorf("no photo: %d bytes, %v, kept %v", len(got), err, maxAge)
	}
	for _, addr := range []string{"html@gnuweeb.org", "huge@gnuweeb.org", "away@gnuweeb.org"} {
		if got, maxAge, err := c.Photo(ctx, addr); got != nil || err == nil || maxAge != keepFailure {
			t.Errorf("%s: %d bytes, %v, kept %v; want a failure", addr, len(got), err, maxAge)
		}
	}

	// Answers are kept: asking again within their time asks Gravatar
	// nothing, and after it asks again.
	before := asked.Load()
	c.Photo(ctx, "photo@gnuweeb.org")
	c.Photo(ctx, "none@gnuweeb.org")
	if n := asked.Load() - before; n != 0 {
		t.Errorf("cached answers asked Gravatar %d times", n)
	}
	now = now.Add(keepNone)
	c.Photo(ctx, "none@gnuweeb.org")
	c.Photo(ctx, "photo@gnuweeb.org")
	if n := asked.Load() - before; n != 1 {
		t.Errorf("after a day Gravatar was asked %d times, want 1 (the address without a photo)", n)
	}
}
