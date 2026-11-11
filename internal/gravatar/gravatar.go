// Package gravatar fetches the photos members keep at Gravatar
// (gravatar.com) for the dashboard to show beside their names. Only the
// server fetches them, never a browser: Gravatar learns the SHA-256 of
// each address looked up, which anyone who guesses the address can make
// again, and nothing of the member looking. Photos are decoded and
// encoded again as PNG, so that the dashboard serves its own bytes, and
// kept in memory for a while.
package gravatar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/draw"
	_ "image/gif"  // registers the GIF decoder
	_ "image/jpeg" // registers the JPEG decoder
	"image/png"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// How photos are fetched and kept.
const (
	// Size is the side, in pixels, asked of Gravatar.
	Size = 256
	// maxSide refuses a picture larger than this a side before it is
	// decoded, whatever Gravatar sent.
	maxSide = 1024
	// maxBytes caps the file.
	maxBytes = 1 << 20
	timeout  = 5 * time.Second
	// Gravatar is asked at most this many times at once.
	parallel = 4
	// How long an answer is kept: a photo, an address without one, and
	// a failure, so that an outage is not asked about on every page.
	keepPhoto   = 72 * time.Hour
	keepNone    = 24 * time.Hour
	keepFailure = 15 * time.Minute
)

// BaseURL is Gravatar's.
const BaseURL = "https://gravatar.com"

// Hash is what Gravatar knows an address by: the SHA-256, in hex, of the
// address without the spaces around it, in lower case.
func Hash(address string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(address))))
	return hex.EncodeToString(sum[:])
}

// Client fetches photos from Gravatar and keeps them. It is safe for
// concurrent use.
type Client struct {
	base  string
	http  *http.Client
	now   func() time.Time
	slots chan struct{}
	group singleflight.Group

	mu    sync.Mutex
	cache map[string]entry
}

type entry struct {
	png   []byte // nil: no photo
	until time.Time
}

// New returns a client of Gravatar itself.
func New() *Client {
	c, _ := NewAt(BaseURL, http.DefaultTransport)
	return c
}

// NewAt returns a client of the Gravatar at base through rt: the tests'
// own server. Redirects are followed once at most, over base's scheme,
// to Gravatar's hosts or base's own.
func NewAt(base string, rt http.RoundTripper) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	c := &Client{
		base:  strings.TrimSuffix(base, "/"),
		now:   time.Now,
		slots: make(chan struct{}, parallel),
		cache: map[string]entry{},
	}
	c.http = &http.Client{
		Transport: rt,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			h := req.URL.Hostname()
			if len(via) > 1 || req.URL.Scheme != u.Scheme ||
				(h != u.Hostname() && h != "gravatar.com" && !strings.HasSuffix(h, ".gravatar.com")) {
				return errors.New("gravatar: redirect refused")
			}
			return nil
		},
	}
	return c, nil
}

// Photo returns the photo of address as PNG, or nil when Gravatar has
// none or could not be asked, and how long the answer may be kept. err
// says why a photo could not be had; the caller logs it and shows none.
func (c *Client) Photo(ctx context.Context, address string) (photo []byte, maxAge time.Duration, err error) {
	h := Hash(address)
	now := c.now()
	c.mu.Lock()
	e, ok := c.cache[h]
	c.mu.Unlock()
	if ok && now.Before(e.until) {
		return e.png, e.until.Sub(now), nil
	}
	ch := c.group.DoChan(h, func() (any, error) {
		c.slots <- struct{}{}
		defer func() { <-c.slots }()
		photo, err := c.fetch(h)
		keep := keepPhoto
		switch {
		case err != nil:
			keep = keepFailure
		case photo == nil:
			keep = keepNone
		}
		now := c.now()
		e := entry{png: photo, until: now.Add(keep)}
		c.mu.Lock()
		// Expired entries go as new ones come, so that the cache holds
		// no more than the addresses asked about lately.
		for k, old := range c.cache {
			if !now.Before(old.until) {
				delete(c.cache, k)
			}
		}
		c.cache[h] = e
		c.mu.Unlock()
		return e, err
	})
	select {
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case res := <-ch:
		e := res.Val.(entry)
		return e.png, e.until.Sub(c.now()), res.Err
	}
}

// fetch asks Gravatar for the photo of h: nil for an address without
// one, an error for anything but a picture of a type and size it takes.
func (c *Client) fetch(h string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/avatar/%s?d=404&s=%d&r=g", c.base, h, Size), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "image/jpeg, image/png, image/gif")
	req.Header.Set("User-Agent", "matcha (GNUWeeb OpenPGP key directory)")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gravatar: status %d", resp.StatusCode)
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch mt {
	case "image/jpeg", "image/png", "image/gif":
	default:
		return nil, fmt.Errorf("gravatar: type %q", mt)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBytes {
		return nil, errors.New("gravatar: file too large")
	}
	return render(b)
}

// render decodes a JPEG, PNG or GIF of at most maxSide pixels a side and
// encodes the square in its middle as PNG, with the pixels alone.
func render(b []byte) ([]byte, error) {
	cfg, format, err := image.DecodeConfig(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("gravatar: %w", err)
	}
	if format != "jpeg" && format != "png" && format != "gif" {
		return nil, fmt.Errorf("gravatar: format %q", format)
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxSide || cfg.Height > maxSide {
		return nil, fmt.Errorf("gravatar: %dx%d pixels", cfg.Width, cfg.Height)
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("gravatar: %w", err)
	}
	r := img.Bounds()
	side := min(r.Dx(), r.Dy())
	from := image.Pt(r.Min.X+(r.Dx()-side)/2, r.Min.Y+(r.Dy()-side)/2)
	sq := image.NewRGBA(image.Rect(0, 0, side, side))
	draw.Draw(sq, sq.Bounds(), img, from, draw.Src)
	var out bytes.Buffer
	if err := png.Encode(&out, sq); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
