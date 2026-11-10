package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// static holds the stylesheet, the favicon, htmx and the fonts. htmx is
// 2.0.11 from the htmx.org npm package (0BSD, htmx-LICENSE.txt); the
// fonts are Inter and JetBrains Mono (SIL OFL 1.1, *-OFL.txt), cut to
// Latin, as greentea ships them.
//
//go:embed static
var staticFS embed.FS

// assets serves the embedded files under /static/ and names them with a
// version, so a page can let browsers cache them for good. References
// of the form url("name") in a stylesheet are rewritten to the versioned
// URL at startup, so the fonts it loads are cached the same way and the
// page's preload of a font matches the stylesheet's request.
type assets struct {
	content map[string][]byte
	version map[string]string // file name -> first 12 hex digits of its SHA-256
}

func newAssets() *assets {
	a := &assets{content: make(map[string][]byte), version: make(map[string]string)}
	entries, err := fs.ReadDir(staticFS, "static")
	if err != nil {
		panic(err)
	}
	var sheets []string
	for _, e := range entries {
		b, err := fs.ReadFile(staticFS, "static/"+e.Name())
		if err != nil {
			panic(err)
		}
		a.content[e.Name()] = b
		if path.Ext(e.Name()) == ".css" {
			sheets = append(sheets, e.Name())
		} else {
			a.version[e.Name()] = digest(b)
		}
	}
	for _, name := range sheets {
		b := a.content[name]
		for ref := range a.version {
			b = bytes.ReplaceAll(b, []byte(`url("`+ref+`")`), []byte(`url("`+a.url(ref)+`")`))
		}
		a.content[name] = b
		a.version[name] = digest(b)
	}
	return a
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}

// url returns the versioned URL of a static file; it panics on a name
// that is not embedded, which the tests of the pages catch.
func (a *assets) url(name string) string {
	v, ok := a.version[name]
	if !ok {
		panic("web: no static file " + name)
	}
	return "/static/" + name + "?v=" + v
}

// ServeHTTP serves /static/<name>. A request with the current version is
// cacheable for a year; any other is served without caching.
func (a *assets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	b, ok := a.content[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Get("v") == a.version[name] {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	switch path.Ext(name) {
	case ".txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	case ".woff2":
		w.Header().Set("Content-Type", "font/woff2")
	}
	w.Header().Set("ETag", `"`+a.version[name]+`"`)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))
}
