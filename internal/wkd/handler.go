package wkd

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
)

// Source returns the WKD views of the keys stored under a WKD hash,
// newest first.
type Source interface {
	WKDKeys(ctx context.Context, hash string) ([][]byte, error)
}

// policy is the policy flags file (draft section 4.5). It sets no flag;
// only its presence matters to clients.
const policy = "# OpenPGP Web Key Directory policy; no flags set.\n"

// NewHandler returns the routes of the direct method below
// /.well-known/openpgpkey/: GET and HEAD of hu/<hash> and policy. The
// optional ?l=<local-part> parameter is ignored; the hash alone selects
// the keys. Every other path answers 404.
func NewHandler(src Source, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	// A GET pattern also matches HEAD; net/http drops the body.
	mux.HandleFunc("GET /.well-known/openpgpkey/hu/{hash}", func(w http.ResponseWriter, r *http.Request) {
		hash := r.PathValue("hash")
		if !ValidHash(hash) {
			http.NotFound(w, r)
			return
		}
		blobs, err := src.WKDKeys(r.Context(), hash)
		if err != nil {
			log.Error("wkd lookup", "hash", hash, "err", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if len(blobs) == 0 {
			http.NotFound(w, r)
			return
		}
		n := 0
		for _, b := range blobs {
			n += len(b)
		}
		h := w.Header()
		h.Set("Content-Type", "application/octet-stream")
		h.Set("Content-Length", strconv.Itoa(n))
		for _, b := range blobs {
			if _, err := w.Write(b); err != nil {
				return
			}
		}
	})
	mux.HandleFunc("GET /.well-known/openpgpkey/policy", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(policy))
	})
	return mux
}
