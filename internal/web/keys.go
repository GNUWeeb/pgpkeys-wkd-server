package web

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/web/ui"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/wkd"
)

// Every handler here runs behind requireLogin and works only on the keys
// of the session's address: the address comes from the session, never
// from the request.

// validFingerprint accepts the upper-case hex fingerprints Parse stores
// (40 digits for v4 keys, 64 for v5 and v6).
func validFingerprint(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !('0' <= c && c <= '9' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}

// wkdURL is where clients fetch the member's keys; shown for reference.
func (s *Server) wkdURL(address string) string {
	local, domain, _ := strings.Cut(address, "@")
	return "https://" + domain + "/.well-known/openpgpkey/hu/" + wkd.Hash(local) + "?l=" + url.QueryEscape(local)
}

func (s *Server) keyList(w http.ResponseWriter, r *http.Request) {
	addr := sessionAddress(r)
	stored, err := s.store.Keys(r.Context(), addr)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := s.now()
	list := make([]keys.Info, 0, len(stored))
	for _, k := range stored {
		info, err := keys.Describe(k.Data, now)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		list = append(list, info)
	}

	var f ui.Flash
	q := r.URL.Query()
	if fpr := q.Get("added"); validFingerprint(fpr) {
		f = ui.Flash{Kind: "ok", Text: "Key " + fpr + " saved. WKD serves it now."}
	} else if fpr := q.Get("removed"); validFingerprint(fpr) {
		f = ui.Flash{Kind: "ok", Text: "Key " + fpr + " removed."}
	}
	p := s.page(r, "Your keys")
	p.Nav = "/"
	s.render(w, r, http.StatusOK, ui.Keys(p, list, f, s.wkdURL(addr)))
}

func (s *Server) addKeyForm(w http.ResponseWriter, r *http.Request) {
	p := s.page(r, "Add key")
	p.Nav = "/"
	s.render(w, r, http.StatusOK, ui.AddKey(p, "", "", keys.MaxSize>>10))
}

// addKey stores an uploaded key: the chosen file if there is one, the
// pasted text otherwise.
func (s *Server) addKey(w http.ResponseWriter, r *http.Request) {
	addr := sessionAddress(r)
	pasted := r.PostFormValue("key")
	input := []byte(pasted)
	if f, _, err := r.FormFile("file"); err == nil {
		b, err := io.ReadAll(io.LimitReader(f, keys.MaxSize+1))
		f.Close()
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if len(b) > 0 {
			input = b
		}
	}

	fail := func(msg string) {
		p := s.page(r, "Add key")
		p.Nav = "/"
		s.render(w, r, http.StatusUnprocessableEntity, ui.AddKey(p, pasted, msg, keys.MaxSize>>10))
	}
	if len(strings.TrimSpace(string(input))) == 0 {
		fail("Paste a key or choose a file.")
		return
	}
	k, err := keys.Parse(input, addr, s.now())
	if err != nil {
		fail("This key cannot be added: " + err.Error() + ".")
		return
	}
	if err := s.store.PutKey(r.Context(), addr, k, s.now()); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.log.Info("key saved", "address", addr, "fingerprint", k.Fingerprint)
	http.Redirect(w, r, "/?added="+k.Fingerprint, http.StatusSeeOther)
}

// ownKey finds the session address's key named in the URL, or answers
// 404: another member's key is as absent as a key that does not exist.
func (s *Server) ownKey(w http.ResponseWriter, r *http.Request) (keys.Info, bool) {
	fpr := chi.URLParam(r, "fpr")
	if validFingerprint(fpr) {
		stored, err := s.store.Keys(r.Context(), sessionAddress(r))
		if err != nil {
			s.internalError(w, r, err)
			return keys.Info{}, false
		}
		for _, k := range stored {
			if k.Fingerprint == fpr {
				info, err := keys.Describe(k.Data, s.now())
				if err != nil {
					s.internalError(w, r, err)
					return keys.Info{}, false
				}
				return info, true
			}
		}
	}
	s.message(w, r, http.StatusNotFound, "Key not found", "You have no key with this fingerprint.", "/", "Back to your keys")
	return keys.Info{}, false
}

func (s *Server) removeKeyForm(w http.ResponseWriter, r *http.Request) {
	k, ok := s.ownKey(w, r)
	if !ok {
		return
	}
	p := s.page(r, "Remove key")
	p.Nav = "/"
	s.render(w, r, http.StatusOK, ui.RemoveKey(p, k))
}

func (s *Server) removeKey(w http.ResponseWriter, r *http.Request) {
	addr := sessionAddress(r)
	fpr := chi.URLParam(r, "fpr")
	ok := false
	if validFingerprint(fpr) {
		var err error
		if ok, err = s.store.DeleteKey(r.Context(), addr, fpr); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	if !ok {
		s.message(w, r, http.StatusNotFound, "Key not found", "You have no key with this fingerprint.", "/", "Back to your keys")
		return
	}
	s.log.Info("key removed", "address", addr, "fingerprint", fpr)
	http.Redirect(w, r, "/?removed="+fpr, http.StatusSeeOther)
}
