package web

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/store"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/web/ui"
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
	s.render(w, r, http.StatusOK, ui.Keys(p, list, f, addr))
}

// signers returns every stored key as a possible certifier, once per
// fingerprint from its latest upload, with the addresses each key is
// stored for.
func (s *Server) signers(r *http.Request) ([]keys.Signer, map[string][]string, error) {
	all, err := s.store.AllKeys(r.Context())
	if err != nil {
		return nil, nil, err
	}
	latest := map[string]store.StoredKey{}
	addresses := map[string][]string{}
	for _, k := range all {
		if prev, ok := latest[k.Fingerprint]; !ok || k.Uploaded.After(prev.Uploaded) {
			latest[k.Fingerprint] = k
		}
		addresses[k.Fingerprint] = append(addresses[k.Fingerprint], k.Address)
	}
	signers := make([]keys.Signer, 0, len(latest))
	for fpr, k := range latest {
		signers = append(signers, keys.Signer{Fingerprint: fpr, Data: k.Data})
	}
	return signers, addresses, nil
}

func (s *Server) addKeyForm(w http.ResponseWriter, r *http.Request) {
	p := s.page(r, "Add key")
	p.Nav = "/"
	s.render(w, r, http.StatusOK, ui.AddKey(p, "", "", nil, keys.MaxSize>>10))
}

// formKey returns the pasted text of a key form and the key to use: the
// chosen file if there is one, the pasted text otherwise.
func formKey(r *http.Request) (pasted string, input []byte, err error) {
	pasted = r.PostFormValue("key")
	input = []byte(pasted)
	if f, _, ferr := r.FormFile("file"); ferr == nil {
		b, err := io.ReadAll(io.LimitReader(f, keys.MaxSize+1))
		f.Close()
		if err != nil {
			return "", nil, err
		}
		if len(b) > 0 {
			input = b
		}
	}
	return pasted, input, nil
}

// addKey stores an uploaded key.
func (s *Server) addKey(w http.ResponseWriter, r *http.Request) {
	addr := sessionAddress(r)
	pasted, input, err := formKey(r)
	if err != nil {
		s.internalError(w, r, err)
		return
	}

	fail := func(msg string, fix *keys.Problem) {
		p := s.page(r, "Add key")
		p.Nav = "/"
		s.render(w, r, http.StatusUnprocessableEntity, ui.AddKey(p, pasted, msg, fix, keys.MaxSize>>10))
	}
	if len(strings.TrimSpace(string(input))) == 0 {
		fail("Paste a key or choose a file.", nil)
		return
	}
	k, err := keys.Parse(input, addr, s.now())
	if err != nil {
		var u *keys.Unusable
		if errors.As(err, &u) {
			fail("This key cannot be added. "+u.Problem.Text, &u.Problem)
			return
		}
		fail("This key cannot be added: "+err.Error()+".", nil)
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
