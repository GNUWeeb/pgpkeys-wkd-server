package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

// The CSRF token lives in a __Host- cookie, which only this host can set
// and only over HTTPS, and every state-changing request must echo it in
// the csrf_token form field or the X-CSRF-Token header (double submit).
// The cookie exists from the first page on, so the login forms are
// covered too.
const csrfCookie = "__Host-matcha-csrf"

type csrfKey struct{}

func csrfToken(r *http.Request) string {
	t, _ := r.Context().Value(csrfKey{}).(string)
	return t
}

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) == 43 {
			token = c.Value
		}

		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
			sent := r.Header.Get("X-CSRF-Token")
			if sent == "" {
				sent = r.PostFormValue("csrf_token")
			}
			if token == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(token)) != 1 {
				r = r.WithContext(context.WithValue(r.Context(), csrfKey{}, s.setCSRFCookie(w, token)))
				s.message(w, r, http.StatusForbidden, "Form expired",
					"The form was sent without a valid security token. Load the page again and retry.", r.URL.Path, "Reload")
				return
			}
		}
		token = s.setCSRFCookie(w, token)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), csrfKey{}, token)))
	})
}

// setCSRFCookie issues a new token when there is none and returns the
// token in force.
func (s *Server) setCSRFCookie(w http.ResponseWriter, token string) string {
	if token != "" {
		return token
	}
	token = newSecret()
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

// newSecret returns 256 random bits, base64url-encoded (43 characters).
func newSecret() string {
	var b [32]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
