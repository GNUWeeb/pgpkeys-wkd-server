package web

import (
	"context"
	"crypto/sha256"
	"net/http"
)

const sessionCookie = "__Host-matcha-session"

type sessionKey struct{}

// sessionAddress is the logged-in member's address, or "".
func sessionAddress(r *http.Request) string {
	a, _ := r.Context().Value(sessionKey{}).(string)
	return a
}

// hashSecret is how login tokens and session IDs are stored.
func hashSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// session resolves the session cookie to the member's address.
func (s *Server) session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || c.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		addr, ok, err := s.store.SessionAddress(r.Context(), hashSecret(c.Value), s.now())
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if !ok {
			clearCookie(w, sessionCookie)
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, addr)))
	})
}

// requireLogin sends visitors without a session to the login page.
func (s *Server) requireLogin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sessionAddress(r) == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		h(w, r)
	}
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, address string) error {
	id := newSecret()
	now := s.now()
	if err := s.store.AddSession(r.Context(), hashSecret(id), address, now, now.Add(sessionTTL)); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
