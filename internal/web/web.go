// Package web is the dashboard: login by mailed link and, after login,
// the member's keys.
package web

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/store"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/web/ui"
)

// Lifetimes and limits of the login flow.
const (
	tokenTTL   = 15 * time.Minute
	sessionTTL = 7 * 24 * time.Hour
	// At most addressLimit links are mailed to one address, and one
	// client may ask for at most clientLimit links, per rateWindow.
	rateWindow   = time.Hour
	addressLimit = 5
	clientLimit  = 20
	// mailTimeout bounds one SMTP conversation.
	mailTimeout = 30 * time.Second
	// maxBody caps the body of every state-changing request.
	maxBody = 2 << 20
)

// Mailer sends one plain-text message.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// Options configures the dashboard.
type Options struct {
	// Domain is the mail domain whose members may log in, lower case.
	Domain string
	// BaseURL is the dashboard's public URL without a trailing slash.
	BaseURL string
	// RealIPHeader, when set, names the header that carries the client
	// address behind a reverse proxy.
	RealIPHeader string
}

// Server serves the dashboard.
type Server struct {
	opts    Options
	store   *store.Store
	mailer  Mailer
	log     *slog.Logger
	now     func() time.Time
	clients *limiter
	assets  *assets
	mails   sync.WaitGroup
	router  chi.Router
}

// New returns the dashboard.
func New(opts Options, st *store.Store, mailer Mailer, log *slog.Logger) *Server {
	s := &Server{
		opts:    opts,
		store:   st,
		mailer:  mailer,
		log:     log,
		now:     time.Now,
		clients: newLimiter(clientLimit, rateWindow),
		assets:  newAssets(),
	}
	r := chi.NewRouter()
	r.Use(securityHeaders)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		s.message(w, r, http.StatusNotFound, "Not found", "There is no page here.", "/", "Go to the start page")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		s.message(w, r, http.StatusMethodNotAllowed, "Not allowed", "This page does not accept that request.", "/", "Go to the start page")
	})
	// Static files carry no cookies, so caches may keep them.
	r.Handle("/static/*", s.assets)
	r.Group(func(r chi.Router) {
		r.Use(s.csrf, s.session)
		r.Get("/", s.requireLogin(s.keyList))
		r.Get("/login", s.loginForm)
		r.Post("/login", s.loginRequest)
		r.Get("/login/confirm", s.confirmForm)
		r.Post("/login/confirm", s.confirm)
		r.Post("/logout", s.logout)
		r.Get("/keys/new", s.requireLogin(s.addKeyForm))
		r.Post("/keys", s.requireLogin(s.addKey))
		r.Get("/keys/{fpr}/remove", s.requireLogin(s.removeKeyForm))
		r.Post("/keys/{fpr}/remove", s.requireLogin(s.removeKey))
		r.Get("/trust", s.requireLogin(s.trust))
		r.Get("/members/{address}", s.requireLogin(s.member))
		r.Get("/members/{address}/keys.asc", s.requireLogin(s.memberKeys))
		r.Get("/trust/certify", s.requireLogin(s.certifyForm))
		r.Post("/trust/certify", s.requireLogin(s.certify))
		r.Post("/trust/requests/{id}/accept", s.requireLogin(s.certRequest(func(r *http.Request, id int64, addr string) (bool, error) {
			return s.store.AcceptCertification(r.Context(), id, addr, s.now())
		}, "accepted")))
		r.Post("/trust/requests/{id}/reject", s.requireLogin(s.certRequest(func(r *http.Request, id int64, addr string) (bool, error) {
			return s.store.RejectCertification(r.Context(), id, addr)
		}, "rejected")))
		r.Post("/trust/requests/{id}/withdraw", s.requireLogin(s.certRequest(func(r *http.Request, id int64, addr string) (bool, error) {
			return s.store.WithdrawCertification(r.Context(), id, addr)
		}, "withdrawn")))
	})
	s.router = r
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.router.ServeHTTP(w, r) }

// Wait blocks until every login mail that is being sent has been handed
// over or has failed.
func (s *Server) Wait() { s.mails.Wait() }

// page returns the frame data for r.
func (s *Server) page(r *http.Request, title string) ui.Page {
	return ui.Page{Title: title, CSRF: csrfToken(r), Address: sessionAddress(r), Asset: s.assets.url}
}

// render writes c with the given status.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := c.Render(r.Context(), w); err != nil {
		s.log.Error("render", "path", r.URL.Path, "err", err)
	}
}

func (s *Server) message(w http.ResponseWriter, r *http.Request, status int, heading, text, href, label string) {
	s.render(w, r, status, ui.Message(s.page(r, heading), heading, text, href, label))
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request", "method", r.Method, "path", r.URL.Path, "err", err)
	s.message(w, r, http.StatusInternalServerError, "Something went wrong", "The server could not complete the request. Try again later.", "/", "Go to the start page")
}

// clientIP is the address rate limits are counted against.
func (s *Server) clientIP(r *http.Request) string {
	if s.opts.RealIPHeader != "" {
		if v := r.Header.Get(s.opts.RealIPHeader); v != "" {
			return v
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// securityHeaders sets the headers every dashboard response carries. The
// Content-Security-Policy allows only the dashboard's own scripts, styles
// and fonts; Referrer-Policy keeps login links out of Referer headers;
// no-store keeps pages of a session out of caches after logout.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "+
			"font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
