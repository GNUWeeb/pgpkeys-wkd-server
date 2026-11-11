package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/web/ui"
)

// normalizeAddress checks that input is an address in domain and returns
// it in lower case. The local-part must be a dot-atom of ASCII characters
// (RFC 5322), which every GNUWeeb address is; quoted local-parts and
// non-ASCII addresses are refused.
func normalizeAddress(input, domain string) (string, error) {
	addr := strings.TrimSpace(input)
	local, dom, ok := strings.Cut(addr, "@")
	if !ok || !strings.EqualFold(dom, domain) {
		return "", fmt.Errorf("Enter an address ending in @%s.", domain)
	}
	if !validLocalPart(local) {
		return "", errors.New("That is not a valid mail address.")
	}
	return strings.ToLower(local) + "@" + domain, nil
}

func validLocalPart(s string) bool {
	if s == "" || len(s) > 64 || s[0] == '.' || s[len(s)-1] == '.' || strings.Contains(s, "..") {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte(".!#$%&'*+-/=?^_`{|}~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if sessionAddress(r) != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, ui.Login(s.page(r, "Log in"), s.opts.Domain, "", ""))
}

// loginRequest mails a login link. Every valid address in the domain gets
// the same answer, whether or not a mailbox exists, whether or not the
// per-address limit held the mail back, and whether or not the mail
// server accepted it: the mail is sent in the background, so not even
// the response time tells them apart.
func (s *Server) loginRequest(w http.ResponseWriter, r *http.Request) {
	input := r.PostFormValue("address")
	addr, err := normalizeAddress(input, s.opts.Domain)
	if err != nil {
		s.render(w, r, http.StatusUnprocessableEntity, ui.Login(s.page(r, "Log in"), s.opts.Domain, input, err.Error()))
		return
	}
	now := s.now()
	if !s.clients.allow(s.clientIP(r), now) {
		s.message(w, r, http.StatusTooManyRequests, "Too many requests",
			"Too many login links were requested from your network. Wait an hour and try again.", "", "")
		return
	}
	ctx := r.Context()
	if err := s.store.Purge(ctx, now, now.Add(-rateWindow)); err != nil {
		s.internalError(w, r, err)
		return
	}
	n, err := s.store.CountLoginTokens(ctx, addr, now.Add(-rateWindow))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if n < addressLimit {
		token := newSecret()
		if err := s.store.AddLoginToken(ctx, hashSecret(token), addr, now, now.Add(tokenTTL)); err != nil {
			s.internalError(w, r, err)
			return
		}
		s.sendLink(addr, token)
	} else {
		s.log.Info("login link held back by the per-address limit", "address", addr)
	}
	s.render(w, r, http.StatusOK, ui.CheckMail(s.page(r, "Check your mail"), addr, int(tokenTTL.Minutes())))
}

func (s *Server) sendLink(addr, token string) {
	link := s.opts.BaseURL + "/login/confirm?token=" + url.QueryEscape(token)
	host := strings.TrimPrefix(strings.TrimPrefix(s.opts.BaseURL, "https://"), "http://")
	subject := "Log in to " + host
	body := fmt.Sprintf(`Hello,

someone, hopefully you, asked to log in to the GNUWeeb OpenPGP key
directory as %s. Open this link within %d minutes to log in:

%s

The link works once. If you did not ask for it, ignore this mail.
`, addr, int(tokenTTL.Minutes()), link)

	s.sendMail(addr, subject, body, "login link")
}

// sendMail sends a mail in the background; what names it in the log.
// Wait waits for it.
func (s *Server) sendMail(to, subject, body, what string) {
	s.mails.Add(1)
	go func() {
		defer s.mails.Done()
		ctx, cancel := context.WithTimeout(context.Background(), mailTimeout)
		defer cancel()
		if err := s.mailer.Send(ctx, to, subject, body); err != nil {
			s.log.Error("sending "+what, "address", to, "err", err)
			return
		}
		s.log.Info(what+" sent", "address", to)
	}()
}

func (s *Server) invalidLink(w http.ResponseWriter, r *http.Request) {
	s.message(w, r, http.StatusBadRequest, "Link not valid",
		"This login link is wrong, expired or already used. Ask for a new one.", "/login", "Log in")
}

// confirmForm is where the mailed link lands. It checks the token without
// using it up and asks for a button press.
func (s *Server) confirmForm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	addr, ok, err := s.store.LoginTokenAddress(r.Context(), hashSecret(token), s.now())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if token == "" || !ok {
		s.invalidLink(w, r)
		return
	}
	s.render(w, r, http.StatusOK, ui.Confirm(s.page(r, "Log in"), token, addr))
}

// confirm uses up the token and starts a session.
func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	token := r.PostFormValue("token")
	addr, ok, err := s.store.UseLoginToken(r.Context(), hashSecret(token), s.now())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if token == "" || !ok {
		s.invalidLink(w, r)
		return
	}
	if old, err := r.Cookie(sessionCookie); err == nil {
		if err := s.store.DeleteSession(r.Context(), hashSecret(old.Value)); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	if err := s.startSession(w, r, addr); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.log.Info("login", "address", addr)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.store.DeleteSession(r.Context(), hashSecret(c.Value)); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	clearCookie(w, sessionCookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
