package web

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/go-chi/chi/v5"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/web/ui"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/wkd"
)

// memberURL is the dashboard page of the member with address.
func memberURL(address string) string { return "/members/" + url.PathEscape(address) }

// memberAddresses links each address to the member's page.
func (s *Server) memberAddresses(addresses []string) []ui.MemberAddress {
	out := make([]ui.MemberAddress, 0, len(addresses))
	for _, a := range addresses {
		out = append(out, ui.MemberAddress{Address: a, URL: memberURL(a)})
	}
	return out
}

// member shows another member's keys, as WKD serves them to anyone who
// knows the address: their User IDs, dates and status, but not who
// certified them, which stays between the members linked (the web of
// trust page). An address without keys answers 404.
func (s *Server) member(w http.ResponseWriter, r *http.Request) {
	addr := strings.ToLower(chi.URLParam(r, "address"))
	stored, err := s.store.Keys(r.Context(), addr)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(stored) == 0 {
		s.message(w, r, http.StatusNotFound, "Member not found", "No keys are stored for this address.", "/trust", "Back to the web of trust")
		return
	}
	now := s.now()
	v := ui.MemberView{Address: addr, Self: addr == sessionAddress(r), Download: memberURL(addr) + "/keys.asc"}
	for _, k := range stored {
		info, err := keys.Describe(k.Data, now)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		v.Keys = append(v.Keys, info)
	}
	v.Name = displayName(v.Keys, addr)
	v.Initials = initials(v.Name)
	p := s.page(r, v.Name)
	p.Nav = "/trust"
	s.render(w, r, http.StatusOK, ui.Member(p, v))
}

// memberKeys serves the keys of a member, armored, as WKD serves them:
// without the certifications of other keys.
func (s *Server) memberKeys(w http.ResponseWriter, r *http.Request) {
	addr := strings.ToLower(chi.URLParam(r, "address"))
	local, domain, _ := strings.Cut(addr, "@")
	var views [][]byte
	if domain == s.opts.Domain {
		var err error
		if views, err = s.store.WKDKeys(r.Context(), wkd.Hash(local)); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	if len(views) == 0 {
		s.message(w, r, http.StatusNotFound, "Member not found", "No keys are stored for this address.", "/trust", "Back to the web of trust")
		return
	}
	var b bytes.Buffer
	aw, err := armor.Encode(&b, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	for _, v := range views {
		aw.Write(v)
	}
	if err := aw.Close(); err != nil {
		s.internalError(w, r, err)
		return
	}
	b.WriteByte('\n')
	w.Header().Set("Content-Type", "application/pgp-keys")
	w.Header().Set("Content-Disposition", `attachment; filename="`+local+`.asc"`)
	w.Write(b.Bytes())
}

// displayName is the name in the newest User ID with address, such as
// "Alice Liddell" in "Alice Liddell <alice@gnuweeb.org>", or address when
// no such User ID has one.
func displayName(list []keys.Info, address string) string {
	for _, k := range list {
		for _, id := range k.UserIDs {
			name, rest, ok := strings.Cut(id, " <")
			if ok && strings.EqualFold(strings.TrimSuffix(rest, ">"), address) && strings.TrimSpace(name) != "" {
				return strings.TrimSpace(name)
			}
		}
	}
	return address
}

// initials are the first letters of the first and last word of name, the
// local part when name is an address, or the first letter alone of one
// word.
func initials(name string) string {
	if local, _, ok := strings.Cut(name, "@"); ok {
		name = local
	}
	words := strings.FieldsFunc(name, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	first := func(w string) string {
		r, _ := utf8.DecodeRuneInString(w)
		return string(unicode.ToUpper(r))
	}
	switch len(words) {
	case 0:
		return "?"
	case 1:
		return first(words[0])
	}
	return first(words[0]) + first(words[len(words)-1])
}
