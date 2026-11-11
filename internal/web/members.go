package web

import (
	"bytes"
	"cmp"
	"image"
	"image/png"
	"net/http"
	"net/url"
	"slices"
	"strconv"
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
		s.message(w, r, http.StatusNotFound, "Member not found", "No keys are stored for this address.", "/members", "Back to the members")
		return
	}
	now := s.now()
	v := ui.MemberView{Address: addr, Download: memberURL(addr) + "/keys.asc", Photo: s.photoURL(addr)}
	fprs := make([]string, 0, len(stored))
	for _, k := range stored {
		info, err := keys.Describe(k.Data, now)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		v.Keys = append(v.Keys, info)
		fprs = append(fprs, k.Fingerprint)
	}
	if v.Root, err = s.rootPathOf(r.Context(), fprs); err != nil {
		s.internalError(w, r, err)
		return
	}
	v.Name = displayName(v.Keys, addr)
	v.Initials = initials(v.Name)
	p := s.page(r, v.Name)
	p.Nav = "/members"
	s.render(w, r, http.StatusOK, ui.Member(p, v))
}

// photoURL serves the photo of the member with address, or is empty
// when photos are off.
func (s *Server) photoURL(address string) string {
	if s.opts.Gravatar == nil {
		return ""
	}
	return memberURL(address) + "/avatar.png"
}

// members lists every member who has keys stored, by name, each linked
// to their page.
func (s *Server) members(w http.ResponseWriter, r *http.Request) {
	all, err := s.store.AllKeys(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := s.now()
	signers, addresses := signersOf(all)
	certified, err := certEdges(signers, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	paths := s.rootPaths(signers, certified)
	byAddress := map[string][]keys.Info{}
	var order []string
	for _, k := range all {
		info, err := keys.Describe(k.Data, now)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		if _, ok := byAddress[k.Address]; !ok {
			order = append(order, k.Address)
		}
		byAddress[k.Address] = append(byAddress[k.Address], info)
	}
	rows := make([]ui.MemberRow, 0, len(order))
	for _, addr := range order {
		name := displayName(byAddress[addr], addr)
		row := ui.MemberRow{
			Address: addr, Name: name, Initials: initials(name), URL: memberURL(addr),
			Photo: s.photoURL(addr), Keys: len(byAddress[addr]),
		}
		if s.opts.RootKey != "" {
			fprs := make([]string, 0, len(byAddress[addr]))
			for _, k := range byAddress[addr] {
				fprs = append(fprs, k.Fingerprint)
			}
			row.Root = s.rootPathView(paths, addresses, fprs)
		}
		rows = append(rows, row)
	}
	slices.SortStableFunc(rows, func(a, b ui.MemberRow) int {
		return cmp.Or(strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), strings.Compare(a.Address, b.Address))
	})
	// Who certified whom, by address: a member's keys certifying each
	// other is no link.
	var links [][2]string
	for from, tos := range certified {
		for _, to := range tos {
			for _, a := range addresses[from] {
				for _, b := range addresses[to] {
					if a != b && !slices.Contains(links, [2]string{a, b}) {
						links = append(links, [2]string{a, b})
					}
				}
			}
		}
	}
	p := s.page(r, "Members")
	p.Nav = "/members"
	s.render(w, r, http.StatusOK, ui.Members(p, rows, layoutGraph(rows, links)))
}

// blankPNG is a transparent pixel: the photo of a member who has none,
// over which the initials show.
var blankPNG = func() []byte {
	var b bytes.Buffer
	png.Encode(&b, image.NewNRGBA(image.Rect(0, 0, 1, 1)))
	return b.Bytes()
}()

// memberPhoto serves the photo a member keeps at Gravatar, which the
// server fetches, or a transparent pixel when there is none or Gravatar
// cannot be asked. Addresses without keys answer 404, so that the
// dashboard asks Gravatar about members alone.
func (s *Server) memberPhoto(w http.ResponseWriter, r *http.Request) {
	if s.opts.Gravatar == nil {
		http.NotFound(w, r)
		return
	}
	addr := strings.ToLower(chi.URLParam(r, "address"))
	stored, err := s.store.Keys(r.Context(), addr)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(stored) == 0 {
		http.NotFound(w, r)
		return
	}
	photo, maxAge, err := s.opts.Gravatar.Photo(r.Context(), addr)
	if err != nil {
		s.log.Warn("gravatar", "address", addr, "err", err)
	}
	if photo == nil {
		photo = blankPNG
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age="+strconv.Itoa(int(maxAge.Seconds())))
	w.Write(photo)
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
		s.message(w, r, http.StatusNotFound, "Member not found", "No keys are stored for this address.", "/members", "Back to the members")
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
