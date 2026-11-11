package web

import (
	"cmp"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/store"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/web/ui"
)

// trust shows the member's direct links in the web of trust: the members
// whose keys certified the member's keys, and the members whose keys the
// member's keys certified. Members linked to neither are not shown. Above
// and below them, it lists the submitted certifications that wait for the
// member and those the member submitted that wait for others.
func (s *Server) trust(w http.ResponseWriter, r *http.Request) {
	addr := sessionAddress(r)
	own, err := s.store.Keys(r.Context(), addr)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	signers, addresses, err := s.signers(r)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := s.now()
	mine := map[string]bool{}
	ownSigners := make([]keys.Signer, 0, len(own))
	for _, k := range own {
		mine[k.Fingerprint] = true
		ownSigners = append(ownSigners, keys.Signer{Fingerprint: k.Fingerprint, Data: k.Data})
	}

	// A member's keys certifying each other is not a link to anyone.
	var in, out []link
	others := 0
	for _, k := range own {
		certs, n, err := keys.Certifications(k.Data, signers, now)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		others += n
		for _, c := range certs {
			if !mine[c.Signer] {
				in = append(in, link{other: c.Signer, Certification: c})
			}
		}
	}
	for _, k := range signers {
		if mine[k.Fingerprint] {
			continue
		}
		certs, _, err := keys.Certifications(k.Data, ownSigners, now)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		for _, c := range certs {
			out = append(out, link{other: k.Fingerprint, Certification: c})
		}
	}

	waiting, err := s.store.PendingFor(r.Context(), addr)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	sent, err := s.store.PendingBy(r.Context(), addr)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	v := ui.TrustView{
		In:     s.trustLinks(in, addresses),
		Out:    s.trustLinks(out, addresses),
		Others: others,
	}
	fprs := make([]string, 0, len(own))
	for _, k := range own {
		fprs = append(fprs, k.Fingerprint)
	}
	if v.Root, err = s.rootPathOf(r.Context(), fprs); err != nil {
		s.internalError(w, r, err)
		return
	}
	for _, c := range waiting {
		v.Waiting = append(v.Waiting, ui.CertRequest{ID: c.ID, Members: s.memberAddresses([]string{c.SubmittedBy}),
			Fingerprint: c.Signer, UserID: c.UserID, Created: c.Created})
	}
	for _, c := range sent {
		v.Sent = append(v.Sent, ui.CertRequest{ID: c.ID, Members: s.memberAddresses(addresses[c.Fingerprint]),
			Fingerprint: c.Fingerprint, UserID: c.UserID, Created: c.Created})
	}
	p := s.page(r, "Web of trust")
	p.Nav = "/trust"
	s.render(w, r, http.StatusOK, ui.Trust(p, v, trustFlash[r.URL.Query().Get("done")]))
}

// trustFlash is the notice the web of trust page shows after a change.
var trustFlash = map[string]ui.Flash{
	"submitted": {Kind: "ok", Text: "Certification sent to the key's owner."},
	"accepted":  {Kind: "ok", Text: "Certification accepted."},
	"rejected":  {Kind: "ok", Text: "Certification rejected."},
	"withdrawn": {Kind: "ok", Text: "Certification withdrawn."},
}

func (s *Server) certifyForm(w http.ResponseWriter, r *http.Request) {
	p := s.page(r, "Submit a certification")
	p.Nav = "/trust"
	s.render(w, r, http.StatusOK, ui.Certify(p, "", "", keys.MaxSize>>10))
}

// certify takes the certifications the member's keys made on another
// member's stored key from the copy the member submitted, and keeps them
// until the key's owner accepts them. The owner is mailed when one of them
// is new.
func (s *Server) certify(w http.ResponseWriter, r *http.Request) {
	addr := sessionAddress(r)
	pasted, input, err := formKey(r)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	fail := func(msg string) {
		p := s.page(r, "Submit a certification")
		p.Nav = "/trust"
		s.render(w, r, http.StatusUnprocessableEntity, ui.Certify(p, pasted, msg, keys.MaxSize>>10))
	}
	if len(strings.TrimSpace(string(input))) == 0 {
		fail("Paste a key or choose a file.")
		return
	}
	data, fpr, err := keys.ReadSubmitted(input)
	if err != nil {
		fail("This cannot be submitted: " + err.Error() + ".")
		return
	}
	all, err := s.store.AllKeys(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var target *store.StoredKey
	var owners []string
	var own []keys.Signer
	for i, k := range all {
		if k.Fingerprint == fpr {
			owners = append(owners, k.Address)
			if target == nil || k.Uploaded.After(target.Uploaded) {
				target = &all[i]
			}
		}
		if k.Address == addr {
			own = append(own, keys.Signer{Fingerprint: k.Fingerprint, Data: k.Data})
		}
	}
	switch {
	case target == nil:
		fail("This key is not in the directory. Its owner has to add it first.")
		return
	case slices.Contains(owners, addr):
		fail("This is your own key. Submit another member's key that you certified.")
		return
	case len(own) == 0:
		fail("Add your own key first: only certifications made with a key stored for you are taken.")
		return
	}
	now := s.now()
	subs, err := keys.Submitted(data, target.Data, own, now)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(subs) == 0 {
		fail("The key holds no certification by your keys that it does not have already. Certify it with gpg --sign-key, export it again and paste it here.")
		return
	}
	asked := false
	for _, sub := range subs {
		isNew, err := s.store.SubmitCertification(r.Context(), fpr, sub, addr, now)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		asked = asked || isNew
	}
	s.log.Info("certification submitted", "address", addr, "fingerprint", fpr, "certifications", len(subs))
	if asked {
		for _, o := range owners {
			s.sendMail(o, addr+" certified your OpenPGP key", fmt.Sprintf(`Hello,

%s certified your OpenPGP key

  %s

in the GNUWeeb OpenPGP key directory. Accept or reject the
certification here:

%s/trust

Nothing changes until you accept it. Accepted certifications are added
to your key in the directory; Web Key Directory serves your key without
them, as before.
`, addr, fpr, s.opts.BaseURL), "certification request")
		}
	}
	http.Redirect(w, r, "/trust?done=submitted", http.StatusSeeOther)
}

// certRequest runs act on the request named in the URL for the session's
// address and goes back to the web of trust page with done, or answers
// 404 when act finds no such request for the member.
func (s *Server) certRequest(act func(r *http.Request, id int64, address string) (bool, error), done string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := sessionAddress(r)
		id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		ok := false
		if err == nil {
			if ok, err = act(r, id, addr); err != nil {
				s.internalError(w, r, err)
				return
			}
		}
		if !ok {
			s.message(w, r, http.StatusNotFound, "Request not found", "No such certification waits for you.", "/trust", "Back to the web of trust")
			return
		}
		s.log.Info("certification "+done, "address", addr, "request", id)
		http.Redirect(w, r, "/trust?done="+done, http.StatusSeeOther)
	}
}

// link is a certification between one of the member's keys and the key
// of another member, other.
type link struct {
	other string
	keys.Certification
}

// trustLinks groups links by the other member's key, ordered by address,
// with the certified User IDs and the date of the latest certification.
func (s *Server) trustLinks(links []link, addresses map[string][]string) []ui.TrustLink {
	byKey := map[string]int{}
	var out []ui.TrustLink
	for _, l := range links {
		i, ok := byKey[l.other]
		if !ok {
			i = len(out)
			byKey[l.other] = i
			out = append(out, ui.TrustLink{Fingerprint: l.other, Addresses: s.memberAddresses(addresses[l.other])})
		}
		t := &out[i]
		if !slices.Contains(t.UserIDs, l.UserID) {
			t.UserIDs = append(t.UserIDs, l.UserID)
		}
		t.Certified = latest(t.Certified, l.Created)
	}
	slices.SortFunc(out, func(a, b ui.TrustLink) int {
		return cmp.Or(cmp.Compare(firstAddress(a), firstAddress(b)), cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
	return out
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func firstAddress(t ui.TrustLink) string {
	if len(t.Addresses) == 0 {
		return ""
	}
	return t.Addresses[0].Address
}
