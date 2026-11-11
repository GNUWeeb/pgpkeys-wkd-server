package web

import (
	"cmp"
	"net/http"
	"slices"
	"time"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/web/ui"
)

// trust shows the member's direct links in the web of trust: the members
// whose keys certified the member's keys, and the members whose keys the
// member's keys certified. Members linked to neither are not shown.
func (s *Server) trust(w http.ResponseWriter, r *http.Request) {
	own, err := s.store.Keys(r.Context(), sessionAddress(r))
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

	p := s.page(r, "Web of trust")
	p.Nav = "/trust"
	s.render(w, r, http.StatusOK, ui.Trust(p, s.trustLinks(in, addresses), others, s.trustLinks(out, addresses)))
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
