package web

import (
	"context"
	"slices"
	"time"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/keys"
	"git.gnuweeb.net/GNUWeeb/matcha/internal/web/ui"
)

// certEdges returns, per stored key, the stored keys it certified on one
// of their User IDs (a certification keys.Certifications counts), in the
// order of signers.
func certEdges(signers []keys.Signer, now time.Time) (map[string][]string, error) {
	certified := map[string][]string{}
	for _, k := range signers {
		certs, _, err := keys.Certifications(k.Data, signers, now)
		if err != nil {
			return nil, err
		}
		for _, c := range certs {
			if !slices.Contains(certified[c.Signer], k.Fingerprint) {
				certified[c.Signer] = append(certified[c.Signer], k.Fingerprint)
			}
		}
	}
	return certified, nil
}

// rootPaths traces the web of trust from the root key, as kernel.org
// traces its keyring to Linus Torvalds' key: for every stored key the
// root key reaches through certified (certEdges), the shortest chain of
// fingerprints from the root key to it. Among chains of one length the
// first in certified's order wins. The root key's own chain is itself
// alone. It is nil when no root key is set or the root key is not stored.
func (s *Server) rootPaths(signers []keys.Signer, certified map[string][]string) map[string][]string {
	root := s.opts.RootKey
	if root == "" || !slices.ContainsFunc(signers, func(k keys.Signer) bool { return k.Fingerprint == root }) {
		return nil
	}
	paths := map[string][]string{root: {root}}
	queue := []string{root}
	for len(queue) > 0 {
		from := queue[0]
		queue = queue[1:]
		for _, to := range certified[from] {
			if _, ok := paths[to]; !ok {
				paths[to] = append(slices.Clone(paths[from]), to)
				queue = append(queue, to)
			}
		}
	}
	return paths
}

// rootPathView is the shortest of the chains in paths that lead to one of
// the keys fprs, a member's keys, with the addresses of each key on it.
// Its Steps are empty when no chain leads there.
func (s *Server) rootPathView(paths, addresses map[string][]string, fprs []string) *ui.RootPath {
	var best []string
	for _, f := range fprs {
		if p, ok := paths[f]; ok && (best == nil || len(p) < len(best)) {
			best = p
		}
	}
	v := &ui.RootPath{}
	for _, f := range best {
		v.Steps = append(v.Steps, ui.PathStep{Fingerprint: f, Addresses: s.memberAddresses(addresses[f])})
	}
	return v
}

// rootPathOf is rootPathView for the member whose keys are fprs, read
// from the store; nil when no root key is set.
func (s *Server) rootPathOf(ctx context.Context, fprs []string) (*ui.RootPath, error) {
	if s.opts.RootKey == "" {
		return nil, nil
	}
	all, err := s.store.AllKeys(ctx)
	if err != nil {
		return nil, err
	}
	signers, addresses := signersOf(all)
	certified, err := certEdges(signers, s.now())
	if err != nil {
		return nil, err
	}
	return s.rootPathView(s.rootPaths(signers, certified), addresses, fprs), nil
}
