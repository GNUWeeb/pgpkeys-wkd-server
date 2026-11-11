package web

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func TestRootPaths(t *testing.T) {
	h := newHarness(t)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}
	names := map[*openpgp.Entity]string{}
	newKey := func(name string) *openpgp.Entity {
		e, err := openpgp.NewEntity(name, "", name+"@gnuweeb.org", cfg)
		if err != nil {
			t.Fatal(err)
		}
		names[e] = name
		return e
	}
	root, alice, bob, carol, dave := newKey("root"), newKey("alice"), newKey("bob"), newKey("carol"), newKey("dave")
	sign := func(e, by *openpgp.Entity) {
		if err := e.SignIdentity(names[e]+" <"+names[e]+"@gnuweeb.org>", by, cfg); err != nil {
			t.Fatal(err)
		}
	}
	// root -> alice -> bob, and bob also by carol; dave certified the
	// root, which does not connect dave; carol is certified by no one
	// connected.
	sign(alice, root)
	sign(bob, alice)
	sign(bob, carol)
	sign(root, dave)
	for _, e := range []*openpgp.Entity{root, alice, bob, carol, dave} {
		addr := names[e] + "@gnuweeb.org"
		if resp, _ := h.post(h.loginAs(addr), "/keys", url.Values{"key": {armoredEntity(t, e)}}); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("%s's upload: status %d", addr, resp.StatusCode)
		}
	}
	c := h.loginAs("bob@gnuweeb.org")

	// Without a root key, nothing is said about one.
	if _, body := h.get(c, "/members/bob@gnuweeb.org"); strings.Contains(body, "root key") {
		t.Error("member page mentions a root key while none is set")
	}

	h.srv.opts.RootKey = strings.ToUpper(fingerprintHex(root.PrimaryKey.Fingerprint))
	_, body := h.get(c, "/members/bob@gnuweeb.org")
	path := body[strings.Index(body, `class="path"`):]
	path = path[:strings.Index(path, "</p>")]
	r, a, b := strings.Index(path, `href="/members/root@`), strings.Index(path, `href="/members/alice@`), strings.Index(path, `href="/members/bob@`)
	if r < 0 || r > a || a > b || strings.Contains(path, "carol@") {
		t.Errorf("bob's path is not root, alice, bob: %s", path)
	}

	_, list := h.get(c, "/members")
	graph, _, ok := strings.Cut(list, "</svg>")
	if !ok {
		t.Fatal("members page has no graph")
	}
	// Members sit in bands by their steps from the root key: the root key's
	// holder on top, then alice, then bob, and those not connected last.
	rowY := func(addr string) int {
		m := regexp.MustCompile(`href="/members/` + addr + `@gnuweeb.org"[^>]*><rect x="\d+" y="(\d+)"`).FindStringSubmatch(graph)
		if m == nil {
			t.Fatalf("graph has no box for %s", addr)
		}
		y, _ := strconv.Atoi(m[1])
		return y
	}
	if ys := []int{rowY("root"), rowY("alice"), rowY("bob"), rowY("carol")}; !slices.IsSorted(ys) || ys[0] == ys[1] || ys[1] == ys[2] || ys[2] == ys[3] || rowY("dave") != ys[3] {
		t.Errorf("graph rows: root, alice, bob, carol at %v, dave at %d", ys, rowY("dave"))
	}
	// Every certification between members is an arrow, whatever its
	// direction, and the bands run from the root key down.
	for _, edge := range []string{"root@gnuweeb.org certified alice@gnuweeb.org", "alice@gnuweeb.org certified bob@gnuweeb.org",
		"carol@gnuweeb.org certified bob@gnuweeb.org", "dave@gnuweeb.org certified root@gnuweeb.org"} {
		if !strings.Contains(graph, "<title>"+edge+"</title>") {
			t.Errorf("graph lacks %q", edge)
		}
	}
	if n := strings.Count(graph, `class="graph-edge`); n != 4 {
		t.Errorf("graph has %d arrows, want 4", n)
	}
	// Bob, looking, sees his own chain highlighted: root to alice to bob.
	var mine []string
	for _, m := range regexp.MustCompile(`class="graph-edge mine"[^>]*>\s*<title>([^<]*)</title>`).FindAllStringSubmatch(graph, -1) {
		mine = append(mine, m[1])
	}
	slices.Sort(mine)
	if want := []string{"alice@gnuweeb.org certified bob@gnuweeb.org", "root@gnuweeb.org certified alice@gnuweeb.org"}; !slices.Equal(mine, want) {
		t.Errorf("highlighted arrows: %v, want %v", mine, want)
	}
	if bands := []int{strings.Index(graph, ">Root key<"), strings.Index(graph, ">1 step<"), strings.Index(graph, ">2 steps<"), strings.Index(graph, ">No path from root key<")}; !slices.IsSorted(bands) || bands[0] < 0 {
		t.Errorf("graph bands out of order: %v", bands)
	}
	if _, body := h.get(c, "/members/dave@gnuweeb.org"); !strings.Contains(body, "No path from the root key.") {
		t.Error("dave's page does not say no path leads to him")
	}

	// A root key that is not stored connects no one.
	h.srv.opts.RootKey = strings.Repeat("A", 40)
	if _, list := h.get(c, "/members"); strings.Contains(list, ">Root key<") || strings.Contains(list, "step") {
		t.Error("an unknown root key connects members")
	}
}
