package web

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"

	"git.gnuweeb.net/GNUWeeb/matcha/internal/web/ui"
)

// Sizes of the web of trust graph, in SVG units (pixels at 100%).
const (
	graphNodeW = 180
	graphNodeH = 46
	graphGapX  = 28
	graphGapY  = 64
	// graphMargin leaves room left of the first column for the arrows
	// that run along the side of the boxes.
	graphMargin  = 40
	graphPerRow  = 5
	graphNameMax = 22
	graphAddrMax = 26
)

// layoutGraph draws the members (rows, sorted by name) and who certified
// whom (links, by address, from certifier to certified). With a root key,
// members sit in bands by their steps from it, the root key's holder on
// top and those it does not reach at the bottom, so that most links
// point down; without one, all sit in one band. A band wraps after
// graphPerRow members. mine, the addresses on the viewer's own chain from
// the root key, is highlighted.
func layoutGraph(rows []ui.MemberRow, links [][2]string, mine []string) ui.Graph {
	if len(rows) == 0 {
		return ui.Graph{}
	}
	steps := func(m ui.MemberRow) int {
		if m.Root == nil {
			return 0
		}
		if len(m.Root.Steps) == 0 {
			return -1
		}
		return len(m.Root.Steps) - 1
	}
	withRoot := rows[0].Root != nil
	// Bands in order: 0, 1, 2, ..., then -1 (not connected).
	bandOf := map[int][]ui.MemberRow{}
	var bands []int
	for _, m := range rows {
		s := steps(m)
		if _, ok := bandOf[s]; !ok {
			bands = append(bands, s)
		}
		bandOf[s] = append(bandOf[s], m)
	}
	slices.SortFunc(bands, func(a, b int) int {
		if (a < 0) != (b < 0) {
			return cmp.Compare(b, a)
		}
		return cmp.Compare(a, b)
	})

	g := ui.Graph{}
	left := graphMargin
	widest := 0
	at := map[string]int{} // address to node index
	// Room above the first row for its label and for arcs between
	// members of one row.
	y := graphMargin + graphGapY/2
	for _, b := range bands {
		members := bandOf[b]
		if withRoot {
			label := "No path from root key"
			switch {
			case b == 0:
				label = "Root key"
			case b == 1:
				label = "1 step"
			case b > 1:
				label = strconv.Itoa(b) + " steps"
			}
			g.Bands = append(g.Bands, ui.GraphBand{Label: label, X: left, Y: y - 12})
		}
		for i := 0; i < len(members); i += graphPerRow {
			row := members[i:min(i+graphPerRow, len(members))]
			widest = max(widest, len(row))
			for j, m := range row {
				at[m.Address] = len(g.Nodes)
				g.Nodes = append(g.Nodes, ui.GraphNode{
					X: left + j*(graphNodeW+graphGapX), Y: y,
					Name: shorten(m.Name, graphNameMax), Address: shorten(m.Address, graphAddrMax), URL: m.URL,
					Root: withRoot && b == 0, Unconnected: withRoot && b < 0, Mine: slices.Contains(mine, m.Address),
				})
			}
			y += graphNodeH + graphGapY
		}
	}
	g.Width = left + widest*(graphNodeW+graphGapX) - graphGapX + graphMargin
	g.Height = y - graphGapY + graphMargin
	g.NodeW, g.NodeH = graphNodeW, graphNodeH

	slices.SortFunc(links, func(a, b [2]string) int {
		return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
	})
	onPath := func(l [2]string) bool {
		for i := 1; i < len(mine); i++ {
			if mine[i-1] == l[0] && mine[i] == l[1] {
				return true
			}
		}
		return false
	}
	// Arrows on the viewer's chain come last, drawn over the others.
	slices.SortStableFunc(links, func(a, b [2]string) int {
		return cmp.Compare(btoi(onPath(a)), btoi(onPath(b)))
	})
	for _, l := range links {
		from, ok1 := at[l[0]]
		to, ok2 := at[l[1]]
		if !ok1 || !ok2 {
			continue
		}
		g.Edges = append(g.Edges, ui.GraphEdge{
			D:     edgePath(g.Nodes[from], g.Nodes[to]),
			Title: l[0] + " certified " + l[1],
			Mine:  onPath(l),
		})
	}
	return g
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// edgePath is the SVG path of an arrow from node a to node b: from a's
// bottom to b's top when b sits one row lower, an arc above the row
// between members of one row, and otherwise along the left of the boxes,
// from a's left side to b's, so that it does not run behind the boxes of
// the rows between.
func edgePath(a, b ui.GraphNode) string {
	ax, bx := a.X+graphNodeW/2, b.X+graphNodeW/2
	switch b.Y - a.Y {
	case graphNodeH + graphGapY:
		y1, y2 := a.Y+graphNodeH, b.Y
		mid := (y1 + y2) / 2
		return fmt.Sprintf("M%d %dC%d %d %d %d %d %d", ax, y1, ax, mid, bx, mid, bx, y2)
	case 0:
		y := a.Y
		lift := min(graphGapY/2+12*abs(b.X-a.X)/(graphNodeW+graphGapX), graphGapY/2+graphMargin-4)
		return fmt.Sprintf("M%d %dC%d %d %d %d %d %d", ax, y, ax, y-lift, bx, y-lift, bx, y)
	default:
		ay, by := a.Y+graphNodeH/2, b.Y+graphNodeH/2
		out := graphMargin * 3 / 4
		return fmt.Sprintf("M%d %dC%d %d %d %d %d %d", a.X, ay, a.X-out, ay, b.X-out, by, b.X, by)
	}
}

// shorten cuts s to n runes, ending with "..." when it was longer.
func shorten(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
