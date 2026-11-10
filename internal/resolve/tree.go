package resolve

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/Anurag-Chevendra/mantis/internal/semver"
)

// This file simulates npm's ideal tree builder (Arborist buildIdealTree,
// place-dep and can-place-dep), which is what decides how many copies of a
// package end up installed and at which versions:
//
//   * nodes are processed in order of (depth, location), npm's DepsQueue;
//   * a node's unmet edges are resolved in name order;
//   * a new version is picked with npm-pick-manifest's rules;
//   * it is placed at the shallowest ancestor where it does not conflict,
//     walking up from the dependent and stopping at the first conflict;
//   * an existing node is replaced only by an equal or newer version that
//     satisfies everything already depending on it (can-place-dep);
//   * nested copies made unnecessary by a placement are pruned.
//
// Peer dependencies are placed starting from the dependent's parent, so they
// land beside the dependent, which is where npm puts them.

type tnode struct {
	name     string
	version  string
	parent   *tnode
	children map[string]*tnode
	depth    int
	location string
	edges    []tedge
	removed  bool
	dev      bool
	optional bool
	isRoot   bool
	local    bool // workspace member
}

type tedge struct {
	name      string
	spec      string
	peer      bool
	optional  bool // optional dependency or optional peer
	peerOpt   bool // optional peer: missing is fine
	dev       bool
	devOrigin bool
}

type tree struct {
	r        *Resolver
	ctx      context.Context
	root     *tnode
	all      []*tnode
	seen     map[*tnode]bool
	queue    []*tnode
	unmet    map[string]string // name -> reason, for edges that could not be met
	pref     sync.WaitGroup
	override map[string]string
	byDep    map[string][]*tnode // dependency name -> nodes with an edge to it
}

func (t *tree) add(n *tnode) {
	t.all = append(t.all, n)
	for _, e := range n.edges {
		t.byDep[e.name] = append(t.byDep[e.name], n)
	}
}

func newNode(name, version string, parent *tnode) *tnode {
	n := &tnode{name: name, version: version, parent: parent, children: map[string]*tnode{}}
	if parent != nil {
		n.depth = parent.depth + 1
		if parent.location == "" {
			n.location = "node_modules/" + name
		} else {
			n.location = parent.location + "/node_modules/" + name
		}
	}
	return n
}

// resolve finds the node an edge from n named name resolves to, following
// Node's module resolution: n's own node_modules, then each parent's.
func resolveFrom(n *tnode, name string) *tnode {
	for p := n; p != nil; p = p.parent {
		if c, ok := p.children[name]; ok && !c.removed {
			return c
		}
	}
	return nil
}

func satisfies(version, spec string) bool {
	if spec == "" || spec == "*" || spec == "latest" {
		return true
	}
	rng, err := semver.ParseRange(spec)
	if err != nil {
		return false
	}
	v, err := semver.Parse(version)
	if err != nil {
		return false
	}
	return rng.Satisfies(v)
}

// edgesIn lists every edge in the tree that currently resolves to target.
func (t *tree) edgesIn(target *tnode) []struct {
	from *tnode
	e    tedge
} {
	var out []struct {
		from *tnode
		e    tedge
	}
	for _, n := range t.byDep[target.name] {
		if n.removed {
			continue
		}
		for _, e := range n.edges {
			if e.name == target.name && resolveFrom(n, e.name) == target {
				out = append(out, struct {
					from *tnode
					e    tedge
				}{n, e})
			}
		}
	}
	return out
}

func isDescendantOf(n, anc *tnode) bool {
	for p := n; p != nil; p = p.parent {
		if p == anc {
			return true
		}
	}
	return false
}

func (t *tree) push(n *tnode) {
	t.queue = append(t.queue, n)
}

func (t *tree) pop() *tnode {
	sort.SliceStable(t.queue, func(i, j int) bool {
		a, b := t.queue[i], t.queue[j]
		if a.depth != b.depth {
			return a.depth < b.depth
		}
		return localeLess(a.location, b.location)
	})
	n := t.queue[0]
	t.queue = t.queue[1:]
	return n
}

// localeLess approximates ICU's "en" collation used by npm for paths:
// punctuation sorts before digits, digits before letters, letters compare
// case insensitively first.
func localeLess(a, b string) bool {
	ka, kb := collKey(a), collKey(b)
	for i := 0; i < len(ka) && i < len(kb); i++ {
		if ka[i] != kb[i] {
			return ka[i] < kb[i]
		}
	}
	if len(ka) != len(kb) {
		return len(ka) < len(kb)
	}
	return a < b
}

func collKey(s string) []int {
	out := make([]int, 0, len(s))
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			out = append(out, 3000+int(c-'a')*2)
		case c >= 'A' && c <= 'Z':
			out = append(out, 3000+int(c-'A')*2+1)
		case c >= '0' && c <= '9':
			out = append(out, 2000+int(c-'0'))
		default:
			out = append(out, 1000+punctRank(c))
		}
	}
	return out
}

func punctRank(c rune) int {
	const order = "_-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$"
	if i := strings.IndexRune(order, c); i >= 0 {
		return i
	}
	return 500 + int(c)
}

// build runs the queue to completion.
func (t *tree) build() {
	t.push(t.root)
	for len(t.queue) > 0 {
		if t.ctx.Err() != nil {
			return
		}
		// Past the cap there is no point fetching more: the caller refuses
		// the tree anyway, so stop the registry traffic now.
		if t.r.opt.MaxPackages > 0 && len(t.all) > t.r.opt.MaxPackages {
			return
		}
		n := t.pop()
		if n.removed || t.seen[n] {
			continue
		}
		t.seen[n] = true
		t.step(n)
	}
}

type task struct {
	e   tedge
	ver string
	doc *packument
}

func (t *tree) step(n *tnode) {
	var tasks []task
	for _, e := range n.edges {
		to := resolveFrom(n, e.name)
		if to != nil && satisfies(to.version, e.spec) {
			continue
		}
		if to == nil && e.peerOpt {
			continue // optional peer not in the tree: fine
		}
		if why := t.r.hold(e.name); why != "" {
			t.unmet[e.name] = why
			continue
		}
		doc, err := t.r.getOrFetch(t.ctx, e.name)
		if err != nil {
			t.unmet[e.name] = err.Error()
			continue
		}
		kind := kindRegistry
		if _, err := semver.ParseRange(e.spec); err != nil {
			kind = kindTag
		}
		ver, ok := pick(doc, e.spec, kind, nil)
		if !ok {
			t.unmet[e.name] = "no published version matches " + quote(e.spec)
			continue
		}
		tasks = append(tasks, task{e: e, ver: ver, doc: doc})
	}
	sort.SliceStable(tasks, func(i, j int) bool { return localeLess(tasks[i].e.name, tasks[j].e.name) })
	for _, tk := range tasks {
		// Earlier placements in this step can satisfy a later edge.
		if to := resolveFrom(n, tk.e.name); to != nil && satisfies(to.version, tk.e.spec) {
			continue
		}
		t.place(n, tk)
	}
}

type placement int

const (
	conflict placement = iota
	ok
	keep
	replace
)

func (t *tree) place(from *tnode, tk task) {
	start := from
	if tk.e.peer && from.parent != nil {
		start = from.parent
	}
	var target *tnode
	var how placement
	for tg := start; tg != nil; tg = tg.parent {
		if !tg.isRoot && hasPeerEdge(tg, tk.e.name) {
			continue
		}
		c := t.canPlace(tg, from, tk)
		if c == conflict {
			break
		}
		target, how = tg, c
	}
	if target == nil {
		// npm would raise ERESOLVE for its own deps; with conflicts allowed
		// it nests directly under the dependent.
		target, how = from, replace
		if !tk.e.peer {
			if cur := from.children[tk.e.name]; cur == nil {
				how = ok
			}
		} else if from.parent != nil {
			target = from.parent
		}
	}
	if how == keep {
		return
	}
	// A cycle back to an identical ancestor becomes a link, not a new node.
	for p := target; p != nil; p = p.parent {
		if p.name == tk.e.name && p.version == tk.ver && !p.isRoot {
			return
		}
	}
	node := newNode(tk.e.name, tk.ver, target)
	node.dev = tk.e.dev
	node.optional = tk.e.optional
	node.edges = t.edgesFor(tk.doc.Versions[tk.ver], tk.e.dev)
	if old := target.children[tk.e.name]; old != nil {
		// Replace keeps the old node's children in place.
		for k, c := range old.children {
			c.parent = node
			node.children[k] = c
		}
		old.removed = true
		t.removeSubtreeIfOrphan(old)
	}
	target.children[tk.e.name] = node
	t.add(node)
	t.prefetch(node)
	t.push(node)

	// Dependents that now resolve to the new node but are not satisfied by
	// it, or were satisfied by the node it replaced, must be revisited.
	for _, in := range t.edgesIn(node) {
		if !satisfies(node.version, in.e.spec) {
			delete(t.seen, in.from)
			t.push(in.from)
		}
	}
	// Prune nested copies under target that this node makes redundant.
	for _, other := range t.byName(node.name) {
		if other == node || other.removed || !isDescendantOf(other, target) {
			continue
		}
		t.pruneDedupable(other)
	}
}

func hasPeerEdge(n *tnode, name string) bool {
	for _, e := range n.edges {
		if e.name == name && e.peer {
			return true
		}
	}
	return false
}

// canPlace mirrors can-place-dep.js for a dep without peer sets.
func (t *tree) canPlace(target, from *tnode, tk task) placement {
	cur := target.children[tk.e.name]
	if cur != nil && cur.removed {
		cur = nil
	}
	if cur != nil {
		if cur.version == tk.ver && satisfies(cur.version, tk.e.spec) {
			return keep
		}
		tryReplace := semverGTE(tk.ver, cur.version)
		if tryReplace && t.canReplace(cur, tk.ver) {
			return replace
		}
		if satisfies(cur.version, tk.e.spec) {
			return keep
		}
		// The deepest a non peer can go is under its dependent.
		deepest := from
		if tk.e.peer && from.parent != nil {
			deepest = from.parent
		}
		if target != deepest {
			return conflict
		}
		return replace
	}
	// Placing here must not shadow a node that descendants rely on.
	if vis := resolveFrom(target, tk.e.name); vis != nil {
		for _, in := range t.edgesIn(vis) {
			if isDescendantOf(in.from, target) && satisfies(vis.version, in.e.spec) && !satisfies(tk.ver, in.e.spec) {
				return conflict
			}
		}
	}
	return ok
}

func (t *tree) canReplace(cur *tnode, ver string) bool {
	for _, in := range t.edgesIn(cur) {
		if !satisfies(ver, in.e.spec) {
			return false
		}
	}
	return true
}

// pruneDedupable removes n when the node its dependents would see without
// it satisfies all of them.
func (t *tree) pruneDedupable(n *tnode) {
	if n.parent == nil || n.parent.parent == nil && n.parent.isRoot && n.depth == 1 {
		return // top level nodes are never pruned this way
	}
	other := resolveFrom(n.parent.parent, n.name)
	if other == nil || other == n {
		return
	}
	for _, in := range t.edgesIn(n) {
		if !satisfies(other.version, in.e.spec) {
			return
		}
	}
	if len(n.children) > 0 {
		return // keep it simple: nodes with nested children stay
	}
	n.removed = true
	delete(n.parent.children, n.name)
}

func (t *tree) removeSubtreeIfOrphan(n *tnode) {
	// The old node's children were moved to the replacement; nothing to do.
}

func semverGTE(a, b string) bool {
	va, err1 := semver.Parse(a)
	vb, err2 := semver.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return semver.Compare(va, vb) >= 0
}

func quote(s string) string { return "\"" + s + "\"" }

// edgesFor builds a placed package's outgoing edges.
func (t *tree) edgesFor(pv packumentVersion, dev bool) []tedge {
	var out []tedge
	for _, n := range sortedKeys(pv.Dependencies) {
		out = append(out, t.regEdge(n, pv.Dependencies[n], tedge{dev: dev}))
	}
	for _, n := range sortedKeys(pv.OptionalDependencies) {
		out = append(out, t.regEdge(n, pv.OptionalDependencies[n], tedge{dev: dev, optional: true}))
	}
	for _, n := range sortedKeys(pv.PeerDependencies) {
		if _, dup := pv.Dependencies[n]; dup {
			continue
		}
		opt := pv.PeerDependenciesMeta[n].Optional
		out = append(out, t.regEdge(n, pv.PeerDependencies[n], tedge{dev: dev, peer: true, peerOpt: opt, optional: opt}))
	}
	// Drop edges that are not registry lookups (git, file, tarball): they are
	// reported separately and never placed.
	keep := out[:0]
	for _, e := range out {
		if e.name != "" {
			keep = append(keep, e)
		}
	}
	return keep
}

// regEdge normalises a dependency into a registry edge, following aliases
// and overrides. Non registry specs return an empty edge.
func (t *tree) regEdge(name, spec string, base tedge) tedge {
	if v, ok := t.override[name]; ok && v != "" && !strings.HasPrefix(v, "$") {
		spec = v
	}
	kind, s := classify(name, spec)
	if kind == kindAlias {
		name, s = splitAlias(s)
		kind, s = classify(name, s)
	}
	if kind != kindRegistry && kind != kindTag {
		return tedge{}
	}
	base.name, base.spec = name, s
	return base
}

func (t *tree) prefetch(n *tnode) {
	for _, e := range n.edges {
		name := e.name
		if t.r.hold(name) != "" || t.r.cached(name) {
			continue
		}
		t.pref.Add(1)
		go func() {
			defer t.pref.Done()
			_, _ = t.r.getOrFetch(t.ctx, name)
		}()
	}
}

func (t *tree) byName(name string) []*tnode {
	var out []*tnode
	for _, n := range t.all {
		if n.name == name {
			out = append(out, n)
		}
	}
	return out
}
