// Package lockfile reads npm ecosystem lockfiles and returns the exact
// package versions they pin.
//
// Mantis never runs a package manager and never fetches anything from a
// registry. Everything here is a pure function of the bytes on disk, which is
// what makes the result reproducible and safe to run on untrusted projects.
package lockfile

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Format identifies a lockfile dialect.
type Format string

const (
	FormatNPM         Format = "npm"          // package-lock.json, npm-shrinkwrap.json
	FormatPNPM        Format = "pnpm"         // pnpm-lock.yaml
	FormatYarnClassic Format = "yarn-classic" // yarn.lock, v1
	FormatYarnBerry   Format = "yarn-berry"   // yarn.lock, v2 and later
	FormatBun         Format = "bun"          // bun.lock (text format)
	// FormatManifest is a package.json with no lockfile, resolved by
	// Mantis from registry metadata (see internal/resolve).
	FormatManifest Format = "package.json"
)

// Source says where a pinned package comes from. Only SourceRegistry packages
// are candidates for a verdict lookup; everything else is local code, a git
// checkout or an arbitrary tarball, and is reported but never sent anywhere.
type Source string

const (
	SourceRegistry Source = "registry" // an npm registry (public or private)
	SourceGit      Source = "git"      // git, github:, codeload tarballs
	SourceTarball  Source = "tarball"  // a remote tarball URL outside a registry
	SourceLocal    Source = "local"    // file:, link:, portal:, workspace members
	// SourceUnresolved is a dependency named in a package.json that Mantis
	// could not or would not resolve to a version (see Package.Note).
	SourceUnresolved Source = "unresolved"
)

// Package is one pinned version.
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Source    Source `json:"source"`
	Resolved  string `json:"resolved,omitempty"`  // URL or spec the lockfile records
	Registry  string `json:"registry,omitempty"`  // registry host, when known
	Integrity string `json:"integrity,omitempty"` // SRI string, when present
	Dev       *bool  `json:"dev,omitempty"`       // nil when the lockfile does not say
	Optional  bool   `json:"optional,omitempty"`
	// Note explains an unresolved package, or records the range a
	// resolved one was chosen from.
	Note string `json:"note,omitempty"`
}

// Key is the identity used for de-duplication: name@version.
func (p Package) Key() string { return p.Name + "@" + p.Version }

// Result is everything read from one lockfile.
type Result struct {
	Path     string    `json:"path"`
	Format   Format    `json:"format"`
	Version  string    `json:"lockfile_version,omitempty"`
	Packages []Package `json:"packages"`
	Warnings []string  `json:"warnings,omitempty"`
	// Graph is the first hop of the tree, when the format records it.
	Graph *Graph `json:"-"`
}

// Graph is the first hop of a dependency tree: the project's direct
// dependencies and what each of them depends on directly. Nodes are
// name@version. It powers the console's graph view; the policy later keeps
// only public packages that are sent anyway.
type Graph struct {
	Direct []GraphNode `json:"direct"`
	Edges  [][2]string `json:"edges"` // [parent, child]
	// Below maps each deeper package to the first hop package it is pulled
	// in through, so the console can say "3 flagged below" on a node.
	Below map[string]string `json:"below,omitempty"`
}

func (g *Graph) addBelow(desc, via string) {
	if desc == "" || via == "" || desc == via {
		return
	}
	if g.Below == nil {
		g.Below = map[string]string{}
	}
	if _, ok := g.Below[desc]; !ok {
		g.Below[desc] = via
	}
}

// fillBelow walks down from every first hop child with next, recording
// each package it reaches that is not itself on the first hop.
func (g *Graph) fillBelow(next func(id string) []string, keyOf func(id string) string, starts map[string]string) {
	onHop := map[string]bool{}
	for _, d := range g.Direct {
		onHop[d.Key] = true
	}
	for _, e := range g.Edges {
		onHop[e[1]] = true
	}
	// One walk from every start at once, level by level, so a package is
	// credited to the first hop package nearest to it.
	ids := make([]string, 0, len(starts))
	for id := range starts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	viaOf := map[string]string{}
	queue := make([]string, 0, len(ids))
	for _, id := range ids {
		viaOf[id] = starts[id]
		queue = append(queue, id)
	}
	for len(queue) > 0 && len(g.Below) < 50000 {
		id := queue[0]
		queue = queue[1:]
		for _, c := range next(id) {
			if _, seen := viaOf[c]; seen {
				continue
			}
			viaOf[c] = viaOf[id]
			if k := keyOf(c); k != "" && !onHop[k] {
				g.addBelow(k, viaOf[id])
			}
			queue = append(queue, c)
		}
	}
}

// GraphNode is one direct dependency.
type GraphNode struct {
	Key string `json:"key"`
	Dev bool   `json:"dev,omitempty"`
}

func (g *Graph) addDirect(key string, dev bool) {
	for i, d := range g.Direct {
		if d.Key == key {
			g.Direct[i].Dev = g.Direct[i].Dev && dev
			return
		}
	}
	g.Direct = append(g.Direct, GraphNode{Key: key, Dev: dev})
}

func (g *Graph) addEdge(parent, child string) {
	if parent == "" || child == "" || parent == child {
		return
	}
	g.Edges = append(g.Edges, [2]string{parent, child})
}

// Merge adds another graph's nodes and edges, without duplicates.
func (g *Graph) Merge(o *Graph) {
	if o == nil {
		return
	}
	for _, d := range o.Direct {
		g.addDirect(d.Key, d.Dev)
	}
	seen := map[[2]string]bool{}
	for _, e := range g.Edges {
		seen[e] = true
	}
	for _, e := range o.Edges {
		if !seen[e] {
			seen[e] = true
			g.Edges = append(g.Edges, e)
		}
	}
	for d, v := range o.Below {
		g.addBelow(d, v)
	}
}

// Keep drops every node for which ok is false, and the edges touching it.
func (g *Graph) Keep(ok func(key string) bool) {
	direct := g.Direct[:0]
	for _, d := range g.Direct {
		if ok(d.Key) {
			direct = append(direct, d)
		}
	}
	g.Direct = direct
	edges := g.Edges[:0]
	for _, e := range g.Edges {
		if ok(e[0]) && ok(e[1]) {
			edges = append(edges, e)
		}
	}
	g.Edges = edges
	for d, v := range g.Below {
		if !ok(d) || !ok(v) {
			delete(g.Below, d)
		}
	}
}

// Names lists the file names Mantis recognises, in the order they are tried
// within one directory.
var Names = []string{
	"npm-shrinkwrap.json",
	"package-lock.json",
	"pnpm-lock.yaml",
	"yarn.lock",
	"bun.lock",
}

// MaxSize caps how much of a lockfile is read. The largest real lockfiles are
// a few tens of megabytes; anything past this is refused rather than parsed.
const MaxSize = 256 << 20

// IsLockfile reports whether a base name is a recognised lockfile.
func IsLockfile(base string) bool {
	for _, n := range Names {
		if base == n {
			return true
		}
	}
	return false
}

// ParseFile reads and parses one lockfile, picking the parser by file name.
func ParseFile(path string) (*Result, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if info.Size() > MaxSize {
		return nil, fmt.Errorf("%s: %d bytes is larger than the %d byte limit", path, info.Size(), MaxSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	res, err := Parse(filepath.Base(path), data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	res.Path = path
	return res, nil
}

// Parse parses lockfile bytes. name is the base file name, used to pick the
// dialect.
func Parse(name string, data []byte) (*Result, error) {
	var (
		res *Result
		err error
	)
	switch name {
	case "package-lock.json", "npm-shrinkwrap.json":
		res, err = parseNPM(data)
	case "pnpm-lock.yaml":
		res, err = parsePNPM(data)
	case "yarn.lock":
		res, err = parseYarn(data)
	case "bun.lock":
		res, err = parseBun(data)
	default:
		return nil, fmt.Errorf("unrecognised lockfile name %q", name)
	}
	if err != nil {
		return nil, err
	}
	res.Packages = Dedupe(res.Packages)
	return res, nil
}

// Dedupe merges packages with the same name@version. A package marked
// production anywhere stays production; a registry source wins over others.
func Dedupe(in []Package) []Package {
	idx := make(map[string]int, len(in))
	out := make([]Package, 0, len(in))
	for _, p := range in {
		k := p.Key() + "|" + string(p.Source)
		if i, ok := idx[k]; ok {
			cur := &out[i]
			if cur.Dev != nil && p.Dev != nil && !*p.Dev {
				f := false
				cur.Dev = &f
			} else if cur.Dev != nil && p.Dev == nil {
				cur.Dev = nil
			}
			cur.Optional = cur.Optional && p.Optional
			if cur.Integrity == "" {
				cur.Integrity = p.Integrity
			}
			if cur.Resolved == "" {
				cur.Resolved = p.Resolved
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].Source < out[j].Source
	})
	return out
}

// splitIdent splits "name@rest" where name may be scoped ("@scope/name").
func splitIdent(s string) (name, rest string, ok bool) {
	start := 0
	if strings.HasPrefix(s, "@") {
		start = 1
	}
	i := strings.Index(s[start:], "@")
	if i < 0 {
		return s, "", false
	}
	i += start
	return s[:i], s[i+1:], true
}

// classifyURL decides the source of a "resolved" value that is a URL or a
// protocol prefixed spec.
func classifyURL(resolved string) (Source, string) {
	r := strings.TrimSpace(resolved)
	low := strings.ToLower(r)
	switch {
	case r == "":
		return SourceRegistry, ""
	case strings.HasPrefix(low, "file:"), strings.HasPrefix(low, "link:"),
		strings.HasPrefix(low, "portal:"), strings.HasPrefix(low, "workspace:"),
		strings.HasPrefix(low, "./"), strings.HasPrefix(low, "../"), strings.HasPrefix(low, "/"):
		return SourceLocal, ""
	case strings.HasPrefix(low, "git+"), strings.HasPrefix(low, "git:"), strings.HasPrefix(low, "git@"),
		strings.HasPrefix(low, "github:"), strings.HasPrefix(low, "gitlab:"), strings.HasPrefix(low, "bitbucket:"),
		strings.HasPrefix(low, "ssh:"):
		return SourceGit, ""
	case strings.HasPrefix(low, "http://"), strings.HasPrefix(low, "https://"):
		u, err := url.Parse(r)
		if err != nil {
			return SourceTarball, ""
		}
		host := strings.ToLower(u.Hostname())
		switch {
		case host == "codeload.github.com", host == "github.com", host == "gitlab.com", host == "bitbucket.org":
			return SourceGit, host
		case strings.Contains(u.Path, "/-/") && strings.HasSuffix(u.Path, ".tgz"):
			// The registry tarball layout: /<name>/-/<name>-<version>.tgz
			return SourceRegistry, host
		default:
			return SourceTarball, host
		}
	default:
		// A relative path written without ./ (npm does this for workspaces).
		if !strings.Contains(r, "://") && !strings.Contains(r, ":") {
			return SourceLocal, ""
		}
		return SourceTarball, ""
	}
}

func boolPtr(b bool) *bool { return &b }
