// Package resolve works out which exact versions `npm install` would pick
// for a package.json that has no lockfile, without installing anything.
//
// It reads only registry metadata (the abbreviated "corgi" documents npm
// itself downloads first). No tarball is downloaded, no install script can
// run, and nothing is written to disk. That is what makes it usable as a
// gate before the first install, which is the moment that matters.
//
// The result is a prediction of what npm would install today: versions are
// chosen with npm's own rules (dist-tag latest when it satisfies the range,
// otherwise the highest satisfying non deprecated version; existing picks
// reused when they satisfy a later range; peer dependencies included). It is
// not a lockfile, and a later install can differ when new versions publish.
package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Anurag-Chevendra/mantis/internal/lockfile"
	"github.com/Anurag-Chevendra/mantis/internal/semver"
)

// DefaultRegistry is public npm.
const DefaultRegistry = "https://registry.npmjs.org"

// Options configure a Resolver.
type Options struct {
	Registry    string
	HTTP        *http.Client
	UserAgent   string
	Prod        bool // leave out the root's devDependencies
	Concurrency int
	MaxPackages int
	// Hold returns a non empty reason when a name must not be looked up on
	// the registry (a private scope, an excluded name). Looking a name up
	// tells the registry it exists in your project, so private names are
	// never fetched.
	Hold func(name string) string
}

// ErrTooMany is returned when a tree grows past Options.MaxPackages.
var ErrTooMany = errors.New("stopped")

// Resolver resolves manifests. It caches registry documents across calls,
// so a monorepo's packages share lookups.
type Resolver struct {
	opt     Options
	base    *url.URL
	mu      sync.Mutex
	entries map[string]*entry
	sem     chan struct{}
}

// New builds a resolver.
func New(opt Options) (*Resolver, error) {
	if opt.Registry == "" {
		opt.Registry = DefaultRegistry
	}
	u, err := url.Parse(strings.TrimRight(opt.Registry, "/"))
	if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
		return nil, fmt.Errorf("registry %q must be an https URL", opt.Registry)
	}
	if opt.HTTP == nil {
		opt.HTTP = http.DefaultClient
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 16
	}
	if opt.MaxPackages <= 0 {
		opt.MaxPackages = 20000
	}
	return &Resolver{opt: opt, base: u, entries: map[string]*entry{}, sem: make(chan struct{}, opt.Concurrency)}, nil
}

// Host is the registry host, for reports.
func (r *Resolver) Host() string { return r.base.Hostname() }

type manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Overrides            map[string]any    `json:"overrides"`
	Workspaces           json.RawMessage   `json:"workspaces"`
}

type packument struct {
	Name     string                      `json:"name"`
	DistTags map[string]string           `json:"dist-tags"`
	Versions map[string]packumentVersion `json:"versions"`
	parsed   []semver.Version
	keys     []string
}

type packumentVersion struct {
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	PeerDependenciesMeta map[string]struct {
		Optional bool `json:"optional"`
	} `json:"peerDependenciesMeta"`
	Deprecated json.RawMessage `json:"deprecated"`
	Dist       struct {
		Integrity string `json:"integrity"`
		Tarball   string `json:"tarball"`
	} `json:"dist"`
}

func (v packumentVersion) deprecated() bool {
	d := strings.TrimSpace(string(v.Deprecated))
	return d != "" && d != "false" && d != `""` && d != "null"
}

// ResolveManifest resolves dir/package.json and any npm workspaces it
// declares by simulating npm's ideal tree (see tree.go). ctx bounds the
// whole resolution.
func (r *Resolver) ResolveManifest(ctx context.Context, path string) (*lockfile.Result, error) {
	rootM, err := readManifest(path)
	if err != nil {
		return nil, err
	}
	res := &lockfile.Result{Path: path, Format: lockfile.FormatManifest, Version: "resolved from " + r.Host()}
	dir := filepath.Dir(path)

	t := &tree{r: r, ctx: ctx, seen: map[*tnode]bool{}, unmet: map[string]string{},
		override: map[string]string{}, byDep: map[string][]*tnode{}}
	for k, v := range rootM.Overrides {
		if s, ok := v.(string); ok {
			t.override[k] = s
		} else {
			res.Warnings = append(res.Warnings, "nested override for "+k+" is not applied")
		}
	}

	// Non registry dependencies are reported, never placed.
	nonReg := func(m map[string]string) {
		for _, n := range sortedKeys(m) {
			spec := m[n]
			if v, ok := t.override[n]; ok && v != "" {
				spec = v
			}
			kind, s := classify(n, spec)
			switch kind {
			case kindLocal:
				res.Packages = append(res.Packages, lockfile.Package{Name: n, Version: s, Source: lockfile.SourceLocal, Resolved: s})
			case kindGit:
				res.Packages = append(res.Packages, lockfile.Package{Name: n, Version: s, Source: lockfile.SourceGit, Resolved: s})
			case kindTarball:
				res.Packages = append(res.Packages, lockfile.Package{Name: n, Version: s, Source: lockfile.SourceTarball, Resolved: s})
			}
		}
	}
	manifestEdges := func(m *manifest, withDev bool) []tedge {
		var out []tedge
		for _, n := range sortedKeys(m.Dependencies) {
			out = append(out, t.regEdge(n, m.Dependencies[n], tedge{}))
		}
		for _, n := range sortedKeys(m.OptionalDependencies) {
			out = append(out, t.regEdge(n, m.OptionalDependencies[n], tedge{optional: true}))
		}
		if withDev {
			for _, n := range sortedKeys(m.DevDependencies) {
				out = append(out, t.regEdge(n, m.DevDependencies[n], tedge{dev: true, devOrigin: true}))
			}
		}
		nonReg(m.Dependencies)
		nonReg(m.OptionalDependencies)
		if withDev {
			nonReg(m.DevDependencies)
		}
		keep := out[:0]
		for _, e := range out {
			if e.name != "" {
				keep = append(keep, e)
			}
		}
		return keep
	}

	root := &tnode{name: rootM.Name, children: map[string]*tnode{}, isRoot: true}
	root.edges = manifestEdges(rootM, !r.opt.Prod)
	t.root = root

	// npm workspaces: each member is linked at the top level and its
	// dependencies are installed into the root.
	members, werr := workspaceMembers(dir, rootM.Workspaces)
	if werr != nil {
		res.Warnings = append(res.Warnings, werr.Error())
	}
	for _, mp := range members {
		m, err := readManifest(mp)
		if err != nil {
			res.Warnings = append(res.Warnings, err.Error())
			continue
		}
		if m.Name == "" {
			continue
		}
		res.Packages = append(res.Packages, lockfile.Package{Name: m.Name, Version: firstNonEmpty(m.Version, "0.0.0"),
			Source: lockfile.SourceLocal, Resolved: relSlash(dir, filepath.Dir(mp))})
		node := newNode(m.Name, firstNonEmpty(m.Version, "0.0.0"), root)
		node.local = true
		node.edges = manifestEdges(m, !r.opt.Prod)
		root.children[m.Name] = node
		t.add(node)
		t.push(node)
	}
	t.add(root)
	t.prefetch(root)
	for _, c := range root.children {
		t.prefetch(c)
	}

	t.build()
	t.pref.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if count := len(t.all); count > r.opt.MaxPackages {
		return nil, fmt.Errorf("%w: the tree has %d packages, more than --max-packages", ErrTooMany, count)
	}

	// The first hop, for the console's graph: the project's (and each
	// workspace member's) dependencies and what each resolves to directly.
	g := &lockfile.Graph{}
	hop1 := map[*tnode]string{}
	direct := []*tnode{root}
	for _, c := range root.children {
		if c.local {
			direct = append(direct, c)
		}
	}
	for _, owner := range direct {
		for _, e := range owner.edges {
			n := resolveFrom(owner, e.name)
			if n == nil || n.local || n.removed {
				continue
			}
			pk := n.name + "@" + n.version
			g.Direct = append(g.Direct, lockfile.GraphNode{Key: pk, Dev: e.devOrigin})
			for _, ce := range n.edges {
				if c := resolveFrom(n, ce.name); c != nil && !c.local && !c.removed {
					g.Edges = append(g.Edges, [2]string{pk, c.name + "@" + c.version})
					hop1[c] = c.name + "@" + c.version
				}
			}
		}
	}
	onHop := map[string]bool{}
	for _, d := range g.Direct {
		onHop[d.Key] = true
	}
	for _, e := range g.Edges {
		onHop[e[1]] = true
	}
	starts := make([]*tnode, 0, len(hop1))
	for n := range hop1 {
		starts = append(starts, n)
	}
	sort.Slice(starts, func(i, j int) bool { return hop1[starts[i]] < hop1[starts[j]] })
	viaOf := map[*tnode]string{}
	queue := append([]*tnode{}, starts...)
	for _, n := range starts {
		viaOf[n] = hop1[n]
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, ce := range n.edges {
			c := resolveFrom(n, ce.name)
			if c == nil || c.local || c.removed {
				continue
			}
			if _, seen := viaOf[c]; seen {
				continue
			}
			viaOf[c] = viaOf[n]
			if k := c.name + "@" + c.version; !onHop[k] {
				if g.Below == nil {
					g.Below = map[string]string{}
				}
				if _, ok := g.Below[k]; !ok {
					g.Below[k] = viaOf[n]
				}
			}
			queue = append(queue, c)
		}
	}
	dedup := &lockfile.Graph{}
	dedup.Merge(g)
	res.Graph = dedup

	// dev means reachable only through the root's devDependencies.
	prod := map[*tnode]bool{}
	var walk func(n *tnode)
	walk = func(n *tnode) {
		for _, e := range n.edges {
			if e.devOrigin {
				continue
			}
			to := resolveFrom(n, e.name)
			if to != nil && !to.local && !prod[to] {
				prod[to] = true
				walk(to)
			}
		}
	}
	walk(root)
	for _, c := range root.children {
		if c.local {
			walk(c)
		}
	}

	for _, n := range t.all {
		if n.removed || n.isRoot || n.local {
			continue
		}
		doc, _ := r.getOrFetch(ctx, n.name)
		var pv packumentVersion
		if doc != nil {
			pv = doc.Versions[n.version]
		}
		dev := !prod[n]
		res.Packages = append(res.Packages, lockfile.Package{
			Name: n.name, Version: n.version, Source: lockfile.SourceRegistry,
			Registry: r.Host(), Integrity: pv.Dist.Integrity, Resolved: pv.Dist.Tarball,
			Dev: &dev, Optional: n.optional,
		})
		nonRegFromVersion(pv, res)
	}
	for _, name := range sortedKeys(t.unmet) {
		res.Packages = append(res.Packages, lockfile.Package{Name: name, Version: "*", Source: lockfile.SourceUnresolved, Note: t.unmet[name]})
	}
	res.Packages = lockfile.Dedupe(res.Packages)
	return res, nil
}

// nonRegFromVersion reports git and tarball dependencies of a published
// package.
func nonRegFromVersion(pv packumentVersion, res *lockfile.Result) {
	for _, m := range []map[string]string{pv.Dependencies, pv.OptionalDependencies} {
		for _, n := range sortedKeys(m) {
			switch kind, s := classify(n, m[n]); kind {
			case kindGit:
				res.Packages = append(res.Packages, lockfile.Package{Name: n, Version: s, Source: lockfile.SourceGit, Resolved: s})
			case kindTarball:
				res.Packages = append(res.Packages, lockfile.Package{Name: n, Version: s, Source: lockfile.SourceTarball, Resolved: s})
			}
		}
	}
}

func (r *Resolver) hold(name string) string {
	if r.opt.Hold == nil {
		return ""
	}
	return r.opt.Hold(name)
}

// pick applies npm's choice rules.
func pick(doc *packument, spec string, kind specKind, already []string) (string, bool) {
	if kind == kindTag {
		v, ok := doc.DistTags[spec]
		if !ok {
			return "", false
		}
		_, exists := doc.Versions[v]
		return v, exists
	}
	rng, err := semver.ParseRange(spec)
	if err != nil {
		return "", false
	}
	// Reuse a version already in the tree when it satisfies this range;
	// npm keeps an existing node rather than adding a second copy.
	best := ""
	var bestV semver.Version
	for _, s := range already {
		v, err := semver.Parse(s)
		if err == nil && rng.Satisfies(v) && (best == "" || semver.Compare(v, bestV) > 0) {
			best, bestV = s, v
		}
	}
	if best != "" {
		return best, true
	}
	if latest, ok := doc.DistTags["latest"]; ok {
		if v, err := semver.Parse(latest); err == nil && rng.Satisfies(v) {
			if _, exists := doc.Versions[latest]; exists {
				return latest, true
			}
		}
	}
	// Highest satisfying, preferring versions that are not deprecated.
	bestDep := ""
	var bestDepV semver.Version
	for i, v := range doc.parsed {
		if !rng.Satisfies(v) {
			continue
		}
		key := doc.keys[i]
		if doc.Versions[key].deprecated() {
			if bestDep == "" || semver.Compare(v, bestDepV) > 0 {
				bestDep, bestDepV = key, v
			}
			continue
		}
		if best == "" || semver.Compare(v, bestV) > 0 {
			best, bestV = key, v
		}
	}
	if best != "" {
		return best, true
	}
	return bestDep, bestDep != ""
}

// ---- registry -----------------------------------------------------------------

type entry struct {
	once sync.Once
	doc  *packument
	err  error
}

// getOrFetch returns the registry document for name, fetching it at most
// once even when many goroutines ask at the same time.
func (r *Resolver) getOrFetch(ctx context.Context, name string) (*packument, error) {
	r.mu.Lock()
	e, ok := r.entries[name]
	if !ok {
		e = &entry{}
		r.entries[name] = e
	}
	r.mu.Unlock()
	e.once.Do(func() {
		r.sem <- struct{}{}
		defer func() { <-r.sem }()
		e.doc, e.err = r.fetch(ctx, name)
	})
	return e.doc, e.err
}

func (r *Resolver) cached(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.entries[name]
	return ok
}

// ErrNotFound marks a name the registry does not have.
var ErrNotFound = errors.New("not found on the registry")

func (r *Resolver) fetch(ctx context.Context, name string) (*packument, error) {
	u := *r.base
	// Scoped names keep the @ and encode the slash, as npm does.
	// RawPath must be a valid encoding of Path, so Path holds the real slash
	// and RawPath the %2f form the registry expects.
	u.Path = strings.TrimRight(r.base.Path, "/") + "/" + name
	u.RawPath = strings.TrimRight(r.base.EscapedPath(), "/") + "/" + strings.Replace(url.PathEscape(name), "%2F", "%2f", 1)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8")
		req.Header.Set("User-Agent", r.opt.UserAgent)
		resp, err := r.opt.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return nil, ErrNotFound
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("registry answered HTTP %d", resp.StatusCode)
			continue
		case resp.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("registry answered HTTP %d", resp.StatusCode)
		}
		var doc packument
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("unreadable registry document: %w", err)
		}
		for k := range doc.Versions {
			if v, err := semver.Parse(k); err == nil {
				doc.parsed = append(doc.parsed, v)
				doc.keys = append(doc.keys, k)
			}
		}
		return &doc, nil
	}
	return nil, fmt.Errorf("registry unreachable: %v", lastErr)
}

// ---- specs ---------------------------------------------------------------------

type specKind int

const (
	kindRegistry specKind = iota
	kindTag
	kindAlias
	kindLocal
	kindGit
	kindTarball
)

func classify(name, spec string) (specKind, string) {
	s := strings.TrimSpace(spec)
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, "npm:"):
		return kindAlias, s
	case strings.HasPrefix(low, "file:"), strings.HasPrefix(low, "link:"), strings.HasPrefix(low, "workspace:"),
		strings.HasPrefix(low, "portal:"), strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"),
		strings.HasPrefix(s, "/"), strings.HasPrefix(s, "~/"):
		return kindLocal, s
	case strings.HasPrefix(low, "git+"), strings.HasPrefix(low, "git:"), strings.HasPrefix(low, "git@"),
		strings.HasPrefix(low, "github:"), strings.HasPrefix(low, "gitlab:"), strings.HasPrefix(low, "bitbucket:"),
		strings.HasPrefix(low, "gist:"):
		return kindGit, s
	case strings.HasPrefix(low, "http://"), strings.HasPrefix(low, "https://"):
		if strings.Contains(low, "github.com/") && !strings.HasSuffix(low, ".tgz") {
			return kindGit, s
		}
		return kindTarball, s
	}
	if _, err := semver.ParseRange(s); err == nil {
		return kindRegistry, s
	}
	// "user/repo" or "user/repo#ref" is GitHub shorthand.
	if strings.Count(s, "/") == 1 && !strings.HasPrefix(s, "@") && !strings.ContainsAny(s, " :") {
		return kindGit, s
	}
	if isTag(s) {
		return kindTag, s
	}
	return kindGit, s // unknown forms are never looked up
}

func isTag(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// splitAlias turns "npm:real@range" into ("real", "range").
func splitAlias(spec string) (string, string) {
	s := strings.TrimSpace(spec)[4:]
	start := 0
	if strings.HasPrefix(s, "@") {
		start = 1
	}
	if i := strings.Index(s[start:], "@"); i >= 0 {
		return s[:start+i], s[start+i+1:]
	}
	return s, "latest"
}

// ---- manifests -----------------------------------------------------------------

func readManifest(path string) (*manifest, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > 8<<20 {
		return nil, fmt.Errorf("%s is larger than 8 MB", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: not valid JSON: %w", path, err)
	}
	return &m, nil
}

func workspaceMembers(dir string, raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var patterns []string
	if err := json.Unmarshal(raw, &patterns); err != nil {
		var obj struct {
			Packages []string `json:"packages"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, errors.New("unreadable workspaces field")
		}
		patterns = obj.Packages
	}
	var out []string
	seen := map[string]bool{}
	for _, p := range patterns {
		if strings.Contains(p, "..") || filepath.IsAbs(p) {
			continue // never resolve outside the project
		}
		matches, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(p, "/")), "package.json"))
		if err != nil {
			continue
		}
		for _, m := range matches {
			if strings.Contains(filepath.ToSlash(m), "/node_modules/") || seen[m] {
				continue
			}
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func relSlash(base, p string) string {
	r, err := filepath.Rel(base, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(r)
}

func isLoopback(h string) bool { return h == "localhost" || h == "127.0.0.1" || h == "::1" }
