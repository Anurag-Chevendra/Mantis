// Package report turns lockfile results into the inventory Mantis prints:
// human text, a stable JSON document, or a CycloneDX SBOM.
package report

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Anurag-Chevendra/mantis/internal/api"
	"github.com/Anurag-Chevendra/mantis/internal/lockfile"
	"github.com/Anurag-Chevendra/mantis/internal/policy"
)

// SchemaVersion of the JSON document. Bumped only on breaking changes.
const SchemaVersion = 1

// Lockfile summarises one parsed lockfile.
type Lockfile struct {
	Path     string   `json:"path"` // relative to the scan base
	Format   string   `json:"format"`
	Version  string   `json:"lockfile_version,omitempty"`
	Packages int      `json:"packages"`
	Warnings []string `json:"warnings,omitempty"`
}

// Root is one directory with lockfiles.
type Root struct {
	Dir       string     `json:"dir"`
	Manifests int        `json:"manifests"`
	Lockfiles []Lockfile `json:"lockfiles"`
}

// Package is one unique name@version across the whole scan.
type Package struct {
	policy.Decision
	PURL      string   `json:"purl,omitempty"`
	Lockfiles []string `json:"lockfiles"`
}

// Summary counts.
type Summary struct {
	Total    int            `json:"total"`
	Send     int            `json:"checkable"`
	HeldBack int            `json:"held_back"`
	BySource map[string]int `json:"by_source"`
}

// Inventory is the whole result of `mantis deps`, and the first half of
// `mantis scan`.
type Inventory struct {
	SchemaVersion int              `json:"schema_version"`
	Tool          Tool             `json:"tool"`
	GeneratedAt   time.Time        `json:"generated_at"`
	Base          string           `json:"base"`
	Roots         []Root           `json:"roots"`
	Packages      []Package        `json:"packages"`
	Summary       Summary          `json:"summary"`
	Unresolved    []string         `json:"unresolved_manifests,omitempty"`
	Warnings      []string         `json:"warnings,omitempty"`
	Check         *api.CheckResult `json:"check,omitempty"`
	// Graph is the first hop of the tree, public packages only.
	Graph *lockfile.Graph `json:"graph,omitempty"`
}

// Tool identifies the producer.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Builder accumulates lockfile results.
type Builder struct {
	inv  *Inventory
	idx  map[string]int
	base string
}

// NewBuilder starts an inventory rooted at base (absolute path).
func NewBuilder(base, toolVersion string) *Builder {
	return &Builder{
		base: base,
		idx:  map[string]int{},
		inv: &Inventory{
			SchemaVersion: SchemaVersion,
			Tool:          Tool{Name: "mantis", Version: toolVersion},
			GeneratedAt:   time.Now().UTC().Truncate(time.Second),
			Base:          ".",
			Packages:      []Package{},
			Roots:         []Root{},
		},
	}
}

// Rel makes a path relative to the scan base, with forward slashes, so
// reports never contain the user's home directory.
func (b *Builder) Rel(p string) string {
	r, err := filepath.Rel(b.base, p)
	if err != nil {
		return filepath.ToSlash(filepath.Base(p))
	}
	return filepath.ToSlash(r)
}

// AddRoot records a root and its parsed lockfiles with their decisions.
func (b *Builder) AddRoot(dir string, manifests int, results []*lockfile.Result, decide func(lockfile.Package) policy.Decision) {
	root := Root{Dir: b.Rel(dir), Manifests: manifests}
	for _, res := range results {
		rel := b.Rel(res.Path)
		root.Lockfiles = append(root.Lockfiles, Lockfile{
			Path: rel, Format: string(res.Format), Version: res.Version,
			Packages: len(res.Packages), Warnings: res.Warnings,
		})
		if res.Graph != nil {
			if b.inv.Graph == nil {
				b.inv.Graph = &lockfile.Graph{}
			}
			b.inv.Graph.Merge(res.Graph)
		}
		for _, p := range res.Packages {
			k := p.Key() + "|" + string(p.Source)
			if i, ok := b.idx[k]; ok {
				b.inv.Packages[i].Lockfiles = appendUnique(b.inv.Packages[i].Lockfiles, rel)
				continue
			}
			d := decide(p)
			b.idx[k] = len(b.inv.Packages)
			b.inv.Packages = append(b.inv.Packages, Package{Decision: d, PURL: PURL(p), Lockfiles: []string{rel}})
		}
	}
	b.inv.Roots = append(b.inv.Roots, root)
}

// Warn adds a scan level warning.
func (b *Builder) Warn(w ...string) { b.inv.Warnings = append(b.inv.Warnings, w...) }

// Unresolved records manifests with no lockfile.
func (b *Builder) Unresolved(paths []string) {
	for _, p := range paths {
		b.inv.Unresolved = append(b.inv.Unresolved, b.Rel(p))
	}
}

// Done sorts and counts.
func (b *Builder) Done() *Inventory {
	inv := b.inv
	sort.Slice(inv.Packages, func(i, j int) bool {
		a, c := inv.Packages[i], inv.Packages[j]
		if a.Name != c.Name {
			return a.Name < c.Name
		}
		if a.Version != c.Version {
			return a.Version < c.Version
		}
		return a.Source < c.Source
	})
	s := Summary{BySource: map[string]int{}}
	for _, p := range inv.Packages {
		s.Total++
		s.BySource[string(p.Source)]++
		if p.Send {
			s.Send++
		} else {
			s.HeldBack++
		}
	}
	inv.Summary = s
	if inv.Graph != nil {
		// The graph names only what is sent anyway: public registry
		// versions the policy lets through. Nothing held back appears.
		sent := map[string]bool{}
		for _, p := range inv.Packages {
			if p.Send {
				sent[p.Key()] = true
			}
		}
		inv.Graph.Keep(func(k string) bool { return sent[k] })
		if len(inv.Graph.Direct) == 0 {
			inv.Graph = nil
		}
	}
	return inv
}

// Checkable returns name@version for every package cleared to send.
func (inv *Inventory) Checkable() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range inv.Packages {
		if p.Send && !seen[p.Key()] {
			seen[p.Key()] = true
			out = append(out, p.Key())
		}
	}
	return out
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// PURL is the package URL (github.com/package-url/purl-spec) for registry
// packages, "" otherwise.
func PURL(p lockfile.Package) string {
	if p.Source != lockfile.SourceRegistry || p.Name == "" || p.Version == "" {
		return ""
	}
	name := p.Name
	ns := ""
	if strings.HasPrefix(name, "@") {
		if s, n, ok := strings.Cut(name, "/"); ok {
			ns, name = s, n
		}
	}
	out := "pkg:npm/"
	// The purl spec requires '@' in the npm namespace to be %40 encoded;
	// url.PathEscape leaves '@' alone, so it is replaced explicitly.
	esc := func(s string) string { return strings.ReplaceAll(url.PathEscape(s), "@", "%40") }
	if ns != "" {
		out += esc(ns) + "/"
	}
	return out + esc(name) + "@" + esc(p.Version)
}

// WriteJSON writes the inventory as indented JSON.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// ---- CycloneDX ---------------------------------------------------------------

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref"`
	Group      string        `json:"group,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	Scope      string        `json:"scope,omitempty"`
	PURL       string        `json:"purl,omitempty"`
	Hashes     []cdxHash     `json:"hashes,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// WriteCycloneDX writes a CycloneDX 1.5 JSON SBOM of every pinned package.
func WriteCycloneDX(w io.Writer, inv *Inventory, projectName string) error {
	comps := make([]cdxComponent, 0, len(inv.Packages))
	for i, p := range inv.Packages {
		group, name := "", p.Name
		if strings.HasPrefix(name, "@") {
			if s, n, ok := strings.Cut(name, "/"); ok {
				group, name = s, n
			}
		}
		ref := p.PURL
		if ref == "" {
			ref = fmt.Sprintf("mantis:%d:%s@%s", i, p.Name, p.Version)
		}
		c := cdxComponent{
			Type: "library", BOMRef: ref, Group: group, Name: name, Version: p.Version, PURL: p.PURL,
			Properties: []cdxProperty{{Name: "mantis:source", Value: string(p.Source)}},
		}
		if p.Dev != nil && *p.Dev {
			c.Scope = "optional"
			c.Properties = append(c.Properties, cdxProperty{Name: "cdx:npm:package:development", Value: "true"})
		}
		if h, ok := sriToHash(p.Integrity); ok {
			c.Hashes = []cdxHash{h}
		}
		comps = append(comps, c)
	}
	if projectName == "" {
		projectName = "project"
	}
	doc := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.5",
		"serialNumber": "urn:uuid:" + uuid4(),
		"version":      1,
		"metadata": map[string]any{
			"timestamp": inv.GeneratedAt.Format(time.RFC3339),
			"tools": map[string]any{"components": []map[string]string{
				{"type": "application", "name": "mantis", "version": inv.Tool.Version},
			}},
			"component": map[string]string{"type": "application", "bom-ref": "root", "name": projectName},
		},
		"components": comps,
	}
	return WriteJSON(w, doc)
}

// sriToHash converts "sha512-<base64>" to a CycloneDX hash.
func sriToHash(sri string) (cdxHash, bool) {
	// An SRI string may list several hashes; take the strongest known one.
	best := cdxHash{}
	rank := 0
	for _, part := range strings.Fields(sri) {
		alg, b64, ok := strings.Cut(part, "-")
		if !ok {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}
		name, r := "", 0
		switch alg {
		case "sha512":
			name, r = "SHA-512", 3
		case "sha384":
			name, r = "SHA-384", 2
		case "sha256":
			name, r = "SHA-256", 1
		case "sha1":
			name, r = "SHA-1", 0
		default:
			continue
		}
		if r >= rank && (best.Alg == "" || r > rank) {
			best, rank = cdxHash{Alg: name, Content: hex.EncodeToString(raw)}, r
		}
	}
	return best, best.Alg != ""
}

func uuid4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
