package lockfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

// pnpm-lock.yaml.
//
//   v5.x  keys "/name/1.2.3" or "/@scope/name/1.2.3_peer+suffix"
//   v6.0  keys "/name@1.2.3" or "/@scope/name@1.2.3(peer@1.0.0)"
//   v7+   keys "name@1.2.3" (no leading slash); peers move to "snapshots"
//
// Packages that do not come from a registry carry explicit "name" and
// "version" fields and a "resolution" with a tarball URL, git repo or
// directory.
//
// pnpm 11 and later can write two YAML documents into one file: first the
// lockfile for pnpm itself and its config dependencies, then the project's.
// Both are installed, so every document is read.

type pnpmLock struct {
	LockfileVersion any                     `yaml:"lockfileVersion"`
	Packages        map[string]pnpmPackage  `yaml:"packages"`
	Importers       map[string]pnpmImporter `yaml:"importers"`
	Snapshots       map[string]pnpmSnapshot `yaml:"snapshots"`
}

type pnpmImporter struct {
	Dependencies         map[string]any `yaml:"dependencies"`
	DevDependencies      map[string]any `yaml:"devDependencies"`
	OptionalDependencies map[string]any `yaml:"optionalDependencies"`
}

type pnpmSnapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type pnpmPackage struct {
	Name       string         `yaml:"name"`
	Version    string         `yaml:"version"`
	Resolution map[string]any `yaml:"resolution"`
	Dev        *bool          `yaml:"dev"`
	Optional   bool           `yaml:"optional"`

	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

func parsePNPM(data []byte) (*Result, error) {
	lock := pnpmLock{Packages: map[string]pnpmPackage{}, Importers: map[string]pnpmImporter{}, Snapshots: map[string]pnpmSnapshot{}}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	docs := 0
	for {
		var doc pnpmLock
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("not valid YAML: %w", err)
		}
		docs++
		if doc.LockfileVersion != nil {
			lock.LockfileVersion = doc.LockfileVersion
		}
		for k, v := range doc.Packages {
			lock.Packages[k] = v
		}
		for k, v := range doc.Snapshots {
			lock.Snapshots[k] = v
		}
		if docs > 1 || len(doc.Packages) > 0 {
			// The project's importers live in the last document.
			for k, v := range doc.Importers {
				lock.Importers[k] = v
			}
		}
	}
	if docs == 0 {
		return nil, errors.New("empty lockfile")
	}
	ver := strings.TrimSpace(fmt.Sprint(lock.LockfileVersion))
	res := &Result{Format: FormatPNPM, Version: ver}
	major := 0
	if f, err := strconv.ParseFloat(ver, 64); err == nil {
		major = int(f)
	}
	if major == 0 {
		return nil, fmt.Errorf("missing or unreadable lockfileVersion %q", ver)
	}
	if major < 5 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("lockfileVersion %s predates v5; results may be incomplete", ver))
	}
	if major > 9 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("lockfileVersion %s is newer than Mantis knows; read as v9", ver))
	}

	keys := make([]string, 0, len(lock.Packages))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		e := lock.Packages[key]
		name, version := pnpmKey(key, major)

		src := SourceRegistry
		resolved := ""
		host := ""
		integrity, _ := e.Resolution["integrity"].(string)
		if t, ok := e.Resolution["tarball"].(string); ok && t != "" {
			resolved = t
			src, host = classifyURL(t)
			if strings.HasPrefix(t, "file:") {
				src = SourceLocal
			}
		}
		if typ, _ := e.Resolution["type"].(string); typ == "git" {
			src = SourceGit
			repo, _ := e.Resolution["repo"].(string)
			commit, _ := e.Resolution["commit"].(string)
			resolved = strings.TrimSuffix(repo+"#"+commit, "#")
		} else if typ == "directory" {
			src = SourceLocal
			resolved, _ = e.Resolution["directory"].(string)
		}
		if _, ok := e.Resolution["repo"].(string); ok && src == SourceRegistry {
			src = SourceGit
		}
		if strings.HasPrefix(key, "file:") || strings.HasPrefix(key, "link:") ||
			strings.Contains(version, "file:") || strings.Contains(version, "link:") {
			src = SourceLocal
		}

		// Explicit fields win: they are the only reliable source for
		// non-registry entries, whose keys hold a URL rather than a version.
		if e.Name != "" {
			name = e.Name
		}
		if e.Version != "" {
			version = e.Version
		}
		if name == "" || version == "" {
			res.Warnings = append(res.Warnings, fmt.Sprintf("could not read name and version from %q, skipped", key))
			continue
		}
		res.Packages = append(res.Packages, Package{
			Name:      name,
			Version:   version,
			Source:    src,
			Resolved:  resolved,
			Registry:  host,
			Integrity: integrity,
			Dev:       e.Dev,
			Optional:  e.Optional,
		})
	}
	res.Graph = pnpmGraph(&lock)
	return res, nil
}

// pnpmGraph reads the first hop: each importer's dependencies, and what each
// of those depends on (snapshots in v9, packages before that).
func pnpmGraph(lock *pnpmLock) *Graph {
	if len(lock.Importers) == 0 {
		return nil
	}
	clean := func(name, ver string) (string, string) {
		if i := strings.IndexByte(ver, '('); i >= 0 {
			ver = ver[:i]
		}
		ver = strings.TrimPrefix(ver, "/")
		// An alias records the real package: "real@1.0.0".
		if i := strings.LastIndex(ver, "@"); i > 0 && (ver[0] < '0' || ver[0] > '9') {
			name, ver = ver[:i], ver[i+1:]
		}
		return name, ver
	}
	full := func(name, ver string) string {
		if strings.HasPrefix(ver, "link:") || strings.HasPrefix(ver, "file:") || strings.Contains(ver, "://") {
			return ""
		}
		return name + "@" + strings.TrimPrefix(ver, "/")
	}
	children := func(key string) map[string]string {
		for _, k := range []string{key, "/" + key} {
			if s, ok := lock.Snapshots[k]; ok {
				return mergeStr(s.Dependencies, s.OptionalDependencies)
			}
			if p, ok := lock.Packages[k]; ok && (len(p.Dependencies) > 0 || len(p.OptionalDependencies) > 0) {
				return mergeStr(p.Dependencies, p.OptionalDependencies)
			}
		}
		return nil
	}
	g := &Graph{}
	starts := map[string]string{} // lookup key -> clean key
	cleanKey := func(lookup string) string {
		i := strings.LastIndex(strings.SplitN(lookup, "(", 2)[0], "@")
		if i <= 0 {
			return ""
		}
		n, v := clean(lookup[:i], lookup[i+1:])
		return n + "@" + v
	}
	next := func(lookup string) []string {
		kids := children(lookup)
		var out []string
		for _, c := range sortedNames(kids) {
			if f := full(c, kids[c]); f != "" {
				if strings.Contains(kids[c], "@") && kids[c][0] != '@' && (kids[c][0] < '0' || kids[c][0] > '9') {
					f = kids[c]
				}
				out = append(out, f)
			}
		}
		return out
	}
	imps := make([]string, 0, len(lock.Importers))
	for k := range lock.Importers {
		imps = append(imps, k)
	}
	sort.Strings(imps)
	for _, ik := range imps {
		imp := lock.Importers[ik]
		for _, grp := range []struct {
			m   map[string]any
			dev bool
		}{{imp.Dependencies, false}, {imp.OptionalDependencies, false}, {imp.DevDependencies, true}} {
			names := make([]string, 0, len(grp.m))
			for n := range grp.m {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				raw := ""
				switch v := grp.m[n].(type) {
				case string:
					raw = v
				case map[string]any:
					raw, _ = v["version"].(string)
				}
				lookup := full(n, raw)
				if lookup == "" {
					continue
				}
				dn, dv := clean(n, raw)
				parent := dn + "@" + dv
				g.addDirect(parent, grp.dev)
				kids := children(lookup)
				if kids == nil {
					kids = children(parent)
				}
				for _, c := range sortedNames(kids) {
					if full(c, kids[c]) == "" {
						continue
					}
					cn, cv := clean(c, kids[c])
					g.addEdge(parent, cn+"@"+cv)
					f := full(c, kids[c])
					if strings.Contains(kids[c], "@") && kids[c][0] != '@' && (kids[c][0] < '0' || kids[c][0] > '9') {
						f = kids[c]
					}
					starts[f] = cn + "@" + cv
				}
			}
		}
	}
	g.fillBelow(next, cleanKey, starts)
	return g
}

func mergeStr(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// pnpmKey extracts name and version from a packages key.
func pnpmKey(key string, major int) (name, version string) {
	k := strings.TrimPrefix(key, "/")
	if major >= 6 {
		n, rest, ok := splitIdent(k)
		if !ok {
			return "", ""
		}
		if i := strings.IndexByte(rest, '('); i >= 0 {
			rest = rest[:i]
		}
		return n, rest
	}
	// v5: name/version_peers, where name may contain one slash when scoped.
	i := strings.LastIndexByte(k, '/')
	if i <= 0 {
		return "", ""
	}
	name, version = k[:i], k[i+1:]
	if strings.HasPrefix(name, "@") && !strings.Contains(name, "/") {
		return "", ""
	}
	if !strings.HasPrefix(name, "@") && strings.Contains(name, "/") {
		// "registry.npmjs.org/foo/1.0.0" or "github.com/user/repo/sha":
		// a non-registry key. The entry's own name and version fields decide.
		return "", ""
	}
	if j := strings.IndexByte(version, '_'); j >= 0 {
		version = version[:j]
	}
	return name, version
}
