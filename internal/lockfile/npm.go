package lockfile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// npm package-lock.json and npm-shrinkwrap.json.
//
//   v1 (npm 5 and 6): a nested "dependencies" tree.
//   v2 (npm 7 and 8): "packages" keyed by install path, plus v1 "dependencies".
//   v3 (npm 9 and later): "packages" only.
//
// When "packages" is present it is authoritative and "dependencies" is ignored.

type npmLock struct {
	LockfileVersion json.RawMessage       `json:"lockfileVersion"`
	Packages        map[string]npmPackage `json:"packages"`
	Dependencies    map[string]npmV1Entry `json:"dependencies"`
}

type npmPackage struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Resolved    string `json:"resolved"`
	Integrity   string `json:"integrity"`
	Link        bool   `json:"link"`
	Dev         bool   `json:"dev"`
	Optional    bool   `json:"optional"`
	DevOptional bool   `json:"devOptional"`
	InBundle    bool   `json:"inBundle"`

	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type npmV1Entry struct {
	Version      string                `json:"version"`
	Resolved     string                `json:"resolved"`
	Integrity    string                `json:"integrity"`
	Dev          bool                  `json:"dev"`
	Optional     bool                  `json:"optional"`
	Bundled      bool                  `json:"bundled"`
	Dependencies map[string]npmV1Entry `json:"dependencies"`
}

func parseNPM(data []byte) (*Result, error) {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	res := &Result{Format: FormatNPM, Version: strings.Trim(string(lock.LockfileVersion), `"`)}
	if v, err := strconv.Atoi(res.Version); err == nil && v > 3 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("lockfileVersion %d is newer than Mantis knows; read as v3", v))
	}

	if len(lock.Packages) > 0 {
		keys := make([]string, 0, len(lock.Packages))
		for k := range lock.Packages {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, path := range keys {
			p := lock.Packages[path]
			if path == "" {
				continue // the project itself
			}
			i := strings.LastIndex(path, "node_modules/")
			if i < 0 {
				continue // a workspace member's source folder, not an install
			}
			name := path[i+len("node_modules/"):]
			if p.Link {
				// A symlink to a workspace member or a file: dependency. The
				// target folder's own entry holds its version.
				target := lock.Packages[p.Resolved]
				v := target.Version
				if v == "" {
					v = "file:" + p.Resolved
				}
				res.Packages = append(res.Packages, Package{
					Name: name, Version: v, Source: SourceLocal, Resolved: p.Resolved,
				})
				continue
			}
			if p.Name != "" {
				name = p.Name // npm alias: installed under one name, really another
			}
			version := p.Version
			src, host := classifyURL(p.Resolved)
			if p.Resolved == "" && version == "" {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: no version recorded, skipped", path))
				continue
			}
			if p.InBundle && p.Resolved == "" {
				// Shipped inside its parent's tarball; still real code that runs.
				src = SourceRegistry
			}
			if strings.HasPrefix(version, "file:") || strings.HasPrefix(version, "link:") {
				src = SourceLocal
			}
			pkg := Package{
				Name:      name,
				Version:   version,
				Source:    src,
				Resolved:  p.Resolved,
				Registry:  host,
				Integrity: p.Integrity,
				Dev:       boolPtr(p.Dev || p.DevOptional),
				Optional:  p.Optional || p.DevOptional,
			}
			if src != SourceRegistry && pkg.Version == "" {
				pkg.Version = p.Resolved
			}
			res.Packages = append(res.Packages, pkg)
		}
		res.Graph = npmGraph(lock.Packages)
		return res, nil
	}

	if len(lock.Dependencies) > 0 {
		walkNPMv1(lock.Dependencies, res)
		return res, nil
	}
	return res, nil
}

func walkNPMv1(deps map[string]npmV1Entry, res *Result) {
	names := make([]string, 0, len(deps))
	for n := range deps {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		e := deps[name]
		realName, version := name, e.Version
		// npm 6 alias: "alias": {"version": "npm:real@1.2.3"}
		if strings.HasPrefix(version, "npm:") {
			if n, v, ok := splitIdent(strings.TrimPrefix(version, "npm:")); ok {
				realName, version = n, v
			}
		}
		src, host := classifyURL(e.Resolved)
		if strings.Contains(version, ":") || strings.Contains(version, "/") {
			// git specs, file: paths and URLs live in the version field in v1
			s, h := classifyURL(version)
			src, host = s, h
		}
		res.Packages = append(res.Packages, Package{
			Name:      realName,
			Version:   version,
			Source:    src,
			Resolved:  e.Resolved,
			Registry:  host,
			Integrity: e.Integrity,
			Dev:       boolPtr(e.Dev),
			Optional:  e.Optional,
		})
		if len(e.Dependencies) > 0 {
			walkNPMv1(e.Dependencies, res)
		}
	}
}

// npmGraph reads the first hop from a v2/v3 lockfile: the root's
// dependencies and, for each, the dependencies it resolves to, following
// node's lookup rule (nearest node_modules up the install path).
func npmGraph(pkgs map[string]npmPackage) *Graph {
	root, ok := pkgs[""]
	if !ok {
		return nil
	}
	resolve := func(from, name string) (string, npmPackage, bool) {
		p := from
		for {
			k := "node_modules/" + name
			if p != "" {
				k = p + "/node_modules/" + name
			}
			if v, ok := pkgs[k]; ok {
				return k, v, true
			}
			if p == "" {
				return "", npmPackage{}, false
			}
			if i := strings.LastIndex(p, "/node_modules/"); i >= 0 {
				p = p[:i]
			} else {
				p = ""
			}
		}
	}
	key := func(path string, p npmPackage) string {
		if p.Link || p.Version == "" || strings.Contains(p.Version, ":") {
			return ""
		}
		name := path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]
		if p.Name != "" {
			name = p.Name
		}
		return name + "@" + p.Version
	}
	g := &Graph{}
	starts := map[string]string{} // install path -> key
	depsOf := func(path string) []string {
		p := pkgs[path]
		var out []string
		for _, m := range []map[string]string{p.Dependencies, p.OptionalDependencies, p.PeerDependencies} {
			for _, c := range sortedNames(m) {
				if cp, _, ok := resolve(path, c); ok {
					out = append(out, cp)
				}
			}
		}
		return out
	}
	add := func(names map[string]string, dev bool) {
		for _, n := range sortedNames(names) {
			path, p, ok := resolve("", n)
			if !ok {
				continue
			}
			k := key(path, p)
			if k == "" {
				continue
			}
			g.addDirect(k, dev)
			kids := map[string]string{}
			for _, m := range []map[string]string{p.Dependencies, p.OptionalDependencies, p.PeerDependencies} {
				for c, r := range m {
					kids[c] = r
				}
			}
			for _, c := range sortedNames(kids) {
				if cp, cv, ok := resolve(path, c); ok {
					if ck := key(cp, cv); ck != "" {
						g.addEdge(k, ck)
						starts[cp] = ck
					}
				}
			}
		}
	}
	add(root.Dependencies, false)
	add(root.OptionalDependencies, false)
	add(root.DevDependencies, true)
	g.fillBelow(depsOf, func(path string) string { return key(path, pkgs[path]) }, starts)
	return g
}

func sortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
