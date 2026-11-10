package lockfile

import (
	"bufio"
	"bytes"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/goccy/go-yaml"
)

// yarn.lock comes in two unrelated formats that share a file name.
//
// Classic (Yarn 1) is a custom indentation format:
//
//	"@babel/core@^7.0.0", "@babel/core@^7.1.0":
//	  version "7.12.3"
//	  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.12.3.tgz#..."
//	  integrity sha512-...
//
// Berry (Yarn 2 and later) is YAML with a __metadata block:
//
//	"lodash@npm:^4.17.21":
//	  version: 4.17.21
//	  resolution: "lodash@npm:4.17.21"
func parseYarn(data []byte) (*Result, error) {
	if isYarnBerry(data) {
		return parseYarnBerry(data)
	}
	return parseYarnClassic(data)
}

func isYarnBerry(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for i := 0; sc.Scan() && i < 50; i++ {
		if strings.HasPrefix(sc.Text(), "__metadata:") {
			return true
		}
	}
	return false
}

// ---- classic ---------------------------------------------------------------

func parseYarnClassic(data []byte) (*Result, error) {
	res := &Result{Format: FormatYarnClassic, Version: "1"}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 16<<20)

	var (
		specs    []string
		fields   map[string]string
		lineNo   int
		sawEntry bool
	)
	flush := func() {
		if specs == nil {
			return
		}
		if p, ok := yarnClassicPackage(specs, fields); ok {
			res.Packages = append(res.Packages, p)
		} else {
			res.Warnings = append(res.Warnings, fmt.Sprintf("could not read entry %q, skipped", strings.Join(specs, ", ")))
		}
		specs, fields = nil, nil
	}

	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 0:
			flush()
			if !strings.HasSuffix(trimmed, ":") {
				return nil, fmt.Errorf("line %d: expected an entry header ending in ':'", lineNo)
			}
			specs = splitYarnSpecs(strings.TrimSuffix(trimmed, ":"))
			fields = map[string]string{}
			sawEntry = true
		case indent == 2 && fields != nil:
			if strings.HasSuffix(trimmed, ":") {
				continue // "dependencies:" and friends; their children are ranges, not pins
			}
			k, v := splitYarnField(trimmed)
			fields[k] = v
		default:
			// nested dependency ranges: not pins, ignored
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	if !sawEntry && len(bytes.TrimSpace(data)) > 0 && !bytes.Contains(data, []byte("yarn lockfile v1")) {
		return nil, fmt.Errorf("no entries found; not a yarn lockfile")
	}
	return res, nil
}

func splitYarnSpecs(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitYarnField(s string) (string, string) {
	k, v := s, ""
	if i := strings.IndexByte(s, ' '); i >= 0 {
		k, v = s[:i], strings.TrimSpace(s[i+1:])
	}
	return strings.Trim(k, `"`), strings.Trim(v, `"`)
}

func yarnClassicPackage(specs []string, f map[string]string) (Package, bool) {
	if len(specs) == 0 {
		return Package{}, false
	}
	name, rng, ok := splitIdent(specs[0])
	if !ok {
		return Package{}, false
	}
	// alias: "alias@npm:real@^1.0.0"
	if strings.HasPrefix(rng, "npm:") {
		if n, _, ok := splitIdent(strings.TrimPrefix(rng, "npm:")); ok {
			name = n
		}
	}
	version := f["version"]
	resolved := f["resolved"]
	src, host := classifyURL(resolved)
	low := strings.ToLower(rng)
	if strings.HasPrefix(low, "file:") || strings.HasPrefix(low, "link:") {
		src = SourceLocal
	} else if strings.HasPrefix(low, "github:") || strings.HasPrefix(low, "git") ||
		(strings.Contains(rng, "/") && !strings.HasPrefix(low, "npm:") && !strings.Contains(low, "://") && src != SourceRegistry) {
		src = SourceGit
	}
	if version == "" {
		return Package{}, false
	}
	return Package{
		Name:      name,
		Version:   version,
		Source:    src,
		Resolved:  stripFragment(resolved),
		Registry:  host,
		Integrity: f["integrity"],
	}, true
}

func stripFragment(u string) string {
	if i := strings.IndexByte(u, '#'); i >= 0 && strings.Contains(u, "://") && !strings.HasPrefix(u, "git") {
		return u[:i]
	}
	return u
}

// ---- berry -----------------------------------------------------------------

type berryEntry struct {
	Version    string `yaml:"version"`
	Resolution string `yaml:"resolution"`
	Checksum   string `yaml:"checksum"`
	LinkType   string `yaml:"linkType"`
}

func parseYarnBerry(data []byte) (*Result, error) {
	// Decoded loosely: __metadata has a different shape from the entries.
	var generic map[string]any
	if err := yaml.Unmarshal(data, &generic); err != nil {
		return nil, fmt.Errorf("not valid YAML: %w", err)
	}
	res := &Result{Format: FormatYarnBerry}
	if md, ok := generic["__metadata"].(map[string]any); ok {
		res.Version = fmt.Sprint(md["version"])
	}
	keys := make([]string, 0, len(generic))
	for k := range generic {
		if k != "__metadata" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	for _, k := range keys {
		m, ok := generic[k].(map[string]any)
		if !ok {
			continue
		}
		e := berryEntry{
			Version:    str(m["version"]),
			Resolution: str(m["resolution"]),
			Checksum:   str(m["checksum"]),
			LinkType:   str(m["linkType"]),
		}
		p, ok := berryPackage(e)
		if !ok {
			res.Warnings = append(res.Warnings, fmt.Sprintf("could not read resolution %q, skipped", e.Resolution))
			continue
		}
		res.Packages = append(res.Packages, p)
	}
	return res, nil
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// berryPackage reads a resolution such as:
//
//	lodash@npm:4.17.21
//	@types/node@npm:20.1.0
//	app@workspace:.
//	resolve@patch:resolve@npm%3A1.22.8#~builtin<compat/resolve>::version=1.22.8&hash=c3c19d
//	my-dep@https://github.com/user/repo.git#commit=abc123
func berryPackage(e berryEntry) (Package, bool) {
	name, rest, ok := splitIdent(e.Resolution)
	if !ok {
		return Package{}, false
	}
	proto, ref, _ := strings.Cut(rest, ":")
	switch proto {
	case "npm":
		v := ref
		if n, vv, ok := splitIdent(ref); ok && n != "" {
			// npm:real@1.0.0 alias form
			name, v = n, vv
		}
		if e.Version != "" {
			v = e.Version
		}
		// Yarn's checksum is "<cacheKey>/<sha512 hex>", not an npm SRI string,
		// so it is not reported as Integrity.
		return Package{Name: name, Version: v, Source: SourceRegistry}, true
	case "patch":
		// The patched code is the base npm package plus a local diff. Report
		// the base so it can still be looked up.
		inner := ref
		if i := strings.IndexByte(inner, '#'); i >= 0 {
			inner = inner[:i]
		}
		if dec, err := url.QueryUnescape(inner); err == nil {
			inner = dec
		}
		if n, r, ok := splitIdent(inner); ok && strings.HasPrefix(r, "npm:") {
			v := strings.TrimPrefix(r, "npm:")
			if e.Version != "" {
				v = e.Version
			}
			return Package{Name: n, Version: v, Source: SourceRegistry}, true
		}
		return Package{Name: name, Version: e.Version, Source: SourceLocal, Resolved: e.Resolution}, e.Version != ""
	case "workspace", "portal", "link", "file", "exec":
		return Package{Name: name, Version: firstNonEmpty(e.Version, ref), Source: SourceLocal, Resolved: e.Resolution}, true
	case "git", "git+ssh", "git+https", "github":
		return Package{Name: name, Version: firstNonEmpty(e.Version, ref), Source: SourceGit, Resolved: e.Resolution}, true
	case "http", "https":
		src, host := classifyURL(rest)
		return Package{Name: name, Version: firstNonEmpty(e.Version, rest), Source: src, Registry: host, Resolved: rest}, true
	default:
		return Package{Name: name, Version: firstNonEmpty(e.Version, ref), Source: SourceTarball, Resolved: e.Resolution}, e.Version != "" || ref != ""
	}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
