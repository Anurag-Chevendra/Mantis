package lockfile

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func load(t *testing.T, dir, name string) *Result {
	t.Helper()
	res, err := ParseFile(filepath.Join("..", "..", "testdata", dir, name))
	if err != nil {
		t.Fatalf("parse %s/%s: %v", dir, name, err)
	}
	return res
}

func index(res *Result) map[string]Package {
	m := map[string]Package{}
	for _, p := range res.Packages {
		m[p.Key()] = p
	}
	return m
}

type want struct {
	key    string
	source Source
	dev    *bool // nil: do not check
}

func check(t *testing.T, res *Result, wants []want, total int) {
	t.Helper()
	got := index(res)
	for _, w := range wants {
		p, ok := got[w.key]
		if !ok {
			t.Errorf("%s: missing %s; have %v", res.Format, w.key, keys(got))
			continue
		}
		if p.Source != w.source {
			t.Errorf("%s: %s source = %s, want %s", res.Format, w.key, p.Source, w.source)
		}
		if w.dev != nil && (p.Dev == nil || *p.Dev != *w.dev) {
			t.Errorf("%s: %s dev = %v, want %v", res.Format, w.key, p.Dev, *w.dev)
		}
	}
	if total >= 0 && len(res.Packages) != total {
		t.Errorf("%s: %d packages, want %d: %v", res.Format, len(res.Packages), total, keys(got))
	}
}

func keys(m map[string]Package) []string {
	out := make([]string, 0, len(m))
	for k, p := range m {
		out = append(out, k+"("+string(p.Source)+")")
	}
	return out
}

var (
	yes = boolPtr(true)
	no  = boolPtr(false)
)

// The common fixture project: debug (with nested ms), a scoped package, an
// npm alias (lod -> lodash), a local file: dependency, a dev dependency and an
// optional dependency.
var common = []want{
	{"debug@2.6.9", SourceRegistry, nil},
	{"ms@2.0.0", SourceRegistry, nil},
	{"@sindresorhus/is@4.6.0", SourceRegistry, nil},
	{"lodash@4.17.21", SourceRegistry, nil},
	{"is-number@7.0.0", SourceRegistry, nil},
	{"left-pad@1.3.0", SourceRegistry, nil},
}

func TestNPMv3(t *testing.T) {
	res := load(t, "npm-v3", "package-lock.json")
	if res.Format != FormatNPM || res.Version != "3" {
		t.Fatalf("format %s version %s", res.Format, res.Version)
	}
	w := append([]want{}, common...)
	w[0].dev, w[4].dev = no, yes
	w = append(w, want{"slugify@1.6.6", SourceGit, nil})
	check(t, res, w, 8)
	if p := index(res)["localpkg@0.1.0"]; p.Source != SourceLocal {
		t.Errorf("localpkg should be local, got %+v", p)
	}
	if p := index(res)["lodash@4.17.21"]; p.Registry != "registry.npmjs.org" || !strings.HasPrefix(p.Integrity, "sha512-") {
		t.Errorf("lodash registry/integrity not read: %+v", p)
	}
}

func TestNPMv1(t *testing.T) {
	res := load(t, "npm-v1", "package-lock.json")
	if res.Version != "1" {
		t.Fatalf("version %s", res.Version)
	}
	check(t, res, common, -1)
	for _, p := range res.Packages {
		if p.Name == "lod" {
			t.Errorf("alias should resolve to lodash, got %+v", p)
		}
		if p.Name == "localpkg" && p.Source != SourceLocal {
			t.Errorf("localpkg should be local: %+v", p)
		}
	}
}

func TestNPMWorkspaces(t *testing.T) {
	res := load(t, "npm-workspaces", "package-lock.json")
	// a and b are workspace links (local); the two ms versions are installs.
	check(t, res, []want{
		{"ms@2.1.3", SourceRegistry, nil},
		{"ms@2.0.0", SourceRegistry, nil},
		{"a@1.0.0", SourceLocal, nil},
		{"b@1.0.0", SourceLocal, nil},
	}, 4)
}

func TestNPMEdge(t *testing.T) {
	res := load(t, "edge-npm-v3", "package-lock.json")
	check(t, res, []want{
		{"slugify@1.6.6", SourceGit, nil},
		{"@corp/secret-sdk@9.9.9", SourceRegistry, nil},
		{"remote-tar@1.0.0", SourceTarball, nil},
		{"ms@2.0.0", SourceRegistry, yes},
		{"foo@1.0.0", SourceRegistry, yes},
	}, 5)
	if p := index(res)["@corp/secret-sdk@9.9.9"]; p.Registry != "artifactory.corp.example.com" {
		t.Errorf("private registry host not recorded: %+v", p)
	}
}

func TestPNPMv9(t *testing.T) {
	res := load(t, "pnpm-v9", "pnpm-lock.yaml")
	if res.Version != "9.0" {
		t.Fatalf("version %s", res.Version)
	}
	w := append([]want{}, common...)
	w = append(w, want{"slugify@1.6.6", SourceGit, nil})
	check(t, res, w, -1)
	for _, p := range res.Packages {
		if p.Source == SourceRegistry && strings.Contains(p.Version, "(") {
			t.Errorf("peer suffix left in version: %+v", p)
		}
	}
}

func TestPNPMv6(t *testing.T) {
	res := load(t, "pnpm-v6", "pnpm-lock.yaml")
	check(t, res, []want{
		{"react-dom@18.2.0", SourceRegistry, no},
		{"react@18.2.0", SourceRegistry, no},
		{"loose-envify@1.4.0", SourceRegistry, no},
		{"js-tokens@4.0.0", SourceRegistry, yes},
		{"@scope/private-lib@2.0.0", SourceRegistry, no},
	}, 5)
	if p := index(res)["@scope/private-lib@2.0.0"]; p.Registry != "npm.corp.example.com" {
		t.Errorf("tarball registry host not recorded: %+v", p)
	}
}

func TestPNPMv5(t *testing.T) {
	res := load(t, "pnpm-v5", "pnpm-lock.yaml")
	check(t, res, []want{
		{"@types/node@18.11.9", SourceRegistry, yes},
		{"debug@2.6.9", SourceRegistry, no},
		{"ms@2.0.0", SourceRegistry, no},
		{"react-dom@18.2.0", SourceRegistry, no},
		{"react@18.2.0", SourceRegistry, no},
		{"slugify@1.6.6", SourceGit, no},
	}, 6)
}

func TestYarnClassic(t *testing.T) {
	res := load(t, "yarn-classic", "yarn.lock")
	if res.Format != FormatYarnClassic {
		t.Fatalf("format %s", res.Format)
	}
	check(t, res, common, -1)
	if p := index(res)["localpkg@0.1.0"]; p.Source != SourceLocal {
		t.Errorf("localpkg should be local: %+v", p)
	}
}

func TestYarnClassicEdge(t *testing.T) {
	res := load(t, "edge-yarn-classic", "yarn.lock")
	check(t, res, []want{
		{"@corp/internal-ui@3.1.4", SourceRegistry, nil},
		{"lodash@4.17.21", SourceRegistry, nil},
		{"slugify@1.6.6", SourceGit, nil},
		{"localpkg@0.1.0", SourceLocal, nil},
	}, 4)
	if p := index(res)["@corp/internal-ui@3.1.4"]; p.Registry != "npm.corp.example.com" {
		t.Errorf("private registry host not recorded: %+v", p)
	}
}

func TestYarnBerry(t *testing.T) {
	res := load(t, "yarn-berry", "yarn.lock")
	if res.Format != FormatYarnBerry {
		t.Fatalf("format %s", res.Format)
	}
	check(t, res, common, -1)
	for _, p := range res.Packages {
		if p.Name == "fixture-app" && p.Source != SourceLocal {
			t.Errorf("workspace root should be local: %+v", p)
		}
		if p.Name == "lod" {
			t.Errorf("alias should resolve to lodash: %+v", p)
		}
	}
}

func TestBun(t *testing.T) {
	res := load(t, "bun", "bun.lock")
	check(t, res, common, 7)
	if p := index(res)["lodash@4.17.21"]; !strings.HasPrefix(p.Integrity, "sha512-") {
		t.Errorf("integrity not read: %+v", p)
	}
	var local bool
	for _, p := range res.Packages {
		if p.Name == "localpkg" && p.Source == SourceLocal {
			local = true
		}
	}
	if !local {
		t.Error("localpkg should be local")
	}
}

func TestBerryResolutions(t *testing.T) {
	cases := []struct {
		res, name, ver string
		src            Source
	}{
		{"lodash@npm:4.17.21", "lodash", "4.17.21", SourceRegistry},
		{"@types/node@npm:20.1.0", "@types/node", "20.1.0", SourceRegistry},
		{"resolve@patch:resolve@npm%3A1.22.8#~builtin<compat/resolve>::version=1.22.8&hash=c3c19d", "resolve", "1.22.8", SourceRegistry},
		{"app@workspace:.", "app", "0.0.0-use.local", SourceLocal},
		{"dep@https://github.com/user/repo.git#commit=abc", "dep", "1.0.0", SourceGit},
	}
	for _, c := range cases {
		ver := "1.0.0"
		if c.src == SourceLocal {
			ver = "0.0.0-use.local"
		} else if c.src == SourceRegistry {
			ver = ""
		}
		p, ok := berryPackage(berryEntry{Resolution: c.res, Version: ver})
		if !ok || p.Name != c.name || p.Source != c.src || (c.src == SourceRegistry && p.Version != c.ver) {
			t.Errorf("%s: got %+v ok=%v", c.res, p, ok)
		}
	}
}

func TestJSONC(t *testing.T) {
	in := `{"a": [1, 2,], "s": "x,]", // c
	"b": {"c": 1,}, /* x */ }`
	out, err := jsoncToJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), ",]") && !strings.Contains(string(out), `"x,]"`) {
		t.Fatalf("trailing comma left: %s", out)
	}
	if !strings.Contains(string(out), `"x,]"`) {
		t.Fatalf("string content changed: %s", out)
	}
}

func TestRejectsGarbage(t *testing.T) {
	for _, n := range []string{"package-lock.json", "pnpm-lock.yaml", "bun.lock"} {
		if _, err := Parse(n, []byte("\x00\x01 not a lockfile {{{")); err == nil {
			t.Errorf("%s: expected an error for garbage input", n)
		}
	}
	if _, err := Parse("unknown.lock", nil); err == nil {
		t.Error("expected error for unknown file name")
	}
}

func FuzzParse(f *testing.F) {
	f.Add("package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}`))
	f.Add("yarn.lock", []byte("a@^1:\n  version \"1.0.0\"\n"))
	f.Add("pnpm-lock.yaml", []byte("lockfileVersion: '9.0'\npackages:\n  a@1.0.0: {}\n"))
	f.Add("bun.lock", []byte(`{"lockfileVersion":1,"packages":{"a":["a@1.0.0","",{},"sha512-x"],}}`))
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		// Must never panic, whatever the input.
		_, _ = Parse(name, data)
	})
}

// pnpm 11+ writes the package manager's own lockfile as a first YAML
// document; the project's packages are in the second.
func TestPNPMMultiDocument(t *testing.T) {
	data := []byte(`---
lockfileVersion: '9.0'
importers:
  .:
    packageManagerDependencies:
      pnpm: {specifier: 12.18.0, version: 12.18.0}
packages:
  pnpm@12.18.0:
    resolution: {integrity: sha512-a}
---
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      left-pad: {specifier: ^1.3.0, version: 1.3.0}
packages:
  left-pad@1.3.0:
    resolution: {integrity: sha512-b}
`)
	res, err := Parse("pnpm-lock.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	got := keys(index(res))
	sort.Strings(got)
	if strings.Join(got, " ") != "left-pad@1.3.0(registry) pnpm@12.18.0(registry)" {
		t.Fatalf("got %v", got)
	}
}

func TestNPMGraphFirstHop(t *testing.T) {
	data := []byte(`{"lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"a":"^1"},"devDependencies":{"d":"^1"}},
"node_modules/a":{"version":"1.0.0","dependencies":{"b":"^2","c":"^1"}},
"node_modules/b":{"version":"2.0.0","dependencies":{"deep":"^1"}},
"node_modules/a/node_modules/c":{"version":"1.5.0"},
"node_modules/c":{"version":"1.0.0"},
"node_modules/deep":{"version":"1.0.0"},
"node_modules/d":{"version":"3.0.0","dev":true}}}`)
	res, err := Parse("package-lock.json", data)
	if err != nil {
		t.Fatal(err)
	}
	g := res.Graph
	if g == nil || len(g.Direct) != 2 || g.Direct[0].Key != "a@1.0.0" || g.Direct[1].Key != "d@3.0.0" || !g.Direct[1].Dev {
		t.Fatalf("direct %+v", g)
	}
	want := "[[a@1.0.0 b@2.0.0] [a@1.0.0 c@1.5.0]]"
	if got := fmt.Sprint(g.Edges); got != want {
		t.Fatalf("edges %s, want %s (nested copy wins, one hop only)", got, want)
	}
}

func TestPNPMGraphFirstHop(t *testing.T) {
	data := []byte(`lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      a: {specifier: ^1, version: 1.0.0}
    devDependencies:
      w: {specifier: ^1, version: 'string-width@4.2.3'}
packages:
  a@1.0.0: {resolution: {integrity: x}}
  b@2.0.0: {resolution: {integrity: x}}
  string-width@4.2.3: {resolution: {integrity: x}}
snapshots:
  a@1.0.0:
    dependencies:
      b: 2.0.0(peer@1.0.0)
  b@2.0.0: {}
  string-width@4.2.3: {}
`)
	res, err := Parse("pnpm-lock.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	g := res.Graph
	if g == nil || len(g.Direct) != 2 || fmt.Sprint(g.Edges) != "[[a@1.0.0 b@2.0.0]]" {
		t.Fatalf("graph %+v", g)
	}
	if g.Direct[1].Key != "string-width@4.2.3" || !g.Direct[1].Dev {
		t.Fatalf("alias not resolved: %+v", g.Direct)
	}
}
