package resolve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Anurag-Chevendra/mantis/internal/lockfile"
)

// fakeRegistry serves abbreviated documents built from a compact table:
// name -> version -> dependencies. "latest" is the highest listed version
// unless tags overrides it.
type fakeRegistry struct {
	mu        sync.Mutex
	pkgs      map[string]map[string]map[string]string
	peers     map[string]map[string]map[string]string
	tags      map[string]string
	deprecate map[string]bool // name@version
	requested []string
	rawPaths  []string
}

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	f.mu.Lock()
	f.requested = append(f.requested, name)
	f.rawPaths = append(f.rawPaths, r.URL.EscapedPath())
	f.mu.Unlock()
	if !strings.Contains(r.Header.Get("Accept"), "application/vnd.npm.install-v1+json") {
		http.Error(w, "want corgi", http.StatusNotAcceptable)
		return
	}
	vers, ok := f.pkgs[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	doc := map[string]any{"name": name}
	versions := map[string]any{}
	latest := ""
	for v, deps := range vers {
		pv := map[string]any{"version": v, "dependencies": deps,
			"dist": map[string]string{"integrity": "sha512-" + name + v, "tarball": "https://x/" + name + "-" + v + ".tgz"}}
		if p := f.peers[name][v]; p != nil {
			pv["peerDependencies"] = p
		}
		if f.deprecate[name+"@"+v] {
			pv["deprecated"] = "do not use"
		}
		versions[v] = pv
		if latest == "" || v > latest {
			latest = v
		}
	}
	if t, ok := f.tags[name]; ok {
		latest = t
	}
	doc["versions"] = versions
	doc["dist-tags"] = map[string]string{"latest": latest}
	w.Header().Set("Content-Type", "application/vnd.npm.install-v1+json")
	_ = json.NewEncoder(w).Encode(doc)
}

func writeManifest(t *testing.T, v any) string {
	t.Helper()
	dir := t.TempDir()
	b, _ := json.Marshal(v)
	p := filepath.Join(dir, "package.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func run(t *testing.T, f *fakeRegistry, opt Options, manifest any) *lockfile.Result {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	opt.Registry = srv.URL
	opt.HTTP = srv.Client()
	r, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.ResolveManifest(context.Background(), writeManifest(t, manifest))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func keys(res *lockfile.Result, src lockfile.Source) []string {
	var out []string
	for _, p := range res.Packages {
		if p.Source == src {
			out = append(out, p.Name+"@"+p.Version)
		}
	}
	sort.Strings(out)
	return out
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestPicksLatestThenHighestSatisfying(t *testing.T) {
	f := &fakeRegistry{
		pkgs: map[string]map[string]map[string]string{
			"a": {"1.0.0": nil, "1.2.0": nil, "2.0.0": nil},
			"b": {"1.0.0": nil, "1.1.0": nil, "1.2.0": nil},
		},
		tags:      map[string]string{"b": "1.0.0"},
		deprecate: map[string]bool{"a@1.2.0": true},
	}
	// a: latest 2.0.0 does not satisfy ^1, 1.2.0 is deprecated, so 1.0.0.
	// b: latest 1.0.0 satisfies ^1 and wins over the higher 1.2.0.
	res := run(t, f, Options{}, map[string]any{"dependencies": map[string]string{"a": "^1", "b": "^1"}})
	eq(t, keys(res, lockfile.SourceRegistry), []string{"a@1.0.0", "b@1.0.0"})
}

func TestConflictNestsAndSharedVersionDedupes(t *testing.T) {
	f := &fakeRegistry{pkgs: map[string]map[string]map[string]string{
		"app-a": {"1.0.0": {"lib": "^1"}},
		"app-b": {"1.0.0": {"lib": "^2"}},
		"app-c": {"1.0.0": {"lib": "^1.1"}},
		"lib":   {"1.0.0": nil, "1.1.0": nil, "2.0.0": nil},
	}}
	res := run(t, f, Options{}, map[string]any{"dependencies": map[string]string{"app-a": "1", "app-b": "1", "app-c": "1"}})
	eq(t, keys(res, lockfile.SourceRegistry), []string{"app-a@1.0.0", "app-b@1.0.0", "app-c@1.0.0", "lib@1.1.0", "lib@2.0.0"})
}

func TestHeldNamesAreNeverRequested(t *testing.T) {
	f := &fakeRegistry{pkgs: map[string]map[string]map[string]string{
		"pub":           {"1.0.0": {"@corp/secret": "^1"}},
		"@corp/secret":  {"1.0.0": nil},
		"@corp/another": {"1.0.0": nil},
	}}
	hold := func(n string) string {
		if strings.HasPrefix(n, "@corp/") {
			return "private scope"
		}
		return ""
	}
	res := run(t, f, Options{Hold: hold}, map[string]any{"dependencies": map[string]string{"pub": "1", "@corp/another": "1"}})
	for _, n := range f.requested {
		if strings.HasPrefix(n, "@corp/") {
			t.Fatalf("held name %q was sent to the registry", n)
		}
	}
	eq(t, keys(res, lockfile.SourceRegistry), []string{"pub@1.0.0"})
	if got := keys(res, lockfile.SourceUnresolved); len(got) != 2 {
		t.Fatalf("held names should be reported unresolved, got %v", got)
	}
}

func TestDevFlagAndProd(t *testing.T) {
	f := &fakeRegistry{pkgs: map[string]map[string]map[string]string{
		"run":    {"1.0.0": {"shared": "1"}},
		"tool":   {"1.0.0": {"shared": "1", "only": "1"}},
		"shared": {"1.0.0": nil},
		"only":   {"1.0.0": nil},
	}}
	m := map[string]any{"dependencies": map[string]string{"run": "1"}, "devDependencies": map[string]string{"tool": "1"}}
	res := run(t, f, Options{}, m)
	dev := map[string]bool{}
	for _, p := range res.Packages {
		dev[p.Name] = p.Dev != nil && *p.Dev
	}
	if dev["run"] || dev["shared"] || !dev["tool"] || !dev["only"] {
		t.Fatalf("dev flags wrong: %v", dev)
	}
	res = run(t, f, Options{Prod: true}, m)
	eq(t, keys(res, lockfile.SourceRegistry), []string{"run@1.0.0", "shared@1.0.0"})
}

func TestScopedNameEncodingAndPeers(t *testing.T) {
	f := &fakeRegistry{
		pkgs: map[string]map[string]map[string]string{
			"@s/plugin": {"1.0.0": nil},
			"host":      {"1.0.0": nil, "2.0.0": nil},
		},
		peers: map[string]map[string]map[string]string{"@s/plugin": {"1.0.0": {"host": "^1"}}},
	}
	res := run(t, f, Options{}, map[string]any{"dependencies": map[string]string{"@s/plugin": "^1"}})
	eq(t, keys(res, lockfile.SourceRegistry), []string{"@s/plugin@1.0.0", "host@1.0.0"})
	found := false
	for _, p := range f.rawPaths {
		if p == "/@s%2fplugin" {
			found = true
		}
	}
	if !found {
		t.Fatalf("scoped name not requested as /@s%%2fplugin: %v", f.rawPaths)
	}
}

func TestUnknownNameAndNonRegistrySpecs(t *testing.T) {
	f := &fakeRegistry{pkgs: map[string]map[string]map[string]string{"ok": {"1.0.0": nil}}}
	res := run(t, f, Options{}, map[string]any{"dependencies": map[string]string{
		"ok": "1", "ghost": "1", "local": "file:../x", "gitdep": "github:o/r#abc",
	}})
	eq(t, keys(res, lockfile.SourceRegistry), []string{"ok@1.0.0"})
	eq(t, keys(res, lockfile.SourceUnresolved), []string{"ghost@*"})
	if len(keys(res, lockfile.SourceLocal)) != 1 || len(keys(res, lockfile.SourceGit)) != 1 {
		t.Fatalf("local and git specs should be reported, not fetched: %+v", res.Packages)
	}
	for _, n := range f.requested {
		if n == "local" || n == "gitdep" {
			t.Fatalf("%s was looked up on the registry", n)
		}
	}
}

func TestRejectsPlainHTTPRegistry(t *testing.T) {
	if _, err := New(Options{Registry: "http://registry.example.com"}); err == nil {
		t.Fatal("plain http registry accepted")
	}
}

func TestMaxPackagesStopsFetchingEarly(t *testing.T) {
	// A chain p0 -> p1 -> ... -> p39. With a cap of 5 the walk must stop long
	// before the end of the chain and the tree must be refused.
	pkgs := map[string]map[string]map[string]string{}
	for i := 0; i < 40; i++ {
		deps := map[string]string{}
		if i < 39 {
			deps[fmt.Sprintf("p%d", i+1)] = "1"
		}
		pkgs[fmt.Sprintf("p%d", i)] = map[string]map[string]string{"1.0.0": deps}
	}
	f := &fakeRegistry{pkgs: pkgs}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	r, err := New(Options{Registry: srv.URL, HTTP: srv.Client(), MaxPackages: 5})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.ResolveManifest(context.Background(), writeManifest(t, map[string]any{"dependencies": map[string]string{"p0": "1"}}))
	if err == nil || !strings.Contains(err.Error(), "max-packages") {
		t.Fatalf("want a max-packages refusal, got %v", err)
	}
	if n := len(f.requested); n > 12 {
		t.Fatalf("fetched %d documents after the cap; the walk should stop early", n)
	}
}
