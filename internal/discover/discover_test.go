package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalk(t *testing.T) {
	base := t.TempDir()
	for _, p := range []string{
		"package.json", "package-lock.json",
		"packages/a/package.json", "packages/b/package.json", // workspace members of the root
		"edge/package.json", "edge/pnpm-lock.yaml", // nested root
		"tools/release/package.json",  // grouped under the top root
		"node_modules/x/package.json", // never a root
		"node_modules/x/package-lock.json",
		"test/fixtures/demo/package.json", "test/fixtures/demo/yarn.lock", // skipped by default
		"legacy/bun.lockb",
	} {
		touch(t, filepath.Join(base, p))
	}
	res, err := Walk(base, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Roots) != 2 {
		t.Fatalf("roots = %+v", res.Roots)
	}
	if res.Roots[0].Dir != base || res.Roots[0].Manifests != 4 {
		t.Errorf("top root %+v", res.Roots[0])
	}
	if filepath.Base(res.Roots[1].Dir) != "edge" || res.Roots[1].Manifests != 1 {
		t.Errorf("edge root %+v", res.Roots[1])
	}
	if len(res.Warnings) != 1 {
		t.Errorf("expected one bun.lockb warning, got %v", res.Warnings)
	}

	res, _ = Walk(base, Options{IncludeFixtures: true})
	if len(res.Roots) != 3 {
		t.Errorf("with fixtures: %d roots", len(res.Roots))
	}
}

func TestUnresolved(t *testing.T) {
	base := t.TempDir()
	touch(t, filepath.Join(base, "a", "package.json"))
	res, err := Walk(base, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Roots) != 0 || len(res.Unresolved) != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestSingleLockfile(t *testing.T) {
	base := t.TempDir()
	lf := filepath.Join(base, "yarn.lock")
	touch(t, lf)
	res, err := Walk(lf, Options{})
	if err != nil || len(res.Roots) != 1 || res.Roots[0].Lockfiles[0] != lf {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestSymlinkNotFollowed(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	touch(t, filepath.Join(outside, "package-lock.json"))
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Skip("symlinks unsupported here")
	}
	res, err := Walk(base, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Roots) != 0 {
		t.Fatalf("followed a symlink out of the tree: %+v", res.Roots)
	}
}
