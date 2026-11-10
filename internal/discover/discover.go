// Package discover finds lockfiles in a project tree.
//
// A root is a directory that holds at least one lockfile. A package.json
// belongs to the nearest root at or above it; one with no root above it is
// reported as unresolved, because without a lockfile the exact versions that
// would be installed are not knowable, and Mantis does not guess.
package discover

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Anurag-Chevendra/mantis/internal/lockfile"
)

// Root is one directory with lockfiles.
type Root struct {
	Dir       string   `json:"dir"`
	Lockfiles []string `json:"lockfiles"`
	Manifests int      `json:"manifests"` // package.json files grouped under this root
}

// Result of a walk.
type Result struct {
	Base       string   `json:"base"`
	Roots      []Root   `json:"roots"`
	Unresolved []string `json:"unresolved,omitempty"` // package.json with no lockfile above it
	Warnings   []string `json:"warnings,omitempty"`
	Skipped    int      `json:"skipped_dirs"`
}

// Options control the walk.
type Options struct {
	IncludeFixtures bool // also walk test fixture and example folders
	MaxDepth        int  // 0 means the default
}

// DefaultMaxDepth bounds the walk so a pathological tree cannot run forever.
const DefaultMaxDepth = 24

// never walked: installed packages, VCS metadata, caches and build output of
// other ecosystems. node_modules matters most: every package inside it has a
// package.json and none of them are the user's project.
var skipDirs = map[string]bool{
	"node_modules": true, ".git": true, ".hg": true, ".svn": true,
	".yarn": true, ".pnpm-store": true, ".npm": true, ".bun": true,
	".next": true, ".nuxt": true, ".svelte-kit": true, ".turbo": true, ".cache": true,
	"bower_components": true, "jspm_packages": true,
	".venv": true, "venv": true, "__pycache__": true, "target": true,
	".idea": true, ".vscode": true, "coverage": true,
}

// skipped unless IncludeFixtures: they hold sample projects, not dependencies
// of this one.
var fixtureDirs = map[string]bool{
	"fixtures": true, "__fixtures__": true, "testdata": true, "test-fixtures": true,
	"examples": true, "example": true,
}

// Walk scans base. It never follows symlinks and never reads anything except
// directory listings; lockfiles are parsed later by the caller.
func Walk(base string, opt Options) (*Result, error) {
	abs, err := filepath.Abs(base)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		// A single lockfile was named directly.
		if lockfile.IsLockfile(filepath.Base(abs)) {
			return &Result{Base: filepath.Dir(abs), Roots: []Root{{Dir: filepath.Dir(abs), Lockfiles: []string{abs}}}}, nil
		}
		return nil, errors.New(base + " is not a directory or a supported lockfile")
	}
	maxDepth := opt.MaxDepth
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}

	res := &Result{Base: abs}
	lockDirs := map[string][]string{}
	var manifests []string

	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				res.Warnings = append(res.Warnings, "permission denied: "+rel(abs, path))
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != abs {
				if skipDirs[name] || (!opt.IncludeFixtures && fixtureDirs[name]) {
					res.Skipped++
					return fs.SkipDir
				}
				if strings.Count(rel(abs, path), string(filepath.Separator))+1 > maxDepth {
					res.Warnings = append(res.Warnings, "max depth reached at "+rel(abs, path))
					return fs.SkipDir
				}
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		switch {
		case lockfile.IsLockfile(name):
			dir := filepath.Dir(path)
			lockDirs[dir] = append(lockDirs[dir], path)
		case name == "bun.lockb":
			res.Warnings = append(res.Warnings, rel(abs, path)+": binary bun.lockb is not supported; run `bun install --save-text-lockfile` to write bun.lock")
		case name == "package.json":
			manifests = append(manifests, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	dirs := make([]string, 0, len(lockDirs))
	for d := range lockDirs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	rootIdx := map[string]int{}
	for _, d := range dirs {
		files := lockDirs[d]
		sort.Slice(files, func(i, j int) bool { return order(files[i]) < order(files[j]) })
		rootIdx[d] = len(res.Roots)
		res.Roots = append(res.Roots, Root{Dir: d, Lockfiles: files})
	}

	for _, m := range manifests {
		if r, ok := nearestRoot(filepath.Dir(m), abs, rootIdx); ok {
			res.Roots[r].Manifests++
		} else {
			res.Unresolved = append(res.Unresolved, m)
		}
	}
	sort.Strings(res.Unresolved)
	return res, nil
}

func nearestRoot(dir, base string, idx map[string]int) (int, bool) {
	for {
		if i, ok := idx[dir]; ok {
			return i, true
		}
		if dir == base {
			return 0, false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return 0, false
		}
		dir = parent
	}
}

func order(path string) int {
	b := filepath.Base(path)
	for i, n := range lockfile.Names {
		if n == b {
			return i
		}
	}
	return len(lockfile.Names)
}

func rel(base, path string) string {
	r, err := filepath.Rel(base, path)
	if err != nil {
		return path
	}
	return r
}
