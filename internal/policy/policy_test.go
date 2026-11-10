package policy

import (
	"strings"
	"testing"

	"github.com/Anurag-Chevendra/mantis/internal/config"
	"github.com/Anurag-Chevendra/mantis/internal/lockfile"
)

func pkg(name, ver string, src lockfile.Source, host string) lockfile.Package {
	return lockfile.Package{Name: name, Version: ver, Source: src, Registry: host}
}

func TestDecide(t *testing.T) {
	cfg := &config.Config{}
	cfg.Exclude.Scopes = []string{"acme"}
	cfg.Exclude.Packages = []string{"internal-*"}
	regs := &config.Registries{Scopes: map[string]string{"@bank": "npm.bank.example"}}
	p := New(cfg, regs)

	cases := []struct {
		pkg    lockfile.Package
		send   bool
		reason string
	}{
		{pkg("lodash", "4.17.21", lockfile.SourceRegistry, "registry.npmjs.org"), true, "public npm"},
		{pkg("lodash", "4.17.21", lockfile.SourceRegistry, ""), true, "public npm"},
		{pkg("@types/node", "20.0.0", lockfile.SourceRegistry, "registry.yarnpkg.com"), true, "public npm"},
		{pkg("@acme/ui", "1.0.0", lockfile.SourceRegistry, ""), false, "excluded scope @acme"},
		{pkg("@ACME/ui", "1.0.0", lockfile.SourceRegistry, ""), false, "excluded scope @acme"},
		{pkg("@bank/core", "1.0.0", lockfile.SourceRegistry, ""), false, "private registry npm.bank.example"},
		{pkg("internal-auth", "1.0.0", lockfile.SourceRegistry, ""), false, "excluded by pattern"},
		{pkg("left-pad", "1.3.0", lockfile.SourceRegistry, "artifactory.corp"), false, "non public registry artifactory.corp"},
		{pkg("x", "1.0.0", lockfile.SourceLocal, ""), false, "local code"},
		{pkg("x", "1.0.0", lockfile.SourceGit, ""), false, "git"},
		{pkg("x", "1.0.0", lockfile.SourceTarball, ""), false, "tarball"},
		{pkg("bad name", "1.0.0", lockfile.SourceRegistry, ""), false, "not a valid"},
		{pkg("x", "https://evil", lockfile.SourceRegistry, ""), false, "not a valid"},
	}
	for _, c := range cases {
		d := p.Decide(c.pkg)
		if d.Send != c.send || !strings.Contains(d.Reason, c.reason) {
			t.Errorf("%s@%s (%s %s): send=%v reason=%q; want send=%v reason~%q",
				c.pkg.Name, c.pkg.Version, c.pkg.Source, c.pkg.Registry, d.Send, d.Reason, c.send, c.reason)
		}
	}
}

func TestCustomRegistryOptIn(t *testing.T) {
	p := New(&config.Config{}, &config.Registries{Default: "artifactory.corp", Scopes: map[string]string{}})
	pk := pkg("react", "18.2.0", lockfile.SourceRegistry, "")
	if p.Decide(pk).Send {
		t.Fatal("a project whose default registry is private must not send by default")
	}
	p.AllowCustomRegistry(true)
	if !p.Decide(pk).Send {
		t.Fatal("--allow-custom-registry should allow it")
	}
	// A private scope stays private even when custom registries are allowed.
	p2 := New(&config.Config{AllowCustomRegistry: true}, &config.Registries{Scopes: map[string]string{"@corp": "npm.corp"}})
	if p2.Decide(pkg("@corp/x", "1.0.0", lockfile.SourceRegistry, "")).Send {
		t.Fatal("private scope must never be sent")
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"a", "lodash", "@types/node", "left-pad", "JSONStream", "a.b_c~d"} {
		if !validName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range []string{"", "@scope", "@/x", "a/b", "@a/b/c", "has space", strings.Repeat("a", 215), "x;rm"} {
		if validName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}
