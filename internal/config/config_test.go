package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadRegistriesIgnoresAuth(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".npmrc", strings.Join([]string{
		"; comment",
		"registry=https://artifactory.corp.example/api/npm/npm/",
		"@corp:registry=https://npm.corp.example/",
		"//npm.corp.example/:_authToken=SECRET_TOKEN_VALUE",
		"always-auth=true",
	}, "\n"))
	write(t, dir, ".yarnrc.yml", "npmScopes:\n  bank:\n    npmRegistryServer: \"https://npm.bank.example\"\n    npmAuthToken: SECRET\n")
	r, err := ReadRegistries(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Default != "artifactory.corp.example" {
		t.Errorf("default %q", r.Default)
	}
	if r.Scopes["@corp"] != "npm.corp.example" || r.Scopes["@bank"] != "npm.bank.example" {
		t.Errorf("scopes %v", r.Scopes)
	}
	for k, v := range r.Scopes {
		if strings.Contains(k+v, "SECRET") {
			t.Fatal("a token leaked into the parsed registries")
		}
	}
}

func TestLoadStrict(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, FileName, "exclude:\n  scopes: [\"@acme\"]\nfail_on: none\n")
	c, path, err := Load(dir)
	if err != nil || path == "" || c.FailOn != "none" || c.Exclude.Scopes[0] != "@acme" {
		t.Fatalf("load: %+v %q %v", c, path, err)
	}
	write(t, dir, FileName, "exclud:\n  scopes: [x]\n")
	if _, _, err := Load(dir); err == nil {
		t.Fatal("a misspelled key must be an error, not silently ignored")
	}
	write(t, dir, FileName, "fail_on: sometimes\n")
	if _, _, err := Load(dir); err == nil {
		t.Fatal("invalid fail_on must be rejected")
	}
}

func TestHost(t *testing.T) {
	cases := map[string]string{
		"https://registry.npmjs.org/":       "registry.npmjs.org",
		"https://user:pw@npm.corp:8443/a/b": "npm.corp",
		"HTTP://Registry.Example.COM":       "registry.example.com",
		"npm.corp.example":                  "npm.corp.example",
	}
	for in, want := range cases {
		if got := Host(in); got != want {
			t.Errorf("Host(%q) = %q, want %q", in, got, want)
		}
	}
}
