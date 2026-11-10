// Package config reads the optional .mantis.yml at the root of a scan and the
// registry settings a project already declares for its package manager.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-yaml"
)

// FileName is the per project config file.
const FileName = ".mantis.yml"

// Config is the project policy. Every field is optional.
type Config struct {
	Exclude struct {
		// Scopes never sent, e.g. "@acme". Matched case insensitively.
		Scopes []string `yaml:"scopes"`
		// Package name globs never sent, e.g. "acme-*". path.Match syntax.
		Packages []string `yaml:"packages"`
	} `yaml:"exclude"`
	// Registry hosts treated as public npm, in addition to the defaults.
	PublicRegistries []string `yaml:"public_registries"`
	// Send packages resolved from a non public registry host. Off by
	// default; turn on for a mirror that only proxies public npm.
	AllowCustomRegistry bool `yaml:"allow_custom_registry"`
	// "review" (default) exits 1 when any package needs review; "none"
	// always exits 0 on a completed scan.
	FailOn string `yaml:"fail_on"`
	// Project name shown in the console's scan history.
	Project string `yaml:"project"`
}

// Load reads dir/.mantis.yml. A missing file is not an error.
func Load(dir string) (*Config, string, error) {
	c := &Config{}
	path := filepath.Join(dir, FileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	if err := yaml.UnmarshalWithOptions(data, c, yaml.Strict()); err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	switch c.FailOn {
	case "", "review", "none":
	default:
		return nil, "", fmt.Errorf("%s: fail_on must be \"review\" or \"none\", not %q", path, c.FailOn)
	}
	return c, path, nil
}

// Registries is what a project's own package manager config says about where
// packages come from. Only registry URLs are read; auth lines are skipped
// without being parsed, so tokens in .npmrc are never held in memory beyond
// the line scanner.
type Registries struct {
	Default string            // host of the default registry, "" if unset
	Scopes  map[string]string // "@scope" -> registry host
	Sources []string          // files that contributed
}

// ReadRegistries reads dir/.npmrc and dir/.yarnrc.yml. It does not read the
// user's home directory: what Mantis sends must be decided by the project,
// not by the machine it happens to run on.
func ReadRegistries(dir string) (*Registries, error) {
	r := &Registries{Scopes: map[string]string{}}
	if err := readNpmrc(filepath.Join(dir, ".npmrc"), r); err != nil {
		return nil, err
	}
	if err := readYarnrc(filepath.Join(dir, ".yarnrc.yml"), r); err != nil {
		return nil, err
	}
	return r, nil
}

func readNpmrc(path string, r *Registries) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	used := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(line, "//") {
			continue // comments and every per-host auth line
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		switch {
		case k == "registry":
			r.Default = Host(v)
			used = true
		case strings.HasPrefix(k, "@") && strings.HasSuffix(k, ":registry"):
			r.Scopes[strings.ToLower(strings.TrimSuffix(k, ":registry"))] = Host(v)
			used = true
		}
	}
	if used {
		r.Sources = append(r.Sources, path)
	}
	return sc.Err()
}

func readYarnrc(path string, r *Registries) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var y struct {
		NpmRegistryServer string `yaml:"npmRegistryServer"`
		NpmScopes         map[string]struct {
			NpmRegistryServer string `yaml:"npmRegistryServer"`
		} `yaml:"npmScopes"`
	}
	if err := yaml.Unmarshal(data, &y); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	used := false
	if y.NpmRegistryServer != "" {
		r.Default = Host(y.NpmRegistryServer)
		used = true
	}
	for s, v := range y.NpmScopes {
		if v.NpmRegistryServer != "" {
			r.Scopes["@"+strings.ToLower(strings.TrimPrefix(s, "@"))] = Host(v.NpmRegistryServer)
			used = true
		}
	}
	if used {
		r.Sources = append(r.Sources, path)
	}
	return nil
}

// Host extracts a lower case host name from a registry URL.
func Host(u string) string {
	u = strings.TrimSpace(u)
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.LastIndex(u, "@"); i >= 0 {
		u = u[i+1:] // user:pass@host
	}
	if i := strings.LastIndex(u, ":"); i >= 0 && !strings.Contains(u[i:], "]") {
		u = u[:i]
	}
	return strings.ToLower(u)
}
