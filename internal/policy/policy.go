// Package policy decides which packages may leave the machine.
//
// The rule is conservative by design: a package name is sent to the verdict
// API only when it is known to come from public npm. Local code, git
// dependencies, arbitrary tarballs, private scopes and anything resolved from
// a private registry stay on the machine, and each one is reported with the
// reason it was held back.
package policy

import (
	"path"
	"sort"
	"strings"

	"github.com/Anurag-Chevendra/mantis/internal/config"
	"github.com/Anurag-Chevendra/mantis/internal/lockfile"
)

// DefaultPublicRegistries are the hosts that serve public npm.
var DefaultPublicRegistries = []string{"registry.npmjs.org", "registry.yarnpkg.com"}

// Decision for one package.
type Decision struct {
	lockfile.Package
	Send   bool   `json:"send"`
	Reason string `json:"reason"`
}

// Policy is built once per scan root.
type Policy struct {
	public        map[string]bool
	excludeScopes map[string]string // scope -> why
	excludeGlobs  []string
	allowCustom   bool
	defaultHost   string // project's default registry host, "" when public or unset
}

// New combines .mantis.yml with the project's own registry settings.
func New(cfg *config.Config, regs *config.Registries) *Policy {
	p := &Policy{
		public:        map[string]bool{},
		excludeScopes: map[string]string{},
	}
	for _, h := range DefaultPublicRegistries {
		p.public[h] = true
	}
	if cfg != nil {
		for _, h := range cfg.PublicRegistries {
			p.public[config.Host(h)] = true
		}
		for _, s := range cfg.Exclude.Scopes {
			s = strings.ToLower(strings.TrimSpace(s))
			if s != "" && !strings.HasPrefix(s, "@") {
				s = "@" + s
			}
			p.excludeScopes[s] = "excluded scope " + s + " (" + config.FileName + ")"
		}
		p.excludeGlobs = cfg.Exclude.Packages
		p.allowCustom = cfg.AllowCustomRegistry
	}
	if regs != nil {
		for scope, host := range regs.Scopes {
			if !p.public[host] {
				if _, ok := p.excludeScopes[scope]; !ok {
					p.excludeScopes[scope] = "scope " + scope + " uses private registry " + host
				}
			}
		}
		if regs.Default != "" && !p.public[regs.Default] {
			p.defaultHost = regs.Default
		}
	}
	return p
}

// AllowCustomRegistry overrides the config file (command line flag).
func (p *Policy) AllowCustomRegistry(v bool) { p.allowCustom = p.allowCustom || v }

// Decide classifies one package.
func (p *Policy) Decide(pkg lockfile.Package) Decision {
	d := Decision{Package: pkg}
	switch pkg.Source {
	case lockfile.SourceLocal:
		d.Reason = "local code (file:, link: or workspace)"
		return d
	case lockfile.SourceGit:
		d.Reason = "git dependency"
		return d
	case lockfile.SourceTarball:
		d.Reason = "remote tarball outside a registry"
		return d
	case lockfile.SourceUnresolved:
		d.Reason = "not resolved: " + pkg.Note
		return d
	}
	name := strings.ToLower(pkg.Name)
	if strings.HasPrefix(name, "@") {
		scope, _, _ := strings.Cut(name, "/")
		if why, ok := p.excludeScopes[scope]; ok {
			d.Reason = why
			return d
		}
	}
	for _, g := range p.excludeGlobs {
		if ok, _ := path.Match(strings.ToLower(g), name); ok {
			d.Reason = "excluded by pattern " + g + " (" + config.FileName + ")"
			return d
		}
	}
	host := pkg.Registry
	if host == "" {
		host = p.defaultHost // lockfile does not say: the project default applies
	}
	if host != "" && !p.public[host] {
		if !p.allowCustom {
			d.Reason = "resolved from non public registry " + host + " (pass --allow-custom-registry if it only mirrors npm)"
			return d
		}
		d.Send = true
		d.Reason = "custom registry " + host + " allowed"
		return d
	}
	if !validName(pkg.Name) || pkg.Version == "" || strings.ContainsAny(pkg.Version, " /:") {
		d.Reason = "not a valid npm name and version"
		return d
	}
	d.Send = true
	d.Reason = "public npm"
	return d
}

// Apply decides every package and returns them sorted by name.
func (p *Policy) Apply(pkgs []lockfile.Package) []Decision {
	out := make([]Decision, 0, len(pkgs))
	for _, pkg := range pkgs {
		out = append(out, p.Decide(pkg))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// validName is npm's rule in short: lower case URL safe characters, at most
// 214 long, an optional single @scope/ prefix.
func validName(n string) bool {
	if n == "" || len(n) > 214 {
		return false
	}
	s := n
	if strings.HasPrefix(s, "@") {
		scope, rest, ok := strings.Cut(s[1:], "/")
		if !ok || scope == "" || rest == "" || strings.Contains(rest, "/") {
			return false
		}
		s = scope + rest
	} else if strings.Contains(s, "/") {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~', c == '!', c == '*', c == '\'', c == '(', c == ')':
		case c >= 'A' && c <= 'Z':
			// legacy packages with capitals exist on npm
		default:
			return false
		}
	}
	return true
}
