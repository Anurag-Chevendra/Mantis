package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/Anurag-Chevendra/mantis/internal/api"
	"github.com/Anurag-Chevendra/mantis/internal/config"
	"github.com/Anurag-Chevendra/mantis/internal/discover"
	"github.com/Anurag-Chevendra/mantis/internal/lockfile"
	"github.com/Anurag-Chevendra/mantis/internal/policy"
	"github.com/Anurag-Chevendra/mantis/internal/report"
	"github.com/Anurag-Chevendra/mantis/internal/resolve"
	"github.com/Anurag-Chevendra/mantis/internal/version"
)

// collectFlags are shared by deps and scan.
type collectFlags struct {
	includeFixtures     bool
	allowCustomRegistry bool
	maxDepth            int
	offline             bool
	prod                bool
	registry            string
	maxPackages         int
	stderr              io.Writer // progress for resolution; nil for none
	http                *http.Client
}

func (c *collectFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&c.includeFixtures, "include-fixtures", false, "also read lockfiles under test fixture and example folders")
	fs.BoolVar(&c.allowCustomRegistry, "allow-custom-registry", false, "allow sending packages resolved from a non public registry (a mirror of npm)")
	fs.IntVar(&c.maxDepth, "max-depth", discover.DefaultMaxDepth, "maximum folder depth to walk")
	fs.BoolVar(&c.offline, "offline", false, "never contact a registry; a package.json without a lockfile is then skipped")
	fs.BoolVar(&c.prod, "prod", false, "when resolving a package.json, leave out devDependencies")
	fs.StringVar(&c.registry, "registry", resolve.DefaultRegistry, "registry used to resolve a package.json that has no lockfile (metadata only, no auth)")
	fs.IntVar(&c.maxPackages, "max-packages", 0, "when resolving a package.json, stop past this many packages (default 20000)")
}

// collect walks the tree, parses every lockfile and applies the policy.
// Lockfiles are read as files only. A package.json with no lockfile is
// resolved from registry metadata unless cf.offline is set.
func collect(path string, cf collectFlags) (*report.Inventory, *config.Config, error) {
	walk, err := discover.Walk(path, discover.Options{IncludeFixtures: cf.includeFixtures, MaxDepth: cf.maxDepth})
	if err != nil {
		return nil, nil, fail(ExitUsage, "%v", err)
	}
	cfg, _, err := config.Load(walk.Base)
	if err != nil {
		return nil, nil, fail(ExitUsage, "%v", err)
	}
	if len(walk.Roots) == 0 && (len(walk.Unresolved) == 0 || cf.offline) {
		msg := "no lockfile found under " + walk.Base + " (looked for " + joinNames() + ")"
		if len(walk.Unresolved) > 0 {
			msg += "; found package.json without one, which needs registry lookups (drop --offline)"
		}
		return nil, nil, fail(ExitUsage, "%s", msg)
	}

	b := report.NewBuilder(walk.Base, version.Version)
	b.Warn(walk.Warnings...)
	if cf.offline {
		b.Unresolved(walk.Unresolved)
	} else if len(walk.Unresolved) > 0 {
		if err := resolveManifests(walk, cfg, cf, b); err != nil {
			return nil, nil, err
		}
	}
	for _, root := range walk.Roots {
		// Registry settings come from the root's own .npmrc/.yarnrc.yml,
		// falling back to the scan base for a monorepo with one config.
		regs, err := config.ReadRegistries(root.Dir)
		if err != nil {
			return nil, nil, fail(ExitUsage, "%v", err)
		}
		if len(regs.Sources) == 0 && root.Dir != walk.Base {
			if regs, err = config.ReadRegistries(walk.Base); err != nil {
				return nil, nil, fail(ExitUsage, "%v", err)
			}
		}
		pol := policy.New(cfg, regs)
		pol.AllowCustomRegistry(cf.allowCustomRegistry)

		var results []*lockfile.Result
		for _, lf := range root.Lockfiles {
			res, err := lockfile.ParseFile(lf)
			if err != nil {
				b.Warn("could not read " + b.Rel(lf) + ": " + err.Error())
				continue
			}
			results = append(results, res)
		}
		b.AddRoot(root.Dir, root.Manifests, results, pol.Decide)
	}
	return b.Done(), cfg, nil
}

func joinNames() string {
	s := ""
	for i, n := range lockfile.Names {
		if i > 0 {
			s += ", "
		}
		s += n
	}
	return s
}

func absBase(path string) string {
	a, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return a
}

// resolveManifests handles package.json files that have no lockfile: it
// predicts what npm would install from registry metadata alone. Nothing is
// installed, downloaded or executed, and private names are never looked up.
func resolveManifests(walk *discover.Result, cfg *config.Config, cf collectFlags, b *report.Builder) error {
	hc := cf.http
	if hc == nil {
		hc = api.NewHTTPClient(60 * time.Second)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	for _, m := range walk.Unresolved {
		dir := filepath.Dir(m)
		regs, err := config.ReadRegistries(dir)
		if err != nil {
			return fail(ExitUsage, "%v", err)
		}
		if len(regs.Sources) == 0 && dir != walk.Base {
			if regs, err = config.ReadRegistries(walk.Base); err != nil {
				return fail(ExitUsage, "%v", err)
			}
		}
		pol := policy.New(cfg, regs)
		pol.AllowCustomRegistry(cf.allowCustomRegistry)
		res, err := resolve.New(resolve.Options{
			Registry:    cf.registry,
			HTTP:        hc,
			UserAgent:   version.UserAgent(),
			Prod:        cf.prod,
			MaxPackages: cf.maxPackages,
			Hold: func(name string) string {
				d := pol.Decide(lockfile.Package{Name: name, Version: "0.0.0", Source: lockfile.SourceRegistry})
				if d.Send {
					return ""
				}
				return d.Reason + "; not looked up"
			},
		})
		if err != nil {
			return fail(ExitUsage, "%v", err)
		}
		if cf.stderr != nil {
			fmt.Fprintf(cf.stderr, "  %s has no lockfile: resolving from %s (metadata only; nothing is installed or run)\n", b.Rel(m), res.Host())
		}
		r, err := res.ResolveManifest(ctx, m)
		if err != nil {
			if ctx.Err() != nil {
				return fail(ExitNetwork, "resolving %s: %v", b.Rel(m), ctx.Err())
			}
			if errors.Is(err, resolve.ErrTooMany) {
				return fail(ExitUsage, "resolving %s: %v", b.Rel(m), err)
			}
			b.Warn("could not resolve " + b.Rel(m) + ": " + err.Error())
			continue
		}
		b.AddRoot(dir, 1, []*lockfile.Result{r}, pol.Decide)
	}
	return nil
}
