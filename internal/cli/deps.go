package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Anurag-Chevendra/mantis/internal/report"
	"github.com/Anurag-Chevendra/mantis/internal/version"
)

func runDeps(args []string, env *Env) error {
	fs := newFlags("deps", "List every package version under a path: pinned by a lockfile, or the versions npm would\ninstall for a package.json that has none (registry metadata only; --offline to skip).", env)
	var cf collectFlags
	cf.register(fs)
	format := fs.String("format", "text", "output format: text, json, cyclonedx or html")
	open := fs.Bool("open", false, "write the HTML report and open it in your browser (implies --format html)")
	output := fs.String("output", "", "write to this file instead of stdout")
	quiet := fs.Bool("quiet", false, "print only the list, no summary")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return fail(ExitUsage, "deps takes at most one path")
	}
	path := "."
	if len(pos) == 1 {
		path = pos[0]
	}
	if *open {
		*format = "html"
	}
	switch *format {
	case "text", "json", "cyclonedx", "html":
	default:
		return fail(ExitUsage, "unknown --format %q (text, json, cyclonedx or html)", *format)
	}

	cf.http = env.HTTP
	if *format == "text" || *format == "html" {
		cf.stderr = env.Stderr
	}
	inv, cfg, err := collect(path, cf)
	if err != nil {
		return err
	}
	if *format == "html" {
		name := cfg.Project
		if name == "" {
			name = filepath.Base(absBase(path))
		}
		return writeHTML(env, inv, name, *output, *open)
	}

	var buf bytes.Buffer
	out := io.Writer(&buf)
	st := env.OutStyle
	if *output != "" {
		st = report.Style{}
	}
	switch *format {
	case "json":
		err = report.WriteJSON(out, inv)
	case "cyclonedx":
		name := cfg.Project
		if name == "" {
			name = filepath.Base(absBase(path))
		}
		err = report.WriteCycloneDX(out, inv, name)
	default:
		if !*quiet {
			report.Header(env.Stderr, env.ErrStyle, version.Version, "dependency collector")
			report.WriteSummary(env.Stderr, env.ErrStyle, inv)
			fmt.Fprintln(env.Stderr)
		}
		report.WriteList(out, st, inv)
	}
	if err != nil {
		return err
	}
	return emit(env, *output, buf.Bytes())
}

// emit writes to a file atomically, or to stdout.
func emit(env *Env, path string, data []byte) error {
	if path == "" {
		_, err := env.Stdout.Write(data)
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fail(ExitUsage, "%v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fail(ExitUsage, "%v", err)
	}
	fmt.Fprintf(env.Stderr, "  wrote %s\n", path)
	return nil
}
