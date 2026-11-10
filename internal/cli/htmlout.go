package cli

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Anurag-Chevendra/mantis/internal/report"
)

// htmlReport is one HTML report destination. With --output it is that file;
// with --open and no --output it is a new private temp file; otherwise it is
// stdout. A file can be rewritten while a scan runs, so the browser can show
// it from the first second and fill in as results arrive.
type htmlReport struct {
	env   *Env
	title string
	path  string // "" means stdout
	open  bool
	shown bool
	wrote bool
}

func newHTMLReport(env *Env, title, output string, open bool) (*htmlReport, error) {
	h := &htmlReport{env: env, title: title, path: output, open: open}
	if output == "" && open {
		f, err := os.CreateTemp("", "mantis_report_*.html")
		if err != nil {
			return nil, fail(ExitUsage, "%v", err)
		}
		h.path = f.Name()
		f.Close()
	}
	return h, nil
}

// live reports whether the report can be shown before the scan finishes.
func (h *htmlReport) live() bool { return h.path != "" && h.open }

// write renders the report. live is nil for the final version.
func (h *htmlReport) write(inv *report.Inventory, live *report.Live) error {
	var buf bytes.Buffer
	if err := report.WriteHTML(&buf, inv, report.HTMLOptions{Title: h.title, FeedURL: FeedURL, Live: live}); err != nil {
		return err
	}
	if h.path == "" {
		if live != nil {
			return nil
		}
		_, err := h.env.Stdout.Write(buf.Bytes())
		return err
	}
	// Write beside, then rename, so the browser never reads half a file.
	// If the rename is refused (Windows can hold a file the browser is
	// reading), fall back to writing in place.
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return fail(ExitUsage, "%v", err)
	}
	if err := os.Rename(tmp, h.path); err != nil {
		os.Remove(tmp)
		if err := os.WriteFile(h.path, buf.Bytes(), 0o600); err != nil {
			return fail(ExitUsage, "%v", err)
		}
	}
	if live == nil && !h.wrote {
		fmt.Fprintf(h.env.Stderr, "  wrote %s\n", h.path)
	}
	if live == nil {
		h.wrote = true
	}
	return nil
}

// show opens the report in the browser, once.
func (h *htmlReport) show() {
	if !h.open || h.shown || h.path == "" {
		return
	}
	h.shown = true
	if err := openFile(h.env, h.path); err != nil {
		fmt.Fprintf(h.env.Stderr, "  could not open a browser (%v); open %s yourself\n", err, h.path)
	}
}

// writeHTML writes a finished report and opens it when asked.
func writeHTML(env *Env, inv *report.Inventory, title, output string, open bool) error {
	h, err := newHTMLReport(env, title, output, open)
	if err != nil {
		return err
	}
	if err := h.write(inv, nil); err != nil {
		return err
	}
	h.show()
	return nil
}

// openFile shows a local report in the default browser. The path is passed
// as a single argument, never through a shell.
func openFile(env *Env, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // C:/x becomes /C:/x
	}
	u := (&url.URL{Scheme: "file", Path: p}).String()
	if env.OpenBrowser != nil {
		return env.OpenBrowser(u)
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", abs)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", abs)
	default:
		cmd = exec.Command("xdg-open", abs)
	}
	return cmd.Start()
}
