package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Style decides whether ANSI color is used.
type Style struct{ Color bool }

// DetectStyle enables color only for a terminal, and never when NO_COLOR is
// set (https://no-color.org).
func DetectStyle(f *os.File) Style {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return Style{}
	}
	info, err := f.Stat()
	if err != nil {
		return Style{}
	}
	return Style{Color: info.Mode()&os.ModeCharDevice != 0}
}

func (s Style) wrap(code, v string) string {
	if !s.Color {
		return v
	}
	return "\x1b[" + code + "m" + v + "\x1b[0m"
}

func (s Style) Bold(v string) string   { return s.wrap("1", v) }
func (s Style) Dim(v string) string    { return s.wrap("2", v) }
func (s Style) Red(v string) string    { return s.wrap("31;1", v) }
func (s Style) Green(v string) string  { return s.wrap("32", v) }
func (s Style) Yellow(v string) string { return s.wrap("33", v) }

// Header is the first line of human output.
func Header(w io.Writer, st Style, version, what string) {
	fmt.Fprintf(w, "\n  %s %s · %s\n\n", st.Bold("MANTIS"), version, what)
}

// WriteSummary prints where packages were found and how many may be checked.
func WriteSummary(w io.Writer, st Style, inv *Inventory) {
	for _, r := range inv.Roots {
		for _, lf := range r.Lockfiles {
			label := lf.Format
			if lf.Format == "package.json" {
				label = "no lockfile"
			} else if lf.Version != "" {
				label += " v" + strings.TrimPrefix(lf.Version, "v")
			}
			fmt.Fprintf(w, "  %-34s %-20s %s\n", trimTo(lf.Path, 34), st.Dim(label), plural(lf.Packages, "package"))
			for _, warn := range lf.Warnings {
				fmt.Fprintf(w, "    %s %s\n", st.Yellow("!"), warn)
			}
		}
	}
	if len(inv.Roots) > 0 {
		fmt.Fprintln(w)
	}
	s := inv.Summary
	fmt.Fprintf(w, "  %-22s %s\n", "unique versions", st.Bold(fmt.Sprint(s.Total)))
	fmt.Fprintf(w, "  %-22s %d  %s\n", "checkable", s.Send, st.Dim("(public npm; only name@version is ever sent)"))
	if s.HeldBack > 0 {
		fmt.Fprintf(w, "  %-22s %d  %s\n", "held back", s.HeldBack, st.Dim("("+heldBackBreakdown(inv)+"; never sent)"))
	}
	for _, r := range inv.Roots {
		for _, lf := range r.Lockfiles {
			if lf.Format == "package.json" {
				fmt.Fprintf(w, "  %s %s\n", st.Yellow("!"), lf.Path+": no lockfile, so versions are what npm would pick today ("+lf.Version+"). Commit a lockfile to make installs repeatable.")
			}
		}
	}
	for _, u := range inv.Unresolved {
		fmt.Fprintf(w, "  %s %s has no lockfile; versions are not pinned, so it was not read\n", st.Yellow("!"), u)
	}
	for _, warn := range inv.Warnings {
		fmt.Fprintf(w, "  %s %s\n", st.Yellow("!"), warn)
	}
}

func heldBackBreakdown(inv *Inventory) string {
	counts := map[string]int{}
	for _, p := range inv.Packages {
		if p.Send {
			continue
		}
		k := string(p.Source)
		if p.Source == "registry" {
			k = "private"
		}
		counts[k]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, counts[k]))
	}
	return strings.Join(parts, " · ")
}

// WriteList prints one package per line: name@version, source, and the
// reason a held back package stays local.
func WriteList(w io.Writer, st Style, inv *Inventory) {
	width := 0
	for _, p := range inv.Packages {
		if n := len(p.Key()); n > width {
			width = n
		}
	}
	if width > 60 {
		width = 60
	}
	for _, p := range inv.Packages {
		mark := st.Green("●")
		note := ""
		if !p.Send {
			mark = st.Dim("○")
			note = st.Dim(p.Reason)
		}
		dev := ""
		if p.Dev != nil && *p.Dev {
			dev = st.Dim(" dev")
		}
		fmt.Fprintf(w, "%s %-*s %-9s%s %s\n", mark, width, p.Key(), p.Source, dev, note)
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func trimTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n+1:]
}
