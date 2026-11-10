// Package version holds build metadata, set at release time with -ldflags.
package version

import "runtime/debug"

var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// String is "0.1.0 (abc1234, 2026-11-10)" or a best effort for go install.
func String() string {
	v, c, d := Version, Commit, Date
	if v == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				v = bi.Main.Version
			}
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if c == "" {
						c = s.Value
					}
				case "vcs.time":
					if d == "" {
						d = s.Value
					}
				}
			}
		}
	}
	if len(c) > 7 {
		c = c[:7]
	}
	out := v
	if c != "" || d != "" {
		out += " (" + c
		if c != "" && d != "" {
			out += ", "
		}
		out += d + ")"
	}
	return out
}

// UserAgent identifies Mantis to the API.
func UserAgent() string {
	return "mantis/" + Version + " (+https://github.com/Anurag-Chevendra/mantis)"
}
