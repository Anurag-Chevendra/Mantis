// Package cli implements the mantis command line.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Anurag-Chevendra/mantis/internal/auth"
	"github.com/Anurag-Chevendra/mantis/internal/report"
	"github.com/Anurag-Chevendra/mantis/internal/version"
)

// Exit codes. Documented in README; stable across releases.
const (
	ExitOK       = 0 // completed, nothing needs review
	ExitReview   = 1 // completed, at least one package needs review
	ExitUsage    = 2 // bad flags, bad config, nothing to read
	ExitAuth     = 3 // not logged in, key invalid, expired or lacking scope
	ExitNetwork  = 4 // API or console unreachable, or answered with an error
	ExitInternal = 5 // anything else
)

// Default endpoints. Overridable for self hosted deployments.
const (
	DefaultAPI     = "https://api.snappyfeet.org"
	DefaultConsole = "https://console.snappyfeet.org"
)

// Env is everything the commands touch outside the process, so tests can
// run them end to end without a terminal, a keyring or the network.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	// Interactive is true when stdin and stderr are a terminal.
	Interactive bool
	// Style for stdout and stderr.
	OutStyle, ErrStyle report.Style
	// Store overrides credential storage (tests). nil means the OS keyring.
	Store auth.Store
	// HTTP overrides the HTTP client (tests).
	HTTP *http.Client
	// OpenBrowser opens a URL; nil means the platform default.
	OpenBrowser func(string) error
}

// DefaultEnv is the real process environment.
func DefaultEnv() *Env {
	interactive := isTerminal(os.Stdin) && isTerminal(os.Stderr)
	return &Env{
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Getenv:      os.Getenv,
		Interactive: interactive,
		OutStyle:    report.DetectStyle(os.Stdout),
		ErrStyle:    report.DetectStyle(os.Stderr),
	}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// exitError carries an exit code and a message for the user.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func fail(code int, format string, a ...any) error {
	return &exitError{code: code, msg: fmt.Sprintf(format, a...)}
}

const usage = `Mantis lists every npm package your project installs and checks each one
against Cohen's sandbox verdicts, before you run npm install. It works from a
lockfile or from package.json alone. It never installs or runs anything, and
sends nothing but package names and versions.

Usage:
  mantis <command> [flags] [path]

Commands:
  deps      List every package the project installs. Nothing is sent to Cohen.
  scan      Check those packages against Cohen.
              --analyze   queue a sandbox analysis for versions with no verdict
              --open      show the result in your browser
              --dry-run   print exactly what would be sent, then stop
  login     Sign in through the Cohen console in your browser.
            Use "login --with-token" to paste a key from the console instead.
  logout    Revoke this machine's key and forget it.
  whoami    Show the account, plan and scopes of the current key.
  version   Print the version.

Examples:
  mantis deps                      list packages in this folder
  mantis deps --open               same list, as a report in your browser
  mantis scan                      check them; exit code 1 if any need review
  mantis scan --analyze            also queue analyses for unknown versions
  mantis scan --dry-run            see the request body without sending it
  mantis scan --analyze --yes      queue without asking (CI)

Run "mantis <command> -h" for every flag of a command.

Environment:
  MANTIS_TOKEN        API key to use instead of the stored login (CI)
  MANTIS_API_URL      API base URL      (default https://api.snappyfeet.org)
  MANTIS_CONSOLE_URL  Console base URL  (default https://console.snappyfeet.org)
  NO_COLOR            Disable color output
  HTTPS_PROXY         Proxy for all requests; system CA store is used for TLS

Exit codes:
  0 nothing needs review   1 something needs review   2 usage or config error
  3 authentication error   4 network or server error  5 internal error
`

// Run executes one command line and returns the process exit code.
func Run(args []string, env *Env) int {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, usage)
		return ExitUsage
	}
	var err error
	switch cmd, rest := args[0], args[1:]; cmd {
	case "deps", "list":
		err = runDeps(rest, env)
	case "scan", "check":
		err = runScan(rest, env)
	case "login":
		err = runLogin(rest, env)
	case "logout":
		err = runLogout(rest, env)
	case "whoami", "status":
		err = runWhoami(rest, env)
	case "version", "--version", "-v":
		fmt.Fprintln(env.Stdout, "mantis", version.String())
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usage)
	default:
		fmt.Fprintf(env.Stderr, "mantis: unknown command %q\n\n%s", cmd, usage)
		return ExitUsage
	}
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.msg != "" {
			fmt.Fprintln(env.Stderr, "mantis:", ee.msg)
		}
		return ee.code
	}
	fmt.Fprintln(env.Stderr, "mantis:", err)
	return ExitInternal
}

// parseInterleaved lets flags appear before or after the path argument,
// which is what people type ("mantis scan . --json").
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func newFlags(name, summary string, env *Env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(env.Stderr, "%s\n\nUsage:\n  mantis %s [flags]\n\nFlags:\n", summary, name)
		fs.PrintDefaults()
	}
	return fs
}

func (e *Env) env(key, def string) string {
	if v := strings.TrimSpace(e.Getenv(key)); v != "" {
		return v
	}
	return def
}

func (e *Env) store() auth.Store {
	if e.Store != nil {
		return e.Store
	}
	return auth.Keyring{}
}
