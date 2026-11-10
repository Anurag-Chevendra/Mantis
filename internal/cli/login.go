package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/Anurag-Chevendra/mantis/internal/api"
	"github.com/Anurag-Chevendra/mantis/internal/auth"
	"github.com/Anurag-Chevendra/mantis/internal/version"
)

// apiClient builds a client for base using, in order: MANTIS_TOKEN, the
// stored login for that host (keyring), then the opt-in credentials file.
func apiClient(env *Env, base string) (*api.Client, string, error) {
	u, err := api.ValidateBaseURL(base)
	if err != nil {
		return nil, "", fail(ExitUsage, "%v", err)
	}
	token, source := env.Getenv("MANTIS_TOKEN"), "MANTIS_TOKEN"
	if strings.TrimSpace(token) == "" {
		cred, src, err := loadCredential(env, u.Host)
		if err != nil {
			return nil, "", err
		}
		token, source = cred.Token, src
	}
	token = strings.TrimSpace(token)
	opts := []api.Option{}
	if env.HTTP != nil {
		opts = append(opts, api.WithHTTPClient(env.HTTP))
	}
	c, err := api.New(u.String(), token, version.UserAgent(), opts...)
	if err != nil {
		return nil, "", fail(ExitUsage, "%v", err)
	}
	return c, source, nil
}

func loadCredential(env *Env, host string) (*auth.Credential, string, error) {
	st := env.store()
	cred, err := st.Get(host)
	if err == nil {
		return cred, st.Name(), nil
	}
	if env.Store == nil {
		// Fall back to the opt-in file, only if the user created one.
		if p, perr := auth.DefaultFilePath(); perr == nil {
			if _, serr := os.Stat(p); serr == nil {
				f := auth.File{Path: p}
				if c, ferr := f.Get(host); ferr == nil {
					return c, f.Name(), nil
				} else if !errors.Is(ferr, auth.ErrNotFound) {
					return nil, "", fail(ExitAuth, "%v", ferr)
				}
			}
		}
	}
	if errors.Is(err, auth.ErrNotFound) {
		return nil, "", fail(ExitAuth, "not logged in to %s. Run `mantis login`, or set MANTIS_TOKEN in CI.", host)
	}
	return nil, "", fail(ExitAuth, "could not read the stored login from %s: %v. Set MANTIS_TOKEN, or run `mantis login --insecure-storage`.", st.Name(), err)
}

func runLogin(args []string, env *Env) error {
	fs := newFlags("login", "Sign in through the Cohen console in your browser (OAuth 2.0 device flow).\nThe resulting key is stored in your operating system's credential store.", env)
	noBrowser := fs.Bool("no-browser", false, "do not offer to open a browser; print the link and code only")
	deviceName := fs.String("device-name", "", "name this machine on your console's Keys page (default: hostname)")
	insecure := fs.Bool("insecure-storage", false, "store the key in a file readable only by you, when no keyring is available")
	withToken := fs.Bool("with-token", false, "read an existing API key from stdin instead of using the browser")
	apiURL := fs.String("api", "", "API base URL")
	consoleURL := fs.String("console", "", "console base URL")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return fail(ExitUsage, "login takes no arguments")
	}
	apiBase := firstNonEmpty(*apiURL, env.env("MANTIS_API_URL", DefaultAPI))
	consoleBase := firstNonEmpty(*consoleURL, env.env("MANTIS_CONSOLE_URL", DefaultConsole))
	apiU, err := api.ValidateBaseURL(apiBase)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	consoleU, err := api.ValidateBaseURL(consoleBase)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	store := env.store()
	if *insecure && env.Store == nil {
		p, err := auth.DefaultFilePath()
		if err != nil {
			return fail(ExitInternal, "%v", err)
		}
		store = auth.File{Path: p}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	st := env.ErrStyle
	w := env.Stderr

	var token, scope, device string
	if *withToken {
		b, err := io.ReadAll(io.LimitReader(env.Stdin, 4096))
		if err != nil {
			return fail(ExitUsage, "%v", err)
		}
		token = strings.TrimSpace(string(b))
		if token == "" {
			return fail(ExitUsage, "no key on stdin. Example: mantis login --with-token < key.txt")
		}
	} else {
		device = *deviceName
		if device == "" {
			device, _ = os.Hostname()
		}
		device = cleanDeviceName(device)
		flow := &auth.Flow{Console: consoleU, HTTP: httpClient(env), UserAgent: version.UserAgent(), DeviceName: "Mantis on " + device}
		dc, err := flow.Start(ctx)
		if err != nil {
			return fail(ExitNetwork, "%v", err)
		}
		fmt.Fprintf(w, "\n  %s\n\n", st.Bold("Sign in to Cohen"))
		// The link carries the code so the page is prefilled; the console
		// still requires the user to confirm the code and click Approve.
		link := firstNonEmpty(dc.VerificationURIComplete, dc.VerificationURI)
		fmt.Fprintf(w, "  1. Open    %s\n", st.Bold(link))
		fmt.Fprintf(w, "  2. Sign in, check that the page shows this code, then approve:\n\n")
		fmt.Fprintf(w, "             %s\n\n", st.Bold(spaced(dc.UserCode)))
		fmt.Fprintf(w, "  %s\n", st.Dim(fmt.Sprintf("This machine will appear as \"Mantis on %s\" on your Keys page.", device)))
		fmt.Fprintf(w, "  %s\n\n", st.Dim(fmt.Sprintf("The code expires in %d minutes. Mantis never sees your password.", max(1, dc.ExpiresIn/60))))

		if !*noBrowser && env.Interactive {
			open := dc.VerificationURIComplete
			if open == "" {
				open = dc.VerificationURI
			}
			fmt.Fprintf(w, "  Press Enter to open it in your browser, or open the link yourself. ")
			go func() {
				r := bufio.NewReader(env.Stdin)
				if _, err := r.ReadString('\n'); err == nil {
					if err := openBrowser(env, open); err != nil {
						fmt.Fprintf(w, "\n  could not open a browser (%v); open the link above yourself\n", err)
					}
				}
			}()
		}
		fmt.Fprintf(w, "\n  waiting for approval… %s\n", st.Dim("(Ctrl+C to cancel)"))
		tok, err := flow.Wait(ctx, dc)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return fail(ExitAuth, "login cancelled")
			}
			return fail(ExitAuth, "%v", err)
		}
		token, scope = tok.AccessToken, tok.Scope
	}

	// Prove the key works before keeping it.
	opts := []api.Option{}
	if env.HTTP != nil {
		opts = append(opts, api.WithHTTPClient(env.HTTP))
	}
	client, err := api.New(apiU.String(), token, version.UserAgent(), opts...)
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	ks, err := client.Key(ctx)
	if err != nil {
		return apiFail(err)
	}
	previous, _ := store.Get(apiU.Host)
	cred := &auth.Credential{Host: apiU.Host, Token: token, Scope: firstNonEmpty(scope, strings.Join(ks.Key.Scopes, " ")), Device: device, CreatedAt: time.Now().UTC()}
	if err := store.Set(cred); err != nil {
		// Never leave an orphaned key on the account when it cannot be kept.
		if !*withToken {
			flow := &auth.Flow{Console: consoleU, HTTP: httpClient(env), UserAgent: version.UserAgent()}
			_ = flow.Revoke(context.Background(), token)
		}
		return fail(ExitAuth, "could not save the key to %s: %v\n  On a machine without a keyring, use MANTIS_TOKEN, or run `mantis login --insecure-storage` to keep it in a file only you can read.", store.Name(), err)
	}
	// Logging in again replaces this machine's key: revoke the old one so
	// the account does not collect forgotten live keys.
	if previous != nil && previous.Token != "" && previous.Token != token {
		flow := &auth.Flow{Console: consoleU, HTTP: httpClient(env), UserAgent: version.UserAgent()}
		if err := flow.Revoke(ctx, previous.Token); err != nil {
			fmt.Fprintf(w, "  %s could not revoke this machine's previous key (%v); revoke it on your Keys page\n", st.Yellow("!"), err)
		}
	}
	fmt.Fprintf(w, "\n  %s Logged in to %s · plan %s · scopes %s\n", st.Green("✓"), apiU.Host, st.Bold(ks.Tier), strings.Join(ks.Key.Scopes, ", "))
	fmt.Fprintf(w, "  %s\n\n", st.Dim("Key stored in "+store.Name()+". `mantis logout` revokes it."))
	return nil
}

func runLogout(args []string, env *Env) error {
	fs := newFlags("logout", "Revoke this machine's key in the console and remove it locally.", env)
	apiURL := fs.String("api", "", "API base URL")
	consoleURL := fs.String("console", "", "console base URL")
	keepRemote := fs.Bool("local-only", false, "forget the key here but do not revoke it in the console")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}
	apiU, err := api.ValidateBaseURL(firstNonEmpty(*apiURL, env.env("MANTIS_API_URL", DefaultAPI)))
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	consoleU, err := api.ValidateBaseURL(firstNonEmpty(*consoleURL, env.env("MANTIS_CONSOLE_URL", DefaultConsole)))
	if err != nil {
		return fail(ExitUsage, "%v", err)
	}
	stores := []auth.Store{env.store()}
	if env.Store == nil {
		if p, err := auth.DefaultFilePath(); err == nil {
			stores = append(stores, auth.File{Path: p})
		}
	}
	found := false
	for _, s := range stores {
		cred, err := s.Get(apiU.Host)
		if err != nil {
			continue
		}
		found = true
		if !*keepRemote {
			flow := &auth.Flow{Console: consoleU, HTTP: httpClient(env), UserAgent: version.UserAgent()}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			err := flow.Revoke(ctx, cred.Token)
			cancel()
			if err != nil {
				fmt.Fprintf(env.Stderr, "  could not revoke the key in the console (%v); it was still removed here. Revoke it on your Keys page.\n", err)
			}
		}
		if err := s.Delete(apiU.Host); err != nil && !errors.Is(err, auth.ErrNotFound) {
			return fail(ExitInternal, "could not remove the key from %s: %v", s.Name(), err)
		}
		fmt.Fprintf(env.Stderr, "  logged out of %s (%s)\n", apiU.Host, s.Name())
	}
	if !found {
		fmt.Fprintf(env.Stderr, "  not logged in to %s\n", apiU.Host)
	}
	return nil
}

func runWhoami(args []string, env *Env) error {
	fs := newFlags("whoami", "Show the plan, allowance and scopes of the key Mantis would use.", env)
	apiURL := fs.String("api", "", "API base URL")
	if _, err := parseInterleaved(fs, args); err != nil {
		return err
	}
	client, source, err := apiClient(env, firstNonEmpty(*apiURL, env.env("MANTIS_API_URL", DefaultAPI)))
	if err != nil {
		return err
	}
	ks, err := client.Key(context.Background())
	if err != nil {
		return apiFail(err)
	}
	w := env.Stdout
	fmt.Fprintf(w, "plan        %s\n", ks.Tier)
	fmt.Fprintf(w, "scopes      %s\n", strings.Join(ks.Key.Scopes, ", "))
	fmt.Fprintf(w, "analyses    %d of %d used, resets %s\n", ks.Analyses.Used, ks.Analyses.Limit, ks.Analyses.Resets)
	if ks.LookupsToday.Limit != nil {
		fmt.Fprintf(w, "lookups     %d of %d today\n", ks.LookupsToday.Used, *ks.LookupsToday.Limit)
	} else {
		fmt.Fprintf(w, "lookups     unmetered\n")
	}
	if ks.Key.InGrace {
		fmt.Fprintf(w, "status      expired, in grace period: reads only\n")
	}
	fmt.Fprintf(w, "key from    %s\n", source)
	return nil
}

func httpClient(env *Env) *http.Client {
	if env.HTTP != nil {
		return env.HTTP
	}
	return api.NewHTTPClient(30 * time.Second)
}

// openBrowser opens a URL that has already been checked to be on the
// console host. The URL is passed as a single argument, never through a shell.
func openBrowser(env *Env, raw string) error {
	if env.OpenBrowser != nil {
		return env.OpenBrowser(raw)
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return errors.New("refusing to open a non web URL")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u.String())
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u.String())
	default:
		cmd = exec.Command("xdg-open", u.String())
	}
	return cmd.Start()
}

func spaced(code string) string { return strings.Join(strings.Split(code, ""), " ") }

func cleanDeviceName(s string) string {
	b := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= 0x20 && r != 0x7f && len(b) < 64 {
			b = append(b, r)
		}
	}
	if len(b) == 0 {
		return "this machine"
	}
	return string(b)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
