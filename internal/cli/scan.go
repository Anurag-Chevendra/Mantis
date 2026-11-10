package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Anurag-Chevendra/mantis/internal/api"
	"github.com/Anurag-Chevendra/mantis/internal/report"
	"github.com/Anurag-Chevendra/mantis/internal/version"
)

// FeedURL is where a verdict's public evidence page lives.
const FeedURL = "https://trail.snappyfeet.org/?p="

func runScan(args []string, env *Env) error {
	fs := newFlags("scan", "Check every public npm package under a path against Cohen.\nOnly name@version is sent. Local, git, tarball and private packages stay on this machine.\n\nExamples:\n  mantis scan                    check; exit code 1 if anything needs review\n  mantis scan --analyze          also queue analyses for versions with no verdict\n  mantis scan --analyze --open   queue, then show the result in your browser\n  mantis scan --dry-run          print the exact request body, send nothing", env)
	var cf collectFlags
	cf.register(fs)
	format := fs.String("format", "text", "output format: text, json or html")
	open := fs.Bool("open", false, "also write the HTML report and open it in your browser")
	output := fs.String("output", "", "write the report to this file (JSON unless --format html)")
	failOn := fs.String("fail-on", "", "exit 1 when anything needs: review (default) or none")
	analyze := fs.Bool("analyze", false, "queue a deep analysis for versions with no verdict yet (uses your monthly allowance)")
	yes := fs.Bool("yes", false, "do not ask before queueing analyses (for CI with --analyze)")
	noGraph := fs.Bool("no-graph", false, "do not send which dependency pulled in which (the console then shows no graph)")
	wait := fs.Bool("wait", false, "after queueing, stay until the analyses finish and report their verdicts (on by default with --open in a terminal)")
	dryRun := fs.Bool("dry-run", false, "print exactly what would be sent, then stop; no network")
	project := fs.String("project", "", "project name shown in your console's scan history")
	apiURL := fs.String("api", "", "API base URL (default $MANTIS_API_URL or "+DefaultAPI+")")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return fail(ExitUsage, "scan takes at most one path")
	}
	path := "."
	if len(pos) == 1 {
		path = pos[0]
	}
	if *format != "text" && *format != "json" && *format != "html" {
		return fail(ExitUsage, "unknown --format %q (text, json or html)", *format)
	}
	html := *format == "html" || *open

	cf.http = env.HTTP
	if *format != "json" {
		cf.stderr = env.Stderr
	}
	inv, cfg, err := collect(path, cf)
	if err != nil {
		return err
	}
	fo := *failOn
	if fo == "" {
		fo = cfg.FailOn
	}
	if fo == "" {
		fo = "review"
	}
	if fo != "review" && fo != "none" {
		return fail(ExitUsage, "--fail-on must be review or none")
	}
	proj := *project
	if proj == "" {
		proj = cfg.Project
	}
	if proj == "" {
		proj = filepath.Base(absBase(path))
	}

	versions := inv.Checkable()
	if *dryRun {
		body := map[string]any{"versions": versions, "queue_unknown": *analyze}
		if inv.Graph != nil && !*noGraph {
			body["graph"] = inv.Graph
		}
		fmt.Fprintf(env.Stderr, "  dry run: this is the complete request body; %d of %d versions, nothing else.\n  held back (never sent): %d\n\n",
			len(versions), inv.Summary.Total, inv.Summary.HeldBack)
		return report.WriteJSON(env.Stdout, body)
	}

	text := *format != "json"
	if text {
		report.Header(env.Stderr, env.ErrStyle, version.Version, "dependency check")
		report.WriteSummary(env.Stderr, env.ErrStyle, inv)
		fmt.Fprintln(env.Stderr)
	}
	if len(versions) == 0 {
		if text {
			fmt.Fprintln(env.Stderr, "  nothing to check: every package is local, git, private or excluded")
		}
		if html {
			return writeHTML(env, inv, proj, *output, *open)
		}
		return writeScanJSON(env, *format, *output, inv)
	}

	base := *apiURL
	if base == "" {
		base = env.env("MANTIS_API_URL", DefaultAPI)
	}
	client, _, err := apiClient(env, base)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// --analyze needs the queue scope. Ask the free, unmetered key endpoint
	// first, so a free key does not spend its lookups before being refused.
	var keyStatus *api.KeyStatus
	if *analyze {
		ks, err := client.Key(ctx)
		keyStatus = ks
		if err != nil {
			return apiFail(err)
		}
		if !slices.Contains(ks.Key.Scopes, "queue") {
			return fail(ExitAuth, "--analyze queues sandbox analyses, which needs a paid plan; this key (%s plan) can only read verdicts.\n  Run without --analyze to check against existing verdicts.", ks.Tier)
		}
	}

	if text {
		client.OnRetry(func(attempt, max int, err error) {
			fmt.Fprintf(env.Stderr, "\r  %s\n", env.ErrStyle.Yellow(fmt.Sprintf("! Cohen did not answer (%v); retrying, attempt %d of %d", err, attempt, max)))
		})
	}

	// With --open the report is shown before the check starts and filled in
	// as each batch is answered, so nobody stares at a silent terminal.
	var rep *htmlReport
	if html {
		if rep, err = newHTMLReport(env, proj, *output, *open); err != nil {
			return err
		}
	}
	liveWrite := func(phase string, done int, pending []string, stopped bool) {
		if rep == nil || !rep.live() {
			return
		}
		_ = rep.write(inv, &report.Live{Phase: phase, Done: done, Total: len(versions), Pending: pending, Stopped: stopped})
		rep.show()
	}
	liveWrite(fmt.Sprintf("Checking %d versions against Cohen", len(versions)), 0, versions, false)

	started := time.Now()
	opt := api.CheckOptions{Project: proj, Client: "mantis/" + version.Version}
	if inv.Graph != nil && !*noGraph {
		opt.Graph = inv.Graph
	}
	if text {
		fmt.Fprintf(env.Stderr, "  checking %d versions against Cohen…", len(versions))
	}
	opt.Progress = func(done, total int, partial *api.CheckResult) {
		if text {
			fmt.Fprintf(env.Stderr, "\r  checking %d versions against Cohen… %d done", total, done)
		}
		if done < total {
			inv.Check = partial
			liveWrite(fmt.Sprintf("Checking %d versions against Cohen", total), done, versions[done:], false)
		}
	}
	// With --yes there is nothing to ask, so check and queue in one request:
	// one scan in the console history instead of two.
	opt.QueueUnknown = *analyze && *yes
	res, err := client.Check(ctx, versions, opt)
	if text {
		fmt.Fprintln(env.Stderr)
	}
	if err != nil {
		liveWrite("Stopped: "+apiFail(err).Error(), countDone(res), nil, true)
		return apiFail(err)
	}
	inv.Check = res

	if *analyze && len(res.Unknown) > 0 {
		n := len(res.Unknown)
		if !*yes {
			if !env.Interactive {
				return fail(ExitUsage, "%d versions have no verdict; queueing them spends %d analyses. Re-run with --analyze --yes to confirm in CI.", n, n)
			}
			used, limit, resets := 0, 0, ""
			if keyStatus != nil {
				used, limit, resets = keyStatus.Analyses.Used, keyStatus.Analyses.Limit, keyStatus.Analyses.Resets
			}
			if res.Allowance != nil && res.Allowance.Limit > 0 {
				used, limit = res.Allowance.Used, res.Allowance.Limit
				resets = firstNonEmpty(res.Allowance.Resets, resets)
			}
			if limit > 0 {
				if left := limit - used; n > left {
					fmt.Fprintf(env.Stderr, "  %d versions have no verdict, but only %d analyses are left this month (resets %s). Nothing was queued.\n",
						n, max(left, 0), resets)
					*analyze = false
				}
			}
		}
		if *analyze && !*yes {
			liveWrite(fmt.Sprintf("Waiting for you in the terminal: queue %d analyses?", n), len(versions), nil, false)
			fmt.Fprintf(env.Stderr, "  %d versions have no verdict yet. Queue %d deep analyses? This uses %d from this month's allowance. [y/n] ", n, n, n)
			if !confirm(env) {
				fmt.Fprintln(env.Stderr, "  not queued")
				*analyze = false
			}
		}
		if *analyze {
			unknown := make([]string, 0, n)
			for _, u := range res.Unknown {
				unknown = append(unknown, u.Name+"@"+u.Version)
			}
			opt.QueueUnknown = true
			opt.Progress = nil
			if len(res.Scans) > 0 {
				opt.ScanID, opt.Requeue = res.Scans[0], true
			}
			liveWrite(fmt.Sprintf("Queueing %d analyses", n), len(versions), nil, false)
			q, err := client.Check(ctx, unknown, opt)
			if err != nil {
				liveWrite("Stopped while queueing: "+apiFail(err).Error(), len(versions), nil, true)
				return apiFail(err)
			}
			res.Merge(q)
			for _, id := range q.Scans {
				if !slices.Contains(res.Scans, id) {
					res.Scans = append(res.Scans, id)
				}
			}
		}
	}
	inv.Check = res

	if text {
		writeScanText(env, inv, res, time.Since(started), len(versions))
	}

	// Queued analyses take minutes each. With --open in a terminal (or with
	// --wait) Mantis stays and keeps the report live until they finish.
	// Ctrl+C stops watching; the analyses carry on in Cohen regardless.
	if len(res.Queued) > 0 && (*wait || (rep != nil && rep.live() && env.Interactive)) {
		console := strings.TrimRight(env.env("MANTIS_CONSOLE_URL", DefaultConsole), "/")
		links := make([]string, 0, len(res.Scans))
		for _, id := range res.Scans {
			links = append(links, console+"/scans/"+url.PathEscape(id))
		}
		watchJobs(ctx, env, client, inv, res, links, rep, text)
	}
	if html {
		if err := rep.write(inv, nil); err != nil {
			return err
		}
		rep.show()
	} else if err := writeScanJSON(env, *format, *output, inv); err != nil {
		return err
	}
	if fo == "review" && len(res.Review) > 0 {
		return &exitError{code: ExitReview}
	}
	// A package Cohen could not check is not a pass: CI must not go green.
	if fo == "review" && summarise(res).unchecked > 0 {
		return fail(ExitNetwork, "%d packages could not be checked (the verdict store or a source was unreachable). Nothing about them is known; run again shortly.", summarise(res).unchecked)
	}
	return nil
}

// watchJobs polls the scans' jobs (GET /api/scan/{id}, never metered) and
// moves each queued version to its verdict as the sandbox finishes it.
func watchJobs(ctx context.Context, env *Env, client *api.Client, inv *report.Inventory,
	res *api.CheckResult, links []string, rep *htmlReport, text bool) {
	total := len(res.Queued)
	w := env.Stderr
	if text {
		fmt.Fprintf(w, "\n  watching %d analyses; Ctrl+C stops watching (they keep running in Cohen)\n", total)
		for _, l := range links {
			fmt.Fprintf(w, "  %s\n", env.ErrStyle.Dim(l))
		}
	}
	const every = 20 * time.Second
	for {
		done := total - len(res.Queued)
		running := 0
		for _, q := range res.Queued {
			if q.State == "running" {
				running++
			}
		}
		note := fmt.Sprintf("%d of %d analysed, %d running now. Each takes a few minutes; this page updates itself.", done, total, running)
		if rep != nil && rep.live() {
			_ = rep.write(inv, &report.Live{Phase: fmt.Sprintf("Analysing %d versions in the sandbox", total),
				Done: done, Total: total, Note: note, Refresh: 10, Links: links})
		}
		if text {
			fmt.Fprintf(w, "\r  analysed %d of %d · %d running · %d review so far   ", done, total, running, len(res.Review))
		}
		if len(res.Queued) == 0 || allFailed(res.Queued) {
			break
		}
		select {
		case <-ctx.Done():
			waiting := 0
			for _, q := range res.Queued {
				if q.State != "running" && q.State != "failed" {
					waiting++
				}
			}
			cancel := false
			if waiting > 0 && env.Interactive {
				fmt.Fprintf(w, "\n  stopped watching. Also cancel the %d analyses that have not started? They are refunded. [y/n] ", waiting)
				cancel = confirm(env)
			}
			if cancel {
				cctx, done := context.WithTimeout(context.Background(), 30*time.Second)
				n := 0
				for _, id := range res.Scans {
					if c, err := client.CancelScan(cctx, id); err == nil {
						n += c
					} else {
						fmt.Fprintf(w, "  could not cancel: %v\n", err)
					}
				}
				done()
				fmt.Fprintf(w, "  cancelled %d analyses; any already running will finish\n", n)
				if rep != nil && rep.live() {
					_ = rep.write(inv, &report.Live{Phase: "Stopped: waiting analyses cancelled", Done: total - len(res.Queued), Total: total,
						Note: fmt.Sprintf("%d analyses were cancelled and refunded.", n), Stopped: true, Links: links})
				}
			} else {
				if text {
					fmt.Fprintf(w, "\n  stopped watching; the remaining analyses carry on in Cohen\n")
				}
				if rep != nil && rep.live() {
					_ = rep.write(inv, &report.Live{Phase: "Stopped watching", Done: total - len(res.Queued), Total: total,
						Note: "The remaining analyses carry on in Cohen. Open the console for live results.", Stopped: true, Links: links})
				}
			}
			return
		case <-time.After(every):
		}
		states := map[string]api.ScanJob{}
		for _, id := range res.Scans {
			st, err := client.Scan(ctx, id)
			if err != nil {
				continue // a missed poll is retried on the next round
			}
			for _, j := range st.Jobs {
				states[j.Job] = j
			}
		}
		byJob := map[string]int{}
		for i, r := range res.Results {
			if r.Job != "" {
				byJob[r.Job] = i
			}
		}
		setResult := func(job string, f func(r *api.Result)) {
			if i, ok := byJob[job]; ok {
				f(&res.Results[i])
			}
		}
		keep := res.Queued[:0]
		for _, q := range res.Queued {
			j, ok := states[q.Job]
			if ok {
				setResult(q.Job, func(r *api.Result) {
					r.State, r.Percent = j.State, j.Progress.Percent
					if j.State == "done" {
						r.Verdict = strings.ToLower(j.Verdict)
						r.KnownMalware = r.KnownMalware || j.KnownMalware
						if len(j.Sources) > 0 {
							r.Sources = j.Sources
						}
					}
				})
			}
			switch {
			case !ok:
				keep = append(keep, q)
			case j.State == "done" && strings.EqualFold(j.Verdict, "review"):
				res.Review = append(res.Review, api.Verdict{Name: q.Name, Version: q.Version, Verdict: "review"})
				res.Counts.Review++
			case j.State == "done":
				res.Counts.Clean++
			case j.State == "claimed" || j.State == "running":
				q.State, q.Percent = "running", j.Progress.Percent
				keep = append(keep, q)
			case j.State == "failed" || j.State == "cancelled":
				q.State = "failed"
				keep = append(keep, q)
			default:
				q.State = "queued"
				keep = append(keep, q)
			}
		}
		res.Queued = keep
	}
	if text {
		fmt.Fprintf(w, "\n  all analyses finished\n")
		if len(res.Review) > 0 {
			fmt.Fprintf(w, "  %s\n", env.ErrStyle.Bold(fmt.Sprintf("%d package(s) need a human", len(res.Review))))
		}
	}
}

func allFailed(q []api.Queued) bool {
	for _, x := range q {
		if x.State != "failed" {
			return false
		}
	}
	return true
}

// confirm asks for an explicit y or n. Blank lines are ignored, because a
// key pressed while the check was running would otherwise answer a question
// that spends the user's allowance. End of input counts as no.
func confirm(env *Env) bool {
	r := bufio.NewReader(env.Stdin)
	for {
		line, err := r.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return true
		case "n", "no":
			return false
		case "":
			if err != nil {
				return false
			}
			continue
		default:
			fmt.Fprint(env.Stderr, "  please type y or n: ")
		}
		if err != nil {
			return false
		}
	}
}

// countDone is how many versions a partial result answered.
func countDone(r *api.CheckResult) int {
	if r == nil {
		return 0
	}
	return r.Counts.Clean + r.Counts.Review + r.Counts.Queued + r.Counts.Skipped + len(r.Unknown)
}

func writeScanText(env *Env, inv *report.Inventory, res *api.CheckResult, took time.Duration, sent int) {
	st := env.ErrStyle
	w := env.Stderr
	sum := summarise(res)
	fmt.Fprintf(w, "  %-22s %d versions · %.1fs\n", "checked", sent, took.Seconds())
	fmt.Fprintf(w, "  %-22s %s\n", "clean", st.Green(fmt.Sprint(res.Counts.Clean)))
	rv := fmt.Sprint(len(res.Review))
	if len(res.Review) > 0 {
		rv = st.Red(rv)
	}
	fmt.Fprintf(w, "  %-22s %s\n", "review", rv)
	if sum.malware > 0 {
		fmt.Fprintf(w, "  %-22s %s  %s\n", "known malware", st.Red(fmt.Sprint(sum.malware)), st.Dim("(OSV or npm already flagged it; included in review)"))
	}
	if len(res.Unknown) > 0 {
		fmt.Fprintf(w, "  %-22s %d  %s\n", "no verdict yet", len(res.Unknown), st.Dim("(--analyze queues them)"))
	}
	if len(res.Queued) > 0 {
		note := "(results land in your console)"
		if sum.etaMax > 0 {
			note = fmt.Sprintf("(queue position %d onwards; all done in about %s)", sum.firstPos, humanDuration(sum.etaMax))
		}
		fmt.Fprintf(w, "  %-22s %d  %s\n", "queued for analysis", len(res.Queued), st.Dim(note))
	}
	if res.Counts.Attached > 0 {
		fmt.Fprintf(w, "  %-22s %d  %s\n", "already analysing", res.Counts.Attached, st.Dim("(someone queued these first; free)"))
	}
	if sum.notOnNpm > 0 {
		fmt.Fprintf(w, "  %-22s %s  %s\n", "not on npm", st.Yellow(fmt.Sprint(sum.notOnNpm)), st.Dim("(npm has no such name or version; npm deletes malicious versions, so check these)"))
		for _, r := range res.Results {
			if r.State == "skipped" && (r.Reason == "not_in_registry" || r.Reason == "version_not_found") {
				fmt.Fprintf(w, "    %s %s\n", st.Yellow("!"), r.Key())
			}
		}
	}
	if sum.osvMissed > 0 {
		fmt.Fprintf(w, "  %s %s\n", st.Yellow("!"), fmt.Sprintf("OSV could not be reached for %d versions, so the known malware check is incomplete for them", sum.osvMissed))
	}
	if sum.unchecked > 0 {
		fmt.Fprintf(w, "  %-22s %s  %s\n", "not checked", st.Yellow(fmt.Sprint(sum.unchecked)), st.Dim("(Cohen could not reach a source; this is not a pass)"))
	}
	if sum.advised > 0 {
		fmt.Fprintf(w, "  %-22s %d  %s\n", "known vulnerabilities", sum.advised, st.Dim("(packages with GHSA or CVE advisories; not malware)"))
	}
	if a := res.Allowance; a != nil && a.Limit > 0 {
		fmt.Fprintf(w, "  %-22s %d of %d used%s\n", "analyses this month", a.Used, a.Limit, st.Dim(map[bool]string{true: ", resets " + a.Resets, false: ""}[a.Resets != ""]))
	}
	if len(res.Review) > 0 {
		fmt.Fprintln(w)
		for _, r := range res.Review {
			key := r.Name + "@" + r.Version
			label := "REVIEW"
			if src := sum.sources[key]; len(src) > 0 {
				label = "MALWARE"
			}
			fmt.Fprintf(w, "  %s  %s\n", st.Red(fmt.Sprintf("%-7s", label)), st.Bold(key))
			for _, src := range sum.sources[key] {
				fmt.Fprintf(w, "           %s\n", st.Dim(sourceLine(src)))
			}
			fmt.Fprintf(w, "           %s\n", st.Dim(FeedURL+url.QueryEscape(key)))
			if where := lockfilesFor(inv, r.Name, r.Version); len(where) > 0 {
				fmt.Fprintf(w, "           %s\n", st.Dim("pinned in "+strings.Join(where, ", ")))
			}
		}
	}
	fmt.Fprintln(w)
	switch {
	case len(res.Review) > 0:
		fmt.Fprintf(w, "  %s\n", st.Bold(fmt.Sprintf("%d package(s) need a human", len(res.Review))))
	case sum.unchecked > 0:
		fmt.Fprintf(w, "  %s\n", st.Yellow(fmt.Sprintf("%d package(s) could not be checked; run again shortly", sum.unchecked)))
	default:
		fmt.Fprintf(w, "  %s\n", st.Green("nothing needs review"))
	}
}

type resultSummary struct {
	malware, notOnNpm, unchecked, advised int
	osvMissed                             int
	firstPos, etaMax                      int
	sources                               map[string][]api.Source
}

func summarise(res *api.CheckResult) resultSummary {
	s := resultSummary{sources: map[string][]api.Source{}}
	for _, r := range res.Results {
		if r.KnownMalware {
			s.malware++
			s.sources[r.Key()] = r.Sources
		}
		switch r.State {
		case "skipped":
			if r.Reason == "not_in_registry" || r.Reason == "version_not_found" {
				s.notOnNpm++
			}
		case "unavailable":
			s.unchecked++
		}
		if len(r.Vulnerabilities) > 0 {
			s.advised++
		}
		if r.OSVChecked != nil && !*r.OSVChecked {
			s.osvMissed++
		}
		if r.QueuePosition != nil && (s.firstPos == 0 || *r.QueuePosition < s.firstPos) {
			s.firstPos = *r.QueuePosition
		}
		if r.ETASeconds != nil && *r.ETASeconds > s.etaMax {
			s.etaMax = *r.ETASeconds
		}
	}
	return s
}

func sourceLine(src api.Source) string {
	switch src.Source {
	case "osv":
		return "OSV " + src.ID + "  " + src.URL
	case "npm_security_holding":
		return "npm replaced it with a security holding package  " + src.URL
	}
	return src.Source + " " + src.ID
}

func humanDuration(sec int) string {
	switch {
	case sec < 90:
		return fmt.Sprintf("%d s", sec)
	case sec < 5400:
		return fmt.Sprintf("%d min", (sec+30)/60)
	default:
		return fmt.Sprintf("%.1f h", float64(sec)/3600)
	}
}

func lockfilesFor(inv *report.Inventory, name, ver string) []string {
	for _, p := range inv.Packages {
		if p.Name == name && p.Version == ver {
			return p.Lockfiles
		}
	}
	return nil
}

func writeScanJSON(env *Env, format, output string, inv *report.Inventory) error {
	if format != "json" && output == "" {
		return nil
	}
	var b strings.Builder
	if err := report.WriteJSON(&b, inv); err != nil {
		return err
	}
	if output != "" {
		return emit(env, output, []byte(b.String()))
	}
	_, err := fmt.Fprint(env.Stdout, b.String())
	return err
}

func apiFail(err error) error {
	var ae *api.Error
	if errors.Is(err, context.Canceled) {
		return fail(ExitNetwork, "interrupted")
	}
	if errors.As(err, &ae) {
		switch {
		case ae.Status == 401:
			return fail(ExitAuth, "%s. Run `mantis login` again, or check MANTIS_TOKEN.", strings.TrimSuffix(ae.Message, "."))
		case ae.Status == 403:
			return fail(ExitAuth, "%s", ae.Error())
		}
		return fail(ExitNetwork, "%s", ae.Error())
	}
	return fail(ExitNetwork, "%v", err)
}
