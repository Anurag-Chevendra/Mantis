// Package api is the client for the Cohen verdict API.
//
// It sends package names and versions, nothing else: no file contents, no
// paths, no environment. Every request carries the caller's key in an
// Authorization header and goes over HTTPS only.
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the public Cohen API.
const DefaultBaseURL = "https://api.snappyfeet.org"

// MaxBatch is the server's per request limit for bulk checks.
const MaxBatch = 5000

// DefaultBatch is how many versions Mantis sends per request. The server
// checks OSV, npm and its verdict store for each one before answering, and a
// proxy in front of it (Cloudflare) cuts responses off at 100 s, so large
// trees go in several moderate requests rather than one huge one.
const DefaultBatch = 300

// Client talks to one API host.
type Client struct {
	base      *url.URL
	token     string
	userAgent string
	http      *http.Client
	batch     int
	retries   int
	sleep     func(context.Context, time.Duration) error
	onRetry   func(attempt, max int, err error)
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient replaces the transport (tests).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithBatchSize lowers the per request batch (tests).
func WithBatchSize(n int) Option { return func(c *Client) { c.batch = n } }

// WithRetryNotice is called before each retry, so a person watching a
// terminal knows Mantis is waiting rather than stuck.
func WithRetryNotice(f func(attempt, max int, err error)) Option {
	return func(c *Client) { c.onRetry = f }
}

// OnRetry sets the retry notice after construction.
func (c *Client) OnRetry(f func(attempt, max int, err error)) { c.onRetry = f }

// WithNoSleep makes retries immediate (tests).
func WithNoSleep() Option {
	return func(c *Client) { c.sleep = func(context.Context, time.Duration) error { return nil } }
}

// New validates the base URL and builds a client.
func New(base, token, userAgent string, opts ...Option) (*Client, error) {
	u, err := ValidateBaseURL(base)
	if err != nil {
		return nil, err
	}
	c := &Client{
		base:      u,
		token:     token,
		userAgent: userAgent,
		http:      NewHTTPClient(95 * time.Second),
		batch:     DefaultBatch,
		retries:   4,
		sleep:     sleepCtx,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// ValidateBaseURL accepts https URLs, and http only for loopback hosts
// (local development and tests). A key is never sent in clear text.
func ValidateBaseURL(base string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid URL %q", base)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("URL %q must not contain credentials, a query or a fragment", base)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("refusing plain http for %s: use https", u.Host)
		}
	default:
		return nil, fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	return u, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NewHTTPClient is the one HTTP client configuration Mantis uses: system
// trust store (so corporate TLS inspection CAs work), HTTPS_PROXY and
// NO_PROXY honoured, TLS 1.2 minimum, and no redirects to another host, so a
// credential can never be forwarded somewhere unexpected.
func NewHTTPClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyFromEnvironment
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if req.URL.Host != via[0].URL.Host || req.URL.Scheme != via[0].URL.Scheme {
				return fmt.Errorf("refusing redirect from %s to %s", via[0].URL.Host, req.URL.Host)
			}
			return nil
		},
	}
}

// Error is a non 2xx answer from the API.
type Error struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s (HTTP %d, %s)", e.Message, e.Status, e.Code)
	}
	return fmt.Sprintf("HTTP %d %s", e.Status, e.Code)
}

// IsAuth reports whether the key was missing, invalid, expired or revoked.
func IsAuth(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusUnauthorized
}

// KeyStatus is GET /api/key.
type KeyStatus struct {
	Tier     string `json:"tier"`
	Analyses struct {
		Used   int    `json:"used"`
		Limit  int    `json:"limit"`
		Resets string `json:"resets"`
	} `json:"analyses"`
	LookupsToday struct {
		Used  int  `json:"used"`
		Limit *int `json:"limit"`
	} `json:"lookups_today"`
	Key struct {
		Scopes  []string `json:"scopes"`
		InGrace bool     `json:"in_grace"`
	} `json:"key"`
}

// Key returns the caller's tier, allowance and scopes. It is never metered.
func (c *Client) Key(ctx context.Context) (*KeyStatus, error) {
	var ks KeyStatus
	if err := c.do(ctx, http.MethodGet, "/api/key", nil, nil, &ks); err != nil {
		return nil, err
	}
	return &ks, nil
}

// Verdict is one known result.
type Verdict struct {
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	Verdict    string          `json:"verdict"`
	AnalyzedAt json.RawMessage `json:"analyzed_at,omitempty"`
	Summary    json.RawMessage `json:"summary,omitempty"`
}

// NameVersion is a package the API could not answer for.
type NameVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Queued is a deep analysis started by the request.
type Queued struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Job     string `json:"job"`
	// Filled in while Mantis watches the job: queued, running or failed,
	// and the sandbox's rough progress.
	State   string `json:"state,omitempty"`
	Percent int    `json:"percent,omitempty"`
}

// ScanJob is one job as GET /api/scan/{id} reports it.
type ScanJob struct {
	Job          string   `json:"job"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	State        string   `json:"state"` // queued, claimed, running, done, failed, cancelled
	Phase        string   `json:"phase"`
	Verdict      string   `json:"verdict"`
	TimedOut     bool     `json:"timed_out"`
	KnownMalware bool     `json:"known_malware"`
	Sources      []Source `json:"sources"`
	Error        string   `json:"error"`
	Progress     struct {
		Percent    int  `json:"percent"`
		ETASeconds *int `json:"eta_seconds"`
	} `json:"progress"`
}

// ScanState is GET /api/scan/{id}: every job one bulk request created.
type ScanState struct {
	Scan        string `json:"scan"`
	JobsSummary struct {
		Queued   int  `json:"queued"`
		Running  int  `json:"running"`
		Done     int  `json:"done"`
		Failed   int  `json:"failed"`
		Complete bool `json:"complete"`
	} `json:"jobs_summary"`
	Jobs []ScanJob `json:"jobs"`
}

// CancelScan withdraws a scan's analyses that have not started; they are
// refunded. It returns how many were withdrawn.
func (c *Client) CancelScan(ctx context.Context, id string) (int, error) {
	var out struct {
		Cancelled int `json:"cancelled"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/scan/"+url.PathEscape(id)+"/cancel", map[string]any{}, nil, &out); err != nil {
		return 0, err
	}
	return out.Cancelled, nil
}

// Scan reads the state of one bulk request's jobs. It is never metered.
func (c *Client) Scan(ctx context.Context, id string) (*ScanState, error) {
	var out ScanState
	if err := c.do(ctx, http.MethodGet, "/api/scan/"+url.PathEscape(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Counts summarises a check.
type Counts struct {
	Clean        int `json:"clean"`
	Review       int `json:"review"`
	KnownMalware int `json:"known_malware"`
	Queued       int `json:"queued"`
	Attached     int `json:"attached"` // joined an analysis already running; free
	Skipped      int `json:"skipped"`
	Unavailable  int `json:"unavailable"`
}

// Source is evidence that a version is known malware.
type Source struct {
	Source string `json:"source"` // osv or npm_security_holding
	ID     string `json:"id,omitempty"`
	URL    string `json:"url,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Advisory is a known vulnerability (GHSA, CVE). It is not malware and
// never decides the verdict; it is reported so it is not lost.
type Advisory struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// Result is the console's answer for one name@version, in the order sent.
type Result struct {
	Input           string          `json:"input"`
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	State           string          `json:"state"` // done, unknown, queued, claimed, running, pending, skipped, unavailable
	Verdict         string          `json:"verdict,omitempty"`
	Cached          bool            `json:"cached,omitempty"`
	AnalyzedAt      json.RawMessage `json:"analyzed_at,omitempty"`
	KnownMalware    bool            `json:"known_malware"`
	Sources         []Source        `json:"sources,omitempty"`
	Vulnerabilities []Advisory      `json:"vulnerabilities,omitempty"`
	OSVChecked      *bool           `json:"osv_checked,omitempty"`
	Reason          string          `json:"reason,omitempty"` // not_in_registry, version_not_found, verdict_store_unavailable, sandbox_saturated, malformed
	Job             string          `json:"job,omitempty"`
	QueuePosition   *int            `json:"queue_position,omitempty"`
	ETASeconds      *int            `json:"eta_seconds,omitempty"`
	Charged         bool            `json:"charged,omitempty"`
	Percent         int             `json:"percent,omitempty"` // set while Mantis watches the job
}

// Key is name@version.
func (r Result) Key() string { return r.Name + "@" + r.Version }

// Allowance is the account's monthly analyses after the request.
type Allowance struct {
	Used   int    `json:"used"`
	Limit  int    `json:"limit"`
	Resets string `json:"resets,omitempty"`
}

// CheckResult merges every batch of one check.
type CheckResult struct {
	Scans   []string      `json:"scans"`
	Counts  Counts        `json:"counts"`
	Review  []Verdict     `json:"review"`
	Unknown []NameVersion `json:"unknown"`
	Queued  []Queued      `json:"queued"`
	// Results has one entry per version sent, with everything the console
	// knows about it. Review, Unknown and Queued are summaries of it.
	Results []Result `json:"results"`
	// Allowance after the last batch, as the server reports it.
	Allowance *Allowance `json:"allowance,omitempty"`
}

// Merge folds a later pass (the queue pass) into r: its results replace the
// earlier answers for the same versions.
func (r *CheckResult) Merge(q *CheckResult) {
	idx := map[string]int{}
	for i, x := range r.Results {
		idx[x.Key()] = i
	}
	for _, x := range q.Results {
		if i, ok := idx[x.Key()]; ok {
			r.Results[i] = x
		} else {
			r.Results = append(r.Results, x)
		}
	}
	r.Queued = append(r.Queued, q.Queued...)
	r.Counts.Queued += q.Counts.Queued
	r.Counts.Attached += q.Counts.Attached
	r.Counts.Unavailable += q.Counts.Unavailable
	r.Unknown = []NameVersion{}
	if q.Allowance != nil {
		r.Allowance = q.Allowance
	}
}

// CheckOptions control a bulk check.
type CheckOptions struct {
	// QueueUnknown starts a deep analysis for versions with no verdict.
	// Each one spends an analysis from the monthly allowance.
	QueueUnknown bool
	Project      string
	Client       string // X-Client, e.g. "mantis/0.1.0"
	// Progress, when set, is called after each batch with the versions done
	// so far and the merged result up to that point.
	Progress func(done, total int, partial *CheckResult)
	// ScanID continues an existing scan, so a large tree sent in several
	// requests, and a later queue pass, stay one scan in the console.
	ScanID string
	// Requeue marks a pass that queues versions already reported unknown.
	Requeue bool
	// Graph, when set, is sent once with the first request: the project's
	// direct dependencies and what each depends on, as name@version pairs
	// of versions in the request. It draws the console's graph view.
	Graph any
}

type checkResponse struct {
	Scan      string        `json:"scan"`
	Counts    Counts        `json:"counts"`
	Review    []Verdict     `json:"review"`
	Unknown   []NameVersion `json:"unknown"`
	Queued    []Queued      `json:"queued"`
	Results   []Result      `json:"results"`
	Allowance *Allowance    `json:"allowance"`
}

// Check sends name@version strings in batches of at most MaxBatch.
// Each batch has its own idempotency key, reused on retry, so a retried
// request can never spend the allowance twice.
func (c *Client) Check(ctx context.Context, versions []string, opt CheckOptions) (*CheckResult, error) {
	out := &CheckResult{Review: []Verdict{}, Unknown: []NameVersion{}, Queued: []Queued{}, Scans: []string{}}
	for start := 0; start < len(versions); start += c.batch {
		end := min(start+c.batch, len(versions))
		body := map[string]any{
			"versions":      versions[start:end],
			"queue_unknown": opt.QueueUnknown,
		}
		if start == 0 && opt.Graph != nil && !opt.Requeue {
			body["graph"] = opt.Graph
		}
		hdr := http.Header{}
		hdr.Set("Idempotency-Key", "mantis-"+randomHex(16))
		if opt.Project != "" {
			hdr.Set("X-Project", sanitizeHeader(opt.Project, 120))
		}
		if opt.Client != "" {
			hdr.Set("X-Client", opt.Client)
		}
		if opt.ScanID != "" {
			hdr.Set("X-Scan-Id", opt.ScanID)
			if opt.Requeue {
				hdr.Set("X-Scan-Phase", "queue")
			}
		}
		var r checkResponse
		if err := c.do(ctx, http.MethodPost, "/api/package/npm", body, hdr, &r); err != nil {
			return out, err
		}
		if r.Scan != "" {
			if opt.ScanID == "" {
				opt.ScanID = r.Scan
			}
			if !slices.Contains(out.Scans, r.Scan) {
				out.Scans = append(out.Scans, r.Scan)
			}
		}
		out.Counts.Clean += r.Counts.Clean
		out.Counts.Review += r.Counts.Review
		out.Counts.KnownMalware += r.Counts.KnownMalware
		out.Counts.Queued += r.Counts.Queued
		out.Counts.Attached += r.Counts.Attached
		out.Counts.Skipped += r.Counts.Skipped
		out.Counts.Unavailable += r.Counts.Unavailable
		out.Results = append(out.Results, r.Results...)
		out.Review = append(out.Review, r.Review...)
		out.Unknown = append(out.Unknown, r.Unknown...)
		out.Queued = append(out.Queued, r.Queued...)
		if r.Allowance != nil {
			out.Allowance = r.Allowance
		}
		if opt.Progress != nil {
			opt.Progress(end, len(versions), out)
		}
	}
	return out, nil
}

// do performs one request with retries on transient failures: network
// errors, 429, 502, 503 and 504. Retry-After is honoured.
func (c *Client) do(ctx context.Context, method, path string, body any, hdr http.Header, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + path

	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			if c.onRetry != nil {
				c.onRetry(attempt, c.retries, lastErr)
			}
			if err := c.sleep(ctx, backoff(attempt, lastErr)); err != nil {
				return err
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
		if err != nil {
			return err
		}
		for k, v := range hdr {
			req.Header[k] = v
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.userAgent)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = err
			continue
		}
		data, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out == nil {
				return nil
			}
			if err := json.Unmarshal(data, out); err != nil {
				return fmt.Errorf("unexpected response from %s: %w", u.Host, err)
			}
			return nil
		}
		apiErr := &Error{Status: resp.StatusCode}
		_ = json.Unmarshal(data, apiErr)
		if apiErr.Code == "" {
			apiErr.Code = http.StatusText(resp.StatusCode)
		}
		switch resp.StatusCode {
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			after := parseRetryAfter(resp.Header.Get("Retry-After"))
			// A spent quota is not transient, and nobody should watch a
			// silent terminal for an hour: report it now.
			if apiErr.Code == "daily_cap" || apiErr.Code == "allowance_spent" || after > maxRetryWait {
				return apiErr
			}
			lastErr = &retryAfter{err: apiErr, after: after}
			continue
		}
		return apiErr
	}
	var ra *retryAfter
	if errors.As(lastErr, &ra) {
		return ra.err
	}
	return fmt.Errorf("could not reach %s: %w", u.Host, lastErr)
}

// maxRetryWait is the longest Retry-After Mantis will wait out; anything
// longer is returned to the user instead.
const maxRetryWait = 30 * time.Second

type retryAfter struct {
	err   *Error
	after time.Duration
}

func (r *retryAfter) Error() string { return r.err.Error() }

func backoff(attempt int, last error) time.Duration {
	var ra *retryAfter
	if errors.As(last, &ra) && ra.after > 0 {
		return min(ra.after, maxRetryWait)
	}
	base := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
	jitter := time.Duration(mrand.Int64N(int64(base / 2)))
	return base + jitter
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// sanitizeHeader keeps a header value printable ASCII and bounded.
func sanitizeHeader(s string, max int) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < max; i++ {
		if s[i] >= 0x20 && s[i] < 0x7f {
			b = append(b, s[i])
		}
	}
	return string(b)
}
