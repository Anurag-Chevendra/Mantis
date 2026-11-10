package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Anurag-Chevendra/mantis/internal/auth"
	"github.com/Anurag-Chevendra/mantis/internal/report"
)

// fakeCohen serves the console's device flow and the API.
type fakeCohen struct {
	srv      *httptest.Server
	mu       sync.Mutex
	revoked  []string
	received [][]string
	queued   [][]string
}

const goodKey = "cohen_live_TESTKEYTESTKEYTESTKEY"

func newFakeCohen(t *testing.T) *fakeCohen {
	f := &fakeCohen{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/device/code":
			json.NewEncoder(w).Encode(map[string]any{"device_code": "d1", "user_code": "ABCD-EFGH",
				"verification_uri": f.srv.URL + "/device", "expires_in": 600, "interval": 1})
		case "/oauth/token":
			json.NewEncoder(w).Encode(map[string]any{"access_token": goodKey, "token_type": "Bearer", "scope": "read queue"})
		case "/oauth/revoke":
			r.ParseForm()
			f.mu.Lock()
			f.revoked = append(f.revoked, r.Form.Get("token"))
			f.mu.Unlock()
		case "/api/key":
			if r.Header.Get("Authorization") != "Bearer "+goodKey {
				w.WriteHeader(401)
				io.WriteString(w, `{"error":"invalid_key","message":"That key is not valid."}`)
				return
			}
			io.WriteString(w, `{"tier":"individual","analyses":{"used":3,"limit":150,"resets":"2026-12-01"},"lookups_today":{"used":0,"limit":null},"key":{"scopes":["read","queue","evidence"],"in_grace":false}}`)
		case "/api/package/npm":
			if r.Header.Get("Authorization") != "Bearer "+goodKey {
				w.WriteHeader(401)
				io.WriteString(w, `{"error":"invalid_key","message":"That key is not valid."}`)
				return
			}
			var body struct {
				Versions     []string `json:"versions"`
				QueueUnknown bool     `json:"queue_unknown"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			if body.QueueUnknown {
				f.queued = append(f.queued, body.Versions)
			} else {
				f.received = append(f.received, body.Versions)
			}
			f.mu.Unlock()
			resp := map[string]any{"scan": "s1", "counts": map[string]int{}, "review": []any{}, "unknown": []any{}, "queued": []any{}}
			review, unknown, queued := []any{}, []any{}, []any{}
			clean := 0
			for _, v := range body.Versions {
				i := strings.LastIndex(v, "@")
				n, ver := v[:i], v[i+1:]
				// Like the real console: known verdicts are answered, and only
				// versions nobody has analysed are queued.
				switch {
				case n == "left-pad":
					review = append(review, map[string]string{"name": n, "version": ver, "verdict": "review"})
				case n == "is-number" && body.QueueUnknown:
					queued = append(queued, map[string]string{"name": n, "version": ver, "job": "job_1"})
				case n == "is-number":
					unknown = append(unknown, map[string]string{"name": n, "version": ver})
				default:
					clean++
				}
			}
			resp["review"], resp["unknown"], resp["queued"] = review, unknown, queued
			resp["counts"] = map[string]int{"clean": clean, "review": len(review), "queued": len(queued)}
			w.WriteHeader(207)
			json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func testEnv(t *testing.T, f *fakeCohen, extra map[string]string) (*Env, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	vars := map[string]string{"MANTIS_API_URL": f.srv.URL, "MANTIS_CONSOLE_URL": f.srv.URL}
	for k, v := range extra {
		vars[k] = v
	}
	return &Env{
		Stdin:  strings.NewReader(""),
		Stdout: &out, Stderr: &errb,
		Getenv: func(k string) string { return vars[k] },
		Store:  auth.File{Path: filepath.Join(t.TempDir(), "creds.json")},
		HTTP:   f.srv.Client(),
	}, &out, &errb
}

var fixture = filepath.Join("..", "..", "testdata", "npm-v3")

func TestDepsJSON(t *testing.T) {
	f := newFakeCohen(t)
	env, out, _ := testEnv(t, f, nil)
	if code := Run([]string{"deps", fixture, "--format", "json"}, env); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var inv report.Inventory
	if err := json.Unmarshal(out.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	if inv.SchemaVersion != 1 || inv.Summary.Total != 8 || inv.Summary.Send != 6 || inv.Summary.HeldBack != 2 {
		t.Fatalf("summary %+v", inv.Summary)
	}
	if strings.Contains(out.String(), "/home/") || strings.Contains(out.String(), "/tmp/") {
		t.Fatal("report leaks absolute paths")
	}
	for _, p := range inv.Packages {
		if p.Name == "@sindresorhus/is" && p.PURL != "pkg:npm/%40sindresorhus/is@4.6.0" {
			t.Errorf("purl %q", p.PURL)
		}
	}
	if len(f.received) != 0 {
		t.Fatal("deps must never touch the network")
	}
}

func TestDepsCycloneDX(t *testing.T) {
	f := newFakeCohen(t)
	env, out, _ := testEnv(t, f, nil)
	if code := Run([]string{"deps", "--format", "cyclonedx", fixture}, env); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			Name   string                          `json:"name"`
			PURL   string                          `json:"purl"`
			Hashes []struct{ Alg, Content string } `json:"hashes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BomFormat != "CycloneDX" || doc.SpecVersion != "1.5" || len(doc.Components) != 8 {
		t.Fatalf("%+v", doc)
	}
	var hashed bool
	for _, c := range doc.Components {
		if c.Name == "lodash" && len(c.Hashes) == 1 && c.Hashes[0].Alg == "SHA-512" && len(c.Hashes[0].Content) == 128 {
			hashed = true
		}
	}
	if !hashed {
		t.Fatal("lodash SHA-512 hash missing")
	}
}

func TestScanNotLoggedIn(t *testing.T) {
	f := newFakeCohen(t)
	env, _, errb := testEnv(t, f, nil)
	if code := Run([]string{"scan", fixture}, env); code != ExitAuth {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(errb.String(), "mantis login") {
		t.Fatalf("unhelpful message: %s", errb)
	}
}

func TestLoginScanWhoamiLogout(t *testing.T) {
	f := newFakeCohen(t)
	env, out, errb := testEnv(t, f, nil)

	// login (device flow; polling sleeps 1s once)
	if code := Run([]string{"login", "--no-browser", "--device-name", "ci-box"}, env); code != 0 {
		t.Fatalf("login exit %d: %s", code, errb)
	}
	if !strings.Contains(errb.String(), "A B C D - E F G H") || !strings.Contains(errb.String(), "Mantis on ci-box") {
		t.Fatalf("login output missing code or device name:\n%s", errb)
	}
	if strings.Contains(errb.String(), goodKey) {
		t.Fatal("login printed the key")
	}

	// scan: left-pad needs review -> exit 1, only public versions sent
	errb.Reset()
	if code := Run([]string{"scan", fixture}, env); code != ExitReview {
		t.Fatalf("scan exit %d: %s", code, errb)
	}
	if len(f.received) != 1 || len(f.received[0]) != 6 {
		t.Fatalf("sent %v", f.received)
	}
	for _, v := range f.received[0] {
		if strings.HasPrefix(v, "slugify") || strings.HasPrefix(v, "localpkg") {
			t.Fatalf("held back package was sent: %s", v)
		}
	}
	if !strings.Contains(errb.String(), "REVIEW") || !strings.Contains(errb.String(), "left-pad@1.3.0") {
		t.Fatalf("review not shown:\n%s", errb)
	}

	// --fail-on none -> exit 0
	if code := Run([]string{"scan", fixture, "--fail-on", "none"}, env); code != 0 {
		t.Fatalf("fail-on none exit %d", code)
	}

	// --analyze without a terminal and without --yes must refuse to spend
	if code := Run([]string{"scan", fixture, "--analyze"}, env); code != ExitUsage {
		t.Fatalf("analyze without --yes exit %d", code)
	}
	if len(f.queued) != 0 {
		t.Fatal("analyses were queued without confirmation")
	}
	// with --yes it checks and queues in one request (one scan in history)
	out.Reset()
	before := len(f.received)
	if code := Run([]string{"scan", fixture, "--analyze", "--yes", "--format", "json", "--fail-on", "none"}, env); code != 0 {
		t.Fatalf("analyze --yes exit %d", code)
	}
	if len(f.queued) != 1 || len(f.received) != before {
		t.Fatalf("want exactly one queueing request, got queued %v", f.queued)
	}
	var inv report.Inventory
	if err := json.Unmarshal(out.Bytes(), &inv); err != nil || inv.Check == nil || len(inv.Check.Queued) != 1 {
		t.Fatalf("json check: %v %+v", err, inv.Check)
	}

	// whoami
	out.Reset()
	if code := Run([]string{"whoami"}, env); code != 0 || !strings.Contains(out.String(), "individual") {
		t.Fatalf("whoami %s", out)
	}

	// logout revokes remotely and forgets locally
	if code := Run([]string{"logout"}, env); code != 0 {
		t.Fatal("logout failed")
	}
	if len(f.revoked) != 1 || f.revoked[0] != goodKey {
		t.Fatalf("revoked %v", f.revoked)
	}
	if code := Run([]string{"scan", fixture}, env); code != ExitAuth {
		t.Fatalf("after logout exit %d", code)
	}
}

func TestEnvTokenAndBadKey(t *testing.T) {
	f := newFakeCohen(t)
	env, _, _ := testEnv(t, f, map[string]string{"MANTIS_TOKEN": goodKey})
	if code := Run([]string{"scan", fixture, "--fail-on", "none"}, env); code != 0 {
		t.Fatalf("env token exit %d", code)
	}
	env, _, errb := testEnv(t, f, map[string]string{"MANTIS_TOKEN": "cohen_live_wrong"})
	if code := Run([]string{"scan", fixture}, env); code != ExitAuth {
		t.Fatalf("bad key exit %d: %s", code, errb)
	}
}

func TestRefusesPlainHTTP(t *testing.T) {
	f := newFakeCohen(t)
	env, _, _ := testEnv(t, f, map[string]string{"MANTIS_TOKEN": goodKey, "MANTIS_API_URL": "http://api.snappyfeet.org"})
	if code := Run([]string{"scan", fixture}, env); code != ExitUsage {
		t.Fatalf("plain http should be refused, exit %d", code)
	}
}

func TestDryRunMakesNoRequest(t *testing.T) {
	f := newFakeCohen(t)
	env, out, _ := testEnv(t, f, nil) // not even logged in
	if code := Run([]string{"scan", "--dry-run", fixture}, env); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(f.received) != 0 || !strings.Contains(out.String(), `"versions"`) {
		t.Fatalf("dry run sent a request or printed nothing: %s", out)
	}
}

func TestNoLockfile(t *testing.T) {
	f := newFakeCohen(t)
	env, _, errb := testEnv(t, f, nil)
	if code := Run([]string{"deps", t.TempDir()}, env); code != ExitUsage || !strings.Contains(errb.String(), "no lockfile") {
		t.Fatalf("exit %d: %s", code, errb)
	}
}

func TestUnknownCommand(t *testing.T) {
	f := newFakeCohen(t)
	env, _, _ := testEnv(t, f, nil)
	if code := Run([]string{"frobnicate"}, env); code != ExitUsage {
		t.Fatalf("exit %d", code)
	}
}
