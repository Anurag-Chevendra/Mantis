package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDepsOpenWritesHTMLAndOpensIt(t *testing.T) {
	f := newFakeCohen(t)
	env, out, _ := testEnv(t, f, nil)
	var opened string
	env.OpenBrowser = func(u string) error { opened = u; return nil }
	if code := Run([]string{"deps", fixture, "--open"}, env); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if out.Len() != 0 {
		t.Fatal("--open should not print the report to stdout")
	}
	u, err := url.Parse(opened)
	if err != nil || u.Scheme != "file" {
		t.Fatalf("opened %q", opened)
	}
	p := u.Path
	if len(p) > 2 && p[2] == ':' { // /C:/...
		p = p[1:]
	}
	b, err := os.ReadFile(filepath.FromSlash(p))
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.FromSlash(p))
	if !strings.Contains(string(b), "Content-Security-Policy") || !strings.Contains(string(b), "@sindresorhus/is") {
		t.Fatal("report content missing")
	}
	if len(f.received) != 0 {
		t.Fatal("deps must never touch the API")
	}
}

func TestDepsResolvesPackageJSONWithoutLockfile(t *testing.T) {
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		docs := map[string]any{
			"/left": map[string]any{"name": "left", "dist-tags": map[string]string{"latest": "1.2.0"},
				"versions": map[string]any{"1.2.0": map[string]any{"version": "1.2.0", "dependencies": map[string]string{"right": "^2"}}}},
			"/right": map[string]any{"name": "right", "dist-tags": map[string]string{"latest": "2.1.0"},
				"versions": map[string]any{"2.1.0": map[string]any{"version": "2.1.0"}}},
		}
		d, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(d)
	}))
	defer reg.Close()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"p","dependencies":{"left":"^1"}}`), 0o644)

	f := newFakeCohen(t)
	env, out, _ := testEnv(t, f, nil)
	env.HTTP = reg.Client()
	if code := Run([]string{"deps", dir, "--registry", reg.URL, "--format", "json"}, env); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), `"right"`) || !strings.Contains(out.String(), `"2.1.0"`) {
		t.Fatalf("transitive dependency missing: %s", out.String())
	}

	env, _, errb := testEnv(t, f, nil)
	if code := Run([]string{"deps", dir, "--offline"}, env); code != ExitUsage {
		t.Fatalf("--offline should refuse to resolve, exit %d", code)
	}
	if !strings.Contains(errb.String(), "drop --offline") {
		t.Fatalf("unhelpful message: %s", errb.String())
	}
}

func TestConfirmIgnoresBlankLines(t *testing.T) {
	for in, want := range map[string]bool{"\n\ny\n": true, "\nyes\n": true, "\n\n": false, "": false, "maybe\nn\n": false, "\nY\n": true} {
		var errb strings.Builder
		env := &Env{Stdin: strings.NewReader(in), Stderr: &errb}
		if got := confirm(env); got != want {
			t.Errorf("confirm(%q) = %v, want %v", in, got, want)
		}
	}
}
