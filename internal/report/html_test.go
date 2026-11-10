package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/Anurag-Chevendra/mantis/internal/api"
	"github.com/Anurag-Chevendra/mantis/internal/lockfile"
	"github.com/Anurag-Chevendra/mantis/internal/policy"
)

func TestHTMLIsSelfContainedAndPinned(t *testing.T) {
	evil := `x</script><script>alert(1)</script>`
	inv := &Inventory{Tool: Tool{Name: "mantis", Version: "0.1.0"},
		Packages: []Package{{Decision: policy.Decision{Package: lockfile.Package{Name: evil, Version: "1.0.0", Source: lockfile.SourceRegistry}, Send: true}}},
		Check:    &api.CheckResult{Review: []api.Verdict{{Name: evil, Version: "1.0.0", Verdict: "REVIEW"}}},
	}
	var b bytes.Buffer
	if err := WriteHTML(&b, inv, HTMLOptions{Title: `<b>t</b>`, FeedURL: "https://trail.snappyfeet.org/?p="}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Count(out, "</script>") != 2 {
		t.Fatal("untrusted data closed a script element")
	}
	if strings.Contains(out, "<b>t</b>") {
		t.Fatal("title not escaped")
	}
	for _, bad := range []string{"<link", "src=\"http", "@import", "url(http", "fetch(", "XMLHttpRequest", "innerHTML"} {
		if strings.Contains(out, bad) {
			t.Fatalf("report contains %q", bad)
		}
	}
	csp := regexp.MustCompile(`script-src '([^']+)'`).FindStringSubmatch(out)
	if csp == nil || csp[1] != hash(htmlScript) {
		t.Fatal("script hash missing from CSP")
	}
	if !strings.Contains(out, "default-src 'none'") || !strings.Contains(out, hash(htmlStyle)) {
		t.Fatal("CSP is not locked down")
	}
}
