package lockfile

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// bun.lock, the text lockfile Bun writes since 1.2. It is JSON with trailing
// commas allowed (JSONC). The binary bun.lockb is not supported: convert it
// with `bun install --save-text-lockfile`.
//
//	"packages": {
//	  "lodash": ["lodash@4.17.21", "", {}, "sha512-..."],
//	  "app/debug": ["debug@2.6.9", "", {...}, "sha512-..."],
//	  "my-lib": ["my-lib@workspace:packages/my-lib"],
//	}
//
// Element 0 is "name@version-or-spec". For registry packages element 1 is the
// registry URL ("" for the default) and the last string element is the SRI.

type bunLock struct {
	LockfileVersion json.RawMessage              `json:"lockfileVersion"`
	Packages        map[string][]json.RawMessage `json:"packages"`
}

func parseBun(data []byte) (*Result, error) {
	clean, err := jsoncToJSON(data)
	if err != nil {
		return nil, err
	}
	var lock bunLock
	if err := json.Unmarshal(clean, &lock); err != nil {
		return nil, fmt.Errorf("not valid JSON (after allowing trailing commas): %w", err)
	}
	res := &Result{Format: FormatBun, Version: string(lock.LockfileVersion)}
	keys := make([]string, 0, len(lock.Packages))
	for k := range lock.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		arr := lock.Packages[key]
		if len(arr) == 0 {
			continue
		}
		var ident string
		if err := json.Unmarshal(arr[0], &ident); err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: unreadable entry, skipped", key))
			continue
		}
		name, spec, ok := splitIdent(ident)
		if !ok {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: unreadable ident %q, skipped", key, ident))
			continue
		}
		p := Package{Name: name, Version: spec, Source: SourceRegistry}
		low := strings.ToLower(spec)
		switch {
		case strings.HasPrefix(low, "workspace:"), strings.HasPrefix(low, "file:"), strings.HasPrefix(low, "link:"):
			p.Source = SourceLocal
		case strings.HasPrefix(low, "github:"), strings.HasPrefix(low, "git+"), strings.HasPrefix(low, "git:"),
			strings.HasPrefix(low, "gitlab:"), strings.HasPrefix(low, "bitbucket:"):
			p.Source = SourceGit
			p.Resolved = spec
		case strings.HasPrefix(low, "http://"), strings.HasPrefix(low, "https://"):
			p.Source, p.Registry = classifyURL(spec)
			p.Resolved = spec
		default:
			if len(arr) > 1 {
				var reg string
				if json.Unmarshal(arr[1], &reg) == nil && reg != "" {
					if u, err := url.Parse(reg); err == nil {
						p.Registry = strings.ToLower(u.Hostname())
					}
				}
			}
			var last string
			if json.Unmarshal(arr[len(arr)-1], &last) == nil && strings.HasPrefix(last, "sha") && strings.Contains(last, "-") {
				p.Integrity = last
			}
		}
		res.Packages = append(res.Packages, p)
	}
	return res, nil
}

// jsoncToJSON removes // and /* */ comments and trailing commas outside of
// strings. It is deliberately small: bun.lock only uses trailing commas.
func jsoncToJSON(in []byte) ([]byte, error) {
	out := make([]byte, 0, len(in))
	inStr, esc := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			if i < len(in) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			end := strings.Index(string(in[i+2:]), "*/")
			if end < 0 {
				return nil, fmt.Errorf("unterminated comment")
			}
			i += end + 3
		case c == ',':
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\t' || in[j] == '\n' || in[j] == '\r') {
				j++
			}
			if j < len(in) && (in[j] == '}' || in[j] == ']') {
				continue // trailing comma
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	if inStr {
		return nil, fmt.Errorf("unterminated string")
	}
	return out, nil
}
