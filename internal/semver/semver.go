// Package semver implements npm's flavour of semantic versioning: version
// parsing and ordering, and range matching with the same desugaring and
// prerelease rules as the semver package npm itself uses (loose: false,
// includePrerelease: false).
//
// It is tested differentially against npm's bundled semver; see
// testdata/semver_corpus.json and semver_test.go.
package semver

import (
	"errors"
	"strconv"
	"strings"
)

// Version is a parsed semver 2.0.0 version.
type Version struct {
	Major, Minor, Patch uint64
	Pre                 []ident // prerelease identifiers
	Raw                 string
}

type ident struct {
	num   uint64
	str   string
	isNum bool
}

// Parse parses a version. A leading "v" or "=" and surrounding spaces are
// allowed, as in npm. Build metadata is accepted and ignored for ordering.
func Parse(s string) (Version, error) {
	raw := s
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "=v")
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, errors.New("empty version")
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if !validIdents(s[i+1:], false) {
			return Version{}, errors.New("invalid build metadata")
		}
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s, pre = s[:i], s[i+1:]
		if !validIdents(pre, true) {
			return Version{}, errors.New("invalid prerelease")
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, errors.New("version needs major.minor.patch")
	}
	var nums [3]uint64
	for i, p := range parts {
		n, err := parseNum(p)
		if err != nil {
			return Version{}, err
		}
		nums[i] = n
	}
	v := Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Raw: raw}
	if pre != "" {
		for _, id := range strings.Split(pre, ".") {
			if n, err := strconv.ParseUint(id, 10, 64); err == nil && isDigits(id) {
				v.Pre = append(v.Pre, ident{num: n, isNum: true, str: id})
			} else {
				v.Pre = append(v.Pre, ident{str: id})
			}
		}
	}
	return v, nil
}

func parseNum(p string) (uint64, error) {
	if p == "" || !isDigits(p) {
		return 0, errors.New("invalid number " + strconv.Quote(p))
	}
	if len(p) > 1 && p[0] == '0' {
		return 0, errors.New("leading zero in " + p)
	}
	if len(p) > 16 { // npm caps at Number.MAX_SAFE_INTEGER
		return 0, errors.New("number too large")
	}
	n, err := strconv.ParseUint(p, 10, 64)
	if err != nil || n > 9007199254740991 {
		return 0, errors.New("number too large")
	}
	return n, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validIdents(s string, pre bool) bool {
	if s == "" {
		return false
	}
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		for i := 0; i < len(id); i++ {
			c := id[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
				return false
			}
		}
		if pre && isDigits(id) && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

// String is the canonical form without build metadata.
func (v Version) String() string {
	s := strconv.FormatUint(v.Major, 10) + "." + strconv.FormatUint(v.Minor, 10) + "." + strconv.FormatUint(v.Patch, 10)
	if len(v.Pre) > 0 {
		ids := make([]string, len(v.Pre))
		for i, p := range v.Pre {
			ids[i] = p.str
		}
		s += "-" + strings.Join(ids, ".")
	}
	return s
}

// Compare returns -1, 0 or 1.
func Compare(a, b Version) int {
	switch {
	case a.Major != b.Major:
		return cmpU(a.Major, b.Major)
	case a.Minor != b.Minor:
		return cmpU(a.Minor, b.Minor)
	case a.Patch != b.Patch:
		return cmpU(a.Patch, b.Patch)
	}
	// A version without prerelease is greater than one with.
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; ; i++ {
		switch {
		case i >= len(a.Pre) && i >= len(b.Pre):
			return 0
		case i >= len(a.Pre):
			return -1
		case i >= len(b.Pre):
			return 1
		}
		x, y := a.Pre[i], b.Pre[i]
		switch {
		case x.isNum && y.isNum:
			if x.num != y.num {
				return cmpU(x.num, y.num)
			}
		case x.isNum:
			return -1 // numeric identifiers sort before alphanumeric
		case y.isNum:
			return 1
		default:
			if x.str != y.str {
				if x.str < y.str {
					return -1
				}
				return 1
			}
		}
	}
}

func cmpU(a, b uint64) int {
	if a < b {
		return -1
	}
	return 1
}

// ---- ranges ------------------------------------------------------------------

type op int

const (
	opEQ op = iota
	opLT
	opLTE
	opGT
	opGTE
	opAny
)

type comparator struct {
	op op
	v  Version
}

func (c comparator) test(v Version) bool {
	switch c.op {
	case opAny:
		return true
	case opEQ:
		return Compare(v, c.v) == 0
	case opLT:
		return Compare(v, c.v) < 0
	case opLTE:
		return Compare(v, c.v) <= 0
	case opGT:
		return Compare(v, c.v) > 0
	default:
		return Compare(v, c.v) >= 0
	}
}

// Range is a parsed npm range: an OR of AND comparator sets.
type Range struct {
	sets [][]comparator
	Raw  string
}

// ParseRange parses an npm range such as "^1.2.3", "~1.2 || >=3.0.0 <4",
// "1.2.3 - 2.0", "1.x", "*" or "".
func ParseRange(s string) (Range, error) {
	r := Range{Raw: s}
	for _, part := range strings.Split(s, "||") {
		set, err := parseSet(strings.TrimSpace(part))
		if err != nil {
			return Range{}, err
		}
		r.sets = append(r.sets, set)
	}
	return r, nil
}

// Satisfies reports whether v is in the range, following npm's prerelease
// rule: a prerelease version only matches a set that names a prerelease of
// the same major.minor.patch.
func (r Range) Satisfies(v Version) bool {
	for _, set := range r.sets {
		if testSet(set, v) {
			return true
		}
	}
	return false
}

func testSet(set []comparator, v Version) bool {
	for _, c := range set {
		if !c.test(v) {
			return false
		}
	}
	if len(v.Pre) == 0 {
		return true
	}
	for _, c := range set {
		if c.op == opAny {
			continue
		}
		if len(c.v.Pre) > 0 && c.v.Major == v.Major && c.v.Minor == v.Minor && c.v.Patch == v.Patch {
			return true
		}
	}
	return false
}

// partial is a possibly incomplete version: "1", "1.2", "1.x", "*".
type partial struct {
	major, minor, patch    uint64
	nMajor, nMinor, nPatch bool // false when the part is missing or a wildcard
	pre                    []ident
	preRaw                 string
}

func (p partial) any() bool { return !p.nMajor }

func parsePartial(s string) (partial, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "=v")
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var p partial
	if s == "" || s == "*" || s == "x" || s == "X" {
		return p, nil
	}
	core := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core, p.preRaw = s[:i], s[i+1:]
		if !validIdents(p.preRaw, true) {
			return p, errors.New("invalid prerelease in " + strconv.Quote(s))
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) > 3 {
		return p, errors.New("invalid version " + strconv.Quote(s))
	}
	wild := false
	for i, part := range parts {
		if part == "x" || part == "X" || part == "*" {
			wild = true
			continue
		}
		if wild {
			// npm treats everything after a wildcard as a wildcard: "1.x.3" is "1.x".
			if _, err := parseNum(part); err != nil {
				return p, err
			}
			continue
		}
		n, err := parseNum(part)
		if err != nil {
			return p, err
		}
		switch i {
		case 0:
			p.major, p.nMajor = n, true
		case 1:
			p.minor, p.nMinor = n, true
		case 2:
			p.patch, p.nPatch = n, true
		}
	}
	if p.preRaw != "" {
		if len(parts) < 3 {
			return p, errors.New("prerelease needs major.minor.patch in " + strconv.Quote(s))
		}
		if !p.nPatch {
			// npm accepts a prerelease on a wildcard version and ignores it.
			p.preRaw = ""
			return p, nil
		}
		v, err := Parse(core + "-" + p.preRaw)
		if err != nil {
			return p, err
		}
		p.pre = v.Pre
	}
	return p, nil
}

func ver(major, minor, patch uint64, pre []ident) Version {
	return Version{Major: major, Minor: minor, Patch: patch, Pre: pre}
}

// zero is the "-0" prerelease npm appends to exclusive upper bounds.
var zero = []ident{{num: 0, isNum: true, str: "0"}}

func full(p partial) Version { return ver(p.major, p.minor, p.patch, p.pre) }

func parseSet(s string) ([]comparator, error) {
	if s == "" {
		return []comparator{{op: opAny}}, nil
	}
	// hyphen range: "a - b" (spaces required around the dash)
	if a, b, ok := cutHyphen(s); ok {
		return hyphen(a, b)
	}
	toks := tokens(s)
	var out []comparator
	for _, t := range toks {
		cs, err := primitive(t)
		if err != nil {
			return nil, err
		}
		out = append(out, cs...)
	}
	if len(out) == 0 {
		return []comparator{{op: opAny}}, nil
	}
	return out, nil
}

func cutHyphen(s string) (string, string, bool) {
	i := strings.Index(s, " - ")
	if i < 0 {
		return "", "", false
	}
	a, b := strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+3:])
	if a == "" || b == "" || strings.ContainsAny(a, " <>~^") || strings.ContainsAny(b, " <>~^") {
		return "", "", false
	}
	return a, b, true
}

// tokens splits on whitespace but keeps an operator attached to the version
// that follows it ("> 1.2" is one comparator).
func tokens(s string) []string {
	fields := strings.Fields(s)
	var out []string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if isOperator(f) && i+1 < len(fields) {
			f += fields[i+1]
			i++
		}
		out = append(out, f)
	}
	return out
}

func isOperator(s string) bool {
	switch s {
	case "<", ">", "<=", ">=", "=", "~", "^", "~>":
		return true
	}
	return false
}

func hyphen(a, b string) ([]comparator, error) {
	from, err := parsePartial(a)
	if err != nil {
		return nil, err
	}
	to, err := parsePartial(b)
	if err != nil {
		return nil, err
	}
	var out []comparator
	if from.any() {
		// no lower bound
	} else {
		out = append(out, comparator{op: opGTE, v: ver(from.major, from.minor, from.patch, from.pre)})
	}
	switch {
	case to.any():
	case !to.nMinor:
		out = append(out, comparator{op: opLT, v: ver(to.major+1, 0, 0, zero)})
	case !to.nPatch:
		out = append(out, comparator{op: opLT, v: ver(to.major, to.minor+1, 0, zero)})
	default:
		out = append(out, comparator{op: opLTE, v: full(to)})
	}
	if len(out) == 0 {
		out = []comparator{{op: opAny}}
	}
	return out, nil
}

func primitive(t string) ([]comparator, error) {
	switch {
	case strings.HasPrefix(t, "~>"):
		return tilde(t[2:])
	case strings.HasPrefix(t, "~"):
		return tilde(t[1:])
	case strings.HasPrefix(t, "^"):
		return caret(t[1:])
	case strings.HasPrefix(t, ">="):
		return cmpPartial(opGTE, t[2:])
	case strings.HasPrefix(t, "<="):
		return cmpPartial(opLTE, t[2:])
	case strings.HasPrefix(t, ">"):
		return cmpPartial(opGT, t[1:])
	case strings.HasPrefix(t, "<"):
		return cmpPartial(opLT, t[1:])
	case strings.HasPrefix(t, "="):
		return xrange(t[1:])
	default:
		return xrange(t)
	}
}

func xrange(s string) ([]comparator, error) {
	p, err := parsePartial(s)
	if err != nil {
		return nil, err
	}
	switch {
	case p.any():
		return []comparator{{op: opAny}}, nil
	case !p.nMinor:
		return []comparator{{op: opGTE, v: ver(p.major, 0, 0, nil)}, {op: opLT, v: ver(p.major+1, 0, 0, zero)}}, nil
	case !p.nPatch:
		return []comparator{{op: opGTE, v: ver(p.major, p.minor, 0, nil)}, {op: opLT, v: ver(p.major, p.minor+1, 0, zero)}}, nil
	default:
		return []comparator{{op: opEQ, v: full(p)}}, nil
	}
}

func cmpPartial(o op, s string) ([]comparator, error) {
	p, err := parsePartial(s)
	if err != nil {
		return nil, err
	}
	if p.any() {
		if o == opGT || o == opLT {
			// ">*" and "<*" match nothing
			return []comparator{{op: opLT, v: ver(0, 0, 0, zero)}}, nil
		}
		return []comparator{{op: opAny}}, nil
	}
	if p.nPatch {
		return []comparator{{op: o, v: full(p)}}, nil
	}
	// Partial versions with an operator, as npm desugars them.
	switch o {
	case opGT:
		if !p.nMinor {
			return []comparator{{op: opGTE, v: ver(p.major+1, 0, 0, nil)}}, nil
		}
		return []comparator{{op: opGTE, v: ver(p.major, p.minor+1, 0, nil)}}, nil
	case opGTE:
		return []comparator{{op: opGTE, v: ver(p.major, p.minor, 0, nil)}}, nil
	case opLT:
		return []comparator{{op: opLT, v: ver(p.major, p.minor, 0, zero)}}, nil
	default: // opLTE
		if !p.nMinor {
			return []comparator{{op: opLT, v: ver(p.major+1, 0, 0, zero)}}, nil
		}
		return []comparator{{op: opLT, v: ver(p.major, p.minor+1, 0, zero)}}, nil
	}
}

func tilde(s string) ([]comparator, error) {
	p, err := parsePartial(s)
	if err != nil {
		return nil, err
	}
	switch {
	case p.any():
		return []comparator{{op: opAny}}, nil
	case !p.nMinor:
		return []comparator{{op: opGTE, v: ver(p.major, 0, 0, nil)}, {op: opLT, v: ver(p.major+1, 0, 0, zero)}}, nil
	case !p.nPatch:
		return []comparator{{op: opGTE, v: ver(p.major, p.minor, 0, nil)}, {op: opLT, v: ver(p.major, p.minor+1, 0, zero)}}, nil
	default:
		return []comparator{{op: opGTE, v: full(p)}, {op: opLT, v: ver(p.major, p.minor+1, 0, zero)}}, nil
	}
}

func caret(s string) ([]comparator, error) {
	p, err := parsePartial(s)
	if err != nil {
		return nil, err
	}
	switch {
	case p.any():
		return []comparator{{op: opAny}}, nil
	case !p.nMinor:
		return []comparator{{op: opGTE, v: ver(p.major, 0, 0, nil)}, {op: opLT, v: ver(p.major+1, 0, 0, zero)}}, nil
	case !p.nPatch:
		if p.major == 0 {
			return []comparator{{op: opGTE, v: ver(0, p.minor, 0, nil)}, {op: opLT, v: ver(0, p.minor+1, 0, zero)}}, nil
		}
		return []comparator{{op: opGTE, v: ver(p.major, p.minor, 0, nil)}, {op: opLT, v: ver(p.major+1, 0, 0, zero)}}, nil
	}
	lo := comparator{op: opGTE, v: full(p)}
	switch {
	case p.major != 0:
		return []comparator{lo, {op: opLT, v: ver(p.major+1, 0, 0, zero)}}, nil
	case p.minor != 0:
		return []comparator{lo, {op: opLT, v: ver(0, p.minor+1, 0, zero)}}, nil
	default:
		return []comparator{lo, {op: opLT, v: ver(0, 0, p.patch+1, zero)}}, nil
	}
}

// MaxSatisfying returns the index of the highest version in vs that
// satisfies r, or -1.
func MaxSatisfying(vs []Version, r Range) int {
	best := -1
	for i, v := range vs {
		if r.Satisfies(v) && (best < 0 || Compare(v, vs[best]) > 0) {
			best = i
		}
	}
	return best
}
