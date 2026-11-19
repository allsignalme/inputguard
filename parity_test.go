package inputguard

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/allsignalme/inputguard/internal/legacy"
)

// The engine this library grew out of is kept in internal/legacy as an oracle: configured like it, the new
// engine must clean and flag exactly the same way.

type corpusLine struct {
	ctx, payload string
	line         int
}

func readCorpus(t testing.TB, name string) []corpusLine {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var out []corpusLine
	for i, raw := range strings.Split(string(data), "\n") {
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		ctx, payload, ok := strings.Cut(raw, " ")
		if !ok {
			t.Fatalf("%s:%d: missing context", name, i+1)
		}
		out = append(out, corpusLine{ctx, payload, i + 1})
	}
	return out
}

func corpusPayloads(t testing.TB) []string {
	var out []string
	for _, f := range []string{"malicious.txt", "benign.txt"} {
		for _, l := range readCorpus(t, f) {
			out = append(out, l.payload)
		}
	}
	return out
}

func fromLegacyCtx(c legacy.Context) Context {
	switch c {
	case legacy.CtxURL:
		return CtxURL
	case legacy.CtxVerbatim:
		return CtxIdentifier
	case legacy.CtxSecret:
		return CtxSecret
	}
	return CtxText
}

func toLegacyCtx(c Context) legacy.Context {
	switch c {
	case CtxURL:
		return legacy.CtxURL
	case CtxIdentifier:
		return legacy.CtxVerbatim
	case CtxSecret:
		return legacy.CtxSecret
	}
	return legacy.CtxText
}

// legacyRules: the rules the old engine had.
var legacyRules = map[RuleID]bool{
	RuleTagDangerous: true, RuleTagGeneric: true, RuleEventHandler: true, RuleScheme: true,
	RuleTemplate: true, RuleJSCall: true, RuleJSBreakout: true, RuleControlChar: true, RuleTooComplex: true,
}

func parityGuard(t testing.TB, reject bool) *Guard {
	t.Helper()
	var off []RuleID
	for _, r := range Rules() {
		if !legacyRules[r.ID] {
			off = append(off, r.ID)
		}
	}
	opts := []Option{
		WithClassifier(func(k, v string) Context { return fromLegacyCtx(legacy.Classify(k, v)) }),
		WithoutRules(off...),
		WithLimits(Limits{MaxDepth: 33, MaxStringBytes: -1, MaxMembers: -1, MaxElements: -1}),
	}
	if reject {
		opts = append(opts, WithMode(ModeReject), WithProfile(ProfileStrict))
	}
	g, err := New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func ruleSet[T any](items []T, id func(T) RuleID) []string {
	seen := map[string]bool{}
	for _, it := range items {
		seen[string(id(it))] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestParity_CleanString(t *testing.T) {
	g := parityGuard(t, false)
	for _, s := range corpusPayloads(t) {
		for _, ctx := range []Context{CtxText, CtxURL, CtxIdentifier} {
			want, wantFs, wantChanged := legacy.CleanString(toLegacyCtx(ctx), s)
			got, rep := g.ProcessString(s, ctx)
			if got != want || rep.Changed != wantChanged {
				t.Errorf("[%v] %q:\n got  %q changed=%v\n want %q changed=%v", ctx, s, got, rep.Changed, want, wantChanged)
			}
			gr := ruleSet(rep.Findings, func(f Finding) RuleID { return f.Rule })
			wr := ruleSet(wantFs, func(f legacy.Finding) RuleID { return RuleID(f.Rule) })
			if !slices.Equal(gr, wr) {
				t.Errorf("[%v] %q: rules %v, want %v", ctx, s, gr, wr)
			}
		}
	}
}

func TestParity_StrictRules(t *testing.T) {
	g := parityGuard(t, true)
	for _, s := range corpusPayloads(t) {
		for _, ctx := range []Context{CtxText, CtxURL} {
			fs := legacy.Detect(s, legacy.DetectOptions{Strict: true, URL: ctx == CtxURL})
			want := ruleSet(fs, func(f legacy.Finding) RuleID { return RuleID(f.Rule) })
			if legacyHasControl(s) {
				want = append(want, string(RuleControlChar))
				sort.Strings(want)
			}
			rep := g.CheckString(s, ctx)
			got := ruleSet(rep.Findings, func(f Finding) RuleID { return f.Rule })
			if !slices.Equal(got, want) {
				t.Errorf("[%v] %q: rules %v, want %v", ctx, s, got, want)
			}
			if rep.Rejected != (len(want) > 0) {
				t.Errorf("[%v] %q: rejected=%v", ctx, s, rep.Rejected)
			}
		}
	}
}

func legacyHasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return true
		}
	}
	return false
}

// TestParity_MaybeDirty: the fast path never skips a body the old engine would clean or flag, and skips every body
// the old fast path skipped. (It skips more: a backslash before "u" or "x" only counts when an escape can follow,
// so Windows paths such as C:\Users stay on the fast path.)
func TestParity_MaybeDirty(t *testing.T) {
	g := parityGuard(t, false)
	for _, s := range corpusPayloads(t) {
		for _, body := range jsonBodies(s) {
			got := g.MaybeDirty(body)
			if got && !legacy.MaybeDirty(body) {
				t.Errorf("%s: MaybeDirty=true, legacy false", body)
			}
			if !got {
				if _, r, _ := legacy.CleanJSON(body, legacy.ModeClean, nil); r.Changed || len(r.Findings) > 0 {
					t.Errorf("%s: skipped, but the old engine flags %v", body, r.Findings)
				}
			}
		}
	}
}

// jsonBodies embeds s in a few JSON shapes, with and without HTML escaping.
func jsonBodies(s string) [][]byte {
	var out [][]byte
	for _, v := range []any{
		map[string]any{"description": s},
		map[string]any{"url": s, "n": 1},
		[]any{s, map[string]any{"a": []any{s}}},
		map[string]any{s: "x"},
		map[string]any{"embedded": mustJSON(map[string]any{"note": s}, false)},
	} {
		out = append(out, mustJSON(v, true), mustJSON(v, false))
	}
	return out
}

func mustJSON(v any, escapeHTML bool) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func decodeAny(t testing.TB, b []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, b)
	}
	return v
}

func checkJSONParity(t *testing.T, g *Guard, body []byte) {
	t.Helper()
	want, wrep, _ := legacy.CleanJSON(body, legacy.ModeClean, nil)
	got, grep := g.ProcessJSON(body)
	if grep.Changed != wrep.Changed {
		t.Errorf("%s: changed=%v, legacy %v", body, grep.Changed, wrep.Changed)
	}
	if !reflect.DeepEqual(decodeAny(t, got), decodeAny(t, want)) {
		t.Errorf("%s:\n got  %s\n want %s", body, got, want)
	}
	gp := findingKeys(grep.Findings, func(f Finding) (string, RuleID) { return f.Path, f.Rule })
	wp := findingKeys(wrep.Findings, func(f legacy.PathFinding) (string, RuleID) { return f.Path, RuleID(f.Rule) })
	if !slices.Equal(gp, wp) {
		t.Errorf("%s: findings %v, legacy %v", body, gp, wp)
	}
}

func findingKeys[T any](fs []T, key func(T) (string, RuleID)) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		p, r := key(f)
		out = append(out, p+" "+string(r))
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func TestParity_JSON_Corpus(t *testing.T) {
	g := parityGuard(t, false)
	for _, s := range corpusPayloads(t) {
		for _, body := range jsonBodies(s) {
			checkJSONParity(t, g, body)
		}
	}
}

// TestParity_JSON_Fixtures injects each payload into each string leaf of real payloads.
func TestParity_JSON_Fixtures(t *testing.T) {
	g := parityGuard(t, false)
	payloads := corpusPayloads(t)
	for _, name := range []string{"app_capi_events.json", "collect_browser.json"} {
		raw, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		checkJSONParity(t, g, raw)
		leaves := countLeaves(decodeAny(t, raw))
		for i, s := range payloads {
			v := decodeAny(t, raw)
			n := i % leaves
			setLeaf(v, &n, s)
			checkJSONParity(t, g, mustJSON(v, i%2 == 0))
		}
	}
}

func countLeaves(v any) int {
	switch x := v.(type) {
	case string:
		return 1
	case map[string]any:
		n := 0
		for _, e := range x {
			n += countLeaves(e)
		}
		return n
	case []any:
		n := 0
		for _, e := range x {
			n += countLeaves(e)
		}
		return n
	}
	return 0
}

// setLeaf replaces the n-th string leaf (in sorted key order).
func setLeaf(v any, n *int, s string) (any, bool) {
	switch x := v.(type) {
	case string:
		if *n == 0 {
			*n = -1
			return s, true
		}
		*n--
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if nv, ok := setLeaf(x[k], n, s); ok {
				x[k] = nv
			}
			if *n < 0 {
				return v, false
			}
		}
	case []any:
		for i := range x {
			if nv, ok := setLeaf(x[i], n, s); ok {
				x[i] = nv
			}
			if *n < 0 {
				return v, false
			}
		}
	}
	return v, false
}

func FuzzParity_CleanString(f *testing.F) {
	for _, s := range corpusPayloads(f) {
		f.Add(s, uint8(0))
	}
	g := parityGuard(f, false)
	f.Fuzz(func(t *testing.T, s string, c uint8) {
		if !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool { return r >= 0x80 && r <= 0x9f }) {
			// Two deliberate differences. The old engine replaced invalid UTF-8 only as a side effect of strings.Map
			// when it stripped a control character (here: RuleInvalidUTF8, off in the parity configuration), and
			// RuleControlChar now covers C1 controls (U+0080–U+009F: NEL, CSI…) as well as C0 and DEL.
			return
		}
		ctx := []Context{CtxText, CtxURL, CtxIdentifier}[int(c)%3]
		want, _, wantChanged := legacy.CleanString(toLegacyCtx(ctx), s)
		got, rep := g.ProcessString(s, ctx)
		if got != want || rep.Changed != wantChanged {
			t.Errorf("[%v] %q: got %q (%v), want %q (%v)", ctx, s, got, rep.Changed, want, wantChanged)
		}
	})
}
