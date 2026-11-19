package inputguard

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type ruleLine struct {
	expect  string
	ctx     Context
	payload string
	line    int
}

var ctxNames = map[string]Context{
	"text": CtxText, "url": CtxURL, "redirect": CtxRedirect, "id": CtxIdentifier, "path": CtxPath, "header": CtxHeader,
}

func readRuleCorpus(t testing.TB) []ruleLine {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "rules.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var out []ruleLine
	for i, raw := range strings.Split(string(data), "\n") {
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		parts := strings.SplitN(raw, " ", 3)
		if len(parts) != 3 {
			t.Fatalf("rules.txt:%d: want 3 fields", i+1)
		}
		ctx, ok := ctxNames[parts[1]]
		if !ok {
			t.Fatalf("rules.txt:%d: unknown context %q", i+1, parts[1])
		}
		p := parts[2]
		if strings.HasPrefix(p, `"`) {
			if u, err := strconv.Unquote(p); err == nil {
				p = u
			}
		}
		if parts[0] != "ok" {
			if _, known := LookupRule(RuleID(parts[0])); !known {
				t.Fatalf("rules.txt:%d: unknown rule %q", i+1, parts[0])
			}
		}
		out = append(out, ruleLine{parts[0], ctx, p, i + 1})
	}
	return out
}

func strictAll(t testing.TB, opts ...Option) *Guard {
	t.Helper()
	base := []Option{
		WithMode(ModeReject), WithProfile(ProfileStrict),
		WithCategories(CatXSS, CatTemplate, CatInjection, CatUnicode, CatStructure, CatOutput),
		WithRedirectHosts("shop.example.com"),
	}
	g, err := New(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestRuleCorpus(t *testing.T) {
	g := strictAll(t)
	lines := readRuleCorpus(t)
	if len(lines) < 150 {
		t.Fatalf("corpus too small: %d", len(lines))
	}
	for _, l := range lines {
		r := g.CheckString(l.payload, l.ctx)
		if l.expect == "ok" {
			for _, f := range r.Findings {
				if !legacyRules[f.Rule] {
					t.Errorf("rules.txt:%d [%v] %q: unexpected %s", l.line, l.ctx, l.payload, f.Rule)
				}
			}
			continue
		}
		found := false
		for _, f := range r.Findings {
			found = found || string(f.Rule) == l.expect
		}
		if !found {
			t.Errorf("rules.txt:%d [%v] %q: %s not reported (got %v)", l.line, l.ctx, l.payload, l.expect, r.Rules())
		}
	}
}

// TestRuleCorpus_Cleaned: in clean mode every malicious line comes out clean for its rule, and benign lines come
// out unchanged.
func TestRuleCorpus_Cleaned(t *testing.T) {
	g, err := New(WithProfile(ProfileStrict),
		WithCategories(CatXSS, CatTemplate, CatInjection, CatUnicode, CatStructure, CatOutput),
		WithRedirectHosts("shop.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range readRuleCorpus(t) {
		out, r := g.ProcessString(l.payload, l.ctx)
		if l.expect == "ok" {
			if r.Changed && !hasLegacyFinding(r) {
				t.Errorf("rules.txt:%d [%v] %q: changed to %q (%v)", l.line, l.ctx, l.payload, out, r.Rules())
			}
			continue
		}
		if !r.Changed {
			t.Errorf("rules.txt:%d [%v] %q: not changed", l.line, l.ctx, l.payload)
			continue
		}
		if again := g.CheckString(out, l.ctx); len(again.Findings) > 0 {
			t.Errorf("rules.txt:%d [%v] %q → %q: still %v", l.line, l.ctx, l.payload, out, again.Rules())
		}
	}
}

func hasLegacyFinding(r Report) bool {
	for _, f := range r.Findings {
		if legacyRules[f.Rule] {
			return true
		}
	}
	return false
}

// TestBenignCorpus_StrictNewRules: the original benign corpus raises no new rule in any context but redirect
// (where most free text is, rightly, not a same-site path).
func TestBenignCorpus_StrictNewRules(t *testing.T) {
	g := strictAll(t)
	for _, l := range readCorpus(t, "benign.txt") {
		for _, ctx := range []Context{CtxText, CtxURL, CtxIdentifier, CtxPath, CtxHeader} {
			for _, f := range g.CheckString(l.payload, ctx).Findings {
				if !legacyRules[f.Rule] {
					t.Errorf("benign.txt:%d [%v] %q: %s", l.line, ctx, l.payload, f.Rule)
				}
			}
		}
	}
}

// TestMaliciousCorpus_BalancedDefault: the default guard flags every "any" line of the original corpus.
func TestMaliciousCorpus_BalancedDefault(t *testing.T) {
	g := MustNew()
	for _, l := range readCorpus(t, "malicious.txt") {
		if l.ctx != "any" {
			continue
		}
		for _, ctx := range []Context{CtxText, CtxURL, CtxIdentifier} {
			if r := g.CheckString(l.payload, ctx); len(r.Findings) == 0 {
				t.Errorf("malicious.txt:%d [%v] %q: not flagged", l.line, ctx, l.payload)
			}
		}
	}
}
