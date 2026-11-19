package inputguard

import (
	"strings"
	"testing"
)

func TestKeyTableAndClassifier(t *testing.T) {
	kt := DefaultKeyTable()
	kt.Exact["Promo_Code"] = CtxIdentifier
	g := MustNew(WithKeyTable(kt), WithKeyContext(CtxURL, "Target"))
	if out, _ := g.ProcessField("promo_code", "AB<b>C</b>"); out != "" {
		t.Errorf("key table: %q", out)
	}
	if out, _ := g.ProcessField("target", "https://shop.example.com/?x=<script>&y=1"); out != "https://shop.example.com/?y=1" {
		t.Errorf("key context: %q", out)
	}
	gc := MustNew(WithClassifier(func(key, _ string) Context {
		if key == "raw" {
			return CtxSkip
		}
		return CtxText
	}))
	if out, _ := gc.ProcessJSON([]byte(`{"raw":"<b>x</b>","t":"<b>x</b>"}`)); string(out) != `{"raw":"<b>x</b>","t":""}` {
		t.Errorf("classifier: %s", out)
	}
	// The default table is a copy: changing it does not change the default guard.
	kt.Exact["name"] = CtxIdentifier
	if out, _ := MustNew().ProcessField("name", "Ann <b>x</b>"); out != "Ann" {
		t.Errorf("default changed: %q", out)
	}
}

func TestFormulaContexts(t *testing.T) {
	g := MustNew(WithRules(RuleFormula), WithFormulaContexts(CtxText, CtxIdentifier))
	if out, _ := g.ProcessString("=1+1", CtxIdentifier); out != "" {
		t.Errorf("identifier: %q", out) // identifiers are emptied, never prefixed
	}
	if out, _ := g.ProcessString("=1+1", CtxText); out != "'=1+1" {
		t.Errorf("text: %q", out)
	}
	if out, _ := g.ProcessString("=1+1", CtxURL); out != "=1+1" {
		t.Errorf("url is not a formula context: %q", out)
	}
}

func TestSSRFAllow(t *testing.T) {
	g := MustNew(WithRules(RuleSSRF), WithSSRFAllow("10.1.0.0/16", "127.0.0.2", "internal.example"))
	for _, ok := range []string{"http://10.1.2.3/", "http://127.0.0.2/", "http://internal.example/"} {
		if r := g.CheckString(ok, CtxURL); len(r.Findings) > 0 {
			t.Errorf("%s: %v", ok, r.Rules())
		}
	}
	for _, bad := range []string{"http://10.2.0.1/", "http://127.0.0.1/", "http://[::ffff:10.2.0.1]/"} {
		if r := g.CheckString(bad, CtxURL); !hasRule(r, RuleSSRF) {
			t.Errorf("%s: not flagged", bad)
		}
	}
}

func TestRedirectHosts(t *testing.T) {
	g := MustNew(WithRules(RuleRedirect), WithRedirectHosts("=shop.example.com", "cdn.example.net"))
	cases := map[string]bool{
		"https://shop.example.com/a":     false,
		"https://www.shop.example.com/a": true, // exact host only
		"https://img.cdn.example.net/":   false,
		"https://cdn.example.net./":      false,
		"/local":                         false,
		"https://evil.example/":          true,
	}
	for u, want := range cases {
		if got := hasRule(g.CheckString(u, CtxRedirect), RuleRedirect); got != want {
			t.Errorf("%s: flagged=%v", u, got)
		}
	}
	// Without allowed hosts, only same-site targets pass.
	if !hasRule(MustNew(WithRules(RuleRedirect)).CheckString("https://shop.example.com/", CtxRedirect), RuleRedirect) {
		t.Error("absolute target allowed without WithRedirectHosts")
	}
}

func TestAccessorsAndStrings(t *testing.T) {
	g := MustNew(WithMode(ModeReject), WithAction(RuleTagGeneric, ActionReport))
	if g.Mode() != ModeReject || g.Profile() != ProfileStrict {
		t.Errorf("mode %v profile %v", g.Mode(), g.Profile())
	}
	if g.ActionFor(RuleTagGeneric) != ActionReport || g.ActionFor(RuleScheme) != ActionReject || g.ActionFor("nope") != ActionIgnore {
		t.Error("ActionFor")
	}
	for _, s := range []string{
		ModeClean.String(), ModeReject.String(), ProfileBalanced.String(), ProfileStrict.String(),
		ActionClean.String(), ActionReject.String(), ActionReport.String(), ActionIgnore.String(), ActionDefault.String(),
		SeverityLow.String(), SeverityMedium.String(), SeverityHigh.String(), SeverityCritical.String(),
	} {
		if s == "" || strings.Contains(s, "%") {
			t.Errorf("String() = %q", s)
		}
	}
	for c := Context(0); c < ctxCount; c++ {
		if c.String() == "" {
			t.Errorf("context %d has no name", c)
		}
	}
}

func TestReportHelpers(t *testing.T) {
	g := MustNew()
	_, r := g.ProcessJSON([]byte(`{"a":"<script>","b":["<b>x</b>","javascript:alert(1)"],"c":"<script>"}`))
	if got := r.Rules(); len(got) != 3 {
		t.Errorf("Rules %v", got)
	}
	rules, fields := r.Summary(2)
	if rules != "tag_dangerous,tag_generic,scheme" || fields != "a,b[0]" {
		t.Errorf("Summary %q %q", rules, fields)
	}
	if r.Err() != nil || r.Clean() {
		t.Error("cleaned report is not an error and not clean")
	}
	if !(Report{}).Clean() {
		t.Error("empty report is clean")
	}
}

func TestFindingsTruncated(t *testing.T) {
	g := MustNew(WithLimits(Limits{MaxFindings: 3}))
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 10; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"<script>"`)
	}
	b.WriteString("]")
	out, r := g.ProcessJSON([]byte(b.String()))
	if len(r.Findings) != 3 || !r.Truncated || strings.Contains(string(out), "script") {
		t.Errorf("%s %+v", out, r)
	}
}

func TestURLCleaning(t *testing.T) {
	g := MustNew()
	cases := map[string]string{
		"https://shop.example.com/a/b<script>/c?x=1#top":      "https://shop.example.com/a/?x=1#top",
		"https://shop.example.com/p?a=1&b=<svg onload=1>&c=3": "https://shop.example.com/p?a=1&c=3",
		"https://shop.example.com/p#<img src=x onerror=1>":    "https://shop.example.com/p",
		"//cdn.example.com/x.js?v=1&cb=javascript:alert(1)":   "//cdn.example.com/x.js?v=1",
		"/relative/<script>/x":                                "/relative/",
		"javascript:alert(1)":                                 "",
		"https://<script>.example.com/":                       "",
		"  https://shop.example.com/?q=%3Cscript%3Ealert(1)":  "https://shop.example.com/",
		// Path segments are kept up to the one that makes the path dirty; quotes alone are inert there.
		"https://shop.example.com/'\"--></style></script><svg>": "https://shop.example.com/'\"--></",
	}
	for in, want := range cases {
		if got, _ := g.ProcessString(in, CtxURL); got != want {
			t.Errorf("%q:\n got  %q\n want %q", in, got, want)
		}
	}
}

func TestSkipStringEscapes(t *testing.T) {
	// Over-limit members are skipped (validated, not inspected); their escapes must still be validated.
	g := MustNew(WithLimits(Limits{MaxMembers: 1}))
	valid := `{"a":"<b>","b":"\" \\ \/ \b \f \n \r \t \u00e9"}`
	out, r := g.ProcessJSON([]byte(valid))
	if r.InvalidJSON || string(out) != `{"a":""}` {
		t.Errorf("valid escapes: %s %+v", out, r)
	}
	for _, bad := range []string{`{"a":"<b>","b":"\x"}`, `{"a":"<b>","b":"\u12"}`, "{\"a\":\"<b>\",\"b\":\"\x01\"}", `{"a":"<b>","b":"x`} {
		if _, r := g.ProcessJSON([]byte(bad)); !r.InvalidJSON {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTraversalOverlong(t *testing.T) {
	g := MustNew()
	for _, p := range []string{"..%c0%afetc", "..%e0%80%afetc", "..%c1%9cwindows", "%25c0%25ae%25c0%25ae/x", `C:\boot.ini`} {
		if r := g.CheckString(p, CtxPath); !hasRule(r, RulePathTraversal) {
			t.Errorf("%s: %v", p, r.Rules())
		}
	}
}
