package inputguard

import (
	"reflect"
	"testing"
)

func TestProcessValue_InPlace(t *testing.T) {
	g := MustNew()
	v := map[string]any{
		"name":  "ok <script>x</script>",
		"tags":  []any{"a", "<img src=x onerror=1>", 3.5},
		"attrs": map[string]string{"color": "red", "a\x00": "x", "a": "y"},
		"list":  []string{"fine", "<b>x</b>"},
		"rows":  []map[string]any{{"__proto__": map[string]any{"x": 1}, "k": "v"}},
		"data":  `{"note":"<b>x</b>","n":1}`,
		"id":    "123<svg onload=1>",
		"n":     42,
	}
	out, r := g.ProcessValue(v)
	want := map[string]any{
		"name":  "ok",
		"tags":  []any{"a", "", 3.5},
		"attrs": map[string]string{"color": "red", "a": "y"},
		"list":  []string{"fine", ""},
		"rows":  []map[string]any{{"k": "v"}},
		"data":  `{"note":"","n":1}`,
		"id":    "",
		"n":     42,
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("got  %#v\nwant %#v", out, want)
	}
	if !r.Changed || len(r.Findings) < 7 {
		t.Errorf("report %+v", r)
	}
	for i := 1; i < len(r.Findings); i++ {
		if r.Findings[i-1].Path > r.Findings[i].Path {
			t.Errorf("findings not sorted: %+v", r.Findings)
		}
	}
}

func TestProcessValue_TopLevelString(t *testing.T) {
	g := MustNew()
	out, r := g.ProcessValue("x<script>")
	if out != "x" || !r.Changed {
		t.Errorf("%v %+v", out, r)
	}
	out, r = g.ProcessValue(12)
	if out != 12 || r.Changed {
		t.Errorf("%v %+v", out, r)
	}
}

func TestProcessValue_RejectLeavesValueUntouched(t *testing.T) {
	g := MustNew(WithAction(RuleScheme, ActionReject))
	v := map[string]any{"a": "<b>x</b>", "u": "javascript:alert(1)"}
	_, r := g.ProcessValue(v)
	if !r.Rejected || r.Changed || v["a"] != "<b>x</b>" {
		t.Errorf("%v %+v", v, r)
	}
}

func TestProcessValue_Depth(t *testing.T) {
	g := MustNew(WithLimits(Limits{MaxDepth: 2}))
	v := map[string]any{"a": map[string]any{"b": map[string]any{"c": "x"}}}
	_, r := g.ProcessValue(v)
	if !r.LimitExceeded || v["a"].(map[string]any)["b"] != nil {
		t.Errorf("%v %+v", v, r)
	}
	// A cycle is cut by the depth limit.
	cyc := []any{nil}
	cyc[0] = cyc
	if _, r := MustNew().ProcessValue(cyc); !r.LimitExceeded {
		t.Errorf("cycle: %+v", r)
	}
}

func TestCleanLeaves_DoesNotModify(t *testing.T) {
	g := MustNew()
	v := map[string]any{"a": []any{"ok", "<b>x</b>"}, "b": "fine", "c\x00": "k"}
	changes, r := g.CleanLeaves(v)
	if len(changes) != 1 || FormatPath(changes[0].Path) != "a[1]" || changes[0].Old != "<b>x</b>" || changes[0].New != "" {
		t.Errorf("changes %+v", changes)
	}
	if v["a"].([]any)[1] != "<b>x</b>" || v["c\x00"] != "k" || r.Changed {
		t.Errorf("value modified: %v %+v", v, r)
	}
}

func TestProcessString_And_Field(t *testing.T) {
	g := MustNew()
	if out, r := g.ProcessString("https://shop.example.com/p?a=1&x=<script>&b=2", CtxURL); out != "https://shop.example.com/p?a=1&b=2" || !r.Changed {
		t.Errorf("url: %q %+v", out, r)
	}
	if out, _ := g.ProcessField("event_id", "e1<b>x</b>"); out != "" {
		t.Errorf("identifier: %q", out)
	}
	if out, _ := g.ProcessField("password", "p<b>x</b>"); out != "" {
		t.Errorf("secret in clean mode: %q", out)
	}
	gr := MustNew(WithMode(ModeReject))
	if r := gr.CheckString("p<script>x", CtxSecret); len(r.Findings) != 0 {
		t.Errorf("secret in reject mode is not inspected: %+v", r)
	}
	if g.MaybeDirtyString("plain text") {
		t.Errorf("MaybeDirtyString")
	}
}

func TestOptions_Errors(t *testing.T) {
	for name, opt := range map[string]Option{
		"unknown rule":     WithRules("nope"),
		"unknown category": WithCategories("nope"),
		"bad pattern":      WithExempt("a[x]"),
		"bad host":         WithRedirectHosts("https://x"),
		"bad ssrf entry":   WithSSRFAllow("a/b/c"),
		"bad action":       WithAction(RuleScheme, Action(99)),
	} {
		if _, err := New(opt); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestRulesTable(t *testing.T) {
	seen := map[RuleID]bool{}
	for _, r := range Rules() {
		if seen[r.ID] || r.Summary == "" || r.Category == "" {
			t.Errorf("rule %+v", r)
		}
		seen[r.ID] = true
		if _, ok := LookupRule(r.ID); !ok {
			t.Errorf("lookup %s", r.ID)
		}
	}
	// Every built-in rule is produced by some detector or key check.
	produced := map[RuleID]bool{
		RuleTooComplex: true, RuleProtoPollution: true, RuleDuplicateKey: true, RuleKeyOperator: true,
		RuleKeyInvalid: true,
	}
	for _, d := range builtinDetectors {
		for _, id := range d.rules {
			produced[id] = true
		}
	}
	for id := range seen {
		if !produced[id] {
			t.Errorf("rule %s has no detector", id)
		}
	}
}
