package inputguard

import (
	"strings"
	"testing"
	"time"
)

// Regression tests for the second review round.

func TestRegress2_LinearTime(t *testing.T) {
	g := MustNew()
	for name, body := range map[string]string{
		"dot segments in a path": `{"file":"` + strings.Repeat("/.", 200_000) + `x.."}`,
		"dot segments":           `{"a":"` + strings.Repeat("/.", 200_000) + `"}`,
	} {
		start := time.Now()
		g.ProcessJSON([]byte(body))
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: %v", name, d)
		}
	}
	start := time.Now()
	out, _ := g.ProcessString("https://x.com"+strings.Repeat("/a", 100_000)+"/<script>", CtxURL)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("cleanPath: %v", d)
	}
	if want := "https://x.com" + strings.Repeat("/a", 100_000) + "/"; out != want {
		t.Errorf("cleanPath kept %d bytes, want %d", len(out), len(want))
	}
}

// HTTP clients map hosts with IDNA, so compatibility forms reach the loopback.
func TestRegress2_SSRFCompatibilityHosts(t *testing.T) {
	g := MustNew(WithRules(RuleSSRF))
	for _, u := range []string{"http://①②⑦.0.0.1/", "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/", "http://¹²⁷.0.0.1/", "http://ＬＯＣＡＬＨＯＳＴ/"} {
		if r := g.CheckString(u, CtxURL); !hasRule(r, RuleSSRF) {
			t.Errorf("%s: %v", u, r.Rules())
		}
	}
}

func TestRegress2_NestedTwoLevels(t *testing.T) {
	g := MustNew()
	body := `{"a":"[\"[\\\"java\\\\tscript:alert(1)\\\"]\"]"}`
	if !g.MaybeDirty([]byte(body)) {
		t.Errorf("fast path skipped %s", body)
	}
	if r := g.CheckJSON([]byte(body)); !hasRule(r, RuleScheme) {
		t.Errorf("%s: %v", body, r.Rules())
	}
	// A nested document whose quotes are written ".
	gx := MustNew(WithAction(RuleTagDangerous, ActionIgnore), WithAction(RuleTagGeneric, ActionIgnore),
		WithAction(RuleEventHandler, ActionIgnore), WithAction(RuleScheme, ActionIgnore))
	q := `\` + `u0022` // an escaped quote, spelled out
	body = `{"a":"[` + q + `x\\by` + q + `]"}`
	if !gx.MaybeDirty([]byte(body)) {
		t.Errorf("fast path skipped %s", body)
	}
	if r := gx.CheckJSON([]byte(body)); !hasRule(r, RuleControlChar) {
		t.Errorf("%s: %v", body, r.Rules())
	}
}

func TestRegress2_KeptPartKeepsSpellingWithNonASCII(t *testing.T) {
	g := MustNew()
	for in, want := range map[string]string{
		"Café &amp;amp; bar <img src=x onerror=1>":                "Café &amp;amp; bar",
		"Giảm giá 50%25 cho áo &amp;amp; quần <script>x</script>": "Giảm giá 50%25 cho áo &amp;amp; quần",
	} {
		if out, _ := g.ProcessString(in, CtxText); out != want {
			t.Errorf("%q: got %q, want %q", in, out, want)
		}
	}
}

func TestRegress2_HomepageIsAURL(t *testing.T) {
	if r := MustNew().CheckJSON([]byte(`{"homepage":"javascript:\nalert(document.cookie)"}`)); !hasRule(r, RuleScheme) {
		t.Errorf("%v", r.Rules())
	}
}

// Characters IDNA maps to nothing do not hide a host.
func TestRegress2_SSRFIgnorableCharacters(t *testing.T) {
	g := MustNew(WithRules(RuleSSRF))
	for _, r := range []rune{0xFE00, 0xFE0F, 0x034F, 0x180B, 0x00AD, 0x200D} {
		for _, u := range []string{
			"http://127" + string(r) + ".0.0.1/",
			"http://local" + string(r) + "host/",
		} {
			if rep := g.CheckString(u, CtxURL); !hasRule(rep, RuleSSRF) {
				t.Errorf("%q: %v", u, rep.Rules())
			}
		}
	}
}
