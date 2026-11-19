package inputguard

import (
	"strings"
	"testing"
	"time"
)

// Regression tests for defects found in review before v0.1.0.

// Long runs of separators or of "on" once took quadratic time.
func TestRegress_LinearTimeOnHostileRuns(t *testing.T) {
	g := MustNew()
	for name, body := range map[string]string{
		"slashes":     `{"a":"` + strings.Repeat("/", 400_000) + `"}`,
		"backslashes": `{"a":"` + strings.Repeat(`\\`, 200_000) + `"}`,
		"path field":  `{"file":"` + strings.Repeat(`\\`, 200_000) + `"}`,
		"handlers":    `{"a":"<` + strings.Repeat("on", 200_000) + `"}`,
		"spaces":      `{"a":"data:` + strings.Repeat(" ", 400_000) + `"}`,
	} {
		start := time.Now()
		g.ProcessJSON([]byte(body))
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: %v", name, d)
		}
	}
}

func TestRegress_SchemeSplitByManyStrippedCharacters(t *testing.T) {
	g := MustNew()
	for _, body := range []string{
		`{"url":"jav\r\nascript:alert(document.cookie)"}`,
		`{"url":"java\t\tscript:alert(1)"}`,
		`{"url":"java\u0009\u0009script:alert(1)"}`,
	} {
		if !g.MaybeDirty([]byte(body)) {
			t.Errorf("fast path skipped %s", body)
		}
		if r := g.CheckJSON([]byte(body)); !hasRule(r, RuleScheme) {
			t.Errorf("%s: %v", body, r.Rules())
		}
	}
	if out, _ := g.ProcessString("java\t\t\tscript:alert(1)", CtxURL); out != "" {
		t.Errorf("ProcessString: %q", out)
	}
}

func TestRegress_HostReadAsAParserReadsIt(t *testing.T) {
	g := MustNew(WithRules(RuleRedirect, RuleSSRF), WithRedirectHosts("shop.example.com"))
	if r := g.CheckString("https://shop.example.com%2F@evil.com/", CtxRedirect); !hasRule(r, RuleRedirect) {
		t.Errorf("redirect: %v", r.Rules())
	}
	if r := g.CheckString("http://example.com%2F@169.254.169.254/latest/meta-data/", CtxURL); !hasRule(r, RuleSSRF) {
		t.Errorf("ssrf: %v", r.Rules())
	}
	// Still allowed: an encoded URL in the query of an allowed one.
	if r := g.CheckString("https://shop.example.com/r?to=https%3A%2F%2Fother.example%2F", CtxRedirect); len(r.Findings) > 0 {
		t.Errorf("allowed redirect flagged: %v", r.Rules())
	}
}

// A JSON document inside a string decodes one level further.
func TestRegress_EmbeddedDocumentEscapes(t *testing.T) {
	g := MustNew()
	for _, body := range []string{
		`{"a":"{\"u\":\"java\\tscript:alert(1)\"}"}`,
		`{"a":"[\"x onclick\\n=alert(1)\"]"}`,
		`{"a":"{\"k\":\"x\\b\"}"}`,
	} {
		if !g.MaybeDirty([]byte(body)) {
			t.Errorf("fast path skipped %s", body)
		}
		out, r := g.ProcessJSON([]byte(body))
		if !r.Changed || len(r.Findings) == 0 {
			t.Errorf("%s: not cleaned (%s)", body, out)
		}
	}
}

func TestRegress_EncodingsTheFastPathMissed(t *testing.T) {
	g := MustNew()
	for _, body := range []string{
		`{"url":"data:         text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="}`,
		`{"file":"/%65tc/passwd"}`,
		`{"url":"https://shop.example.com/?f=/%65tc/passwd"}`,
		`{"file":"/ｅtc/passwd"}`,
		`{"a":"x%2522onmouseover%253dalert(1)"}`,
		`{"a":"x%2520onclick=alert(1)"}`,
	} {
		if !g.MaybeDirty([]byte(body)) {
			t.Errorf("fast path skipped %s", body)
		}
		if r := g.CheckJSON([]byte(body)); len(r.Findings) == 0 {
			t.Errorf("%s: not flagged", body)
		}
	}
}

func TestRegress_SensitiveNamesWholeWordsAndDotSegments(t *testing.T) {
	g := MustNew()
	for _, ok := range []string{"/srv/etc/groups/admins.csv", "https://docs.example.com/etc/group-tours", "https://example.com/a/b/..."} {
		if r := g.CheckString(ok, CtxPath); hasRule(r, RulePathTraversal) {
			t.Errorf("%s flagged", ok)
		}
	}
	for _, bad := range []string{"/etc/./passwd", "/etc//passwd", "/etc/passwd.bak", "a/...//b"} {
		if r := g.CheckString(bad, CtxPath); !hasRule(r, RulePathTraversal) {
			t.Errorf("%s not flagged", bad)
		}
	}
}

// The part kept before a cut keeps its own spelling when it decodes to the same text.
func TestRegress_KeptPartKeepsItsSpelling(t *testing.T) {
	g := MustNew()
	for in, want := range map[string]string{
		"Tom &amp;amp; Jerry 50%25 off <script>alert(1)</script>": "Tom &amp;amp; Jerry 50%25 off",
		"a%26b%3Dc <img src=x onerror=1>":                         "a%26b%3Dc",
		"plain text <script>":                                     "plain text",
	} {
		if out, _ := g.ProcessString(in, CtxText); out != want {
			t.Errorf("%q: got %q, want %q", in, out, want)
		}
	}
}

func TestRegress_MongoKeyRulesAreOptIn(t *testing.T) {
	g := MustNew(WithMode(ModeReject))
	if g.Enabled(RuleKeyOperator) || g.Enabled(RuleKeyInvalid) {
		t.Error("strict profile enabled the Mongo key rules")
	}
	if r := g.CheckJSON([]byte(`{"config.headers":{"$schema":"x"}}`)); r.Rejected {
		t.Errorf("rejected: %v", r.Rules())
	}
	if !MustNew(WithKeyPolicy(KeyPolicyMongo)).Enabled(RuleKeyOperator) {
		t.Error("KeyPolicyMongo")
	}
}
