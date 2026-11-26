package inputguard

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"unicode/utf8"
)

// The golden files record what this engine does on the shared corpus, so that the JavaScript port (js/) can be
// checked against it: same findings (rule, path, context, action, byte offset), same output bytes, same flags. Run
// `go test -run 'TestGolden|TestJSTables' -update` after changing a rule; without -update the tests fail when a
// file is stale, so CI keeps them in step with the code.

var update = flag.Bool("update", false, "rewrite testdata/golden and the generated JavaScript tables")

const goldenDir = "testdata/golden"

// goldenContexts are the contexts every corpus value is run in. CtxSecret is CtxIdentifier in clean mode and
// CtxSkip in reject mode; CtxSkip inspects nothing.
var goldenContexts = []Context{CtxText, CtxURL, CtxIdentifier, CtxPath, CtxHeader, CtxRedirect}

type goldenConfig struct {
	name string
	opts []Option
}

// goldenConfigs: the configurations the port must reproduce. balanced_clean is the default guard (the web pixel and
// the storefront collect route); social_strict mixes reject and clean actions like the social backend's strict
// routes.
func goldenConfigs() []goldenConfig {
	all := WithCategories(CatXSS, CatTemplate, CatInjection, CatUnicode, CatStructure, CatOutput)
	return []goldenConfig{
		{"balanced_clean", nil},
		{"strict_clean", []Option{WithProfile(ProfileStrict), all, WithRedirectHosts("shop.example.com")}},
		{"strict_reject", []Option{WithMode(ModeReject), WithProfile(ProfileStrict), all,
			WithRedirectHosts("shop.example.com")}},
		{"social_strict", []Option{WithMode(ModeReject), WithProfile(ProfileStrict),
			WithAction(RuleInvisible, ActionClean), WithAction(RuleHeaderCRLF, ActionClean),
			WithRedirectHosts("allsignalme.com", "myshopify.com")}},
	}
}

// goldenReport is a Report in short form. A finding is [rule, path, context, action, offset]; strings.json leaves
// out the path (always empty) and the context (the result's own).
type goldenReport struct {
	Changed       bool    `json:"changed,omitempty"`
	Rejected      bool    `json:"rejected,omitempty"`
	Truncated     bool    `json:"truncated,omitempty"`
	LimitExceeded bool    `json:"limitExceeded,omitempty"`
	Findings      [][]any `json:"findings,omitempty"`
}

func toGoldenReport(t *testing.T, r Report, bare Context) goldenReport {
	t.Helper()
	g := goldenReport{Changed: r.Changed, Rejected: r.Rejected, Truncated: r.Truncated, LimitExceeded: r.LimitExceeded}
	for _, f := range r.Findings {
		if bare != CtxSkip {
			if f.Path != "" || f.Context != bare {
				t.Fatalf("finding on a bare string with path %q, context %v", f.Path, f.Context)
			}
			g.Findings = append(g.Findings, []any{f.Rule, f.Action.String(), f.Offset})
			continue
		}
		g.Findings = append(g.Findings, []any{f.Rule, f.Path, f.Context.String(), f.Action.String(), f.Offset})
	}
	return g
}

func (g goldenReport) empty() bool {
	return !g.Changed && !g.Rejected && !g.Truncated && !g.LimitExceeded && len(g.Findings) == 0
}

// goldenString encodes a string as a JSON string when it is valid UTF-8, else as {"hex": "…"}.
func goldenString(s string) json.RawMessage {
	if utf8.ValidString(s) {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(s)
		return bytes.TrimRight(buf.Bytes(), "\n")
	}
	b, _ := json.Marshal(map[string]string{"hex": hex.EncodeToString([]byte(s))})
	return b
}

type goldenStringResult struct {
	Input  int             `json:"i"`
	Config string          `json:"cfg"`
	Ctx    string          `json:"ctx"`
	Out    json.RawMessage `json:"out,omitempty"` // absent: the output is the input
	goldenReport
}

// goldenInputs: every payload of the three corpora, once, in corpus order.
func goldenInputs(t *testing.T) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, l := range readRuleCorpus(t) {
		add(l.payload)
	}
	for _, s := range corpusPayloads(t) {
		add(s)
	}
	return out
}

func newGoldenGuard(t *testing.T, c goldenConfig, extra ...Option) *Guard {
	t.Helper()
	g, err := New(append(append([]Option(nil), c.opts...), extra...)...)
	if err != nil {
		t.Fatalf("%s: %v", c.name, err)
	}
	return g
}

func TestGolden_Strings(t *testing.T) {
	inputs := goldenInputs(t)
	doc := struct {
		Configs  []string             `json:"configs"`
		Contexts []string             `json:"contexts"`
		Inputs   []json.RawMessage    `json:"inputs"`
		Results  []goldenStringResult `json:"results"`
	}{}
	for _, c := range goldenContexts {
		doc.Contexts = append(doc.Contexts, c.String())
	}
	for _, s := range inputs {
		doc.Inputs = append(doc.Inputs, goldenString(s))
	}
	for _, c := range goldenConfigs() {
		doc.Configs = append(doc.Configs, c.name)
		g := newGoldenGuard(t, c)
		for i, s := range inputs {
			for _, ctx := range goldenContexts {
				out, r := g.ProcessString(s, ctx)
				gr := toGoldenReport(t, r, ctx)
				if gr.empty() && out == s {
					continue
				}
				res := goldenStringResult{Input: i, Config: c.name, Ctx: ctx.String(), goldenReport: gr}
				if out != s {
					res.Out = goldenString(out)
				}
				doc.Results = append(doc.Results, res)
			}
		}
	}
	checkGolden(t, "strings.json", doc)
}

// GoldenDoc places one payload in fields of each context, in an array, nested, and as a key. The JavaScript test
// builds the same document from the payload.
func goldenDoc(p string) map[string]any {
	return map[string]any{
		"event_name":       "ViewContent",
		"dl":               p,
		"event_source_url": p,
		"fbc":              p,
		"content_name":     p,
		"redirect_url":     p,
		"file_path":        p,
		"user_agent":       p,
		"contents":         []any{map[string]any{"id": p, "quantity": 1.0}, p},
		"keys":             map[string]any{p: "v"},
	}
}

type goldenValueResult struct {
	Doc    int             `json:"doc"`
	Config string          `json:"cfg"`
	Out    json.RawMessage `json:"out,omitempty"` // absent: unchanged
	goldenReport
}

func TestGolden_Values(t *testing.T) {
	var docs []json.RawMessage
	for _, name := range []string{"app_capi_events.json", "collect_browser.json"} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, json.RawMessage(bytes.TrimSpace(b)))
	}
	structural, _ := json.Marshal(map[string]any{
		"__proto__":   map[string]any{"admin": true},
		"constructor": map[string]any{"prototype": map[string]any{"admin": true}},
		"$where":      "1",
		"name[$ne]":   "x",
		"ok":          []any{"a", 1.0, true, nil},
		"deep":        []any{[]any{[]any{[]any{[]any{"<script>"}}}}},
		"wide":        []any{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "<b>x</b>"},
	})
	docs = append(docs, structural)
	var payloads []string
	for _, s := range corpusPayloads(t) {
		if utf8.ValidString(s) {
			payloads = append(payloads, s)
		}
	}
	doc := struct {
		Configs  []string            `json:"configs"`
		Docs     []json.RawMessage   `json:"docs"`
		Payloads []json.RawMessage   `json:"payloads"`
		Results  []goldenValueResult `json:"results"`
	}{Docs: docs}
	for _, p := range payloads {
		doc.Payloads = append(doc.Payloads, goldenString(p))
	}
	cfgs := append(goldenConfigs(),
		goldenConfig{"balanced_limits", []Option{WithLimits(Limits{MaxDepth: 3, MaxStrings: 8})}})
	for _, c := range cfgs {
		doc.Configs = append(doc.Configs, c.name)
		g := newGoldenGuard(t, c, WithEmbeddedJSON(false))
		for i := 0; i < len(docs)+len(payloads); i++ {
			var v any
			if i < len(docs) {
				if err := json.Unmarshal(docs[i], &v); err != nil {
					t.Fatal(err)
				}
			} else {
				v = goldenDoc(payloads[i-len(docs)])
			}
			out, r := g.ProcessValue(v)
			gr := toGoldenReport(t, r, CtxSkip)
			if gr.empty() {
				continue
			}
			res := goldenValueResult{Doc: i, Config: c.name, goldenReport: gr}
			if r.Changed {
				var buf bytes.Buffer
				enc := json.NewEncoder(&buf)
				enc.SetEscapeHTML(false)
				if err := enc.Encode(out); err != nil {
					t.Fatal(err)
				}
				res.Out = bytes.TrimRight(buf.Bytes(), "\n")
			}
			doc.Results = append(doc.Results, res)
		}
	}
	checkGolden(t, "values.json", doc)
}

func TestGolden_Classifier(t *testing.T) {
	table := DefaultKeyTable()
	var keys []string
	for k := range table.Exact {
		keys = append(keys, k, "X"+k)
	}
	for s := range table.Suffix {
		keys = append(keys, "item"+s, "ITEM"+s)
	}
	for s := range table.Contains {
		keys = append(keys, "my_"+s+"_x")
	}
	keys = append(keys, "", "title", "dl", "content_name", "description", "Event_Source_URL", "sku_ids", "SKU")
	sort.Strings(keys)
	values := []string{"", "plain text", "https://a.example/x", "HTTP://A.EXAMPLE", "//a.example/x", "/a/b",
		"%2F%2Fa.example", "/" + string(rune(0x7f)) + "/a.example", "&#47;&#47;a.example", "javascript:alert(1)"}
	cl := defaultClassifier()
	rows := [][]string{}
	for _, k := range keys {
		var line []string
		for _, v := range values {
			line = append(line, cl(k, v).String())
		}
		rows = append(rows, append([]string{k}, line...))
	}
	checkGolden(t, "classify.json", map[string]any{"values": values, "rows": rows})
}

func TestGolden_Meta(t *testing.T) {
	var rules [][]any
	for _, r := range Rules() {
		rules = append(rules, []any{r.ID, r.Category, r.Severity.String(), r.Profile.String(), r.Summary})
	}
	checkGolden(t, "meta.json", map[string]any{"rules": rules, "limits": defaultLimits})
}

func checkGolden(t *testing.T, name string, v any) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	got := oneRecordPerLine(buf.Bytes())
	path := filepath.Join(goldenDir, name)
	if *update {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -run TestGolden -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: run go test -run TestGolden -update and review the diff", path)
	}
}

// oneRecordPerLine breaks compact JSON after a "}," that closes a record (one followed by `{"`), outside strings:
// one record per line keeps the files readable and their diffs small.
func oneRecordPerLine(b []byte) []byte {
	out := make([]byte, 0, len(b)+len(b)/32)
	inStr, esc := false, false
	for i, c := range b {
		out = append(out, c)
		switch {
		case inStr && esc:
			esc = false
		case inStr && c == '\\':
			esc = true
		case c == '"':
			inStr = !inStr
		case !inStr && c == ',' && i > 0 && (b[i-1] == '}' || b[i-1] == ']') && i+1 < len(b) &&
			(b[i+1] == '{' || b[i+1] == '"' || b[i+1] == '['):
			out = append(out, '\n')
		}
	}
	return out
}
