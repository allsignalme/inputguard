package inputguard

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
)

func process(t *testing.T, g *Guard, in string) (string, Report) {
	t.Helper()
	out, r := g.ProcessJSON([]byte(in))
	if !r.InvalidJSON && !json.Valid(out) {
		t.Fatalf("output is not valid JSON: %s", out)
	}
	return string(out), r
}

func expectJSON(t *testing.T, g *Guard, in, want string) Report {
	t.Helper()
	got, r := process(t, g, in)
	if got != want {
		t.Errorf("ProcessJSON(%s)\n got  %s\n want %s\n report %+v", in, got, want, r)
	}
	if r.Changed != (in != want) {
		t.Errorf("ProcessJSON(%s): Changed=%v", in, r.Changed)
	}
	return r
}

func hasRule(r Report, id RuleID) bool {
	for _, f := range r.Findings {
		if f.Rule == id {
			return true
		}
	}
	return false
}

func TestJSON_KeepsEverythingElseByteForByte(t *testing.T) {
	g := MustNew()
	in := "{ \"b\" : 1.50e+3,\n  \"a\": \"hi <script>alert(1)</script>\",\t\"big\": 12345678901234567890123,\n" +
		"  \"c\": [ 1, \"\\u00e9t\\u00e9\", {\"d\": null} ], \"e\": true }"
	want := "{ \"b\" : 1.50e+3,\n  \"a\": \"hi\",\t\"big\": 12345678901234567890123,\n" +
		"  \"c\": [ 1, \"\\u00e9t\\u00e9\", {\"d\": null} ], \"e\": true }"
	r := expectJSON(t, g, in, want)
	if len(r.Findings) != 1 || r.Findings[0].Path != "a" || r.Findings[0].Rule != RuleTagDangerous {
		t.Errorf("findings %+v", r.Findings)
	}
}

func TestJSON_CleanBodyIsReturnedAsIs(t *testing.T) {
	g := MustNew()
	in := []byte(`{"name":"Áo thun","price":"199.000đ","url":"https://shop.example.com/p?a=1&b=2"}`)
	if g.MaybeDirty(in) {
		t.Errorf("MaybeDirty on a clean body")
	}
	out, r := g.ProcessJSON(in)
	if &out[0] != &in[0] || !r.Clean() {
		t.Errorf("clean body: %s %+v", out, r)
	}
}

func TestJSON_EscapedPayloads(t *testing.T) {
	g := MustNew()
	lt, gt := esc("003c"), esc("003e")
	expectJSON(t, g, `{"a":"x`+lt+`script`+gt+`alert(1)`+lt+`/script`+gt+`"}`, `{"a":"x"}`)
	ls := `{"a":"ok","l":"line` + esc("2028") + `sep"}`
	expectJSON(t, g, ls, ls)
}

// esc spells a JSON \uXXXX escape (built at run time so that no tool rewrites it into the character).
func esc(hex string) string { return "\\" + "u" + hex }

func TestJSON_PrototypePollution(t *testing.T) {
	g := MustNew()
	r := expectJSON(t, g, `{"__proto__":{"admin":true},"a":1}`, `{"a":1}`)
	if !hasRule(r, RuleProtoPollution) || r.Findings[0].Path != "[key]" {
		t.Errorf("findings %+v", r.Findings)
	}
	expectJSON(t, g, `{"constructor":{"prototype":{"x":1}},"b":2}`, `{"constructor":{},"b":2}`)
	expectJSON(t, g, `{"a":1,"`+esc("005f")+`_proto__":{"x":1}}`, `{"a":1}`)
	expectJSON(t, g, `{"items":[{"__proto__":1,"ok":2}]}`, `{"items":[{"ok":2}]}`)
	expectJSON(t, g, `{"prototype":1}`, `{"prototype":1}`) // only under constructor
	r = MustNew(WithMode(ModeReject)).CheckJSON([]byte(`{"__proto__":{}}`))
	if !r.Rejected || !errors.Is(r.Err(), ErrRejected) {
		t.Errorf("reject mode: %+v", r)
	}
}

func TestJSON_DeleteMembers_Commas(t *testing.T) {
	g := MustNew()
	cases := map[string]string{
		`{"__proto__":1}`:                             `{}`,
		`{"__proto__":1,"a":1}`:                       `{"a":1}`,
		`{"a":1,"__proto__":1}`:                       `{"a":1}`,
		`{"a":1,"__proto__":1,"b":2}`:                 `{"a":1,"b":2}`,
		`{"__proto__":1,"__proto__":2,"a":1}`:         `{"a":1}`,
		`{"a":1,"__proto__":1,"__proto__":2}`:         `{"a":1}`,
		`{ "a" : 1 , "__proto__" : [1,2] , "b" : 2 }`: `{ "a" : 1 , "b" : 2 }`,
		`{"x":"<script>","__proto__":1}`:              `{"x":""}`,
	}
	for in, want := range cases {
		expectJSON(t, g, in, want)
	}
}

func TestJSON_KeyNames(t *testing.T) {
	g := MustNew()
	r := expectJSON(t, g, `{"<img src=x onerror=alert(1)>":"v","k":1}`, `{"k":1}`)
	if !hasRule(r, RuleTagDangerous) || r.Findings[0].Path != "[key]" {
		t.Errorf("findings %+v", r.Findings)
	}
	// Control characters are removed from the name; a renamed key never overwrites an existing one.
	expectJSON(t, g, `{"na\u0000me":"x"}`, `{"name":"x"}`)
	expectJSON(t, g, `{"a\u0000":"x","a":"y"}`, `{"a":"y"}`)
	expectJSON(t, g, `{"a":"y","a\u0000":"x"}`, `{"a":"y"}`)
	// Key names are checked inside exempt subtrees too.
	ge := MustNew(WithExempt("content"))
	expectJSON(t, ge, `{"content":{"<script>":"x","b":"<b>x</b>"}}`, `{"content":{"b":"<b>x</b>"}}`)
}

func TestJSON_DuplicateKeys(t *testing.T) {
	g := MustNew(WithRules(RuleDuplicateKey))
	r := expectJSON(t, g, `{"role":"admin","name":"a","role":"user"}`, `{"name":"a","role":"user"}`)
	if !hasRule(r, RuleDuplicateKey) {
		t.Errorf("findings %+v", r.Findings)
	}
	// Large objects use the map path.
	var b strings.Builder
	b.WriteString(`{"dup":1`)
	for i := 0; i < 30; i++ {
		b.WriteString(`,"k` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `":1`)
	}
	b.WriteString(`,"dup":2}`)
	out, r := g.ProcessJSON([]byte(b.String()))
	if strings.Count(string(out), `"dup"`) != 1 || !strings.Contains(string(out), `"dup":2`) || !hasRule(r, RuleDuplicateKey) {
		t.Errorf("large object: %s", out)
	}
	// Off by default: duplicates are left alone.
	expectJSON(t, MustNew(), `{"a":1,"a":2}`, `{"a":1,"a":2}`)
}

func TestJSON_MongoKeys(t *testing.T) {
	g := MustNew(WithKeyPolicy(KeyPolicyMongo))
	r := expectJSON(t, g, `{"$where":"1","a.b":1,"ok":{"$set":{"x":1}},"n":2}`, `{"ok":{},"n":2}`)
	if !hasRule(r, RuleKeyOperator) || !hasRule(r, RuleKeyInvalid) {
		t.Errorf("findings %+v", r.Findings)
	}
	gs := strictAll(t)
	r = gs.CheckJSON([]byte(`{"user":"admin","password":{"$ne":""}}`))
	if !r.Rejected || !hasRule(r, RuleNoSQLOperator) {
		t.Errorf("nosql operator key: %+v", r)
	}
	r = gs.CheckJSON([]byte(`{"password[$ne]":"x"}`))
	if !hasRule(r, RuleNoSQLOperator) {
		t.Errorf("bracketed operator key: %+v", r)
	}
}

func nested(depth int, leaf string) string {
	return strings.Repeat("[", depth) + leaf + strings.Repeat("]", depth)
}

func TestJSON_Limits(t *testing.T) {
	g := MustNew()
	r := expectJSON(t, g, `{"a":`+nested(32, `"<b>x</b>"`)+`}`, `{"a":`+nested(31, "null")+`}`)
	if !r.LimitExceeded || !hasRule(r, RuleTooComplex) {
		t.Errorf("depth: %+v", r)
	}
	expectJSON(t, g, nested(32, `1`), nested(32, `1`))

	gl := MustNew(WithLimits(Limits{MaxMembers: 2, MaxElements: 3}))
	expectJSON(t, gl, `{"a":1,"b":"<b>x</b>","c":3,"d":{"e":1}}`, `{"a":1,"b":""}`)
	expectJSON(t, gl, `[1,"<b>x</b>",3,4,[5]]`, `[1,"",3]`)
	gs := MustNew(WithLimits(Limits{MaxStrings: 4}))
	expectJSON(t, gs, `["a","b","c","d","<b>x</b>","plain"]`, `["a","b","c","d","","plain"]`)

	// Over the limit, the rest is still validated.
	_, r = gl.ProcessJSON([]byte(`["<b>",2,3,4,}]`))
	if !r.InvalidJSON {
		t.Errorf("invalid JSON past the limit accepted: %+v", r)
	}

	gr := MustNew(WithMode(ModeReject), WithProfile(ProfileBalanced))
	r = gr.CheckJSON([]byte(nested(40, "1")))
	if !r.Rejected || !r.LimitExceeded || r.Err() == nil || !strings.Contains(r.Err().Error(), "too deep") {
		t.Errorf("reject on depth: %+v %v", r, r.Err())
	}

	grep := MustNew(WithLimits(Limits{MaxDepth: 2, OnExceed: ActionReport}))
	in := `[[["<script>"]]]`
	expectJSON(t, grep, in, in)

	// Deep nesting does not exhaust the stack: past the limit the scan is iterative.
	deep := nested(1_000_000, `"<b>"`)
	out, r := g.ProcessJSON([]byte(deep))
	if !r.LimitExceeded || !json.Valid(out) {
		t.Errorf("very deep: %+v", r)
	}
}

func TestJSON_Invalid(t *testing.T) {
	// The scanner validates what it parses. (In clean mode the fast path returns a body that cannot hold
	// anything without parsing it; a guard whose rules the fast path does not cover always parses.)
	g := strictAll(t)
	for _, in := range []string{
		``, ` `, `{`, `{"a":}`, `{"a":1,}`, `[1,]`, `{"a":1} x`, `{"a":"<script>"`, `{'a':1}`, `{"a":01}`,
		`{"a":1.}`, `{"a":-}`, `{"a":tru}`, `{"a":"\x"}`, "{\"a\":\"\x01\"}", `{"__proto__":[1,},"a":"<b>"}`,
		`"\ud800`, `{"a":"\u12"}`,
	} {
		out, r := g.ProcessJSON([]byte(in))
		if !r.InvalidJSON || string(out) != in {
			t.Errorf("%q: %q %+v", in, out, r)
		}
	}
}

func TestJSON_Scalars(t *testing.T) {
	g := MustNew()
	expectJSON(t, g, `"<script>x"`, `""`)
	expectJSON(t, g, `"ok"`, `"ok"`)
	expectJSON(t, g, ` 12 `, ` 12 `)
	expectJSON(t, g, `null`, `null`)
}

func TestJSON_EmbeddedJSON(t *testing.T) {
	g := MustNew()
	r := expectJSON(t, g,
		`{"data":"{\"note\":\"ok <script>alert(1)</script>\",\"n\":1.50}"}`,
		`{"data":"{\"note\":\"ok\",\"n\":1.50}"}`)
	if len(r.Findings) != 1 || r.Findings[0].Path != "data.note" {
		t.Errorf("findings %+v", r.Findings)
	}
	expectJSON(t, g, `{"d":"[\"<b>x</b>\",2]"}`, `{"d":"[\"\",2]"}`)
	expectJSON(t, g, `{"d":"{\"__proto__\":{\"a\":1},\"b\":2}"}`, `{"d":"{\"b\":2}"}`)
	// Not valid JSON inside: cleaned as text.
	expectJSON(t, g, `{"d":"{not json <script>}"}`, `{"d":"{not json"}`)
	expectJSON(t, MustNew(WithEmbeddedJSON(false)), `{"d":"[\"<b>x</b>\"]"}`, `{"d":"["}`)
}

func TestJSON_ExemptAndFieldContexts(t *testing.T) {
	g := MustNew(WithExempt("content", "items[*].note", "**.description"))
	in := `{"content":"<b>x</b>","items":[{"note":"<b>x</b>","name":"<b>y</b>"}],"a":{"b":{"description":"<i>z</i>"}}}`
	expectJSON(t, g, in, `{"content":"<b>x</b>","items":[{"note":"<b>x</b>","name":""}],"a":{"b":{"description":"<i>z</i>"}}}`)

	gc := MustNew(WithFieldContext("items[*].ref", CtxIdentifier))
	expectJSON(t, gc, `{"items":[{"ref":"ab<b>c</b>"}],"ref":"ab<b>c</b>"}`, `{"items":[{"ref":""}],"ref":"ab"}`)
}

func TestJSON_ActionsAndObserver(t *testing.T) {
	var seen []Report
	g := MustNew(WithAction(RuleTagGeneric, ActionReport), WithObserver(func(r Report) { seen = append(seen, r) }))
	in := `{"a":"<b>bold</b>","b":"<script>x"}`
	r := expectJSON(t, g, in, `{"a":"<b>bold</b>","b":""}`)
	if len(seen) != 1 || len(r.Findings) != 2 {
		t.Fatalf("observer %d, findings %+v", len(seen), r.Findings)
	}
	for _, f := range r.Findings {
		if f.Rule == RuleTagGeneric && f.Action != ActionReport {
			t.Errorf("action %v", f.Action)
		}
	}
	// A rejecting rule leaves the whole body unchanged, even when others clean.
	gm := MustNew(WithAction(RuleScheme, ActionReject))
	out, r := gm.ProcessJSON([]byte(`{"a":"<b>x</b>","u":"javascript:alert(1)"}`))
	if !r.Rejected || r.Changed || string(out) != `{"a":"<b>x</b>","u":"javascript:alert(1)"}` {
		t.Errorf("mixed actions: %s %+v", out, r)
	}
	if msg := r.Err().Error(); !strings.Contains(msg, "u: script URL scheme") || strings.Contains(msg, "javascript") {
		t.Errorf("message %q", msg)
	}
	// Severity action.
	gs := MustNew(WithSeverityAction(SeverityHigh, ActionIgnore))
	expectJSON(t, gs, `{"a":"<b>x</b>"}`, `{"a":"<b>x</b>"}`)
}

func TestJSON_CustomDetector(t *testing.T) {
	ssn := regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	g := MustNew(WithDetector(Detector{
		ID:       "ssn",
		Category: "pii",
		Contexts: []Context{CtxText},
		MayMatch: func(raw string) bool { return strings.Count(raw, "-") >= 2 },
		Detect: func(in Input) int {
			if loc := ssn.FindStringIndex(in.Decoded); loc != nil {
				return loc[0]
			}
			return -1
		},
	}))
	r := expectJSON(t, g, `{"note":"call me, ssn 123-45-6789 thanks","id":"123-45-6789"}`, `{"note":"call me, ssn","id":"123-45-6789"}`)
	if !hasRule(r, "ssn") || r.Findings[0].Category != "pii" {
		t.Errorf("findings %+v", r.Findings)
	}
}

func TestJSON_UnicodeCleaning(t *testing.T) {
	g := MustNew()
	expectJSON(t, g, `{"a":"x`+esc("202e")+`y"}`, `{"a":"xy"}`)
	out, r := g.ProcessJSON([]byte("{\"a\":\"x\xffy\"}"))
	if string(out) != `{"a":"x�y"}` || !hasRule(r, RuleInvalidUTF8) {
		t.Errorf("invalid UTF-8: %s %+v", out, r)
	}
}

func TestTopicFilter(t *testing.T) {
	var calls int
	f := MustNew().TopicFilter(TopicFilterConfig{Topics: []string{"events"}, OnFinding: func(string, Report) { calls++ }})
	dirty := []byte(`{"a":"<script>x"}`)
	if got := f("other", dirty); string(got) != string(dirty) {
		t.Errorf("other topic changed")
	}
	if got := f("events", dirty); string(got) != `{"a":""}` || calls != 1 {
		t.Errorf("events: %s, calls %d", got, calls)
	}
	dry := MustNew().TopicFilter(TopicFilterConfig{Topics: []string{"events"}, DryRun: true})
	if got := dry("events", dirty); string(got) != string(dirty) {
		t.Errorf("dry run changed")
	}
	if got := f("events", []byte("not json <script>")); string(got) != "not json <script>" {
		t.Errorf("not JSON changed")
	}
}
