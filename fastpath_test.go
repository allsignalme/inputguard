package inputguard

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

// keyFor: a key the default classifier maps to the context.
var keyFor = map[Context]string{
	CtxText: "note", CtxURL: "url", CtxRedirect: "redirect", CtxIdentifier: "event_id", CtxPath: "file",
	CtxHeader: "user_agent",
}

// escapeAll writes s as a JSON string with every non-alphanumeric character as \uXXXX.
func escapeAll(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		if r < 0x80 && (('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9')) {
			b.WriteRune(r)
			continue
		}
		if r > 0xffff {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
			continue
		}
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	b.WriteByte('"')
	return b.String()
}

// TestFastPath_EncodedBodies: every malicious line of a rule the body fast path covers is found whatever way the
// body escapes it, and the full scan agrees.
func TestFastPath_EncodedBodies(t *testing.T) {
	testEncodedBodies(t, MustNew())
	testEncodedBodies(t, MustNew(WithRules(RuleHeaderCRLF)))
}

func testEncodedBodies(t *testing.T, g *Guard) {
	if !g.bodyFast {
		t.Fatal("guard has no body fast path")
	}
	for _, l := range readRuleCorpus(t) {
		if l.expect == "ok" || !g.Enabled(RuleID(l.expect)) {
			continue
		}
		key := keyFor[l.ctx]
		plain := string(mustJSON(map[string]any{key: l.payload}, false))
		bodies := []string{
			plain,
			string(mustJSON(map[string]any{key: l.payload}, true)),
			`{"` + key + `":` + escapeAll(l.payload) + `}`,
			strings.ReplaceAll(plain, "/", `\/`),
		}
		for _, body := range bodies {
			if !g.MaybeDirty([]byte(body)) {
				t.Errorf("rules.txt:%d: fast path skipped %s", l.line, body)
				continue
			}
			if r := g.CheckJSON([]byte(body)); !hasRule(r, RuleID(l.expect)) {
				t.Errorf("rules.txt:%d: %s not found in %s (%v)", l.line, l.expect, body, r.Rules())
			}
		}
	}
}

// TestFastPath_CommonCleanBodies: everyday payloads stay on the fast path.
func TestFastPath_CommonCleanBodies(t *testing.T) {
	g := MustNew()
	for _, body := range []string{
		`{"url":"https://shop.example.com/p?utm_campaign=sale_50%25&fbclid=IwAR1&variant=1"}`,
		`{"url":"https:\/\/shop.example.com\/collections\/all"}`,
		`{"title":"Áo thun nam – giảm 50%","q":"%E1%BA%A3o%20kho%C3%A1c","quote":"%E2%80%99"}`,
		`{"text":"Loading","path":"/products/x","price":"1.000.000đ"}`,
		`{"go":"a=1\u0026b=2","note":"x \u003e y"}`,
		`{"windows":"C:\\Users\\shop\\file.csv"}`,
		// (A line break between two letters is checked: java\nscript: is how scheme filters are dodged.)
		`{"description":"Line one.\nLine two:\r\n- item","product":"prototype kit"}`,
	} {
		if g.MaybeDirty([]byte(body)) {
			t.Errorf("clean body leaves the fast path: %s", body)
		}
	}
}
