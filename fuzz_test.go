package inputguard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func fuzzGuards(t testing.TB) []*Guard {
	return []*Guard{
		MustNew(),
		MustNew(WithProfile(ProfileStrict), WithCategories(CatXSS, CatTemplate, CatInjection, CatUnicode, CatStructure,
			CatOutput), WithKeyPolicy(KeyPolicyMongo), WithRedirectHosts("shop.example.com"),
			WithLimits(Limits{MaxDepth: 6, MaxMembers: 8, MaxElements: 8, MaxStrings: 40})),
	}
}

func seedJSON(f *testing.F) {
	for _, s := range corpusPayloads(f) {
		for _, b := range jsonBodies(s) {
			f.Add(b)
		}
	}
	for _, name := range []string{"app_capi_events.json", "collect_browser.json"} {
		raw, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	for _, s := range []string{
		`{"__proto__":{"a":1},"a\u0000":1,"a":2,"a":3}`, `{"d":"{\"x\":\"<b>\",\"x\":1}"}`, `[[[[[[[["<b>"]]]]]]]]`,
		`{"$where":"1","password":{"$ne":""}}`, "{\"a\":\"x\xffy\"}", `{"a":"\ud800"}`,
	} {
		f.Add([]byte(s))
	}
}

// FuzzProcessJSON checks, for any input: no panic; valid JSON in ⇒ valid JSON out; cleaning is idempotent;
// the body fast path never skips a body the full scan would change or flag.
func FuzzProcessJSON(f *testing.F) {
	seedJSON(f)
	guards := fuzzGuards(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		valid := json.Valid(data)
		for gi, g := range guards {
			orig := string(data)
			out, r := g.ProcessJSON(data)
			if string(data) != orig {
				t.Fatalf("guard %d modified its input", gi)
			}
			if r.InvalidJSON && valid {
				t.Fatalf("guard %d: valid JSON reported invalid: %q", gi, data)
			}
			if !r.InvalidJSON && !valid && (r.Changed || len(r.Findings) > 0) {
				t.Fatalf("guard %d: invalid JSON accepted: %q", gi, data)
			}
			if r.Changed && !json.Valid(out) {
				t.Fatalf("guard %d: output not valid JSON:\n in  %q\n out %q", gi, data, out)
			}
			if r.Changed {
				out2, r2 := g.ProcessJSON(out)
				if r2.Changed {
					t.Fatalf("guard %d: not idempotent:\n in   %q\n out  %q\n out2 %q\n %+v", gi, data, out, out2, r2.Findings)
				}
			}
			slow := *g
			slow.bodyFast, slow.noGates = false, true
			if rs := slow.CheckJSON(data); !sameRules(r, rs) {
				t.Fatalf("guard %d: fast checks change the findings of %q:\n fast %v\n slow %v", gi, data, r.Findings, rs.Findings)
			}
		}
	})
}

// FuzzProcessString: no panic; cleaning is idempotent; the per-value fast path never skips a match.
func FuzzProcessString(f *testing.F) {
	for _, s := range corpusPayloads(f) {
		f.Add(s, uint8(0))
	}
	for _, l := range readRuleCorpus(f) {
		f.Add(l.payload, uint8(l.ctx))
	}
	guards := fuzzGuards(f)
	contexts := []Context{CtxText, CtxURL, CtxIdentifier, CtxSecret, CtxPath, CtxHeader, CtxRedirect, CtxSkip}
	f.Fuzz(func(t *testing.T, s string, c uint8) {
		ctx := contexts[int(c)%len(contexts)]
		for gi, g := range guards {
			out, r := g.ProcessString(s, ctx)
			if r.Changed {
				if out2, r2 := g.ProcessString(out, ctx); r2.Changed {
					t.Fatalf("guard %d [%v]: not idempotent: %q → %q → %q (%v)", gi, ctx, s, out, out2, r2.Rules())
				}
			} else if out != s {
				t.Fatalf("guard %d: changed output without Changed", gi)
			}
			if !g.MaybeDirtyString(s) && len(r.Findings) > 0 {
				t.Fatalf("guard %d [%v]: per-value fast path skipped %q: %v", gi, ctx, s, r.Rules())
			}
			slow := *g
			slow.noGates = true
			if rs := slow.CheckString(s, ctx); !sameRules(r, rs) {
				t.Fatalf("guard %d [%v]: fast checks change the findings of %q: %v vs %v", gi, ctx, s, r.Rules(), rs.Rules())
			}
		}
	})
}

// sameRules: the same (path, rule) findings, in any order. Offsets may differ (a cut changes what a later rule sees).
func sameRules(a, b Report) bool {
	key := func(r Report) map[string]bool {
		m := map[string]bool{}
		for _, f := range r.Findings {
			m[f.Path+" "+string(f.Rule)] = true
		}
		return m
	}
	ka, kb := key(a), key(b)
	if len(ka) != len(kb) {
		return false
	}
	for k := range ka {
		if !kb[k] {
			return false
		}
	}
	return true
}
