package inputguard

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/allsignalme/inputguard/internal/legacy"
)

func benchBody(b testing.TB, name string) []byte {
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		b.Fatal(err)
	}
	return raw
}

// dirtyBody: the fixture with one description-like field carrying a payload.
func dirtyBody(b *testing.B) []byte {
	raw := benchBody(b, "app_capi_events.json")
	return bytes.Replace(raw, []byte(`"Purchase"`), []byte(`"Purchase <img src=x onerror=alert(1)>"`), 1)
}

func BenchmarkMaybeDirty_Clean(b *testing.B) {
	body := benchBody(b, "app_capi_events.json")
	g := MustNew()
	b.Run("new", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		b.ReportAllocs()
		for b.Loop() {
			if g.MaybeDirty(body) {
				b.Fatal("dirty")
			}
		}
	})
	b.Run("legacy", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		b.ReportAllocs()
		for b.Loop() {
			if legacy.MaybeDirty(body) {
				b.Fatal("dirty")
			}
		}
	})
}

func benchJSON(b *testing.B, body []byte, g *Guard, mode legacy.Mode) {
	b.Run("new", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		b.ReportAllocs()
		for b.Loop() {
			g.ProcessJSON(body)
		}
	})
	b.Run("legacy", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		b.ReportAllocs()
		for b.Loop() {
			_, _, _ = legacy.CleanJSON(body, mode, nil)
		}
	})
}

func BenchmarkProcessJSON_Clean(b *testing.B) {
	benchJSON(b, benchBody(b, "collect_browser.json"), MustNew(), legacy.ModeClean)
}

// BenchmarkProcessJSON_CleanFullScan: a clean body the fast path cannot skip (the scanner runs end to end),
// against what decoding the same body with encoding/json costs.
func BenchmarkProcessJSON_CleanFullScan(b *testing.B) {
	body := benchBody(b, "collect_browser.json")
	g := *MustNew()
	g.bodyFast = false
	b.Run("new", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		b.ReportAllocs()
		for b.Loop() {
			g.ProcessJSON(body)
		}
	})
	b.Run("encoding_json", func(b *testing.B) {
		b.SetBytes(int64(len(body)))
		b.ReportAllocs()
		for b.Loop() {
			var v any
			_ = json.Unmarshal(body, &v)
		}
	})
}

func BenchmarkProcessJSON_Dirty(b *testing.B) {
	benchJSON(b, dirtyBody(b), MustNew(), legacy.ModeClean)
}

func BenchmarkProcessJSON_RejectStrict(b *testing.B) {
	benchJSON(b, dirtyBody(b), MustNew(WithMode(ModeReject)), legacy.ModeStrict)
}

// BenchmarkProcessJSON_AllRules: every rule on, clean mode.
func BenchmarkProcessJSON_AllRules(b *testing.B) {
	g := MustNew(WithProfile(ProfileStrict), WithCategories(CatXSS, CatTemplate, CatInjection, CatUnicode,
		CatStructure, CatOutput), WithRedirectHosts("shop.example.com"))
	body := dirtyBody(b)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		g.ProcessJSON(body)
	}
}

func BenchmarkProcessString(b *testing.B) {
	g := MustNew()
	for name, s := range map[string]string{
		"clean": "Áo thun nam cổ tròn, chất liệu cotton 100%, giao hàng toàn quốc",
		"dirty": `Áo thun nam "><svg onload=alert(document.cookie)>`,
	} {
		b.Run(name+"/new", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				g.ProcessString(s, CtxText)
			}
		})
		b.Run(name+"/legacy", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				legacy.CleanString(legacy.CtxText, s)
			}
		})
	}
}
