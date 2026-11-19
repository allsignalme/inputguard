package inputguard

import (
	"sync"
	"testing"
)

// TestConcurrentUse: one guard shared by many goroutines (pooled scanners, lazy default classifier) gives every
// caller its own result. Run with -race.
func TestConcurrentUse(t *testing.T) {
	g := MustNew(WithRules(RuleDuplicateKey))
	inputs := map[string]string{
		`{"a":"x<script>","b":[1,"<b>y</b>"]}`:      `{"a":"x","b":[1,""]}`,
		`{"__proto__":1,"k":"v","k":"w"}`:           `{"k":"w"}`,
		`{"d":"{\"n\":\"<img src=x onerror=1>\"}"}`: `{"d":"{\"n\":\"\"}"}`,
		`{"clean":"nothing here","n":12.50}`:         `{"clean":"nothing here","n":12.50}`,
	}
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				for in, want := range inputs {
					if out, _ := g.ProcessJSON([]byte(in)); string(out) != want {
						t.Errorf("%s: got %s, want %s", in, out, want)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}
