package inputguard_test

import (
	"errors"
	"fmt"

	"github.com/allsignalme/inputguard"
)

// The default guard cleans: the malicious part of a value is removed, everything else is kept byte for byte.
func Example() {
	g := inputguard.MustNew()
	out, r := g.ProcessJSON([]byte(`{"name":"Áo thun <img src=x onerror=alert(1)>","price":199000,"url":"https://shop.example.com/p?a=1&x=javascript:alert(1)"}`))
	fmt.Println(string(out))
	for _, f := range r.Findings {
		fmt.Println(f.Path, f.Rule)
	}
	// Output:
	// {"name":"Áo thun","price":199000,"url":"https://shop.example.com/p?a=1"}
	// name tag_dangerous
	// name tag_generic
	// name event_handler
	// url scheme
}

// A reject-mode guard (strict profile) for configuration APIs: nothing is changed, the report says why.
func Example_reject() {
	g := inputguard.MustNew(inputguard.WithMode(inputguard.ModeReject))
	_, r := g.ProcessJSON([]byte(`{"title":"Hello {{constructor.constructor('alert(1)')()}}","note":"fine"}`))
	err := r.Err()
	fmt.Println(errors.Is(err, inputguard.ErrRejected))
	fmt.Println(err)
	// Output:
	// true
	// input rejected: title: template expression
}

// Field contexts decide how a value is cleaned; exemptions skip content checks for a subtree.
func Example_fields() {
	g := inputguard.MustNew(
		inputguard.WithFieldContext("items[*].sku", inputguard.CtxIdentifier),
		inputguard.WithExempt("template.html"),
	)
	out, _ := g.ProcessJSON([]byte(`{"items":[{"sku":"A1<b>","title":"Mug <b>"}],"template":{"html":"<b>kept</b>"}}`))
	fmt.Println(string(out))
	// Output:
	// {"items":[{"sku":"","title":"Mug"}],"template":{"html":"<b>kept</b>"}}
}

// Rules beyond the default profile, each with its own action.
func Example_rules() {
	g := inputguard.MustNew(
		inputguard.WithRules(inputguard.RuleSSRF, inputguard.RuleFormula),
		inputguard.WithAction(inputguard.RuleSSRF, inputguard.ActionReject),
	)
	_, r := g.ProcessJSON([]byte(`{"webhook_url":"http://169.254.169.254/latest/meta-data/"}`))
	fmt.Println(r.Rejected, r.Rules())
	out, _ := g.ProcessString("=HYPERLINK(\"http://evil.example\",\"x\")", inputguard.CtxText)
	fmt.Println(out)
	// Output:
	// true [ssrf]
	// '=HYPERLINK("http://evil.example","x")
}
