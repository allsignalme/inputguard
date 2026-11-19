package inputguard

import "strings"

// XSS: tags, event handlers, script schemes. Template / JavaScript-call rules are a separate group (strict profile).

var allInspected = maskOf(CtxText, CtxURL, CtxIdentifier, CtxPath, CtxHeader, CtxRedirect)

func init() {
	registerDetector(&builtinDetector{
		name:     "xss",
		rules:    []RuleID{RuleTagDangerous, RuleTagGeneric, RuleEventHandler, RuleScheme},
		contexts: allInspected,
		fast:     fbXSS,
		needNorm: true,
		detect:   detectXSS,
		clean:    cleanCut,
	})
	registerDetector(&builtinDetector{
		name:     "template",
		rules:    []RuleID{RuleTemplate, RuleJSCall, RuleJSBreakout},
		contexts: allInspected,
		mayMatch: func(_ *Guard, raw string) bool { return mayHaveTemplateOrJS(raw) },
		needNorm: true,
		detect:   detectTemplate,
		clean:    cleanCut,
	})
}

func detectXSS(g *Guard, in *input, emit func(RuleID, int)) {
	f := in.folded()
	if dangerous, generic := scanTags(f); dangerous >= 0 || generic >= 0 {
		if dangerous >= 0 {
			emit(RuleTagDangerous, dangerous)
		}
		if generic >= 0 {
			emit(RuleTagGeneric, generic)
		}
	}
	if idx := scanHandlers(f); idx >= 0 {
		emit(RuleEventHandler, idx)
	}
	if !mayHaveScheme(f) {
		return
	}
	// Scheme after a quote/=/( anywhere, and "javascript:x" at the start of any value.
	if idx := matchIndex(schemeAfterDelimiter, f); idx >= 0 {
		emit(RuleScheme, idx)
	}
	if idx := matchIndex(schemeAtStart, f); idx >= 0 {
		emit(RuleScheme, idx)
	}
	// A bare dangerous scheme (or data:text/html) at the start counts where the value is used as a link. In text,
	// "JavaScript: The Good Parts" is a book title.
	if in.ctx.isURL() || g.profile == ProfileStrict {
		if idx := matchIndex(schemeAtStartURL, f); idx >= 0 {
			emit(RuleScheme, idx)
		}
	}
}

func detectTemplate(_ *Guard, in *input, emit func(RuleID, int)) {
	f := in.folded()
	if strings.Contains(f, "{{") || strings.Contains(f, "{%") || strings.Contains(f, "${") || strings.Contains(f, "<%") {
		if idx := matchIndex(templateRe, f); idx >= 0 {
			emit(RuleTemplate, idx)
		}
	}
	paren := strings.IndexByte(f, '(') >= 0
	if jsCallGate(f, paren) {
		if idx := matchIndex(jsCallRe, f); idx >= 0 {
			emit(RuleJSCall, idx)
		}
	}
	if paren && strings.ContainsAny(f, "\"'`") {
		if idx := matchIndex(jsBreakoutRe, f); idx >= 0 {
			emit(RuleJSBreakout, idx)
		}
	}
}

// jsCallWords: names one of the jsCallRe alternatives needs.
var (
	jsCallNames = []string{
		"eval", "atob", "btoa", "settimeout", "setinterval", "fromcharcode", "unescape", "decodeuricomponent",
		"execscript", "import",
	}
	jsPropNames = []string{"function", "html", "document", "window", "globalthis"}
)

func jsCallGate(f string, paren bool) bool {
	if paren {
		for _, w := range jsCallNames {
			if strings.Contains(f, w) {
				return true
			}
		}
	}
	for _, w := range jsPropNames {
		if strings.Contains(f, w) {
			return true
		}
	}
	return false
}

// mayHaveTemplateOrJS: the template rule needs { or <, the call and breakout rules (, the property rules one of
// jsPropNames; an encoded or fullwidth form may decode to any of them.
func mayHaveTemplateOrJS(raw string) bool {
	return mayBeEncoded(raw) || strings.ContainsAny(raw, "{<(") || containsAnyFold(raw, jsPropNames)
}
