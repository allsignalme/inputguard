package inputguard

// RuleID names one kind of malicious content. It is what reports, logs and error messages carry — never the value.
type RuleID string

// Cross-site scripting: content a browser would run when the value is rendered into HTML or used as a link.
const (
	RuleTagDangerous RuleID = "tag_dangerous" // <script, <img, <svg… (also unclosed)
	RuleTagGeneric   RuleID = "tag_generic"   // a closed known tag, a tag with attributes, comment, CDATA, doctype
	RuleEventHandler RuleID = "event_handler" // onerror=, onload=… (attribute breakout)
	RuleScheme       RuleID = "scheme"        // javascript:, vbscript:, data:text/html…
	RuleTemplate     RuleID = "template"      // {{ }}, {% %}, ${ }, <% %> (server- and client-side template injection)
	RuleJSCall       RuleID = "js_call"       // eval(, atob(, document.cookie…
	RuleJSBreakout   RuleID = "js_breakout"   // ";alert(1)// (breaking out of a JavaScript string)
)

// Server-side injection.
const (
	RuleSQLInjection  RuleID = "sql_injection"  // ' OR 1=1--, UNION SELECT, ; DROP TABLE…
	RuleNoSQLOperator RuleID = "nosql_operator" // {"$ne": …}, $where, operator keys
	RulePathTraversal RuleID = "path_traversal" // ../, ..\, %2e%2e%2f, /etc/passwd
	RuleHeaderCRLF    RuleID = "header_crlf"    // CR/LF where a header, cookie or redirect value is built
	RuleCommand       RuleID = "command"        // ; rm -rf, $(…), `…`, | curl
)

// Unicode abuse.
const (
	RuleControlChar  RuleID = "control_char"   // C0/C1 control characters, DEL, NUL
	RuleBidi         RuleID = "bidi_control"   // bidirectional overrides (Trojan Source)
	RuleInvisible    RuleID = "invisible_char" // zero-width and other invisible characters
	RuleInvalidUTF8  RuleID = "invalid_utf8"   // bytes that are not valid UTF-8 (overlong forms included)
	RuleMixedScripts RuleID = "mixed_scripts"  // confusable identifier mixing scripts (Latin + Cyrillic…)
)

// Structure of the document.
const (
	RuleTooComplex     RuleID = "too_complex"     // over a depth, size or count limit
	RuleProtoPollution RuleID = "proto_pollution" // __proto__, constructor.prototype
	RuleDuplicateKey   RuleID = "duplicate_key"   // the same key twice in one object (parsers disagree on which wins)
	RuleKeyOperator    RuleID = "key_operator"    // key starting with $ (MongoDB operator)
	RuleKeyInvalid     RuleID = "key_invalid"     // key with ., NUL or other characters a store rejects
)

// Output contexts.
const (
	RuleFormula  RuleID = "formula_injection" // =, +, -, @ at the start of a value later opened as a spreadsheet
	RuleSSRF     RuleID = "ssrf"              // URL pointing at a private, loopback, link-local or metadata address
	RuleRedirect RuleID = "open_redirect"     // redirect target outside the allowed hosts
)

// Category groups rules for configuration and metrics.
type Category string

const (
	CatXSS       Category = "xss"
	CatTemplate  Category = "template"
	CatInjection Category = "injection"
	CatUnicode   Category = "unicode"
	CatStructure Category = "structure"
	CatOutput    Category = "output"
)

// Severity orders findings. Actions and filters can be set per severity.
type Severity int

const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// RuleInfo describes a rule.
type RuleInfo struct {
	ID       RuleID
	Category Category
	Severity Severity
	// Profile is the least strict profile that enables the rule by default.
	Profile Profile
	// Summary is a one-line description safe to show to an API client.
	Summary string
}

var ruleTable = []RuleInfo{
	{RuleTagDangerous, CatXSS, SeverityCritical, ProfileBalanced, "HTML tag that runs script"},
	{RuleTagGeneric, CatXSS, SeverityHigh, ProfileBalanced, "HTML markup"},
	{RuleEventHandler, CatXSS, SeverityCritical, ProfileBalanced, "HTML event handler attribute"},
	{RuleScheme, CatXSS, SeverityCritical, ProfileBalanced, "script URL scheme"},
	{RuleTemplate, CatTemplate, SeverityHigh, ProfileStrict, "template expression"},
	{RuleJSCall, CatTemplate, SeverityHigh, ProfileStrict, "JavaScript call"},
	{RuleJSBreakout, CatTemplate, SeverityHigh, ProfileStrict, "JavaScript string breakout"},

	{RuleSQLInjection, CatInjection, SeverityHigh, ProfileStrict, "SQL injection"},
	{RuleNoSQLOperator, CatInjection, SeverityHigh, ProfileStrict, "NoSQL query operator"},
	{RulePathTraversal, CatInjection, SeverityHigh, ProfileBalanced, "path traversal"},
	{RuleHeaderCRLF, CatInjection, SeverityHigh, ProfileStrict, "line break in a header value"},
	{RuleCommand, CatInjection, SeverityHigh, ProfileStrict, "shell command injection"},

	{RuleControlChar, CatUnicode, SeverityMedium, ProfileBalanced, "control character"},
	{RuleBidi, CatUnicode, SeverityHigh, ProfileBalanced, "bidirectional text override"},
	{RuleInvisible, CatUnicode, SeverityLow, ProfileStrict, "invisible character"},
	{RuleInvalidUTF8, CatUnicode, SeverityMedium, ProfileBalanced, "invalid UTF-8"},
	{RuleMixedScripts, CatUnicode, SeverityMedium, ProfileStrict, "identifier mixing look-alike scripts"},

	{RuleTooComplex, CatStructure, SeverityMedium, ProfileBalanced, "document too deep or too large"},
	{RuleProtoPollution, CatStructure, SeverityCritical, ProfileBalanced, "prototype pollution key"},
	{RuleDuplicateKey, CatStructure, SeverityMedium, ProfileStrict, "duplicate key"},
	{RuleKeyOperator, CatStructure, SeverityHigh, ProfileOptIn, "operator key"},
	{RuleKeyInvalid, CatStructure, SeverityMedium, ProfileOptIn, "invalid key"},

	{RuleFormula, CatOutput, SeverityMedium, ProfileStrict, "spreadsheet formula"},
	{RuleSSRF, CatOutput, SeverityHigh, ProfileStrict, "URL to an internal address"},
	{RuleRedirect, CatOutput, SeverityMedium, ProfileStrict, "redirect to a foreign host"},
}

var ruleIndex = func() map[RuleID]RuleInfo {
	m := make(map[RuleID]RuleInfo, len(ruleTable))
	for _, r := range ruleTable {
		m[r.ID] = r
	}
	return m
}()

// Rules lists every rule the library knows, in a stable order.
func Rules() []RuleInfo {
	out := make([]RuleInfo, len(ruleTable))
	copy(out, ruleTable)
	return out
}

// LookupRule returns a rule's description.
func LookupRule(id RuleID) (RuleInfo, bool) {
	r, ok := ruleIndex[id]
	return r, ok
}
