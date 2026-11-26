# inputguard

A fast, configurable filter for untrusted input in Go. It finds content that becomes dangerous where it ends up
(script in a page, a SQL query, a shell, a file path, a header, a spreadsheet, a server-side fetch, a redirect)
in JSON documents, Go values and single strings, and either **cleans** it (removing only the malicious part) or
**rejects** it (with a report that names rules and fields, never values).

```go
g := inputguard.MustNew() // clean mode, balanced profile

out, report := g.ProcessJSON(body)
// out: body itself when nothing is found (one pass, no allocation);
//      otherwise a copy where only the cleaned strings differ, byte for byte.
```

- **Fast on clean input.** One pass over the bytes, driven by a table built from the enabled rules, proves that
  most bodies cannot contain anything; they are returned as is, without parsing or allocating (≈1.2 GB/s).
- **Precise when cleaning.** A streaming scanner decodes only suspicious strings and splices the cleaned ones
  back in place: key order, number formatting (big integers included) and whitespace are untouched.
- **Context-aware.** A URL loses only the bad query parameter; free text is cut before the payload; an identifier
  or hash is emptied (one changed byte would break it); a secret is never inspected when rejecting.
- **Configurable.** Profiles, per-rule and per-severity actions, key tables, path patterns, exemptions, limits,
  allowed redirect hosts, SSRF allow lists, custom detectors.
- **Tested against attackers' encodings.** Percent-encoding (nested), HTML entities, JSON and JavaScript escapes
  (also inside JSON embedded in a string), fullwidth and small forms, ligatures, invisible characters, line breaks
  inside keywords. Fuzzing checks that cleaning is idempotent, that output stays valid JSON, and that the fast
  checks never change what the rules find.

```
go get github.com/allsignalme/inputguard
```

Go 1.24 or later. One dependency: `golang.org/x/text` (NFKC).

## Rules

| Category | Rule | Default profile | What it catches |
|---|---|---|---|
| xss | `tag_dangerous` | balanced | `<script`, `<img`, `<svg`… even unclosed |
| xss | `tag_generic` | balanced | a closed known tag, a tag with attributes, comments, CDATA |
| xss | `event_handler` | balanced | `onerror=`, `" onmouseover=` (attribute breakout) |
| xss | `scheme` | balanced | `javascript:`, `vbscript:`, `data:text/html`… in any encoding |
| template | `template` | strict | `{{ }}`, `{% %}`, `${ }`, `<% %>` |
| template | `js_call` | strict | `eval(`, `atob(`, `document.cookie`, `.innerHTML`… |
| template | `js_breakout` | strict | `";alert(1)//` |
| injection | `sql_injection` | strict | tautologies, `UNION SELECT`, stacked queries, time-based and catalog probes |
| injection | `nosql_operator` | strict | `field[$ne]=`, `{"$gt": ""}` in a string, operator keys, `$where` |
| injection | `path_traversal` | balanced | `../` (encoded, overlong, fullwidth, `..;/`), sensitive files (`/etc/passwd`, `win.ini`…) |
| injection | `header_crlf` | strict | CR/LF in a header value, `%0d%0a` in a URL |
| injection | `command` | strict | `; rm -rf`, `$(…)`, `` `…` ``, `\| curl`, `${IFS}` |
| unicode | `control_char` | balanced | C0/C1 controls, DEL, NUL |
| unicode | `bidi_control` | balanced | bidirectional overrides (Trojan Source) |
| unicode | `invisible_char` | strict | zero-width and other invisible characters |
| unicode | `invalid_utf8` | balanced | bytes that are not UTF-8 (replaced by U+FFFD when cleaning) |
| unicode | `mixed_scripts` | strict | one word mixing Latin with Cyrillic, Greek… (`pаypal`) |
| structure | `too_complex` | balanced | over a depth, size or count limit |
| structure | `proto_pollution` | balanced | `__proto__`, `constructor.prototype` keys |
| structure | `duplicate_key` | strict | the same key twice in one object |
| structure | `key_operator` | Mongo key policy | keys starting with `$` |
| structure | `key_invalid` | Mongo key policy | keys with `.` or NUL |
| output | `formula_injection` | strict | `=`, `+cmd\|`, `@SUM(` at the start of a cell value |
| output | `ssrf` | strict | URLs to loopback, private, link-local, metadata hosts, in every IP notation |
| output | `open_redirect` | strict | redirect targets outside the allowed hosts, including `//host`, `/\host`, `https:host` |

`inputguard.Rules()` lists them with severity and summary.

## Modes, profiles, actions

```go
// Storefront events, third-party webhooks: clean and keep the data.
clean := inputguard.MustNew()

// Writes a person makes through your API: reject with a 400.
reject := inputguard.MustNew(inputguard.WithMode(inputguard.ModeReject)) // strict profile by default

// Pick rules and actions.
g := inputguard.MustNew(
	inputguard.WithRules(inputguard.RuleSSRF, inputguard.RuleSQLInjection),
	inputguard.WithAction(inputguard.RuleSSRF, inputguard.ActionReject),       // reject on this one
	inputguard.WithAction(inputguard.RuleTagGeneric, inputguard.ActionReport), // only report this one
	inputguard.WithSeverityAction(inputguard.SeverityLow, inputguard.ActionIgnore),
)
```

Actions are `ActionClean`, `ActionReject`, `ActionReport` and `ActionIgnore`. If any finding is rejected, the whole
input is returned unchanged with `Report.Rejected`; `Report.Err()` then returns an error whose message lists the
rules and fields (`errors.Is(err, inputguard.ErrRejected)`).

## Contexts

How a value is checked and cleaned depends on its context:

| Context | Cleaning | Chosen for keys like |
|---|---|---|
| `CtxText` | cut before the payload | anything else |
| `CtxURL` | drop the bad parameter, fragment or path segment; a bad scheme or host, path traversal or an internal address (`ssrf`) empties it | `url`, `*_url`, `href`, `src`, `link`… or a value starting with `http(s)://`, `//` |
| `CtxRedirect` | URL rules plus `open_redirect` | `redirect`, `return_to`, `next`, `success_url`… |
| `CtxIdentifier` | emptied | `id`, `*_id`, `email`, `phone`, hashed fields, click ids, `*_token`… |
| `CtxSecret` | emptied when cleaning (a password with markup would be stored empty: use `CtxSkip` for fields you must keep as sent); never inspected when rejecting | `password`, `token`, `api_key`, `*secret*`… |
| `CtxPath` | emptied on traversal | `path`, `file`, `filename`, `*_path`… |
| `CtxHeader` | CR/LF removed | `user_agent`, `cookie`, `host`… |
| `CtxSkip` | not inspected | — |

Change it with `WithKeyTable` (start from `DefaultKeyTable()`), `WithKeyContext`, `WithClassifier`, or per path:

```go
g := inputguard.MustNew(
	inputguard.WithFieldContext("items[*].sku", inputguard.CtxIdentifier),
	inputguard.WithExempt("template.html", "**.description"), // content not inspected (key names still are)
)
```

Patterns: `a.b`, `items[*].x` (any index), `items[0].x`, `*.x` (any key), `**.x` (any depth).

## Structure and limits

The scanner checks key names (markup, control characters, prototype pollution, operator keys), JSON embedded in
strings (parsed and cleaned member by member, so it stays valid JSON), and limits that bound the work on a
hostile document:

```go
inputguard.WithLimits(inputguard.Limits{
	MaxDepth: 32, MaxStrings: 20000, MaxStringBytes: 1 << 20, MaxMembers: 10000, MaxElements: 100000,
	MaxFindings: 100,
	OnExceed: inputguard.ActionDefault, // clean mode: prune what is over; reject mode: reject
})
```

Nesting past the limit is skipped iteratively (a million `[` does not exhaust the stack) and still validated.
Limits apply to documents that are scanned; in clean mode a body the fast path clears is returned untouched
whatever its shape (`OnExceed: ActionReject` scans every body).

A body that is not valid JSON is returned unchanged with `Report.InvalidJSON`. Reject it: Go's `json.Decoder`
(and frameworks built on it) reads the first value of `{"a":"<script>"} x` and ignores the rest.

## HTTP

```go
mw := httpguard.Middleware(httpguard.Config{
	Guard:    inputguard.MustNew(),
	Query:    true,                   // also query parameters
	Headers:  []string{"User-Agent"}, // and these headers
	OnReport: func(r *http.Request, rep inputguard.Report) { log.Print(rep.Summary(5)) },
})
http.Handle("/api/", mw(api))
```

A body is JSON when its Content-Type says so or when it starts with `{` or `[` (handlers decode JSON whatever the
header says); other bodies, uploads included, pass untouched. JSON bodies are cleaned in place before the handler
reads them. A rejected request gets `400 {"error":{"code":"input_rejected","message":…,"fields":[{"path":…,"rule":…}]}}`,
a body that does not parse gets `400 {"error":{"code":"invalid_json",…}}`. NDJSON / JSON Lines bodies are checked
line by line. Query pairs are split on `&` and `;` (for handlers behind `http.AllowQuerySemicolons`); only the pairs
that change are rewritten.

## Other entry points

```go
out, r := g.ProcessString(s, inputguard.CtxURL)     // one value
out, r := g.ProcessField("return_to", s)            // one value, context from the name
v, r := g.ProcessValue(map[string]any{…})           // decoded Go values, cleaned in place
changes, r := g.CleanLeaves(v)                      // what cleaning would change, without changing v
filter := g.TopicFilter(inputguard.TopicFilterConfig{Topics: []string{"events"}}) // message payloads
```

Custom rules plug into the same pipeline:

```go
inputguard.WithDetector(inputguard.Detector{
	ID: "ssn", Category: "pii", Contexts: []inputguard.Context{inputguard.CtxText},
	MayMatch: func(raw string) bool { return strings.Count(raw, "-") >= 2 }, // cheap prefilter
	Detect: func(in inputguard.Input) int { /* offset in in.Decoded, or -1 */ },
})
```

## Performance

Go 1.27, Intel 14-core laptop, `go test -bench .` on the fixtures in `testdata/` (1.4 KB and 2.8 KB event
payloads). "Previous engine" is the implementation this library grew out of, kept in `internal/legacy` as a test
oracle.

| | inputguard | previous engine |
|---|---|---|
| clean body, fast path | 1.1 µs, 0 allocs | 0.8 µs, 0 allocs |
| clean body, full scan (fast path off) | 6.3 µs, 0 allocs | — (`encoding/json` decode alone: 27 µs, 309 allocs) |
| body with one payload, cleaned | 6.4 µs, 29 allocs | 30 µs, 230 allocs |
| strict profile, reject mode | 64 µs, 167 allocs | 163 µs, 296 allocs |

The balanced fast path also covers path traversal, prototype pollution and invalid UTF-8, which the previous
engine did not check.

## Guarantees and limits

- Reports never contain values, only rule ids, field paths (unsafe key names print as `[key]`) and offsets.
- The guard is immutable after `New` and safe for concurrent use.
- Fuzzing (`go test -fuzz`) checks: no panic; valid JSON in, valid JSON out; cleaning is idempotent; the same
  findings with every fast check switched off; and, configured like it, the same results as the previous engine.
- Work is linear in the size of the input (no backtracking regular expressions; Go's RE2).
- Values are decoded the way a browser or a lenient server would before matching: nested percent-encoding, HTML
  entities, JavaScript escapes, removal of invisible characters, and NFKC for fullwidth forms, small forms, Latin
  ligatures and dot leaders. Other compatibility characters (mathematical letters, superscripts) are not folded:
  nothing reads them as markup or code.
- Free text cut before a payload keeps its own spelling when it decodes to the same text (`Tom &amp; Jerry
  <script>` keeps `&amp;`); otherwise the kept part is returned decoded.
- This is a filter, not a substitute for output encoding, parameterized queries, or checking the address an
  outbound request actually connects to. `ssrf` does not resolve DNS names: a name that resolves to a private
  address passes; check at connection time as well.
- `httpguard` inspects JSON bodies only (not forms or multipart). A body that is a bare JSON string is inspected
  only when declared as JSON.

## JavaScript and TypeScript

[`js/`](js/) holds a TypeScript port published on npm as `@allsignalme/inputguard`. It gives the same results as
this module on the shared corpus (`testdata/golden`, written by `go test -run TestGolden -update`), and has a
smaller build with the balanced rules only for browsers. See [js/README.md](js/README.md).

## License

MIT
