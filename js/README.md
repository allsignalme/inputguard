# @allsignalme/inputguard

The TypeScript port of [inputguard](https://github.com/allsignalme/inputguard), a filter for untrusted input. It
finds content that becomes dangerous where it ends up (script in a page, a SQL query, a shell, a file path, a
header, a spreadsheet, a server-side fetch, a redirect) in strings and JSON-like values, and either **cleans** it
(removing only the malicious part) or **rejects** it (with a report that names rules and fields, never values).

It gives **the same results as the Go module, byte for byte**: same findings, same cleaned output, same flags. The
Go engine records what it does on a shared corpus (`testdata/golden`), and this package's tests check every case
against it.

```sh
npm install @allsignalme/inputguard
```

```ts
import { Guard } from "@allsignalme/inputguard";

const guard = new Guard(); // clean mode, balanced profile

guard.processString("Áo thun <script>alert(1)</script>").value;
// "Áo thun"
guard.processString("https://shop.example.com/p?utm=%3Cscript%3E&q=1", "url").value;
// "https://shop.example.com/p?q=1": only the bad query pair is dropped, the rest is kept verbatim
guard.processField("fbc", "fb.1.2.<svg onload=alert(1)>").value;
// "": an identifier carrying a payload is emptied (fbc is an identifier in the default key table)

const { value, report } = guard.processValue(JSON.parse(body));
// value: the input itself when nothing is cleaned, otherwise a cleaned copy (the input is never modified)
// report: { findings, changed, rejected, truncated, limitExceeded }
```

It runs in browsers, web workers (no DOM needed) and Node 18 or later, and has no dependencies.

## Two builds

| Import | Rules | Size (minified, gzip) |
|---|---|---|
| `@allsignalme/inputguard` | every rule | ≈ 38 KB |
| `@allsignalme/inputguard/balanced` | the balanced profile only | ≈ 23 KB |

The balanced build gives the same results as the full one for a balanced guard. It is meant for browsers, such as a
tracking pixel cleaning what it sends. Asking it for a strict rule, `redirectHosts` or `ssrfAllow` throws.

```ts
import { Guard } from "@allsignalme/inputguard/balanced";
```

## API

`new Guard(options?)` builds an immutable guard: build it once and share it.

| Method | |
|---|---|
| `processString(s, context = "text")` | `{ value, report }` for one value in a context |
| `checkString(s, context)` | the report only |
| `processField(key, s)` | `processString` with the context the classifier picks from the key |
| `processValue(v)` | plain objects, arrays and strings, nested in any combination (other values are left alone) |
| `mightBeDirty(s)` | the fast path: `false` means `processString` returns `s` unchanged with an empty report |
| `enabled(rule)`, `actionFor(rule)`, `mode`, `profile` | the effective configuration |

Helpers: `isClean(report)`, `reportRules(report)`, `rejectedError(report)` (a `RejectedError` whose message lists
rejected rules and paths, never values), `rules()`, `lookupRule(id)`, `defaultKeyTable()`.

A finding is `{ rule, category, severity, path, context, action, offset }`. `offset` is a **byte offset in the UTF-8
encoding** of the decoded value, as in Go.

Contexts: `text`, `url`, `identifier`, `secret`, `path`, `header`, `redirect`, `skip`. The rules, profiles, actions
and contexts are those of the Go module: see its [README](../README.md#rules).

### Options

| Option | Go |
|---|---|
| `mode: "clean" \| "reject"` | `WithMode` |
| `profile: "balanced" \| "strict"` | `WithProfile` |
| `categories`, `rules`, `withoutRules` | `WithCategories`, `WithRules`, `WithoutRules` |
| `actions: { rule: action }`, `severityActions: { severity: action }` | `WithAction`, `WithSeverityAction` |
| `keyTable`, `keyContexts: { url: ["dl"] }`, `classifier` | `WithKeyTable`, `WithKeyContext`, `WithClassifier` |
| `fieldContexts: [["items[*].link", "url"]]`, `exempt: ["html_body"]` | `WithFieldContext`, `WithExempt` |
| `limits: { maxDepth, maxStrings, maxStringBytes, maxFindings, onExceed }` | `WithLimits` |
| `redirectHosts`, `ssrfAllow`, `formulaContexts` | `WithRedirectHosts`, `WithSSRFAllow`, `WithFormulaContexts` |
| `observer` | `WithObserver` |

Options apply in this order: `categories`, `rules`, `withoutRules`, `actions`, `severityActions`, `redirectHosts`.
An action turns its rule on unless `withoutRules` turned it off or the action is `"ignore"`.

## Same results as Go

The engine works on the UTF-8 bytes of each value, like the Go original. Lengths, limits and offsets are counted in
bytes, and invalid sequences are handled the same way. Data tables are generated from Go itself: the HTML entity
table from the `html` package, and the Unicode tables (letters, scripts, format characters) from the `unicode`
package. Decoding therefore does not depend on the Unicode version of the browser.

In a JavaScript string, a lone surrogate counts as one invalid byte: it is an `invalid_utf8` finding and cleaning
replaces it with U+FFFD.

Regular expressions: JavaScript's engine backtracks, so patterns that RE2 runs in linear time can take quadratic
time on hostile input. The patterns at risk run on a linear-time engine (a Pike VM, as in RE2) once the input is
longer than 4 KB. Both engines find the same match, and tests compare them on random input. Tests also run
hostile values of up to 400 KB through every rule: time grows linearly with the length.

## Not in this port

- The raw JSON scanner (`ProcessJSON`, `CheckJSON`, `MaybeDirty`): values come from `JSON.parse`. So there is no
  `duplicate_key` (`JSON.parse` keeps the last value), no `invalidJSON` flag, and a string holding JSON is
  inspected as text (Go with `WithEmbeddedJSON(false)`).
- `WithKeyPolicy`: turn `key_operator` and `key_invalid` on with `rules` or `categories` instead.
- Custom detectors (`WithDetector`), `CleanLeaves`, the `httpguard` adapter and `TopicFilter`.
- The NFKC mapping of non-ASCII host names (ssrf and open_redirect rules) uses the JavaScript engine's
  `normalize("NFKC")`, which may differ from Go's on characters added in recent Unicode versions.

## Development

```sh
npm ci
npm run typecheck
npm test            # golden parity, API, hostile inputs, both regular expression engines
npm run coverage    # with an 80 % threshold
npm run size        # bundle sizes, budget of the balanced build, smoke test in a worker thread
```

After changing a rule in the Go module, regenerate the golden files and tables from the repository root, and
review the diff:

```sh
go test -run 'TestGolden|TestJSTables' -update .
```

## License

MIT
