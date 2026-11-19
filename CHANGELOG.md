# Changelog

## v0.1.3 — 2026-11-19

- `formula_injection`: the function name must touch its parenthesis, as spreadsheets require: `- Image (front view)`,
  `+ Call (555) 123-4567` pass.

## v0.1.2 — 2026-11-19

Fewer false positives on everyday text, found by running real admin and merchant input through the strict profile:
- `sql_injection`: a tautology needs a literal operand (`' or 1=1`, `' or 'a'='a`, `' or name='x`), a comment after a
  quote must end the value (`admin'--`), `UNION SELECT` must be followed by a select list, and `SELECT … FROM`,
  `DELETE FROM`, `INSERT INTO`, `UPDATE … SET` after `;` need a quote, a number or `)` before it. "the European Union
  (select countries only)", `Samsung 55" -- 4K`, "Googlebot; select pages from sitemap", "10 or 20 > 5 items",
  "'Hot' or 'New' = tag" and a pasted service-account key (`"-----BEGIN PRIVATE KEY-----`) pass.
- `command`: common words after a separator (`reboot`, `id`, `sleep 8 hours`, `bash party`) no longer count; `id`,
  `whoami`… count inside `$(…)` or backticks.
- `formula_injection`: only functions that reach outside the sheet (`HYPERLINK`, `WEBSERVICE`, `IMPORTXML`…) or a DDE
  call (`cmd|'…'`); `- Combo(2 áo)`, `@Admin(VN) team`, `=SUM(A1:A3)` pass.
- Identifiers: a value whose only findings are stray characters (zero-width space, control characters…) keeps its
  content with the characters removed, instead of being emptied.

## v0.1.1 — 2026-11-19

- `formula_injection` flags only what a spreadsheet would run: a leading `=` `+` `-` `@` followed by a function
  call (`HYPERLINK(`, `SUM(`) or a DDE call (`cmd|`). Text such as `-20% (Black Friday)` or `=== Sale ===` passes;
  the value is read as received (fullwidth or percent-encoded signs are not formulas).
- `mixed_scripts` needs a look-alike letter in the minority script (`pаypal`, `Χerox`); `10kΩ` and `Ωmega` pass.
- `open_redirect`: a non-HTTP scheme counts when it has an authority (`intent://`, `ftp://`) or runs or embeds
  content (`data:`, `javascript:`…); `Hotline: 1900 1234` in a redirect field is not a scheme.

## v0.1.0 — 2026-11-19

First release.

- Guard with clean and reject modes, balanced and strict profiles, per-rule and per-severity actions.
- Rules: XSS (tags, event handlers, script schemes), template and JavaScript injection, SQL, NoSQL operators, path
  traversal, CR/LF in headers, shell commands, control / bidi / invisible characters, invalid UTF-8, mixed scripts,
  prototype pollution, duplicate keys, Mongo operator and invalid keys, structural limits, spreadsheet formulas,
  SSRF, open redirects. Custom detectors.
- Streaming JSON scanner that edits cleaned strings in place; single-pass fast path for clean bodies.
- Contexts chosen by key table, path patterns or a custom classifier; exemptions.
- `ProcessJSON`, `CheckJSON`, `ProcessString`, `ProcessField`, `ProcessValue`, `CleanLeaves`, `TopicFilter`.
- `httpguard`: net/http middleware (JSON recognised by content, NDJSON line by line, query pairs split on `&`
  and `;`, invalid JSON answered 400).
