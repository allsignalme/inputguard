# Changelog

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
