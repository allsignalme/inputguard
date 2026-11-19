# Changelog

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
- `httpguard`: net/http middleware.
