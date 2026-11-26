# Changelog

## 0.1.1 — 2026-11-26

- `processValue` copies a value only down to `limits.maxDepth`: a value nested thousands of levels deep (or one
  that contains itself) no longer overflows the stack when something in it is cleaned.
- `typesVersions` for `@allsignalme/inputguard/balanced`, so TypeScript projects with `moduleResolution: node`
  find its types.

## 0.1.0 — 2026-11-26

First release: TypeScript port of the Go module at v0.1.3.

- Every rule, the same results as Go on the shared corpus (findings, byte offsets, cleaned output, flags).
- Two builds: `@allsignalme/inputguard` (every rule) and `@allsignalme/inputguard/balanced` (balanced profile).
- `processString`, `checkString`, `processField`, `processValue` (never modifies its input), `mightBeDirty`.
- Linear-time engine for the regular expressions at risk of quadratic time on long hostile input.
