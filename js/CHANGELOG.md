# Changelog

## 0.1.0 — unreleased

First release: TypeScript port of the Go module at v0.1.3.

- Every rule, the same results as Go on the shared corpus (findings, byte offsets, cleaned output, flags).
- Two builds: `@allsignalme/inputguard` (every rule) and `@allsignalme/inputguard/balanced` (balanced profile).
- `processString`, `checkString`, `processField`, `processValue` (never modifies its input), `mightBeDirty`.
- Linear-time engine for the regular expressions at risk of quadratic time on long hostile input.
