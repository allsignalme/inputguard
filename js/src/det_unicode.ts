// Character-level Unicode rules: control characters, bidirectional overrides, invisible characters, invalid UTF-8.
// They look at the raw value and are cleaned by removing the offending characters.

import { decodeRune, RUNE_ERROR, RUNE_ERROR_BYTES } from "./bytes.js";
import type { DetectorDef, Emit, Input } from "./detector.js";
import { ALL_INSPECTED, CLEAN_CHARS } from "./detector.js";
import { FB_UNICODE } from "./prefilter.js";
import type { RuleID } from "./rule.js";

export const UNI_NONE = 0;
export const UNI_CONTROL = 1;
export const UNI_BIDI = 2;
export const UNI_INVISIBLE = 3;
export const UNI_INVALID = 4;

/** classifyRune: which character-level rule a rune falls under. Tab, LF, CR are text; ZWJ builds emoji. */
export function classifyRune(r: number): number {
  if (r === 0x09 || r === 0x0a || r === 0x0d) return UNI_NONE;
  if (r < 0x20 || r === 0x7f || (r >= 0x80 && r <= 0x9f)) return UNI_CONTROL;
  if ((r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)) return UNI_BIDI;
  switch (r) {
    case 0x00ad:
    case 0x180e:
    case 0x200b:
    case 0x200c:
    case 0x200e:
    case 0x200f:
    case 0x2060:
    case 0x2061:
    case 0x2062:
    case 0x2063:
    case 0x2064:
    case 0xfeff:
      return UNI_INVISIBLE;
  }
  return UNI_NONE;
}

const UNI_RULES: (RuleID | null)[] = [null, "control_char", "bidi_control", "invisible_char", "invalid_utf8"];

function detectUnicode(_env: unknown, input: Input, emit: Emit): void {
  const s = input.raw;
  for (let i = 0; i < s.length; ) {
    const [r, size] = decodeRune(s, i);
    const k = r === RUNE_ERROR && size === 1 ? UNI_INVALID : classifyRune(r);
    if (k !== UNI_NONE) emit(UNI_RULES[k] as RuleID, i);
    i += size;
  }
}

/** stripUnicodeIssues removes characters of the given kinds; invalid UTF-8 becomes U+FFFD. */
export function stripUnicodeIssues(s: string, drop: boolean[]): string {
  let out: string | null = null;
  for (let i = 0; i < s.length; ) {
    const [r, size] = decodeRune(s, i);
    const k = r === RUNE_ERROR && size === 1 ? UNI_INVALID : classifyRune(r);
    if (k !== UNI_NONE && drop[k]) {
      if (out === null) out = s.slice(0, i);
      if (k === UNI_INVALID) out += RUNE_ERROR_BYTES;
      i += size;
      continue;
    }
    if (out !== null) out += s.slice(i, i + size);
    i += size;
  }
  return out === null ? s : out;
}

export const unicodeDetector: DetectorDef = {
  name: "unicode",
  rules: ["control_char", "bidi_control", "invisible_char", "invalid_utf8"],
  contexts: ALL_INSPECTED,
  fast: FB_UNICODE,
  detect: detectUnicode,
  clean: CLEAN_CHARS,
};
