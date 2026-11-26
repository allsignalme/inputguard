// Port of internal/norm: turns a value into what a browser or interpreter would see. Percent-encoding, HTML
// entities, JavaScript escapes, NFKC compatibility forms and invisible characters are decoded or removed, up to
// MAX_ROUNDS nested layers. All strings are byte strings (see bytes.ts).

import {
  asciiLower,
  decodeRune,
  encodeRune,
  hexPair,
  mapRunes,
  RUNE_ERROR,
  RUNE_ERROR_BYTES,
  toBytes,
  toValidUTF8,
  unhex,
  validRune,
} from "./bytes.js";
import { ENTITY2_DATA, ENTITY_DATA, LONGEST_ENTITY_WITHOUT_SEMICOLON, WINDOWS_1252 } from "./tables/entities.js";

/** Number of decoding rounds: three nested layers (%25253C). */
export const MAX_ROUNDS = 3;

export interface Normalized {
  /** %XX, entities, escapes and NFKC decoded, invisible characters removed, case kept. */
  decoded: string;
  /** decoded with ASCII lowercased: the same length, so an offset in folded is valid in decoded. */
  folded: string;
}

/** normalize decodes repeatedly until the string stops changing (at most MAX_ROUNDS rounds). */
export function normalize(s: string): Normalized {
  let d = s;
  for (let i = 0; i < MAX_ROUNDS; i++) {
    const next = normalizeRound(d);
    if (next === d) break;
    d = next;
  }
  // The last round can produce new invisible characters (%00, an escaped zero-width space): remove them too.
  d = stripInvisible(d);
  return { decoded: d, folded: asciiLower(d) };
}

// One layer. %XX before entities, so that %26lt%3B becomes < in a single round.
function normalizeRound(s: string): string {
  s = stripInvisible(s);
  s = decodeJSEscapes(s);
  s = decodePercent(s);
  s = unescapeHTML(s);
  return foldCompat(s);
}

/**
 * isFoldable: fullwidth ASCII (U+FF01–FF5E), small forms (U+FE50–FE6B), Latin ligatures (U+FB00–FB06) and the dot
 * leaders (U+2024–2026): the compatibility characters foldCompat replaces with their NFKC form.
 */
export function isFoldable(r: number): boolean {
  return (
    (r >= 0xff01 && r <= 0xff5e) || (r >= 0xfe50 && r <= 0xfe6b) || (r >= 0xfb00 && r <= 0xfb06) || (r >= 0x2024 && r <= 0x2026)
  );
}

const foldCache = new Map<number, string>();

function nfkcOf(r: number): string {
  let v = foldCache.get(r);
  if (v === undefined) {
    v = toBytes(String.fromCodePoint(r).normalize("NFKC"));
    foldCache.set(r, v);
  }
  return v;
}

/** foldCompat replaces the isFoldable characters of s with their NFKC form. */
export function foldCompat(s: string): string {
  let start = -1;
  for (let i = 0; i < s.length; ) {
    const [r, size] = decodeRune(s, i);
    if (isFoldable(r)) {
      start = i;
      break;
    }
    i += size;
  }
  if (start < 0) return s;
  let out = s.slice(0, start);
  for (let i = start; i < s.length; ) {
    const [r, size] = decodeRune(s, i);
    out += isFoldable(r) ? nfkcOf(r) : r === RUNE_ERROR && size === 1 ? RUNE_ERROR_BYTES : s.slice(i, i + size);
    i += size;
  }
  return out;
}

/** isInvisible: control and invisible characters inserted to split keywords. Tab, LF, CR and ZWJ are kept. */
export function isInvisible(r: number): boolean {
  if (r === 0x09 || r === 0x0a || r === 0x0d) return false;
  if (r < 0x20 || r === 0x7f || (r >= 0x80 && r <= 0x9f)) return true;
  if ((r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)) return true;
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
      return true;
  }
  return false;
}

export function stripInvisible(s: string): string {
  return mapRunes(s, (r) => (isInvisible(r) ? -1 : r));
}

/** decodePercent decodes %XX leniently (anything else is kept, + too); the result is valid UTF-8. */
export function decodePercent(s: string): string {
  if (s.indexOf("%") < 0) return s;
  let out = "";
  let changed = false;
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) === 0x25 && i + 2 < s.length) {
      const v = hexPair(s.charCodeAt(i + 1), s.charCodeAt(i + 2));
      if (v >= 0) {
        out += String.fromCharCode(v);
        i += 2;
        changed = true;
        continue;
      }
    }
    out += s[i];
  }
  if (!changed) return s;
  return toValidUTF8(out, RUNE_ERROR_BYTES);
}

/** decodeJSEscapes decodes \uXXXX (surrogate pairs included), \u{X…} and \xXX. */
export function decodeJSEscapes(s: string): string {
  if (s.indexOf("\\") < 0) return s;
  let out = "";
  let changed = false;
  for (let i = 0; i < s.length; ) {
    if (s.charCodeAt(i) === 0x5c && i + 1 < s.length) {
      let r = 0;
      let n = 0;
      const e = s.charCodeAt(i + 1);
      if (e === 0x75) {
        [r, n] = parseUnicodeEscape(s, i);
      } else if (e === 0x78 && i + 3 < s.length) {
        const v = hexPair(s.charCodeAt(i + 2), s.charCodeAt(i + 3));
        if (v >= 0) {
          r = v;
          n = 4;
        }
      }
      if (n > 0) {
        out += encodeRune(r);
        i += n;
        changed = true;
        continue;
      }
    }
    out += s[i];
    i++;
  }
  return changed ? out : s;
}

// parseUnicodeEscape reads \uXXXX or \u{X…} at s[i]: the rune and the bytes read (0 = not an escape). A lone
// surrogate becomes U+FFFD.
function parseUnicodeEscape(s: string, i: number): [number, number] {
  const len = s.length - i;
  if (len >= 4 && s.charCodeAt(i + 2) === 0x7b) {
    const close = s.indexOf("}", i);
    const end = close < 0 ? -1 : close - i;
    if (end < 4 || end > 9) return [0, 0];
    const v = hexValue(s, i + 3, i + end);
    if (v < 0 || v > 0x10ffff) return [0, 0];
    return [validRune(v) ? v : RUNE_ERROR, end + 1];
  }
  if (len < 6) return [0, 0];
  const v = hexValue(s, i + 2, i + 6);
  if (v < 0) return [0, 0];
  if (v >= 0xd800 && v <= 0xdbff) {
    if (len >= 12 && s.charCodeAt(i + 6) === 0x5c && s.charCodeAt(i + 7) === 0x75) {
      const lo = hexValue(s, i + 8, i + 12);
      if (lo >= 0xdc00 && lo <= 0xdfff) return [((v - 0xd800) << 10) + (lo - 0xdc00) + 0x10000, 12];
    }
    return [RUNE_ERROR, 6];
  }
  return [validRune(v) ? v : RUNE_ERROR, 6];
}

function hexValue(s: string, from: number, to: number): number {
  if (from >= to) return -1;
  let v = 0;
  for (let k = from; k < to; k++) {
    const d = unhex(s.charCodeAt(k));
    if (d < 0) return -1;
    v = v * 16 + d;
  }
  return v;
}

// --- HTML entities: html.UnescapeString ---

let entities: Map<string, number> | null = null;
let entities2: Map<string, [number, number]> | null = null;

function entityMaps(): [Map<string, number>, Map<string, [number, number]>] {
  if (entities === null || entities2 === null) {
    entities = new Map();
    let cp = 0;
    for (const group of ENTITY_DATA.split("|")) {
      const c = group.indexOf(":");
      cp += parseInt(group.slice(0, c), 36);
      for (const name of group.slice(c + 1).split(",")) {
        const last = name[name.length - 1];
        if (last === "!") {
          entities.set(name.slice(0, -1), cp);
          entities.set(name.slice(0, -1) + ";", cp);
        } else if (last === "~") {
          entities.set(name.slice(0, -1), cp);
        } else {
          entities.set(name + ";", cp);
        }
      }
    }
    entities2 = new Map();
    for (const e of ENTITY2_DATA.split("|")) {
      const c = e.lastIndexOf(":");
      const [a, b] = e.slice(c + 1).split(",");
      entities2.set(e.slice(0, c), [parseInt(a, 16), parseInt(b, 16)]);
    }
  }
  return [entities, entities2];
}

/** unescapeHTML is html.UnescapeString. */
export function unescapeHTML(s: string): string {
  let i = s.indexOf("&");
  if (i < 0) return s;
  let out = s.slice(0, i);
  let src = i;
  let [text, next] = unescapeEntity(s, src);
  out += text;
  src = next;
  while (src < s.length) {
    if (s.charCodeAt(src) === 0x26) {
      i = 0;
    } else {
      const j = s.indexOf("&", src);
      i = j < 0 ? -1 : j - src;
    }
    if (i < 0) {
      out += s.slice(src);
      break;
    }
    if (i > 0) out += s.slice(src, src + i);
    [text, next] = unescapeEntity(s, src + i);
    out += text;
    src = next;
  }
  return out;
}

// unescapeEntity reads the reference at s[src] == '&': its replacement and the index after it.
function unescapeEntity(s: string, src: number): [string, number] {
  const n = s.length - src;
  let i = 1;
  if (n <= 1) return ["&", src + 1];
  if (s.charCodeAt(src + 1) === 0x23) {
    if (n <= 3) return ["&", src + 1];
    i++;
    let c = s.charCodeAt(src + i);
    let hex = false;
    if (c === 0x78 || c === 0x58) {
      hex = true;
      i++;
    }
    let x = 0; // a Go rune: int32 arithmetic, wrapping
    while (i < n) {
      c = s.charCodeAt(src + i);
      i++;
      if (hex) {
        const d = unhex(c);
        if (d >= 0) {
          x = (Math.imul(16, x) + d) | 0;
          continue;
        }
      } else if (c >= 0x30 && c <= 0x39) {
        x = (Math.imul(10, x) + (c - 0x30)) | 0;
        continue;
      }
      if (c !== 0x3b) i--;
      break;
    }
    if (i <= 3) return ["&", src + 1];
    if (x >= 0x80 && x <= 0x9f) {
      x = WINDOWS_1252[x - 0x80];
    } else if (x === 0 || (x >= 0xd800 && x <= 0xdfff) || x > 0x10ffff) {
      x = RUNE_ERROR;
    }
    return [encodeRune(x), src + i];
  }
  while (i < n) {
    const c = s.charCodeAt(src + i);
    i++;
    if ((c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39)) continue;
    if (c !== 0x3b) i--;
    break;
  }
  const name = s.slice(src + 1, src + i);
  if (name.length > 0) {
    const [one, two] = entityMaps();
    const x = one.get(name);
    if (x !== undefined) return [encodeRune(x), src + i];
    const x2 = two.get(name);
    if (x2 !== undefined) return [encodeRune(x2[0]) + encodeRune(x2[1]), src + i];
    const maxLen = Math.min(name.length - 1, LONGEST_ENTITY_WITHOUT_SEMICOLON);
    for (let j = maxLen; j > 1; j--) {
      const y = one.get(name.slice(0, j));
      if (y !== undefined) return [encodeRune(y), src + j + 1];
    }
  }
  return [s.slice(src, src + i), src + i];
}
