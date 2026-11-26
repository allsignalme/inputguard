// Byte strings. The engine works on the UTF-8 bytes of a value, like the Go original: every internal string holds
// one code unit per byte (0–255). Offsets, lengths, limits and the handling of invalid sequences are then the same
// as in Go, byte for byte. The public API converts JavaScript strings at the boundary (toBytes / fromBytes).

export const RUNE_ERROR = 0xfffd;
export const RUNE_SELF = 0x80;
export const MAX_RUNE = 0x10ffff;

/** UTF-8 of U+FFFD as a byte string. */
export const RUNE_ERROR_BYTES = "\xef\xbf\xbd";

/** A lone surrogate in a JavaScript string becomes this byte: never valid UTF-8, so it is an invalid_utf8 finding. */
const LONE_SURROGATE_BYTE = 0xff;

const CHUNK = 0x2000;

function fromCodes(codes: number[]): string {
  if (codes.length <= CHUNK) return String.fromCharCode.apply(null, codes);
  let out = "";
  for (let i = 0; i < codes.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, codes.slice(i, i + CHUNK));
  }
  return out;
}

function isASCII(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) >= 0x80) return false;
  }
  return true;
}

/** toBytes encodes a JavaScript string as a byte string (UTF-8). */
export function toBytes(s: string): string {
  if (isASCII(s)) return s;
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) {
      out.push(c);
      continue;
    }
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const lo = s.charCodeAt(i + 1);
      if (lo >= 0xdc00 && lo <= 0xdfff) {
        c = (c - 0xd800) * 0x400 + (lo - 0xdc00) + 0x10000;
        i++;
      }
    }
    if (c >= 0xd800 && c <= 0xdfff) {
      out.push(LONE_SURROGATE_BYTE);
      continue;
    }
    pushRune(out, c);
  }
  return fromCodes(out);
}

/** fromBytes decodes a byte string; each invalid byte becomes U+FFFD. */
export function fromBytes(b: string): string {
  if (isASCII(b)) return b;
  let out = "";
  let start = 0;
  const parts: string[] = [];
  for (let i = 0; i < b.length; ) {
    const c = b.charCodeAt(i);
    if (c < 0x80) {
      i++;
      continue;
    }
    if (i > start) parts.push(b.slice(start, i));
    const [r, size] = decodeRune(b, i);
    parts.push(String.fromCodePoint(r));
    i += size;
    start = i;
  }
  if (start < b.length) parts.push(b.slice(start));
  out = parts.join("");
  return out;
}

function pushRune(out: number[], r: number): void {
  if (r < 0x80) {
    out.push(r);
  } else if (r < 0x800) {
    out.push(0xc0 | (r >> 6), 0x80 | (r & 0x3f));
  } else if (r < 0x10000) {
    out.push(0xe0 | (r >> 12), 0x80 | ((r >> 6) & 0x3f), 0x80 | (r & 0x3f));
  } else {
    out.push(0xf0 | (r >> 18), 0x80 | ((r >> 12) & 0x3f), 0x80 | ((r >> 6) & 0x3f), 0x80 | (r & 0x3f));
  }
}

/** validRune is utf8.ValidRune. */
export function validRune(r: number): boolean {
  return (r >= 0 && r < 0xd800) || (r > 0xdfff && r <= MAX_RUNE);
}

/** encodeRune is utf8.AppendRune as a byte string: an invalid rune encodes U+FFFD. */
export function encodeRune(r: number): string {
  if (r >= 0 && r < 0x80) return String.fromCharCode(r);
  if (!validRune(r)) return RUNE_ERROR_BYTES;
  const out: number[] = [];
  pushRune(out, r);
  return String.fromCharCode.apply(null, out);
}

/**
 * decodeRune is utf8.DecodeRuneInString(s[i:]): the rune and its size; (RUNE_ERROR, 1) for an invalid byte,
 * (RUNE_ERROR, 0) at the end.
 */
export function decodeRune(s: string, i: number): [number, number] {
  const n = s.length;
  if (i >= n) return [RUNE_ERROR, 0];
  const c0 = s.charCodeAt(i);
  if (c0 < 0x80) return [c0, 1];
  let size: number;
  let lo = 0x80;
  let hi = 0xbf;
  if (c0 >= 0xc2 && c0 <= 0xdf) {
    size = 2;
  } else if (c0 >= 0xe0 && c0 <= 0xef) {
    size = 3;
    if (c0 === 0xe0) lo = 0xa0;
    else if (c0 === 0xed) hi = 0x9f;
  } else if (c0 >= 0xf0 && c0 <= 0xf4) {
    size = 4;
    if (c0 === 0xf0) lo = 0x90;
    else if (c0 === 0xf4) hi = 0x8f;
  } else {
    return [RUNE_ERROR, 1];
  }
  if (i + size > n) return [RUNE_ERROR, 1];
  const c1 = s.charCodeAt(i + 1);
  if (c1 < lo || c1 > hi) return [RUNE_ERROR, 1];
  if (size === 2) return [((c0 & 0x1f) << 6) | (c1 & 0x3f), 2];
  const c2 = s.charCodeAt(i + 2);
  if (c2 < 0x80 || c2 > 0xbf) return [RUNE_ERROR, 1];
  if (size === 3) return [((c0 & 0x0f) << 12) | ((c1 & 0x3f) << 6) | (c2 & 0x3f), 3];
  const c3 = s.charCodeAt(i + 3);
  if (c3 < 0x80 || c3 > 0xbf) return [RUNE_ERROR, 1];
  return [((c0 & 0x07) << 18) | ((c1 & 0x3f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f), 4];
}

/** decodeLastRune is utf8.DecodeLastRuneInString(s[:end]). */
export function decodeLastRune(s: string, end: number): [number, number] {
  if (end === 0) return [RUNE_ERROR, 0];
  let start = end - 1;
  const c = s.charCodeAt(start);
  if (c < 0x80) return [c, 1];
  const lim = Math.max(end - 4, 0);
  for (start--; start >= lim; start--) {
    if ((s.charCodeAt(start) & 0xc0) !== 0x80) break;
  }
  if (start < 0) start = 0;
  const [r, size] = decodeRune(s.slice(start, end), 0);
  if (start + size !== end) return [RUNE_ERROR, 1];
  return [r, size];
}

/** validUTF8 is utf8.ValidString. */
export function validUTF8(s: string): boolean {
  for (let i = 0; i < s.length; ) {
    if (s.charCodeAt(i) < 0x80) {
      i++;
      continue;
    }
    const [r, size] = decodeRune(s, i);
    if (r === RUNE_ERROR && size === 1) return false;
    i += size;
  }
  return true;
}

/** mapRunes is strings.Map: f returns the replacement rune or -1 to drop it; invalid bytes are read as U+FFFD. */
export function mapRunes(s: string, f: (r: number) => number): string {
  let out: string | null = null;
  for (let i = 0; i < s.length; ) {
    const [r, size] = decodeRune(s, i);
    const m = f(r);
    const same = m === r && !(r === RUNE_ERROR && size === 1);
    if (out === null) {
      if (same) {
        i += size;
        continue;
      }
      out = s.slice(0, i);
    }
    if (m >= 0) out += same ? s.slice(i, i + size) : encodeRune(m);
    i += size;
  }
  return out === null ? s : out;
}

/** toValidUTF8 is strings.ToValidUTF8: each run of invalid bytes becomes one replacement. */
export function toValidUTF8(s: string, replacement: string): string {
  if (validUTF8(s)) return s;
  let out = "";
  let invalid = false;
  for (let i = 0; i < s.length; ) {
    const c = s.charCodeAt(i);
    if (c < 0x80) {
      out += s[i];
      i++;
      invalid = false;
      continue;
    }
    const [r, size] = decodeRune(s, i);
    if (r === RUNE_ERROR && size === 1) {
      i++;
      if (!invalid) {
        invalid = true;
        out += replacement;
      }
      continue;
    }
    invalid = false;
    out += s.slice(i, i + size);
    i += size;
  }
  return out;
}

/** trimLeftRunes is strings.TrimLeftFunc. */
export function trimLeftRunes(s: string, f: (r: number) => boolean): string {
  let i = 0;
  while (i < s.length) {
    const [r, size] = decodeRune(s, i);
    if (!f(r)) break;
    i += size;
  }
  return s.slice(i);
}

/** trimRightRunes is strings.TrimRightFunc. */
export function trimRightRunes(s: string, f: (r: number) => boolean): string {
  let end = s.length;
  while (end > 0) {
    const [r, size] = decodeLastRune(s, end);
    if (!f(r)) break;
    end -= size;
  }
  return s.slice(0, end);
}

/** indexAny is strings.IndexAny for an ASCII set. */
export function indexAny(s: string, chars: string): number {
  for (let i = 0; i < s.length; i++) {
    if (chars.indexOf(s[i]) >= 0) return i;
  }
  return -1;
}

export function containsAny(s: string, chars: string): boolean {
  return indexAny(s, chars) >= 0;
}

export function isLetter(c: number): boolean {
  return (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a);
}

export function isLowerASCII(c: number): boolean {
  return c >= 0x61 && c <= 0x7a;
}

export function isDigit(c: number): boolean {
  return c >= 0x30 && c <= 0x39;
}

export function isWordByte(c: number): boolean {
  return c === 0x5f || isLetter(c) || isDigit(c);
}

export function lowerByte(c: number): number {
  return c >= 0x41 && c <= 0x5a ? c + 0x20 : c;
}

/** unhex: the value of a hex digit, or -1. */
export function unhex(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  return -1;
}

/** hexPair: the byte two hex digits spell, or -1. */
export function hexPair(hi: number, lo: number): number {
  const h = unhex(hi);
  const l = unhex(lo);
  return h < 0 || l < 0 ? -1 : (h << 4) | l;
}

/** asciiLower lowers A–Z only; the length is unchanged. */
export function asciiLower(s: string): string {
  let i = 0;
  while (i < s.length) {
    const c = s.charCodeAt(i);
    if (c >= 0x41 && c <= 0x5a) break;
    i++;
  }
  if (i === s.length) return s;
  let out = s.slice(0, i);
  for (; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out += c >= 0x41 && c <= 0x5a ? String.fromCharCode(c + 0x20) : s[i];
  }
  return out;
}

/** hasPrefixFold: s starts with prefix, ASCII case-insensitively (prefix is ASCII). */
export function hasPrefixFold(s: string, prefix: string): boolean {
  if (s.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (lowerByte(s.charCodeAt(i)) !== lowerByte(prefix.charCodeAt(i))) return false;
  }
  return true;
}

export function hasNonASCII(s: string): boolean {
  return !isASCII(s);
}

/** isRESpace: exactly RE2's \s class: [\t\n\f\r ]. */
export function isRESpace(c: number): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d;
}
