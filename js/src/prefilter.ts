// The fast path (port of fastpath.go and prefilter.go, value part): one pass over the bytes of a value that answers
// "could an enabled rule match anywhere in here?". The answer must be a superset of what the detectors find; it
// also decides, as in Go, whether a value is decoded at all, so the cleaned output matches the Go engine's.

import { hexPair, isLetter, isWordByte, lowerByte, unhex, validUTF8 } from "./bytes.js";
import { MAX_ROUNDS } from "./norm.js";

export const FB_XSS = 1 << 0; // tags, handlers, script schemes (and every invisible / control character)
export const FB_UNICODE = 1 << 1; // control, bidi, invisible characters
export const FB_CRLF = 1 << 2; // CR/LF raw in a value
export const FB_CRLF_ENC = 1 << 3; // CR/LF once decoded: %0d, &#10;, \x0a…
export const FB_TRAVERSAL = 1 << 4; // "..", encoded dots and separators, sensitive file names

const FAST_TRIGGER: Uint8Array = (() => {
  const t = new Uint8Array(256);
  const set = (bits: number, chars: number[] | string) => {
    for (let i = 0; i < chars.length; i++) {
      const c = typeof chars === "string" ? chars.charCodeAt(i) : chars[i];
      t[c] |= bits;
    }
  };
  set(FB_XSS, "<\\%&oOjJvVlLmMdD");
  // Invisible characters are removed by normalize, so they can split anything a decoding group looks for.
  const decoding = FB_XSS | FB_UNICODE | FB_TRAVERSAL | FB_CRLF_ENC;
  for (let c = 0; c < 0x20; c++) t[c] |= decoding;
  t[0x7f] |= decoding;
  set(decoding, [0xc2, 0xe1, 0xe2, 0xef]);
  set(FB_UNICODE, "\\");
  set(FB_CRLF, [0x0d, 0x0a, 0x5c]);
  set(FB_CRLF_ENC, [0x5c, 0x25, 0x26, 0xef]);
  set(FB_TRAVERSAL, [0x2e, 0x2f, 0x5c, 0x25, 0x26, 0xe2, 0xef]);
  return t;
})();

/** scanFast: b, one decoded value, may hold something the groups in m flag. */
export function scanFast(b: string, m: number): boolean {
  const n = b.length;
  for (let i = 0; i < n; i++) {
    const c = b.charCodeAt(i);
    const t = FAST_TRIGGER[c] & m;
    if (t === 0) continue;
    switch (c) {
      case 0x3c: // <
      case 0x24: // $
        return true;
      case 0x6f:
      case 0x4f: // o O
        if (handlerAt(b, i)) return true;
        break;
      case 0x6a:
      case 0x4a:
        if (wordAt(b, i, "javascript")) return true;
        break;
      case 0x76:
      case 0x56:
        if (wordAt(b, i, "vbscript")) return true;
        break;
      case 0x6c:
      case 0x4c:
        if (wordAt(b, i, "livescript")) return true;
        break;
      case 0x6d:
      case 0x4d:
        if (wordAt(b, i, "mocha") && colonNext(b, i + 5)) return true;
        break;
      case 0x64:
      case 0x44:
        if (wordAt(b, i, "data") && dataTypeNear(b, i + 4)) return true;
        break;
      case 0x5c: // backslash: a JavaScript escape normalize decodes, or a Windows path separator
        if (valueEscapeHit(b, i, t)) return true;
        break;
      case 0x25:
        if (percentHit(b, i, t)) return true;
        break;
      case 0x26:
        if (ampHit(b, i, t)) return true;
        break;
      case 0x2e:
        if (i + 1 < n && b.charCodeAt(i + 1) === 0x2e) return true;
        break;
      case 0x2f:
        if (sepRunStart(b, i) && sensitivePathAt(b, i)) return true;
        break;
      case 0x09:
      case 0x0a:
      case 0x0d:
        if ((t & FB_CRLF) !== 0 && c !== 0x09) return true;
        if ((t & FB_XSS) !== 0 && wsRunInWord(b, i)) return true; // tabs / line breaks inside a word: java\tscript:
        break;
      case 0xef: // EF AC ligatures; EF B9 small forms; EF BC, EF BD fullwidth ASCII; EF BB BF BOM
        if (i + 2 < n) {
          const b1 = b.charCodeAt(i + 1);
          const b2 = b.charCodeAt(i + 2);
          if ((t & (FB_XSS | FB_TRAVERSAL | FB_CRLF_ENC)) !== 0 && (b1 === 0xac || b1 === 0xb9 || b1 === 0xbc || b1 === 0xbd)) {
            return true;
          }
          if (b1 === 0xbb && b2 === 0xbf) return true;
        }
        break;
      case 0xe2:
        if (i + 2 < n) {
          if (isInvisibleE2(b.charCodeAt(i + 1), b.charCodeAt(i + 2))) return true;
          const b1 = b.charCodeAt(i + 1);
          const b2 = b.charCodeAt(i + 2);
          if ((t & FB_TRAVERSAL) !== 0 && b1 === 0x80 && b2 >= 0xa4 && b2 <= 0xa6) return true;
        }
        break;
      case 0xe1: // U+180E
        if (i + 2 < n && b.charCodeAt(i + 1) === 0xa0 && b.charCodeAt(i + 2) === 0x8e) return true;
        break;
      case 0xc2: // C1 controls, soft hyphen
        if (i + 1 < n && (b.charCodeAt(i + 1) <= 0x9f || b.charCodeAt(i + 1) === 0xad)) return true;
        break;
      default: // other C0 controls and DEL
        return true;
    }
  }
  return false;
}

/** fastValue: the fast check for one value with the bits of its context. */
export function fastValue(s: string, bits: number, invalidOn: boolean): boolean {
  if (bits === 0) return false;
  return scanFast(s, bits) || ((bits & FB_UNICODE) !== 0 && invalidOn && !validUTF8(s));
}

function valueEscapeHit(b: string, i: number, t: number): boolean {
  if (i + 1 < b.length && (t & (FB_XSS | FB_CRLF_ENC | FB_TRAVERSAL)) !== 0 && jsEscapeAt(b, i + 1)) return true;
  return (t & FB_TRAVERSAL) !== 0 && sepRunStart(b, i) && sensitivePathAt(b, i);
}

function isURLStripped(c: number): boolean {
  return c === 0x09 || c === 0x0a || c === 0x0d;
}

// wsRunInWord: b[i] starts a run of raw tabs / line breaks with a letter on each side.
function wsRunInWord(b: string, i: number): boolean {
  if (i === 0 || isURLStripped(b.charCodeAt(i - 1)) || !isLetter(b.charCodeAt(i - 1))) return false;
  let j = i;
  while (j < b.length && isURLStripped(b.charCodeAt(j))) j++;
  return j < b.length && isLetter(b.charCodeAt(j));
}

/** sepRunStart: b[i] (a separator) starts a run of separators and "." segments. */
export function sepRunStart(b: string, i: number): boolean {
  if (i === 0) return true;
  const p = b.charCodeAt(i - 1);
  return !isPathSep(p) && !(p === 0x2e && i >= 2 && isPathSep(b.charCodeAt(i - 2)));
}

// jsEscapeAt: b[k] starts what normalize may decode as a JavaScript escape. %, & and \ count as possible digits.
function jsEscapeAt(b: string, k: number): boolean {
  if (k >= b.length) return false;
  let n = 0;
  const c0 = b.charCodeAt(k);
  if (c0 === 0x75) {
    if (k + 1 < b.length && b.charCodeAt(k + 1) === 0x7b) return true;
    n = 4;
  } else if (c0 === 0x78) {
    n = 2;
  } else {
    return false;
  }
  for (let m = 1; m <= n; m++) {
    if (k + m >= b.length) return false;
    const c = b.charCodeAt(k + m);
    if (unhex(c) < 0 && c !== 0x25 && c !== 0x26 && c !== 0x5c) return false;
  }
  return true;
}

function percentHit(b: string, i: number, t: number): boolean {
  if ((t & FB_XSS) !== 0 && suspiciousPercentAt(b, i + 1, 0)) return true;
  if ((t & (FB_CRLF_ENC | FB_TRAVERSAL)) === 0) return false;
  if (i + 1 < b.length && (b.charCodeAt(i + 1) | 0x20) === 0x75) return (t & FB_TRAVERSAL) !== 0;
  return pctPairHit(b, i + 1, t, 0);
}

function pctPairHit(b: string, j: number, t: number, depth: number): boolean {
  if (j + 1 >= b.length) return false;
  const v = hexPair(b.charCodeAt(j), b.charCodeAt(j + 1));
  if (v < 0) return false;
  switch (v) {
    case 0x25:
      return depth < MAX_ROUNDS && pctPairHit(b, j + 2, t, depth + 1);
    case 0x26:
      return ampHit(b, j + 1, t);
    case 0x0d:
    case 0x0a:
      return (t & FB_CRLF_ENC) !== 0;
    case 0xc2:
      return pctByteIn(b, j + 2, 0x80, 0x9f) || pctByteIs(b, j + 2, 0xad);
    case 0xe1:
      return pctByteIs(b, j + 2, 0xa0);
    case 0x5c:
      return true;
    case 0x75:
    case 0x78: // \%75002e: the escape letter itself encoded
      return j >= 2 && b.charCodeAt(j - 2) === 0x5c;
    case 0x2e:
    case 0x2f:
    case 0xc0:
    case 0xc1:
      return (t & FB_TRAVERSAL) !== 0;
    case 0xe0: {
      if ((t & FB_TRAVERSAL) === 0 || j + 4 >= b.length || b.charCodeAt(j + 2) !== 0x25) return false;
      const v2 = hexPair(b.charCodeAt(j + 3), b.charCodeAt(j + 4));
      return v2 >= 0x80 && v2 <= 0x9f;
    }
    case 0xef:
      return pctByteIs(b, j + 2, 0xac) || pctByteIs(b, j + 2, 0xb9) || pctByteIs(b, j + 2, 0xbc) || pctByteIs(b, j + 2, 0xbd);
    case 0xe2: {
      if (j + 7 >= b.length || b.charCodeAt(j + 2) !== 0x25 || b.charCodeAt(j + 5) !== 0x25) return false;
      const v2 = hexPair(b.charCodeAt(j + 3), b.charCodeAt(j + 4));
      const v3 = hexPair(b.charCodeAt(j + 6), b.charCodeAt(j + 7));
      if (v2 < 0 || v3 < 0) return false;
      return isInvisibleE2(v2, v3) || ((t & FB_TRAVERSAL) !== 0 && v2 === 0x80 && v3 >= 0xa4 && v3 <= 0xa6);
    }
  }
  if (v < 0x20 || v === 0x7f) return true;
  // An encoded letter or digit can spell a file name: /%65tc/passwd.
  return (t & FB_TRAVERSAL) !== 0 && v < 0x80 && (isLetter(v) || (v >= 0x30 && v <= 0x39));
}

function pctByteIn(b: string, k: number, lo: number, hi: number): boolean {
  if (k + 2 >= b.length || b.charCodeAt(k) !== 0x25) return false;
  const v = hexPair(b.charCodeAt(k + 1), b.charCodeAt(k + 2));
  return v >= 0 && v >= lo && v <= hi;
}

function pctByteIs(b: string, k: number, c: number): boolean {
  if (k + 2 >= b.length || b.charCodeAt(k) !== 0x25) return false;
  return hexPair(b.charCodeAt(k + 1), b.charCodeAt(k + 2)) === c;
}

function ampHit(b: string, i: number, t: number): boolean {
  if ((t & FB_XSS) !== 0 && entityAt(b, i + 1)) return true;
  if ((t & (FB_CRLF_ENC | FB_TRAVERSAL)) === 0) return false;
  let j = i + 1;
  for (let k = 0; k < 3 && wordAt(b, j, "amp;"); k++) j += 4;
  if ((j < b.length && (b.charCodeAt(j) === 0x23 || b.charCodeAt(j) === 0x25)) || wordAt(b, j, "percnt")) return true;
  if ((t & FB_CRLF_ENC) !== 0 && wordAt(b, j, "newline")) return true;
  return (
    (t & FB_TRAVERSAL) !== 0 &&
    (wordAt(b, j, "period") || wordAt(b, j, "hellip") || wordAt(b, j, "nldr") || wordAt(b, j, "mldr") ||
      wordAt(b, j, "sol") || wordAt(b, j, "bsol"))
  );
}

// Names only ever asked for to read secrets or probe a server. "/" stands for any run of / and \.
const SENSITIVE_FILES = [
  "etc/passwd", "etc/shadow", "etc/hosts", "etc/group", "proc/self/", "proc/version", "win.ini", "boot.ini",
  "windows/system32", "var/run/secrets", ".aws/credentials", ".ssh/", ".git/config",
];

const SENSITIVE_BY_FIRST: string[][] = (() => {
  const t: string[][] = Array.from({ length: 256 }, () => []);
  for (const w of SENSITIVE_FILES) t[w.charCodeAt(0)].push(w);
  return t;
})();

/** sensitivePathAt: at b[i] a run of separators is followed by a sensitive file name. */
export function sensitivePathAt(b: string, i: number): boolean {
  const j = skipSeparators(b, i);
  if (j === i || j >= b.length) return false;
  for (const w of SENSITIVE_BY_FIRST[lowerByte(b.charCodeAt(j))]) {
    if (pathWordAt(b, j, w)) return true;
  }
  return false;
}

function pathWordAt(b: string, j: number, w: string): boolean {
  for (let k = 0; k < w.length; k++) {
    if (w.charCodeAt(k) === 0x2f) {
      if (j >= b.length || !isPathSep(b.charCodeAt(j))) return false;
      j = skipSeparators(b, j);
      continue;
    }
    if (j >= b.length || lowerByte(b.charCodeAt(j)) !== w.charCodeAt(k)) return false;
    j++;
  }
  const last = w.charCodeAt(w.length - 1);
  return last === 0x2f || j >= b.length || !(isWordByte(b.charCodeAt(j)) || b.charCodeAt(j) === 0x2d);
}

function skipSeparators(b: string, j: number): number {
  if (j >= b.length || !isPathSep(b.charCodeAt(j))) return j;
  while (j < b.length) {
    const c = b.charCodeAt(j);
    if (isPathSep(c)) {
      j++;
    } else if (c === 0x2e && j + 1 < b.length && isPathSep(b.charCodeAt(j + 1))) {
      j += 2;
    } else {
      return j;
    }
  }
  return j;
}

export function isPathSep(c: number): boolean {
  return c === 0x2f || c === 0x5c;
}

// --- prefilter.go ---

/** handlerAt: boundary + on + 3 or more letters + optional spaces + = (or %3d) at i. */
function handlerAt(b: string, i: number): boolean {
  const n = b.length;
  if (i + 1 >= n || (b.charCodeAt(i + 1) | 0x20) !== 0x6e || !handlerBoundary(b, i)) return false;
  let j = i + 2;
  while (j < n && isLetter(b.charCodeAt(j))) j++;
  if (j - (i + 2) < 3) return false;
  while (j < n) {
    const c = b.charCodeAt(j);
    if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d || c === 0x0c) {
      j++;
      continue;
    }
    if (c === 0x25) {
      const [v, end] = pctDecode(b, j);
      if (v === 0x20 || v === 0x09 || v === 0x0a || v === 0x0d || v === 0x0c) {
        j = end;
        continue;
      }
    }
    break;
  }
  if (j < n && b.charCodeAt(j) === 0x25) return pctDecode(b, j)[0] === 0x3d;
  return j < n && b.charCodeAt(j) === 0x3d;
}

// pctDecode reads a percent-encoded byte at b[j] == '%', nested encodings included: [byte or -1, index after].
function pctDecode(b: string, j: number): [number, number] {
  let k = j + 1;
  for (let n = 0; n < MAX_ROUNDS && k + 1 < b.length && b.charCodeAt(k) === 0x32 && b.charCodeAt(k + 1) === 0x35; n++) k += 2;
  if (k + 1 >= b.length) return [-1, 0];
  return [hexPair(b.charCodeAt(k), b.charCodeAt(k + 1)), k + 2];
}

// pctDecodedBefore: b[:i] ends with a percent-encoded byte, nested encodings included. -1 when not.
function pctDecodedBefore(b: string, i: number): number {
  if (i < 3) return -1;
  const v = hexPair(b.charCodeAt(i - 2), b.charCodeAt(i - 1));
  if (v < 0) return -1;
  let k = i - 3;
  for (let n = 0; n <= MAX_ROUNDS && k >= 0; n++) {
    if (b.charCodeAt(k) === 0x25) return v;
    if (k < 1 || b.charCodeAt(k - 1) !== 0x32 || b.charCodeAt(k) !== 0x35) return -1;
    k -= 2;
  }
  return -1;
}

function handlerBoundary(b: string, i: number): boolean {
  if (i === 0) return true;
  switch (b.charCodeAt(i - 1)) {
    case 0x20:
    case 0x09:
    case 0x0a:
    case 0x0d:
    case 0x0c:
    case 0x2f:
    case 0x3b:
    case 0x22:
    case 0x27:
    case 0x60:
      return true;
  }
  const v = pctDecodedBefore(b, i);
  if (v === 0x20 || v === 0x2f || v === 0x3b || v === 0x22 || v === 0x27 || v === 0x60) return true;
  const p = b.charCodeAt(i - 1);
  return i >= 2 && b.charCodeAt(i - 2) === 0x5c && (p === 0x74 || p === 0x6e || p === 0x72);
}

/** entityAt: an HTML entity that yields an anchor character of the XSS rules. */
export function entityAt(b: string, j: number): boolean {
  return entityAtDepth(b, j, 0);
}

function entityAtDepth(b: string, j: number, depth: number): boolean {
  if (j >= b.length) return false;
  if (b.charCodeAt(j) === 0x23 || percentIs(b, j, 0x23)) return true;
  if (wordAt(b, j, "lt") || wordAt(b, j, "tab") || wordAt(b, j, "newline") || wordAt(b, j, "equals")) return true;
  if (depth >= MAX_ROUNDS || !wordAt(b, j, "amp")) return false;
  let k = j + 3;
  if (k < b.length && b.charCodeAt(k) === 0x3b) k++;
  else if (percentIs(b, k, 0x3b)) k += 3;
  return entityAtDepth(b, k, depth + 1);
}

function suspiciousPercentAt(b: string, j: number, depth: number): boolean {
  if (j + 1 >= b.length) return false;
  const v = hexPair(b.charCodeAt(j), b.charCodeAt(j + 1));
  if (v < 0) return false;
  if (v === 0x25) return depth < MAX_ROUNDS && suspiciousPercentAt(b, j + 2, depth + 1);
  if (v === 0x26) return entityAt(b, j + 2);
  return v === 0x3c || v === 0x5c || v < 0x20 || v === 0x7f || v === 0xef || isLetter(v);
}

function percentIs(b: string, k: number, c: number): boolean {
  if (k + 2 >= b.length || b.charCodeAt(k) !== 0x25) return false;
  return hexPair(b.charCodeAt(k + 1), b.charCodeAt(k + 2)) === c;
}

function colonNext(b: string, j: number): boolean {
  while (j < b.length && isURLStripped(b.charCodeAt(j))) j++;
  if (j >= b.length) return false;
  const c = b.charCodeAt(j);
  return c === 0x3a || c === 0x25 || c === 0x26 || c === 0x5c;
}

function dataTypeNear(b: string, j: number): boolean {
  for (let k = j; k < b.length; k++) {
    if (wordAt(b, k, "text/") || wordAt(b, k, "application/") || wordAt(b, k, "image/svg")) return true;
    switch (b.charCodeAt(k)) {
      case 0x3a:
      case 0x20:
      case 0x09:
      case 0x0a:
      case 0x0d:
      case 0x0c:
        continue;
      case 0x25:
      case 0x26:
      case 0x5c:
        return true;
    }
    if (k > j + 8) return false;
  }
  return false;
}

/** wordAt matches word (lowercase letters, digits, / . ; #) at b[i], ASCII case-insensitively. */
export function wordAt(b: string, i: number, word: string): boolean {
  if (i + word.length > b.length) return false;
  for (let k = 0; k < word.length; k++) {
    if ((b.charCodeAt(i + k) | 0x20) !== word.charCodeAt(k)) return false;
  }
  return true;
}

export function isInvisibleE2(b1: number, b2: number): boolean {
  if (b1 === 0x80) return b2 === 0x8b || b2 === 0x8c || b2 === 0x8e || b2 === 0x8f || (b2 >= 0xaa && b2 <= 0xae);
  if (b1 === 0x81) return (b2 >= 0xa0 && b2 <= 0xa4) || (b2 >= 0xa6 && b2 <= 0xa9);
  return false;
}

/** mayBeEncoded: the value may decode to other ASCII characters. */
export function mayBeEncoded(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x25 || c === 0x26 || c === 0x5c || c === 0xef) return true;
    if ((c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || c === 0x7f) return true;
    if (c === 0xc2 && i + 1 < s.length && (s.charCodeAt(i + 1) <= 0x9f || s.charCodeAt(i + 1) === 0xad)) return true;
    if (
      (c === 0xe1 || c === 0xe2) &&
      i + 2 < s.length &&
      ((c === 0xe1 && s.charCodeAt(i + 1) === 0xa0 && s.charCodeAt(i + 2) === 0x8e) ||
        (c === 0xe2 && isInvisibleE2(s.charCodeAt(i + 1), s.charCodeAt(i + 2))))
    ) {
      return true;
    }
  }
  return false;
}

/** containsFoldASCII: s contains word (lowercase), ASCII case-insensitively. */
export function containsFoldASCII(s: string, word: string): boolean {
  if (word.length === 0) return true;
  const c0 = word.charCodeAt(0);
  for (let i = 0; i + word.length <= s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c | 0x20) !== (c0 | 0x20) && c !== c0) continue;
    let k = 0;
    while (k < word.length && lowerByte(s.charCodeAt(i + k)) === word.charCodeAt(k)) k++;
    if (k === word.length) return true;
  }
  return false;
}

export function containsAnyFold(s: string, words: readonly string[]): boolean {
  for (const w of words) if (containsFoldASCII(s, w)) return true;
  return false;
}
