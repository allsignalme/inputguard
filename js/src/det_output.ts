// Rules about where a value ends up: a spreadsheet (formula injection), a server-side fetch (SSRF), a browser
// redirect (open redirect); and look-alike identifiers mixing scripts. Port of det_output.go.

import {
  asciiLower,
  containsAny,
  decodeRune,
  fromBytes,
  hasNonASCII,
  indexAny,
  mapRunes,
  RUNE_SELF,
  toBytes,
  trimLeftRunes,
} from "./bytes.js";
import type { DetectorDef, DetectorEnv, Emit, Input } from "./detector.js";
import { ALL_INSPECTED, CLEAN_CUT, CLEAN_EMPTY, CLEAN_PREFIX } from "./detector.js";

import { internalAddr, parseHostIP } from "./ip.js";
import { normalize } from "./norm.js";
import { isPathSep, mayBeEncoded } from "./prefilter.js";
import { CTX_REDIRECT, maskHas, maskOf, URL_CONTEXTS } from "./rule.js";
import { splitScheme } from "./url.js";
import {
  isArmenian,
  isCf,
  isCherokee,
  isCyrillic,
  isGreek,
  isLatin,
  isLetterRune,
  isMn,
  isOtherDefaultIgnorable,
  isVariationSelector,
} from "./unitables.js";

// --- Formula (CSV) injection ---

function mayBeFormula(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    switch (s.charCodeAt(i)) {
      case 0x09:
      case 0x0d:
      case 0x0a:
        continue;
      case 0x3d:
      case 0x2b:
      case 0x2d:
      case 0x40:
        return true;
    }
    return false;
  }
  return false;
}

// formulaCallRe is Go's case-insensitive
//   (?i)\b(?:hyperlink|webservice|…|dde)\(|[a-z0-9_.]+\|\s*'|\bcmd\s*\|
// on ASCII-lowercased bytes. Go's (?i) also matches the Kelvin sign (U+212A) for k and the long s (U+017F) for s,
// spelled out here as their UTF-8 bytes.
const K = "(?:k|\\xe2\\x84\\xaa)";
const S = "(?:s|\\xc5\\xbf)";
const formulaCallRe = new RegExp(
  "\\b(?:hyperlin" + K + "|web" + S + "ervice|importxml|importdata|importhtml|importfeed|importrange|image|filterxml|" +
    "call|regi" + S + "ter(?:\\.id)?|exec|rtd|dde)\\(|(?:[a-z0-9_.]|\\xc5\\xbf|\\xe2\\x84\\xaa)+\\|[\\t\\n\\f\\r ]*'|" +
    "\\bcmd[\\t\\n\\f\\r ]*\\|",
);

// detectFormula flags a value a spreadsheet would run to reach outside: it starts with = + - or @ (possibly after
// tabs or line breaks) and calls a function that fetches, links or runs something, or a DDE server (cmd|'…').
function detectFormula(env: DetectorEnv, input: Input, emit: Emit): void {
  if (!maskHas(env.formulaOn, input.ctx)) return;
  const s = input.raw;
  let i = 0;
  while (i < s.length && (s.charCodeAt(i) === 0x09 || s.charCodeAt(i) === 0x0d || s.charCodeAt(i) === 0x0a)) i++;
  if (i < s.length && "=+-@".indexOf(s[i]) >= 0 && formulaCallRe.test(asciiLower(s.slice(i + 1)))) emit("formula_injection", 0);
}

// --- SSRF ---

const SSRF_SCHEMES = new Set(["file", "gopher", "dict", "ldap", "ldaps", "tftp", "jar", "netdoc", "smb", "phar", "expect", "glob"]);
const SPECIAL_SCHEMES = new Set(["http", "https", "ws", "wss", "ftp"]);

interface LooseURL {
  scheme: string;
  hasAuthority: boolean;
  host: string;
}

// The URL rules read the value as received and fully decoded; either reading can flag it.
function urlReadings(input: Input): [string, string] {
  return [input.raw, input.decoded()];
}

function detectSSRF(env: DetectorEnv, input: Input, emit: Emit): void {
  for (const s of urlReadings(input)) {
    if (ssrfTarget(env, parseURLLoose(s))) {
      emit("ssrf", 0);
      return;
    }
  }
}

function ssrfTarget(env: DetectorEnv, u: LooseURL): boolean {
  if (SSRF_SCHEMES.has(u.scheme)) return true;
  if (!u.hasAuthority || u.host === "" || env.allowsSSRFHost(u.host)) return false;
  if (internalHostName(u.host)) return true;
  const a = parseHostIP(u.host);
  return a !== null && internalAddr(a) && !env.allowsSSRFAddr(a);
}

const INTERNAL_NAMES = new Set([
  "localhost", "metadata", "metadata.google.internal", "instance-data", "kubernetes", "kubernetes.default",
  "localtest.me", "lvh.me", "vcap.me", "lacolhost.com", "0",
]);
const INTERNAL_SUFFIXES = [
  ".localhost", ".internal", ".local", ".localdomain", ".home.arpa", ".intranet", ".corp", ".lan",
  ".svc.cluster.local", ".cluster.local", ".nip.io", ".sslip.io", ".xip.io", ".localtest.me", ".lvh.me",
  ".vcap.me", ".lacolhost.com",
];

function internalHostName(h: string): boolean {
  if (INTERNAL_NAMES.has(h)) return true;
  for (const s of INTERNAL_SUFFIXES) if (h.endsWith(s)) return true;
  return false;
}

// --- Open redirect ---

const REDIRECT_SCHEMES = new Set([
  "javascript", "vbscript", "livescript", "data", "file", "blob", "filesystem", "intent", "about", "view-source", "jar",
]);

function detectRedirect(env: DetectorEnv, input: Input, emit: Emit): void {
  for (const s of urlReadings(input)) {
    if (foreignRedirect(env, parseURLLoose(s))) {
      emit("open_redirect", 0);
      return;
    }
  }
}

function foreignRedirect(env: DetectorEnv, u: LooseURL): boolean {
  if (u.scheme !== "" && u.scheme !== "http" && u.scheme !== "https") {
    // Another protocol or app, or a scheme that runs or embeds content. "Hotline: 1900 1234" takes the browser nowhere.
    return u.hasAuthority || REDIRECT_SCHEMES.has(u.scheme);
  }
  return u.hasAuthority && (u.host === "" || !env.allowsRedirectHost(u.host));
}

// --- URL parsing shared by the SSRF and redirect checks ---

// Ideographic full stop (U+3002), halfwidth ideographic full stop (U+FF61), fullwidth full stop (U+FF0E).
const UNICODE_DOTS = ["\xe3\x80\x82", "\xef\xbd\xa1", "\xef\xbc\x8e"];

function replaceDots(s: string): string {
  if (!hasNonASCII(s)) return s;
  let out = "";
  for (let i = 0; i < s.length; ) {
    const d = UNICODE_DOTS.find((u) => s.startsWith(u, i));
    if (d !== undefined) {
      out += ".";
      i += d.length;
    } else {
      out += s[i];
      i++;
    }
  }
  return out;
}

/** toLowerUnicode is strings.ToLower: simple lowercase mapping per rune. */
function toLowerUnicode(s: string): string {
  if (!hasNonASCII(s)) return asciiLower(s);
  return mapRunes(s, (r) => {
    if (r === 0x130) return 0x69; // İ: Go's simple mapping (JavaScript gives i + combining dot)
    const l = String.fromCodePoint(r).toLowerCase();
    const cp = l.codePointAt(0) as number;
    return l.length === String.fromCodePoint(cp).length ? cp : r;
  });
}

function dropIgnorable(r: number): number {
  return isVariationSelector(r) || isOtherDefaultIgnorable(r) || isCf(r) ? -1 : r;
}

/**
 * parseURLLoose reads a URL the way a browser does: leading spaces and controls dropped, tabs and line breaks
 * removed, backslashes count as slashes after a special scheme, userinfo skipped, Unicode dots are dots.
 */
function parseURLLoose(s: string): LooseURL {
  s = trimLeftRunes(s, (r) => r <= 0x20);
  if (containsAny(s, "\t\n\r")) s = mapRunes(s, (r) => (r === 0x09 || r === 0x0a || r === 0x0d ? -1 : r));
  const u: LooseURL = { scheme: "", hasAuthority: false, host: "" };
  let rest: string;
  const sc = splitScheme(s);
  if (sc !== null) {
    u.scheme = asciiLower(sc[0]);
    const after = sc[1];
    if (SPECIAL_SCHEMES.has(u.scheme)) {
      rest = trimLeftSeps(after);
      u.hasAuthority = true;
    } else if (after.startsWith("//")) {
      rest = after.slice(2);
      u.hasAuthority = true;
    } else {
      return u;
    }
  } else if (s.length >= 2 && isPathSep(s.charCodeAt(0)) && isPathSep(s.charCodeAt(1))) {
    rest = trimLeftSeps(s);
    u.hasAuthority = true;
  } else {
    return u;
  }
  let auth = rest;
  const end = indexAny(rest, "/\\?#");
  if (end >= 0) auth = rest.slice(0, end);
  const at = auth.lastIndexOf("@");
  if (at >= 0) auth = auth.slice(at + 1);
  if (containsAny(auth, "%&\\") || hasNonASCII(auth)) auth = normalize(auth).decoded;
  if (hasNonASCII(auth)) {
    // HTTP clients map the host with IDNA (close to NFKC with case folding): ①②⑦.0.0.1 reaches the loopback.
    auth = toBytes(fromBytes(mapRunes(auth, dropIgnorable)).normalize("NFKC"));
  }
  auth = replaceDots(auth);
  let host = auth;
  if (host.startsWith("[")) {
    const i = host.indexOf("]");
    if (i >= 0) host = host.slice(0, i + 1);
  } else {
    const i = host.lastIndexOf(":");
    if (i >= 0) host = host.slice(0, i);
  }
  host = toLowerUnicode(host);
  let e = host.length;
  while (e > 0 && host.charCodeAt(e - 1) === 0x2e) e--;
  u.host = host.slice(0, e);
  return u;
}

function trimLeftSeps(s: string): string {
  let i = 0;
  while (i < s.length && isPathSep(s.charCodeAt(i))) i++;
  return s.slice(i);
}

// --- Mixed scripts ---

const SCRIPT_LATIN = 1;
const SCRIPT_CYRILLIC = 2;
const SCRIPT_GREEK = 4;
const SCRIPT_ARMENIAN = 8;
const SCRIPT_CHEROKEE = 16;

function scriptOf(r: number): number {
  if (r < RUNE_SELF) return (r >= 0x61 && r <= 0x7a) || (r >= 0x41 && r <= 0x5a) ? SCRIPT_LATIN : 0;
  if (isLatin(r)) return SCRIPT_LATIN;
  if (isCyrillic(r)) return SCRIPT_CYRILLIC;
  if (isGreek(r)) return SCRIPT_GREEK;
  if (isArmenian(r)) return SCRIPT_ARMENIAN;
  if (isCherokee(r)) return SCRIPT_CHEROKEE;
  return 0;
}

function mayHaveConfusableScript(s: string): boolean {
  if (mayBeEncoded(s)) return true;
  for (let i = 0; i < s.length; ) {
    if (s.charCodeAt(i) < RUNE_SELF) {
      i++;
      continue;
    }
    const [r, size] = decodeRune(s, i);
    i += size;
    if (r < 0x250 || (r >= 0x1e00 && r <= 0x1eff)) continue;
    const sc = scriptOf(r);
    if (sc !== 0 && sc !== SCRIPT_LATIN) return true;
  }
  return false;
}

function detectMixedScripts(_env: DetectorEnv, input: Input, emit: Emit): void {
  const s = input.decoded();
  let start = -1;
  let i = 0;
  while (i < s.length) {
    const [r, size] = decodeRune(s, i);
    if (isLetterRune(r) || isMn(r)) {
      if (start < 0) start = i;
      i += size;
      continue;
    }
    if (start >= 0 && confusableWord(s.slice(start, i))) {
      emit("mixed_scripts", start);
      return;
    }
    start = -1;
    i += size;
  }
  if (start >= 0 && confusableWord(s.slice(start))) emit("mixed_scripts", start);
}

function bitIndex(sc: number): number {
  let n = 0;
  while (sc > 1) {
    sc >>= 1;
    n++;
  }
  return n;
}

function confusableWord(w: string): boolean {
  const counts = [0, 0, 0, 0, 0, 0];
  let mask = 0;
  const runes: number[] = [];
  for (let i = 0; i < w.length; ) {
    const [r, size] = decodeRune(w, i);
    runes.push(r);
    i += size;
    const sc = scriptOf(r);
    if (sc !== 0) {
      mask |= sc;
      counts[bitIndex(sc)]++;
    }
  }
  if ((mask & (mask - 1)) === 0) return false;
  let major = 0; // Latin wins ties
  for (let k = 1; k < counts.length; k++) if (counts[k] > counts[major]) major = k;
  for (const r of runes) {
    const sc = scriptOf(r);
    if (sc === 0 || bitIndex(sc) === major) continue;
    if ((sc === SCRIPT_LATIN && LATIN_LOOKALIKE.has(r)) || (sc !== SCRIPT_LATIN && HOMOGLYPHS.has(r))) return true;
  }
  return false;
}

// Cyrillic, Greek, Armenian and Cherokee letters that look like Latin ones.
const HOMOGLYPHS = new Set([
  // Cyrillic
  0x430, 0x435, 0x43e, 0x440, 0x441, 0x443, 0x445, 0x456, 0x458, 0x455, 0x501, 0x51b, 0x51d, 0x475, 0x4bb,
  0x4cf, 0x410, 0x412, 0x415, 0x41a, 0x41c, 0x41d, 0x41e, 0x420, 0x421, 0x422, 0x425, 0x423, 0x406, 0x408,
  0x405, 0x51a, 0x51c,
  // Greek
  0x3bf, 0x3b1, 0x3bd, 0x3c1, 0x3b9, 0x3ba, 0x3c5, 0x3c7, 0x3b3, 0x3f2, 0x3f3, 0x391, 0x392, 0x395, 0x396,
  0x397, 0x399, 0x39a, 0x39c, 0x39d, 0x39f, 0x3a1, 0x3a4, 0x3a5, 0x3a7, 0x3f9,
  // Armenian
  0x585, 0x57d, 0x581, 0x570, 0x578, 0x54f, 0x555,
  // Cherokee
  0x13aa, 0x13f4, 0x13df, 0x13ac, 0x13bb, 0x13e6, 0x13b7, 0x13e2, 0x13da, 0x13a2, 0x13b3, 0x13c3, 0x13ab,
  0x13de, 0x13a0, 0x13d9, 0x13a9, 0x13c0, 0x13d2,
]);

// Latin letters that look like Cyrillic or Greek ones.
const LATIN_LOOKALIKE = new Set(Array.from("acehijkopsxyABCEHIJKMNOPSTXYZ", (c) => c.charCodeAt(0)));

export const formulaDetector: DetectorDef = {
  name: "formula",
  rules: ["formula_injection"],
  contexts: ALL_INSPECTED, // narrowed by formulaContexts at detection time
  fast: 0,
  mayMatch: mayBeFormula,
  detect: detectFormula,
  clean: CLEAN_PREFIX,
};

export const ssrfDetector: DetectorDef = {
  name: "ssrf",
  rules: ["ssrf"],
  contexts: URL_CONTEXTS,
  fast: 0,
  detect: detectSSRF,
  clean: CLEAN_EMPTY,
};

export const redirectDetector: DetectorDef = {
  name: "redirect",
  rules: ["open_redirect"],
  contexts: maskOf(CTX_REDIRECT),
  fast: 0,
  detect: detectRedirect,
  clean: CLEAN_EMPTY,
};

export const mixedScriptsDetector: DetectorDef = {
  name: "mixed_scripts",
  rules: ["mixed_scripts"],
  contexts: ALL_INSPECTED,
  fast: 0,
  mayMatch: mayHaveConfusableScript,
  detect: detectMixedScripts,
  clean: CLEAN_CUT,
};
