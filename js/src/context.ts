// The default classifier: the context of a value from its key and its shape.

import { asciiLower, hasPrefixFold, toBytes } from "./bytes.js";
import { normalize } from "./norm.js";
import { mayBeEncoded } from "./prefilter.js";
import type { Context } from "./rule.js";
import { CTX_TEXT, CTX_URL, ctxNumber } from "./rule.js";

/** Picks the context of a value from its key (the nearest object key; array elements inherit it) and the value. */
export type Classifier = (key: string, value: string) => Context;

/** Internal classifier, on byte strings, returning a context number. */
export type ByteClassifier = (key: string, value: string) => number;

/** The data-driven part of the default classifier. Keys are compared case-insensitively. */
export interface KeyTable {
  /** Maps a key to its context. */
  exact: Record<string, Context>;
  /** Maps a key suffix ("_id", "_url") to its context. */
  suffix: Record<string, Context>;
  /** Maps a substring ("password") to its context. Checked before exact. */
  contains: Record<string, Context>;
}

/** defaultKeyTable returns a fresh copy of the default key classification. */
export function defaultKeyTable(): KeyTable {
  const t: KeyTable = {
    exact: {},
    suffix: {},
    contains: { password: "secret", passwd: "secret", secret: "secret" },
  };
  for (const k of [
    // Hashed customer data and match keys (Meta / OpenAI Conversions APIs): one changed byte breaks the match.
    "em", "ph", "fn", "ln", "ct", "st", "zp", "ge", "db",
    "email", "phone", "first_name", "last_name", "city", "state", "zip",
    "fbp", "fbc", "obj_fbp_fbc", "external_id", "ext_id", "event_id", "id",
    "oppref", "obref", "fbclid", "gclid", "ttclid", "msclkid", "client_id", "shopify_client_id",
    "bv", "fp", "content_id", "content_ids", "sku", "gtin", "uuid", "hash", "checksum", "nonce", "etag",
  ]) {
    t.exact[k] = "identifier";
  }
  for (const k of [
    "token", "access_token", "refresh_token", "id_token", "api_key", "apikey", "authorization",
    "private_key", "dsn", "client_secret", "session", "cookie_secret",
  ]) {
    t.exact[k] = "secret";
  }
  for (const k of ["filename", "file_name", "filepath", "file_path", "path", "dir", "directory", "file"]) t.exact[k] = "path";
  for (const k of ["user_agent", "header", "headers", "cookie", "content_type", "host"]) t.exact[k] = "header";
  // "_token" names (checkout_token, cart_token…) are ids that travel in clear; secret ones are listed by name above.
  for (const s of ["_token", "_id", "_ids", "_hash", "_uuid", "_sku"]) t.suffix[s] = "identifier";
  for (const s of [
    "url", "uri", "href", "link", "site", "referrer", "referer", "landing", "location", "callback", "website",
    "src", "origin", "endpoint", "webhook", "image", "avatar", "icon", "logo", "homepage", "home_page", "blog",
    "portfolio",
  ]) {
    t.suffix["_" + s] = "url";
    t.exact[s] = "url";
  }
  for (const s of ["_path", "_file", "_filename", "_dir"]) t.suffix[s] = "path";
  for (const s of [
    "redirect", "redirect_url", "redirect_uri", "redirect_to", "return_to", "return_url", "returnurl", "next",
    "next_url", "continue", "goto", "back_url", "success_url", "cancel_url", "failure_url", "error_url",
  ]) {
    t.exact[s] = "redirect";
  }
  t.suffix["_redirect"] = "redirect";
  t.suffix["_return_url"] = "redirect";
  return t;
}

function entries(m: Record<string, Context>): [string, number][] {
  return Object.keys(m).map((k) => [toBytes(k.toLowerCase()), ctxNumber(m[k])]);
}

/**
 * compileKeyTable builds the classifier over a key table: contains, then exact, then suffix (longest first), then
 * the shape of the value (http://, https:// or // ⇒ URL), else text.
 */
export function compileKeyTable(t: KeyTable): ByteClassifier {
  const contains = entries(t.contains);
  const suffixes = entries(t.suffix);
  const exact = new Map(entries(t.exact));
  // Longest first, stable for equal lengths (insertion sort, as in Go).
  sortByLenDesc(suffixes);
  sortByLenDesc(contains);
  return (key, value) => {
    const k = asciiLower(key);
    for (const [sub, ctx] of contains) if (k.includes(sub)) return ctx;
    const e = exact.get(k);
    if (e !== undefined) return e;
    for (const [suf, ctx] of suffixes) if (k.endsWith(suf)) return ctx;
    return looksLikeURLValue(value) ? CTX_URL : CTX_TEXT;
  };
}

function sortByLenDesc(s: [string, number][]): void {
  for (let i = 1; i < s.length; i++) {
    for (let j = i; j > 0 && s[j][0].length > s[j - 1][0].length; j--) {
      const t = s[j];
      s[j] = s[j - 1];
      s[j - 1] = t;
    }
  }
}

let defaultCl: ByteClassifier | null = null;

export function defaultClassifier(): ByteClassifier {
  if (defaultCl === null) defaultCl = compileKeyTable(defaultKeyTable());
  return defaultCl;
}

function looksLikeURL(v: string): boolean {
  return hasPrefixFold(v, "http://") || hasPrefixFold(v, "https://") || v.startsWith("//");
}

/** looksLikeURLValue: the value, as received or decoded, has the shape of a URL. */
export function looksLikeURLValue(v: string): boolean {
  return looksLikeURL(v) || (mayBeEncoded(v) && looksLikeURL(normalize(v).decoded));
}
