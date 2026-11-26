// URL helpers shared by cleaning and the URL rules (byte strings).

import { containsAny, indexAny } from "./bytes.js";

/** splitScheme: [scheme, rest after ":"] when s starts with a URL scheme, else null. */
export function splitScheme(s: string): [string, string] | null {
  const i = s.indexOf(":");
  if (i <= 0 || containsAny(s.slice(0, i), "/?#")) return null;
  for (let j = 0; j < i; j++) {
    const c = s.charCodeAt(j);
    const alpha = (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a);
    const other = (c >= 0x30 && c <= 0x39) || c === 0x2b || c === 0x2e || c === 0x2d;
    if (!alpha && (j === 0 || !other)) return null;
  }
  return [s.slice(0, i), s.slice(i + 1)];
}

/** splitAuthority splits "host/path" at the first "/", "?" or "#". */
export function splitAuthority(s: string): [string, string] {
  const i = indexAny(s, "/?#");
  return i >= 0 ? [s.slice(0, i), s.slice(i)] : [s, ""];
}

/** cut is strings.Cut. */
export function cut(s: string, sep: string): [string, string, boolean] {
  const i = s.indexOf(sep);
  return i < 0 ? [s, "", false] : [s.slice(0, i), s.slice(i + sep.length), true];
}
