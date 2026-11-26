// IP addresses the way Go's net/netip parses them (ParseAddr, ParsePrefix, Prefix.Contains, Addr.Unmap), plus the
// lenient IPv4 forms URL parsers and inet_aton accept. Only the strict-profile URL rules (ssrf) use this module.

import type { IPAddr } from "./detector.js";

export type Addr = IPAddr;

/** parseAddr is netip.ParseAddr. */
export function parseAddr(s: string): Addr | null {
  for (let i = 0; i < s.length; i++) {
    switch (s[i]) {
      case ".":
        return parseIPv4(s);
      case ":":
        return parseIPv6(s);
      case "%":
        return null;
    }
  }
  return null;
}

function parseIPv4(s: string): Addr | null {
  const f = parseIPv4Fields(s);
  return f === null ? null : { bytes: f, zone: "" };
}

function parseIPv4Fields(s: string): number[] | null {
  const fields = [0, 0, 0, 0];
  let val = 0;
  let pos = 0;
  let digLen = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0x30 && c <= 0x39) {
      if (digLen === 1 && val === 0) return null; // leading zero
      val = val * 10 + (c - 0x30);
      digLen++;
      if (val > 255) return null;
    } else if (c === 0x2e) {
      if (i === 0 || i === s.length - 1 || s.charCodeAt(i - 1) === 0x2e) return null;
      if (pos === 3) return null;
      fields[pos++] = val;
      val = 0;
      digLen = 0;
    } else {
      return null;
    }
  }
  if (pos < 3) return null;
  fields[3] = val;
  return fields;
}

function parseIPv6(input: string): Addr | null {
  let s = input;
  let zone = "";
  const pct = s.indexOf("%");
  if (pct >= 0) {
    zone = s.slice(pct + 1);
    s = s.slice(0, pct);
    if (zone === "") return null;
  }
  const ip = new Array<number>(16).fill(0);
  let ellipsis = -1;
  if (s.length >= 2 && s[0] === ":" && s[1] === ":") {
    ellipsis = 0;
    s = s.slice(2);
    if (s.length === 0) return { bytes: ip, zone };
  }
  let i = 0;
  while (i < 16) {
    let off = 0;
    let acc = 0;
    for (; off < s.length; off++) {
      const c = s.charCodeAt(off);
      let d: number;
      if (c >= 0x30 && c <= 0x39) d = c - 0x30;
      else if (c >= 0x61 && c <= 0x66) d = c - 0x61 + 10;
      else if (c >= 0x41 && c <= 0x46) d = c - 0x41 + 10;
      else break;
      acc = acc * 16 + d;
      if (off > 3) return null; // more than 4 digits in a group
      if (acc > 0xffff) return null;
    }
    if (off === 0) return null;
    if (off < s.length && s[off] === ".") {
      if (ellipsis < 0 && i !== 12) return null;
      if (i + 4 > 16) return null;
      const f = parseIPv4Fields(s);
      if (f === null) return null;
      for (let k = 0; k < 4; k++) ip[i + k] = f[k];
      s = "";
      i += 4;
      break;
    }
    ip[i] = acc >> 8;
    ip[i + 1] = acc & 0xff;
    i += 2;
    s = s.slice(off);
    if (s.length === 0) break;
    if (s[0] !== ":") return null;
    if (s.length === 1) return null;
    s = s.slice(1);
    if (s[0] === ":") {
      if (ellipsis >= 0) return null;
      ellipsis = i;
      s = s.slice(1);
      if (s.length === 0) break;
    }
  }
  if (s.length !== 0) return null;
  if (i < 16) {
    if (ellipsis < 0) return null;
    const n = 16 - i;
    for (let j = i - 1; j >= ellipsis; j--) ip[j + n] = ip[j];
    for (let j = ellipsis; j < ellipsis + n; j++) ip[j] = 0;
  } else if (ellipsis >= 0) {
    return null;
  }
  return { bytes: ip, zone };
}

export function is6(a: Addr): boolean {
  return a.bytes.length === 16;
}

/** unmap is Addr.Unmap: an IPv4-mapped IPv6 address becomes IPv4 (zone dropped). */
export function unmap(a: Addr): Addr {
  if (!is6(a)) return a;
  const b = a.bytes;
  for (let i = 0; i < 10; i++) if (b[i] !== 0) return a;
  if (b[10] !== 0xff || b[11] !== 0xff) return a;
  return { bytes: b.slice(12), zone: "" };
}

export interface Prefix {
  addr: number[];
  bits: number;
}

/** parsePrefix is netip.ParsePrefix followed by Masked. */
export function parsePrefix(s: string): Prefix | null {
  const i = s.lastIndexOf("/");
  if (i < 0) return null;
  const a = parseAddr(s.slice(0, i));
  if (a === null || (is6(a) && a.zone !== "")) return null;
  const bitsStr = s.slice(i + 1);
  if (!/^(?:0|[1-9][0-9]*)$/.test(bitsStr) && !(bitsStr.length === 1 && /[0-9]/.test(bitsStr))) return null;
  const bits = Number(bitsStr);
  const max = a.bytes.length * 8;
  if (bits < 0 || bits > max) return null;
  return { addr: maskBytes(a.bytes, bits), bits };
}

/** prefixOf is netip.PrefixFrom(a, a.BitLen()). */
export function prefixOf(a: Addr): Prefix {
  return { addr: a.bytes.slice(), bits: a.bytes.length * 8 };
}

function maskBytes(b: number[], bits: number): number[] {
  return b.map((v, i) => {
    const keep = Math.max(0, Math.min(8, bits - i * 8));
    return keep === 8 ? v : v & ((0xff << (8 - keep)) & 0xff);
  });
}

/** prefixContains is Prefix.Contains: same family, no zone, same leading bits. */
export function prefixContains(p: Prefix, a: Addr): boolean {
  if (a.zone !== "" || p.addr.length !== a.bytes.length) return false;
  const m = maskBytes(a.bytes, p.bits);
  for (let i = 0; i < m.length; i++) if (m[i] !== p.addr[i]) return false;
  return true;
}

function v4(b: number[], from: number): Addr {
  return { bytes: b.slice(from, from + 4), zone: "" };
}

/**
 * parseHostIP reads an IP literal the way URL parsers and inet_aton do: IPv6 in brackets (zone allowed), and IPv4
 * in 1 to 4 parts, each decimal, octal (leading 0) or hex (0x): 127.1, 2130706433, 0x7f.0.0.1, 0177.0.0.1.
 */
export function parseHostIP(h: string): Addr | null {
  if (h.startsWith("[") && h.endsWith("]") && h.length >= 2) {
    h = h.slice(1, -1);
    const z = h.indexOf("%");
    if (z >= 0) h = h.slice(0, z);
    const a = parseAddr(h);
    return a !== null && is6(a) ? a : null;
  }
  if (h.indexOf(":") >= 0) return parseAddr(h);
  const parts = h.split(".");
  if (parts.length > 4) return null;
  const vals: number[] = [];
  for (let p of parts) {
    if (p === "") return null;
    let base = 10;
    if (p.length > 2 && (p.slice(0, 2) === "0x" || p.slice(0, 2) === "0X")) {
      base = 16;
      p = p.slice(2);
    } else if (p.length > 1 && p[0] === "0") {
      base = 8;
      p = p.slice(1);
    }
    const v = parseUint32(p, base);
    if (v < 0) return null;
    vals.push(v);
  }
  const last = vals.length - 1;
  let ip = 0;
  for (let i = 0; i < last; i++) {
    if (vals[i] > 255) return null;
    ip += vals[i] * 2 ** (24 - 8 * i);
  }
  if (vals[last] >= 2 ** (32 - 8 * last)) return null;
  ip += vals[last];
  return { bytes: [Math.floor(ip / 2 ** 24) & 0xff, Math.floor(ip / 2 ** 16) & 0xff, Math.floor(ip / 2 ** 8) & 0xff, ip & 0xff], zone: "" };
}

// parseUint32 is strconv.ParseUint(s, base, 32): -1 on an empty string, a bad digit or a value over 2^32-1.
function parseUint32(s: string, base: number): number {
  if (s === "") return -1;
  let v = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    let d: number;
    if (c >= 0x30 && c <= 0x39) d = c - 0x30;
    else if (c >= 0x61 && c <= 0x7a) d = c - 0x61 + 10;
    else if (c >= 0x41 && c <= 0x5a) d = c - 0x41 + 10;
    else return -1;
    if (d >= base) return -1;
    v = v * base + d;
    if (v > 0xffffffff) return -1;
  }
  return v;
}

const INTERNAL_PREFIXES: Prefix[] = [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
  "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
  "::/128", "::1/128", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
].map((s) => parsePrefix(s) as Prefix);

/**
 * internalAddr: loopback, private, link-local, shared, unspecified, multicast or reserved, also when wrapped in
 * IPv6 (mapped, compatible, NAT64, 6to4).
 */
export function internalAddr(a: Addr): boolean {
  a = unmap(a);
  if (is6(a)) {
    const b = a.bytes;
    if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return internalAddr(v4(b, 12)); // NAT64
    if (b[0] === 0x20 && b[1] === 0x02) return internalAddr(v4(b, 2)); // 6to4
    if (b.slice(0, 12).every((x) => x === 0) && !(b[12] === 0 && b[13] === 0)) return internalAddr(v4(b, 12));
  }
  for (const p of INTERNAL_PREFIXES) if (prefixContains(p, a)) return true;
  return false;
}
