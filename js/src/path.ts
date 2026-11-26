// Field patterns: "a.b", "items[*].url", "items[2].url", "**.description", "*.name".

import type { PathSeg } from "./finding.js";
import { safePathKey } from "./finding.js";

const KEY = 0;
const ANY_KEY = 1;
const ANY_INDEX = 2;
const INDEX = 3;
const ANY_DEPTH = 4;

interface PatSeg {
  kind: number;
  key: string;
  index: number;
}

export type Pattern = PatSeg[];

function bad(s: string): Error {
  return new Error(`inputguard: bad field pattern ${JSON.stringify(s)}`);
}

export function compilePattern(s: string): Pattern {
  if (s === "") throw new Error("inputguard: empty field pattern");
  const p: Pattern = [];
  for (const part of s.split(".")) {
    if (part === "") throw bad(s);
    const b = part.indexOf("[");
    const name = b < 0 ? part : part.slice(0, b);
    const rest = b < 0 ? "" : part.slice(b + 1);
    if (name === "**") {
      if (rest !== "") throw bad(s);
      p.push({ kind: ANY_DEPTH, key: "", index: 0 });
      continue;
    } else if (name === "*") {
      p.push({ kind: ANY_KEY, key: "", index: 0 });
    } else if (name === "") {
      if (b < 0) throw bad(s);
    } else {
      p.push({ kind: KEY, key: name, index: 0 });
    }
    if (b < 0) continue;
    for (const g of ("[" + rest).split("[").slice(1)) {
      if (!g.endsWith("]")) throw bad(s);
      const inner = g.slice(0, -1);
      if (inner === "*") {
        p.push({ kind: ANY_INDEX, key: "", index: 0 });
        continue;
      }
      if (!/^[+-]?\d+$/.test(inner)) throw bad(s);
      const n = Number(inner);
      if (n < 0 || !Number.isSafeInteger(n)) throw bad(s);
      p.push({ kind: INDEX, key: "", index: n });
    }
  }
  return p;
}

export function matchPattern(p: Pattern, segs: readonly PathSeg[], pi = 0, si = 0): boolean {
  while (pi < p.length) {
    const ps = p[pi];
    if (ps.kind === ANY_DEPTH) {
      if (pi + 1 === p.length) return true;
      for (let i = si; i <= segs.length; i++) {
        if (matchPattern(p, segs, pi + 1, i)) return true;
      }
      return false;
    }
    if (si >= segs.length) return false;
    const s = segs[si];
    switch (ps.kind) {
      case KEY:
        // A key unsafe to print never matches a literal pattern, so a client cannot dress a key up as an exempt path.
        if (s.index >= 0 || s.key !== ps.key || !safePathKey(s.key)) return false;
        break;
      case ANY_KEY:
        if (s.index >= 0) return false;
        break;
      case ANY_INDEX:
        if (s.index < 0) return false;
        break;
      case INDEX:
        if (s.index !== ps.index) return false;
        break;
    }
    pi++;
    si++;
  }
  return si === segs.length;
}

export function matchAny(ps: readonly Pattern[], segs: readonly PathSeg[]): boolean {
  for (const p of ps) if (matchPattern(p, segs)) return true;
  return false;
}
