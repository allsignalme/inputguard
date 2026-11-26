// Patterns of the strict rules. The ones that can take quadratic time in a backtracking engine on hostile input
// (lazy or open-ended scans that many start positions repeat: templates, UNION with comments, stacked SELECT…FROM,
// command echo, formula DDE) run on the linear-time engine (pikevm.ts) once the input is long; the JavaScript engine
// handles short inputs and the patterns that stay linear in it. Both engines find the same leftmost-first match.

import type { Program } from "./pikevm.js";
import { compile, exec } from "./pikevm.js";
import { goRe, matchIndex } from "./regex.js";

/** Inputs longer than this run on the linear-time engine; shorter ones on the JavaScript engine. */
export const LINEAR_THRESHOLD = 4096;

/** A Go pattern runnable on both engines. */
export interface SafeRe {
  readonly src: string;
  readonly native: RegExp;
  /** Runs on the linear-time engine past LINEAR_THRESHOLD. */
  readonly linear: boolean;
  prog: Program | null;
}

/** Every pattern built, for the tests that compare the two engines. */
export const SAFE_PATTERNS: SafeRe[] = [];

function make(src: string, linear: boolean): SafeRe {
  const re: SafeRe = { src, native: goRe(src), linear, prog: null };
  SAFE_PATTERNS.push(re);
  return re;
}

/** safeRe: a pattern that needs the linear-time engine on long inputs. */
export function safeRe(src: string): SafeRe {
  return make(src, true);
}

/** nativeRe: a pattern that stays linear in the JavaScript engine (checked by test/regress.test.ts). */
export function nativeRe(src: string): SafeRe {
  return make(src, false);
}

/** matchIndexSafe is matchIndex, in linear time on long inputs for safeRe patterns. */
export function matchIndexSafe(re: SafeRe, s: string): number {
  if (!re.linear || s.length <= LINEAR_THRESHOLD) return matchIndex(re.native, s);
  if (re.prog === null) re.prog = compile(re.src);
  const m = exec(re.prog, s);
  if (m === null) return -1;
  return m[1] >= 0 ? m[1] : m[0];
}
