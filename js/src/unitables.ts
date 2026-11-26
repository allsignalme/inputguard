// Range tables generated from Go's unicode package (tables/unicode.ts), parsed on first use.

import * as T from "./tables/unicode.js";

export type RangeTable = Int32Array;

const cache = new Map<string, RangeTable>();

function table(data: string): RangeTable {
  let t = cache.get(data);
  if (t === undefined) {
    const parts = data.split(",");
    t = new Int32Array(parts.length);
    for (let i = 0; i < parts.length; i++) t[i] = parseInt(parts[i], 36);
    cache.set(data, t);
  }
  return t;
}

function inTable(t: RangeTable, r: number): boolean {
  let lo = 0;
  let hi = t.length / 2 - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (r < t[2 * mid]) hi = mid - 1;
    else if (r > t[2 * mid + 1]) lo = mid + 1;
    else return true;
  }
  return false;
}

export const isLetterRune = (r: number): boolean => inTable(table(T.LETTER), r);
export const isMn = (r: number): boolean => inTable(table(T.MN), r);
export const isCf = (r: number): boolean => inTable(table(T.CF), r);
export const isLatin = (r: number): boolean => inTable(table(T.LATIN), r);
export const isCyrillic = (r: number): boolean => inTable(table(T.CYRILLIC), r);
export const isGreek = (r: number): boolean => inTable(table(T.GREEK), r);
export const isArmenian = (r: number): boolean => inTable(table(T.ARMENIAN), r);
export const isCherokee = (r: number): boolean => inTable(table(T.CHEROKEE), r);
export const isVariationSelector = (r: number): boolean => inTable(table(T.VARIATION_SELECTOR), r);
export const isOtherDefaultIgnorable = (r: number): boolean => inTable(table(T.OTHER_DEFAULT_IGNORABLE), r);
export const isSpaceRune = (r: number): boolean => inTable(table(T.SPACE), r);
export const unicodeVersion = T.UNICODE_VERSION;
