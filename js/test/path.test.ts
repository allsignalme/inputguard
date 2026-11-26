import { describe, expect, it } from "vitest";
import { compilePattern, matchAny, matchPattern } from "../src/path.js";
import type { PathSeg } from "../src/finding.js";
import { formatPath, safePathKey } from "../src/finding.js";

const k = (key: string): PathSeg => ({ key, index: -1 });
const ix = (index: number): PathSeg => ({ key: "", index });

describe("field patterns", () => {
  const cases: Array<[string, PathSeg[], boolean]> = [
    ["a.b", [k("a"), k("b")], true],
    ["a.b", [k("a")], false],
    ["a.b", [k("a"), k("b"), k("c")], false],
    ["items[*].url", [k("items"), ix(3), k("url")], true],
    ["items[*].url", [k("items"), k("x"), k("url")], false],
    ["items[2].url", [k("items"), ix(2), k("url")], true],
    ["items[2].url", [k("items"), ix(1), k("url")], false],
    ["**.description", [k("description")], true],
    ["**.description", [k("a"), ix(0), k("description")], true],
    ["**.description", [k("a"), k("b")], false],
    ["a.**", [k("a"), k("b"), ix(1)], true],
    ["*.name", [k("x"), k("name")], true],
    ["*.name", [ix(0), k("name")], false],
    ["[*]", [ix(5)], true],
    ["[*]", [k("a")], false],
    ["a[0][1]", [k("a"), ix(0), ix(1)], true],
    // A key unsafe to print never matches a literal pattern.
    ["a b", [k("a b")], false],
  ];
  for (const [p, segs, want] of cases) {
    it(`${p} on ${formatPath(segs)}`, () => {
      expect(matchPattern(compilePattern(p), segs)).toBe(want);
    });
  }

  it("rejects bad patterns", () => {
    for (const p of ["", "a..b", "a.", "**[0]", "a[", "a[x]", "a[-1]", "[0", "."]) expect(() => compilePattern(p), p).toThrow(/inputguard/);
    expect(matchAny([compilePattern("x"), compilePattern("y")], [k("y")])).toBe(true);
    expect(matchAny([], [k("y")])).toBe(false);
  });

  it("formats paths and keys", () => {
    expect(formatPath([k("items"), ix(0), k("title")])).toBe("items[0].title");
    expect(formatPath([k("<b>"), k("x")])).toBe("[key].x");
    expect(safePathKey("a".repeat(65))).toBe(false);
    expect(safePathKey("ok-key_1")).toBe(true);
  });
});
