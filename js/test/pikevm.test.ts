// The linear-time engine must find exactly what the JavaScript engine finds: same match start, same group 1 start.
// Every pattern of the strict rules is run on random strings built from the tokens the patterns care about.

import { describe, expect, it } from "vitest";
import "../src/detectors.js";
import { compile, exec } from "../src/pikevm.js";
import { matchIndex } from "../src/regex.js";
import { LINEAR_THRESHOLD, matchIndexSafe, SAFE_PATTERNS, safeRe } from "../src/saferegex.js";

const TOKENS = [
  " ", "  ", "\t", "\n", "\r", "\f", "'", '"', "`", "(", ")", ";", "--", "#", "/*", "*/", "/", "*", "union", "select",
  "all", "distinct", "from", "or", "and", "xor", "not", "like", "is", "in", "true", "false", "null", "1", "42", "3.5",
  "a", "b_c", ".", ",", "=", "<>", "!=", "<", ">", "|", "||", "&", "&&", "{{", "}}", "{%", "%}", "${", "}", "{", "<%",
  "%>", "$(", "$", "echo", "id", "ls", "rm", "-rf", "curl", "https:", "sleep", "sleep(", "char(", "benchmark(",
  "@@version", "@", "$ne", "$where", "[", "]", "drop", "table", "update", "set", "insert", "into", "delete", "waitfor",
  "delay", "document", "window", ".cookie", "innerhtml", "eval", "import", "new", "function", "hyperlink", "cmd",
  "webservice", "register", ".id", "\xe2\x84\xaa", "\xc5\xbf", "\xc3\xa9", "\xff", "information_schema", "sys.",
  "x_y", "ifs", "/bin/sh", "-c", "python", "nc", "-e",
];

// A small deterministic generator, so that a failure can be reproduced.
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 0x100000000;
  };
}

function randomInput(next: () => number): string {
  const n = Math.floor(next() * 24);
  let out = "";
  for (let i = 0; i < n; i++) out += TOKENS[Math.floor(next() * TOKENS.length)];
  return out;
}

describe("pikevm", () => {
  it("agrees with the JavaScript engine on every strict pattern", () => {
    expect(SAFE_PATTERNS.length).toBeGreaterThan(10);
    const next = rng(20261126);
    const bad: string[] = [];
    for (const re of SAFE_PATTERNS) {
      const prog = compile(re.src);
      for (let k = 0; k < 3000 && bad.length < 10; k++) {
        const s = randomInput(next);
        const m = exec(prog, s);
        const got = m === null ? -1 : m[1] >= 0 ? m[1] : m[0];
        const want = matchIndex(re.native, s);
        if (got !== want) bad.push(`${re.src.slice(0, 60)}… on ${JSON.stringify(s)}: ${got}, want ${want}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it("supports the syntax the rules use", () => {
    const cases: Array<[string, string, number]> = [
      ["a{2,3}b", "aaab", 0],
      ["a{2,}?b", "xaaaab", 1],
      ["x(?:ab)?c", "xc", 0],
      ["^\\s*(a)", "  a", 2],
      ["b$", "ab", 1],
      ["\\bfoo\\b", "a foo", 2],
      ["[^\\n]+z", "ab\nz", -1],
      ["[\\s\\S]*?z", "a\nz", 0],
      ["\\x41\\.", "A.", 0],
      ["[a\\-z]", "-", 0],
      ["b|(a)", "b", 0],
      ["b|(a)", "xa", 1],
    ];
    for (const [src, s, want] of cases) {
      const m = exec(compile(src), s);
      expect(m === null ? -1 : m[1] >= 0 ? m[1] : m[0], src).toBe(want);
      expect(matchIndex(safeRe(src).native, s), src).toBe(want);
    }
    expect(() => compile("a\\q")).toThrow();
    expect(() => compile("(a")).toThrow();
    expect(() => safeRe("(a)b")).toThrow(/group 1/);
    expect(() => safeRe("x(a)(?:b)")).toThrow(/group 1/);
    expect(() => safeRe("(a)(b)")).toThrow(/group 1/);
    expect(() => safeRe("x(?:a|(b))")).toThrow(/group 1/); // the group must close at the last character
    expect(safeRe("x(a|b)").native.source).toBe("x(a|b)");
    expect(() => compile("[a")).toThrow();
  });

  it("uses the linear engine past the threshold, with the same result", () => {
    const re = safeRe("\\{\\{[\\s\\S]*?\\}\\}");
    const long = "x".repeat(LINEAR_THRESHOLD) + "{{a}}";
    expect(matchIndexSafe(re, long)).toBe(LINEAR_THRESHOLD);
    expect(matchIndexSafe(re, "{{" + "a".repeat(LINEAR_THRESHOLD))).toBe(-1);
  });
});
