// Hostile inputs: JavaScript regular expressions backtrack, so every pattern is run on long adversarial strings.
// The Go engine's regression cases (regress_test.go, regress2_test.go) and runs aimed at each regular expression.

import { describe, expect, it } from "vitest";
import { Guard } from "../src/index.js";

const strict = new Guard({
  mode: "reject",
  profile: "strict",
  categories: ["xss", "template", "injection", "unicode", "structure", "output"],
  redirectHosts: ["shop.example.com"],
});
const strictClean = new Guard({
  profile: "strict",
  categories: ["xss", "template", "injection", "unicode", "structure", "output"],
  redirectHosts: ["shop.example.com"],
});
const balanced = new Guard();

const r = (s: string, n: number): string => s.repeat(n);

const HOSTILE: Record<string, string> = {
  slashes: r("/", 200_000),
  backslashes: r("\\", 100_000),
  handlers: "<" + r("on", 100_000),
  spaces: "data:" + r(" ", 200_000),
  "dot segments": r("/.", 100_000) + "x..",
  "quotes and or": r("' or ", 30_000),
  "quote paren": r("')(", 50_000),
  "union select": r("union /* select ", 15_000),
  "stacked semicolons": r("'; select ", 20_000),
  "templates {{": r("{{", 75_000),
  "templates ${": r("${", 75_000),
  "templates <%": r("<%", 75_000),
  "js calls": r("document . ", 25_000),
  "js breakout": r("\"; a(", 30_000),
  "command separators": r("; sleep ", 25_000),
  "command subst": r("$( ", 50_000),
  "nosql": r("[ $ ", 50_000),
  "schemes": r("'java\t", 30_000),
  "percent": r("%25", 65_000),
  "entities": r("&amp;", 40_000),
  "escapes": r("\\u00", 40_000),
  "formula": "=" + r("a|", 75_000),
  "tags": r("<a ", 65_000),
  "comments": r("<!--", 50_000),
  "mixed letters": r("pа", 75_000),
};

describe("hostile inputs finish quickly", () => {
  for (const [name, s] of Object.entries(HOSTILE)) {
    it(name, () => {
      for (const [gname, g] of [
        ["balanced", balanced],
        ["strict", strict],
        ["strict clean", strictClean],
      ] as const) {
        for (const ctx of ["text", "url", "path"] as const) {
          const start = performance.now();
          g.processString(s, ctx);
          const ms = performance.now() - start;
          // Linear input takes well under a second (several under coverage); quadratic would take minutes.
          expect(ms, `${gname} ${ctx}: ${ms.toFixed(0)} ms for ${s.length} characters`).toBeLessThan(10_000);
        }
      }
    });
  }

  it("cleanPath on a long path keeps the clean prefix", () => {
    const out = balanced.processString("https://x.com" + r("/a", 100_000) + "/<script>", "url").value;
    expect(out).toBe("https://x.com" + r("/a", 100_000) + "/");
  });
});

describe("regressions from the Go engine", () => {
  it("a scheme split by tabs and line breaks", () => {
    for (const s of ["jav\r\nascript:alert(document.cookie)", "java\t\tscript:alert(1)", "java\t\t\tscript:alert(1)"]) {
      expect(balanced.processString(s, "url").value).toBe("");
    }
  });

  it("SSRF through compatibility forms", () => {
    const g = new Guard({ rules: ["ssrf"] });
    for (const u of ["http://①②⑦.0.0.1/", "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/", "http://¹²⁷.0.0.1/", "http://ＬＯＣＡＬＨＯＳＴ/", "http://0x7f.1/", "http://[::ffff:127.0.0.1]/", "http://2130706433/"]) {
      expect(g.checkString(u, "url").findings.map((f) => f.rule), u).toContain("ssrf");
    }
    const allow = new Guard({ rules: ["ssrf"], ssrfAllow: ["10.1.0.0/16", "metadata", "fd00::1"] });
    expect(allow.checkString("http://10.1.2.3/", "url").findings).toEqual([]);
    expect(allow.checkString("http://metadata/", "url").findings).toEqual([]);
    expect(allow.checkString("http://[fd00::1]/", "url").findings).toEqual([]);
    expect(allow.checkString("http://10.2.0.1/", "url").findings).not.toEqual([]);
  });
});
