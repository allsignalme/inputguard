import { describe, expect, it } from "vitest";
import { Guard as BalancedGuard } from "../src/balanced.js";
import type { Report } from "../src/index.js";
import { defaultKeyTable, Guard, isClean, lookupRule, RejectedError, rejectedError, reportRules, rules } from "../src/index.js";

const cp = (...codes: number[]): string => String.fromCodePoint(...codes);

describe("processString", () => {
  const g = new Guard();

  it("keeps clean values as the same string", () => {
    for (const s of ["", "Áo thun nam cổ tròn", "Sale " + cp(0x1f525) + " -20% (Black Friday)", 'Samsung 55" -- 4K', "Tom & Jerry"]) {
      const { value, report } = g.processString(s);
      expect(value).toBe(s);
      expect(isClean(report)).toBe(true);
    }
  });

  it("cuts text at the payload and reports byte offsets", () => {
    const { value, report } = g.processString("Áo thun <script>alert(1)</script>");
    expect(value).toBe("Áo thun");
    expect(report.changed).toBe(true);
    expect(report.findings[0]).toMatchObject({ rule: "tag_dangerous", path: "", context: "text", action: "clean", offset: 9 });
    expect(reportRules(report)).toEqual(["tag_dangerous"]);
  });

  it("drops only the bad query pair of a URL and keeps the rest verbatim", () => {
    const url = "https://shop.example.com/products/ao-thun?utm_content=%3Cscript%3Ealert(1)%3C%2Fscript%3E&q=%C3%A1o&variant=1";
    expect(g.processString(url, "url").value).toBe("https://shop.example.com/products/ao-thun?q=%C3%A1o&variant=1");
    expect(g.processString("javascript:alert(1)", "url").value).toBe("");
  });

  it("treats a lone surrogate as invalid UTF-8", () => {
    const s = "a" + String.fromCharCode(0xd800) + "b";
    const { value, report } = g.processString(s);
    expect(reportRules(report)).toEqual(["invalid_utf8"]);
    expect(value).toBe("a" + cp(0xfffd) + "b");
  });

  it("removes control and bidi characters and keeps the rest", () => {
    const { value } = g.processString("ab" + cp(0x202e) + "cd" + cp(0x07));
    expect(value).toBe("abcd");
  });

  it("empties an identifier carrying a payload, keeps one with a stray character", () => {
    expect(g.processString("fb.1.2.<svg onload=alert(1)>", "identifier").value).toBe("");
    const strict = new Guard({ profile: "strict" });
    expect(strict.processString("abc" + cp(0x200b) + "def", "identifier").value).toBe("abcdef");
  });

  it("checkString and mightBeDirty", () => {
    expect(reportRules(g.checkString("<img src=x onerror=alert(1)>"))).toContain("event_handler");
    expect(g.mightBeDirty("plain text")).toBe(false);
    expect(g.mightBeDirty("<b>")).toBe(true);
  });

  it("secret: skipped when rejecting, an identifier when cleaning", () => {
    const reject = new Guard({ mode: "reject" });
    expect(isClean(reject.checkString("<script>", "secret"))).toBe(true);
    expect(g.processString("<script>", "secret").value).toBe("");
  });
});

describe("processField and classification", () => {
  it("picks the context from the key", () => {
    const g = new Guard();
    expect(g.processField("event_source_url", "javascript:alert(1)").value).toBe("");
    expect(g.processField("title", "JavaScript: The Good Parts").value).toBe("JavaScript: The Good Parts");
    expect(g.processField("email", "a<b>x</b>").value).toBe("");
    expect(g.processField("user_email", "a<b>x</b>").value).toBe("a");
  });

  it("keyContexts, keyTable and a custom classifier", () => {
    // A scheme followed by a space is text ("JavaScript: The Good Parts") but a link in a URL field.
    const url = "javascript: alert(1)";
    expect(new Guard().processField("dl", url).value).toBe(url);
    expect(new Guard({ keyContexts: { url: ["DL"] } }).processField("dl", url).value).toBe("");
    const table = defaultKeyTable();
    table.suffix["_link2"] = "url";
    expect(new Guard({ keyTable: table }).processField("my_link2", url).value).toBe("");
    const g = new Guard({ classifier: (key) => (key === "x" ? "url" : "text") });
    expect(g.processField("x", url).value).toBe("");
    expect(g.processField("y", url).value).toBe(url);
  });
});

describe("processValue", () => {
  it("never changes its input and returns it as is when clean", () => {
    const g = new Guard();
    const clean = { a: "x", n: 1, list: [true, null, "y"] };
    expect(g.processValue(clean).value).toBe(clean);
    const dirty = JSON.parse('{"__proto__": {"admin": true}, "title": "<b>x</b> ok", "deep": [{"t": "<script>"}]}') as object;
    const before = JSON.stringify(dirty);
    const { value, report } = g.processValue(dirty);
    expect(JSON.stringify(dirty)).toBe(before);
    expect(value).not.toBe(dirty);
    expect(Object.prototype.hasOwnProperty.call(value, "__proto__")).toBe(false);
    expect(value).toEqual({ title: "", deep: [{ t: "" }] });
    expect(report.findings.map((f) => [f.rule, f.path])).toEqual([
      ["proto_pollution", "[key]"],
      ["tag_dangerous", "deep[0].t"],
      ["tag_generic", "title"],
    ]);
  });

  it("leaves non-JSON values alone", () => {
    const g = new Guard();
    const d = new Date(0);
    const v = { d, f: () => 1, m: new Map([["k", "<script>"]]) };
    expect(g.processValue(v).value).toBe(v);
    expect(g.processValue("<b>x</b>").value).toBe("");
    expect(g.processValue(42).value).toBe(42);
  });

  it("renames a key whose only problem is a stray character", () => {
    const g = new Guard();
    const { value } = g.processValue({ ["ti" + cp(0x07) + "tle"]: "a", title: "b", ["na" + cp(0x07) + "me"]: "c" });
    expect(value).toEqual({ title: "b", name: "c" });
  });

  it("exempt and fieldContexts", () => {
    const g = new Guard({ exempt: ["html_body", "items[*].raw"], fieldContexts: [["items[*].link", "url"]] });
    const doc = { html_body: "<b>ok</b>", items: [{ raw: "<i>x</i>", link: "javascript:alert(1)", name: "<b>n</b>" }] };
    const { value } = g.processValue(doc);
    expect(value).toEqual({ html_body: "<b>ok</b>", items: [{ raw: "<i>x</i>", link: "", name: "" }] });
  });

  it("limits: depth and string count", () => {
    const g = new Guard({ limits: { maxDepth: 2, maxStrings: 2 } });
    const { value, report } = g.processValue({ a: { b: { c: "x" } }, s: ["1", "<b>2</b>", "<b>3</b>"] });
    expect(report.limitExceeded).toBe(true);
    expect(value).toEqual({ a: { b: null }, s: ["1", "", ""] });
    const reject = new Guard({ limits: { maxDepth: 1, onExceed: "reject" } });
    const r = reject.processValue({ a: { b: 1 } });
    expect(r.report.rejected).toBe(true);
    expect(r.value).toEqual({ a: { b: 1 } });
  });

  it("an over-limit string", () => {
    const g = new Guard({ limits: { maxStringBytes: 8 } });
    expect(g.processString("<b>1234567</b>").value).toBe("");
    expect(g.processString("123456789").value).toBe("123456789");
    const report = new Guard({ limits: { maxStringBytes: 8, onExceed: "report" } }).processString("<b>1234567</b>");
    expect(report.value).toBe("<b>1234567</b>");
    expect(report.report.limitExceeded).toBe(true);
  });
});

describe("reject mode and reports", () => {
  it("rejects without changing the value and explains why", () => {
    const g = new Guard({ mode: "reject" });
    expect(g.mode).toBe("reject");
    expect(g.profile).toBe("strict");
    const { value, report } = g.processValue({ name: "x' OR 1=1 --", ok: "fine" });
    expect(value).toEqual({ name: "x' OR 1=1 --", ok: "fine" });
    expect(report.rejected).toBe(true);
    const err = rejectedError(report);
    expect(err).toBeInstanceOf(RejectedError);
    expect(err?.message).toBe("input rejected: name: SQL injection");
    expect(rejectedError({ ...report, rejected: false })).toBeNull();
    const limit: Report = { findings: [], changed: false, rejected: true, truncated: false, limitExceeded: true };
    expect(new RejectedError(limit).message).toBe("input rejected: document too deep or too large");
  });

  it("actions per rule and per severity, observer, truncation", () => {
    const seen: Report[] = [];
    const g = new Guard({
      actions: { tag_generic: "report", control_char: "ignore" },
      severityActions: { critical: "reject" },
      observer: (r) => seen.push(r),
      limits: { maxFindings: 1 },
    });
    expect(g.actionFor("tag_generic")).toBe("report");
    expect(g.actionFor("tag_dangerous")).toBe("reject");
    expect(g.enabled("control_char")).toBe(false);
    expect(g.processString("<b>x</b>").value).toBe("<b>x</b>");
    const r = g.processString("<script>").report;
    expect(r.rejected).toBe(true);
    expect(seen.length).toBe(2);
    expect(g.processString("<b>x</b>" + cp(0x202e)).report.truncated).toBe(true);
  });

  it("rules and categories", () => {
    const g = new Guard({ categories: ["injection"], withoutRules: ["command"], rules: ["mixed_scripts"] });
    expect(g.enabled("sql_injection")).toBe(true);
    expect(g.enabled("command")).toBe(false);
    expect(g.enabled("mixed_scripts")).toBe(true);
    expect(g.enabled("template")).toBe(false);
    expect(new Guard({ redirectHosts: ["shop.example.com"] }).enabled("open_redirect")).toBe(true);
  });
});

describe("configuration errors", () => {
  it("throws on unknown names and bad patterns", () => {
    const bad: unknown[] = [
      { rules: ["nope"] },
      { withoutRules: ["nope"] },
      { categories: ["nope"] },
      { actions: { nope: "clean" } },
      { actions: { scheme: "nope" } },
      { severityActions: { nope: "clean" } },
      { mode: "nope" },
      { profile: "nope" },
      { redirectHosts: ["a/b"] },
      { ssrfAllow: ["a/b?c"] },
      { exempt: ["a..b"] },
      { exempt: [""] },
      { fieldContexts: [["a[x]", "url"]] },
      { fieldContexts: [["a", "nope"]] },
      { keyContexts: { nope: ["a"] } },
    ];
    for (const o of bad) expect(() => new Guard(o as never), JSON.stringify(o)).toThrow(/inputguard/);
  });

  it("the balanced build refuses strict rules", () => {
    expect(() => new BalancedGuard({ profile: "strict" })).toThrow(/not in this build/);
    expect(() => new BalancedGuard({ rules: ["sql_injection"] })).toThrow(/not in this build/);
    const g = new BalancedGuard({ mode: "reject", profile: "balanced" });
    expect(g.processString("<script>").report.rejected).toBe(true);
  });
});

describe("rule table", () => {
  it("lists and looks up rules", () => {
    expect(rules()).toHaveLength(25);
    expect(lookupRule("scheme")).toMatchObject({ category: "xss", severity: "critical", profile: "balanced" });
    expect(lookupRule("nope")).toBeUndefined();
  });
});
