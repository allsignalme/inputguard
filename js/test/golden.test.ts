// Parity with the Go engine: the golden files under ../testdata/golden record what the Go engine does on the shared
// corpus (go test -run TestGolden -update writes them). Every finding (rule, path, context, action, byte offset),
// every output byte and every report flag must be the same.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { defaultClassifier } from "../src/context.js";
import { ALL_DETECTORS } from "../src/detectors.js";
import type { GuardOptions } from "../src/engine.js";
import { Engine } from "../src/engine.js";
import { hostRules } from "../src/hosts.js";
import { Guard } from "../src/index.js";
import { CONTEXT_NAMES, ctxNumber, RULE_TABLE } from "../src/rule.js";
import type { Context } from "../src/rule.js";
import { toBytes } from "../src/bytes.js";

const goldenDir = fileURLToPath(new URL("../../testdata/golden/", import.meta.url));

function golden<T>(name: string): T {
  return JSON.parse(readFileSync(goldenDir + name, "utf8")) as T;
}

type GoldenString = string | { hex: string };

/** bytesOf decodes a golden string into a byte string. */
function bytesOf(g: GoldenString): string {
  if (typeof g === "string") return toBytes(g);
  let out = "";
  for (let i = 0; i < g.hex.length; i += 2) out += String.fromCharCode(parseInt(g.hex.slice(i, i + 2), 16));
  return out;
}

const ALL_CATEGORIES = ["xss", "template", "injection", "unicode", "structure", "output"] as const;

export const GOLDEN_CONFIGS: Record<string, GuardOptions> = {
  balanced_clean: {},
  strict_clean: { profile: "strict", categories: [...ALL_CATEGORIES], redirectHosts: ["shop.example.com"] },
  strict_reject: { mode: "reject", profile: "strict", categories: [...ALL_CATEGORIES], redirectHosts: ["shop.example.com"] },
  social_strict: {
    mode: "reject",
    profile: "strict",
    actions: { invisible_char: "clean", header_crlf: "clean" },
    redirectHosts: ["allsignalme.com", "myshopify.com"],
  },
  balanced_limits: { limits: { maxDepth: 3, maxStrings: 8 } },
};

interface Report {
  changed?: boolean;
  rejected?: boolean;
  truncated?: boolean;
  limitExceeded?: boolean;
  findings?: Array<Array<string | number>>;
}

function flags(r: { changed: boolean; rejected: boolean; truncated: boolean; limitExceeded: boolean }): string {
  return JSON.stringify([r.changed, r.rejected, r.truncated, r.limitExceeded]);
}

function expectedFlags(r: Report | undefined): string {
  return JSON.stringify([!!r?.changed, !!r?.rejected, !!r?.truncated, !!r?.limitExceeded]);
}

function show(b: string): string {
  return JSON.stringify(b);
}

describe("golden: strings", () => {
  const g = golden<{
    configs: string[];
    contexts: Context[];
    inputs: GoldenString[];
    results: Array<Report & { i: number; cfg: string; ctx: Context; out?: GoldenString }>;
  }>("strings.json");
  const expected = new Map<string, (typeof g.results)[number]>();
  for (const r of g.results) expected.set(`${r.cfg}/${r.ctx}/${r.i}`, r);
  const inputs = g.inputs.map(bytesOf);

  for (const cfg of g.configs) {
    it(`${cfg}: every corpus value in every context`, () => {
      const e = new Engine(ALL_DETECTORS, GOLDEN_CONFIGS[cfg], hostRules);
      const bad: string[] = [];
      inputs.forEach((input, i) => {
        for (const ctx of g.contexts) {
          const want = expected.get(`${cfg}/${ctx}/${i}`);
          const [out, rep] = e.processBytes(input, ctxNumber(ctx));
          const wantOut = want?.out !== undefined ? bytesOf(want.out) : input;
          const got = JSON.stringify(rep.findings.map((f) => [f.rule, f.action, f.offset]));
          const exp = JSON.stringify(want?.findings ?? []);
          if (out !== wantOut || got !== exp || flags(rep) !== expectedFlags(want)) {
            bad.push(`#${i} ${ctx} ${show(input)}\n  out  ${show(out)}\n  want ${show(wantOut)}\n  findings ${got}\n  want     ${exp}\n  flags ${flags(rep)} want ${expectedFlags(want)}`);
          }
          for (const f of rep.findings) {
            if (f.path !== "" || f.context !== ctx) bad.push(`#${i} ${ctx}: finding with path ${f.path} context ${f.context}`);
          }
        }
      });
      expect(bad.slice(0, 15).join("\n"), `${bad.length} mismatches`).toBe("");
    });
  }
});

function goldenDoc(p: string): Record<string, unknown> {
  return {
    event_name: "ViewContent",
    dl: p,
    event_source_url: p,
    fbc: p,
    content_name: p,
    redirect_url: p,
    file_path: p,
    user_agent: p,
    contents: [{ id: p, quantity: 1 }, p],
    keys: { [p]: "v" },
  };
}

describe("golden: values", () => {
  const raw = readFileSync(goldenDir + "values.json", "utf8");
  const g = JSON.parse(raw) as {
    configs: string[];
    docs: unknown[];
    payloads: string[];
    results: Array<Report & { doc: number; cfg: string; out?: unknown }>;
  };
  const expected = new Map<string, (typeof g.results)[number]>();
  for (const r of g.results) expected.set(`${r.cfg}/${r.doc}`, r);
  // Parse each document afresh: processValue must not change its input.
  const docs = (): unknown[] => {
    const fresh = (JSON.parse(raw) as { docs: unknown[] }).docs;
    return [...fresh, ...g.payloads.map(goldenDoc)];
  };

  for (const cfg of g.configs) {
    it(`${cfg}: every document`, () => {
      const guard = new Guard(GOLDEN_CONFIGS[cfg]);
      const bad: string[] = [];
      docs().forEach((doc, i) => {
        const before = JSON.stringify(doc);
        const want = expected.get(`${cfg}/${i}`);
        const { value, report } = guard.processValue(doc);
        const got = JSON.stringify(report.findings.map((f) => [f.rule, f.path, f.context, f.action, f.offset]));
        const exp = JSON.stringify(want?.findings ?? []);
        if (got !== exp || flags(report) !== expectedFlags(want)) {
          bad.push(`doc ${i}: findings ${got}\n  want     ${exp}\n  flags ${flags(report)} want ${expectedFlags(want)}`);
        }
        try {
          expect(value).toEqual(want?.out !== undefined ? want.out : doc);
        } catch {
          bad.push(`doc ${i}: output ${JSON.stringify(value)}\n  want ${JSON.stringify(want?.out ?? doc)}`);
        }
        if (JSON.stringify(doc) !== before) bad.push(`doc ${i}: input modified`);
        if (want?.out === undefined && value !== doc) bad.push(`doc ${i}: unchanged value not returned as is`);
      });
      expect(bad.slice(0, 10).join("\n"), `${bad.length} mismatches`).toBe("");
    });
  }
});

describe("golden: classifier and rule table", () => {
  it("classifies every key of the default table like Go", () => {
    const g = golden<{ values: string[]; rows: string[][] }>("classify.json");
    const cl = defaultClassifier();
    const bad: string[] = [];
    for (const [key, ...ctxs] of g.rows) {
      g.values.forEach((v, j) => {
        const got = CONTEXT_NAMES[cl(toBytes(key), toBytes(v))];
        if (got !== ctxs[j]) bad.push(`${JSON.stringify(key)} ${JSON.stringify(v)}: ${got}, want ${ctxs[j]}`);
      });
    }
    expect(bad).toEqual([]);
  });

  it("has the Go rule table and default limits", () => {
    const g = golden<{ rules: string[][]; limits: Record<string, number> }>("meta.json");
    expect(RULE_TABLE.map((r) => [r.id, r.category, r.severity, r.profile, r.summary])).toEqual(g.rules);
    const e = new Engine(ALL_DETECTORS);
    expect([e.maxDepth, e.maxStrings, e.maxStringBytes, e.maxFindings]).toEqual([
      g.limits.MaxDepth,
      g.limits.MaxStrings,
      g.limits.MaxStringBytes,
      g.limits.MaxFindings,
    ]);
  });
});
