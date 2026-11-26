// Findings and reports.

import type { Category, Context, RuleID, Severity } from "./rule.js";
import { RULE_TABLE } from "./rule.js";

/** What happened to a finding. */
export type FindingAction = "clean" | "reject" | "report";

/**
 * One rule matching one field. It never contains the value: values can be personal data or the payload itself.
 */
export interface Finding {
  rule: RuleID;
  category: Category;
  severity: Severity;
  /**
   * Locates the field: "items[0].title". A finding on a key name ends with "[key]"; a key that is unsafe to print
   * (not 1–64 bytes of [A-Za-z0-9_-]) is printed as "[key]" too. Empty for a bare string.
   */
  path: string;
  context: Context;
  action: FindingAction;
  /** Byte offset (UTF-8) in the decoded value where the malicious part starts, -1 when not applicable. */
  offset: number;
}

/** The outcome of inspecting one value. */
export interface Report {
  findings: Finding[];
  /** The output differs from the input. */
  changed: boolean;
  /** At least one finding has the action "reject"; the output is the input, unchanged. */
  rejected: boolean;
  /** More findings than limits.maxFindings occurred; only the first ones are kept. */
  truncated: boolean;
  /** A structural limit was hit (see the too_complex rule). */
  limitExceeded: boolean;
}

export function emptyReport(): Report {
  return { findings: [], changed: false, rejected: false, truncated: false, limitExceeded: false };
}

/** isClean: nothing was found. */
export function isClean(r: Report): boolean {
  return r.findings.length === 0 && !r.rejected && !r.limitExceeded;
}

/** reportRules returns the distinct rules found, in order of first appearance. */
export function reportRules(r: Report): RuleID[] {
  const out: RuleID[] = [];
  for (const f of r.findings) if (!out.includes(f.rule)) out.push(f.rule);
  return out;
}

/** RejectedError lists the rejected rules and paths, never values: its message can go back to an API client. */
export class RejectedError extends Error {
  readonly report: Report;

  constructor(report: Report) {
    let msg = "input rejected";
    let first = true;
    for (const f of report.findings) {
      if (f.action !== "reject") continue;
      msg += first ? ": " : "; ";
      first = false;
      if (f.path !== "") msg += f.path + ": ";
      msg += RULE_TABLE.find((r) => r.id === f.rule)?.summary ?? f.rule;
    }
    if (first && report.limitExceeded) msg += ": " + (RULE_TABLE.find((r) => r.id === "too_complex")?.summary ?? "");
    super(msg);
    this.name = "RejectedError";
    this.report = report;
  }
}

/** rejectedError returns a RejectedError when the report is rejected, else null. */
export function rejectedError(r: Report): RejectedError | null {
  return r.rejected ? new RejectedError(r) : null;
}

/** One step of a path: an object key (index -1) or an array index. Keys are byte strings internally. */
export interface PathSeg {
  key: string;
  index: number;
}

export const KEY_PATH_MARKER = "[key]";
const MAX_PATH_KEY_LEN = 64;

/** safePathKey: 1–64 bytes of [A-Za-z0-9_-]. Enough for any API field name, unable to carry a payload. */
export function safePathKey(k: string): boolean {
  if (k === "" || k.length > MAX_PATH_KEY_LEN) return false;
  for (let i = 0; i < k.length; i++) {
    const c = k.charCodeAt(i);
    const ok = (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) || (c >= 0x30 && c <= 0x39) || c === 0x5f || c === 0x2d;
    if (!ok) return false;
  }
  return true;
}

export function formatPath(segs: readonly PathSeg[]): string {
  let out = "";
  segs.forEach((s, i) => {
    if (s.index >= 0) {
      out += "[" + s.index + "]";
      return;
    }
    if (!safePathKey(s.key)) {
      out += KEY_PATH_MARKER;
      return;
    }
    if (i > 0) out += ".";
    out += s.key;
  });
  return out;
}

/** sortFindings orders findings by path, stably (byte order, as in Go). */
export function sortFindings(fs: Finding[]): void {
  fs.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}
