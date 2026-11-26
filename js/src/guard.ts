// The public Guard. Values cross the boundary as JavaScript strings; the engine works on their UTF-8 bytes.

import { fromBytes, toBytes } from "./bytes.js";
import type { DetectorDef } from "./detector.js";
import type { Action, GuardOptions, HostRulesFactory, Mode } from "./engine.js";
import { cloneValue, Engine, Walker } from "./engine.js";
import type { Report } from "./finding.js";
import type { Context, Profile, RuleID } from "./rule.js";
import { ctxNumber } from "./rule.js";

export interface Processed<T> {
  /** The value to use: the input when nothing was cleaned or when the report is rejected. */
  value: T;
  report: Report;
}

export class GuardBase {
  readonly #e: Engine;

  protected constructor(detectors: readonly DetectorDef[], options?: GuardOptions, hosts: HostRulesFactory | null = null) {
    this.#e = new Engine(detectors, options, hosts);
  }

  get mode(): Mode {
    return this.#e.mode;
  }

  get profile(): Profile {
    return this.#e.profile;
  }

  /** enabled reports whether a rule is on. */
  enabled(rule: RuleID): boolean {
    return this.#e.ruleOn(rule);
  }

  /** actionFor returns the effective action of a rule. */
  actionFor(rule: RuleID): Action {
    return this.#e.actionFor(rule);
  }

  /** processString inspects one value in a context and applies the configured actions. */
  processString(s: string, context: Context = "text"): Processed<string> {
    const b = toBytes(s);
    const [out, report] = this.#e.processBytes(b, ctxNumber(context));
    return { value: out === b ? s : fromBytes(out), report };
  }

  /** checkString reports what processString would find. */
  checkString(s: string, context: Context = "text"): Report {
    return this.processString(s, context).report;
  }

  /** processField is processString with the context the classifier picks from the field name. */
  processField(key: string, s: string): Processed<string> {
    const b = toBytes(s);
    const [out, report] = this.#e.processBytes(b, this.#e.classifyKey(toBytes(key), b));
    return { value: out === b ? s : fromBytes(out), report };
  }

  /** mightBeDirty is the fast path: false means processString returns s unchanged with an empty report. */
  mightBeDirty(s: string): boolean {
    return this.#e.maybeDirtyAny(toBytes(s));
  }

  /**
   * processValue inspects a JSON-like value: plain objects, arrays and strings, nested in any combination (other
   * values are left alone). The input is never modified: when something is cleaned, the result is a copy. When the
   * report is rejected, the value is returned unchanged.
   */
  processValue<T>(v: T): Processed<T> {
    const dry = new Walker(this.#e, true);
    dry.walk(v, "", 0);
    if (dry.rep.report.rejected || !dry.changed) return { value: v, report: dry.finish(false) };
    const copy = cloneValue(v);
    const w = new Walker(this.#e, false);
    const [nv, replaced] = w.walk(copy, "", 0);
    return { value: (replaced ? nv : copy) as T, report: w.finish(w.changed) };
  }
}
