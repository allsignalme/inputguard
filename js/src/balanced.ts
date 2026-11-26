// @allsignalme/inputguard/balanced: the rules of the balanced profile only (tags, event handlers, script schemes,
// path traversal, control / bidi / invisible characters, invalid UTF-8, prototype pollution, limits). Same results
// as the full build for a balanced guard, in a smaller bundle. Asking for a strict rule throws.

import type { DetectorDef } from "./detector.js";
import { traversalDetector } from "./det_traversal.js";
import { unicodeDetector } from "./det_unicode.js";
import { xssDetector } from "./det_xss.js";
import type { GuardOptions } from "./engine.js";
import { GuardBase } from "./guard.js";

const BALANCED_DETECTORS: readonly DetectorDef[] = [traversalDetector, unicodeDetector, xssDetector];

/** Guard with the balanced rules only. With no options it cleans with the balanced profile. */
export class Guard extends GuardBase {
  constructor(options?: GuardOptions) {
    super(BALANCED_DETECTORS, options);
  }
}

export type { Action, GuardOptions, Limits, Mode } from "./engine.js";
export type { Processed } from "./guard.js";
export type { Classifier, KeyTable } from "./context.js";
export { defaultKeyTable } from "./context.js";
export type { Finding, FindingAction, Report } from "./finding.js";
export { isClean, RejectedError, rejectedError, reportRules } from "./finding.js";
export type { Category, Context, Profile, RuleID, RuleInfo, Severity } from "./rule.js";
export { lookupRule, rules } from "./rule.js";
