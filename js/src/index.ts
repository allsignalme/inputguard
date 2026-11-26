// @allsignalme/inputguard: every rule. For a smaller bundle with the balanced rules only, import
// "@allsignalme/inputguard/balanced".

import { ALL_DETECTORS } from "./detectors.js";
import type { GuardOptions } from "./engine.js";
import { GuardBase } from "./guard.js";
import { hostRules } from "./hosts.js";

/**
 * Guard inspects and cleans input. Build it once and share it: it is immutable. With no options it cleans
 * (mode "clean") with the balanced profile.
 */
export class Guard extends GuardBase {
  constructor(options?: GuardOptions) {
    super(ALL_DETECTORS, options, hostRules);
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
