// The engine: configuration (guard.go, options.go), detection (detector.go), cleaning (process.go, clean_url.go)
// and the value walker (value.go). It works on byte strings; guard.ts converts at the API boundary.

import {
  asciiLower,
  decodeRune,
  fromBytes,
  indexAny,
  mapRunes,
  toBytes,
  trimLeftRunes,
  trimRightRunes,
} from "./bytes.js";
import type { ByteClassifier, Classifier, KeyTable } from "./context.js";
import { compileKeyTable, defaultClassifier, defaultKeyTable } from "./context.js";
import type { DetectorDef, DetectorEnv, IPAddr } from "./detector.js";
import { CLEAN_CHARS, CLEAN_CUT, CLEAN_EMPTY, CLEAN_PREFIX, Input } from "./detector.js";
import { isNoSQLOperatorKey } from "./det_injection_keys.js";
import { stripUnicodeIssues, UNI_BIDI, UNI_CONTROL, UNI_INVALID, UNI_INVISIBLE } from "./det_unicode.js";
import type { Finding, PathSeg, Report } from "./finding.js";
import { emptyReport, formatPath, KEY_PATH_MARKER, sortFindings } from "./finding.js";
import { normalize } from "./norm.js";
import type { Pattern } from "./path.js";
import { compilePattern, matchAny, matchPattern } from "./path.js";
import { fastValue } from "./prefilter.js";
import type { Category, Context, Profile, RuleID, Severity } from "./rule.js";
import {
  CONTEXT_NAMES,
  CTX_COUNT,
  CTX_IDENTIFIER,
  CTX_SECRET,
  CTX_SKIP,
  CTX_TEXT,
  ctxNumber,
  isURLCtx,
  knownRule,
  maskHas,
  maskOf,
  RULE_TABLE,
} from "./rule.js";
import { cut, splitAuthority, splitScheme } from "./url.js";

/** What happens to a finding. "default" follows the mode. */
export type Action = "default" | "clean" | "reject" | "report" | "ignore";

export type Mode = "clean" | "reject";

/** Structural limits. 0 or absent: the default; a negative value: no limit. */
export interface Limits {
  /** Nesting of objects and arrays (default 32). */
  maxDepth?: number;
  /** String values per document (default 20 000). */
  maxStrings?: number;
  /** Bytes (UTF-8) in one string (default 1 MiB). */
  maxStringBytes?: number;
  /** Findings kept in a report (default 100). */
  maxFindings?: number;
  /**
   * Past a limit: "default" prunes in clean mode (the branch becomes null, a suspicious over-limit string becomes
   * "") and rejects in reject mode; "reject" rejects in both; "report" keeps the value and only reports.
   */
  onExceed?: Action;
}

export interface GuardOptions {
  /** "clean" (default) cleans and lets data through; "reject" changes nothing and marks the report rejected. */
  mode?: Mode;
  /** Default rule set: "balanced" for clean mode, "strict" for reject mode. */
  profile?: Profile;
  /** Turn every rule of these categories on. Applied first. */
  categories?: Category[];
  /** Turn rules on regardless of the profile. */
  rules?: RuleID[];
  /** Turn rules off regardless of the profile (after categories and rules). */
  withoutRules?: RuleID[];
  /** Action per rule; it also turns the rule on unless set off above or the action is "ignore". */
  actions?: Partial<Record<RuleID, Action>>;
  /** Action per severity (a per-rule action wins). */
  severityActions?: Partial<Record<Severity, Action>>;
  /** Replace the key table of the default classifier (see defaultKeyTable). */
  keyTable?: KeyTable;
  /** Add or override exact keys of the key table: { url: ["dl"] }. */
  keyContexts?: Partial<Record<Context, string[]>>;
  /** Replace the classifier entirely (field contexts still take precedence). */
  classifier?: Classifier;
  /** Force the context of fields matching a pattern: ["items[*].url", "url"]. First match wins. */
  fieldContexts?: Array<[pattern: string, context: Context]>;
  /** Skip the content of fields matching these patterns (key names are still checked). */
  exempt?: string[];
  limits?: Limits;
  /** Hosts a redirect URL may point to ("example.com" and subdomains; "=example.com" exactly). Turns open_redirect on. */
  redirectHosts?: string[];
  /** Hosts or CIDR ranges the ssrf rule must not flag. */
  ssrfAllow?: string[];
  /** Contexts the formula rule applies to (default: text). */
  formulaContexts?: Context[];
  /** Called with every report that has findings. */
  observer?: (r: Report) => void;
}

// Actions, numbered as in Go.
const A_DEFAULT = 0;
const A_CLEAN = 1;
const A_REJECT = 2;
const A_REPORT = 3;
const A_IGNORE = 4;
const ACTION_NAMES: Action[] = ["default", "clean", "reject", "report", "ignore"];

function actionNumber(a: Action): number {
  const n = ACTION_NAMES.indexOf(a);
  if (n < 0) throw new Error(`inputguard: unknown action ${JSON.stringify(a)}`);
  return n;
}

const PROFILE_RANK: Record<string, number> = { balanced: 1, strict: 2, "opt-in": 255 };

// Rules no detector reports: the walker checks them (too_complex, proto_pollution, key_operator, key_invalid) or the
// port does not have them (duplicate_key needs the raw JSON text).
const STRUCTURAL: ReadonlySet<RuleID> = new Set<RuleID>(["too_complex", "proto_pollution", "duplicate_key", "key_operator", "key_invalid"]);

const MAX_CLEAN_PASSES = 3;
const MAX_KEEP_RAW = 64 << 10;
const MAX_ESCAPE_LEN = 12;
const NO_LIMIT = Number.MAX_SAFE_INTEGER;

interface Hit {
  rule: number;
  offset: number;
  clean: number;
}

interface ActiveDetector {
  def: DetectorDef;
}

/** The host lists of the URL rules (strict profile), built by hosts.ts in the full build. */
export interface HostRules {
  allowsRedirectHost(host: string): boolean;
  allowsSSRFHost(host: string): boolean;
  allowsSSRFAddr(addr: IPAddr): boolean;
}

export type HostRulesFactory = (redirectHosts: readonly string[], ssrfAllow: readonly string[]) => HostRules;

const NO_HOSTS: HostRules = {
  allowsRedirectHost: () => false,
  allowsSSRFHost: () => false,
  allowsSSRFAddr: () => false,
};

function pick(v: number | undefined, def: number): number {
  if (v === undefined || v === 0) return def;
  return v < 0 ? NO_LIMIT : v;
}

export class Engine implements DetectorEnv {
  readonly mode: Mode;
  readonly profile: Profile;
  readonly strictProfile: boolean;
  readonly formulaOn: number;
  private readonly on: boolean[];
  private readonly action: number[];
  private readonly ruleNum = new Map<RuleID, number>();
  private readonly classify: ByteClassifier;
  private readonly fieldCtx: Array<[Pattern, number]> = [];
  readonly exempt: Pattern[] = [];
  readonly maxDepth: number;
  readonly maxStrings: number;
  readonly maxStringBytes: number;
  readonly maxFindings: number;
  readonly limitAct: number;
  private readonly hosts: HostRules;
  private readonly detectors: ActiveDetector[] = [];
  private readonly valueBits: number[] = new Array<number>(CTX_COUNT).fill(0);
  private anyBits = 0;
  private readonly slow: ActiveDetector[][] = Array.from({ length: CTX_COUNT }, () => []);
  private readonly slowAny: ActiveDetector[] = [];
  private readonly invalidOn: boolean;
  readonly protoKeys: boolean;
  readonly nosqlKeys: boolean;
  readonly mongoOperator: boolean;
  readonly mongoInvalid: boolean;
  readonly observer: ((r: Report) => void) | undefined;

  constructor(builtins: readonly DetectorDef[], opts: GuardOptions = {}, hostRules: HostRulesFactory | null = null) {
    const enable = new Map<RuleID, boolean>();
    const actions = new Map<RuleID, number>();
    const sevActions = new Map<Severity, number>();
    const checkRule = (id: string): RuleID => {
      if (!knownRule(id)) throw new Error(`inputguard: unknown rule ${JSON.stringify(id)}`);
      return id;
    };

    const mode: Mode = opts.mode ?? "clean";
    if (mode !== "clean" && mode !== "reject") throw new Error(`inputguard: unknown mode ${JSON.stringify(mode)}`);
    if (opts.profile !== undefined && opts.profile !== "balanced" && opts.profile !== "strict") {
      throw new Error(`inputguard: unknown profile ${JSON.stringify(opts.profile)}`);
    }
    for (const cat of opts.categories ?? []) {
      let found = false;
      for (const info of RULE_TABLE) {
        if (info.category === cat) {
          enable.set(info.id, true);
          found = true;
        }
      }
      if (!found) throw new Error(`inputguard: unknown category ${JSON.stringify(cat)}`);
    }
    for (const id of opts.rules ?? []) enable.set(checkRule(id), true);
    for (const id of opts.withoutRules ?? []) enable.set(checkRule(id), false);
    for (const [id, a] of Object.entries(opts.actions ?? {})) {
      const rule = checkRule(id);
      const n = actionNumber(a as Action);
      actions.set(rule, n);
      if (n !== A_IGNORE && !enable.has(rule)) enable.set(rule, true);
    }
    for (const [sev, a] of Object.entries(opts.severityActions ?? {})) {
      if (!["low", "medium", "high", "critical"].includes(sev)) throw new Error(`inputguard: unknown severity ${JSON.stringify(sev)}`);
      sevActions.set(sev as Severity, actionNumber(a as Action));
    }
    if (opts.redirectHosts !== undefined && !enable.has("open_redirect")) enable.set("open_redirect", true);

    this.mode = mode;
    this.profile = opts.profile ?? (mode === "reject" ? "strict" : "balanced");
    this.strictProfile = this.profile === "strict";
    const def = mode === "reject" ? A_REJECT : A_CLEAN;
    this.on = [];
    this.action = [];
    RULE_TABLE.forEach((info, i) => {
      this.ruleNum.set(info.id, i);
      let on = PROFILE_RANK[info.profile] <= PROFILE_RANK[this.profile];
      const e = enable.get(info.id);
      if (e !== undefined) on = e;
      let a = actions.get(info.id) ?? sevActions.get(info.severity) ?? A_DEFAULT;
      if (a === A_IGNORE) on = false;
      if (a === A_DEFAULT) a = def;
      this.on.push(on);
      this.action.push(a);
    });

    // A rule on whose detector this build does not ship cannot be honoured.
    const shipped = new Set<RuleID>();
    for (const d of builtins) for (const id of d.rules) shipped.add(id);
    RULE_TABLE.forEach((info, i) => {
      if (this.on[i] && !STRUCTURAL.has(info.id) && !shipped.has(info.id)) {
        throw new Error(
          `inputguard: rule ${info.id} is not in this build; import "@allsignalme/inputguard" instead of the balanced entry`,
        );
      }
    });

    if (opts.classifier !== undefined) {
      const custom = opts.classifier;
      this.classify = (k, v) => ctxNumber(custom(fromBytes(k), fromBytes(v)));
    } else if (opts.keyTable !== undefined || opts.keyContexts !== undefined) {
      const t = opts.keyTable ?? defaultKeyTable();
      const table: KeyTable = { exact: { ...t.exact }, suffix: { ...t.suffix }, contains: { ...t.contains } };
      for (const [ctx, keys] of Object.entries(opts.keyContexts ?? {})) {
        ctxNumber(ctx as Context);
        for (const k of keys ?? []) table.exact[k.toLowerCase()] = ctx as Context;
      }
      this.classify = compileKeyTable(table);
    } else {
      this.classify = defaultClassifier();
    }
    for (const [p, ctx] of opts.fieldContexts ?? []) this.fieldCtx.push([compilePattern(p), ctxNumber(ctx)]);
    for (const p of opts.exempt ?? []) this.exempt.push(compilePattern(p));

    const l = opts.limits ?? {};
    this.maxDepth = pick(l.maxDepth, 32);
    this.maxStrings = pick(l.maxStrings, 20000);
    this.maxStringBytes = pick(l.maxStringBytes, 1 << 20);
    this.maxFindings = pick(l.maxFindings, 100);
    const onExceed = actionNumber(l.onExceed ?? "default");
    this.limitAct = onExceed === A_CLEAN || onExceed === A_REJECT || onExceed === A_REPORT ? onExceed : def;

    if (hostRules === null && ((opts.redirectHosts ?? []).length > 0 || (opts.ssrfAllow ?? []).length > 0)) {
      throw new Error("inputguard: redirectHosts and ssrfAllow are not in this build");
    }
    this.hosts = hostRules === null ? NO_HOSTS : hostRules(opts.redirectHosts ?? [], opts.ssrfAllow ?? []);
    this.formulaOn = opts.formulaContexts !== undefined && opts.formulaContexts.length > 0
      ? maskOf(...opts.formulaContexts.map(ctxNumber))
      : maskOf(CTX_TEXT);
    this.observer = opts.observer;

    for (const d of builtins) {
      if (d.rules.some((id) => this.ruleOn(id))) this.detectors.push({ def: d });
    }
    this.protoKeys = this.ruleOn("proto_pollution");
    this.nosqlKeys = this.ruleOn("nosql_operator");
    this.mongoOperator = this.ruleOn("key_operator");
    this.mongoInvalid = this.ruleOn("key_invalid");
    for (const ad of this.detectors) {
      const bits = ad.def.fast;
      for (let c = 0; c < CTX_COUNT; c++) {
        if (!maskHas(ad.def.contexts, c)) continue;
        if (bits !== 0) this.valueBits[c] |= bits;
        else this.slow[c].push(ad);
      }
      if (bits !== 0) this.anyBits |= bits;
      else this.slowAny.push(ad);
    }
    this.invalidOn = this.ruleOn("invalid_utf8");
  }

  ruleOn(id: RuleID): boolean {
    const n = this.ruleNum.get(id);
    return n !== undefined && this.on[n];
  }

  actionFor(id: RuleID): Action {
    const n = this.ruleNum.get(id);
    return n === undefined ? "ignore" : ACTION_NAMES[this.action[n]];
  }

  // --- DetectorEnv ---

  allowsRedirectHost(host: string): boolean {
    return this.hosts.allowsRedirectHost(host);
  }

  allowsSSRFHost(host: string): boolean {
    return this.hosts.allowsSSRFHost(host);
  }

  allowsSSRFAddr(addr: IPAddr): boolean {
    return this.hosts.allowsSSRFAddr(addr);
  }

  // --- fast path ---

  maybeDirtyValue(raw: string, ctx: number): boolean {
    if (fastValue(raw, this.valueBits[ctx], this.invalidOn)) return true;
    for (const ad of this.slow[ctx]) if (ad.def.mayMatch === undefined || ad.def.mayMatch(raw)) return true;
    return false;
  }

  maybeDirtyAny(s: string): boolean {
    if (fastValue(s, this.anyBits, this.invalidOn)) return true;
    for (const ad of this.slowAny) if (ad.def.mayMatch === undefined || ad.def.mayMatch(s)) return true;
    return false;
  }

  // --- detection ---

  private detect(input: Input): Hit[] {
    const hits: Hit[] = [];
    for (const ad of this.detectors) {
      const d = ad.def;
      if (!maskHas(d.contexts, input.ctx)) continue;
      if (d.fast !== 0) {
        if (!fastValue(input.raw, d.fast, this.invalidOn)) continue;
      } else if (d.mayMatch !== undefined && !d.mayMatch(input.raw)) {
        continue;
      }
      d.detect(this, input, (id, off) => {
        const n = this.ruleNum.get(id);
        if (n === undefined || !this.on[n]) return;
        appendHit(hits, { rule: n, offset: off, clean: d.clean });
      });
    }
    return hits;
  }

  classifyKey(key: string, value: string): number {
    return this.classify(key, value);
  }

  contextFor(segs: readonly PathSeg[], key: string, value: string): number {
    for (const [p, ctx] of this.fieldCtx) if (matchPattern(p, segs)) return ctx;
    return this.classify(key, value);
  }

  private effectiveContext(ctx: number): number {
    if (ctx === CTX_SECRET) return this.mode === "reject" ? CTX_SKIP : CTX_IDENTIFIER;
    return ctx;
  }

  /** processBytes is Guard.ProcessString on a byte string. */
  processBytes(s: string, ctx: number): [string, Report] {
    const rep = new Reporter(this);
    let out = s;
    if (s.length > this.maxStringBytes) {
      if (rep.limitHit() && this.limitAct === A_CLEAN && this.maybeDirtyAny(s)) out = "";
    } else {
      const [ns, changed] = this.processString(s, ctx, "", rep, false);
      if (changed) out = ns;
    }
    const r = rep.report;
    if (r.rejected) out = s;
    r.changed = out !== s;
    if (this.observer !== undefined && (r.findings.length > 0 || r.limitExceeded)) this.observer(r);
    return [out, r];
  }

  /** processString inspects one value, records findings in rep and returns the value to use and whether it changed. */
  processString(s: string, ctx: number, key: string, rep: Reporter | null, onKey: boolean): [string, boolean] {
    ctx = this.effectiveContext(ctx);
    if (ctx === CTX_SKIP || !this.maybeDirtyValue(s, ctx)) return [s, false];
    const input = new Input(s, ctx, key);
    const hits = this.detect(input);
    if (hits.length === 0) return [s, false];
    let needClean = false;
    let rejected = false;
    for (const h of hits) {
      const a = this.action[h.rule];
      if (rep !== null) rep.add(h.rule, ctx, a, h.offset, onKey);
      if (a === A_REJECT) rejected = true;
      else if (a === A_CLEAN) needClean = true;
    }
    if (rejected || !needClean) return [s, false];
    const out = this.cleanValue(input, hits);
    return [out, out !== s];
  }

  // --- cleaning ---

  private cleanValue(input: Input, hits: Hit[]): string {
    if (input.ctx === CTX_IDENTIFIER && !this.onlyCharacterHits(hits)) return "";
    let s = input.raw;
    const drop = [false, false, false, false, false];
    let charLevel = false;
    let cutHit = false;
    let prefix = false;
    let empty = false;
    for (const h of hits) {
      if (this.action[h.rule] !== A_CLEAN) continue;
      switch (h.clean) {
        case CLEAN_CHARS:
          charLevel = true;
          switch (RULE_TABLE[h.rule].id) {
            case "control_char":
              drop[UNI_CONTROL] = true;
              break;
            case "bidi_control":
              drop[UNI_BIDI] = true;
              break;
            case "invisible_char":
              drop[UNI_INVISIBLE] = true;
              break;
            case "invalid_utf8":
              drop[UNI_INVALID] = true;
              break;
          }
          break;
        case CLEAN_CUT:
          cutHit = true;
          break;
        case CLEAN_PREFIX:
          prefix = true;
          break;
        case CLEAN_EMPTY:
          empty = true;
          break;
      }
    }
    if (empty) return "";
    if (charLevel) {
      s = stripUnicodeIssues(s, drop);
      if (this.hasCleanHit(hits, "header_crlf")) s = stripCRLF(s);
    }
    if (cutHit) {
      let out = "";
      let ok = false;
      if (isURLCtx(input.ctx)) [out, ok] = this.cleanURL(s, input.ctx);
      if (!ok) out = this.keepRaw(s, this.cleanText(s, input.ctx, input.key), input.ctx, input.key);
      s = out;
    }
    if (prefix && s !== "") s = "'" + s;
    // The result must itself be clean for every rule being cleaned; otherwise give up on the value.
    if (s !== "" && this.cleanDirty(s, input.ctx, input.key)) return "";
    return s;
  }

  private onlyCharacterHits(hits: Hit[]): boolean {
    for (const h of hits) if (this.action[h.rule] === A_CLEAN && h.clean !== CLEAN_CHARS) return false;
    return true;
  }

  private hasCleanHit(hits: Hit[], id: RuleID): boolean {
    const n = this.ruleNum.get(id);
    return hits.some((h) => h.rule === n && this.action[h.rule] === A_CLEAN);
  }

  /** cleanDirty: does any rule whose action is "clean" still match s? */
  cleanDirty(s: string, ctx: number, key: string): boolean {
    if (!this.maybeDirtyValue(s, ctx)) return false;
    for (const h of this.detect(new Input(s, ctx, key))) if (this.action[h.rule] === A_CLEAN) return true;
    return false;
  }

  // cutScan: the decoded value and the earliest offset of a cut-type finding being cleaned (-1 if none).
  private cutScan(s: string, ctx: number, key: string): [string, number] {
    if (!this.maybeDirtyValue(s, ctx)) return [s, -1];
    const input = new Input(s, ctx, key);
    let first = -1;
    for (const h of this.detect(input)) {
      if (h.clean !== CLEAN_CUT || this.action[h.rule] !== A_CLEAN) continue;
      const off = h.offset < 0 ? 0 : h.offset;
      if (first < 0 || off < first) first = off;
    }
    if (first < 0) return input.done ? [input.decoded(), -1] : [s, -1];
    return [input.decoded(), first];
  }

  // cleanText cuts at the earliest finding, trims characters used to break out, and checks again. The kept part is
  // returned decoded.
  private cleanText(s: string, ctx: number, key: string): string {
    let [dec, idx] = this.cutScan(s, ctx, key);
    for (let pass = 0; pass < MAX_CLEAN_PASSES; pass++) {
      if (idx < 0) return dec;
      [dec, idx] = this.cutScan(trimRightRunes(dec.slice(0, idx), isBreakoutTail), ctx, key);
    }
    return idx >= 0 ? "" : dec;
  }

  // keepRaw: when the raw value starts with a prefix that decodes to exactly the kept part, return that raw prefix,
  // so an untouched part keeps its own spelling ("Tom &amp; Jerry"). Found by bisection over the decoded length.
  private keepRaw(raw: string, kept: string, ctx: number, key: string): string {
    if (kept === "" || raw.startsWith(kept) || raw.length > MAX_KEEP_RAW) return kept;
    const cuts: number[] = [];
    for (let i = 0; i < raw.length; ) {
      cuts.push(i);
      i += decodeRune(raw, i)[1];
    }
    cuts.push(raw.length);
    const prefixAt = (c: number): number => {
      for (let j = c; j < cuts.length && j <= c + MAX_ESCAPE_LEN; j++) {
        if (kept.startsWith(normalize(raw.slice(0, cuts[j])).decoded)) return j;
        if (j > c && !inEscape(raw, cuts[j])) break;
      }
      return -1;
    };
    let lo = 0;
    let hi = cuts.length - 1;
    while (lo < hi) {
      const mid = Math.floor((lo + hi + 1) / 2);
      const j = prefixAt(mid);
      if (j >= 0) {
        lo = Math.max(j, mid);
        if (j > mid && j > hi) break;
      } else {
        hi = mid - 1;
      }
    }
    for (let j = lo; j < cuts.length && j <= lo + MAX_ESCAPE_LEN; j++) {
      const head = raw.slice(0, cuts[j]);
      for (const cand of [head, trimRightRunes(head, isBreakoutTail)]) {
        if (normalize(cand).decoded === kept && !this.cleanDirty(cand, ctx, key)) return cand;
      }
    }
    return kept;
  }

  // cleanURL cleans a value shaped like a URL; ok=false: not URL-shaped, clean it as text. Clean parts are kept
  // verbatim (no re-encoding or reordering of the query).
  private cleanURL(s: string, ctx: number): [string, boolean] {
    const trimmed = trimLeftRunes(s, (r) => r <= 0x20);
    let prefix = "";
    let rest: string;
    const sc = splitScheme(trimmed);
    if (sc !== null) {
      const [scheme, after] = sc;
      const ls = asciiLower(scheme);
      if ((ls !== "http" && ls !== "https") || !after.startsWith("//")) return ["", true];
      const [auth, tail] = splitAuthority(after.slice(2));
      if (!this.cleanHost(auth)) return ["", true];
      prefix = scheme + "://" + auth;
      rest = tail;
    } else if (trimmed.startsWith("//")) {
      const [auth, tail] = splitAuthority(trimmed.slice(2));
      if (!this.cleanHost(auth)) return ["", true];
      prefix = "//" + auth;
      rest = tail;
    } else if (trimmed.startsWith("/")) {
      rest = trimmed;
    } else {
      return ["", false];
    }
    const [beforeFrag, frag, hasFrag] = cut(rest, "#");
    const [path, query, hasQuery] = cut(beforeFrag, "?");
    let out = prefix + this.cleanPath(path);
    if (hasQuery) {
      const q = this.cleanQuery(query);
      if (q !== "") out += "?" + q;
    }
    if (hasFrag && !this.cleanDirty(frag, CTX_TEXT, "")) out += "#" + frag;
    if (this.cleanDirty(out, ctx, "")) return ["", true];
    return [out, true];
  }

  private cleanHost(auth: string): boolean {
    return auth !== "" && indexAny(auth, "<>\"'` \t\n\r\\{}|^") < 0 && !this.cleanDirty(auth, CTX_TEXT, "");
  }

  // cleanPath keeps the longest run of leading path segments that is clean (bisection over the segment count).
  private cleanPath(path: string): string {
    if (!this.cleanDirty(path, CTX_TEXT, "")) return path;
    const ends = [0];
    for (let i = 0; i < path.length; i++) if (path.charCodeAt(i) === 0x2f) ends.push(i + 1);
    if (ends[ends.length - 1] !== path.length) ends.push(path.length);
    let lo = 0;
    let hi = ends.length - 2;
    while (lo < hi) {
      const mid = Math.floor((lo + hi + 1) / 2);
      if (this.cleanDirty(path.slice(0, ends[mid]), CTX_TEXT, "")) hi = mid - 1;
      else lo = mid;
    }
    return path.slice(0, ends[lo]);
  }

  // cleanQuery drops exactly the malicious key=value pairs and keeps the others verbatim and in order.
  private cleanQuery(q: string): string {
    if (!this.cleanDirty(q, CTX_TEXT, "")) return q;
    return q
      .split("&")
      .filter((p) => !this.cleanDirty(p, CTX_TEXT, ""))
      .join("&");
  }

  // --- keys ---

  /** checkKey runs the key-name rules on the key at the top of the path: [drop, new key, renamed]. */
  checkKey(rep: Reporter, key: string): [boolean, string, boolean] {
    let drop = false;
    if (this.protoKeys && (key === "__proto__" || (key === "prototype" && rep.parentKey() === "constructor"))) {
      drop = rep.keyRule("proto_pollution") === A_CLEAN || drop;
    }
    if (this.mongoOperator && key !== "" && key.charCodeAt(0) === 0x24) drop = rep.keyRule("key_operator") === A_CLEAN || drop;
    if (this.nosqlKeys && isNoSQLOperatorKey(key)) drop = rep.keyRule("nosql_operator") === A_CLEAN || drop;
    if (this.mongoInvalid && hasInvalidKeyChar(key)) drop = rep.keyRule("key_invalid") === A_CLEAN || drop;
    if (drop || !this.maybeDirtyAny(key)) return [drop, "", false];
    const input = new Input(key, CTX_TEXT, key);
    const kept: Hit[] = [];
    let clean = false;
    let charOnly = true;
    for (const h of this.detect(input)) {
      if (h.clean === CLEAN_PREFIX) continue; // formula injection concerns cell values, not names
      kept.push(h);
      const a = this.action[h.rule];
      rep.add(h.rule, CTX_TEXT, a, h.offset, true);
      if (a === A_CLEAN) {
        clean = true;
        charOnly = charOnly && h.clean === CLEAN_CHARS;
      }
    }
    if (!clean) return [false, "", false];
    if (!charOnly) return [true, "", false];
    const nk = this.cleanValue(input, kept);
    if (nk === "" || this.badKeyName(rep, nk)) return [true, "", false];
    if (nk === key) return [false, "", false];
    return [false, nk, true];
  }

  private badKeyName(rep: Reporter, k: string): boolean {
    return (
      (this.protoKeys && (k === "__proto__" || (k === "prototype" && rep.parentKey() === "constructor"))) ||
      ((this.mongoOperator || this.nosqlKeys) && k !== "" && k.charCodeAt(0) === 0x24) ||
      (this.mongoInvalid && hasInvalidKeyChar(k)) ||
      (this.nosqlKeys && isNoSQLOperatorKey(k))
    );
  }

  ruleNumber(id: RuleID): number {
    return this.ruleNum.get(id) as number;
  }

  actionNumber(rule: number): number {
    return this.action[rule];
  }

  isRuleOn(rule: number): boolean {
    return this.on[rule];
  }

  exemptMatch(segs: readonly PathSeg[]): boolean {
    return matchAny(this.exempt, segs);
  }
}

// hasInvalidKeyChar: a "." or NUL, which a document store rejects in a key.
function hasInvalidKeyChar(k: string): boolean {
  return k.indexOf(".") >= 0 || k.indexOf(String.fromCharCode(0)) >= 0;
}

function appendHit(hits: Hit[], h: Hit): void {
  for (const x of hits) {
    if (x.rule === h.rule) {
      if (h.offset >= 0 && (x.offset < 0 || h.offset < x.offset)) x.offset = h.offset;
      return;
    }
  }
  hits.push(h);
}

// inEscape: the cut at i falls inside a percent, entity or backslash escape that started shortly before.
function inEscape(s: string, i: number): boolean {
  for (let k = i - 1; k >= 0 && k >= i - MAX_ESCAPE_LEN; k--) {
    switch (s.charCodeAt(k)) {
      case 0x25:
      case 0x26:
      case 0x5c:
        return true;
      case 0x3b:
      case 0x20:
        return false;
    }
  }
  return false;
}

/** isUnicodeSpace is unicode.IsSpace. */
function isUnicodeSpace(r: number): boolean {
  if (r <= 0xff) return r === 0x09 || r === 0x0a || r === 0x0b || r === 0x0c || r === 0x0d || r === 0x20 || r === 0x85 || r === 0xa0;
  return r === 0x1680 || (r >= 0x2000 && r <= 0x200a) || r === 0x2028 || r === 0x2029 || r === 0x202f || r === 0x205f || r === 0x3000;
}

function isBreakoutTail(r: number): boolean {
  switch (r) {
    case 0x20:
    case 0x09:
    case 0x0a:
    case 0x0d:
    case 0x0b:
    case 0x0c:
    case 0x85:
    case 0xa0:
      return true;
  }
  if (r > 0x7f) return isUnicodeSpace(r);
  return "'\"`<>/\\;=(-".indexOf(String.fromCharCode(r)) >= 0;
}

function stripCRLF(s: string): string {
  if (indexAny(s, "\r\n") < 0) return s;
  return mapRunes(s, (r) => (r === 0x0d || r === 0x0a ? -1 : r));
}

/** Reporter collects findings for one document. */
export class Reporter {
  readonly report: Report = emptyReport();
  readonly segs: PathSeg[] = [];
  strCount = 0;
  private limitSeen = false;

  constructor(private readonly e: Engine) {}

  add(rule: number, ctx: number, action: number, offset: number, onKey: boolean): void {
    if (action === A_REJECT) this.report.rejected = true;
    if (this.report.findings.length >= this.e.maxFindings) {
      this.report.truncated = true;
      return;
    }
    const info = RULE_TABLE[rule];
    const path = onKey ? formatPath(this.segs.slice(0, -1)) + KEY_PATH_MARKER : formatPath(this.segs);
    const f: Finding = {
      rule: info.id,
      category: info.category,
      severity: info.severity,
      path,
      context: CONTEXT_NAMES[ctx],
      action: ACTION_NAMES[action] as Finding["action"],
      offset,
    };
    this.report.findings.push(f);
  }

  keyRule(id: RuleID): number {
    const n = this.e.ruleNumber(id);
    const a = this.e.actionNumber(n);
    this.add(n, CTX_TEXT, a, -1, true);
    return a;
  }

  parentKey(): string {
    const s = this.segs;
    return s.length >= 2 && s[s.length - 2].index < 0 ? s[s.length - 2].key : "";
  }

  /** limitHit records that a structural limit was hit; false when the value is rejected. */
  limitHit(): boolean {
    this.report.limitExceeded = true;
    const a = this.e.limitAct;
    if (!this.limitSeen) {
      this.limitSeen = true;
      const n = this.e.ruleNumber("too_complex");
      if (this.e.isRuleOn(n)) this.add(n, CTX_TEXT, a, -1, false);
    }
    if (a === A_REJECT) {
      this.report.rejected = true;
      return false;
    }
    return true;
  }
}

// --- value walker ---

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

function setOwn(o: Record<string, unknown>, k: string, v: unknown): void {
  Object.defineProperty(o, k, { value: v, writable: true, enumerable: true, configurable: true });
}

/**
 * cloneValue copies the plain objects and arrays the walker may change: those less than depth levels deep. Deeper
 * ones are shared (the walker never enters them; it replaces them in their cloned parent), so a value nested
 * thousands of levels deep, or one that contains itself, is copied only down to the depth limit.
 */
export function cloneValue<T>(v: T, depth: number): T {
  if (depth <= 0) return v;
  if (Array.isArray(v)) return v.map((x) => cloneValue(x, depth - 1)) as T;
  if (isPlainObject(v)) {
    const o = Object.create(Object.getPrototypeOf(v)) as Record<string, unknown>;
    for (const k of Object.keys(v)) setOwn(o, k, cloneValue(v[k], depth - 1));
    return o as T;
  }
  return v;
}

function byteOrder(a: [string, string], b: [string, string]): number {
  return a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0;
}

/** Walker is Go's valueWalker over JavaScript values (plain objects, arrays, strings). */
export class Walker {
  readonly rep: Reporter;
  private exemptDepth = 0;
  changed = false;

  constructor(
    private readonly e: Engine,
    private readonly dry: boolean,
  ) {
    this.rep = new Reporter(e);
  }

  finish(changed: boolean): Report {
    const r = this.rep.report;
    r.changed = changed && !r.rejected;
    sortFindings(r.findings);
    if (this.e.observer !== undefined && (r.findings.length > 0 || r.limitExceeded)) this.e.observer(r);
    return r;
  }

  private push(seg: PathSeg): boolean {
    this.rep.segs.push(seg);
    if (this.exemptDepth === 0 && this.e.exempt.length > 0 && this.e.exemptMatch(this.rep.segs)) {
      this.exemptDepth++;
      return true;
    }
    return false;
  }

  private pop(entered: boolean): void {
    if (entered) this.exemptDepth--;
    this.rep.segs.pop();
  }

  private limit(): boolean {
    return this.rep.limitHit() && this.e.limitAct === A_CLEAN;
  }

  /** walk returns the replacement for v and whether v must be replaced in its parent. */
  walk(v: unknown, key: string, depth: number): [unknown, boolean] {
    if (typeof v === "string") return this.str(v, key);
    const arr = Array.isArray(v);
    if (!arr && !isPlainObject(v)) return [v, false];
    if (depth >= this.e.maxDepth) {
      if (this.limit()) {
        this.changed = true;
        return [null, !this.dry];
      }
      return [v, false];
    }
    if (arr) {
      const a = v as unknown[];
      for (let i = 0; i < a.length; i++) {
        const entered = this.push({ key: "", index: i });
        const [nv, replaced] = this.walk(a[i], key, depth + 1);
        this.pop(entered);
        if (replaced) a[i] = nv;
      }
    } else {
      this.walkMap(v as Record<string, unknown>, depth + 1);
    }
    return [v, false];
  }

  private walkMap(m: Record<string, unknown>, depth: number): void {
    const keys = Object.keys(m).map((k): [string, string] => [k, toBytes(k)]);
    keys.sort(byteOrder);
    const changes: Array<[string, string, boolean]> = [];
    for (const [k, kb] of keys) {
      const entered = this.push({ key: kb, index: -1 });
      const [drop, nk, renamed] = this.e.checkKey(this.rep, kb);
      if (!drop) {
        const [nv, replaced] = this.walk(m[k], kb, depth);
        if (replaced) setOwn(m, k, nv);
      }
      this.pop(entered);
      if (drop || renamed) changes.push([k, renamed ? fromBytes(nk) : "", drop]);
    }
    if (changes.length === 0) return;
    this.changed = true;
    if (this.dry) return;
    for (const [oldKey, newKey, drop] of changes) {
      const v = m[oldKey];
      delete m[oldKey];
      if (drop) continue;
      if (!Object.prototype.hasOwnProperty.call(m, newKey)) setOwn(m, newKey, v);
    }
  }

  private str(s: string, key: string): [unknown, boolean] {
    const e = this.e;
    const r = this.rep;
    const b = toBytes(s);
    r.strCount++;
    if (r.strCount > e.maxStrings || b.length > e.maxStringBytes) {
      if (this.limit() && this.exemptDepth === 0 && e.maybeDirtyAny(b)) return this.leaf(s, "");
      return [s, false];
    }
    if (this.exemptDepth > 0) return [s, false];
    if (!e.maybeDirtyAny(b)) return [s, false];
    const [out, changed] = e.processString(b, e.contextFor(r.segs, key, b), key, r, false);
    if (!changed) return [s, false];
    return this.leaf(s, fromBytes(out));
  }

  private leaf(old: string, out: string): [unknown, boolean] {
    this.changed = true;
    if (this.dry) return [old, false];
    return [out, true];
  }
}

