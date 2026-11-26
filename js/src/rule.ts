// Rules, categories, severities and contexts.

/** A kind of malicious content. Reports carry it, never the value. */
export type RuleID =
  | "tag_dangerous"
  | "tag_generic"
  | "event_handler"
  | "scheme"
  | "template"
  | "js_call"
  | "js_breakout"
  | "sql_injection"
  | "nosql_operator"
  | "path_traversal"
  | "header_crlf"
  | "command"
  | "control_char"
  | "bidi_control"
  | "invisible_char"
  | "invalid_utf8"
  | "mixed_scripts"
  | "too_complex"
  | "proto_pollution"
  | "duplicate_key"
  | "key_operator"
  | "key_invalid"
  | "formula_injection"
  | "ssrf"
  | "open_redirect";

export type Category = "xss" | "template" | "injection" | "unicode" | "structure" | "output";

export type Severity = "low" | "medium" | "high" | "critical";

/** Profiles choose the rules on by default. "opt-in" marks rules no profile enables. */
export type Profile = "balanced" | "strict";

export interface RuleInfo {
  id: RuleID;
  category: Category;
  severity: Severity;
  /** The least strict profile that enables the rule by default. */
  profile: Profile | "opt-in";
  /** A one-line description safe to show to an API client. */
  summary: string;
}

/** What a field is used for: it decides which rules apply and how a value is cleaned. */
export type Context = "text" | "url" | "identifier" | "secret" | "path" | "header" | "redirect" | "skip";

// Internal numbering, as in Go (iota order).
export const CTX_TEXT = 0;
export const CTX_URL = 1;
export const CTX_IDENTIFIER = 2;
export const CTX_SECRET = 3;
export const CTX_PATH = 4;
export const CTX_HEADER = 5;
export const CTX_REDIRECT = 6;
export const CTX_SKIP = 7;
export const CTX_COUNT = 8;

export const CONTEXT_NAMES: readonly Context[] = ["text", "url", "identifier", "secret", "path", "header", "redirect", "skip"];

export function ctxNumber(c: Context): number {
  const n = CONTEXT_NAMES.indexOf(c);
  if (n < 0) throw new Error(`inputguard: unknown context ${JSON.stringify(c)}`);
  return n;
}

export function isURLCtx(c: number): boolean {
  return c === CTX_URL || c === CTX_REDIRECT;
}

/** A set of contexts as a bit mask. */
export function maskOf(...cs: number[]): number {
  let m = 0;
  for (const c of cs) m |= 1 << c;
  return m;
}

export function maskHas(m: number, c: number): boolean {
  return (m & (1 << c)) !== 0;
}

export const SEVERITY_LEVEL: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

const P_BAL = "balanced";
const P_STRICT = "strict";
const P_OPT = "opt-in";

function r(id: RuleID, category: Category, severity: Severity, profile: RuleInfo["profile"], summary: string): RuleInfo {
  return { id, category, severity, profile, summary };
}

/** The rules, in the order of the Go rule table (findings and rule numbers follow it). */
export const RULE_TABLE: readonly RuleInfo[] = [
  r("tag_dangerous", "xss", "critical", P_BAL, "HTML tag that runs script"),
  r("tag_generic", "xss", "high", P_BAL, "HTML markup"),
  r("event_handler", "xss", "critical", P_BAL, "HTML event handler attribute"),
  r("scheme", "xss", "critical", P_BAL, "script URL scheme"),
  r("template", "template", "high", P_STRICT, "template expression"),
  r("js_call", "template", "high", P_STRICT, "JavaScript call"),
  r("js_breakout", "template", "high", P_STRICT, "JavaScript string breakout"),

  r("sql_injection", "injection", "high", P_STRICT, "SQL injection"),
  r("nosql_operator", "injection", "high", P_STRICT, "NoSQL query operator"),
  r("path_traversal", "injection", "high", P_BAL, "path traversal"),
  r("header_crlf", "injection", "high", P_STRICT, "line break in a header value"),
  r("command", "injection", "high", P_STRICT, "shell command injection"),

  r("control_char", "unicode", "medium", P_BAL, "control character"),
  r("bidi_control", "unicode", "high", P_BAL, "bidirectional text override"),
  r("invisible_char", "unicode", "low", P_STRICT, "invisible character"),
  r("invalid_utf8", "unicode", "medium", P_BAL, "invalid UTF-8"),
  r("mixed_scripts", "unicode", "medium", P_STRICT, "identifier mixing look-alike scripts"),

  r("too_complex", "structure", "medium", P_BAL, "document too deep or too large"),
  r("proto_pollution", "structure", "critical", P_BAL, "prototype pollution key"),
  r("duplicate_key", "structure", "medium", P_STRICT, "duplicate key"),
  r("key_operator", "structure", "high", P_OPT, "operator key"),
  r("key_invalid", "structure", "medium", P_OPT, "invalid key"),

  r("formula_injection", "output", "medium", P_STRICT, "spreadsheet formula"),
  r("ssrf", "output", "high", P_STRICT, "URL to an internal address"),
  r("open_redirect", "output", "medium", P_STRICT, "redirect to a foreign host"),
];

const RULE_INDEX = new Map<string, RuleInfo>(RULE_TABLE.map((info) => [info.id, info]));

/** rules lists every rule, in a stable order. */
export function rules(): RuleInfo[] {
  return RULE_TABLE.map((info) => ({ ...info }));
}

/** lookupRule returns a rule's description. */
export function lookupRule(id: string): RuleInfo | undefined {
  const info = RULE_INDEX.get(id);
  return info === undefined ? undefined : { ...info };
}

export function knownRule(id: string): id is RuleID {
  return RULE_INDEX.has(id);
}

export function ruleNumber(id: RuleID): number {
  return RULE_TABLE.findIndex((info) => info.id === id);
}

export const URL_CONTEXTS = maskOf(CTX_URL, CTX_REDIRECT);
