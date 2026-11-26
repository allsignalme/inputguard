// Template injection and JavaScript calls (strict profile). Port of the template group of det_xss.go.

import { containsAny } from "./bytes.js";
import type { DetectorDef, DetectorEnv, Emit, Input } from "./detector.js";
import { ALL_INSPECTED, CLEAN_CUT } from "./detector.js";
import { containsAnyFold, mayBeEncoded } from "./prefilter.js";
import { goRe, matchIndex } from "./regex.js";

const templateRe = goRe("\\{\\{[\\s\\S]*?\\}\\}|\\{%[\\s\\S]*?%\\}|\\$\\{[^}]*\\}|<%[\\s\\S]*?%>");
const jsCallRe = goRe(
  "\\b(?:eval|atob|btoa|settimeout|setinterval|fromcharcode|unescape|decodeuricomponent|execscript)\\s*\\(" +
    "|\\bnew\\s+function\\b|\\bimport\\s*\\(|\\.\\s*(?:inner|outer)html\\b" +
    "|\\b(?:document|window|globalthis)\\s*\\.\\s*(?:cookie|write|writeln|location|domain|open|eval|body|head|" +
    "createelement|getelementbyid|queryselector)",
);
const jsBreakoutRe = goRe("[\"'`]\\s*[-+;,)\\]}|&*/%^]\\s*[a-z_$][\\w$.]*\\s*\\(");

const JS_CALL_NAMES = [
  "eval", "atob", "btoa", "settimeout", "setinterval", "fromcharcode", "unescape", "decodeuricomponent", "execscript",
  "import",
];
const JS_PROP_NAMES = ["function", "html", "document", "window", "globalthis"];

function jsCallGate(f: string, paren: boolean): boolean {
  if (paren) for (const w of JS_CALL_NAMES) if (f.includes(w)) return true;
  for (const w of JS_PROP_NAMES) if (f.includes(w)) return true;
  return false;
}

function detectTemplate(_env: DetectorEnv, input: Input, emit: Emit): void {
  const f = input.folded();
  if (f.includes("{{") || f.includes("{%") || f.includes("${") || f.includes("<%")) {
    const idx = matchIndex(templateRe, f);
    if (idx >= 0) emit("template", idx);
  }
  const paren = f.indexOf("(") >= 0;
  if (jsCallGate(f, paren)) {
    const idx = matchIndex(jsCallRe, f);
    if (idx >= 0) emit("js_call", idx);
  }
  if (paren && containsAny(f, "\"'`")) {
    const idx = matchIndex(jsBreakoutRe, f);
    if (idx >= 0) emit("js_breakout", idx);
  }
}

export const templateDetector: DetectorDef = {
  name: "template",
  rules: ["template", "js_call", "js_breakout"],
  contexts: ALL_INSPECTED,
  fast: 0,
  mayMatch: (raw) => mayBeEncoded(raw) || containsAny(raw, "{<(") || containsAnyFold(raw, JS_PROP_NAMES),
  detect: detectTemplate,
  clean: CLEAN_CUT,
};
