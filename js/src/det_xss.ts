// Cross-site scripting (tags, event handlers, script schemes). Port of
// xss.go and det_xss.go. Everything runs on the folded value (byte string).

import { containsAny, isLowerASCII, isRESpace } from "./bytes.js";
import type { DetectorDef, DetectorEnv, Emit, Input } from "./detector.js";
import { ALL_INSPECTED, CLEAN_CUT } from "./detector.js";
import { FB_XSS } from "./prefilter.js";
import { goRe, matchIndex } from "./regex.js";
import { isURLCtx } from "./rule.js";

// Tags dangerous even without a closing ">". The name must be followed by a space, "/", ">" or the end.
const DANGEROUS_TAGS =
  "script|iframe|frame|frameset|object|embed|applet|svg|math|img|image|style|link|meta|base|" +
  "body|html|head|xml|isindex|portal|noscript|template|xmp|plaintext|noembed|noframes|textarea|title|video|audio|" +
  "source|input|button|form|select|details|dialog|marquee|bgsound|layer|ilayer|keygen";

// Ordinary HTML tags: they count only when closed by ">".
const KNOWN_TAGS =
  "a|abbr|acronym|address|area|article|aside|b|bdi|bdo|big|blink|blockquote|br|canvas|caption|" +
  "center|cite|code|col|colgroup|data|datalist|dd|del|dfn|dir|div|dl|dt|em|fieldset|figcaption|figure|font|" +
  "footer|h1|h2|h3|h4|h5|h6|header|hgroup|hr|i|ins|kbd|label|legend|li|listing|main|map|mark|menu|menuitem|meter|nav|nobr|" +
  "ol|optgroup|option|output|p|param|picture|pre|progress|q|rp|rt|ruby|s|samp|search|section|slot|small|span|" +
  "strike|strong|sub|summary|sup|table|tbody|td|tfoot|th|thead|time|tr|track|tt|u|ul|var|wbr";

// DOM event attributes, for the form without a quote before it (" onerror="). After a quote every on[a-z]{3,} counts.
const DOM_EVENTS =
  "abort|afterprint|afterscriptexecute|animationcancel|animationend|animationiteration|animationstart|" +
  "auxclick|beforecopy|beforecut|beforeinput|beforeprint|beforescriptexecute|beforetoggle|beforeunload|begin|blur|" +
  "bounce|cancel|canplay|canplaythrough|change|click|close|contextmenu|copy|cuechange|cut|dblclick|drag|dragend|" +
  "dragenter|dragleave|dragover|dragstart|drop|durationchange|end|ended|error|finish|focus|focusin|focusout|" +
  "formdata|fullscreenchange|hashchange|input|invalid|keydown|keypress|keyup|load|loadeddata|loadedmetadata|" +
  "loadstart|message|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseover|mouseup|mousewheel|offline|" +
  "online|pagehide|pageshow|paste|pause|play|playing|pointercancel|pointerdown|pointerenter|pointerleave|" +
  "pointermove|pointerout|pointerover|pointerrawupdate|pointerup|popstate|progress|ratechange|repeat|reset|resize|" +
  "scroll|scrollend|search|securitypolicyviolation|seeked|seeking|select|selectionchange|selectstart|show|" +
  "slotchange|stalled|start|storage|submit|suspend|timeupdate|toggle|touchcancel|touchend|touchmove|touchstart|" +
  "transitioncancel|transitionend|transitionrun|transitionstart|unhandledrejection|unload|volumechange|waiting|" +
  "webkitanimationend|webkitanimationiteration|webkitanimationstart|webkittransitionend|wheel";

const wordSet = (alternation: string): Set<string> => new Set(alternation.split("|"));
const dangerousTagSet = wordSet(DANGEROUS_TAGS);
const knownTagSet = wordSet(KNOWN_TAGS);
const domEventSet = wordSet(DOM_EVENTS);

// Characters browsers remove from a URL before reading the scheme (tab, LF, CR).
const URL_STRIPPED = "[\\t\\n\\r]*";

const spaced = (word: string): string => word.split("").join(URL_STRIPPED);

const EXEC_SCHEMES =
  "(?:" + spaced("javascript") + "|" + spaced("vbscript") + "|" + spaced("livescript") + "|" + spaced("mocha") + ")" +
  URL_STRIPPED + ":";
const DANGEROUS_DATA =
  spaced("data") + URL_STRIPPED + ":\\s*(?:text/html|text/javascript|text/xml|" +
  "application/(?:x-)?javascript|application/xhtml|image/svg\\+xml)";

const schemeAfterDelimiter = goRe("[\"'=(`]\\s*(" + EXEC_SCHEMES + "|" + DANGEROUS_DATA + ")");
const schemeAtStart = goRe("^\\s*(" + EXEC_SCHEMES + "\\S)");
const schemeAtStartURL = goRe("^\\s*(" + EXEC_SCHEMES + "|" + DANGEROUS_DATA + ")");
function mayHaveScheme(s: string): boolean {
  if (s.indexOf(":") < 0) return false;
  return containsAny(s, "\t\n\r") || s.includes("script") || s.includes("mocha") || s.includes("data");
}

// scanHandlers: the earliest offset of the event_handler rule (-1 = none); f is ASCII-lowercased.
export function scanHandlers(f: string): number {
  let best = -1;
  for (let p = 0; p + 1 < f.length; p++) {
    const next = f.indexOf("on", p);
    if (next < 0) break;
    p = next;
    if (best >= 0 && p > best) break;
    if (p > 0 && isLowerASCII(f.charCodeAt(p - 1))) continue;
    let q = p + 2;
    while (q < f.length && isLowerASCII(f.charCodeAt(q))) q++;
    let e = q;
    while (e < f.length && isRESpace(f.charCodeAt(e))) e++;
    if (e >= f.length || f.charCodeAt(e) !== 0x3d) continue;
    const name = f.slice(p + 2, q);
    if (name.length >= 3) {
      let b = p - 1;
      while (b >= 0 && (isRESpace(f.charCodeAt(b)) || f.charCodeAt(b) === 0x2f)) b--;
      if (b >= 0) {
        const c = f.charCodeAt(b);
        if ((c === 0x22 || c === 0x27 || c === 0x60) && (best < 0 || b < best)) best = b;
      }
    }
    if (domEventSet.has(name)) {
      const pc = p === 0 ? -1 : f.charCodeAt(p - 1);
      if ((p === 0 || isRESpace(pc) || pc === 0x2f || pc === 0x3b) && (best < 0 || p < best)) best = p;
    }
  }
  return best;
}

// scanTags: the earliest "<" of a dangerous tag and of an ordinary tag (-1 = none); f is ASCII-lowercased.
export function scanTags(f: string): [number, number] {
  let dangerous = -1;
  let generic = -1;
  const n = f.length;
  for (let i = 0; i < n && (dangerous < 0 || generic < 0); i++) {
    const next = f.indexOf("<", i);
    if (next < 0) break;
    i = next;
    let j = i + 1;
    if (
      generic < 0 &&
      (f.startsWith("!--", j) ||
        f.startsWith("![cdata[", j) ||
        f.startsWith("!doctype", j) ||
        (j + 1 < n && f.charCodeAt(j) === 0x3f && isLowerASCII(f.charCodeAt(j + 1))))
    ) {
      generic = i;
    }
    const closing = j < n && f.charCodeAt(j) === 0x2f;
    if (closing) j++;
    let k = j;
    if (k < n && isLowerASCII(f.charCodeAt(k))) {
      k++;
      while (k < n) {
        const c = f.charCodeAt(k);
        if (!(isLowerASCII(c) || (c >= 0x30 && c <= 0x39) || c === 0x3a || c === 0x2d)) break;
        k++;
      }
    }
    if (k === j) continue;
    const name = f.slice(j, k);
    if (dangerous < 0 && dangerousTagSet.has(name)) {
      const c = k < n ? f.charCodeAt(k) : -1;
      if (k === n || isRESpace(c) || c === 0x2f || c === 0x3e) dangerous = i;
    }
    if (generic < 0 && ((knownTagSet.has(name) && closesTag(f, k)) || (!closing && attrAssignFollows(f, k)))) generic = i;
  }
  return [dangerous, generic];
}

function closesTag(f: string, k: number): boolean {
  if (k >= f.length) return false;
  const c = f.charCodeAt(k);
  if (c === 0x3e) return true;
  if (!isRESpace(c) && c !== 0x2f) return false;
  for (k++; k < f.length; k++) {
    const d = f.charCodeAt(k);
    if (d === 0x3e) return true;
    if (d === 0x3c) return false;
  }
  return false;
}

function attrAssignFollows(f: string, k: number): boolean {
  const n = f.length;
  const start = k;
  while (k < n && (isRESpace(f.charCodeAt(k)) || f.charCodeAt(k) === 0x2f)) k++;
  if (k === start || k >= n) return false;
  let c = f.charCodeAt(k);
  if (!(isLowerASCII(c) || c === 0x5f || c === 0x3a)) return false;
  for (k++; k < n; k++) {
    c = f.charCodeAt(k);
    if (!(isLowerASCII(c) || (c >= 0x30 && c <= 0x39) || c === 0x2d || c === 0x5f || c === 0x3a || c === 0x2e)) break;
  }
  while (k < n && isRESpace(f.charCodeAt(k))) k++;
  return k < n && f.charCodeAt(k) === 0x3d;
}

function detectXSS(env: DetectorEnv, input: Input, emit: Emit): void {
  const f = input.folded();
  const [dangerous, generic] = scanTags(f);
  if (dangerous >= 0) emit("tag_dangerous", dangerous);
  if (generic >= 0) emit("tag_generic", generic);
  const h = scanHandlers(f);
  if (h >= 0) emit("event_handler", h);
  if (!mayHaveScheme(f)) return;
  let idx = matchIndex(schemeAfterDelimiter, f);
  if (idx >= 0) emit("scheme", idx);
  idx = matchIndex(schemeAtStart, f);
  if (idx >= 0) emit("scheme", idx);
  // A bare dangerous scheme at the start counts where the value is a link; in text "JavaScript: The Good Parts" is
  // a book title.
  if (isURLCtx(input.ctx) || env.strictProfile) {
    idx = matchIndex(schemeAtStartURL, f);
    if (idx >= 0) emit("scheme", idx);
  }
}

export const xssDetector: DetectorDef = {
  name: "xss",
  rules: ["tag_dangerous", "tag_generic", "event_handler", "scheme"],
  contexts: ALL_INSPECTED,
  fast: FB_XSS,
  detect: detectXSS,
  clean: CLEAN_CUT,
};
