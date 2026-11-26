// Path traversal (balanced profile). Port of the traversal group of det_injection.go.

import { hexPair } from "./bytes.js";
import type { DetectorDef, Emit, Input } from "./detector.js";
import { CLEAN_EMPTY } from "./detector.js";
import { FB_TRAVERSAL, isPathSep, sensitivePathAt, sepRunStart } from "./prefilter.js";
import { CTX_PATH, CTX_REDIRECT, CTX_URL, maskOf } from "./rule.js";

function detectTraversal(_env: unknown, input: Input, emit: Emit): void {
  if (overlongAt(input.raw) >= 0) {
    emit("path_traversal", -1); // offset in the raw value, not in the decoded one
    return;
  }
  const f = input.folded();
  for (let i = 0; ; ) {
    const j = f.indexOf("..", i);
    if (j < 0) break;
    i = j;
    const p = i === 0 ? -1 : f.charCodeAt(i - 1);
    if (i === 0 || isPathSep(p) || p === 0x3d) {
      let k = i;
      while (k < f.length && f.charCodeAt(k) === 0x2e) k++;
      const dots = k - i;
      if (k < f.length && f.charCodeAt(k) === 0x3b) {
        // ..;/ (path parameter, Tomcat / Jetty)
        while (k < f.length && !isPathSep(f.charCodeAt(k))) k++;
      }
      if ((k < f.length && isPathSep(f.charCodeAt(k))) || (k === f.length && dots === 2)) {
        emit("path_traversal", i);
        return;
      }
      i = k;
      continue;
    }
    i += 2;
  }
  for (let k = 0; k < f.length; k++) {
    if (isPathSep(f.charCodeAt(k)) && sepRunStart(f, k) && sensitivePathAt(f, k)) {
      emit("path_traversal", k);
      return;
    }
  }
}

// overlongAt: the offset of an overlong UTF-8 sequence written with percent-encoding (%c0%af, %e0%80%ae, nested
// %25c0%25af…), or -1.
function overlongAt(s: string): number {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) !== 0x25) continue;
    const j = pctSkip25(s, i + 1);
    if (j + 1 >= s.length) continue;
    const v = hexPair(s.charCodeAt(j), s.charCodeAt(j + 1));
    if (v < 0) continue;
    if (v === 0xc0 || v === 0xc1) return i;
    if (v === 0xe0) {
      let k = j + 2;
      if (k < s.length && s.charCodeAt(k) === 0x25) {
        k = pctSkip25(s, k + 1);
        if (k + 1 < s.length) {
          const w = hexPair(s.charCodeAt(k), s.charCodeAt(k + 1));
          if (w >= 0x80 && w <= 0x9f) return i;
        }
      }
    }
  }
  return -1;
}

function pctSkip25(s: string, j: number): number {
  for (let n = 0; n < 3 && j + 1 < s.length && s.charCodeAt(j) === 0x32 && s.charCodeAt(j + 1) === 0x35; n++) j += 2;
  return j;
}

export const traversalDetector: DetectorDef = {
  name: "traversal",
  rules: ["path_traversal"],
  contexts: maskOf(CTX_PATH, CTX_URL, CTX_REDIRECT),
  fast: FB_TRAVERSAL,
  detect: detectTraversal,
  clean: CLEAN_EMPTY,
};
