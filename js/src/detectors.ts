// The detector sets of the two builds, in the order the Go engine registers them (findings follow this order).

import type { DetectorDef } from "./detector.js";
import { commandDetector, crlfDetector, crlfURLDetector, nosqlDetector, sqlDetector } from "./det_injection.js";
import { formulaDetector, mixedScriptsDetector, redirectDetector, ssrfDetector } from "./det_output.js";
import { templateDetector } from "./det_template.js";
import { traversalDetector } from "./det_traversal.js";
import { unicodeDetector } from "./det_unicode.js";
import { xssDetector } from "./det_xss.js";

export const ALL_DETECTORS: readonly DetectorDef[] = [
  sqlDetector,
  nosqlDetector,
  traversalDetector,
  crlfDetector,
  crlfURLDetector,
  commandDetector,
  formulaDetector,
  ssrfDetector,
  redirectDetector,
  mixedScriptsDetector,
  unicodeDetector,
  xssDetector,
  templateDetector,
];
