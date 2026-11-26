// NoSQL operator names, shared by the nosql detector and the key check of the value walker.

import { asciiLower } from "./bytes.js";

export const MONGO_OPS =
  "ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|expr|or|and|not|nor|elemmatch|all|size|type|mod|" +
  "text|function|accumulator|jsonschema|lookup|options|search";

const MONGO_OP_SET = new Set(MONGO_OPS.split("|").map((op) => "$" + op));

/** isNoSQLOperatorKey: an object key that is a query operator ($ne, $where…) or a bracketed one (password[$ne]). */
export function isNoSQLOperatorKey(k: string): boolean {
  if (k.length > 1 && k.charCodeAt(0) === 0x24) return MONGO_OP_SET.has(asciiLower(k));
  return k.includes("[$");
}
