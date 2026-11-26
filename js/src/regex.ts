// goRe compiles a Go (RE2) regular expression for byte strings, keeping RE2's meaning where JavaScript differs:
//   \s  is [\t\n\f\r ] in RE2 (JavaScript adds \v, NBSP and Unicode spaces)
//   \S  is its complement
//   .   matches anything but \n in RE2 (JavaScript also stops at \r)
//   [\s\S] matches any byte
// \w, \d and \b are ASCII in both. Leftmost-first matching and submatch positions are the same. Patterns must not
// use case-insensitive flags, Unicode classes or a "]" first in a class (none of the ported patterns do).

const SPACE = "\\t\\n\\f\\r ";

export function goRe(src: string): RegExp {
  src = src.split("[\\s\\S]").join("[^]");
  let out = "";
  let inClass = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === "\\") {
      const e = src[i + 1];
      i++;
      if (e === "s") {
        out += inClass ? SPACE : "[" + SPACE + "]";
      } else if (e === "S") {
        if (inClass) throw new Error("goRe: \\S inside a class");
        out += "[^" + SPACE + "]";
      } else {
        out += c + e;
      }
      continue;
    }
    if (inClass) {
      if (c === "]") inClass = false;
      out += c;
      continue;
    }
    if (src.startsWith("[^]", i)) {
      out += "[^]"; // any byte, from [\s\S]
      i += 2;
      continue;
    }
    if (c === "[") {
      inClass = true;
      out += c;
      if (src[i + 1] === "^") {
        out += "^";
        i++;
      }
      if (src[i + 1] === "]") throw new Error("goRe: ] first in a class");
      continue;
    }
    out += c === "." ? "[^\\n]" : c;
  }
  // d: match indices, for the start of group 1.
  return new RegExp(out, "d");
}

type IndexedMatch = RegExpExecArray & { indices?: Array<[number, number] | undefined> };

/** matchIndex: the start of group 1 when it took part, else of the whole match; -1 when nothing matches. */
export function matchIndex(re: RegExp, s: string): number {
  const m = re.exec(s) as IndexedMatch | null;
  if (m === null) return -1;
  const g1 = m.indices?.[1];
  return g1 !== undefined ? g1[0] : m.index;
}
