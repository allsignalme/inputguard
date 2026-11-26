// A linear-time regular expression engine for byte strings (Pike VM, the algorithm behind RE2's NFA). JavaScript
// regular expressions backtrack: on hostile input some patterns of the strict rules take quadratic time, while Go's
// RE2 guarantees linear time. This engine runs the same Go patterns in O(input × pattern) and finds the same
// leftmost-first match (Go and JavaScript agree on it), so results do not change.
//
// Supported syntax (RE2, the subset the rules use): alternation, (…) and (?:…) groups, * + ? {n} {n,} {n,m} and
// their lazy forms, . (any byte but \n), classes [...] with ranges and negation, \d \w \s \S \b, \t \n \r \f,
// \xHH, escaped punctuation, ^ and $ (start and end of text).

const OP_CHAR = 0;
const OP_SPLIT = 1; // try x first, then y
const OP_JMP = 2;
const OP_SAVE = 3;
const OP_BOL = 4;
const OP_EOL = 5;
const OP_WORDB = 6;
const OP_MATCH = 7;

interface Inst {
  op: number;
  set?: Uint8Array; // OP_CHAR: membership of each byte
  x: number;
  y: number;
  n: number; // OP_SAVE slot
}

export interface Program {
  insts: Inst[];
  /** Bytes a match can start with; null when a match can be empty. */
  first: Uint8Array | null;
}

// --- parser: Go regexp syntax to a tree ---

type Node =
  | { t: "set"; set: Uint8Array }
  | { t: "cat"; items: Node[] }
  | { t: "alt"; items: Node[] }
  | { t: "group"; n: number; body: Node } // n = capture index, -1 non-capturing
  | { t: "rep"; body: Node; min: number; max: number; lazy: boolean } // max -1 = unbounded
  | { t: "bol" }
  | { t: "eol" }
  | { t: "wordb" };

const SPACE = [0x09, 0x0a, 0x0c, 0x0d, 0x20];

function newSet(): Uint8Array {
  return new Uint8Array(256);
}

function addRange(s: Uint8Array, lo: number, hi: number): void {
  for (let c = lo; c <= hi; c++) s[c] = 1;
}

function addClassEscape(s: Uint8Array, e: string): boolean {
  switch (e) {
    case "d":
      addRange(s, 0x30, 0x39);
      return true;
    case "w":
      addRange(s, 0x30, 0x39);
      addRange(s, 0x41, 0x5a);
      addRange(s, 0x61, 0x7a);
      s[0x5f] = 1;
      return true;
    case "s":
      for (const c of SPACE) s[c] = 1;
      return true;
    case "S": {
      const t = newSet();
      for (const c of SPACE) t[c] = 1;
      for (let c = 0; c < 256; c++) if (!t[c]) s[c] = 1;
      return true;
    }
  }
  return false;
}

class Parser {
  private i = 0;
  ncap = 0;

  constructor(private readonly src: string) {}

  parse(): Node {
    const n = this.alt();
    if (this.i !== this.src.length) throw new Error(`pikevm: unexpected ${this.src[this.i]} at ${this.i}`);
    return n;
  }

  private alt(): Node {
    const items = [this.cat()];
    while (this.src[this.i] === "|") {
      this.i++;
      items.push(this.cat());
    }
    return items.length === 1 ? items[0] : { t: "alt", items };
  }

  private cat(): Node {
    const items: Node[] = [];
    while (this.i < this.src.length && this.src[this.i] !== "|" && this.src[this.i] !== ")") {
      items.push(this.repeat(this.atom()));
    }
    return { t: "cat", items };
  }

  private repeat(n: Node): Node {
    for (;;) {
      const c = this.src[this.i];
      let min: number;
      let max: number;
      if (c === "*") {
        min = 0;
        max = -1;
        this.i++;
      } else if (c === "+") {
        min = 1;
        max = -1;
        this.i++;
      } else if (c === "?") {
        min = 0;
        max = 1;
        this.i++;
      } else if (c === "{") {
        const m = /^\{(\d+)(,(\d*))?\}/.exec(this.src.slice(this.i));
        if (m === null) return n; // a literal "{" is parsed by atom
        min = Number(m[1]);
        max = m[2] === undefined ? min : m[3] === "" ? -1 : Number(m[3]);
        this.i += m[0].length;
      } else {
        return n;
      }
      let lazy = false;
      if (this.src[this.i] === "?") {
        lazy = true;
        this.i++;
      }
      n = { t: "rep", body: n, min, max, lazy };
    }
  }

  private atom(): Node {
    const c = this.src[this.i++];
    switch (c) {
      case "(": {
        let n = -1;
        if (this.src.startsWith("?:", this.i)) this.i += 2;
        else n = ++this.ncap;
        const body = this.alt();
        if (this.src[this.i++] !== ")") throw new Error("pikevm: missing )");
        return { t: "group", n, body };
      }
      case "[":
        return this.cls();
      case ".": {
        const s = newSet();
        addRange(s, 0, 255);
        s[0x0a] = 0;
        return { t: "set", set: s };
      }
      case "^":
        return { t: "bol" };
      case "$":
        return { t: "eol" };
      case "\\": {
        const e = this.src[this.i++];
        if (e === "b") return { t: "wordb" };
        const s = newSet();
        if (addClassEscape(s, e)) return { t: "set", set: s };
        s[this.escapedByte(e)] = 1;
        return { t: "set", set: s };
      }
      default: {
        const s = newSet();
        s[c.charCodeAt(0)] = 1;
        return { t: "set", set: s };
      }
    }
  }

  private escapedByte(e: string): number {
    switch (e) {
      case "t":
        return 0x09;
      case "n":
        return 0x0a;
      case "r":
        return 0x0d;
      case "f":
        return 0x0c;
      case "x": {
        const v = parseInt(this.src.slice(this.i, this.i + 2), 16);
        if (!/^[0-9a-fA-F]{2}$/.test(this.src.slice(this.i, this.i + 2))) throw new Error("pikevm: bad \\x");
        this.i += 2;
        return v;
      }
    }
    if (/[A-Za-z0-9]/.test(e)) throw new Error(`pikevm: unsupported escape \\${e}`);
    return e.charCodeAt(0);
  }

  private cls(): Node {
    const s = newSet();
    let neg = false;
    if (this.src[this.i] === "^") {
      neg = true;
      this.i++;
    }
    let first = true;
    while (this.i < this.src.length && (this.src[this.i] !== "]" || first)) {
      first = false;
      let lo: number;
      if (this.src[this.i] === "\\") {
        const e = this.src[this.i + 1];
        this.i += 2;
        if (addClassEscape(s, e)) continue;
        lo = this.escapedByte(e);
      } else {
        lo = this.src.charCodeAt(this.i++);
      }
      if (this.src[this.i] === "-" && this.src[this.i + 1] !== "]" && this.i + 1 < this.src.length) {
        this.i++;
        let hi: number;
        if (this.src[this.i] === "\\") {
          const e = this.src[this.i + 1];
          this.i += 2;
          hi = this.escapedByte(e);
        } else {
          hi = this.src.charCodeAt(this.i++);
        }
        addRange(s, lo, hi);
      } else {
        s[lo] = 1;
      }
    }
    if (this.src[this.i++] !== "]") throw new Error("pikevm: missing ]");
    if (neg) for (let c = 0; c < 256; c++) s[c] = s[c] ? 0 : 1;
    return { t: "set", set: s };
  }
}

// --- compiler: tree to instructions ---

class Compiler {
  readonly insts: Inst[] = [];

  emit(op: number, x = 0, y = 0, n = 0, set?: Uint8Array): number {
    this.insts.push({ op, x, y, n, set });
    return this.insts.length - 1;
  }

  node(n: Node): void {
    switch (n.t) {
      case "set":
        this.emit(OP_CHAR, 0, 0, 0, n.set);
        return;
      case "bol":
        this.emit(OP_BOL);
        return;
      case "eol":
        this.emit(OP_EOL);
        return;
      case "wordb":
        this.emit(OP_WORDB);
        return;
      case "cat":
        for (const it of n.items) this.node(it);
        return;
      case "group":
        if (n.n >= 0) this.emit(OP_SAVE, 0, 0, 2 * n.n);
        this.node(n.body);
        if (n.n >= 0) this.emit(OP_SAVE, 0, 0, 2 * n.n + 1);
        return;
      case "alt": {
        const jumps: number[] = [];
        for (let k = 0; k < n.items.length; k++) {
          if (k < n.items.length - 1) {
            const split = this.emit(OP_SPLIT);
            this.insts[split].x = this.insts.length;
            this.node(n.items[k]);
            jumps.push(this.emit(OP_JMP));
            this.insts[split].y = this.insts.length;
          } else {
            this.node(n.items[k]);
          }
        }
        for (const j of jumps) this.insts[j].x = this.insts.length;
        return;
      }
      case "rep": {
        for (let k = 0; k < n.min; k++) this.node(n.body);
        if (n.max < 0) {
          // x*: L: split body, out; body; jmp L
          const split = this.emit(OP_SPLIT);
          const bodyStart = this.insts.length;
          this.node(n.body);
          this.emit(OP_JMP, split);
          this.prefer(split, bodyStart, this.insts.length, n.lazy);
          return;
        }
        // (x(x(x)?)?)? for the optional copies
        const splits: number[] = [];
        for (let k = n.min; k < n.max; k++) {
          const split = this.emit(OP_SPLIT);
          splits.push(split);
          this.insts[split].x = this.insts.length;
          this.node(n.body);
        }
        for (const sp of splits) this.prefer(sp, sp + 1, this.insts.length, n.lazy);
        return;
      }
    }
  }

  private prefer(split: number, body: number, out: number, lazy: boolean): void {
    this.insts[split].x = lazy ? out : body;
    this.insts[split].y = lazy ? body : out;
  }
}

/** compile parses a Go regular expression. Program slots: 0/1 the match, 2/3 group 1. */
export function compile(src: string): Program {
  const p = new Parser(src);
  const tree = p.parse();
  const c = new Compiler();
  c.emit(OP_SAVE, 0, 0, 0);
  c.node(tree);
  c.emit(OP_SAVE, 0, 0, 1);
  c.emit(OP_MATCH);
  return { insts: c.insts, first: firstBytes(c.insts) };
}

// --- execution ---

// firstBytes: the bytes a match can start with (assertions assumed true), or null when a match can be empty.
function firstBytes(insts: Inst[]): Uint8Array | null {
  const set = new Uint8Array(256);
  const seen = new Uint8Array(insts.length);
  const stack = [0];
  while (stack.length > 0) {
    const pc = stack.pop() as number;
    if (seen[pc]) continue;
    seen[pc] = 1;
    const inst = insts[pc];
    switch (inst.op) {
      case OP_JMP:
        stack.push(inst.x);
        break;
      case OP_SPLIT:
        stack.push(inst.x, inst.y);
        break;
      case OP_SAVE:
      case OP_BOL:
      case OP_EOL:
      case OP_WORDB:
        stack.push(pc + 1);
        break;
      case OP_MATCH:
        return null;
      default: {
        const s = inst.set as Uint8Array;
        for (let c = 0; c < 256; c++) if (s[c]) set[c] = 1;
      }
    }
  }
  return set;
}

function isWord(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x5f;
}

type Caps = number[];

class ThreadList {
  readonly pcs: Int32Array;
  readonly caps: Caps[];
  count = 0;
  readonly mark: Int32Array;
  gen = 1;

  constructor(n: number) {
    this.pcs = new Int32Array(n);
    this.caps = new Array<Caps>(n);
    this.mark = new Int32Array(n);
  }

  clear(): void {
    this.count = 0;
    this.gen++;
  }
}

/**
 * exec finds the leftmost-first match of prog in s: [match start, group 1 start] (-1 when group 1 did not take
 * part), or null.
 */
export function exec(prog: Program, s: string): [number, number] | null {
  const insts = prog.insts;
  const ni = insts.length;
  let clist = new ThreadList(ni);
  let nlist = new ThreadList(ni);
  const stackPc = new Int32Array(2 * ni + 2);
  const stackCaps = new Array<Caps>(2 * ni + 2);
  let matched: Caps | null = null;
  const n = s.length;

  // add follows the empty transitions from pc at position i, depth first in priority order.
  const add = (list: ThreadList, pc0: number, caps0: Caps, i: number): void => {
    let sp = 0;
    stackPc[sp] = pc0;
    stackCaps[sp++] = caps0;
    while (sp > 0) {
      const pc = stackPc[--sp];
      const caps = stackCaps[sp];
      if (list.mark[pc] === list.gen) continue;
      list.mark[pc] = list.gen;
      const inst = insts[pc];
      switch (inst.op) {
        case OP_JMP:
          stackPc[sp] = inst.x;
          stackCaps[sp++] = caps;
          break;
        case OP_SPLIT:
          stackPc[sp] = inst.y;
          stackCaps[sp++] = caps;
          stackPc[sp] = inst.x;
          stackCaps[sp++] = caps;
          break;
        case OP_SAVE: {
          const c = caps.slice();
          c[inst.n] = i;
          stackPc[sp] = pc + 1;
          stackCaps[sp++] = c;
          break;
        }
        case OP_BOL:
          if (i === 0) {
            stackPc[sp] = pc + 1;
            stackCaps[sp++] = caps;
          }
          break;
        case OP_EOL:
          if (i === n) {
            stackPc[sp] = pc + 1;
            stackCaps[sp++] = caps;
          }
          break;
        case OP_WORDB:
          if ((i > 0 && isWord(s.charCodeAt(i - 1))) !== (i < n && isWord(s.charCodeAt(i)))) {
            stackPc[sp] = pc + 1;
            stackCaps[sp++] = caps;
          }
          break;
        default:
          list.pcs[list.count] = pc;
          list.caps[list.count++] = caps;
      }
    }
  };

  const empty: Caps = [-1, -1, -1, -1];
  const first = prog.first;
  for (let i = 0; ; i++) {
    if (matched === null) {
      if (clist.count === 0 && first !== null) {
        // Nothing running: jump to the next byte a match can start with.
        while (i < n && first[s.charCodeAt(i)] === 0) i++;
        if (i >= n) break;
      }
      add(clist, 0, empty, i);
    }
    if (clist.count === 0) break;
    const c = i < n ? s.charCodeAt(i) : -1;
    for (let k = 0; k < clist.count; k++) {
      const inst = insts[clist.pcs[k]];
      if (inst.op === OP_MATCH) {
        matched = clist.caps[k];
        break; // lower-priority threads are cut off
      }
      if (c >= 0 && (inst.set as Uint8Array)[c] === 1) add(nlist, clist.pcs[k] + 1, clist.caps[k], i + 1);
    }
    if (i >= n) break;
    const t = clist;
    clist = nlist;
    nlist = t;
    nlist.clear();
  }
  return matched === null ? null : [matched[0], matched[2]];
}
