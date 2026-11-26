// Server-side injection: SQL, NoSQL operators, CR/LF in headers, shell commands. Port of
// det_injection.go. Patterns run on the folded value (byte string).

import { containsAny, indexAny, isRESpace, isWordByte } from "./bytes.js";
import type { DetectorDef, Emit, Input } from "./detector.js";
import { ALL_INSPECTED, CLEAN_CHARS, CLEAN_CUT } from "./detector.js";
import { containsAnyFold, FB_CRLF, FB_CRLF_ENC, mayBeEncoded } from "./prefilter.js";
import { MONGO_OPS } from "./det_injection_keys.js";
import { goRe, matchIndex } from "./regex.js";
import { CTX_HEADER, CTX_IDENTIFIER, CTX_PATH, CTX_REDIRECT, CTX_TEXT, CTX_URL, maskOf, URL_CONTEXTS } from "./rule.js";

const SQL_CONTEXTS = maskOf(CTX_TEXT, CTX_URL, CTX_REDIRECT, CTX_IDENTIFIER, CTX_PATH, CTX_HEADER);


// --- SQL ---

const Q = "['\"`]"; // a quote that can close a SQL string or identifier
const BT = "`";

interface Family {
  gate: (f: string, quote: boolean) => boolean;
  re: RegExp;
}

const SQL_CATALOG = [
  "sleep", "benchmark", "waitfor", "dbms_", "information_schema", "xp_cmdshell", "sp_executesql", "sp_oacreate",
  "pg_catalog", "sqlite_master", "utl_http", "utl_inaddr", "sys.", "mysql.user", "load_file", "outfile",
  "dumpfile", "@@", "extractvalue", "updatexml", "char(", "char (",
];

const SQL_FAMILIES: Family[] = [
  {
    // Tautology after a closing quote or parenthesis: ' or 1=1, ") or ("a"="a, ' or username='admin, ' or true--.
    gate: (f, quote) =>
      (quote || f.indexOf(")") >= 0) &&
      (hasWord(f, "or") || hasWord(f, "and") || hasWord(f, "xor") || f.includes("||") || f.includes("&&")),
    re: goRe(
      "(?:" + Q + String.raw`|\))\s*(?:(?:or|and|xor)\b|\|\||&&)\s*(?:not\s+)?\(*\s*(?:` +
        String.raw`(?:'[^']*'|"[^"]*"|\d+(?:\.\d+)?|true|false|null)\s*` +
        String.raw`(?:=|<>|!=|<=?|>=?|\blike\b|\bis\b|\bin\b|\bbetween\b|\bregexp\b|\brlike\b)\s*` +
        String.raw`(?:['"\d(]|true\b|false\b|null\b|not\b)` +
        String.raw`|[a-z_][\w.$]*\s*(?:=|<>|!=|\blike\b)\s*['"])` +
        "|" + Q + String.raw`\s*(?:or|\|\|)\s+(?:true|1|not\s+false)\s*(?:--|#|/\*|;|$)`,
    ),
  },
  {
    // Numeric tautology: 1 or 1=1.
    gate: (f) => hasWord(f, "or") && f.indexOf("=") >= 0,
    re: goRe(String.raw`\b\d+\s+or\s+\d+\s*=\s*\d+`),
  },
  {
    // A comment right after a quote that closes a value: admin'--, admin' -- (at the end), admin'#, 1')--, x'/*.
    gate: (f, quote) => quote && (f.includes("--") || f.indexOf("#") >= 0 || f.includes("/*")),
    re: goRe(String.raw`(?:^|[\w)])` + Q + String.raw`\)?(?:--|\s*;\s*--|\s*--\s*$|\s*#\s*$|\s*/\*)`),
  },
  {
    // UNION [ALL] SELECT followed by what a select list starts with.
    gate: (f) => f.includes("union") && f.includes("select"),
    re: goRe(
      String.raw`\bunion\b(?:\s|/\*.*?\*/|\()+(?:(?:all|distinct)\b(?:\s|/\*.*?\*/)*)?select\b` +
        String.raw`(?:\s|/\*.*?\*/|\()+(?:\*|null\b|\d|@|'|"|[\w.]+\s*(?:,|\(|\bfrom\b))`,
    ),
  },
  {
    // Stacked queries.
    gate: (f) => stackedKeyword(f),
    re: goRe(
      String.raw`;\s*(?:drop\s+(?:table|database|schema|view|index|user|function|procedure)\b|` +
        String.raw`truncate\s+table\b|alter\s+(?:table|database|user)\b|exec(?:ute)?\s*(?:xp_|sp_|master\.|\()|` +
        String.raw`shutdown\s*(?:;|--|$|with\b)|declare\s+@|create\s+(?:table|user|database|function|procedure|trigger|login)\b|` +
        String.raw`grant\s+(?:all|select|insert|update|delete|execute)\b|waitfor\s+delay\b)` +
        "|(?:" + Q + String.raw`|\)|\d)\s*;\s*(?:select\s[\s\S]*?\bfrom\b|delete\s+from\b|insert\s+into\b|` +
        String.raw`update\s+[\w.` + BT + String.raw`"\[\]]+\s+set\b)`,
    ),
  },
  {
    // Time-based blind injection; catalog and dangerous-function access.
    gate: (f) => SQL_CATALOG.some((w) => f.includes(w)),
    re: goRe(
      [
        String.raw`\b(?:sleep|pg_sleep)\s*\(\s*\d+(?:\.\d+)?\s*\)`,
        String.raw`\bbenchmark\s*\(\s*\d+\s*,`,
        String.raw`\bwaitfor\s+(?:delay|time)\s+'`,
        String.raw`\bdbms_(?:pipe\.receive_message|lock\.sleep)\b`,
        String.raw`\b(?:information_schema|xp_cmdshell|sp_executesql|sp_oacreate|pg_catalog|sqlite_master|utl_http|utl_inaddr)\b`,
        String.raw`\bsys\.(?:objects|tables|columns|databases|sysobjects)\b`,
        String.raw`\bmysql\.user\b`,
        String.raw`\bload_file\s*\(`,
        String.raw`\binto\s+(?:out|dump)file\b`,
        String.raw`@@(?:version|datadir|hostname|basedir)\b`,
        String.raw`\b(?:extractvalue|updatexml)\s*\(`,
        String.raw`\bchar\s*\(\s*\d+(?:\s*,\s*\d+){3,}\s*\)`,
      ].join("|"),
    ),
  },
];

const STACKED_KEYWORDS = [
  "drop", "truncate", "alter", "delete", "insert", "update", "exec", "shutdown", "declare", "select", "create", "grant",
  "waitfor",
];

function stackedKeyword(f: string): boolean {
  for (let i = f.indexOf(";"); i >= 0; ) {
    let j = i + 1;
    while (j < f.length && isRESpace(f.charCodeAt(j))) j++;
    for (const k of STACKED_KEYWORDS) if (f.startsWith(k, j)) return true;
    const next = f.indexOf(";", j);
    if (next < 0) return false;
    i = next;
  }
  return false;
}

const SQL_BYTES = "'\"`;=<>()@#";
const SQL_PLAIN_WORDS = ["union", "outfile", "dumpfile"];
const SQL_UNDERSCORE = [
  "information_schema", "xp_cmdshell", "sp_executesql", "sp_oacreate", "pg_catalog", "sqlite_master",
  "utl_http", "utl_inaddr", "dbms_", "load_file",
];
const SQL_DOT = ["sys.", "mysql.user"];

function mayHaveSQL(s: string): boolean {
  if (mayBeEncoded(s) || containsAny(s, SQL_BYTES) || containsAnyFold(s, SQL_PLAIN_WORDS)) return true;
  return (s.indexOf("_") >= 0 && containsAnyFold(s, SQL_UNDERSCORE)) || (s.indexOf(".") >= 0 && containsAnyFold(s, SQL_DOT));
}

/** hasWord: w occurs in s between non-alphanumeric characters. */
function hasWord(s: string, w: string): boolean {
  for (let i = 0; ; ) {
    const j = s.indexOf(w, i);
    if (j < 0) return false;
    const k = j + w.length;
    if ((j === 0 || !isWordByte(s.charCodeAt(j - 1))) && (k === s.length || !isWordByte(s.charCodeAt(k)))) return true;
    i = j + 1;
  }
}

function detectSQL(_env: unknown, input: Input, emit: Emit): void {
  const f = input.folded();
  const quote = containsAny(f, "'\"`");
  let best = -1;
  for (const fam of SQL_FAMILIES) {
    if (!fam.gate(f, quote)) continue;
    const i = matchIndex(fam.re, f);
    if (i >= 0 && (best < 0 || i < best)) best = i;
  }
  if (best >= 0) emit("sql_injection", best);
}

// --- NoSQL ---

const nosqlRe = goRe(String.raw`(?:\[\s*\$|\{\s*['"]?\s*\$)(?:` + MONGO_OPS + String.raw`)\b|\$where\b`);

function detectNoSQL(_env: unknown, input: Input, emit: Emit): void {
  const i = matchIndex(nosqlRe, input.folded());
  if (i >= 0) emit("nosql_operator", i);
}

// --- Shell commands ---

const commandRe = goRe(
  "(?:[;&|\\n`]|\\$\\()\\s*(?:" +
    [
      String.raw`rm\s+-[a-z]*[rf]`, String.raw`curl\s+(?:-|https?:|ftp:|file:)`, String.raw`wget\s+(?:-|https?:|ftp:)`,
      String.raw`nc\s+-`, String.raw`ncat\s`, String.raw`netcat\s`, String.raw`(?:ba|z|da|k)?sh\s+-[ci]\b`,
      String.raw`/bin/(?:ba|z|da|k)?sh\b`, String.raw`powershell\b`, String.raw`pwsh\b`, String.raw`cmd(?:\.exe)?\s*/[ck]\b`,
      String.raw`chmod\s+[+0-7ugoa]`, String.raw`chown\s+\w`, String.raw`sudo\s+\w`, String.raw`mkfifo\s`,
      String.raw`telnet\s+\w`, String.raw`whoami\b`, String.raw`uname\s+-`, String.raw`ifconfig\b`, String.raw`ipconfig\b`,
      String.raw`nslookup\s+\w`, String.raw`base64\s+-d`, String.raw`python[23]?\s+-c\b`, String.raw`perl\s+-e\b`,
      String.raw`ruby\s+-e\b`, String.raw`php\s+-r\b`, String.raw`node\s+-e\b`,
      String.raw`sleep\s+\d+\s*(?:$|[;&|)` + BT + "])",
      String.raw`cat\s+/`, String.raw`ping\s+-[cn]\b`, String.raw`echo\s+[^;&|\n]*[|>]`, String.raw`tftp\s`,
      String.raw`kill\s+-9`, String.raw`(?:shutdown|reboot)\s+-`,
    ].join("|") +
    ")|(?:\\$\\(|`)\\s*(?:id|whoami|uname|hostname|pwd|ls|cat|curl|wget|bash|sh|env|printenv)\\b|\\$\\{ifs\\}",
);

function detectCommand(_env: unknown, input: Input, emit: Emit): void {
  const i = matchIndex(commandRe, input.folded());
  if (i >= 0) emit("command", i);
}

export const sqlDetector: DetectorDef = {
  name: "sql",
  rules: ["sql_injection"],
  contexts: SQL_CONTEXTS,
  fast: 0,
  mayMatch: mayHaveSQL,
  detect: detectSQL,
  clean: CLEAN_CUT,
};

export const nosqlDetector: DetectorDef = {
  name: "nosql",
  rules: ["nosql_operator"],
  contexts: ALL_INSPECTED,
  fast: 0,
  mayMatch: (raw) => mayBeEncoded(raw) || raw.indexOf("$") >= 0,
  detect: detectNoSQL,
  clean: CLEAN_CUT,
};

// CR/LF: a header (or an id that ends up in one) is checked as received; a URL is checked decoded.
export const crlfDetector: DetectorDef = {
  name: "crlf",
  rules: ["header_crlf"],
  contexts: maskOf(CTX_HEADER, CTX_IDENTIFIER),
  fast: FB_CRLF,
  detect: (_env, input, emit) => {
    const i = indexAny(input.raw, "\r\n");
    if (i >= 0) emit("header_crlf", i);
  },
  clean: CLEAN_CHARS,
};

export const crlfURLDetector: DetectorDef = {
  name: "crlf_url",
  rules: ["header_crlf"],
  contexts: URL_CONTEXTS,
  fast: FB_CRLF | FB_CRLF_ENC,
  detect: (_env, input, emit) => {
    const i = indexAny(input.decoded(), "\r\n");
    if (i >= 0) emit("header_crlf", i);
  },
  clean: CLEAN_CUT,
};

export const commandDetector: DetectorDef = {
  name: "command",
  rules: ["command"],
  contexts: ALL_INSPECTED,
  fast: 0,
  mayMatch: (raw) => mayBeEncoded(raw) || containsAny(raw, ";&|\n`$"),
  detect: detectCommand,
  clean: CLEAN_CUT,
};
