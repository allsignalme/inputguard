package inputguard

import (
	"regexp"
	"strings"
)

// Server-side injection: SQL, NoSQL operators, path traversal, CR/LF in headers, shell commands. Patterns run on
// the normalised value (percent-encoding, entities, escapes and fullwidth forms decoded), lowercased.

var (
	sqlContexts = maskOf(CtxText, CtxURL, CtxRedirect, CtxIdentifier, CtxPath, CtxHeader)
	urlContexts = maskOf(CtxURL, CtxRedirect)
)

func init() {
	registerDetector(&builtinDetector{
		name:     "sql",
		rules:    []RuleID{RuleSQLInjection},
		contexts: sqlContexts,
		mayMatch: func(_ *Guard, raw string) bool { return mayHaveSQL(raw) },
		needNorm: true,
		detect:   detectSQL,
		clean:    cleanCut,
	})
	registerDetector(&builtinDetector{
		name:     "nosql",
		rules:    []RuleID{RuleNoSQLOperator},
		contexts: allInspected,
		mayMatch: func(_ *Guard, raw string) bool { return mayBeEncoded(raw) || strings.IndexByte(raw, '$') >= 0 },
		needNorm: true,
		detect:   detectNoSQL,
		clean:    cleanCut,
	})
	registerDetector(&builtinDetector{
		name:     "traversal",
		rules:    []RuleID{RulePathTraversal},
		contexts: maskOf(CtxPath, CtxURL, CtxRedirect),
		fast:     fbTraversal,
		needNorm: true,
		detect:   detectTraversal,
		clean:    cleanEmpty,
	})
	// CR/LF: a header (or an id that ends up in one, or in a log line) is checked as received; a URL is checked
	// decoded, since %0d%0a is what reaches a Location header.
	registerDetector(&builtinDetector{
		name:     "crlf",
		rules:    []RuleID{RuleHeaderCRLF},
		contexts: maskOf(CtxHeader, CtxIdentifier),
		fast:     fbCRLF,
		detect: func(_ *Guard, in *input, emit func(RuleID, int)) {
			if i := strings.IndexAny(in.raw, "\r\n"); i >= 0 {
				emit(RuleHeaderCRLF, i)
			}
		},
		clean: cleanChars,
	})
	registerDetector(&builtinDetector{
		name:     "crlf_url",
		rules:    []RuleID{RuleHeaderCRLF},
		contexts: urlContexts,
		fast:     fbCRLF | fbCRLFEnc,
		needNorm: true,
		detect: func(_ *Guard, in *input, emit func(RuleID, int)) {
			if i := strings.IndexAny(in.decoded(), "\r\n"); i >= 0 {
				emit(RuleHeaderCRLF, i)
			}
		},
		clean: cleanCut,
	})
	registerDetector(&builtinDetector{
		name:     "command",
		rules:    []RuleID{RuleCommand},
		contexts: allInspected,
		mayMatch: func(_ *Guard, raw string) bool { return mayBeEncoded(raw) || strings.ContainsAny(raw, ";&|\n`$") },
		needNorm: true,
		detect:   detectCommand,
		clean:    cleanCut,
	})
}

// mayBeEncoded: the value may decode to other ASCII characters (percent-encoding, entities, escapes, fullwidth and
// small form variants, which NFKC folds to ASCII punctuation).
func mayBeEncoded(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%', '&', '\\', 0xEF:
			return true
		}
	}
	return false
}

// --- SQL ---

const q = "['\"`]" // a quote that can close a SQL string or identifier

var sqlRe = regexp.MustCompile(strings.Join([]string{
	// Tautology after a closing quote or parenthesis: ' or 1=1, ") or ("a"="a, ' || 'x' like 'x.
	"(?:" + q + "|\\))\\s*(?:(?:or|and|xor)\\b|\\|\\||&&)\\s*(?:not\\s+)?[('\"`]*\\s*[\\w.@$]*['\"`]?\\s*" +
		`(?:=|<>|!=|<=?|>=?|\blike\b|\bis\s+(?:not\s+)?null\b|\bin\s*\(|\bbetween\b|\bregexp\b|\brlike\b)`,
	// ' or true--, ' or 1#
	q + `\s*(?:or|\|\|)\s+(?:true|1|not\s+false)\s*(?:--|#|/\*|;|$)`,
	// Numeric tautology: 1 or 1=1.
	`\b\d+\s+or\s+\d+\s*(?:=|<|>)\s*\d+`,
	// A comment right after a quote ends the query: admin'--, admin'#, '/*.
	q + `\s*;?\s*(?:--(?:\s|$)|#\s*$|/\*)`,
	// UNION-based extraction, with comments or parentheses as separators.
	`\bunion\b(?:\s|/\*.*?\*/|\()+(?:all\b|distinct\b)?(?:\s|/\*.*?\*/|\()*select\b`,
	// Stacked queries.
	`;\s*(?:drop\s+(?:table|database|schema|view|index|user|function|procedure)\b|truncate\s+(?:table\s+)?[\w.` + "`" +
		`"]|alter\s+(?:table|database|user)\b|delete\s+from\b|insert\s+into\b|update\s+[\w.` + "`" + `"\[\]]+\s+set\b|` +
		`exec(?:ute)?\s*(?:xp_|sp_|master\.|\()|shutdown\b|declare\s+@|select\s[\s\S]*?\bfrom\b|` +
		`create\s+(?:table|user|database|function|procedure|trigger|login)\b|grant\s+\w|waitfor\s+delay\b)`,
	// Time-based blind injection.
	`\b(?:sleep|pg_sleep)\s*\(\s*\d+(?:\.\d+)?\s*\)`,
	`\bbenchmark\s*\(\s*\d+\s*,`,
	`\bwaitfor\s+(?:delay|time)\s+'`,
	`\bdbms_(?:pipe\.receive_message|lock\.sleep)\b`,
	// Catalog and dangerous-function access.
	`\b(?:information_schema|xp_cmdshell|sp_executesql|sp_oacreate|pg_catalog|sqlite_master|utl_http|utl_inaddr)\b`,
	`\bsys\.(?:objects|tables|columns|databases|sysobjects)\b`,
	`\bmysql\.user\b`,
	`\bload_file\s*\(`,
	`\binto\s+(?:out|dump)file\b`,
	`@@(?:version|datadir|hostname|basedir)\b`,
	`\b(?:extractvalue|updatexml)\s*\(`,
	`\bchar\s*\(\s*\d+(?:\s*,\s*\d+){3,}\s*\)`,
}, "|"))

var sqlWords = []string{
	"union", "sleep", "benchmark", "waitfor", "information_schema", "xp_", "sp_", "pg_", "sqlite_", "mysql.",
	"sys.", "utl_", "dbms_", "outfile", "dumpfile", "load_file", "extractvalue", "updatexml",
}

var sqlBytes = byteSet("'\"`;=<>()@#")

func mayHaveSQL(s string) bool {
	if mayBeEncoded(s) || hasAnyByte(s, &sqlBytes) {
		return true
	}
	for _, w := range sqlWords {
		if containsFoldASCII(s, w) {
			return true
		}
	}
	return false
}

func detectSQL(_ *Guard, in *input, emit func(RuleID, int)) {
	if i := matchIndex(sqlRe, in.folded()); i >= 0 {
		emit(RuleSQLInjection, i)
	}
}

// --- NoSQL ---

const mongoOps = `ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|expr|or|and|not|nor|elemmatch|all|size|type|mod|` +
	`text|function|accumulator|jsonschema|lookup|options|search`

// nosqlRe: an operator smuggled into a value: field[$ne]=x (query-string objects), {"$gt": ""} in a string, $where.
var nosqlRe = regexp.MustCompile(`(?:\[\s*\$|\{\s*['"]?\s*\$)(?:` + mongoOps + `)\b|\$where\b`)

var mongoOpSet = func() map[string]bool {
	m := map[string]bool{}
	for _, op := range strings.Split(mongoOps, "|") {
		m["$"+op] = true
	}
	return m
}()

func detectNoSQL(_ *Guard, in *input, emit func(RuleID, int)) {
	if i := matchIndex(nosqlRe, in.folded()); i >= 0 {
		emit(RuleNoSQLOperator, i)
	}
}

// isNoSQLOperatorKey: an object key that is a query operator ($ne, $where…) or a bracketed one (password[$ne]).
func isNoSQLOperatorKey(k string) bool {
	if len(k) > 1 && k[0] == '$' {
		return mongoOpSet[lowerASCII(k)]
	}
	return strings.Contains(k, "[$")
}

// --- Path traversal ---

var sensitivePaths = []string{
	"/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group", "/proc/self/", "/proc/version", "win.ini", "boot.ini",
	"/windows/system32", `\windows\system32`, "/var/run/secrets", "/.aws/credentials", "/.ssh/", "/.git/config",
}

func detectTraversal(_ *Guard, in *input, emit func(RuleID, int)) {
	f := in.folded()
	for i := 0; ; {
		j := strings.Index(f[i:], "..")
		if j < 0 {
			break
		}
		i += j
		if i == 0 || isPathSep(f[i-1]) || f[i-1] == '=' {
			k := i
			for k < len(f) && f[k] == '.' {
				k++
			}
			if k < len(f) && f[k] == ';' { // ..;/ (path parameter, Tomcat / Jetty)
				for k < len(f) && !isPathSep(f[k]) {
					k++
				}
			}
			if k == len(f) || isPathSep(f[k]) || overlongSlash(f, k) {
				emit(RulePathTraversal, i)
				return
			}
			i = k
			continue
		}
		i += 2
	}
	for _, p := range sensitivePaths {
		if k := strings.Index(f, p); k >= 0 {
			emit(RulePathTraversal, k)
			return
		}
	}
}

// overlongSlash: an overlong UTF-8 form of / or \ (%c0%af, %e0%80%af, %c1%9c) that old decoders turn into a
// separator.
func overlongSlash(s string, i int) bool {
	switch {
	case i+1 < len(s) && s[i] == 0xC0 && (s[i+1] == 0xAF || s[i+1] == 0xAE):
		return true
	case i+1 < len(s) && s[i] == 0xC1 && (s[i+1] == 0x9C || s[i+1] == 0x1C):
		return true
	case i+2 < len(s) && s[i] == 0xE0 && s[i+1] == 0x80 && s[i+2] == 0xAF:
		return true
	}
	return false
}

// --- Shell commands ---

// commandRe: a command separator ( ; & | newline ` $( ) followed by a command an attacker runs first. Prose such
// as "salt; pepper" never matches: the word after the separator must be one of these, mostly with its usual
// arguments.
var commandRe = regexp.MustCompile("(?:[;&|\\n`]|\\$\\()\\s*(?:" + strings.Join([]string{
	`rm\s+-[a-z]*[rf]`, `curl\s`, `wget\s`, `nc\s+-`, `ncat\s`, `netcat\s`, `bash\b`, `zsh\b`, `sh\s+-c\b`,
	`/bin/(?:ba|z|da|k)?sh\b`, `powershell\b`, `pwsh\b`, `cmd(?:\.exe)?\s*/[ck]\b`, `chmod\s+[+0-7ugoa]`, `chown\s`,
	`sudo\s`, `mkfifo\s`, `telnet\s`, `whoami\b`, `uname\s+-`, `ifconfig\b`, `ipconfig\b`, `nslookup\s`,
	`base64\s+-d`, `python[23]?\s+-c\b`, `perl\s+-e\b`, `ruby\s+-e\b`, `php\s+-r\b`, `node\s+-e\b`, `sleep\s+\d`,
	`cat\s+/`, `ping\s+-[cn]\b`, `id\s*(?:$|[;&|` + "`" + `])`, `echo\s+[^;&|\n]*[|>]`, `tftp\s`, `kill\s+-9`,
	`shutdown\b`, `reboot\b`,
}, "|") + ")|\\$\\{ifs\\}")

func detectCommand(_ *Guard, in *input, emit func(RuleID, int)) {
	if i := matchIndex(commandRe, in.folded()); i >= 0 {
		emit(RuleCommand, i)
	}
}

// --- helpers ---

func byteSet(chars string) (t [256]bool) {
	for i := 0; i < len(chars); i++ {
		t[chars[i]] = true
	}
	return t
}

func hasAnyByte(s string, set *[256]bool) bool {
	for i := 0; i < len(s); i++ {
		if set[s[i]] {
			return true
		}
	}
	return false
}

// containsFoldASCII: s contains word, ASCII case-insensitively (word is lowercase).
func containsFoldASCII[T byteSeq](s T, word string) bool {
	if len(word) == 0 {
		return true
	}
	c0 := word[0]
	for i := 0; i+len(word) <= len(s); i++ {
		if s[i]|0x20 != c0|0x20 && s[i] != c0 {
			continue
		}
		k := 0
		for k < len(word) && lowerByte(s[i+k]) == word[k] {
			k++
		}
		if k == len(word) {
			return true
		}
	}
	return false
}

func lowerByte(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
