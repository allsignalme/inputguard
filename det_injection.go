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
		switch c := s[i]; {
		case c == '%' || c == '&' || c == '\\' || c == 0xEF:
			return true
		case c < 0x20 && c != '\t' && c != '\n' && c != '\r', c == 0x7f:
			return true // removed by Normalize: it can split a keyword (w\x7findow)
		case c == 0xC2 && i+1 < len(s) && (s[i+1] <= 0x9F || s[i+1] == 0xAD):
			return true // C1 control, soft hyphen
		case (c == 0xE1 || c == 0xE2) && i+2 < len(s) &&
			((c == 0xE1 && s[i+1] == 0xA0 && s[i+2] == 0x8E) || (c == 0xE2 && isInvisibleE2(s[i+1], s[i+2]))):
			return true // zero-width, bidi
		}
	}
	return false
}

// --- SQL ---

const q = "['\"`]" // a quote that can close a SQL string or identifier

// sqlFamilies: each pattern family runs only when the literals it needs are present in the lowercased decoded
// value (a gate costs a few substring searches; the regular expression costs far more).
var sqlFamilies = []struct {
	gate func(f string, quote bool) bool
	re   *regexp.Regexp
}{
	{ // Tautology after a closing quote or parenthesis: ' or 1=1, ") or ("a"="a, ' or ''=', ' || 'x' like 'x,
		// ' or username='admin, ' or true--. Both sides of the comparison are literals (or a name compared with a
		// quoted literal), so that prose such as "(good condition) or like new", "(size 42) and price >= 100" or
		// "'Hot' or 'New' = tag" is not one.
		func(f string, quote bool) bool {
			return (quote || strings.IndexByte(f, ')') >= 0) && (hasWord(f, "or") || hasWord(f, "and") ||
				hasWord(f, "xor") || strings.Contains(f, "||") || strings.Contains(f, "&&"))
		},
		regexp.MustCompile("(?:" + q + `|\))\s*(?:(?:or|and|xor)\b|\|\||&&)\s*(?:not\s+)?\(*\s*(?:` +
			`(?:'[^']*'|"[^"]*"|\d+(?:\.\d+)?|true|false|null)\s*` +
			`(?:=|<>|!=|<=?|>=?|\blike\b|\bis\b|\bin\b|\bbetween\b|\bregexp\b|\brlike\b)\s*` +
			`(?:['"\d(]|true\b|false\b|null\b|not\b)` +
			`|[a-z_][\w.$]*\s*(?:=|<>|!=|\blike\b)\s*['"])` +
			`|` + q + `\s*(?:or|\|\|)\s+(?:true|1|not\s+false)\s*(?:--|#|/\*|;|$)`),
	},
	{ // Numeric tautology: 1 or 1=1 (equality: "10 or 20 > 5 items" is prose).
		func(f string, _ bool) bool { return hasWord(f, "or") && strings.IndexByte(f, '=') >= 0 },
		regexp.MustCompile(`\b\d+\s+or\s+\d+\s*=\s*\d+`),
	},
	{ // A comment right after a quote that closes a value ends the query: admin'--, admin' -- (at the end), admin'#,
		// 1')--, x'/*. An inch mark before a dash in prose (55" -- 4K) is followed by more text, and a quote that
		// opens a string ("-----BEGIN PRIVATE KEY-----") closes nothing.
		func(f string, quote bool) bool {
			return quote && (strings.Contains(f, "--") || strings.IndexByte(f, '#') >= 0 || strings.Contains(f, "/*"))
		},
		regexp.MustCompile(`(?:^|[\w)])` + q + `\)?(?:--|\s*;\s*--|\s*--\s*$|\s*#\s*$|\s*/\*)`),
	},
	{ // UNION-based extraction: UNION [ALL] SELECT followed by what a select list starts with (*, NULL, a number, a
		// literal, a variable, a column list, a function, FROM). "the European Union (select countries only)" is prose.
		func(f string, _ bool) bool { return strings.Contains(f, "union") && strings.Contains(f, "select") },
		regexp.MustCompile(`\bunion\b(?:\s|/\*.*?\*/|\()+(?:(?:all|distinct)\b(?:\s|/\*.*?\*/)*)?select\b` +
			`(?:\s|/\*.*?\*/|\()+(?:\*|null\b|\d|@|'|"|[\w.]+\s*(?:,|\(|\bfrom\b))`),
	},
	{ // Stacked queries. Statements that only SQL uses after any ";"; SELECT … FROM, DELETE FROM, INSERT INTO and
		// UPDATE … SET only right after a quote, a number or ")" (the end of the injected value), since "Googlebot;
		// select pages from sitemap" is prose.
		func(f string, _ bool) bool { return stackedKeyword(f) },
		regexp.MustCompile(`;\s*(?:drop\s+(?:table|database|schema|view|index|user|function|procedure)\b|` +
			`truncate\s+table\b|alter\s+(?:table|database|user)\b|exec(?:ute)?\s*(?:xp_|sp_|master\.|\()|` +
			`shutdown\s*(?:;|--|$|with\b)|declare\s+@|create\s+(?:table|user|database|function|procedure|trigger|login)\b|` +
			`grant\s+(?:all|select|insert|update|delete|execute)\b|waitfor\s+delay\b)` +
			`|(?:` + q + `|\)|\d)\s*;\s*(?:select\s[\s\S]*?\bfrom\b|delete\s+from\b|insert\s+into\b|` +
			`update\s+[\w.` + "`" + `"\[\]]+\s+set\b)`),
	},
	{ // Time-based blind injection; catalog and dangerous-function access.
		func(f string, _ bool) bool {
			for _, w := range sqlCatalog {
				if strings.Contains(f, w) {
					return true
				}
			}
			return false
		},
		regexp.MustCompile(strings.Join([]string{
			`\b(?:sleep|pg_sleep)\s*\(\s*\d+(?:\.\d+)?\s*\)`,
			`\bbenchmark\s*\(\s*\d+\s*,`,
			`\bwaitfor\s+(?:delay|time)\s+'`,
			`\bdbms_(?:pipe\.receive_message|lock\.sleep)\b`,
			`\b(?:information_schema|xp_cmdshell|sp_executesql|sp_oacreate|pg_catalog|sqlite_master|utl_http|utl_inaddr)\b`,
			`\bsys\.(?:objects|tables|columns|databases|sysobjects)\b`,
			`\bmysql\.user\b`,
			`\bload_file\s*\(`,
			`\binto\s+(?:out|dump)file\b`,
			`@@(?:version|datadir|hostname|basedir)\b`,
			`\b(?:extractvalue|updatexml)\s*\(`,
			`\bchar\s*\(\s*\d+(?:\s*,\s*\d+){3,}\s*\)`,
		}, "|")),
	},
}

// stackedKeyword: a ";" followed by a statement keyword.
func stackedKeyword(f string) bool {
	for i := strings.IndexByte(f, ';'); i >= 0; {
		j := i + 1
		for j < len(f) && isRESpace(f[j]) {
			j++
		}
		for _, k := range []string{"drop", "truncate", "alter", "delete", "insert", "update", "exec", "shutdown",
			"declare", "select", "create", "grant", "waitfor"} {
			if strings.HasPrefix(f[j:], k) {
				return true
			}
		}
		next := strings.IndexByte(f[j:], ';')
		if next < 0 {
			return false
		}
		i = j + next
	}
	return false
}

// Raw-value prefilter for SQL: the bytes some pattern needs, then the keywords of those that need no punctuation,
// then the catalog names (looked for only when their "_" or "." is there).
var (
	sqlBytes      = byteSet("'\"`;=<>()@#")
	sqlPlainWords = []string{"union", "outfile", "dumpfile"}
	sqlUnderscore = []string{
		"information_schema", "xp_cmdshell", "sp_executesql", "sp_oacreate", "pg_catalog", "sqlite_master",
		"utl_http", "utl_inaddr", "dbms_", "load_file",
	}
	sqlDot = []string{"sys.", "mysql.user"}
)

func mayHaveSQL(s string) bool {
	if mayBeEncoded(s) || hasAnyByte(s, &sqlBytes) || containsAnyFold(s, sqlPlainWords) {
		return true
	}
	return (strings.IndexByte(s, '_') >= 0 && containsAnyFold(s, sqlUnderscore)) ||
		(strings.IndexByte(s, '.') >= 0 && containsAnyFold(s, sqlDot))
}

func containsAnyFold(s string, words []string) bool {
	for _, w := range words {
		if containsFoldASCII(s, w) {
			return true
		}
	}
	return false
}

// sqlCatalog: literals the time-based and catalog patterns need.
var sqlCatalog = []string{
	"sleep", "benchmark", "waitfor", "dbms_", "information_schema", "xp_cmdshell", "sp_executesql", "sp_oacreate",
	"pg_catalog", "sqlite_master", "utl_http", "utl_inaddr", "sys.", "mysql.user", "load_file", "outfile",
	"dumpfile", "@@", "extractvalue", "updatexml", "char(", "char (",
}

// hasWord: w occurs in s between non-alphanumeric characters.
func hasWord(s, w string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		k := j + len(w)
		if (j == 0 || !isWordByte(s[j-1])) && (k == len(s) || !isWordByte(s[k])) {
			return true
		}
		i = j + 1
	}
}

func isWordByte(c byte) bool {
	return c == '_' || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
}

func detectSQL(_ *Guard, in *input, emit func(RuleID, int)) {
	f := in.folded()
	quote := strings.ContainsAny(f, "'\"`")
	best := -1
	for _, fam := range sqlFamilies {
		if !fam.gate(f, quote) {
			continue
		}
		if i := matchIndex(fam.re, f); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	if best >= 0 {
		emit(RuleSQLInjection, best)
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

func detectTraversal(_ *Guard, in *input, emit func(RuleID, int)) {
	if i := overlongAt(in.raw); i >= 0 {
		emit(RulePathTraversal, -1) // offset in the raw value, not in the decoded one
		return
	}
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
			dots := k - i
			if k < len(f) && f[k] == ';' { // ..;/ (path parameter, Tomcat / Jetty)
				for k < len(f) && !isPathSep(f[k]) {
					k++
				}
			}
			// ".." alone or before a separator; three or more dots only before one (....// slips past filters that
			// strip "../"; a trailing "..." is an ellipsis).
			if (k < len(f) && isPathSep(f[k])) || (k == len(f) && dots == 2) {
				emit(RulePathTraversal, i)
				return
			}
			i = k
			continue
		}
		i += 2
	}
	for k := 0; k < len(f); k++ {
		if isPathSep(f[k]) && sepRunStart(f, k) && sensitivePathAt(f, k) {
			emit(RulePathTraversal, k)
			return
		}
	}
}

// overlongAt: the offset of an overlong UTF-8 sequence written with percent-encoding (%c0%af, %e0%80%ae, nested
// %25c0%25af…), or -1. Old decoders turned these into / \ and .; no legitimate input contains them, and Normalize
// replaces them with U+FFFD, so they are looked for before decoding.
func overlongAt(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		j := pctSkip25(s, i+1)
		if j+1 >= len(s) {
			continue
		}
		v, ok := hexPair(s[j], s[j+1])
		if !ok {
			continue
		}
		switch v {
		case 0xC0, 0xC1:
			return i
		case 0xE0:
			if k := j + 2; k < len(s) && s[k] == '%' {
				k = pctSkip25(s, k+1)
				if k+1 < len(s) {
					if w, ok := hexPair(s[k], s[k+1]); ok && w >= 0x80 && w <= 0x9F {
						return i
					}
				}
			}
		}
	}
	return -1
}

// pctSkip25 skips the "25" of nested percent-encoding (%2525…) at s[j:].
func pctSkip25(s string, j int) int {
	for n := 0; n < 3 && j+1 < len(s) && s[j] == '2' && s[j+1] == '5'; n++ {
		j += 2
	}
	return j
}

// --- Shell commands ---

// commandRe: a command separator ( ; & | newline ` $( ) followed by a command an attacker runs first, with the
// arguments it usually takes; or a command substitution ($(…), `…`) of a probing command; or ${IFS}. Prose such
// as "salt; pepper", "Bước 1\nReboot router", "Name | ID" or "sku;id;title" never matches.
var commandRe = regexp.MustCompile("(?:[;&|\\n`]|\\$\\()\\s*(?:" + strings.Join([]string{
	`rm\s+-[a-z]*[rf]`, `curl\s+(?:-|https?:|ftp:|file:)`, `wget\s+(?:-|https?:|ftp:)`, `nc\s+-`, `ncat\s`,
	`netcat\s`, `(?:ba|z|da|k)?sh\s+-[ci]\b`, `/bin/(?:ba|z|da|k)?sh\b`, `powershell\b`, `pwsh\b`,
	`cmd(?:\.exe)?\s*/[ck]\b`, `chmod\s+[+0-7ugoa]`, `chown\s+\w`, `sudo\s+\w`, `mkfifo\s`, `telnet\s+\w`,
	`whoami\b`, `uname\s+-`, `ifconfig\b`, `ipconfig\b`, `nslookup\s+\w`, `base64\s+-d`, `python[23]?\s+-c\b`,
	`perl\s+-e\b`, `ruby\s+-e\b`, `php\s+-r\b`, `node\s+-e\b`, `sleep\s+\d+\s*(?:$|[;&|)` + "`" + `])`, `cat\s+/`,
	`ping\s+-[cn]\b`, `echo\s+[^;&|\n]*[|>]`, `tftp\s`, `kill\s+-9`, `(?:shutdown|reboot)\s+-`,
}, "|") + ")|(?:\\$\\(|`)\\s*(?:id|whoami|uname|hostname|pwd|ls|cat|curl|wget|bash|sh|env|printenv)\\b|\\$\\{ifs\\}")

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
