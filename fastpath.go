package inputguard

import (
	"unicode/utf8"

	"github.com/allsignalme/inputguard/internal/norm"
)

// The fast path: one pass over the bytes of a body (or of one value) that answers "could an enabled rule match
// anywhere in here?" without decoding or allocating. Each rule group declares which trigger bits it needs; a guard
// combines the bits of its enabled groups, so a byte nobody cares about costs one table lookup.
//
// The answer must be a superset of what the detectors find, for every encoding they decode (JSON escapes in a body,
// then percent-encoding, HTML entities, JavaScript escapes and NFKC fullwidth forms in a value). Saying "maybe" too
// often only costs the slow path; saying "no" wrongly lets a payload through, which the fuzz tests guard against.

type fastBits uint8

const (
	fbXSS       fastBits = 1 << iota // tags, handlers, script schemes (and every invisible / control character)
	fbUnicode                        // control, bidi, invisible characters
	fbCRLF                           // CR/LF: raw in a value, escaped (\n \r \u000a) in a body
	fbCRLFEnc                        // CR/LF once decoded: %0d, &#10;, \x0a…
	fbTraversal                      // "..", encoded dots and separators, sensitive file names
	fbProto                          // body only: __proto__, prototype, \u-escaped letters in keys
	fbDollar                         // body only: $ (operator keys)
)

var fastTrigger = func() (t [256]fastBits) {
	set := func(bits fastBits, chars string) {
		for i := 0; i < len(chars); i++ {
			t[chars[i]] |= bits
		}
	}
	set(fbXSS, "<\\%&oOjJvVlLmMdD")
	// Invisible characters (controls, C1, soft hyphen, zero-width, bidi, BOM) are removed by Normalize, so they can
	// split anything a decoding group looks for ("..", a keyword): every such group triggers on them.
	const decoding = fbXSS | fbUnicode | fbTraversal | fbCRLFEnc
	for c := 0; c < 0x20; c++ {
		t[c] |= decoding
	}
	t[0x7f] |= decoding
	set(decoding, "\xC2\xE1\xE2\xEF")
	set(fbUnicode, "\\")
	set(fbCRLF, "\r\n\\")
	set(fbCRLFEnc, "\\%&\xEF")
	set(fbTraversal, "./\\%&\xE2\xEF")
	set(fbProto, "\\_y")
	set(fbDollar, "$")
	return t
}()

// scanFast reports whether b may hold something the groups in m flag. body: b is a raw JSON document (its string
// escapes not yet decoded); otherwise b is one decoded value.
func scanFast[T byteSeq](b T, body bool, m fastBits) bool {
	n := len(b)
	nested := nestedUnknown
	for i := 0; i < n; i++ {
		c := b[i]
		t := fastTrigger[c] & m
		if t == 0 {
			continue
		}
		switch c {
		case '<', '$':
			return true
		case 'o', 'O': // the letters are only triggers for the XSS group
			if handlerAt(b, i, body) {
				return true
			}
		case 'j', 'J':
			if wordAt(b, i, "javascript") {
				return true
			}
		case 'v', 'V':
			if wordAt(b, i, "vbscript") {
				return true
			}
		case 'l', 'L':
			if wordAt(b, i, "livescript") {
				return true
			}
		case 'm', 'M':
			if wordAt(b, i, "mocha") && colonNext(b, i+5) {
				return true
			}
		case 'd', 'D':
			if wordAt(b, i, "data") && dataTypeNear(b, i+4) {
				return true
			}
		case '_': // __proto__
			if i+8 < n && b[i+1] == '_' && wordAt(b, i+2, "proto") && b[i+7] == '_' && b[i+8] == '_' {
				return true
			}
		case 'y': // "prototype" as a whole string (the key under "constructor"), quotes possibly escaped
			if i >= 7 && i+3 < n && b[i-7] == '"' && wordAt(b, i-6, "prototype") && (b[i+3] == '"' || b[i+3] == '\\') {
				return true
			}
		case '\\':
			if !body {
				if valueEscapeHit(b, i, t) {
					return true
				}
				continue
			}
			hit, skip := bodyEscapeHit(b, i, t, &nested)
			if hit {
				return true
			}
			i += skip
		case '%':
			if percentHit(b, i, t) {
				return true
			}
		case '&':
			if ampHit(b, i, t) {
				return true
			}
		case '.':
			if i+1 < n && b[i+1] == '.' {
				return true
			}
		case '/':
			if (i == 0 || !isPathSep(b[i-1])) && sensitivePathAt(b, i) {
				return true
			}
		case '\t', '\n', '\r':
			if t&fbCRLF != 0 && !body && c != '\t' {
				return true
			}
			if t&fbXSS != 0 && wsRunInWord(b, i) {
				return true // tabs / line breaks inside a word: java\t\tscript:
			}
		case 0xEF: // EF AC: ligatures; EF B9: small forms; EF BC, EF BD: fullwidth ASCII; EF BB BF: BOM
			if i+2 < n {
				b1, b2 := b[i+1], b[i+2]
				if t&(fbXSS|fbTraversal|fbCRLFEnc) != 0 && (b1 == 0xAC || b1 == 0xB9 || b1 == 0xBC || b1 == 0xBD) {
					return true // Normalize folds these to ASCII letters, digits and punctuation
				}
				if b1 == 0xBB && b2 == 0xBF {
					return true // BOM
				}
			}
		case 0xE2:
			if i+2 < n {
				if isInvisibleE2(b[i+1], b[i+2]) {
					return true
				}
				if t&fbTraversal != 0 && b[i+1] == 0x80 && b[i+2] >= 0xA4 && b[i+2] <= 0xA6 {
					return true // ․ ‥ … fold to dots
				}
			}
		case 0xE1: // U+180E
			if i+2 < n && b[i+1] == 0xA0 && b[i+2] == 0x8E {
				return true
			}
		case 0xC2: // C1 controls, soft hyphen
			if i+1 < n && (b[i+1] <= 0x9F || b[i+1] == 0xAD) {
				return true
			}
		default: // other C0 controls and DEL
			return true
		}
	}
	return false
}

// valueEscapeHit: a backslash in a decoded value. \uXXXX and \xXX are JavaScript escapes Normalize decodes; a
// backslash is also a Windows path separator.
func valueEscapeHit[T byteSeq](b T, i int, t fastBits) bool {
	if i+1 < len(b) {
		if t&(fbXSS|fbCRLFEnc|fbTraversal) != 0 && jsEscapeAt(b, i+1) {
			return true
		}
	}
	return t&fbTraversal != 0 && (i == 0 || !isPathSep(b[i-1])) && sensitivePathAt(b, i)
}

// isURLStripped: tab, LF, CR — removed from URLs by browsers, so they can split a keyword.
func isURLStripped(c byte) bool { return c == '\t' || c == '\n' || c == '\r' }

// wsRunInWord: b[i] starts a run of raw tabs / line breaks with a letter on each side. Only the start of a run
// does the work, so a long run costs one pass.
func wsRunInWord[T byteSeq](b T, i int) bool {
	if i == 0 || isURLStripped(b[i-1]) || !isLetter(b[i-1]) {
		return false
	}
	j := i
	for j < len(b) && isURLStripped(b[j]) {
		j++
	}
	return j < len(b) && isLetter(b[j])
}

// escRunInWord: in a raw body, b[i] starts a run of escaped tabs / line breaks written with `width` backslashes
// (1: \t in a string, 2: \\t in a JSON document embedded in a string) with a letter on each side.
func escRunInWord[T byteSeq](b T, i, width int) bool {
	isEsc := func(k int) bool {
		if k < 0 || k+width >= len(b) {
			return false
		}
		for m := 0; m < width; m++ {
			if b[k+m] != '\\' {
				return false
			}
		}
		e := b[k+width]
		return e == 't' || e == 'n' || e == 'r'
	}
	step := width + 1
	if i == 0 || isEsc(i-step) || !isLetter(b[i-1]) {
		return false
	}
	j := i
	for isEsc(j) {
		j += step
	}
	return j < len(b) && isLetter(b[j])
}

// jsEscapeAt: b[k] starts what Normalize may decode as a JavaScript escape: u + 4 hex digits or u{…}, x + 2 hex
// digits. %, & and \ count as possible digits, since an outer encoding layer can supply them.
func jsEscapeAt[T byteSeq](b T, k int) bool {
	if k >= len(b) {
		return false
	}
	n := 0
	switch b[k] {
	case 'u':
		if k+1 < len(b) && b[k+1] == '{' {
			return true
		}
		n = 4
	case 'x':
		n = 2
	default:
		return false
	}
	for m := 1; m <= n; m++ {
		if k+m >= len(b) {
			return false
		}
		if c := b[k+m]; !isHexDigit(c) && c != '%' && c != '&' && c != '\\' {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	_, ok := unhex(c)
	return ok
}

// bodyEscapeHit: a JSON escape at b[i] in a raw body. Returns whether it may matter and how many bytes it spans
// beyond the backslash.
func bodyEscapeHit[T byteSeq](b T, i int, t fastBits, nested *int8) (bool, int) {
	n := len(b)
	if i+1 >= n {
		return false, 0
	}
	if t&fbXSS != 0 {
		if _, dirty := jsonEscape(b, i); dirty {
			return true, 0
		}
	}
	runStart := i == 0 || !isPathSep(b[i-1])
	switch e := b[i+1]; e {
	case 'n', 'r':
		return t&(fbCRLF|fbCRLFEnc) != 0, 1
	case 'b', 'f':
		return t&fbUnicode != 0, 1
	case '/':
		return t&fbTraversal != 0 && runStart && sensitivePathAt(b, i), 1
	case '\\':
		// An escaped backslash: in the value it starts a JavaScript escape or separates a Windows path; in a JSON
		// document embedded in a string it starts that document's own escapes (\\t \\n \\b \\u…).
		if i+2 < n {
			switch b[i+2] {
			case 'u', 'x':
				if t&(fbXSS|fbCRLFEnc|fbTraversal) != 0 && jsEscapeAt(b, i+2) {
					return true, 1
				}
				if e2, ok := hex4(b, i+3); ok && b[i+2] == 'u' && t&(fbUnicode|fbCRLF|fbProto|fbDollar) != 0 &&
					(classifyRune(rune(e2)) != uniNone || e2 == '\n' || e2 == '\r' || e2 == '$' ||
						(e2 < 0x80 && (isLetter(byte(e2)) || e2 == '_'))) {
					return true, 1
				}
			case 'b', 'f':
				if t&fbUnicode != 0 && mayNest(b, nested) {
					return true, 1
				}
			case 'n', 'r', 't':
				if t&fbCRLF != 0 && b[i+2] != 't' && mayNest(b, nested) {
					return true, 1
				}
				if t&fbXSS != 0 && escRunInWord(b, i, 2) && mayNest(b, nested) {
					return true, 1
				}
			}
		}
		return t&fbTraversal != 0 && runStart && sensitivePathAt(b, i), 1
	case 'u':
		v, ok := hex4(b, i+2)
		if !ok {
			return true, 0
		}
		switch {
		case t&fbUnicode != 0 && classifyRune(rune(v)) != uniNone:
			return true, 5
		case t&(fbCRLF|fbCRLFEnc) != 0 && (v == '\n' || v == '\r'):
			return true, 5
		case t&(fbCRLFEnc|fbTraversal) != 0 && v == '%':
			return percentHit(b, i+5, t), 5 // b[i+5] is the last hex digit, standing for the "%"
		case t&(fbCRLFEnc|fbTraversal) != 0 && v == '&':
			return ampHit(b, i+5, t), 5
		case t&fbTraversal != 0 && (v == '.' || v == '/' || v == '\\' || v == 0x2024 || v == 0x2025 ||
			v == 0x2026 || v == 0xff0e || v == 0xff0f || v == 0xff3c || v == 0xfe52):
			return true, 5
		case t&fbProto != 0 && v < 0x80 && (isLetter(byte(v)) || v == '_'):
			return true, 5
		case t&fbDollar != 0 && v == '$':
			return true, 5
		}
		return false, 5
	}
	return false, 1
}

const (
	nestedUnknown int8 = iota
	nestedYes
	nestedNo
)

// mayNest: the body holds an escaped quote, so a string may hold a JSON document whose own escapes (\\b \\t…)
// decode one level further. A Windows path (C:\\bin) in a body without one stays on the fast path. Computed once
// per scan.
func mayNest[T byteSeq](b T, state *int8) bool {
	if *state == nestedUnknown {
		*state = nestedNo
		for i := 0; i+1 < len(b); i++ {
			if b[i] == '\\' {
				if b[i+1] == '"' {
					*state = nestedYes
					break
				}
				i++
			}
		}
	}
	return *state == nestedYes
}

// percentHit: b[i] stands for "%". For the decoding groups, %XX matters when it decodes to a line break, a dot or
// separator, the start of an overlong or fullwidth form, or another encoding layer that does (%252e, %26%2346;).
// %u is IIS's %uXXXX.
func percentHit[T byteSeq](b T, i int, t fastBits) bool {
	if t&fbXSS != 0 && suspiciousPercentAt(b, i+1, 0) {
		return true
	}
	if t&(fbCRLFEnc|fbTraversal) == 0 {
		return false
	}
	if i+1 < len(b) && b[i+1]|0x20 == 'u' {
		return t&fbTraversal != 0
	}
	return pctPairHit(b, i+1, t, 0)
}

// pctPairHit: the hex pair at b[j] (after a "%") decodes to something that matters.
func pctPairHit[T byteSeq](b T, j int, t fastBits, depth int) bool {
	if j+1 >= len(b) {
		return false
	}
	v, ok := hexPair(b[j], b[j+1])
	if !ok {
		return false
	}
	switch v {
	case '%':
		return depth < norm.MaxRounds && pctPairHit(b, j+2, t, depth+1)
	case '&':
		return ampHit(b, j+1, t)
	case '\r', '\n':
		return t&fbCRLFEnc != 0
	case 0xC2: // C1 control or soft hyphen: removed by Normalize, it can join what surrounds it (%0%00A0)
		return pctByteIn(b, j+2, 0x80, 0x9F) || pctByteIs(b, j+2, 0xAD)
	case 0xE1: // U+180E
		return pctByteIs(b, j+2, 0xA0)
	case '\\': // a separator, or the start of a JavaScript escape decoded in the next round
		return true
	case 'u', 'x': // \%75002e: the escape letter itself encoded
		return j >= 2 && b[j-2] == '\\'
	case '.', '/', 0xC0, 0xC1:
		return t&fbTraversal != 0
	case 0xE0: // %e0%80%af overlong (second byte 80–9F)
		if t&fbTraversal == 0 || j+4 >= len(b) || b[j+2] != '%' {
			return false
		}
		v2, ok := hexPair(b[j+3], b[j+4])
		return ok && v2 >= 0x80 && v2 <= 0x9F
	case 0xEF: // ligatures (EF AC), small (EF B9) and fullwidth (EF BC, EF BD) forms
		return pctByteIs(b, j+2, 0xAC) || pctByteIs(b, j+2, 0xB9) || pctByteIs(b, j+2, 0xBC) || pctByteIs(b, j+2, 0xBD)
	case 0xE2: // ․ ‥ … (E2 80 A4–A6), zero-width and bidi characters
		if j+7 >= len(b) || b[j+2] != '%' || b[j+5] != '%' {
			return false
		}
		v2, ok2 := hexPair(b[j+3], b[j+4])
		v3, ok3 := hexPair(b[j+6], b[j+7])
		if !ok2 || !ok3 {
			return false
		}
		return isInvisibleE2(v2, v3) || (t&fbTraversal != 0 && v2 == 0x80 && v3 >= 0xA4 && v3 <= 0xA6)
	}
	if v < 0x20 || v == 0x7f {
		return true // a control character Normalize removes, joining what surrounds it
	}
	// An encoded letter or digit (encoders never produce them) can spell a file name: /%65tc/passwd.
	return t&fbTraversal != 0 && v < 0x80 && (isLetter(v) || ('0' <= v && v <= '9'))
}

// pctByteIn: b[k:] is "%XX" decoding to a byte in [lo, hi].
func pctByteIn[T byteSeq](b T, k int, lo, hi byte) bool {
	if k+2 >= len(b) || b[k] != '%' {
		return false
	}
	v, ok := hexPair(b[k+1], b[k+2])
	return ok && v >= lo && v <= hi
}

// pctByteIs: b[k:] is "%XX" decoding to c.
func pctByteIs[T byteSeq](b T, k int, c byte) bool {
	if k+2 >= len(b) || b[k] != '%' {
		return false
	}
	v, ok := hexPair(b[k+1], b[k+2])
	return ok && v == c
}

// ampHit: b[i] stands for "&". A numeric entity can be anything; named entities that decode to a dot, a
// separator, a line break or a percent sign; &amp; nests.
func ampHit[T byteSeq](b T, i int, t fastBits) bool {
	if t&fbXSS != 0 && entityAt(b, i+1) {
		return true
	}
	if t&(fbCRLFEnc|fbTraversal) == 0 {
		return false
	}
	j := i + 1
	for k := 0; k < 3 && wordAt(b, j, "amp;"); k++ {
		j += 4
	}
	if j < len(b) && (b[j] == '#' || b[j] == '%') || wordAt(b, j, "percnt") {
		return true
	}
	if t&fbCRLFEnc != 0 && wordAt(b, j, "newline") {
		return true
	}
	return t&fbTraversal != 0 && (wordAt(b, j, "period") || wordAt(b, j, "hellip") || wordAt(b, j, "nldr") ||
		wordAt(b, j, "mldr") || wordAt(b, j, "sol") || wordAt(b, j, "bsol"))
}

// sensitiveFiles: names that are only ever asked for to read secrets or probe a server. "/" stands for any run of
// / and \ (a body may also escape them: \/ and \\).
var sensitiveFiles = []string{
	"etc/passwd", "etc/shadow", "etc/hosts", "etc/group", "proc/self/", "proc/version", "win.ini", "boot.ini",
	"windows/system32", "var/run/secrets", ".aws/credentials", ".ssh/", ".git/config",
}

// sensitivePathAt: at b[i] a run of separators is followed by a sensitive file name (ASCII case-insensitive).
// Callers start at the first separator of a run, which keeps the scan linear.
func sensitivePathAt[T byteSeq](b T, i int) bool {
	j := skipSeparators(b, i)
	if j == i || j >= len(b) {
		return false
	}
	for _, w := range sensitiveByFirst[lowerByte(b[j])] {
		if pathWordAt(b, j, w) {
			return true
		}
	}
	return false
}

// sensitiveByFirst indexes sensitiveFiles by first byte.
var sensitiveByFirst = func() (t [256][]string) {
	for _, w := range sensitiveFiles {
		t[w[0]] = append(t[w[0]], w)
	}
	return t
}()

// pathWordAt: b[j:] spells w, "/" in w standing for a run of separators (with "." segments: /etc/./passwd), and
// the name ends there (/etc/group-tours is not /etc/group).
func pathWordAt[T byteSeq](b T, j int, w string) bool {
	for k := 0; k < len(w); k++ {
		if w[k] == '/' {
			if j >= len(b) || !isPathSep(b[j]) {
				return false
			}
			j = skipSeparators(b, j)
			continue
		}
		if j >= len(b) || lowerByte(b[j]) != w[k] {
			return false
		}
		j++
	}
	last := w[len(w)-1]
	return last == '/' || j >= len(b) || !(isWordByte(b[j]) || b[j] == '-')
}

// skipSeparators skips a run of / and \ and the "." segments between them, starting at a separator.
func skipSeparators[T byteSeq](b T, j int) int {
	if j >= len(b) || !isPathSep(b[j]) {
		return j
	}
	for j < len(b) {
		switch {
		case isPathSep(b[j]):
			j++
		case b[j] == '.' && j+1 < len(b) && isPathSep(b[j+1]):
			j += 2
		default:
			return j
		}
	}
	return j
}

func isPathSep(c byte) bool { return c == '/' || c == '\\' }

// fastValue: the fast check for one decoded value with the bits of its context.
func (g *Guard) fastValue(s string, bits fastBits) bool {
	if bits == 0 {
		return false
	}
	return scanFast(s, false, bits) || (bits&fbUnicode != 0 && g.invalidOn && !utf8.ValidString(s))
}
