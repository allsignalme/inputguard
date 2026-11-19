package inputguard

import "github.com/allsignalme/inputguard/internal/norm"

type byteSeq interface{ ~string | ~[]byte }

// jsonEscape handles the JSON escape at b[i] == '\\' in a raw body. It returns how many more bytes to skip and
// whether the escape is suspicious. Common harmless escapes (`\"`, `\/`, the `\u0026` Ruby and Go write for `&` in
// URLs, `\u003e`) stay on the fast path.
func jsonEscape[T byteSeq](b T, i int) (int, bool) {
	n := len(b)
	if i+1 >= n {
		return 0, false
	}
	switch b[i+1] {
	case '"', '/':
		return 1, false
	case '\\':
		if jsEscapeAt(b, i+2) {
			return 0, true // the value holds a literal `\u003c` / `\x3c`
		}
		return 1, false
	case 'n', 't', 'r':
		if i > 0 && i+2 < n && isLetter(b[i-1]) && isLetter(b[i+2]) {
			return 0, true
		}
		return 1, false
	case 'u':
		if v, ok := hex4(b, i+2); ok {
			switch v {
			case '&':
				if entityAt(b, i+6) {
					return 0, true
				}
				return 5, false
			case '>':
				return 5, false
			}
			// `\u002f` / `\u0022` are rare (encoders write `\/`, `\"`) but decode to an event-handler boundary:
			// leave them to the slow path.
		}
		return 0, true
	}
	return 0, true // \b \f (control characters) or an unusual escape
}

// handlerAt: boundary + `on` + 3 or more letters + optional spaces + `=` / `%3d` at i (` onerror=`,
// `"onmouseover %3d`). The boundary is required as in the detector, or `utm_content=` (in nearly every ad URL)
// would count.
func handlerAt[T byteSeq](b T, i int, jsonBody bool) bool {
	n := len(b)
	if i+1 >= n || b[i+1]|0x20 != 'n' || !handlerBoundary(b, i) {
		return false
	}
	j := i + 2
	for j < n && isLetter(b[j]) {
		j++
	}
	if j-(i+2) < 3 {
		return false
	}
	for j < n {
		switch {
		case b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r' || b[j] == '\f':
			j++
			continue
		case b[j] == '%' && j+2 < n && b[j+1] == '2' && b[j+2] == '0':
			j += 3
			continue
		case jsonBody && b[j] == '\\' && j+1 < n && (b[j+1] == 't' || b[j+1] == 'n' || b[j+1] == 'r'):
			j += 2
			continue
		}
		break
	}
	return j < n && (b[j] == '=' || (b[j] == '%' && j+2 < n && b[j+1] == '3' && b[j+2]|0x20 == 'd'))
}

// handlerBoundary: the byte before `on…=` is an event_handler boundary (start, space, `/`, `;`, a quote), raw, as
// %XX or as a JSON escape (`\"` and `\/` leave the boundary itself at b[i-1]; `\t` `\n` `\r`).
func handlerBoundary[T byteSeq](b T, i int) bool {
	if i == 0 {
		return true
	}
	switch b[i-1] {
	case ' ', '\t', '\n', '\r', '\f', '/', ';', '"', '\'', '`':
		return true
	}
	if i >= 3 && b[i-3] == '%' {
		if v, ok := hexPair(b[i-2], b[i-1]); ok && (v == ' ' || v == '/' || v == ';' || v == '"' || v == '\'' || v == '`') {
			return true
		}
	}
	return i >= 2 && b[i-2] == '\\' && (b[i-1] == 't' || b[i-1] == 'n' || b[i-1] == 'r')
}

// entityAt: an HTML entity that yields an anchor character of the XSS rules: `&#…`, `&lt`, `&Tab`, `&NewLine`
// (inside a scheme), `&equals` (the `=` of an event handler). `&amp` counts only when another entity follows
// (nested `&amp;lt;`): `?a=1&amp;b=2`, a URL copied from HTML, is ordinary data.
func entityAt[T byteSeq](b T, j int) bool { return entityAtDepth(b, j, 0) }

func entityAtDepth[T byteSeq](b T, j, depth int) bool {
	if j >= len(b) {
		return false
	}
	if b[j] == '#' || percentIs(b, j, '#') {
		return true
	}
	if wordAt(b, j, "lt") || wordAt(b, j, "tab") || wordAt(b, j, "newline") || wordAt(b, j, "equals") {
		return true
	}
	if depth >= norm.MaxRounds || !wordAt(b, j, "amp") {
		return false
	}
	k := j + 3
	if k < len(b) && b[k] == ';' {
		k++
	} else if percentIs(b, k, ';') {
		k += 3
	}
	return entityAtDepth(b, k, depth+1)
}

// suspiciousPercentAt: b[j-1] is `%` and `%XX` decodes to an anchor character of the XSS rules. `%25` (%) and
// `%26` (&) count only when a nested encoding really follows (`%253C`, `%26lt`): `50%25_off` and `Tom %26 Jerry`
// are ordinary data.
func suspiciousPercentAt[T byteSeq](b T, j, depth int) bool {
	if j+1 >= len(b) {
		return false
	}
	v, ok := hexPair(b[j], b[j+1])
	if !ok {
		return false
	}
	switch v {
	case '%': // one decoding layer yields `%` + b[j+2:]: check it as a new `%XX`
		return depth < norm.MaxRounds && suspiciousPercentAt(b, j+2, depth+1)
	case '&':
		return entityAt(b, j+2)
	}
	return suspiciousPercent(v)
}

// percentIs: b[k:] is a `%XX` decoding to c.
func percentIs[T byteSeq](b T, k int, c byte) bool {
	if k+2 >= len(b) || b[k] != '%' {
		return false
	}
	v, ok := hexPair(b[k+1], b[k+2])
	return ok && v == c
}

// colonNext: after j (skipping tabs and line breaks) comes `:` or an encoding of it (`%3a`, `&colon;`, an escape).
func colonNext[T byteSeq](b T, j int) bool {
	for j < len(b) && (b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
		j++
	}
	return j < len(b) && (b[j] == ':' || b[j] == '%' || b[j] == '&' || b[j] == '\\')
}

// dataTypeNear: a dangerous MIME type follows `data` within a few bytes (`data:text/html`, `data%3aapplication/…`).
func dataTypeNear[T byteSeq](b T, j int) bool {
	for k := j; k < len(b) && k <= j+8; k++ {
		if wordAt(b, k, "text/") || wordAt(b, k, "application/") || wordAt(b, k, "image/svg") {
			return true
		}
	}
	return false
}

// wordAt matches word at b[i] ASCII case-insensitively. word is lowercase letters, digits, `/`, `.`, `;` or `#`
// (bytes that |0x20 leaves unchanged).
func wordAt[T byteSeq](b T, i int, word string) bool {
	if i+len(word) > len(b) {
		return false
	}
	for k := 0; k < len(word); k++ {
		if b[i+k]|0x20 != word[k] {
			return false
		}
	}
	return true
}

// suspiciousPercent: a decoded %XX byte that can start an XSS anchor (`%` and `&` are handled by
// suspiciousPercentAt).
func suspiciousPercent(v byte) bool {
	return v == '<' || v == '\\' || v < 0x20 || v == 0x7f || v == 0xef || isLetter(v)
}

func isInvisibleE2(b1, b2 byte) bool {
	switch b1 {
	case 0x80:
		return b2 == 0x8B || b2 == 0x8C || b2 == 0x8E || b2 == 0x8F || (b2 >= 0xAA && b2 <= 0xAE)
	case 0x81:
		return (b2 >= 0xA0 && b2 <= 0xA4) || (b2 >= 0xA6 && b2 <= 0xA9)
	}
	return false
}

func isLetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func hexPair(hi, lo byte) (byte, bool) {
	h, ok1 := unhex(hi)
	l, ok2 := unhex(lo)
	return h<<4 | l, ok1 && ok2
}

func hex4[T byteSeq](b T, j int) (int, bool) {
	if j+4 > len(b) {
		return 0, false
	}
	v := 0
	for k := j; k < j+4; k++ {
		d, ok := unhex(b[k])
		if !ok {
			return 0, false
		}
		v = v<<4 | int(d)
	}
	return v, true
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
