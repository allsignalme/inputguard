// Package norm turns an input string into what a browser or interpreter would see: percent-encoding, HTML entities,
// JavaScript escapes, NFKC compatibility forms and invisible characters are decoded or removed, up to MaxRounds
// nested layers. Detectors run on the result; clean input is never rewritten.
package norm

import (
	"html"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// MaxRounds is the number of decoding rounds: enough for three nested layers (`%25253C`). A browser decodes one
// layer, so a fourth layer is no longer a working payload; stopping here bounds inputs built to loop.
const MaxRounds = 3

// Normalized is what a browser or interpreter would see of an input string.
type Normalized struct {
	// Decoded: %XX, HTML entities, \uXXXX / \xXX escapes and NFKC decoded, invisible characters removed, case
	// kept. Used as output only when the value has a finding (clean values are always kept verbatim).
	Decoded string
	// Folded: Decoded with ASCII lowercased, the SAME length in bytes, so an offset found in Folded is valid in
	// Decoded.
	Folded string
}

// Normalize decodes repeatedly until the string stops changing (at most MaxRounds rounds).
func Normalize(s string) Normalized {
	d := s
	for i := 0; i < MaxRounds; i++ {
		next := normalizeRound(d)
		if next == d {
			break
		}
		d = next
	}
	// The last round can produce new invisible characters (`%00`, `\u200b`): remove them too.
	d = StripInvisible(d)
	return Normalized{Decoded: d, Folded: ASCIILower(d)}
}

// normalizeRound decodes one layer. %XX before entities, so that `%26lt%3B` becomes `<` in a single round.
func normalizeRound(s string) string {
	s = StripInvisible(s)
	s = decodeJSEscapes(s)
	s = decodePercent(s)
	s = html.UnescapeString(s)
	if !norm.NFKC.IsNormalString(s) {
		s = norm.NFKC.String(s) // `＜ｓｃｒｉｐｔ＞` → `<script>`
	}
	return s
}

// IsInvisible: control and invisible characters inserted to split keywords (`java\u200bscript`). `\t \n \r`
// (ordinary text) and ZWJ U+200D (emoji sequences: families, flags…) are kept.
func IsInvisible(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return false
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069: // bidirectional controls
		return true
	}
	switch r {
	case 0x00ad, 0x180e, 0x200b, 0x200c, 0x200e, 0x200f, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff:
		return true
	}
	return false
}

func StripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if IsInvisible(r) {
			return -1
		}
		return r
	}, s)
}

// decodePercent decodes `%XX` leniently: only `%` + 2 hex digits, everything else is kept (url.QueryUnescape
// fails the whole string instead). `+` is kept. The result is always valid UTF-8.
func decodePercent(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	buf := make([]byte, 0, len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok := unhex(s[i+1]); ok {
				if lo, ok := unhex(s[i+2]); ok {
					buf = append(buf, hi<<4|lo)
					i += 2
					changed = true
					continue
				}
			}
		}
		buf = append(buf, s[i])
	}
	if !changed {
		return s
	}
	out := string(buf)
	if !utf8.ValidString(out) {
		out = strings.ToValidUTF8(out, "\uFFFD")
	}
	return out
}

// decodeJSEscapes decodes JavaScript escapes left in a value: `\uXXXX` (surrogate pairs included), `\u{X…}`,
// `\xXX`. Such a string becomes `<` once placed in a JavaScript string and written to the DOM.
func decodeJSEscapes(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			var r rune
			n := 0
			switch s[i+1] {
			case 'u':
				r, n = parseUnicodeEscape(s[i:])
			case 'x':
				if i+3 < len(s) {
					if hi, ok := unhex(s[i+2]); ok {
						if lo, ok := unhex(s[i+3]); ok {
							r, n = rune(hi<<4|lo), 4
						}
					}
				}
			}
			if n > 0 {
				b.WriteRune(r)
				i += n
				changed = true
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	if !changed {
		return s
	}
	return b.String()
}

// parseUnicodeEscape reads `\uXXXX` or `\u{X…}` at the start of s. It returns the rune and the bytes read (0 = not
// an escape). A lone surrogate becomes U+FFFD (never invalid UTF-8).
func parseUnicodeEscape(s string) (rune, int) {
	if len(s) >= 4 && s[2] == '{' {
		end := strings.IndexByte(s, '}')
		if end < 4 || end > 9 {
			return 0, 0
		}
		v, ok := hexValue(s[3:end])
		if !ok || v > utf8.MaxRune {
			return 0, 0
		}
		return validRune(rune(v)), end + 1
	}
	if len(s) < 6 {
		return 0, 0
	}
	v, ok := hexValue(s[2:6])
	if !ok {
		return 0, 0
	}
	r := rune(v)
	if r >= 0xd800 && r <= 0xdbff { // high surrogate: a low surrogate must follow
		if len(s) >= 12 && s[6] == '\\' && s[7] == 'u' {
			if lo, ok := hexValue(s[8:12]); ok && lo >= 0xdc00 && lo <= 0xdfff {
				return (r-0xd800)<<10 + (rune(lo) - 0xdc00) + 0x10000, 12
			}
		}
		return utf8.RuneError, 6
	}
	return validRune(r), 6
}

func validRune(r rune) rune {
	if !utf8.ValidRune(r) {
		return utf8.RuneError
	}
	return r
}

func hexValue(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	v := 0
	for i := 0; i < len(s); i++ {
		d, ok := unhex(s[i])
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

// ASCIILower lowers A–Z only and keeps the length in bytes (strings.ToLower can change it for some runes), so that
// offsets in Folded are valid in Decoded. Every rule keyword is ASCII (after NFKC), so this is enough.
func ASCIILower(s string) string {
	i := 0
	for i < len(s) && (s[i] < 'A' || s[i] > 'Z') {
		i++
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if 'A' <= b[i] && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
