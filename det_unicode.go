package inputguard

import (
	"unicode/utf8"
)

// Character-level Unicode rules: control characters, bidirectional overrides, invisible characters, invalid UTF-8.
// They look at the raw value (no decoding) and are cleaned by removing the offending characters.
//
// Every flagged character other than ASCII controls starts with one of four lead bytes (C2, E1, E2, EF), so text
// in any language is scanned without decoding runes: other multi-byte sequences are skipped by length.

func init() {
	registerDetector(&builtinDetector{
		name:         "unicode",
		rules:        []RuleID{RuleControlChar, RuleBidi, RuleInvisible, RuleInvalidUTF8},
		contexts:     allInspected,
		mayMatch:     func(g *Guard, raw string) bool { return firstUnicodeIssue(g, raw).kind != uniNone },
		bodyMayMatch: unicodeBodyMayMatch,
		detect:       detectUnicode,
		clean:        cleanChars,
	})
}

type uniKind uint8

const (
	uniNone uniKind = iota
	uniControl
	uniBidi
	uniInvisible
	uniInvalid
)

type uniIssue struct {
	kind uniKind
	at   int
}

// classifyRune: which character-level rule a rune falls under. \t \n \r are text; ZWJ (U+200D) builds emoji.
func classifyRune(r rune) uniKind {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return uniNone
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return uniControl
	case (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
		return uniBidi
	}
	switch r {
	case 0x00ad, 0x180e, 0x200b, 0x200c, 0x200e, 0x200f, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff:
		return uniInvisible
	}
	return uniNone
}

// classifyAt classifies the character at s[i] (lead byte c ≥ 0x80) from its bytes, without decoding. Returns the
// kind and the sequence length to skip (1 for a byte that cannot start a valid sequence).
func classifyAt[T byteSeq](s T, i int) (uniKind, int) {
	c := s[i]
	n := len(s)
	switch {
	case c < 0xC2:
		return uniNone, 1 // continuation byte or invalid lead (validity is checked separately)
	case c < 0xE0:
		if c == 0xC2 && i+1 < n && (s[i+1] <= 0x9F || s[i+1] == 0xAD) {
			if s[i+1] == 0xAD {
				return uniInvisible, 2
			}
			if s[i+1] >= 0x80 {
				return uniControl, 2
			}
		}
		return uniNone, 2
	case c < 0xF0:
		if i+2 < n {
			b1, b2 := s[i+1], s[i+2]
			switch c {
			case 0xE1:
				if b1 == 0xA0 && b2 == 0x8E {
					return uniInvisible, 3 // U+180E
				}
			case 0xE2:
				switch {
				case b1 == 0x80 && (b2 >= 0xAA && b2 <= 0xAE):
					return uniBidi, 3 // U+202A–202E
				case b1 == 0x80 && (b2 == 0x8B || b2 == 0x8C || b2 == 0x8E || b2 == 0x8F):
					return uniInvisible, 3 // U+200B, 200C, 200E, 200F
				case b1 == 0x81 && (b2 >= 0xA6 && b2 <= 0xA9):
					return uniBidi, 3 // U+2066–2069
				case b1 == 0x81 && (b2 >= 0xA0 && b2 <= 0xA4):
					return uniInvisible, 3 // U+2060–2064
				}
			case 0xEF:
				if b1 == 0xBB && b2 == 0xBF {
					return uniInvisible, 3 // U+FEFF
				}
			}
		}
		return uniNone, 3
	}
	return uniNone, 4
}

// firstUnicodeIssue returns the first character an ENABLED rule flags.
func firstUnicodeIssue(g *Guard, s string) uniIssue {
	ctrl, bidi, invis, inval := g.ruleOn(RuleControlChar), g.ruleOn(RuleBidi), g.ruleOn(RuleInvisible), g.ruleOn(RuleInvalidUTF8)
	var bad = -1
	if inval && !utf8.ValidString(s) {
		bad = firstInvalid(s)
	}
	for i := 0; i < len(s); {
		if bad >= 0 && i >= bad {
			return uniIssue{uniInvalid, bad}
		}
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			i++
			continue
		}
		if c < 0x80 {
			if ctrl && c != '\t' && c != '\n' && c != '\r' {
				return uniIssue{uniControl, i}
			}
			i++
			continue
		}
		k, size := classifyAt(s, i)
		switch {
		case k == uniControl && ctrl, k == uniBidi && bidi, k == uniInvisible && invis:
			return uniIssue{k, i}
		}
		i += size
	}
	if bad >= 0 {
		return uniIssue{uniInvalid, bad}
	}
	return uniIssue{}
}

func firstInvalid(s string) int {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return -1
}

func detectUnicode(_ *Guard, in *input, emit func(RuleID, int)) {
	s := in.raw
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		var k uniKind
		if r == utf8.RuneError && size == 1 {
			k = uniInvalid
		} else {
			k = classifyRune(r)
		}
		if k != uniNone {
			emit(ruleForUni(k), i)
		}
		i += size
	}
}

func ruleForUni(k uniKind) RuleID {
	switch k {
	case uniControl:
		return RuleControlChar
	case uniBidi:
		return RuleBidi
	case uniInvisible:
		return RuleInvisible
	case uniInvalid:
		return RuleInvalidUTF8
	}
	return ""
}

// stripUnicodeIssues removes characters of the given kinds, replacing invalid UTF-8 with U+FFFD (what a JSON
// decoder does).
func stripUnicodeIssues(s string, drop [5]bool) string {
	var out []byte
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		var k uniKind
		if r == utf8.RuneError && size == 1 {
			k = uniInvalid
		} else {
			k = classifyRune(r)
		}
		if k != uniNone && drop[k] {
			if out == nil {
				out = make([]byte, 0, len(s))
				out = append(out, s[:i]...)
			}
			if k == uniInvalid {
				out = append(out, "�"...)
			}
			i += size
			continue
		}
		if out != nil {
			out = append(out, s[i:i+size]...)
		}
		i += size
	}
	if out == nil {
		return s
	}
	return string(out)
}

// unicodeBodyMayMatch: a raw JSON body carries these characters raw or as \uXXXX / \b / \f escapes.
func unicodeBodyMayMatch(g *Guard, b []byte) bool {
	if g.ruleOn(RuleInvalidUTF8) && !utf8.Valid(b) {
		return true
	}
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c >= 0x20 && c < 0x7f && c != '\\':
			i++
		case c == '\\':
			if i+1 < len(b) {
				switch b[i+1] {
				case 'u':
					if v, ok := hex4(b, i+2); ok && classifyRune(rune(v)) != uniNone {
						return true
					}
					i += 6
					continue
				case 'b', 'f':
					return true
				}
			}
			i += 2
		case c < 0x80:
			if c != '\t' && c != '\n' && c != '\r' {
				return true
			}
			i++
		default:
			k, size := classifyAt(b, i)
			if k != uniNone {
				return true
			}
			i += size
		}
	}
	return false
}
