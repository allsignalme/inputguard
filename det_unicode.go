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
		name:     "unicode",
		rules:    []RuleID{RuleControlChar, RuleBidi, RuleInvisible, RuleInvalidUTF8},
		contexts: allInspected,
		fast:     fbUnicode,
		detect:   detectUnicode,
		clean:    cleanChars,
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

// classifyAt classifies the character at s[i] (lead byte c >= 0x80) from its bytes, without decoding. Returns the
// kind and the number of bytes to skip: the sequence length, or only its well-formed prefix when it is truncated
// or invalid, so that an ASCII byte after a broken sequence is never skipped (validity is checked separately).
func classifyAt[T byteSeq](s T, i int) (uniKind, int) {
	c := s[i]
	want := 0
	switch {
	case c >= 0xC2 && c < 0xE0:
		want = 2
	case c >= 0xE0 && c < 0xF0:
		want = 3
	case c >= 0xF0 && c < 0xF5:
		want = 4
	default:
		return uniNone, 1 // continuation byte or byte that never starts a sequence
	}
	size := 1
	for size < want && i+size < len(s) && s[i+size]&0xC0 == 0x80 {
		size++
	}
	if size < want {
		return uniNone, size
	}
	switch want {
	case 2:
		if c == 0xC2 {
			switch b := s[i+1]; {
			case b == 0xAD:
				return uniInvisible, 2 // U+00AD soft hyphen
			case b <= 0x9F:
				return uniControl, 2 // C1 controls
			}
		}
	case 3:
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
	return uniNone, size
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
