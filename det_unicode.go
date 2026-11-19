package inputguard

import (
	"unicode/utf8"
)

// Character-level Unicode rules: control characters, bidirectional overrides, invisible characters, invalid UTF-8.
// They look at the raw value (no decoding) and are cleaned by removing the offending characters. Every flagged
// character other than ASCII controls starts with one of four lead bytes (C2, E1, E2, EF), which is what the fast
// path looks for.

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
