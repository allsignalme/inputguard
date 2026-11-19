// Package legacy is the engine inputguard grew out of, kept unchanged (comments in Vietnamese, as written) as a
// test oracle: configured like it, the new engine must clean and flag the same way (see parity_test.go). It is not
// used at run time.
package legacy

import (
	"html"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// maxNormalizeRounds: số vòng giải mã tối đa — đủ cho mã hoá lồng 3 lớp (`%25253C`). Trình duyệt chỉ giải một
// lớp nên lớp thứ 4 trở lên không còn là payload chạy được; dừng ở đây để chặn chuỗi được dựng cho vòng lặp dài.
const maxNormalizeRounds = 3

// Normalized là dạng "trình duyệt sẽ thấy" của một chuỗi đầu vào.
type Normalized struct {
	// Decoded: đã giải %XX, thực thể HTML, escape \uXXXX/\xXX, NFKC, bỏ ký tự vô hình — giữ hoa/thường.
	// Chỉ dùng làm đầu ra khi chuỗi có finding (chuỗi sạch luôn giữ nguyên văn).
	Decoded string
	// Folded: Decoded hạ chữ thường ASCII, CÙNG độ dài byte ⇒ vị trí khớp luật trên Folded dùng thẳng cho Decoded.
	Folded string
}

// Normalize giải mã lặp tới khi chuỗi không đổi (tối đa maxNormalizeRounds vòng).
func Normalize(s string) Normalized {
	d := s
	for i := 0; i < maxNormalizeRounds; i++ {
		next := normalizeRound(d)
		if next == d {
			break
		}
		d = next
	}
	// Vòng cuối có thể sinh ra ký tự vô hình mới (vd `%00`, `\u200b`) — bỏ nốt.
	d = stripInvisible(d)
	return Normalized{Decoded: d, Folded: asciiLower(d)}
}

// normalizeRound: một lớp giải mã. Thứ tự %XX trước thực thể để `%26lt%3B` ra `<` ngay trong một vòng.
func normalizeRound(s string) string {
	s = stripInvisible(s)
	s = decodeJSEscapes(s)
	s = decodePercent(s)
	s = html.UnescapeString(s)
	if !norm.NFKC.IsNormalString(s) {
		s = norm.NFKC.String(s) // `＜ｓｃｒｉｐｔ＞` → `<script>`
	}
	return s
}

// isInvisible: ký tự điều khiển / vô hình bị kẻ tấn công chèn để tách từ khoá (`java\u200bscript`).
// Giữ `\t \n \r` (văn bản hợp lệ) và ZWJ U+200D (ghép emoji gia đình, cờ…).
func isInvisible(r rune) bool {
	switch {
	case r == '\t' || r == '\n' || r == '\r':
		return false
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069: // điều khiển hướng chữ (bidi)
		return true
	}
	switch r {
	case 0x00ad, 0x180e, 0x200b, 0x200c, 0x200e, 0x200f, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xfeff:
		return true
	}
	return false
}

func stripInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if isInvisible(r) {
			return -1
		}
		return r
	}, s)
}

// decodePercent giải `%XX` khoan dung: chỉ giải đúng `%` + 2 hex, phần còn lại giữ nguyên (khác url.QueryUnescape
// trả lỗi cả chuỗi). `+` giữ nguyên. Kết quả luôn là UTF-8 hợp lệ.
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

// decodeJSEscapes giải escape kiểu JS còn sót trong giá trị: `\uXXXX` (kể cả cặp surrogate), `\u{X…}`, `\xXX`.
// Chuỗi kiểu này thành `<` khi được nhét vào chuỗi JS rồi ghi ra DOM.
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

// parseUnicodeEscape đọc `\uXXXX` hoặc `\u{X…}` ở đầu s. Trả rune + số byte đã đọc (0 = không phải escape).
// Surrogate đứng lẻ ⇒ U+FFFD (không bao giờ sinh UTF-8 hỏng).
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
	if r >= 0xd800 && r <= 0xdbff { // high surrogate — cần low surrogate ngay sau
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

// asciiLower chỉ hạ A–Z: giữ nguyên độ dài byte (strings.ToLower có thể đổi độ dài với vài rune Unicode) để vị trí
// khớp trên Folded dùng được cho Decoded. Từ khoá của mọi luật đều là ASCII (sau NFKC) nên vậy là đủ.
func asciiLower(s string) string {
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
