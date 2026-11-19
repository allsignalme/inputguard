package inputguard

import "github.com/allsignalme/inputguard/internal/norm"

// MaybeDirty lọc nhanh body JSON cho chế độ Clean: một lượt qua byte thô, không cấp phát. false ⇒ chắc chắn
// CleanJSON không đổi gì ⇒ cho body đi nguyên vẹn (≈ mọi request thật).
//
// Là SIÊU TẬP của Detect với mọi dạng mã hoá trình duyệt hiểu (%XX, thực thể, escape JSON/JS, tab/xuống dòng
// trong từ, ký tự vô hình, full-width). Báo dư chỉ tốn đường chậm, không làm sai.
// Không phủ: dạng tương thích Unicode lạ (chữ toán học, chữ mũ…) — NFKC đưa về ASCII nhưng trình duyệt
// không coi là thẻ / thuộc tính / scheme, nên không phải mối nguy.
func xssMaybeDirtyBody(body []byte) bool { return scan(body, true) }

// maybeDirtyString: như MaybeDirty cho một chuỗi ĐÃ giải mã JSON — bộ duyệt dùng để bỏ qua chuỗi sạch.
func maybeDirtyString(s string) bool { return scan(s, false) }

type byteSeq interface{ ~string | ~[]byte }

// scanInteresting: byte có thể mở đầu một dấu hiệu. Byte khác (phần lớn body thật) bỏ qua bằng một lần tra bảng.
var scanInteresting = func() (t [256]bool) {
	for _, c := range []byte("<\\%&oOjJvVlLmMdD") {
		t[c] = true
	}
	for c := 0; c < 0x20; c++ {
		t[c] = true
	}
	t[0x7f], t[0xEF], t[0xE2], t[0xE1], t[0xC2] = true, true, true, true, true
	return t
}()

// scan: jsonBody=true ⇒ b là JSON thô (hiểu escape JSON).
func scan[T byteSeq](b T, jsonBody bool) bool {
	n := len(b)
	for i := 0; i < n; i++ {
		c := b[i]
		if !scanInteresting[c] {
			continue
		}
		switch c {
		case '<':
			return true
		case '\\':
			if !jsonBody {
				if i+1 < n && (b[i+1]|0x20 == 'u' || b[i+1]|0x20 == 'x') {
					return true // \u003c, \x3c — Normalize giải thành `<`
				}
				continue
			}
			skip, dirty := jsonEscape(b, i)
			if dirty {
				return true
			}
			i += skip
		case '%':
			if suspiciousPercentAt(b, i+1, 0) {
				return true
			}
		case '&':
			if entityAt(b, i+1) {
				return true
			}
		case 'o', 'O':
			if handlerAt(b, i, jsonBody) {
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
		case '\t', '\n', '\r':
			if i > 0 && i+1 < n && isLetter(b[i-1]) && isLetter(b[i+1]) {
				return true // tab/xuống dòng GIỮA từ: `java\tscript:`
			}
		case 0xEF: // U+FF00–U+FFFF: full-width `＜ ＂ ｊ…`, U+FE64 `﹤`, BOM
			if i+2 < n && (b[i+1] == 0xBC || b[i+1] == 0xBD || (b[i+1] == 0xB9 && b[i+2] == 0xA4) ||
				(b[i+1] == 0xBB && b[i+2] == 0xBF)) {
				return true
			}
		case 0xE2: // U+200B/C/E/F, U+202A–E, U+2060–4, U+2066–9 (ZWJ U+200D thì không — ghép emoji)
			if i+2 < n && isInvisibleE2(b[i+1], b[i+2]) {
				return true
			}
		case 0xE1: // U+180E
			if i+2 < n && b[i+1] == 0xA0 && b[i+2] == 0x8E {
				return true
			}
		case 0xC2: // C1 controls U+0080–009F, soft hyphen U+00AD
			if i+1 < n && (b[i+1] <= 0x9F || b[i+1] == 0xAD) {
				return true
			}
		default:
			if c < 0x20 || c == 0x7f {
				return true
			}
		}
	}
	return false
}

// jsonEscape xử lý escape JSON tại b[i] == '\\' trong body thô. Trả số byte cần bỏ qua thêm và có đáng ngờ không.
// Các escape vô hại phổ biến (`\"`, `\/`, `\u0026` của Ruby/Go cho `&` trong URL, `\u003e`) đi tiếp fast path.
func jsonEscape[T byteSeq](b T, i int) (int, bool) {
	n := len(b)
	if i+1 >= n {
		return 0, false
	}
	switch b[i+1] {
	case '"', '/':
		return 1, false
	case '\\':
		if i+2 < n && (b[i+2]|0x20 == 'u' || b[i+2]|0x20 == 'x') {
			return 0, true // chuỗi chứa `\u003c` / `\x3c` dạng chữ
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
			// `\u002f` / `\u0022` hiếm (encoder thường dùng `\/`, `\"`) nhưng giải ra ký tự biên của thuộc tính
			// sự kiện ⇒ để đường chậm xử lý.
		}
		return 0, true
	}
	return 0, true // \b \f (ký tự điều khiển) hoặc escape lạ
}

// handlerAt: biên + `on` + ≥3 chữ + khoảng trắng tuỳ ý + `=` / `%3d` tại i (vd ` onerror=`, `"onmouseover %3d`).
// Phải có biên như luật Detect — không thì `utm_content=` (có trong gần mọi URL quảng cáo) cũng bị tính.
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

// handlerBoundary: ký tự đứng trước `on…=` là biên của luật event_handler (đầu chuỗi, khoảng trắng, `/`, `;`,
// dấu nháy) — ở dạng thô, %XX hoặc escape JSON (`\"`, `\/` để lại đúng ký tự biên ở b[i-1]; `\t` `\n` `\r`).
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

// entityAt: thực thể HTML sinh ra ký tự neo của luật: `&#…`, `&lt`, `&Tab`, `&NewLine` (chen giữa scheme),
// `&equals` (dấu `=` của thuộc tính sự kiện). `&amp` chỉ tính khi sau nó lại là thực thể (mã hoá lồng
// `&amp;lt;`) — `?a=1&amp;b=2` (URL chép từ HTML) là dữ liệu thường.
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

// suspiciousPercentAt: b[j-1] là `%`; `%XX` giải ra ký tự neo của luật. `%25` (dấu %) / `%26` (&) chỉ tính khi
// PHÍA SAU thật sự là mã hoá lồng (`%253C`, `%26lt`) — `50%25_off`, `Tom %26 Jerry` là dữ liệu thường.
func suspiciousPercentAt[T byteSeq](b T, j, depth int) bool {
	if j+1 >= len(b) {
		return false
	}
	v, ok := hexPair(b[j], b[j+1])
	if !ok {
		return false
	}
	switch v {
	case '%': // sau một lớp giải mã thành `%` + b[j+2:] — xét tiếp như một `%XX` mới
		return depth < norm.MaxRounds && suspiciousPercentAt(b, j+2, depth+1)
	case '&':
		return entityAt(b, j+2)
	}
	return suspiciousPercent(v)
}

// percentIs: tại k là `%XX` giải ra đúng c.
func percentIs[T byteSeq](b T, k int, c byte) bool {
	if k+2 >= len(b) || b[k] != '%' {
		return false
	}
	v, ok := hexPair(b[k+1], b[k+2])
	return ok && v == c
}

// colonNext: sau i (bỏ tab/xuống dòng) là `:` hoặc dạng mã hoá của nó (`%3a`, `&colon;`, escape).
func colonNext[T byteSeq](b T, j int) bool {
	for j < len(b) && (b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
		j++
	}
	return j < len(b) && (b[j] == ':' || b[j] == '%' || b[j] == '&' || b[j] == '\\')
}

// dataTypeNear: trong vài byte sau `data` có kiểu MIME nguy hiểm (`data:text/html`, `data%3aapplication/…`).
func dataTypeNear[T byteSeq](b T, j int) bool {
	for k := j; k < len(b) && k <= j+8; k++ {
		if wordAt(b, k, "text/") || wordAt(b, k, "application/") || wordAt(b, k, "image/svg") {
			return true
		}
	}
	return false
}

// wordAt so khớp không phân biệt hoa thường (word viết thường, chỉ gồm chữ / `/`).
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

// suspiciousPercent: ký tự (sau giải %XX) có thể mở đầu dấu hiệu — `%` và `&` xét riêng ở suspiciousPercentAt.
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
