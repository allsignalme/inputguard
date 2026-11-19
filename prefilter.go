package inputguard

import "github.com/allsignalme/inputguard/internal/norm"

type byteSeq interface{ ~string | ~[]byte }

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
		if jsEscapeAt(b, i+2) {
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
