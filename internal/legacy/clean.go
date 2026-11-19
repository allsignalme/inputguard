package legacy

import (
	"regexp"
	"strings"
	"unicode"
)

// Context: ngữ cảnh của một field — quyết định cách làm sạch khi có nội dung độc.
type Context int

const (
	// CtxText: chữ tự do ⇒ cắt từ chỗ độc, giữ phần sạch phía trước.
	CtxText Context = iota
	// CtxURL: URL ⇒ bỏ đúng tham số / fragment / đoạn path độc, giữ URL hợp lệ.
	CtxURL
	// CtxVerbatim: hash / định danh gửi Meta ⇒ có độc thì bỏ CẢ giá trị (sửa một ký tự là lệch hash).
	CtxVerbatim
	// CtxSecret: mật khẩu / token ⇒ Strict không soi (mật khẩu chứa gì cũng hợp lệ); bộ duyệt ở Clean xử lý như
	// CtxVerbatim. Không bao giờ log giá trị.
	CtxSecret
)

func (c Context) String() string {
	switch c {
	case CtxURL:
		return "url"
	case CtxVerbatim:
		return "verbatim"
	case CtxSecret:
		return "secret"
	}
	return "text"
}

// maxCleanPasses: cắt xong có thể lộ ra luật mới ở cuối phần còn lại (`abc<img` + `<script>` ⇒ cắt lần 1 còn
// `abc<img`, khớp `<img$`). Quá số lượt vẫn còn độc thì bỏ cả giá trị.
const maxCleanPasses = 3

var verbatimKeys = map[string]bool{
	"em": true, "ph": true, "fn": true, "ln": true, "ct": true, "st": true, "zp": true, "ge": true, "db": true,
	"email": true, "phone": true, "first_name": true, "last_name": true, "city": true, "state": true, "zip": true,
	"fbp": true, "fbc": true, "obj_fbp_fbc": true, "external_id": true, "ext_id": true, "event_id": true, "id": true,
	"oppref": true, "obref": true, "fbclid": true, "gclid": true, "ttclid": true, "msclkid": true,
	"client_id": true, "shopify_client_id": true,
	// Payload capi của dự án (capi/dto EventInput, body collect): cookie _adsig_bv, hash vân tay signals.fp, id nội dung.
	"bv": true, "fp": true, "content_id": true, "content_ids": true,
}

var secretKeys = map[string]bool{
	"token": true, "access_token": true, "refresh_token": true, "id_token": true,
	"api_key": true, "apikey": true, "authorization": true, "private_key": true,
	"dsn": true, // chuỗi kết nối DB (admin infra) chứa mật khẩu
}

var urlKeyRe = regexp.MustCompile(`(?:^|_)(?:url|uri|href|link|site|referrer|referer|landing|location|callback|redirect|website|src|origin)$`)

// Classify chọn ngữ cảnh theo tên khoá lá (không phân biệt hoa thường), rồi theo dạng giá trị.
func Classify(key, value string) Context {
	k := strings.ToLower(key)
	switch {
	case secretKeys[k] || strings.Contains(k, "password") || strings.Contains(k, "passwd") || strings.Contains(k, "secret"):
		return CtxSecret
	case verbatimKeys[k] || strings.HasSuffix(k, "_token") || strings.HasSuffix(k, "_id") ||
		strings.HasSuffix(k, "_ids") || strings.HasSuffix(k, "_hash"):
		return CtxVerbatim
	case urlKeyRe.MatchString(k) || looksLikeURL(value):
		return CtxURL
	}
	return CtxText
}

func looksLikeURL(v string) bool {
	return hasPrefixFold(v, "http://") || hasPrefixFold(v, "https://") || strings.HasPrefix(v, "//")
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// CleanString làm sạch một giá trị ở chế độ Clean. Trả (giá trị mới, các finding, có đổi không).
// Giá trị sạch luôn được trả NGUYÊN VĂN (không giải mã, không chuẩn hoá).
func CleanString(ctx Context, s string) (string, []Finding, bool) {
	if ctx == CtxSecret {
		return s, nil, false
	}
	var fs []Finding
	cleaned := s
	if i := indexControl(s); i >= 0 {
		cleaned = stripControl(s)
		fs = append(fs, Finding{Rule: RuleControlChar, Index: i})
	}
	opts := DetectOptions{URL: ctx == CtxURL}
	a := Analyze(cleaned, opts)
	if len(a.Findings) == 0 {
		if len(fs) == 0 {
			return s, nil, false
		}
		if ctx == CtxVerbatim {
			return "", fs, true
		}
		return cleaned, fs, true
	}
	fs = append(fs, a.Findings...)
	switch ctx {
	case CtxVerbatim:
		return "", fs, true
	case CtxURL:
		if out, ok := cleanURL(cleaned); ok {
			return out, fs, true
		}
	}
	return cleanText(cleaned, opts), fs, true
}

// strictFindings: chế độ Strict không sửa, chỉ báo — thêm luật template / js / scheme đầu giá trị.
func strictFindings(ctx Context, s string) []Finding {
	if ctx == CtxSecret {
		return nil
	}
	var fs []Finding
	if i := indexControl(s); i >= 0 {
		fs = append(fs, Finding{Rule: RuleControlChar, Index: i})
	}
	return append(fs, Detect(s, DetectOptions{Strict: true, URL: ctx == CtxURL})...)
}

// cleanText cắt từ vị trí độc sớm nhất, bỏ đuôi ký tự thoát ngữ cảnh, kiểm lại.
func cleanText(s string, opts DetectOptions) string {
	a := Analyze(s, opts)
	for pass := 0; pass < maxCleanPasses; pass++ {
		idx := FirstIndex(a.Findings)
		if idx < 0 {
			return a.Decoded
		}
		a = Analyze(strings.TrimRightFunc(a.Decoded[:idx], isBreakoutTail), opts)
	}
	if len(a.Findings) > 0 {
		return ""
	}
	return a.Decoded
}

// isBreakoutTail: ký tự hay đứng ngay trước payload để thoát ngữ cảnh (`"`, `'>`, `-->`, `=`…).
func isBreakoutTail(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune("'\"`<>/\\;=(-", r)
}

// cleanURL làm sạch giá trị có dạng URL (scheme://, //host, /path). ok=false ⇒ không phải dạng URL, người gọi
// làm sạch như text. Các phần sạch giữ nguyên văn (không url.Values.Encode — tránh sắp xếp / mã hoá lại).
func cleanURL(s string) (string, bool) {
	trimmed := strings.TrimLeftFunc(s, func(r rune) bool { return r <= ' ' })
	var prefix, rest string
	if scheme, after, ok := splitScheme(trimmed); ok {
		ls := strings.ToLower(scheme)
		if (ls != "http" && ls != "https") || !strings.HasPrefix(after, "//") {
			return "", true // javascript:, data:, vbscript:… hoặc http: thiếu //
		}
		auth, tail := splitAuthority(after[2:])
		if !cleanHost(auth) {
			return "", true
		}
		prefix, rest = scheme+"://"+auth, tail
	} else if strings.HasPrefix(trimmed, "//") {
		auth, tail := splitAuthority(trimmed[2:])
		if !cleanHost(auth) {
			return "", true
		}
		prefix, rest = "//"+auth, tail
	} else if strings.HasPrefix(trimmed, "/") {
		rest = trimmed
	} else {
		return "", false
	}

	rest, frag, hasFrag := strings.Cut(rest, "#")
	path, query, hasQuery := strings.Cut(rest, "?")
	out := prefix + cleanPath(path)
	if hasQuery {
		if q := cleanQuery(query); q != "" {
			out += "?" + q
		}
	}
	if hasFrag && !isDirty(frag, optsTextOnly) {
		out += "#" + frag
	}
	if isDirty(out, DetectOptions{URL: true}) {
		return "", true
	}
	return out, true
}

var optsTextOnly = DetectOptions{}

func isDirty(s string, opts DetectOptions) bool {
	return len(Detect(s, opts)) > 0
}

// splitScheme: `scheme:rest` theo RFC 3986 (chữ cái đầu, rồi chữ/số/+/./-), trước mọi `/ ? #`.
func splitScheme(s string) (string, string, bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || strings.ContainsAny(s[:i], "/?#") {
		return "", "", false
	}
	for j := 0; j < i; j++ {
		c := s[j]
		isAlpha := ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
		if !isAlpha && (j == 0 || !(('0' <= c && c <= '9') || c == '+' || c == '.' || c == '-')) {
			return "", "", false
		}
	}
	return s[:i], s[i+1:], true
}

func splitAuthority(s string) (string, string) {
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

func cleanHost(auth string) bool {
	return auth != "" && !strings.ContainsAny(auth, "<>\"'` \t\n\r\\{}|^") && !isDirty(auth, optsTextOnly)
}

// cleanPath giữ các đoạn path (kèm `/`) tới trước đoạn làm phần đã giữ trở nên độc — kiểm theo TIỀN TỐ tích luỹ
// nên payload trải qua nhiều đoạn (`'"--></style></script>…`) vẫn bị bắt.
func cleanPath(path string) string {
	if !isDirty(path, optsTextOnly) {
		return path
	}
	kept := ""
	for _, seg := range strings.SplitAfter(path, "/") {
		if isDirty(kept+seg, optsTextOnly) {
			break
		}
		kept += seg
	}
	return kept
}

// cleanQuery bỏ đúng các cặp `key=value` độc, giữ nguyên văn và nguyên thứ tự các cặp còn lại. Chỉ tách theo
// `&` (không theo `;`) để payload chứa `;` không bị xé thành mảnh trông sạch.
func cleanQuery(q string) string {
	if !isDirty(q, optsTextOnly) {
		return q
	}
	parts := strings.Split(q, "&")
	kept := parts[:0]
	for _, p := range parts {
		if !isDirty(p, optsTextOnly) {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "&")
}

// indexControl: vị trí ký tự điều khiển đầu tiên (C0 trừ \t \n \r, và DEL), -1 nếu không có.
func indexControl(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return i
		}
	}
	return -1
}

func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
