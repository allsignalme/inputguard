package inputguard

// Cross-site scripting rules, ported from the TASK-045 engine (social/backend/pkg/inputguard). The tag and event
// handler scanners are hand-written equivalents of reference regular expressions (checked by fuzz tests); the
// remaining rules are RE2 expressions gated by cheap anchor checks. Everything runs on norm.Normalized.Folded.

import (
	"regexp"
	"strings"
)

// Thẻ nguy hiểm ngay cả khi chưa đóng `>` (payload hay bị cắt cụt: `<iMg src=N onerror=…`).
// Sau tên thẻ phải là khoảng trắng, `/`, `>` hoặc hết chuỗi — đúng cách trình duyệt tách tên thẻ.
const dangerousTags = `script|iframe|frame|frameset|object|embed|applet|svg|math|img|image|style|link|meta|base|` +
	`body|html|head|xml|isindex|portal|noscript|template|xmp|plaintext|noembed|noframes|textarea|title|video|audio|` +
	`source|input|button|form|select|details|dialog|marquee|bgsound|layer|ilayer|keygen`

// Thẻ HTML thường — chỉ tính khi đóng đủ `>`; tên lạ như `<M>` (cỡ áo) hay `<3` không bị tính.
const knownTags = `a|abbr|acronym|address|area|article|aside|b|bdi|bdo|big|blink|blockquote|br|canvas|caption|` +
	`center|cite|code|col|colgroup|data|datalist|dd|del|dfn|dir|div|dl|dt|em|fieldset|figcaption|figure|font|` +
	`footer|h1|h2|h3|h4|h5|h6|header|hgroup|hr|i|ins|kbd|label|legend|li|listing|main|map|mark|menu|menuitem|meter|nav|nobr|` +
	`ol|optgroup|option|output|p|param|picture|pre|progress|q|rp|rt|ruby|s|samp|search|section|slot|small|span|` +
	`strike|strong|sub|summary|sup|table|tbody|td|tfoot|th|thead|time|tr|track|tt|u|ul|var|wbr`

// Thuộc tính sự kiện DOM — dùng cho dạng KHÔNG có dấu nháy đứng trước (` onerror=`), để "the onion=good",
// "online=1" không bị bắt. Dạng có nháy đứng trước (`" onxyz=`) thì bắt mọi tên on[a-z]{3,}.
const domEvents = `abort|afterprint|afterscriptexecute|animationcancel|animationend|animationiteration|animationstart|` +
	`auxclick|beforecopy|beforecut|beforeinput|beforeprint|beforescriptexecute|beforetoggle|beforeunload|begin|blur|` +
	`bounce|cancel|canplay|canplaythrough|change|click|close|contextmenu|copy|cuechange|cut|dblclick|drag|dragend|` +
	`dragenter|dragleave|dragover|dragstart|drop|durationchange|end|ended|error|finish|focus|focusin|focusout|` +
	`formdata|fullscreenchange|hashchange|input|invalid|keydown|keypress|keyup|load|loadeddata|loadedmetadata|` +
	`loadstart|message|mousedown|mouseenter|mouseleave|mousemove|mouseout|mouseover|mouseup|mousewheel|offline|` +
	`online|pagehide|pageshow|paste|pause|play|playing|pointercancel|pointerdown|pointerenter|pointerleave|` +
	`pointermove|pointerout|pointerover|pointerrawupdate|pointerup|popstate|progress|ratechange|repeat|reset|resize|` +
	`scroll|scrollend|search|securitypolicyviolation|seeked|seeking|select|selectionchange|selectstart|show|` +
	`slotchange|stalled|start|storage|submit|suspend|timeupdate|toggle|touchcancel|touchend|touchmove|touchstart|` +
	`transitioncancel|transitionend|transitionrun|transitionstart|unhandledrejection|unload|volumechange|waiting|` +
	`webkitanimationend|webkitanimationiteration|webkitanimationstart|webkittransitionend|wheel`

// urlStripped: ký tự trình duyệt BỎ khỏi URL trước khi tách scheme (WHATWG URL: tab, LF, CR). Dấu cách thì
// không — "java script:" không phải scheme hợp lệ nên không cần (và không nên) bắt.
const urlStripped = `[\t\n\r]*`

// spaced chèn urlStripped giữa các chữ: `java\tscript:` vẫn chạy trong href.
func spaced(word string) string {
	parts := make([]string, 0, len(word))
	for _, c := range word {
		parts = append(parts, regexp.QuoteMeta(string(c)))
	}
	return strings.Join(parts, urlStripped)
}

var (
	execSchemes = `(?:` + spaced("javascript") + `|` + spaced("vbscript") + `|` + spaced("livescript") + `|` +
		spaced("mocha") + `)` + urlStripped + `:`
	dangerousData = spaced("data") + urlStripped + `:\s*(?:text/html|text/javascript|text/xml|` +
		`application/(?:x-)?javascript|application/xhtml|image/svg\+xml)`
)

// mayHaveScheme: luật scheme cần `:` và một trong các từ javascript / vbscript / livescript / mocha / data —
// liền, hoặc bị tab / xuống dòng chen giữa (khi đó để regex quyết).
func mayHaveScheme(s string) bool {
	if strings.IndexByte(s, ':') < 0 {
		return false
	}
	return strings.ContainsAny(s, "\t\n\r") || strings.Contains(s, "script") || strings.Contains(s, "mocha") ||
		strings.Contains(s, "data")
}

var domEventSet = wordSet(domEvents)

// scanHandlers trả vị trí sớm nhất của luật event_handler (-1 = không có), tương đương hai regex:
//
//	["'`][\s/]*on[a-z]{3,}\s*=          (vị trí dấu nháy — thoát thuộc tính)
//	(?:^|[\s/;])(on(?:domEvents)\s*=)   (vị trí `on` — thuộc tính sự kiện không có nháy)
//
// (kiểm tương đương bằng FuzzScanHandlers_MatchesReferenceRegex). f đã hạ chữ thường ASCII.
func scanHandlers(f string) int {
	best := -1
	for p := 0; p+1 < len(f); p++ {
		next := strings.Index(f[p:], "on")
		if next < 0 {
			break
		}
		p += next
		if best >= 0 && p > best {
			break // dấu nháy của luật có nháy luôn đứng TRƯỚC `on` ⇒ không thể sớm hơn best nữa
		}
		q := p + 2
		for q < len(f) && isLowerASCII(f[q]) {
			q++
		}
		e := q
		for e < len(f) && isRESpace(f[e]) {
			e++
		}
		if e >= len(f) || f[e] != '=' {
			continue
		}
		name := f[p+2 : q]
		if len(name) >= 3 {
			b := p - 1
			for b >= 0 && (isRESpace(f[b]) || f[b] == '/') {
				b--
			}
			if b >= 0 && (f[b] == '"' || f[b] == '\'' || f[b] == '`') && (best < 0 || b < best) {
				best = b
			}
		}
		if domEventSet[name] && (p == 0 || isRESpace(f[p-1]) || f[p-1] == '/' || f[p-1] == ';') && (best < 0 || p < best) {
			best = p
		}
	}
	return best
}

// Scheme rules run on the folded value. Group 1 marks where the malicious part starts.
var (
	schemeAfterDelimiter = regexp.MustCompile("[\"'=(`]\\s*(" + execSchemes + `|` + dangerousData + `)`)
	schemeAtStart        = regexp.MustCompile(`^\s*(` + execSchemes + `\S)`)
	schemeAtStartURL     = regexp.MustCompile(`^\s*(` + execSchemes + `|` + dangerousData + `)`)
	templateRe           = regexp.MustCompile(`\{\{[\s\S]*?\}\}|\{%[\s\S]*?%\}|\$\{[^}]*\}|<%[\s\S]*?%>`)
	jsCallRe             = regexp.MustCompile(
		`\b(?:eval|atob|btoa|settimeout|setinterval|fromcharcode|unescape|decodeuricomponent|execscript)\s*\(` +
			`|\bnew\s+function\b|\bimport\s*\(|\.\s*(?:inner|outer)html\b` +
			`|\b(?:document|window|globalthis)\s*\.\s*(?:cookie|write|writeln|location|domain|open|eval|body|head|` +
			`createelement|getelementbyid|queryselector)`)
	jsBreakoutRe = regexp.MustCompile("[\"'`]\\s*[-+;,)\\]}|&*/%^]\\s*[a-z_$][\\w$.]*\\s*\\(")
)

var (
	dangerousTagSet = wordSet(dangerousTags)
	knownTagSet     = wordSet(knownTags)
)

func wordSet(alternation string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Split(alternation, "|") {
		m[w] = true
	}
	return m
}

// scanTags trả vị trí `<` sớm nhất của thẻ nguy hiểm và của thẻ thường (-1 = không có), tương đương hai regex:
//
//	tag_dangerous: </?(?:dangerousTags)(?:[\s/>]|$)
//	tag_generic:   </?(?:knownTags)(?:[\s/][^<>]*)?>  |  <[a-z][a-z0-9:-]*[\s/]+[a-z_:][-a-z0-9_:.]*\s*=
//	               |  <!--  |  <![cdata[  |  <!doctype  |  <?[a-z]
//
// (kiểm tương đương bằng FuzzScanTags_MatchesReferenceRegex). f đã hạ chữ thường ASCII.
func scanTags(f string) (dangerous, generic int) {
	dangerous, generic = -1, -1
	n := len(f)
	for i := 0; i < n && (dangerous < 0 || generic < 0); i++ {
		next := strings.IndexByte(f[i:], '<')
		if next < 0 {
			break
		}
		i += next
		j := i + 1
		if generic < 0 && (strings.HasPrefix(f[j:], "!--") || strings.HasPrefix(f[j:], "![cdata[") ||
			strings.HasPrefix(f[j:], "!doctype") || (j+1 < n && f[j] == '?' && isLowerASCII(f[j+1]))) {
			generic = i
		}
		closing := j < n && f[j] == '/'
		if closing {
			j++
		}
		k := j
		if k < n && isLowerASCII(f[k]) {
			k++
			for k < n && (isLowerASCII(f[k]) || ('0' <= f[k] && f[k] <= '9') || f[k] == ':' || f[k] == '-') {
				k++
			}
		}
		if k == j {
			continue
		}
		name := f[j:k]
		if dangerous < 0 && dangerousTagSet[name] && (k == n || isRESpace(f[k]) || f[k] == '/' || f[k] == '>') {
			dangerous = i
		}
		if generic < 0 && ((knownTagSet[name] && closesTag(f, k)) || (!closing && attrAssignFollows(f, k))) {
			generic = i
		}
	}
	return dangerous, generic
}

// closesTag: sau tên thẻ là `>`, hoặc [\s/] rồi các ký tự không phải `<` `>` tới `>`.
func closesTag(f string, k int) bool {
	if k >= len(f) {
		return false
	}
	if f[k] == '>' {
		return true
	}
	if !isRESpace(f[k]) && f[k] != '/' {
		return false
	}
	for k++; k < len(f); k++ {
		switch f[k] {
		case '>':
			return true
		case '<':
			return false
		}
	}
	return false
}

// attrAssignFollows: sau tên thẻ là [\s/]+, tên thuộc tính [a-z_:][-a-z0-9_:.]*, \s*, rồi `=`.
func attrAssignFollows(f string, k int) bool {
	n := len(f)
	start := k
	for k < n && (isRESpace(f[k]) || f[k] == '/') {
		k++
	}
	if k == start || k >= n || !(isLowerASCII(f[k]) || f[k] == '_' || f[k] == ':') {
		return false
	}
	for k++; k < n && (isLowerASCII(f[k]) || ('0' <= f[k] && f[k] <= '9') || strings.IndexByte("-_:.", f[k]) >= 0); k++ {
	}
	for k < n && isRESpace(f[k]) {
		k++
	}
	return k < n && f[k] == '='
}

func isLowerASCII(c byte) bool { return 'a' <= c && c <= 'z' }

// isRESpace: đúng lớp \s của RE2 (Go regexp): [\t\n\f\r ].
func isRESpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

func matchIndex(re *regexp.Regexp, s string) int {
	loc := re.FindStringSubmatchIndex(s)
	if loc == nil {
		return -1
	}
	if len(loc) >= 4 && loc[2] >= 0 {
		return loc[2]
	}
	return loc[0]
}
