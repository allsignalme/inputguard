package legacy

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Mode: hành vi khi gặp nội dung độc.
type Mode int

const (
	// ModeClean: làm sạch rồi cho đi tiếp (ingest event storefront / app, chốt Kafka).
	ModeClean Mode = iota
	// ModeStrict: không sửa gì, chỉ báo finding ⇒ middleware trả 400 (API ghi cấu hình merchant / admin).
	ModeStrict
)

func (m Mode) String() string {
	if m == ModeStrict {
		return "strict"
	}
	return "clean"
}

// RuleControlChar: ký tự điều khiển C0 / DEL — do bộ làm sạch báo, không nằm trong Detect. Postgres từ chối
// `\u0000` trong jsonb/text nên cũng phải bỏ khỏi tên khoá.
const RuleControlChar RuleID = "control_char"

// RuleTooComplex: JSON quá sâu / quá nhiều chuỗi. Strict ⇒ ErrTooComplex; Clean ⇒ nhánh quá sâu thành null, chuỗi
// vượt ngưỡng có dấu hiệu bị bỏ (không bao giờ trả lại bản bẩn vì lý do cấu trúc).
const RuleTooComplex RuleID = "too_complex"

// keyPathSuffix thay một đoạn khoá trong path khi tên khoá không an toàn để in (xem safePathKey): tên khoá do client
// đặt — có thể là payload, PII hay dài cả MB — mà path đi vào log và thông điệp lỗi 400.
const keyPathSuffix = "[key]"

// maxPathKeyLen: khoá dài hơn thế in thành keyPathSuffix.
const maxPathKeyLen = 64

// Giới hạn cấu trúc JSON — chặn body dựng để làm chậm bộ duyệt. maxFindings: số finding giữ lại (log chỉ in 5
// field, lỗi 400 liệt kê từng field) — body dựng hàng vạn chỗ độc không làm phình bộ nhớ.
const (
	maxDepth    = 32
	maxStrings  = 20000
	maxFindings = 100
)

// ErrTooComplex: JSON quá sâu hoặc quá nhiều chuỗi — chỉ trả ở Strict (middleware trả 400).
var ErrTooComplex = errors.New("inputguard: JSON quá sâu hoặc quá nhiều chuỗi")

// FieldMatcher trả true khi path (vd `translations[0].description`) được miễn soi nội dung — cả cây con.
type FieldMatcher func(path string) bool

// PathFinding: một finding gắn với đường dẫn field. KHÔNG chứa giá trị (có thể là PII).
type PathFinding struct {
	Path    string
	Rule    RuleID
	Context Context
}

// Report: kết quả duyệt một body / payload.
type Report struct {
	Changed  bool
	Findings []PathFinding
}

// CleanJSON duyệt body JSON. Clean: trả body đã làm sạch (chỉ serialize lại khi có thay đổi — body sạch trả
// nguyên slice đầu vào). Strict: không sửa, chỉ báo. Body không phải JSON hợp lệ ⇒ trả nguyên, không lỗi
// (handler tự trả 400 khi bind).
//
// Clean đi fast path trước (MaybeDirty) — body sạch không bị decode. Strict luôn duyệt đủ: fast path không phủ
// luật riêng của Strict (template, lời gọi JS) và đường Strict (private/admin) lưu lượng thấp.
func CleanJSON(body []byte, mode Mode, exempt FieldMatcher) ([]byte, Report, error) {
	if mode == ModeClean && !MaybeDirty(body) {
		return body, Report{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // giữ nguyên số lớn (order_id > 2^53)
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return body, Report{}, nil
	}
	w := &walker{mode: mode, exempt: exempt}
	nv, _, err := w.walk(v, "", 0)
	w.finish()
	if err != nil {
		return body, w.report, err
	}
	if mode == ModeStrict || !w.report.Changed {
		return body, w.report, nil
	}
	out, err := encodeJSON(nv)
	if err != nil {
		return body, w.report, err
	}
	return out, w.report, nil
}

// CleanValue duyệt payload Go (map[string]interface{}, map[string]string, []interface{}, []string,
// []map[string]interface{}) và sửa TẠI CHỖ.
func CleanValue(v interface{}, mode Mode, exempt FieldMatcher) Report {
	w := &walker{mode: mode, exempt: exempt}
	_, _, _ = w.walk(v, "", 0) // ErrTooComplex chỉ có ở Strict (không sửa gì); Clean luôn duyệt hết
	w.finish()
	return w.report
}

type walker struct {
	mode    Mode
	exempt  FieldMatcher
	strings int
	report  Report
	segs    []PathSeg // đường dẫn tới node hiện tại — chỉ dựng thành chuỗi khi cần (finding / miễn trừ)
	// inExempt > 0: đang ở trong cây con được miễn soi NỘI DUNG — vẫn duyệt để kiểm tên khoá.
	inExempt int
	// tooComplexSeen: đã báo RuleTooComplex — chỉ một finding cho mọi nhánh quá sâu / chuỗi vượt ngưỡng.
	tooComplexSeen bool
}

// PathSeg: một bước của đường dẫn — khoá map (Index = -1) hoặc phần tử mảng (Index >= 0).
type PathSeg struct {
	Key   string
	Index int
}

func (w *walker) push(key string, idx int) { w.segs = append(w.segs, PathSeg{Key: key, Index: idx}) }
func (w *walker) pop()                     { w.segs = w.segs[:len(w.segs)-1] }

// path dựng `a.b[0].c` từ segs; khoá không an toàn để in thành `[key]` (vd `custom_data[key].x`). Khoá có `.`
// cũng vậy nên không thể giả path miễn trừ (khoá gốc "config.headers" ≠ path config.headers).
func (w *walker) path() string {
	var b strings.Builder
	for i, s := range w.segs {
		if s.Index >= 0 {
			b.WriteByte('[')
			b.WriteString(strconv.Itoa(s.Index))
			b.WriteByte(']')
			continue
		}
		if !safePathKey(s.Key) {
			b.WriteString(keyPathSuffix)
			continue
		}
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(s.Key)
	}
	return b.String()
}

// safePathKey: 1–maxPathKeyLen byte [A-Za-z0-9_-] — đủ cho mọi tên field của API, không chở được payload.
func safePathKey(k string) bool {
	if k == "" || len(k) > maxPathKeyLen {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !isLetter(c) && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func (w *walker) add(rule RuleID, ctx Context) {
	if len(w.report.Findings) < maxFindings {
		w.report.Findings = append(w.report.Findings, PathFinding{Path: w.path(), Rule: rule, Context: ctx})
	}
}

// addKey: finding ở tên khoá (khoá đang nằm trên đỉnh segs) — báo tại path cha + keyPathSuffix, kể cả khi tên khoá
// trông an toàn.
func (w *walker) addKey(rule RuleID) {
	if len(w.report.Findings) >= maxFindings {
		return
	}
	top := w.segs[len(w.segs)-1]
	w.segs = w.segs[:len(w.segs)-1]
	w.report.Findings = append(w.report.Findings, PathFinding{Path: w.path() + keyPathSuffix, Rule: rule, Context: CtxText})
	w.segs = append(w.segs, top)
}

// finish: map được duyệt theo thứ tự ngẫu nhiên ⇒ sắp findings một lần cho kết quả ổn định (log, lỗi 400).
func (w *walker) finish() {
	sort.SliceStable(w.report.Findings, func(i, j int) bool {
		return w.report.Findings[i].Path < w.report.Findings[j].Path
	})
}

// tooComplex: Clean gặp nhánh quá sâu / chuỗi vượt ngưỡng — báo một lần, đánh dấu đã đổi.
func (w *walker) tooComplex() {
	w.report.Changed = true
	if !w.tooComplexSeen {
		w.tooComplexSeen = true
		w.add(RuleTooComplex, CtxText)
	}
}

func (w *walker) exempted() bool {
	return w.exempt != nil && len(w.segs) > 0 && w.exempt(w.path())
}

// walk duyệt v; map / slice được sửa tại chỗ. Trả (giá trị mới, có cần gán lại vào cha không, lỗi) — chỉ chuỗi
// bị đổi mới cần gán lại nên node sạch không tốn cấp phát. key: khoá map gần nhất (phần tử mảng dùng khoá của mảng
// để phân ngữ cảnh).
func (w *walker) walk(v interface{}, key string, depth int) (interface{}, bool, error) {
	if depth > maxDepth {
		if w.mode == ModeStrict {
			return v, false, ErrTooComplex
		}
		w.tooComplex()
		return nil, true, nil // Clean: bỏ nhánh quá sâu, không trả lại bản gốc chưa duyệt
	}
	if w.inExempt == 0 && w.exempted() {
		w.inExempt++
		defer func() { w.inExempt-- }()
	}
	switch x := v.(type) {
	case map[string]interface{}:
		return v, false, w.walkMap(x, depth)
	case map[string]string:
		return v, false, w.walkStringMap(x, depth)
	case []interface{}:
		for i, el := range x {
			w.push("", i)
			nv, replaced, err := w.walk(el, key, depth+1)
			w.pop()
			if err != nil {
				return v, false, err
			}
			if replaced {
				x[i] = nv
			}
		}
	case []map[string]interface{}:
		for i, el := range x {
			w.push("", i)
			_, replaced, err := w.walk(el, key, depth+1)
			w.pop()
			if err != nil {
				return v, false, err
			}
			if replaced {
				x[i] = nil
			}
		}
	case []string:
		for i, s := range x {
			w.push("", i)
			ns, changed, err := w.walkString(s, key, depth+1)
			w.pop()
			if err != nil {
				return v, false, err
			}
			if changed {
				x[i] = ns
			}
		}
	case string:
		ns, changed, err := w.walkString(x, key, depth)
		if changed {
			return ns, true, err
		}
		return v, false, err
	}
	return v, false, nil
}

func (w *walker) walkMap(m map[string]interface{}, depth int) error {
	for k, v := range m {
		w.push(k, -1)
		newKey, drop := w.checkKey(k)
		nv, replaced := v, false
		var err error
		if !drop {
			nv, replaced, err = w.walk(v, k, depth+1)
		}
		w.pop()
		if err != nil {
			return err
		}
		switch {
		case drop:
			delete(m, k)
			w.report.Changed = true
		case newKey != k:
			delete(m, k)
			w.report.Changed = true
			if _, taken := m[newKey]; !taken { // trùng khoá đã có thì bỏ bản đổi tên, không ghi đè dữ liệu thật
				m[newKey] = nv
			}
		case replaced:
			m[k] = nv
		}
	}
	return nil
}

// walkStringMap: map[string]string do code Go dựng — cùng luật khoá / giá trị như walkMap.
func (w *walker) walkStringMap(m map[string]string, depth int) error {
	for k, s := range m {
		w.push(k, -1)
		newKey, drop := w.checkKey(k)
		ns, changed := s, false
		var err error
		if !drop && w.inExempt == 0 && !w.exempted() {
			ns, changed, err = w.walkString(s, k, depth+1)
		}
		w.pop()
		if err != nil {
			return err
		}
		switch {
		case drop:
			delete(m, k)
			w.report.Changed = true
		case newKey != k:
			delete(m, k)
			w.report.Changed = true
			if _, taken := m[newKey]; !taken {
				m[newKey] = ns
			}
		case changed:
			m[k] = ns
		}
	}
	return nil
}

// checkKey soi TÊN khoá (cả trong cây con miễn trừ — miễn nội dung, không miễn tên khoá): khoá chứa thẻ / mã ⇒
// Clean bỏ cặp khoá, Strict báo; khoá có ký tự điều khiển ⇒ Clean bỏ ký tự đó, Strict báo. Trả (khoá mới, có bỏ không).
func (w *walker) checkKey(k string) (string, bool) {
	clean := w.mode == ModeClean
	if clean && !maybeDirtyString(k) {
		return k, false
	}
	if fs := Detect(k, DetectOptions{Strict: !clean}); len(fs) > 0 {
		for _, f := range fs {
			w.addKey(f.Rule)
		}
		return k, clean
	}
	if indexControl(k) >= 0 {
		w.addKey(RuleControlChar)
		if clean {
			return stripControl(k), false
		}
	}
	return k, false
}

func (w *walker) walkString(s, key string, depth int) (string, bool, error) {
	w.strings++
	if w.strings > maxStrings {
		if w.mode == ModeStrict {
			return s, false, ErrTooComplex
		}
		// Clean vượt ngưỡng: không phân tích nữa (chặn CPU), nhưng cũng không để lọt — chuỗi có dấu hiệu bị bỏ.
		if w.inExempt > 0 || !maybeDirtyString(s) {
			return s, false, nil
		}
		w.tooComplex()
		return "", true, nil
	}
	if w.inExempt > 0 {
		return s, false, nil
	}
	if w.mode == ModeClean && !maybeDirtyString(s) {
		return s, false, nil // chuỗi sạch: không chuẩn hoá, không chạy regex (chuỗi JSON lồng sạch thì cả cây con sạch)
	}
	if ns, handled, changed, err := w.walkEmbeddedJSON(s, key, depth); handled {
		return ns, changed, err
	}
	ctx := Classify(key, s)
	if ctx == CtxSecret && w.mode == ModeClean {
		// Dữ liệu Clean (storefront / Shopify) không chở bí mật hợp lệ nào có thẻ: khoá tên `password` / `api_key` trong
		// map tự do (custom_data…) là khoá do client đặt ⇒ có độc thì bỏ cả giá trị như định danh.
		ctx = CtxVerbatim
	}
	if w.mode == ModeStrict {
		for _, f := range strictFindings(ctx, s) {
			w.add(f.Rule, ctx)
		}
		return s, false, nil
	}
	out, fs, changed := CleanString(ctx, s)
	for _, f := range fs {
		w.add(f.Rule, ctx)
	}
	if changed {
		w.report.Changed = true
	}
	return out, changed, nil
}

// walkEmbeddedJSON: giá trị là chuỗi JSON (vd thuộc tính tuỳ ý mang mảng / object dạng chuỗi). Cắt kiểu text sẽ làm vỡ JSON
// ⇒ parse, duyệt đệ quy, serialize lại khi có thay đổi. Trả (chuỗi mới, có phải JSON lồng không, có đổi không, lỗi).
func (w *walker) walkEmbeddedJSON(s, key string, depth int) (string, bool, bool, error) {
	t := strings.TrimSpace(s)
	if len(t) < 2 || !((t[0] == '{' && t[len(t)-1] == '}') || (t[0] == '[' && t[len(t)-1] == ']')) {
		return "", false, false, nil
	}
	dec := json.NewDecoder(strings.NewReader(t))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil || dec.More() {
		return "", false, false, nil
	}
	outer := w.report.Changed
	w.report.Changed = false
	nv, _, err := w.walk(v, key, depth+1)
	inner := w.report.Changed
	w.report.Changed = outer || inner
	if err != nil || !inner || w.mode == ModeStrict {
		return s, true, false, err
	}
	b, err := encodeJSON(nv)
	if err != nil {
		return s, true, false, nil
	}
	return string(b), true, true, nil
}

func encodeJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // giữ `&`, `<` hợp lệ (vd "Tom & Jerry") — không đổi sang dạng escape unicode
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
