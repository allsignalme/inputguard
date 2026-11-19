package inputguard

import (
	"bytes"
	"slices"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

// ProcessJSON inspects a JSON document and applies the configured actions. It returns the body to use and the
// report:
//   - nothing to change: the input slice itself;
//   - cleaned: a new slice in which only the cleaned strings and removed members differ; the rest of the document
//     is kept byte for byte (key order, number formatting, whitespace);
//   - rejected (Report.Rejected): the input slice, unchanged;
//   - not valid JSON (Report.InvalidJSON): the input slice, unchanged and not inspected.
//
// In ModeClean a body that cannot contain anything an enabled rule flags is returned after one pass over its
// bytes, without parsing or allocating.
func (g *Guard) ProcessJSON(body []byte) ([]byte, Report) { return g.processJSON(body, true) }

// CheckJSON returns the report ProcessJSON would return, without building the cleaned body.
func (g *Guard) CheckJSON(body []byte) Report {
	_, r := g.processJSON(body, false)
	return r
}

// MaybeDirty is the body fast path alone: false means ProcessJSON returns the body unchanged with an empty report.
// When the guard's rules are not all covered by the fast path (custom detectors without MayMatch, strict-only
// rules, OnExceed rejecting) it always returns true.
func (g *Guard) MaybeDirty(body []byte) bool {
	if !g.bodyFast || g.structOnFast {
		return true
	}
	return g.maybeDirtyBody(body)
}

func (g *Guard) processJSON(body []byte, build bool) ([]byte, Report) {
	if g.bodyFast && !g.structOnFast && !g.maybeDirtyBody(body) {
		return body, Report{}
	}
	sc := getScanner(g, body, nil)
	defer putScanner(sc)
	if !sc.run() {
		return body, Report{InvalidJSON: true}
	}
	r := sc.rep.report
	sc.rep.report = Report{}
	if !r.Rejected && len(sc.edits) > 0 {
		if !build {
			r.Changed = true
		} else if out := applyEdits(body, sc.edits); !bytes.Equal(out, body) {
			r.Changed = true
			body = out
		}
	}
	if g.observer != nil && (len(r.Findings) > 0 || r.LimitExceeded) {
		g.observer(r)
	}
	return body, r
}

func (g *Guard) structHintString(s string) bool {
	if g.dupKeys || g.mongoInvalid {
		return true
	}
	if (g.mongoOperator || g.nosqlKeys) && strings.IndexByte(s, '$') >= 0 {
		return true
	}
	if !g.protoKeys {
		return false
	}
	if strings.Contains(s, "proto") {
		return true
	}
	for i := 0; ; {
		j := strings.Index(s[i:], `\u`)
		if j < 0 {
			return false
		}
		i += j + 2
		if v, ok := hex4(s, i); ok && v < 0x80 && (isLetter(byte(v)) || v == '_') {
			return true
		}
	}
}

var (
	litNull  = []byte("null")
	litEmpty = []byte(`""`)
)

// edit replaces src[start:end] with repl.
type edit struct {
	start, end int
	repl       []byte
}

func applyEdits(src []byte, edits []edit) []byte {
	if !slices.IsSortedFunc(edits, cmpEdit) {
		slices.SortStableFunc(edits, cmpEdit)
	}
	n := len(src)
	for _, e := range edits {
		n += len(e.repl) - (e.end - e.start)
	}
	out := make([]byte, 0, n)
	pos := 0
	for _, e := range edits {
		if e.start < pos {
			continue // overlapping edits cannot be produced by the scanner; keep the first one
		}
		out = append(out, src[pos:e.start]...)
		out = append(out, e.repl...)
		pos = e.end
	}
	return append(out, src[pos:]...)
}

func cmpEdit(a, b edit) int { return a.start - b.start }

// scanner walks one JSON document in a single pass. Values are only decoded when a fast check says they might
// match; edits are collected as byte ranges and applied once at the end.
type scanner struct {
	g   *Guard
	src []byte
	pos int
	rep *reporter
	own reporter

	edits      []edit
	exempt     int  // > 0: inside a subtree exempt from content checks (key names are still checked)
	stop       bool // a rejection on limits ends the scan
	scratch    []byte
	memberPool [][]member
	skipStack  []bool
	knownKeys  map[string]struct{} // key names found clean in this document (they alias src)
}

// maxKnownKeys bounds the clean-key cache of one document.
const maxKnownKeys = 256

type member struct {
	key        string
	newKey     string // set when renamed
	keyStart   int    // offset of the key's opening quote
	keyEnd     int
	valueEnd   int
	editsStart int
	del        bool
	renamed    bool
	skipped    bool // over the member limit: not inspected
}

func (m *member) effKey() string {
	if m.renamed {
		return m.newKey
	}
	return m.key
}

var scannerPool = sync.Pool{New: func() any { return new(scanner) }}

// getScanner takes a pooled scanner. rep nil: the scanner reports into its own reporter.
func getScanner(g *Guard, src []byte, rep *reporter) *scanner {
	sc := scannerPool.Get().(*scanner)
	*sc = scanner{
		g: g, src: src,
		edits: sc.edits[:0], scratch: sc.scratch[:0], memberPool: sc.memberPool, skipStack: sc.skipStack[:0],
		knownKeys: sc.knownKeys,
		own:       reporter{g: g, segs: sc.own.segs[:0]},
	}
	sc.rep = rep
	if rep == nil {
		sc.rep = &sc.own
	}
	return sc
}

// putScanner drops every reference into the caller's data before pooling.
func putScanner(sc *scanner) {
	const keep = 64 << 10
	if cap(sc.scratch) > keep {
		sc.scratch = nil
	}
	if cap(sc.skipStack) > keep {
		sc.skipStack = nil
	}
	if cap(sc.edits) > 4096 {
		sc.edits = nil
	} else {
		clear(sc.edits[:cap(sc.edits)])
	}
	for i, m := range sc.memberPool {
		clear(m[:cap(m)])
		sc.memberPool[i] = m[:0]
	}
	clear(sc.own.segs[:cap(sc.own.segs)])
	clear(sc.knownKeys)
	sc.own.report = Report{}
	sc.g, sc.src, sc.rep, sc.own.g = nil, nil, nil, nil
	scannerPool.Put(sc)
}

func (sc *scanner) run() bool {
	sc.skipWS()
	if !sc.value("", 0) {
		return false
	}
	if sc.stop {
		return true
	}
	sc.skipWS()
	return sc.pos == len(sc.src)
}

func (sc *scanner) skipWS() {
	for sc.pos < len(sc.src) {
		switch sc.src[sc.pos] {
		case ' ', '\t', '\n', '\r':
			sc.pos++
		default:
			return
		}
	}
}

// value scans the value at sc.pos. key is the nearest object key (array elements inherit it); depth is the number
// of containers around the value.
func (sc *scanner) value(key string, depth int) bool {
	if sc.pos >= len(sc.src) {
		return false
	}
	switch c := sc.src[sc.pos]; {
	case c == '{' || c == '[':
		if depth >= sc.g.limits.MaxDepth {
			start := sc.pos
			if !sc.limitHit() {
				return true
			}
			if !sc.skipValue() {
				return false
			}
			if sc.g.limitAct == ActionClean {
				sc.edits = append(sc.edits, edit{start, sc.pos, litNull})
			}
			return true
		}
		if c == '{' {
			return sc.object(depth + 1)
		}
		return sc.array(key, depth+1)
	case c == '"':
		start := sc.pos
		s, ok := sc.str()
		if !ok {
			return false
		}
		sc.stringValue(s, key, start, sc.pos, depth)
		return true
	case c == 't':
		return sc.literal("true")
	case c == 'f':
		return sc.literal("false")
	case c == 'n':
		return sc.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return sc.number()
	}
	return false
}

func (sc *scanner) literal(lit string) bool {
	if len(sc.src)-sc.pos < len(lit) {
		return false
	}
	for i := 0; i < len(lit); i++ {
		if sc.src[sc.pos+i] != lit[i] {
			return false
		}
	}
	sc.pos += len(lit)
	return true
}

// number validates a JSON number. Numbers are never decoded: they are kept verbatim, without precision loss.
func (sc *scanner) number() bool {
	s, i := sc.src, sc.pos
	if i < len(s) && s[i] == '-' {
		i++
	}
	switch {
	case i < len(s) && s[i] == '0':
		i++
	case i < len(s) && s[i] >= '1' && s[i] <= '9':
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	default:
		return false
	}
	if i < len(s) && s[i] == '.' {
		i++
		d := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == d {
			return false
		}
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		d := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == d {
			return false
		}
	}
	sc.pos = i
	return true
}

func (sc *scanner) pushSeg(seg PathSeg) bool {
	sc.rep.segs = append(sc.rep.segs, seg)
	if sc.exempt == 0 && len(sc.g.exempt) > 0 && sc.g.exempt.match(sc.rep.segs) {
		sc.exempt++
		return true
	}
	return false
}

func (sc *scanner) popSeg(enteredExempt bool) {
	if enteredExempt {
		sc.exempt--
	}
	sc.rep.segs = sc.rep.segs[:len(sc.rep.segs)-1]
}

func (sc *scanner) object(depth int) bool {
	sc.pos++ // {
	sc.skipWS()
	if sc.pos < len(sc.src) && sc.src[sc.pos] == '}' {
		sc.pos++
		return true
	}
	ms := sc.getMembers()
	ok := sc.members(&ms, depth)
	sc.putMembers(ms)
	return ok
}

func (sc *scanner) members(ms *[]member, depth int) bool {
	g := sc.g
	anyRenamed, anyDel := false, false
	for count := 1; ; count++ {
		sc.skipWS()
		if sc.pos >= len(sc.src) || sc.src[sc.pos] != '"' {
			return false
		}
		keyStart := sc.pos
		rawKey, ok := sc.str()
		if !ok {
			return false
		}
		keyEnd := sc.pos
		key := sc.ownKey(rawKey, keyStart, keyEnd)
		sc.skipWS()
		if sc.pos >= len(sc.src) || sc.src[sc.pos] != ':' {
			return false
		}
		sc.pos++
		sc.skipWS()
		m := member{key: key, keyStart: keyStart, keyEnd: keyEnd, editsStart: len(sc.edits)}
		if count > g.limits.MaxMembers {
			if !sc.limitHit() {
				return true
			}
			if !sc.skipValue() {
				return false
			}
			m.skipped = true
			m.del = g.limitAct == ActionClean
		} else {
			entered := sc.pushSeg(PathSeg{Key: key, Index: -1})
			drop, newKey, renamed := g.checkKey(sc.rep, key, &sc.knownKeys)
			if drop {
				ok = sc.skipValue()
			} else {
				ok = sc.value(key, depth)
			}
			sc.popSeg(entered)
			if !ok {
				return false
			}
			if sc.stop {
				return true
			}
			m.del = drop
			if renamed && !drop {
				m.newKey, m.renamed, anyRenamed = newKey, true, true
			}
		}
		m.valueEnd = sc.pos
		anyDel = anyDel || m.del
		*ms = append(*ms, m)
		sc.skipWS()
		if sc.pos >= len(sc.src) {
			return false
		}
		c := sc.src[sc.pos]
		sc.pos++
		if c == '}' {
			break
		}
		if c != ',' {
			return false
		}
	}
	members := *ms
	if (g.dupKeys || anyRenamed) && sc.resolveDuplicates(members) {
		anyDel = true
	}
	if anyDel {
		sc.deleteMembers(members)
	}
	if anyRenamed {
		for i := range members {
			if m := &members[i]; m.renamed && !m.del {
				sc.edits = append(sc.edits, edit{m.keyStart, m.keyEnd, appendJSONString(nil, m.newKey)})
			}
		}
	}
	return true
}

func (sc *scanner) array(key string, depth int) bool {
	sc.pos++ // [
	sc.skipWS()
	if sc.pos < len(sc.src) && sc.src[sc.pos] == ']' {
		sc.pos++
		return true
	}
	g := sc.g
	lastEnd := sc.pos
	for idx := 0; ; idx++ {
		sc.skipWS()
		if idx >= g.limits.MaxElements {
			if !sc.limitHit() {
				return true
			}
			return sc.skipRestOfArray(lastEnd)
		}
		entered := sc.pushSeg(PathSeg{Index: idx})
		ok := sc.value(key, depth)
		sc.popSeg(entered)
		if !ok {
			return false
		}
		if sc.stop {
			return true
		}
		lastEnd = sc.pos
		sc.skipWS()
		if sc.pos >= len(sc.src) {
			return false
		}
		c := sc.src[sc.pos]
		sc.pos++
		if c == ']' {
			return true
		}
		if c != ',' {
			return false
		}
	}
}

// skipRestOfArray validates the elements over the limit without inspecting them; when cleaning, they are removed
// together with the comma after the last kept element.
func (sc *scanner) skipRestOfArray(lastEnd int) bool {
	for {
		if !sc.skipValue() {
			return false
		}
		sc.skipWS()
		if sc.pos >= len(sc.src) {
			return false
		}
		switch sc.src[sc.pos] {
		case ']':
			if sc.g.limitAct == ActionClean {
				sc.edits = append(sc.edits, edit{lastEnd, sc.pos, nil})
			}
			sc.pos++
			return true
		case ',':
			sc.pos++
		default:
			return false
		}
	}
}

// stringValue inspects one string value whose token spans src[start:end].
func (sc *scanner) stringValue(s, key string, start, end, depth int) {
	g := sc.g
	sc.rep.strCount++
	if sc.rep.strCount > g.limits.MaxStrings || len(s) > g.limits.MaxStringBytes {
		if !sc.limitHit() {
			return
		}
		// Not inspected (bounded work), but not let through either when it might carry something.
		if sc.exempt == 0 && g.limitAct == ActionClean && g.maybeDirtyAny(s) {
			sc.edits = append(sc.edits, edit{start, end, litEmpty})
		}
		return
	}
	if sc.exempt > 0 {
		return
	}
	dirty := g.maybeDirtyAny(s)
	if g.embedJSON && looksLikeJSONContainer(s) && (dirty || g.structHintString(s)) && sc.embedded(s, key, start, end, depth) {
		return
	}
	if !dirty {
		return
	}
	ctx := g.contextFor(sc.rep.segs, key, s)
	if out, changed := g.processString(s, ctx, key, sc.rep, false); changed {
		sc.edits = append(sc.edits, edit{start, end, appendJSONString(nil, out)})
	}
}

// embedded inspects a string holding a JSON object or array member by member, so that cleaning keeps it valid
// JSON. Returns false when the string is not valid JSON (it is then inspected as text).
func (sc *scanner) embedded(s, key string, start, end, depth int) bool {
	src := []byte(s) // s may alias the scratch buffer
	inner := getScanner(sc.g, src, sc.rep)
	defer putScanner(inner)
	inner.exempt = sc.exempt
	saved, savedSegs := *sc.rep, len(sc.rep.segs)
	inner.skipWS()
	ok := inner.value(key, depth)
	if ok && !inner.stop {
		inner.skipWS()
		ok = inner.pos == len(src)
	}
	if !ok {
		segs := sc.rep.segs[:savedSegs]
		*sc.rep = saved
		sc.rep.segs = segs
		return false
	}
	if inner.stop {
		sc.stop = true
		return true
	}
	if len(inner.edits) > 0 {
		out := applyEdits(src, inner.edits)
		sc.edits = append(sc.edits, edit{start, end, appendJSONString(nil, unsafeString(out))})
	}
	return true
}

func looksLikeJSONContainer(s string) bool {
	i, j := 0, len(s)-1
	for i <= j && isJSONSpace(s[i]) {
		i++
	}
	for j >= i && isJSONSpace(s[j]) {
		j--
	}
	if j-i < 1 {
		return false
	}
	return (s[i] == '{' && s[j] == '}') || (s[i] == '[' && s[j] == ']')
}

func isJSONSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// checkKey runs the key-name rules on the key at the top of the path. It returns whether the member is dropped
// and, when only offending characters are removed, the new key.
// known (optional) holds names already found clean in this document: in an array of objects the same keys come
// back, and their content check is the costly part. Structural checks still run (they depend on the parent).
func (g *Guard) checkKey(rep *reporter, key string, known *map[string]struct{}) (drop bool, newKey string, renamed bool) {
	if g.protoKeys && (key == "__proto__" || (key == "prototype" && rep.parentKey() == "constructor")) {
		drop = rep.keyRule(RuleProtoPollution) == ActionClean || drop
	}
	if g.mongoOperator && key != "" && key[0] == '$' {
		drop = rep.keyRule(RuleKeyOperator) == ActionClean || drop
	}
	if g.nosqlKeys && isNoSQLOperatorKey(key) {
		drop = rep.keyRule(RuleNoSQLOperator) == ActionClean || drop
	}
	if g.mongoInvalid && strings.ContainsAny(key, ".\x00") {
		drop = rep.keyRule(RuleKeyInvalid) == ActionClean || drop
	}
	if drop || !g.maybeDirtyAny(key) {
		return drop, "", false
	}
	if known != nil {
		if _, ok := (*known)[key]; ok {
			return false, "", false
		}
	}
	// Content rules on the name (also inside exempt subtrees: exemption covers values, not names). A key carrying
	// markup or code drops the member; offending characters are removed from the name.
	in := input{raw: key, ctx: CtxText, key: key}
	var buf [8]hit
	hits := g.detect(&in, buf[:0])
	clean, charOnly := false, true
	n := 0
	for _, h := range hits {
		if h.clean == cleanPrefix {
			continue // formula injection concerns cell values, not names
		}
		hits[n] = h
		n++
		a := g.action[h.rule]
		rep.add(h.rule, CtxText, a, h.offset, true)
		if a == ActionClean {
			clean = true
			charOnly = charOnly && h.clean == cleanChars
		}
	}
	if n == 0 && known != nil {
		if *known == nil {
			*known = make(map[string]struct{}, 16)
		}
		if len(*known) < maxKnownKeys {
			(*known)[key] = struct{}{}
		}
	}
	if !clean {
		return false, "", false
	}
	if !charOnly {
		return true, "", false
	}
	nk := g.cleanValue(&in, hits[:n])
	switch {
	case nk == "" || g.badKeyName(rep, nk):
		return true, "", false // a name that only becomes dangerous once cleaned ("\x7f$where") is dropped too
	case nk == key:
		return false, "", false
	}
	return false, nk, true
}

// badKeyName: would a structural key rule flag this name?
func (g *Guard) badKeyName(rep *reporter, k string) bool {
	return (g.protoKeys && (k == "__proto__" || (k == "prototype" && rep.parentKey() == "constructor"))) ||
		((g.mongoOperator || g.nosqlKeys) && k != "" && k[0] == '$') ||
		(g.mongoInvalid && strings.ContainsAny(k, ".\x00")) ||
		(g.nosqlKeys && isNoSQLOperatorKey(k))
}

// keyRule records a finding on the key at the top of the path and returns its action.
func (r *reporter) keyRule(id RuleID) Action {
	n := r.g.ruleNum[id]
	a := r.g.action[n]
	r.add(n, CtxText, a, -1, true)
	return a
}

func (r *reporter) parentKey() string {
	segs := r.segs
	if len(segs) >= 2 && segs[len(segs)-2].Index < 0 {
		return segs[len(segs)-2].Key
	}
	return ""
}

// resolveDuplicates handles keys that appear twice in one object. Parsers disagree on which occurrence wins, so a
// validator and the application can see different values: RuleDuplicateKey flags every earlier occurrence and
// cleaning removes it, leaving the one most parsers keep. A key renamed by cleaning never overwrites another
// member: the renamed one is dropped. Returns whether a member was deleted.
func (sc *scanner) resolveDuplicates(ms []member) bool {
	deleted := false
	var idx map[string]int
	if len(ms) > 16 {
		idx = make(map[string]int, len(ms))
	}
	for i := range ms {
		m := &ms[i]
		if m.del || m.skipped {
			continue
		}
		k := m.effKey()
		j := -1
		if idx != nil {
			if v, ok := idx[k]; ok {
				j = v
			}
		} else {
			for p := i - 1; p >= 0; p-- {
				if q := &ms[p]; !q.del && !q.skipped && q.effKey() == k {
					j = p
					break
				}
			}
		}
		if j >= 0 {
			prev := &ms[j]
			switch {
			case m.renamed:
				m.del, deleted = true, true
				continue
			case prev.renamed:
				prev.del, deleted = true, true
			case sc.g.dupKeys:
				sc.rep.segs = append(sc.rep.segs, PathSeg{Key: k, Index: -1})
				a := sc.rep.keyRule(RuleDuplicateKey)
				sc.rep.segs = sc.rep.segs[:len(sc.rep.segs)-1]
				if a == ActionClean {
					prev.del, deleted = true, true
				}
			}
		}
		if idx != nil {
			idx[k] = i
		}
	}
	return deleted
}

// deleteMembers removes the deleted members of one object (with the right commas) and the edits nested in them.
func (sc *scanner) deleteMembers(ms []member) {
	n := len(ms)
	end := len(sc.edits)
	w := ms[0].editsStart
	for i := range ms {
		if ms[i].del {
			continue
		}
		to := end
		if i+1 < n {
			to = ms[i+1].editsStart
		}
		w += copy(sc.edits[w:], sc.edits[ms[i].editsStart:to])
	}
	clear(sc.edits[w:end])
	sc.edits = sc.edits[:w]
	lastKept := -1
	for i := n - 1; i >= 0; i-- {
		if !ms[i].del {
			lastKept = i
			break
		}
	}
	for i := 0; i < lastKept; i++ {
		if ms[i].del {
			sc.edits = append(sc.edits, edit{ms[i].keyStart, ms[i+1].keyStart, nil})
		}
	}
	if lastKept < n-1 {
		from := ms[0].keyStart
		if lastKept >= 0 {
			from = ms[lastKept].valueEnd
		}
		sc.edits = append(sc.edits, edit{from, ms[n-1].valueEnd, nil})
	}
}

// limitHit records that a structural limit was hit (RuleTooComplex, once per document). It returns false when the
// scan must stop (the document is rejected).
func (sc *scanner) limitHit() bool {
	r := sc.rep
	r.report.LimitExceeded = true
	a := sc.g.limitAct
	if !r.limitSeen {
		r.limitSeen = true
		if n := sc.g.ruleNum[RuleTooComplex]; sc.g.on[n] {
			r.add(n, CtxText, a, -1, false)
		}
	}
	if a == ActionReject {
		r.report.Rejected = true
		sc.stop = true
		return false
	}
	return true
}

// skipValue validates the value at sc.pos without inspecting it. It is iterative: nesting is attacker-controlled.
func (sc *scanner) skipValue() bool {
	s := sc.src
	stack := sc.skipStack[:0]
	defer func() { sc.skipStack = stack[:0] }()
	for {
		sc.skipWS()
		if sc.pos >= len(s) {
			return false
		}
		switch c := s[sc.pos]; {
		case c == '{':
			sc.pos++
			sc.skipWS()
			if sc.pos < len(s) && s[sc.pos] == '}' {
				sc.pos++
				break
			}
			stack = append(stack, true)
			if !sc.skipKey() {
				return false
			}
			continue
		case c == '[':
			sc.pos++
			sc.skipWS()
			if sc.pos < len(s) && s[sc.pos] == ']' {
				sc.pos++
				break
			}
			stack = append(stack, false)
			continue
		case c == '"':
			if !sc.skipString() {
				return false
			}
		case c == 't':
			if !sc.literal("true") {
				return false
			}
		case c == 'f':
			if !sc.literal("false") {
				return false
			}
		case c == 'n':
			if !sc.literal("null") {
				return false
			}
		case c == '-' || (c >= '0' && c <= '9'):
			if !sc.number() {
				return false
			}
		default:
			return false
		}
		// After a value: close finished containers, then expect the next value.
		for {
			if len(stack) == 0 {
				return true
			}
			sc.skipWS()
			if sc.pos >= len(s) {
				return false
			}
			c := s[sc.pos]
			sc.pos++
			obj := stack[len(stack)-1]
			if c == ',' {
				if obj && !sc.skipKey() {
					return false
				}
				break
			}
			if (obj && c == '}') || (!obj && c == ']') {
				stack = stack[:len(stack)-1]
				continue
			}
			return false
		}
	}
}

// skipKey reads `"key" :` (with surrounding whitespace).
func (sc *scanner) skipKey() bool {
	sc.skipWS()
	if sc.pos >= len(sc.src) || sc.src[sc.pos] != '"' || !sc.skipString() {
		return false
	}
	sc.skipWS()
	if sc.pos >= len(sc.src) || sc.src[sc.pos] != ':' {
		return false
	}
	sc.pos++
	return true
}

// strPlain[c]: byte c needs no attention inside a string token.
var strPlain = func() (t [256]bool) {
	for c := 0x20; c < 256; c++ {
		t[c] = c != '"' && c != '\\'
	}
	return t
}()

func (sc *scanner) skipString() bool {
	s := sc.src
	for i := sc.pos + 1; i < len(s); {
		c := s[i]
		if strPlain[c] {
			i++
			continue
		}
		switch c {
		case '"':
			sc.pos = i + 1
			return true
		case '\\':
			if i+1 >= len(s) {
				return false
			}
			switch s[i+1] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				i += 2
			case 'u':
				if _, ok := hex4(s, i+2); !ok {
					return false
				}
				i += 6
			default:
				return false
			}
		default:
			return false // raw control character
		}
	}
	return false
}

// str reads the string token at sc.pos. The result aliases src when the token has no escapes, else the scratch
// buffer (valid until the next call).
func (sc *scanner) str() (string, bool) {
	s := sc.src
	start := sc.pos + 1
	for i := start; i < len(s); i++ {
		c := s[i]
		if strPlain[c] {
			continue
		}
		if c == '"' {
			sc.pos = i + 1
			return unsafeString(s[start:i]), true
		}
		if c == '\\' {
			return sc.strEscaped(start, i)
		}
		return "", false
	}
	return "", false
}

func (sc *scanner) strEscaped(start, i int) (string, bool) {
	s := sc.src
	buf := append(sc.scratch[:0], s[start:i]...)
	defer func() { sc.scratch = buf[:0] }()
	for i < len(s) {
		c := s[i]
		if strPlain[c] {
			buf = append(buf, c)
			i++
			continue
		}
		switch c {
		case '"':
			sc.pos = i + 1
			return unsafeString(buf), true
		case '\\':
		default:
			return "", false
		}
		if i+1 >= len(s) {
			return "", false
		}
		switch s[i+1] {
		case '"':
			buf = append(buf, '"')
		case '\\':
			buf = append(buf, '\\')
		case '/':
			buf = append(buf, '/')
		case 'b':
			buf = append(buf, '\b')
		case 'f':
			buf = append(buf, '\f')
		case 'n':
			buf = append(buf, '\n')
		case 'r':
			buf = append(buf, '\r')
		case 't':
			buf = append(buf, '\t')
		case 'u':
			v, ok := hex4(s, i+2)
			if !ok {
				return "", false
			}
			r := rune(v)
			i += 6
			if utf16.IsSurrogate(r) {
				r = utf8.RuneError
				if i+1 < len(s) && s[i] == '\\' && s[i+1] == 'u' {
					if lo, ok := hex4(s, i+2); ok {
						if dec := utf16.DecodeRune(rune(v), rune(lo)); dec != utf8.RuneError {
							r = dec
							i += 6
						}
					}
				}
			}
			buf = utf8.AppendRune(buf, r)
			continue
		default:
			return "", false
		}
		i += 2
	}
	return "", false
}

// ownKey: a key decoded into the scratch buffer is copied (the buffer is reused while the key is on the path).
func (sc *scanner) ownKey(k string, start, end int) string {
	if end-start-2 == len(k) {
		return k // no escapes: aliases src, which outlives the scan
	}
	return strings.Clone(k)
}

func (sc *scanner) getMembers() []member {
	if n := len(sc.memberPool); n > 0 {
		m := sc.memberPool[n-1]
		sc.memberPool = sc.memberPool[:n-1]
		return m[:0]
	}
	return make([]member, 0, 8)
}

func (sc *scanner) putMembers(m []member) {
	if cap(m) <= 1024 {
		sc.memberPool = append(sc.memberPool, m[:0])
	}
}

func unsafeString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}

// appendJSONString encodes s as a JSON string. <, > and & are kept as is (valid JSON; an HTML-escaping encoder
// would change bytes the cleaner did not mean to change). U+2028/2029 are escaped for embedding in JavaScript and
// invalid UTF-8 becomes U+FFFD.
func appendJSONString(dst []byte, s string) []byte {
	const hexd = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				dst = append(dst, '\\', c)
			case c == '\n':
				dst = append(dst, '\\', 'n')
			case c == '\r':
				dst = append(dst, '\\', 'r')
			case c == '\t':
				dst = append(dst, '\\', 't')
			case c < 0x20 || c == 0x7f:
				dst = append(dst, '\\', 'u', '0', '0', hexd[c>>4], hexd[c&0xf])
			default:
				dst = append(dst, c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			dst = append(dst, `�`...)
		case r == 0x2028 || r == 0x2029:
			dst = append(dst, '\\', 'u', '2', '0', '2', hexd[r&0xf])
		default:
			dst = append(dst, s[i:i+size]...)
		}
		i += size
	}
	return append(dst, '"')
}
