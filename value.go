package inputguard

import "slices"

// ProcessString inspects one value in the given context and applies the configured actions. It returns the value
// to use: the input when nothing is cleaned or when the report is rejected.
func (g *Guard) ProcessString(s string, ctx Context) (string, Report) {
	rep := reporter{g: g}
	out := s
	if len(s) > g.limits.MaxStringBytes {
		sc := scanner{g: g, rep: &rep}
		if sc.limitHit() && g.limitAct == ActionClean && g.maybeDirtyAny(s) {
			out = ""
		}
	} else if ns, changed := g.processString(s, ctx, "", &rep, false); changed {
		out = ns
	}
	r := rep.report
	if r.Rejected {
		out = s
	}
	r.Changed = out != s
	if g.observer != nil && (len(r.Findings) > 0 || r.LimitExceeded) {
		g.observer(r)
	}
	return out, r
}

// CheckString reports what ProcessString would find.
func (g *Guard) CheckString(s string, ctx Context) Report {
	_, r := g.ProcessString(s, ctx)
	return r
}

// ProcessField is ProcessString with the context chosen by the guard's classifier from the field name.
func (g *Guard) ProcessField(key, s string) (string, Report) {
	return g.ProcessString(s, g.classify(key, s))
}

// MaybeDirtyString is the per-value fast path: false means ProcessString returns s unchanged with an empty report,
// whatever the context.
func (g *Guard) MaybeDirtyString(s string) bool { return g.maybeDirtyAny(s) }

// ProcessValue inspects a decoded Go value: map[string]any, map[string]string, []any, []string,
// []map[string]any and string, nested in any combination (other types are left alone). Maps and slices are
// cleaned IN PLACE; the returned value is v, or the cleaned string when v is a string. When the report is rejected,
// nothing is changed.
func (g *Guard) ProcessValue(v any) (any, Report) {
	w := valueWalker{g: g, rep: &reporter{g: g}}
	if g.mode == ModeReject || g.anyReject() {
		// Rejection must leave the value untouched: inspect first, clean only if nothing rejects.
		w.dry = true
		w.walk(v, "", 0)
		if w.rep.report.Rejected || !w.changed {
			return v, w.finish(false)
		}
		w = valueWalker{g: g, rep: &reporter{g: g}}
	}
	nv, replaced := w.walk(v, "", 0)
	if replaced {
		v = nv
	}
	return v, w.finish(w.changed)
}

// CleanLeaves reports the string leaves of v that cleaning would change, without changing v. A string holding
// embedded JSON counts as one leaf. Map keys that would be dropped or renamed are not leaves: they only appear
// in the report.
func (g *Guard) CleanLeaves(v any) ([]LeafChange, Report) {
	var changes []LeafChange
	w := valueWalker{g: g, rep: &reporter{g: g}, dry: true, leaves: &changes}
	w.walk(v, "", 0)
	r := w.finish(false)
	if r.Rejected {
		return nil, r
	}
	return changes, r
}

func (g *Guard) anyReject() bool {
	for i, on := range g.on {
		if on && g.action[i] == ActionReject {
			return true
		}
	}
	return g.limitAct == ActionReject
}

type valueWalker struct {
	g       *Guard
	rep     *reporter
	exempt  int
	dry     bool // do not modify anything
	changed bool
	leaves  *[]LeafChange
}

func (w *valueWalker) finish(changed bool) Report {
	r := w.rep.report
	r.Changed = changed && !r.Rejected
	sortFindings(r.Findings) // map iteration order is random
	if w.g.observer != nil && (len(r.Findings) > 0 || r.LimitExceeded) {
		w.g.observer(r)
	}
	return r
}

func (w *valueWalker) push(seg PathSeg) bool {
	w.rep.segs = append(w.rep.segs, seg)
	if w.exempt == 0 && len(w.g.exempt) > 0 && w.g.exempt.match(w.rep.segs) {
		w.exempt++
		return true
	}
	return false
}

func (w *valueWalker) pop(entered bool) {
	if entered {
		w.exempt--
	}
	w.rep.segs = w.rep.segs[:len(w.rep.segs)-1]
}

// limit handles a value past a limit; returns whether it is replaced by nil.
func (w *valueWalker) limit() bool {
	sc := scanner{g: w.g, rep: w.rep}
	return sc.limitHit() && w.g.limitAct == ActionClean
}

// walk returns the replacement for v and whether v must be replaced in its parent.
func (w *valueWalker) walk(v any, key string, depth int) (any, bool) {
	switch x := v.(type) {
	case string:
		return w.str(x, key)
	case map[string]any, map[string]string, []any, []string, []map[string]any:
		if depth >= w.g.limits.MaxDepth {
			if w.limit() {
				w.changed = true
				return nil, !w.dry
			}
			return v, false
		}
	default:
		return v, false
	}
	switch x := v.(type) {
	case map[string]any:
		w.walkMap(x, depth+1)
	case map[string]string:
		w.walkStringMap(x, depth+1)
	case []any:
		for i, el := range x {
			e := w.push(PathSeg{Index: i})
			nv, replaced := w.walk(el, key, depth+1)
			w.pop(e)
			if replaced {
				x[i] = nv
			}
		}
	case []string:
		for i, s := range x {
			e := w.push(PathSeg{Index: i})
			ns, replaced := w.str(s, key)
			w.pop(e)
			if replaced {
				x[i] = ns.(string)
			}
		}
	case []map[string]any:
		for i, el := range x {
			e := w.push(PathSeg{Index: i})
			if _, replaced := w.walk(el, key, depth+1); replaced {
				x[i] = nil
			}
			w.pop(e)
		}
	}
	return v, false
}

type keyChange struct {
	old, new string
	drop     bool
}

// sortedKeys: keys in a stable order, so that findings and rename collisions do not depend on map order.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func (w *valueWalker) walkMap(m map[string]any, depth int) {
	var changes []keyChange
	for _, k := range sortedKeys(m) {
		e := w.push(PathSeg{Key: k, Index: -1})
		drop, nk, renamed := w.g.checkKey(w.rep, k)
		if !drop {
			if nv, replaced := w.walk(m[k], k, depth); replaced {
				m[k] = nv
			}
		}
		w.pop(e)
		if drop || renamed {
			changes = append(changes, keyChange{k, nk, drop})
		}
	}
	applyKeyChanges(w, m, changes)
}

func (w *valueWalker) walkStringMap(m map[string]string, depth int) {
	var changes []keyChange
	for _, k := range sortedKeys(m) {
		e := w.push(PathSeg{Key: k, Index: -1})
		drop, nk, renamed := w.g.checkKey(w.rep, k)
		if !drop {
			if ns, replaced := w.str(m[k], k); replaced {
				m[k] = ns.(string)
			}
		}
		w.pop(e)
		if drop || renamed {
			changes = append(changes, keyChange{k, nk, drop})
		}
	}
	applyKeyChanges(w, m, changes)
}

// applyKeyChanges drops and renames keys after the walk. A renamed key never overwrites an existing one.
func applyKeyChanges[V any](w *valueWalker, m map[string]V, changes []keyChange) {
	if len(changes) == 0 {
		return
	}
	w.changed = true
	if w.dry {
		return
	}
	for _, c := range changes {
		v := m[c.old]
		delete(m, c.old)
		if c.drop {
			continue
		}
		if _, taken := m[c.new]; !taken {
			m[c.new] = v
		}
	}
}

// str inspects one string leaf.
func (w *valueWalker) str(s, key string) (any, bool) {
	g := w.g
	r := w.rep
	r.strCount++
	if r.strCount > g.limits.MaxStrings || len(s) > g.limits.MaxStringBytes {
		if w.limit() && w.exempt == 0 && g.maybeDirtyAny(s) {
			return w.leaf(s, "")
		}
		return s, false
	}
	if w.exempt > 0 {
		return s, false
	}
	dirty := g.maybeDirtyAny(s)
	if g.embedJSON && looksLikeJSONContainer(s) && (dirty || g.structHintString(s)) {
		if out, ok := w.embedded(s, key); ok {
			if out == s {
				return s, false
			}
			return w.leaf(s, out)
		}
	}
	if !dirty {
		return s, false
	}
	out, changed := g.processString(s, g.contextFor(r.segs, key, s), key, r, false)
	if !changed {
		return s, false
	}
	return w.leaf(s, out)
}

func (w *valueWalker) leaf(old, out string) (any, bool) {
	w.changed = true
	if w.leaves != nil {
		*w.leaves = append(*w.leaves, LeafChange{Path: slices.Clone(w.rep.segs), Old: old, New: out})
	}
	if w.dry {
		return old, false
	}
	return out, true
}

// embedded runs the JSON scanner on a string holding JSON, reporting into the walker's reporter.
func (w *valueWalker) embedded(s, key string) (string, bool) {
	src := []byte(s)
	sc := getScanner(w.g, src, w.rep)
	defer putScanner(sc)
	sc.exempt = w.exempt
	saved, savedSegs := *w.rep, len(w.rep.segs)
	sc.skipWS()
	ok := sc.value(key, len(w.rep.segs))
	if ok && !sc.stop {
		sc.skipWS()
		ok = sc.pos == len(src)
	}
	if !ok {
		segs := w.rep.segs[:savedSegs]
		*w.rep = saved
		w.rep.segs = segs
		return "", false
	}
	if sc.stop || len(sc.edits) == 0 {
		return s, true
	}
	return string(applyEdits(src, sc.edits)), true
}

// FormatPath renders a path the way findings show it: `a.b[0].c`, with keys that are not safe to print (payloads,
// PII, very long names) shown as `[key]`.
func FormatPath(segs []PathSeg) string { return formatPath(segs) }
