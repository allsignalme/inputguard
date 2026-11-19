package inputguard

import (
	"unicode/utf8"

	"github.com/allsignalme/inputguard/internal/norm"
)

// cleanKind is how a finding is removed in ActionClean.
type cleanKind uint8

const (
	// cleanCut removes the malicious part: text is cut at the first finding, a URL loses the bad parameter,
	// fragment or path segment, an identifier is emptied.
	cleanCut cleanKind = iota
	// cleanChars removes offending characters only (control, bidi, invisible, CR/LF, invalid UTF-8).
	cleanChars
	// cleanPrefix neutralises the value by prefixing it (formula injection).
	cleanPrefix
	// cleanEmpty empties the value.
	cleanEmpty
)

// builtinDetector is one group of built-in rules.
type builtinDetector struct {
	name  string
	rules []RuleID
	// contexts the group runs on.
	contexts ctxMask
	// fast: the trigger bits of the shared fast path (fastpath.go) that cover this group, in values and bodies.
	// Zero: the group has its own mayMatch and the body fast path cannot skip it.
	fast fastBits
	// mayMatch is a cheap check on the decoded JSON string (not yet normalised), for groups without fast bits. It
	// must return true for every value detect would flag. nil = always run.
	mayMatch func(g *Guard, raw string) bool
	// needNorm: detect reads in.Decoded / in.Folded (normalisation is computed lazily, once per value).
	needNorm bool
	// detect reports matches through emit (rule, offset in Decoded; -1 when not positional).
	detect func(g *Guard, in *input, emit func(RuleID, int))
	clean  cleanKind
}

var builtinDetectors []*builtinDetector

// registerDetector adds a built-in rule group. Called from init functions; order of registration is the order
// of detection.
func registerDetector(d *builtinDetector) { builtinDetectors = append(builtinDetectors, d) }

type activeDetector struct {
	builtin  *builtinDetector
	custom   *Detector
	contexts ctxMask
	any      bool
}

// input is one string value being inspected.
type input struct {
	raw  string
	ctx  Context
	key  string
	n    norm.Normalized
	done bool
}

func (in *input) norm() *norm.Normalized {
	if !in.done {
		in.n = norm.Normalize(in.raw)
		in.done = true
	}
	return &in.n
}

// Decoded returns the normalised value (computed on first use).
func (in *input) decoded() string { return in.norm().Decoded }

// folded returns the normalised value with ASCII lowercased (same length as decoded).
func (in *input) folded() string { return in.norm().Folded }

// hit is one rule match on one value.
type hit struct {
	rule   int
	offset int
	clean  cleanKind
}

// detect runs every enabled rule that applies to the context. It appends to hits and returns it.
func (g *Guard) detect(in *input, hits []hit) []hit {
	for _, ad := range g.detectors {
		if ad.custom != nil {
			d := ad.custom
			if !ad.contexts.has(in.ctx) {
				continue
			}
			if d.MayMatch != nil && !d.MayMatch(in.raw) {
				continue
			}
			nn := in.norm()
			if off := d.Detect(Input{Raw: in.raw, Decoded: nn.Decoded, Folded: nn.Folded, Context: in.ctx, Key: in.key}); off >= 0 {
				hits = appendHit(hits, hit{rule: g.ruleNum[d.ID], offset: off, clean: cleanCut})
			}
			continue
		}
		d := ad.builtin
		if !d.contexts.has(in.ctx) {
			continue
		}
		if g.noGates {
			// testing: every detector runs
		} else if d.fast != 0 {
			if !g.fastValue(in.raw, d.fast) {
				continue
			}
		} else if d.mayMatch != nil && !d.mayMatch(g, in.raw) {
			continue
		}
		clean := d.clean
		d.detect(g, in, func(id RuleID, off int) {
			n, ok := g.ruleNum[id]
			if !ok || !g.on[n] {
				return
			}
			hits = appendHit(hits, hit{rule: n, offset: off, clean: clean})
		})
	}
	return hits
}

// appendHit keeps one hit per rule, at the earliest offset.
func appendHit(hits []hit, h hit) []hit {
	for i := range hits {
		if hits[i].rule == h.rule {
			if h.offset >= 0 && (hits[i].offset < 0 || h.offset < hits[i].offset) {
				hits[i].offset = h.offset
			}
			return hits
		}
	}
	return append(hits, h)
}

// maybeDirtyValue is the per-value fast path: false ⇒ no enabled rule can match this value in this context.
func (g *Guard) maybeDirtyValue(raw string, ctx Context) bool {
	if g.noGates {
		return true
	}
	if g.fastValue(raw, g.valueBits[ctx]) {
		return true
	}
	for _, ad := range g.slow[ctx] {
		if ad.mayMatch(g, raw) {
			return true
		}
	}
	return false
}

// maybeDirtyAny: could an enabled rule match s in some context? Cheaper than classifying the value first.
func (g *Guard) maybeDirtyAny(s string) bool {
	if g.noGates {
		return true
	}
	if g.fastValue(s, g.anyBits) {
		return true
	}
	for _, ad := range g.slowAny {
		if ad.mayMatch(g, s) {
			return true
		}
	}
	return false
}

// maybeDirtyBody is the raw-body fast path. Only valid when g.bodyFast.
func (g *Guard) maybeDirtyBody(body []byte) bool {
	return scanFast(body, true, g.bodyBits) || (g.bodyBits&fbUnicode != 0 && g.invalidOn && !utf8.Valid(body))
}

// mayMatch of a detector without fast bits.
func (ad *activeDetector) mayMatch(g *Guard, raw string) bool {
	if ad.custom != nil {
		return ad.custom.MayMatch == nil || ad.custom.MayMatch(raw)
	}
	return ad.builtin.mayMatch == nil || ad.builtin.mayMatch(g, raw)
}
