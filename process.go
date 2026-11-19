package inputguard

import (
	"strings"

	"github.com/allsignalme/inputguard/internal/norm"
)

// maxCleanPasses: cutting can expose a new match at the end of what is left ("abc<img" + "<script>" ⇒ the first cut
// leaves "abc<img"). After this many passes a value that is still dirty is emptied.
const maxCleanPasses = 3

// reporter collects findings for one document.
type reporter struct {
	g      *Guard
	report Report
	segs   []PathSeg
	// strCount counts strings for Limits.MaxStrings (shared with embedded documents).
	strCount int
	// limitSeen: RuleTooComplex already reported.
	limitSeen bool
}

func (r *reporter) path() string { return formatPath(r.segs) }

func (r *reporter) add(rule int, ctx Context, action Action, offset int, onKey bool) {
	switch action {
	case ActionReject:
		r.report.Rejected = true
	case ActionClean:
		// Changed is set by the caller when the output really differs.
	}
	if len(r.report.Findings) >= r.g.limits.MaxFindings {
		r.report.Truncated = true
		return
	}
	info := r.g.ruleInfo[rule]
	p := r.path()
	if onKey {
		p = formatPath(r.segs[:len(r.segs)-1]) + keyPathMarker
	}
	r.report.Findings = append(r.report.Findings, Finding{
		Rule: info.ID, Category: info.Category, Severity: info.Severity,
		Path: p, Context: ctx, Action: action, Offset: offset,
	})
}

// contextFor resolves the context of a value at the reporter's current path.
func (g *Guard) contextFor(segs []PathSeg, key, value string) Context {
	for _, fc := range g.fieldCtx {
		if fc.p.match(segs) {
			return fc.ctx
		}
	}
	return g.classify(key, value)
}

// effective context: secrets are never inspected when rejecting; in clean mode they are treated as identifiers
// (data that should not carry a secret is cleaned like an id: any finding empties it).
func (g *Guard) effectiveContext(ctx Context) Context {
	if ctx == CtxSecret {
		if g.mode == ModeReject {
			return CtxSkip
		}
		return CtxIdentifier
	}
	return ctx
}

// processString inspects one value. It records findings in rep (if not nil) and returns the value to use.
func (g *Guard) processString(s string, ctx Context, key string, rep *reporter, onKey bool) (string, bool) {
	ctx = g.effectiveContext(ctx)
	if ctx == CtxSkip || !g.maybeDirtyValue(s, ctx) {
		return s, false
	}
	in := input{raw: s, ctx: ctx, key: key}
	var buf [8]hit
	hits := g.detect(&in, buf[:0])
	if len(hits) == 0 {
		return s, false
	}
	needClean, rejected := false, false
	for _, h := range hits {
		a := g.action[h.rule]
		if rep != nil {
			rep.add(h.rule, ctx, a, h.offset, onKey)
		}
		switch a {
		case ActionReject:
			rejected = true
		case ActionClean:
			needClean = true
		}
	}
	if rejected || !needClean {
		return s, false
	}
	out := g.cleanValue(&in, hits)
	return out, out != s
}

// cleanValue removes the findings whose action is ActionClean.
func (g *Guard) cleanValue(in *input, hits []hit) string {
	if in.ctx == CtxIdentifier && !onlyCharacterHits(g, hits) {
		return "" // one changed byte breaks an id; an id carrying a payload is not worth keeping
	}
	s := in.raw
	var drop [5]bool
	charLevel, cut, prefix, empty := false, false, false, false
	for _, h := range hits {
		if g.action[h.rule] != ActionClean {
			continue
		}
		switch h.clean {
		case cleanChars:
			charLevel = true
			switch g.ruleInfo[h.rule].ID {
			case RuleControlChar:
				drop[uniControl] = true
			case RuleBidi:
				drop[uniBidi] = true
			case RuleInvisible:
				drop[uniInvisible] = true
			case RuleInvalidUTF8:
				drop[uniInvalid] = true
			case RuleHeaderCRLF:
				// handled below
			}
		case cleanCut:
			cut = true
		case cleanPrefix:
			prefix = true
		case cleanEmpty:
			empty = true
		}
	}
	if empty {
		return ""
	}
	if charLevel {
		s = stripUnicodeIssues(s, drop)
		if g.hasCleanHit(hits, RuleHeaderCRLF) {
			s = stripCRLF(s)
		}
	}
	if cut {
		ctx := in.ctx
		out, ok := "", false
		if ctx.isURL() {
			out, ok = g.cleanURL(s, ctx)
		}
		if !ok {
			out = g.keepRaw(s, g.cleanText(s, ctx, in.key), ctx, in.key)
		}
		s = out
	}
	if prefix && s != "" {
		s = "'" + s
	}
	// The result must itself be clean for every rule being cleaned; otherwise give up on the value.
	if s != "" && g.cleanDirty(s, in.ctx, in.key) {
		return ""
	}
	return s
}

// onlyCharacterHits: every finding being cleaned is a stray character (control, bidi, invisible, invalid UTF-8,
// CR/LF). Removing it restores an identifier pasted with a zero-width space instead of erasing it.
func onlyCharacterHits(g *Guard, hits []hit) bool {
	for _, h := range hits {
		if g.action[h.rule] == ActionClean && h.clean != cleanChars {
			return false
		}
	}
	return true
}

func (g *Guard) hasCleanHit(hits []hit, id RuleID) bool {
	n := g.ruleNum[id]
	for _, h := range hits {
		if h.rule == n && g.action[n] == ActionClean {
			return true
		}
	}
	return false
}

// cleanDirty: does any rule whose action is ActionClean still match s?
func (g *Guard) cleanDirty(s string, ctx Context, key string) bool {
	if !g.maybeDirtyValue(s, ctx) {
		return false
	}
	in := input{raw: s, ctx: ctx, key: key}
	var buf [8]hit
	for _, h := range g.detect(&in, buf[:0]) {
		if g.action[h.rule] == ActionClean {
			return true
		}
	}
	return false
}

// cutScan returns the decoded value and the earliest offset of a cut-type finding being cleaned (-1 if none).
func (g *Guard) cutScan(s string, ctx Context, key string) (string, int) {
	if !g.maybeDirtyValue(s, ctx) {
		return s, -1
	}
	in := input{raw: s, ctx: ctx, key: key}
	var buf [8]hit
	first := -1
	for _, h := range g.detect(&in, buf[:0]) {
		if h.clean != cleanCut || g.action[h.rule] != ActionClean {
			continue
		}
		off := h.offset
		if off < 0 {
			off = 0
		}
		if first < 0 || off < first {
			first = off
		}
	}
	if first < 0 {
		// Once decoded, keep the decoded form (what the original engine returned): the part left after a cut is
		// what the browser would have seen.
		if in.done {
			return in.decoded(), -1
		}
		return s, -1
	}
	return in.decoded(), first
}

// cleanText cuts at the earliest finding, trims characters used to break out of the context, and checks again.
// The kept part is returned DECODED (it is what the browser would have seen).
func (g *Guard) cleanText(s string, ctx Context, key string) string {
	dec, idx := g.cutScan(s, ctx, key)
	for pass := 0; pass < maxCleanPasses; pass++ {
		if idx < 0 {
			return dec
		}
		dec, idx = g.cutScan(strings.TrimRightFunc(dec[:idx], isBreakoutTail), ctx, key)
	}
	if idx >= 0 {
		return ""
	}
	return dec
}

// keepRaw: cleanText returns the kept part decoded (offsets are found in the decoded value). When the raw value
// starts with a prefix that decodes to exactly that, return the raw prefix instead, so that an untouched part keeps
// its own spelling ("Tom &amp; Jerry 50%25 off <script>" keeps "&amp;" and "%25"). Otherwise the decoded form is
// kept. The prefix is found by bisection over its decoded length: a few Normalize calls, for dirty values only.
func (g *Guard) keepRaw(raw, kept string, ctx Context, key string) string {
	if kept == "" || strings.HasPrefix(raw, kept) || len(raw) > maxKeepRaw {
		return kept
	}
	// Candidate cut points: rune boundaries. A cut inside an escape (%2|5, &am|p;) decodes to something that is not
	// a prefix of kept, which would break the bisection, so a probe that fails is moved forward past such an
	// escape first.
	cuts := make([]int, 0, len(raw)+1)
	for i := range raw {
		cuts = append(cuts, i)
	}
	cuts = append(cuts, len(raw))
	prefixAt := func(c int) (int, bool) {
		for j := c; j < len(cuts) && j <= c+maxEscapeLen; j++ {
			if strings.HasPrefix(kept, norm.Normalize(raw[:cuts[j]]).Decoded) {
				return j, true
			}
			if j > c && !inEscape(raw, cuts[j]) {
				break
			}
		}
		return 0, false
	}
	lo, hi := 0, len(cuts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if j, ok := prefixAt(mid); ok {
			lo = max(j, mid)
			if j > mid && j > hi {
				break
			}
		} else {
			hi = mid - 1
		}
	}
	for j := lo; j < len(cuts) && j <= lo+maxEscapeLen; j++ {
		for _, cand := range [2]string{raw[:cuts[j]], strings.TrimRightFunc(raw[:cuts[j]], isBreakoutTail)} {
			if norm.Normalize(cand).Decoded == kept && !g.cleanDirty(cand, ctx, key) {
				return cand
			}
		}
	}
	return kept
}

// keepRaw bounds: values longer than this keep the decoded form; an escape spans at most this many characters.
const (
	maxKeepRaw   = 64 << 10
	maxEscapeLen = 12
)

// inEscape: the cut at i falls inside a percent, entity or backslash escape that started shortly before.
func inEscape(s string, i int) bool {
	for k := i - 1; k >= 0 && k >= i-maxEscapeLen; k-- {
		switch s[k] {
		case '%', '&', '\\':
			return true
		case ';', ' ':
			return false
		}
	}
	return false
}

func isBreakoutTail(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\v', '\f', 0x85, 0xA0:
		return true
	}
	if r > 0x7f {
		return isUnicodeSpace(r)
	}
	return strings.ContainsRune("'\"`<>/\\;=(-", r)
}

func stripCRLF(s string) string {
	if strings.IndexAny(s, "\r\n") < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}
