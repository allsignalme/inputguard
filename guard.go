package inputguard

import (
	"fmt"
	"sync"
)

// Guard inspects and cleans input. Build it once with New and share it: it is immutable and safe for concurrent
// use.
type Guard struct {
	mode     Mode
	profile  Profile
	on       []bool   // indexed by rule number
	action   []Action // effective action per rule number (never ActionDefault)
	ruleInfo []RuleInfo
	ruleNum  map[RuleID]int

	classify  Classifier
	fieldCtx  []compiledFieldCtx
	exempt    patternSet
	limits    Limits
	limitAct  Action // what happens past a limit: ActionClean, ActionReject or ActionReport
	keyPolicy KeyPolicy
	embedJSON bool
	observer  func(Report)

	redirect  hostMatcher
	ssrfAllow ssrfAllowList
	formulaOn ctxMask

	detectors []*activeDetector

	// Fast path (fastpath.go): trigger bits per context, for any context, and for a raw body; detectors without
	// fast bits are asked one by one (slow lists).
	valueBits [ctxCount]fastBits
	anyBits   fastBits
	bodyBits  fastBits
	slow      [ctxCount][]*activeDetector
	slowAny   []*activeDetector
	invalidOn bool
	// bodyFast: the body fast path covers every enabled rule, so a body it clears is returned without parsing.
	bodyFast bool
	// structOnFast: limits must be checked even on bodies the fast path would accept (OnExceed = ActionReject).
	structOnFast bool
	// dupKeys / protoKeys / mongoKeys: key checks to run while scanning.
	dupKeys, protoKeys, mongoOperator, mongoInvalid, nosqlKeys bool
}

type compiledFieldCtx struct {
	p   pattern
	ctx Context
}

// ctxMask is a set of contexts.
type ctxMask uint16

func maskOf(cs ...Context) ctxMask {
	var m ctxMask
	for _, c := range cs {
		m |= 1 << c
	}
	return m
}

func (m ctxMask) has(c Context) bool { return m&(1<<c) != 0 }

// New builds a Guard. With no options it cleans (ModeClean) with the balanced profile.
func New(opts ...Option) (*Guard, error) {
	c := &config{
		enable:     map[RuleID]bool{},
		actions:    map[RuleID]Action{},
		sevActions: map[Severity]Action{},
		embedJSON:  true,
	}
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}
	if c.profile == 0 {
		c.profile = ProfileBalanced
		if c.mode == ModeReject {
			c.profile = ProfileStrict
		}
	}
	g := &Guard{
		mode:      c.mode,
		profile:   c.profile,
		limits:    c.limits.resolved(),
		keyPolicy: c.keyPolicy,
		embedJSON: c.embedJSON,
		observer:  c.observer,
		ruleNum:   map[RuleID]int{},
	}

	// Rule numbering: built-in rules in table order, then custom detectors.
	infos := append([]RuleInfo(nil), ruleTable...)
	for _, d := range c.detectors {
		sev := d.Severity
		if sev == 0 {
			sev = SeverityHigh
		}
		cat := d.Category
		if cat == "" {
			cat = "custom"
		}
		infos = append(infos, RuleInfo{ID: d.ID, Category: cat, Severity: sev, Profile: ProfileBalanced, Summary: string(d.ID)})
	}
	g.ruleInfo = infos
	g.on = make([]bool, len(infos))
	g.action = make([]Action, len(infos))
	def := ActionClean
	if c.mode == ModeReject {
		def = ActionReject
	}
	for i, info := range infos {
		g.ruleNum[info.ID] = i
		on := info.Profile <= c.profile
		if v, set := c.enable[info.ID]; set {
			on = v
		}
		a := ActionDefault
		if v, set := c.actions[info.ID]; set {
			a = v
		} else if v, set := c.sevActions[info.Severity]; set {
			a = v
		}
		if a == ActionIgnore {
			on = false
		}
		if a == ActionDefault {
			a = def
		}
		g.on[i], g.action[i] = on, a
	}
	// Custom detectors are on unless explicitly disabled.
	for i := len(ruleTable); i < len(infos); i++ {
		if v, set := c.enable[infos[i].ID]; set {
			g.on[i] = v
		} else if g.action[i] != ActionIgnore {
			g.on[i] = true
		}
	}

	if c.classifier != nil {
		g.classify = c.classifier
	} else if c.keyTable != nil {
		g.classify = c.keyTable.classifier()
	} else {
		g.classify = defaultClassifier()
	}
	for _, fc := range c.fieldCtx {
		p, err := compilePattern(fc.pattern)
		if err != nil {
			return nil, err
		}
		g.fieldCtx = append(g.fieldCtx, compiledFieldCtx{p, fc.ctx})
	}
	ex, err := compilePatterns(c.exempt)
	if err != nil {
		return nil, err
	}
	g.exempt = ex
	if g.redirect, err = newHostMatcher(c.redirect); err != nil {
		return nil, err
	}
	if g.ssrfAllow, err = newSSRFAllowList(c.ssrfAllow); err != nil {
		return nil, err
	}
	if len(c.formulaCtxs) > 0 {
		g.formulaOn = maskOf(c.formulaCtxs...)
	} else {
		g.formulaOn = maskOf(CtxText)
	}

	for _, d := range builtinDetectors {
		ad := &activeDetector{builtin: d}
		for _, id := range d.rules {
			if g.on[g.ruleNum[id]] {
				ad.any = true
			}
		}
		if ad.any {
			g.detectors = append(g.detectors, ad)
		}
	}
	for _, d := range c.detectors {
		if !g.on[g.ruleNum[d.ID]] {
			continue
		}
		cd := d
		ctxs := cd.Contexts
		if len(ctxs) == 0 {
			ctxs = []Context{CtxText, CtxURL, CtxRedirect, CtxIdentifier}
		}
		g.detectors = append(g.detectors, &activeDetector{custom: &cd, contexts: maskOf(ctxs...), any: true})
	}

	g.dupKeys = g.ruleOn(RuleDuplicateKey)
	g.protoKeys = g.ruleOn(RuleProtoPollution)
	g.mongoOperator = g.ruleOn(RuleKeyOperator)
	g.mongoInvalid = g.ruleOn(RuleKeyInvalid)
	g.nosqlKeys = g.ruleOn(RuleNoSQLOperator)
	switch g.limits.OnExceed {
	case ActionClean, ActionReject, ActionReport:
		g.limitAct = g.limits.OnExceed
	default:
		g.limitAct = def
	}
	g.structOnFast = g.limitAct == ActionReject
	g.buildFastPath()
	return g, nil
}

// MustNew is New that panics on a configuration error (for package-level guards).
func MustNew(opts ...Option) *Guard {
	g, err := New(opts...)
	if err != nil {
		panic(fmt.Sprintf("inputguard: %v", err))
	}
	return g
}

// Mode returns the guard's mode.
func (g *Guard) Mode() Mode { return g.mode }

// Profile returns the guard's profile.
func (g *Guard) Profile() Profile { return g.profile }

// Enabled reports whether a rule is on.
func (g *Guard) Enabled(id RuleID) bool { return g.ruleOn(id) }

func (g *Guard) ruleOn(id RuleID) bool {
	n, ok := g.ruleNum[id]
	return ok && g.on[n]
}

// ActionFor returns the effective action of a rule.
func (g *Guard) ActionFor(id RuleID) Action {
	if n, ok := g.ruleNum[id]; ok {
		return g.action[n]
	}
	return ActionIgnore
}

var (
	defaultClassifierOnce sync.Once
	defaultClassifierFn   Classifier
)

func defaultClassifier() Classifier {
	defaultClassifierOnce.Do(func() { defaultClassifierFn = DefaultKeyTable().classifier() })
	return defaultClassifierFn
}

// buildFastPath combines the trigger bits of the enabled groups per context.
func (g *Guard) buildFastPath() {
	for _, ad := range g.detectors {
		var bits fastBits
		var ctxs ctxMask
		if ad.custom != nil {
			ctxs = ad.contexts
		} else {
			bits, ctxs = ad.builtin.fast, ad.builtin.contexts
		}
		for c := Context(0); c < ctxCount; c++ {
			if !ctxs.has(c) {
				continue
			}
			if bits != 0 {
				g.valueBits[c] |= bits
			} else {
				g.slow[c] = append(g.slow[c], ad)
			}
		}
		if bits != 0 {
			g.anyBits |= bits
		} else {
			g.slowAny = append(g.slowAny, ad)
		}
	}
	g.invalidOn = g.ruleOn(RuleInvalidUTF8)
	g.bodyBits = g.anyBits
	if g.protoKeys {
		g.bodyBits |= fbProto
	}
	if g.mongoOperator || g.nosqlKeys {
		g.bodyBits |= fbDollar
	}
	// Duplicate keys and Mongo key characters need the parser.
	g.bodyFast = len(g.slowAny) == 0 && !g.dupKeys && !g.mongoInvalid
}
