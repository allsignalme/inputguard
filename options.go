package inputguard

import (
	"fmt"
	"strings"
)

// Mode sets the default action for findings.
type Mode uint8

const (
	// ModeClean cleans malicious parts and lets the data through. Use it where blocking would lose data a third
	// party sent (webhooks, tracking events).
	ModeClean Mode = iota
	// ModeReject changes nothing and marks the report rejected. Use it for writes a person makes through your API:
	// a 400 tells them what to fix.
	ModeReject
)

func (m Mode) String() string {
	if m == ModeReject {
		return "reject"
	}
	return "clean"
}

// Profile chooses which rules are on by default.
type Profile uint8

const (
	// ProfileBalanced (default for ModeClean) enables high-confidence rules only: almost no false positives on
	// real data, cheap enough for every request.
	ProfileBalanced Profile = iota + 1
	// ProfileStrict (default for ModeReject) adds rules that need context to be sure (templates, SQL, shell,
	// formulas, SSRF…). Meant for configuration and admin input.
	ProfileStrict
	// ProfileOptIn marks rules no profile enables: they are turned on explicitly (WithRules, WithCategories, or
	// WithKeyPolicy for the store-specific key rules).
	ProfileOptIn Profile = 255
)

func (p Profile) String() string {
	switch p {
	case ProfileStrict:
		return "strict"
	case ProfileOptIn:
		return "opt-in"
	}
	return "balanced"
}

// Action is what happens to one finding.
type Action uint8

const (
	// ActionDefault follows the mode: clean in ModeClean, reject in ModeReject.
	ActionDefault Action = iota
	// ActionClean removes the malicious part (how depends on the context).
	ActionClean
	// ActionReject leaves the value and marks the report rejected.
	ActionReject
	// ActionReport only records the finding.
	ActionReport
	// ActionIgnore drops the finding entirely (the rule is effectively off).
	ActionIgnore
)

func (a Action) String() string {
	switch a {
	case ActionClean:
		return "clean"
	case ActionReject:
		return "reject"
	case ActionReport:
		return "report"
	case ActionIgnore:
		return "ignore"
	}
	return "default"
}

// Limits bound the work done on one document. Zero means the default; a negative value means no limit.
type Limits struct {
	MaxDepth       int // nesting of objects/arrays (default 32)
	MaxStrings     int // string values per document (default 20 000)
	MaxStringBytes int // bytes in one string (default 1 MiB)
	MaxMembers     int // members in one object (default 10 000)
	MaxElements    int // elements in one array (default 100 000)
	MaxFindings    int // findings kept in a report (default 100)
	// OnExceed: ActionDefault prunes in ModeClean (the over-limit branch becomes null, an over-limit string that
	// looks suspicious becomes "") and rejects in ModeReject. ActionReject rejects in both modes; ActionReport keeps
	// the document and only reports. Limits are applied to documents that are scanned: in ModeClean a body the fast
	// path clears (nothing in it can match any enabled rule) is returned without being parsed, whatever its shape;
	// with ActionReject every body is scanned.
	OnExceed Action
}

var defaultLimits = Limits{
	MaxDepth: 32, MaxStrings: 20000, MaxStringBytes: 1 << 20, MaxMembers: 10000, MaxElements: 100000,
	MaxFindings: 100,
}

func (l Limits) resolved() Limits {
	pick := func(v, def int) int {
		switch {
		case v == 0:
			return def
		case v < 0:
			return int(^uint(0) >> 1)
		}
		return v
	}
	return Limits{
		MaxDepth:       pick(l.MaxDepth, defaultLimits.MaxDepth),
		MaxStrings:     pick(l.MaxStrings, defaultLimits.MaxStrings),
		MaxStringBytes: pick(l.MaxStringBytes, defaultLimits.MaxStringBytes),
		MaxMembers:     pick(l.MaxMembers, defaultLimits.MaxMembers),
		MaxElements:    pick(l.MaxElements, defaultLimits.MaxElements),
		MaxFindings:    pick(l.MaxFindings, defaultLimits.MaxFindings),
		OnExceed:       l.OnExceed,
	}
}

// KeyPolicy chooses extra checks on object key names, matching the store the data ends up in.
type KeyPolicy uint8

const (
	// KeyPolicyDefault checks keys for markup, control characters and prototype pollution.
	KeyPolicyDefault KeyPolicy = iota
	// KeyPolicyMongo also flags keys starting with $ (operators) and keys containing . or NUL.
	KeyPolicyMongo
)

// Option configures a Guard.
type Option func(*config) error

type config struct {
	mode        Mode
	profile     Profile
	enable      map[RuleID]bool
	actions     map[RuleID]Action
	sevActions  map[Severity]Action
	keyTable    *KeyTable
	classifier  Classifier
	fieldCtx    []fieldContext
	exempt      []string
	limits      Limits
	keyPolicy   KeyPolicy
	redirect    []string
	ssrfAllow   []string
	embedJSON   bool
	observer    func(Report)
	detectors   []Detector
	formulaCtxs []Context
}

type fieldContext struct {
	pattern string
	ctx     Context
}

// WithMode sets the default action (ModeClean if not set).
func WithMode(m Mode) Option {
	return func(c *config) error {
		if m > ModeReject {
			return fmt.Errorf("inputguard: unknown mode %d", m)
		}
		c.mode = m
		return nil
	}
}

// WithProfile chooses the default rule set. Without it, ModeClean uses ProfileBalanced and ModeReject uses
// ProfileStrict.
func WithProfile(p Profile) Option {
	return func(c *config) error {
		if p != ProfileBalanced && p != ProfileStrict {
			return fmt.Errorf("inputguard: unknown profile %d", p)
		}
		c.profile = p
		return nil
	}
}

// WithRules turns rules on regardless of the profile.
func WithRules(ids ...RuleID) Option {
	return func(c *config) error {
		for _, id := range ids {
			if _, ok := ruleIndex[id]; !ok {
				return fmt.Errorf("inputguard: unknown rule %q", id)
			}
			c.enable[id] = true
		}
		return nil
	}
}

// WithoutRules turns rules off regardless of the profile.
func WithoutRules(ids ...RuleID) Option {
	return func(c *config) error {
		for _, id := range ids {
			if _, ok := ruleIndex[id]; !ok {
				return fmt.Errorf("inputguard: unknown rule %q", id)
			}
			c.enable[id] = false
		}
		return nil
	}
}

// WithCategories turns every rule of the categories on.
func WithCategories(cats ...Category) Option {
	return func(c *config) error {
		for _, cat := range cats {
			found := false
			for _, r := range ruleTable {
				if r.Category == cat {
					c.enable[r.ID] = true
					found = true
				}
			}
			if !found {
				return fmt.Errorf("inputguard: unknown category %q", cat)
			}
		}
		return nil
	}
}

// WithAction overrides the action of one rule (it also enables the rule unless the action is ActionIgnore).
func WithAction(id RuleID, a Action) Option {
	return func(c *config) error {
		if _, ok := ruleIndex[id]; !ok {
			return fmt.Errorf("inputguard: unknown rule %q", id)
		}
		if a > ActionIgnore {
			return fmt.Errorf("inputguard: unknown action %d", a)
		}
		c.actions[id] = a
		if a != ActionIgnore {
			if _, set := c.enable[id]; !set {
				c.enable[id] = true
			}
		}
		return nil
	}
}

// WithSeverityAction sets the action for every finding of a severity (a per-rule WithAction wins).
func WithSeverityAction(s Severity, a Action) Option {
	return func(c *config) error {
		if s < SeverityLow || s > SeverityCritical {
			return fmt.Errorf("inputguard: unknown severity %d", s)
		}
		c.sevActions[s] = a
		return nil
	}
}

// WithKeyTable replaces the key table of the default classifier (see DefaultKeyTable).
func WithKeyTable(t KeyTable) Option {
	return func(c *config) error {
		cl := t.clone()
		c.keyTable = &cl
		return nil
	}
}

// WithKeyContext adds or overrides exact keys in the default key table.
func WithKeyContext(ctx Context, keys ...string) Option {
	return func(c *config) error {
		if c.keyTable == nil {
			t := DefaultKeyTable()
			c.keyTable = &t
		}
		for _, k := range keys {
			c.keyTable.Exact[strings.ToLower(k)] = ctx
		}
		return nil
	}
}

// WithClassifier replaces the classifier entirely. Field patterns (WithFieldContext) still take precedence.
func WithClassifier(f Classifier) Option {
	return func(c *config) error {
		c.classifier = f
		return nil
	}
}

// WithFieldContext forces the context of fields matching a path pattern: "a.b", "items[*].url" (any index),
// "**.description" (any depth), "*.name" (any key at one level). First matching pattern wins.
func WithFieldContext(pattern string, ctx Context) Option {
	return func(c *config) error {
		if _, err := compilePattern(pattern); err != nil {
			return err
		}
		c.fieldCtx = append(c.fieldCtx, fieldContext{pattern, ctx})
		return nil
	}
}

// WithExempt skips the CONTENT of fields matching the patterns (whole subtree). Key names inside are still
// checked. Same pattern syntax as WithFieldContext.
func WithExempt(patterns ...string) Option {
	return func(c *config) error {
		for _, p := range patterns {
			if _, err := compilePattern(p); err != nil {
				return err
			}
		}
		c.exempt = append(c.exempt, patterns...)
		return nil
	}
}

// WithLimits sets structural limits.
func WithLimits(l Limits) Option {
	return func(c *config) error {
		c.limits = l
		return nil
	}
}

// WithKeyPolicy adds key-name checks for a target store.
func WithKeyPolicy(p KeyPolicy) Option {
	return func(c *config) error {
		c.keyPolicy = p
		if p == KeyPolicyMongo {
			for _, id := range []RuleID{RuleKeyOperator, RuleKeyInvalid} {
				if _, set := c.enable[id]; !set {
					c.enable[id] = true
				}
			}
		}
		return nil
	}
}

// WithRedirectHosts lists hosts a redirect URL may point to ("example.com" also allows its subdomains; a leading
// "=" allows the exact host only). It enables RuleRedirect. Relative URLs are always allowed.
func WithRedirectHosts(hosts ...string) Option {
	return func(c *config) error {
		c.redirect = append(c.redirect, hosts...)
		if _, set := c.enable[RuleRedirect]; !set {
			c.enable[RuleRedirect] = true
		}
		return nil
	}
}

// WithSSRFAllow lists hosts or CIDR ranges that RuleSSRF must not flag (e.g. an internal service you call on
// purpose).
func WithSSRFAllow(entries ...string) Option {
	return func(c *config) error {
		c.ssrfAllow = append(c.ssrfAllow, entries...)
		return nil
	}
}

// WithFormulaContexts sets which contexts RuleFormula applies to (default: CtxText). Enable the rule for fields
// that end up in CSV or spreadsheet exports.
func WithFormulaContexts(ctxs ...Context) Option {
	return func(c *config) error {
		c.formulaCtxs = append([]Context(nil), ctxs...)
		return nil
	}
}

// WithEmbeddedJSON controls whether a string value that is itself a JSON object or array is parsed and inspected
// member by member (default true). When off, it is inspected as text.
func WithEmbeddedJSON(on bool) Option {
	return func(c *config) error {
		c.embedJSON = on
		return nil
	}
}

// WithObserver is called with every report that has findings (for metrics or logging). It must not keep the
// report's slices.
func WithObserver(f func(Report)) Option {
	return func(c *config) error {
		c.observer = f
		return nil
	}
}

// WithDetector adds a custom detector.
func WithDetector(d Detector) Option {
	return func(c *config) error {
		if d.ID == "" || d.Detect == nil {
			return fmt.Errorf("inputguard: detector needs an ID and a Detect function")
		}
		if _, clash := ruleIndex[d.ID]; clash {
			return fmt.Errorf("inputguard: detector ID %q clashes with a built-in rule", d.ID)
		}
		c.detectors = append(c.detectors, d)
		return nil
	}
}

// Detector is a custom rule. Detect receives the value decoded the way a browser or interpreter would see it
// (Decoded, and Folded = Decoded with ASCII lowercased, same length) and the raw value; it returns the byte offset
// in Decoded where the malicious part starts, or -1.
type Detector struct {
	ID       RuleID
	Category Category
	Severity Severity
	// Contexts the detector runs on (empty = text, URL and identifier).
	Contexts []Context
	// MayMatch is an optional cheap pre-check on the raw value; returning false skips decoding and Detect. It must
	// return true for every value Detect would flag.
	MayMatch func(raw string) bool
	Detect   func(in Input) int
}

// Input is what a detector sees.
type Input struct {
	Raw     string
	Decoded string
	Folded  string
	Context Context
	Key     string
}
