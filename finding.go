package inputguard

import (
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Finding is one rule matching one field. It never contains the value: values can be personal data or the
// payload itself.
type Finding struct {
	Rule     RuleID
	Category Category
	Severity Severity
	// Path locates the field: "items[0].title". A finding on a key name ends with "[key]"; a key that is unsafe to
	// print (not 1–64 bytes of [A-Za-z0-9_-]) is printed as "[key]" too. Empty for a bare string.
	Path    string
	Context Context
	// Action is what was done: ActionClean, ActionReject or ActionReport.
	Action Action
	// Offset is the byte offset in the decoded value where the malicious part starts (-1 when not applicable).
	Offset int
}

// Report is the outcome of inspecting one document or value.
type Report struct {
	Findings []Finding
	// Changed: the output differs from the input.
	Changed bool
	// Rejected: at least one finding has ActionReject. The output is the input unchanged for those values.
	Rejected bool
	// Truncated: more findings than Limits.MaxFindings occurred; only the first ones are kept.
	Truncated bool
	// InvalidJSON: the body is not valid JSON. It is returned unchanged and not inspected.
	InvalidJSON bool
	// LimitExceeded: a structural limit was hit (see RuleTooComplex).
	LimitExceeded bool
}

// Clean reports whether nothing was found.
func (r Report) Clean() bool { return len(r.Findings) == 0 && !r.Rejected && !r.LimitExceeded }

// Rules returns the distinct rules found, in order of first appearance.
func (r Report) Rules() []RuleID {
	var out []RuleID
	seen := map[RuleID]bool{}
	for _, f := range r.Findings {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			out = append(out, f.Rule)
		}
	}
	return out
}

// Summary returns the distinct rules and up to maxFields distinct paths, comma-separated — for one log line.
func (r Report) Summary(maxFields int) (rules, fields string) {
	var rb, fb strings.Builder
	seenRule, seenField := map[RuleID]bool{}, map[string]bool{}
	n := 0
	for _, f := range r.Findings {
		if !seenRule[f.Rule] {
			seenRule[f.Rule] = true
			if rb.Len() > 0 {
				rb.WriteByte(',')
			}
			rb.WriteString(string(f.Rule))
		}
		if !seenField[f.Path] && n < maxFields {
			seenField[f.Path] = true
			if fb.Len() > 0 {
				fb.WriteByte(',')
			}
			fb.WriteString(f.Path)
			n++
		}
	}
	return rb.String(), fb.String()
}

// ErrRejected is returned by convenience helpers when a report is rejected.
var ErrRejected = errors.New("inputguard: input rejected")

// PathSeg is one step of a path: an object key (Index = -1) or an array index.
type PathSeg struct {
	Key   string
	Index int
}

// LeafChange is one string leaf changed by CleanLeaves. A string holding embedded JSON counts as one leaf.
type LeafChange struct {
	Path     []PathSeg
	Old, New string
}

// Err returns nil unless the report is rejected. The error lists the rejected rules and paths, never values, so
// its message can be returned to an API client. errors.Is(err, ErrRejected) holds.
func (r Report) Err() error {
	if !r.Rejected {
		return nil
	}
	return &RejectedError{Report: r}
}

// RejectedError is the error returned by Report.Err.
type RejectedError struct{ Report Report }

func (e *RejectedError) Unwrap() error { return ErrRejected }

func (e *RejectedError) Error() string {
	var b strings.Builder
	b.WriteString("input rejected")
	first := true
	for _, f := range e.Report.Findings {
		if f.Action != ActionReject {
			continue
		}
		if first {
			b.WriteString(": ")
			first = false
		} else {
			b.WriteString("; ")
		}
		if f.Path != "" {
			b.WriteString(f.Path)
			b.WriteString(": ")
		}
		if info, ok := ruleIndex[f.Rule]; ok {
			b.WriteString(info.Summary)
		} else {
			b.WriteString(string(f.Rule))
		}
	}
	if first && e.Report.LimitExceeded {
		b.WriteString(": ")
		b.WriteString(ruleIndex[RuleTooComplex].Summary)
	}
	return b.String()
}

const (
	keyPathMarker = "[key]"
	maxPathKeyLen = 64
)

// safePathKey: 1–64 bytes of [A-Za-z0-9_-]. Enough for any API field name, unable to carry a payload.
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

func formatPath(segs []PathSeg) string {
	var b strings.Builder
	for i, s := range segs {
		if s.Index >= 0 {
			b.WriteByte('[')
			b.WriteString(strconv.Itoa(s.Index))
			b.WriteByte(']')
			continue
		}
		if !safePathKey(s.Key) {
			b.WriteString(keyPathMarker)
			continue
		}
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(s.Key)
	}
	return b.String()
}

// sortFindings orders findings by path (maps are walked in random order; a stable report is easier to log).
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Path < fs[j].Path })
}
