package inputguard

import (
	"fmt"
	"strconv"
	"strings"
)

// pattern matches a path against "a.b", "items[*].url", "items[2].url", "**.description", "*.name".
// It matches on path segments directly, without building path strings.
type pattern []patSeg

type patKind uint8

const (
	patKey      patKind = iota // exact key
	patAnyKey                  // *
	patAnyIndex                // [*]
	patIndex                   // [n]
	patAnyDepth                // ** (zero or more segments)
)

type patSeg struct {
	kind  patKind
	key   string
	index int
}

func compilePattern(s string) (pattern, error) {
	if s == "" {
		return nil, fmt.Errorf("inputguard: empty field pattern")
	}
	var p pattern
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return nil, fmt.Errorf("inputguard: bad field pattern %q", s)
		}
		name, rest, _ := strings.Cut(part, "[")
		switch name {
		case "**":
			if rest != "" {
				return nil, fmt.Errorf("inputguard: bad field pattern %q", s)
			}
			p = append(p, patSeg{kind: patAnyDepth})
			continue
		case "*":
			p = append(p, patSeg{kind: patAnyKey})
		case "":
			if !strings.Contains(part, "[") {
				return nil, fmt.Errorf("inputguard: bad field pattern %q", s)
			}
		default:
			p = append(p, patSeg{kind: patKey, key: name})
		}
		if !strings.Contains(part, "[") {
			continue
		}
		// One or more [..] groups after the name.
		for _, g := range strings.Split("["+rest, "[")[1:] {
			inner, ok := strings.CutSuffix(g, "]")
			if !ok {
				return nil, fmt.Errorf("inputguard: bad field pattern %q", s)
			}
			if inner == "*" {
				p = append(p, patSeg{kind: patAnyIndex})
				continue
			}
			n, err := strconv.Atoi(inner)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("inputguard: bad field pattern %q", s)
			}
			p = append(p, patSeg{kind: patIndex, index: n})
		}
	}
	return p, nil
}

func (p pattern) match(segs []PathSeg) bool { return matchSegs(p, segs) }

func matchSegs(p pattern, segs []PathSeg) bool {
	for len(p) > 0 {
		ps := p[0]
		if ps.kind == patAnyDepth {
			rest := p[1:]
			if len(rest) == 0 {
				return true
			}
			for i := 0; i <= len(segs); i++ {
				if matchSegs(rest, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		s := segs[0]
		switch ps.kind {
		case patKey:
			// A key unsafe to print (see safePathKey) never matches a literal pattern, so a client cannot dress a
			// key up to look like an exempt path.
			if s.Index >= 0 || s.Key != ps.key || !safePathKey(s.Key) {
				return false
			}
		case patAnyKey:
			if s.Index >= 0 {
				return false
			}
		case patAnyIndex:
			if s.Index < 0 {
				return false
			}
		case patIndex:
			if s.Index != ps.index {
				return false
			}
		}
		p, segs = p[1:], segs[1:]
	}
	return len(segs) == 0
}

type patternSet []pattern

func compilePatterns(ss []string) (patternSet, error) {
	var out patternSet
	for _, s := range ss {
		p, err := compilePattern(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (ps patternSet) match(segs []PathSeg) bool {
	for _, p := range ps {
		if p.match(segs) {
			return true
		}
	}
	return false
}
