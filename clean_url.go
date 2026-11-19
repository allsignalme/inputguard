package inputguard

import (
	"strings"
	"unicode"
)

// cleanURL cleans a value shaped like a URL (scheme://, //host or /path). ok=false: not URL-shaped, clean it as
// text. Clean parts are kept verbatim (no re-encoding or reordering of the query).
func (g *Guard) cleanURL(s string, ctx Context) (string, bool) {
	trimmed := strings.TrimLeftFunc(s, func(r rune) bool { return r <= ' ' })
	var prefix, rest string
	if scheme, after, ok := splitScheme(trimmed); ok {
		ls := strings.ToLower(scheme)
		if (ls != "http" && ls != "https") || !strings.HasPrefix(after, "//") {
			return "", true // javascript:, data:, vbscript:… or http: without //
		}
		auth, tail := splitAuthority(after[2:])
		if !g.cleanHost(auth) {
			return "", true
		}
		prefix, rest = scheme+"://"+auth, tail
	} else if strings.HasPrefix(trimmed, "//") {
		auth, tail := splitAuthority(trimmed[2:])
		if !g.cleanHost(auth) {
			return "", true
		}
		prefix, rest = "//"+auth, tail
	} else if strings.HasPrefix(trimmed, "/") {
		rest = trimmed
	} else {
		return "", false
	}

	rest, frag, hasFrag := strings.Cut(rest, "#")
	path, query, hasQuery := strings.Cut(rest, "?")
	out := prefix + g.cleanPath(path)
	if hasQuery {
		if q := g.cleanQuery(query); q != "" {
			out += "?" + q
		}
	}
	if hasFrag && !g.cleanDirty(frag, CtxText, "") {
		out += "#" + frag
	}
	if g.cleanDirty(out, ctx, "") {
		return "", true
	}
	return out, true
}

func splitScheme(s string) (string, string, bool) {
	i := strings.IndexByte(s, ':')
	if i <= 0 || strings.ContainsAny(s[:i], "/?#") {
		return "", "", false
	}
	for j := 0; j < i; j++ {
		c := s[j]
		isAlpha := ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
		if !isAlpha && (j == 0 || !(('0' <= c && c <= '9') || c == '+' || c == '.' || c == '-')) {
			return "", "", false
		}
	}
	return s[:i], s[i+1:], true
}

func splitAuthority(s string) (string, string) {
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

func (g *Guard) cleanHost(auth string) bool {
	return auth != "" && !strings.ContainsAny(auth, "<>\"'` \t\n\r\\{}|^") && !g.cleanDirty(auth, CtxText, "")
}

// cleanPath keeps path segments (with their "/") up to the one that makes the kept prefix dirty. Checking the
// accumulated prefix catches a payload spread over several segments ("'\"--></style></script>…").
func (g *Guard) cleanPath(path string) string {
	if !g.cleanDirty(path, CtxText, "") {
		return path
	}
	kept := ""
	for _, seg := range strings.SplitAfter(path, "/") {
		if g.cleanDirty(kept+seg, CtxText, "") {
			break
		}
		kept += seg
	}
	return kept
}

// cleanQuery drops exactly the malicious key=value pairs and keeps the others verbatim and in order. Splits on
// "&" only (not ";"), so a payload containing ";" is not torn into clean-looking pieces.
func (g *Guard) cleanQuery(q string) string {
	if !g.cleanDirty(q, CtxText, "") {
		return q
	}
	parts := strings.Split(q, "&")
	kept := parts[:0]
	for _, p := range parts {
		if !g.cleanDirty(p, CtxText, "") {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "&")
}

func isUnicodeSpace(r rune) bool { return unicode.IsSpace(r) }
