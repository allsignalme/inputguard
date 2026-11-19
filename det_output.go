package inputguard

import (
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	textnorm "golang.org/x/text/unicode/norm"

	"github.com/allsignalme/inputguard/internal/norm"
)

// Rules about where a value ends up: a spreadsheet (formula injection), a server-side fetch (SSRF), a browser
// redirect (open redirect); and look-alike identifiers mixing scripts.

func init() {
	registerDetector(&builtinDetector{
		name:     "formula",
		rules:    []RuleID{RuleFormula},
		contexts: allInspected, // narrowed by WithFormulaContexts at detection time
		mayMatch: func(_ *Guard, raw string) bool { return mayBeFormula(raw) },
		detect:   detectFormula,
		clean:    cleanPrefix,
	})
	registerDetector(&builtinDetector{
		name:     "ssrf",
		rules:    []RuleID{RuleSSRF},
		contexts: urlContexts,
		needNorm: true,
		detect:   detectSSRF,
		clean:    cleanEmpty,
	})
	registerDetector(&builtinDetector{
		name:     "redirect",
		rules:    []RuleID{RuleRedirect},
		contexts: maskOf(CtxRedirect),
		needNorm: true,
		detect:   detectRedirect,
		clean:    cleanEmpty,
	})
	registerDetector(&builtinDetector{
		name:     "mixed_scripts",
		rules:    []RuleID{RuleMixedScripts},
		contexts: allInspected,
		mayMatch: func(_ *Guard, raw string) bool { return mayHaveConfusableScript(raw) },
		needNorm: true,
		detect:   detectMixedScripts,
		clean:    cleanCut,
	})
}

// --- Formula (CSV) injection ---

func mayBeFormula(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\t', '\r', '\n':
			continue
		case '=', '+', '-', '@', 0xEF:
			return true
		}
		return false
	}
	return false
}

// detectFormula flags a value a spreadsheet would evaluate: it starts with = (or + - @ followed by a function call,
// a DDE pipe or a sheet reference), possibly after tabs or line breaks some importers strip. Plain numbers and
// phone numbers ("+84 912 345 678", "-12.5") are not flagged.
func detectFormula(g *Guard, in *input, emit func(RuleID, int)) {
	if !g.formulaOn.has(in.ctx) {
		return
	}
	s := in.raw
	i := 0
	for i < len(s) && (s[i] == '\t' || s[i] == '\r' || s[i] == '\n') {
		i++
	}
	r, size := utf8.DecodeRuneInString(s[i:])
	switch r {
	case '=', '＝':
		emit(RuleFormula, 0)
	case '+', '-', '@', '＋', '－', '＠':
		if rest := s[i+size:]; !numericLike(rest) && strings.ContainsAny(rest, "(|!") {
			emit(RuleFormula, 0)
		}
	}
}

func numericLike(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9') && !strings.ContainsRune(" .,()-+/%", rune(c)) {
			return false
		}
	}
	return true
}

// --- SSRF ---

// ssrfSchemes are fetched by some server-side clients and have no business in user input.
var ssrfSchemes = map[string]bool{
	"file": true, "gopher": true, "dict": true, "ldap": true, "ldaps": true, "tftp": true, "jar": true,
	"netdoc": true, "smb": true, "phar": true, "expect": true, "glob": true,
}

// specialSchemes: URL schemes whose authority browsers parse leniently (any mix of / and \ after the colon).
var specialSchemes = map[string]bool{"http": true, "https": true, "ws": true, "wss": true, "ftp": true}

// The URL rules read the value twice: as received (what a URL parser and a browser see: %2F@ inside the
// authority is userinfo, the host comes after it) and fully decoded (what an application that decodes the value
// once more would fetch). Either reading can flag it.
func urlReadings(in *input) [2]string { return [2]string{in.raw, in.decoded()} }

func detectSSRF(g *Guard, in *input, emit func(RuleID, int)) {
	for _, s := range urlReadings(in) {
		if g.ssrfTarget(parseURLLoose(s)) {
			emit(RuleSSRF, 0)
			return
		}
	}
}

func (g *Guard) ssrfTarget(u looseURL) bool {
	if ssrfSchemes[u.scheme] {
		return true
	}
	if !u.hasAuthority || u.host == "" || g.ssrfAllow.allowsHost(u.host) {
		return false
	}
	if internalHostName(u.host) {
		return true
	}
	a, ok := parseHostIP(u.host)
	return ok && internalAddr(a) && !g.ssrfAllow.allowsAddr(a)
}

// internalHostName: names that resolve to the machine itself, the local network or a cloud metadata service,
// whatever DNS says. Other names are not resolved here: a fetch must still check the address it connects to.
func internalHostName(h string) bool {
	switch h {
	case "localhost", "metadata", "metadata.google.internal", "instance-data", "kubernetes", "kubernetes.default",
		"localtest.me", "lvh.me", "vcap.me", "lacolhost.com", "0":
		return true
	}
	for _, suf := range []string{
		".localhost", ".internal", ".local", ".localdomain", ".home.arpa", ".intranet", ".corp", ".lan",
		".svc.cluster.local", ".cluster.local", ".nip.io", ".sslip.io", ".xip.io", ".localtest.me", ".lvh.me",
		".vcap.me", ".lacolhost.com",
	} {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}

// parseHostIP reads an IP literal the way URL parsers and inet_aton do: IPv6 in brackets (zone allowed), and IPv4
// in 1 to 4 parts, each decimal, octal (leading 0) or hex (0x): 127.1, 2130706433, 0x7f.0.0.1, 0177.0.0.1.
func parseHostIP(h string) (netip.Addr, bool) {
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
		if i := strings.IndexByte(h, '%'); i >= 0 {
			h = h[:i]
		}
		a, err := netip.ParseAddr(h)
		return a, err == nil && a.Is6()
	}
	if strings.IndexByte(h, ':') >= 0 {
		a, err := netip.ParseAddr(h)
		return a, err == nil
	}
	parts := strings.Split(h, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	vals := make([]uint64, 0, 4)
	for _, p := range parts {
		if p == "" {
			return netip.Addr{}, false
		}
		base := 10
		switch {
		case len(p) > 2 && (p[:2] == "0x" || p[:2] == "0X"):
			base, p = 16, p[2:]
		case len(p) > 1 && p[0] == '0':
			base, p = 8, p[1:]
		}
		v, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		vals = append(vals, v)
	}
	var ip uint64
	last := len(vals) - 1
	for i, v := range vals[:last] {
		if v > 255 {
			return netip.Addr{}, false
		}
		ip |= v << (24 - 8*i)
	}
	if vals[last] >= 1<<(32-8*last) {
		return netip.Addr{}, false
	}
	ip |= vals[last]
	return netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}), true
}

var internalPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// internalAddr: loopback, private, link-local (cloud metadata), shared, unspecified, multicast or reserved, also
// when wrapped in IPv6 (mapped, compatible, NAT64, 6to4).
func internalAddr(a netip.Addr) bool {
	a = a.Unmap()
	if a.Is6() {
		b := a.As16()
		switch {
		case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b: // 64:ff9b::/96 NAT64
			return internalAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
		case b[0] == 0x20 && b[1] == 0x02: // 2002::/16 6to4
			return internalAddr(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
		case isZero(b[:12]) && !isZero(b[12:14]): // ::a.b.c.d (deprecated IPv4-compatible)
			return internalAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
		}
	}
	for _, p := range internalPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// --- Open redirect ---

// detectRedirect: a redirect target must be relative (same site) or point at a host allowed by
// WithRedirectHosts. Forms browsers read as another host are caught too: //evil, /\evil, \\evil, https:evil.
func detectRedirect(g *Guard, in *input, emit func(RuleID, int)) {
	for _, s := range urlReadings(in) {
		if g.foreignRedirect(parseURLLoose(s)) {
			emit(RuleRedirect, 0)
			return
		}
	}
}

func (g *Guard) foreignRedirect(u looseURL) bool {
	if u.scheme != "" && u.scheme != "http" && u.scheme != "https" {
		return true // mailto:, ftp:, custom schemes (javascript: is RuleScheme)
	}
	return u.hasAuthority && (u.host == "" || !g.redirect.allows(u.host))
}

// --- URL parsing shared by SSRF and redirect checks ---

type looseURL struct {
	scheme       string // lowercased; "" for relative and scheme-relative URLs
	hasAuthority bool
	host         string // lowercased, decoded, without userinfo, port or trailing dot; brackets kept for IPv6
}

// parseURLLoose reads a URL the way a browser does, so that tricks aimed at a stricter parser do not hide the
// host: leading spaces and controls are dropped, tabs and line breaks removed, backslashes count as slashes after
// a special scheme, userinfo is skipped, Unicode dots are dots.
func parseURLLoose(s string) looseURL {
	s = strings.TrimLeftFunc(s, func(r rune) bool { return r <= ' ' })
	if strings.ContainsAny(s, "\t\n\r") {
		s = strings.Map(func(r rune) rune {
			if r == '\t' || r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, s)
	}
	var u looseURL
	rest := s
	if scheme, after, ok := splitScheme(s); ok {
		u.scheme = strings.ToLower(scheme)
		switch {
		case specialSchemes[u.scheme]:
			rest = strings.TrimLeft(after, `/\`)
			u.hasAuthority = true
		case strings.HasPrefix(after, "//"):
			rest = after[2:]
			u.hasAuthority = true
		default:
			return u
		}
	} else if len(s) >= 2 && isPathSep(s[0]) && isPathSep(s[1]) {
		rest = strings.TrimLeft(s, `/\`)
		u.hasAuthority = true
	} else {
		return u
	}
	auth := rest
	if i := strings.IndexAny(rest, `/\?#`); i >= 0 {
		auth = rest[:i]
	}
	if i := strings.LastIndexByte(auth, '@'); i >= 0 {
		auth = auth[i+1:]
	}
	if strings.ContainsAny(auth, "%&\\") || hasNonASCII(auth) {
		auth = norm.Normalize(auth).Decoded
	}
	if hasNonASCII(auth) {
		// HTTP clients map the host with IDNA (UTS 46, close to NFKC with case folding): ①②⑦.0.0.1 and
		// ⓛⓞⓒⓐⓛⓗⓞⓢⓣ reach the loopback.
		auth = textnorm.NFKC.String(strings.Map(dropIgnorable, auth))
	}
	auth = strings.NewReplacer("。", ".", "｡", ".", "．", ".").Replace(auth)
	host := auth
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i >= 0 {
			host = host[:i+1]
		}
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	u.host = strings.TrimRight(strings.ToLower(host), ".")
	return u
}

// dropIgnorable removes the default-ignorable code points IDNA maps to nothing (variation selectors, the combining
// grapheme joiner, format characters such as soft hyphen and zero-width joiners): 127\uFE00.0.0.1 is 127.0.0.1 to
// an HTTP client.
func dropIgnorable(r rune) rune {
	if unicode.Is(unicode.Variation_Selector, r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) ||
		unicode.Is(unicode.Cf, r) {
		return -1
	}
	return r
}

func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return true
		}
	}
	return false
}

// --- Mixed scripts ---

// mayHaveConfusableScript: a letter of a script that mixes with Latin (see scriptOf), or an encoded form. Latin
// letters (Latin-1, Latin Extended, Vietnamese) are skipped without a table lookup.
func mayHaveConfusableScript(s string) bool {
	if mayBeEncoded(s) {
		return true
	}
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r < 0x250 || (r >= 0x1E00 && r <= 0x1EFF) {
			continue
		}
		if sc := scriptOf(r); sc != 0 && sc != scriptLatin {
			return true
		}
	}
	return false
}

const (
	scriptLatin uint8 = 1 << iota
	scriptCyrillic
	scriptGreek
	scriptArmenian
	scriptCherokee
)

func scriptOf(r rune) uint8 {
	switch {
	case r < utf8.RuneSelf:
		if ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') {
			return scriptLatin
		}
		return 0
	case unicode.Is(unicode.Latin, r):
		return scriptLatin
	case unicode.Is(unicode.Cyrillic, r):
		return scriptCyrillic
	case unicode.Is(unicode.Greek, r):
		return scriptGreek
	case unicode.Is(unicode.Armenian, r):
		return scriptArmenian
	case unicode.Is(unicode.Cherokee, r):
		return scriptCherokee
	}
	return 0
}

// detectMixedScripts flags a word that mixes Latin with Cyrillic, Greek, Armenian or Cherokee letters (or two of
// those): "pаypal" with a Cyrillic а. Words in one script, in any language, are never flagged.
func detectMixedScripts(_ *Guard, in *input, emit func(RuleID, int)) {
	s := in.decoded()
	start := -1
	var mask uint8
	for i, r := range s {
		if unicode.IsLetter(r) || unicode.Is(unicode.Mn, r) {
			if start < 0 {
				start, mask = i, 0
			}
			mask |= scriptOf(r)
			continue
		}
		if start >= 0 && mask&(mask-1) != 0 {
			emit(RuleMixedScripts, start)
			return
		}
		start = -1
	}
	if start >= 0 && mask&(mask-1) != 0 {
		emit(RuleMixedScripts, start)
	}
}
