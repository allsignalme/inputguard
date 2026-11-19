package inputguard

import (
	"strings"

	"github.com/allsignalme/inputguard/internal/norm"
)

// Context is what a field is used for. It decides which rules apply and how a value is cleaned.
type Context uint8

const (
	// CtxText is free text (names, descriptions, notes). Cleaning cuts the value at the first malicious part and
	// keeps the clean text before it.
	CtxText Context = iota
	// CtxURL is a link (href, src, redirect target). Cleaning drops only the malicious query parameter, fragment or
	// path segment; a dangerous scheme or host empties the value.
	CtxURL
	// CtxIdentifier is an id, hash, click id or other value compared byte for byte later. Changing one character
	// breaks it, so a malicious value is emptied.
	CtxIdentifier
	// CtxSecret is a password, token or key. Reject mode never inspects it (any character is legitimate); clean
	// mode treats it as CtxIdentifier. Values are never logged.
	CtxSecret
	// CtxPath is a file name or path. Path traversal applies.
	CtxPath
	// CtxHeader is a value written into an HTTP header, cookie or log line. CR/LF applies.
	CtxHeader
	// CtxRedirect is a URL the application redirects the browser to (return_to, next…). URL rules apply, plus
	// RuleRedirect: it must be relative or point at a host allowed by WithRedirectHosts.
	CtxRedirect
	// CtxSkip is not inspected at all (content only: key names are still checked).
	CtxSkip
)

func (c Context) String() string {
	switch c {
	case CtxURL:
		return "url"
	case CtxIdentifier:
		return "identifier"
	case CtxSecret:
		return "secret"
	case CtxPath:
		return "path"
	case CtxHeader:
		return "header"
	case CtxRedirect:
		return "redirect"
	case CtxSkip:
		return "skip"
	}
	return "text"
}

// Classifier picks the context of a value from its key (the nearest object key; array elements inherit their
// array's key) and the value itself.
type Classifier func(key, value string) Context

// KeyTable is the data-driven part of the default classifier. Keys are compared case-insensitively.
type KeyTable struct {
	// Exact maps a key to its context.
	Exact map[string]Context
	// Suffix maps a key suffix (after the last "_" or the whole key, e.g. "_id", "_url") to its context.
	Suffix map[string]Context
	// Contains maps a substring to its context (e.g. "password" → CtxSecret). Checked before Exact.
	Contains map[string]Context
}

// DefaultKeyTable returns the default key classification. Callers may modify the returned copy and pass it to
// WithKeyTable.
func DefaultKeyTable() KeyTable {
	t := KeyTable{
		Exact:    map[string]Context{},
		Suffix:   map[string]Context{},
		Contains: map[string]Context{"password": CtxSecret, "passwd": CtxSecret, "secret": CtxSecret},
	}
	for _, k := range []string{
		// Hashed customer data and match keys (Meta / OpenAI Conversions APIs): one changed byte breaks the match.
		"em", "ph", "fn", "ln", "ct", "st", "zp", "ge", "db",
		"email", "phone", "first_name", "last_name", "city", "state", "zip",
		"fbp", "fbc", "obj_fbp_fbc", "external_id", "ext_id", "event_id", "id",
		"oppref", "obref", "fbclid", "gclid", "ttclid", "msclkid", "client_id", "shopify_client_id",
		"bv", "fp", "content_id", "content_ids", "sku", "gtin", "uuid", "hash", "checksum", "nonce", "etag",
	} {
		t.Exact[k] = CtxIdentifier
	}
	for _, k := range []string{
		"token", "access_token", "refresh_token", "id_token", "api_key", "apikey", "authorization",
		"private_key", "dsn", "client_secret", "session", "cookie_secret",
	} {
		t.Exact[k] = CtxSecret
	}
	for _, k := range []string{"filename", "file_name", "filepath", "file_path", "path", "dir", "directory", "file"} {
		t.Exact[k] = CtxPath
	}
	for _, k := range []string{"user_agent", "header", "headers", "cookie", "content_type", "host"} {
		t.Exact[k] = CtxHeader
	}
	// "_token" names (checkout_token, cart_token…) are ids that travel in clear and are compared byte for byte;
	// the secret ones are listed by exact name above.
	for _, s := range []string{"_token", "_id", "_ids", "_hash", "_uuid", "_sku"} {
		t.Suffix[s] = CtxIdentifier
	}
	for _, s := range []string{
		"url", "uri", "href", "link", "site", "referrer", "referer", "landing", "location", "callback", "website",
		"src", "origin", "endpoint", "webhook", "image", "avatar", "icon", "logo", "homepage", "home_page", "blog",
		"portfolio",
	} {
		t.Suffix["_"+s] = CtxURL
		t.Exact[s] = CtxURL
	}
	for _, s := range []string{"_path", "_file", "_filename", "_dir"} {
		t.Suffix[s] = CtxPath
	}
	for _, s := range []string{
		"redirect", "redirect_url", "redirect_uri", "redirect_to", "return_to", "return_url", "returnurl", "next",
		"next_url", "continue", "goto", "back_url", "success_url", "cancel_url", "failure_url", "error_url",
	} {
		t.Exact[s] = CtxRedirect
	}
	t.Suffix["_redirect"] = CtxRedirect
	t.Suffix["_return_url"] = CtxRedirect
	return t
}

func (t KeyTable) clone() KeyTable {
	c := KeyTable{Exact: map[string]Context{}, Suffix: map[string]Context{}, Contains: map[string]Context{}}
	for k, v := range t.Exact {
		c.Exact[strings.ToLower(k)] = v
	}
	for k, v := range t.Suffix {
		c.Suffix[strings.ToLower(k)] = v
	}
	for k, v := range t.Contains {
		c.Contains[strings.ToLower(k)] = v
	}
	return c
}

// classifier builds the default classifier over a key table: Contains, then Exact, then Suffix, then the shape
// of the value (http://, https:// or // ⇒ URL), else text.
func (t KeyTable) classifier() Classifier {
	contains := make([]struct {
		sub string
		ctx Context
	}, 0, len(t.Contains))
	for k, v := range t.Contains {
		contains = append(contains, struct {
			sub string
			ctx Context
		}{k, v})
	}
	suffixes := make([]struct {
		suf string
		ctx Context
	}, 0, len(t.Suffix))
	for k, v := range t.Suffix {
		suffixes = append(suffixes, struct {
			suf string
			ctx Context
		}{k, v})
	}
	// Longest suffix first, so "_ids" wins over "_id" and the result does not depend on map order.
	sortByLenDesc(suffixes, func(i int) int { return len(suffixes[i].suf) })
	sortByLenDesc(contains, func(i int) int { return len(contains[i].sub) })
	exact := t.Exact
	return func(key, value string) Context {
		k := lowerASCII(key)
		for _, c := range contains {
			if strings.Contains(k, c.sub) {
				return c.ctx
			}
		}
		if c, ok := exact[k]; ok {
			return c
		}
		for _, s := range suffixes {
			if strings.HasSuffix(k, s.suf) {
				return s.ctx
			}
		}
		if looksLikeURLValue(value) {
			return CtxURL
		}
		return CtxText
	}
}

func sortByLenDesc[T any](s []T, length func(i int) int) {
	// Insertion sort: tables are small and this runs once per Guard.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && length(j) > length(j-1); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func looksLikeURL(v string) bool {
	return hasPrefixFold(v, "http://") || hasPrefixFold(v, "https://") || strings.HasPrefix(v, "//")
}

// looksLikeURLValue: the value, as received or decoded, has the shape of a URL. Judging the decoded form too keeps
// the context stable when cleaning removes what hid the shape ("/\x7f/host" becomes "//host").
func looksLikeURLValue(v string) bool {
	return looksLikeURL(v) || (mayBeEncoded(v) && looksLikeURL(norm.Normalize(v).Decoded))
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// lowerASCII lowercases A–Z only and does not allocate when there is nothing to change.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if 'A' <= s[i] && s[i] <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// isURL: the value is a URL (link or redirect target).
func (c Context) isURL() bool { return c == CtxURL || c == CtxRedirect }

// ctxCount is the number of contexts (for per-context tables).
const ctxCount = CtxSkip + 1
