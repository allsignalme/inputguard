package inputguard

import (
	"fmt"
	"net/netip"
	"strings"
)

// hostMatcher holds the allowed redirect hosts. "example.com" allows the host and its subdomains; "=example.com"
// allows the exact host only.
type hostMatcher struct {
	exact  map[string]bool
	suffix []string // ".example.com"
}

func newHostMatcher(hosts []string) (hostMatcher, error) {
	m := hostMatcher{exact: map[string]bool{}}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		exactOnly := strings.HasPrefix(h, "=")
		h = strings.TrimPrefix(h, "=")
		h = strings.TrimSuffix(h, ".")
		if h == "" || strings.ContainsAny(h, "/:?#@ ") {
			return m, fmt.Errorf("inputguard: bad redirect host %q", h)
		}
		m.exact[h] = true
		if !exactOnly {
			m.suffix = append(m.suffix, "."+h)
		}
	}
	return m, nil
}

func (m hostMatcher) empty() bool { return len(m.exact) == 0 }

// allows reports whether host (already lowercased, no port) is allowed.
func (m hostMatcher) allows(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if m.exact[host] {
		return true
	}
	for _, s := range m.suffix {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

// ssrfAllowList holds hosts and address ranges RuleSSRF must not flag.
type ssrfAllowList struct {
	hosts    map[string]bool
	prefixes []netip.Prefix
}

func newSSRFAllowList(entries []string) (ssrfAllowList, error) {
	l := ssrfAllowList{hosts: map[string]bool{}}
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			l.prefixes = append(l.prefixes, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			l.prefixes = append(l.prefixes, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		if strings.ContainsAny(e, "/:?#@ ") {
			return l, fmt.Errorf("inputguard: bad SSRF allow entry %q", e)
		}
		l.hosts[strings.TrimSuffix(e, ".")] = true
	}
	return l, nil
}

func (l ssrfAllowList) allowsHost(host string) bool { return l.hosts[strings.TrimSuffix(host, ".")] }

func (l ssrfAllowList) allowsAddr(a netip.Addr) bool {
	for _, p := range l.prefixes {
		if p.Contains(a.Unmap()) || p.Contains(a) {
			return true
		}
	}
	return false
}
