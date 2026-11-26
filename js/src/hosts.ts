// Allowed redirect hosts and the SSRF allow list. Host names are byte strings (lowercase ASCII in practice).

import { containsAny, toBytes } from "./bytes.js";
import type { HostRules } from "./engine.js";
import type { Addr, Prefix } from "./ip.js";
import { parseAddr, parsePrefix, prefixContains, prefixOf, unmap } from "./ip.js";

function trimDot(h: string): string {
  return h.endsWith(".") ? h.slice(0, -1) : h;
}

/** "example.com" allows the host and its subdomains; "=example.com" the exact host only. */
export class HostMatcher {
  private readonly exact = new Set<string>();
  private readonly suffix: string[] = [];

  constructor(hosts: readonly string[]) {
    for (let h of hosts) {
      h = h.trim().toLowerCase();
      const exactOnly = h.startsWith("=");
      if (exactOnly) h = h.slice(1);
      h = trimDot(h);
      if (h === "" || containsAny(h, "/:?#@ ")) throw new Error(`inputguard: bad redirect host ${JSON.stringify(h)}`);
      h = toBytes(h);
      this.exact.add(h);
      if (!exactOnly) this.suffix.push("." + h);
    }
  }

  /** allows: host is lowercased, without port. */
  allows(host: string): boolean {
    host = trimDot(host);
    if (this.exact.has(host)) return true;
    for (const s of this.suffix) if (host.endsWith(s)) return true;
    return false;
  }
}

/** Hosts and address ranges the ssrf rule must not flag. */
export class SSRFAllowList {
  private readonly hosts = new Set<string>();
  private readonly prefixes: Prefix[] = [];

  constructor(entries: readonly string[]) {
    for (let e of entries) {
      e = e.trim().toLowerCase();
      if (e === "") continue;
      const p = parsePrefix(e);
      if (p !== null) {
        this.prefixes.push(p);
        continue;
      }
      const a = parseAddr(e);
      if (a !== null) {
        this.prefixes.push(prefixOf({ bytes: a.bytes, zone: "" }));
        continue;
      }
      if (containsAny(e, "/:?#@ ")) throw new Error(`inputguard: bad SSRF allow entry ${JSON.stringify(e)}`);
      this.hosts.add(toBytes(trimDot(e)));
    }
  }

  allowsHost(host: string): boolean {
    return this.hosts.has(trimDot(host));
  }

  allowsAddr(a: Addr): boolean {
    const u = unmap(a);
    for (const p of this.prefixes) if (prefixContains(p, u) || prefixContains(p, a)) return true;
    return false;
  }
}

/** hostRules builds the host lists of the URL rules. */
export function hostRules(redirectHosts: readonly string[], ssrfAllow: readonly string[]): HostRules {
  const redirect = new HostMatcher(redirectHosts);
  const ssrf = new SSRFAllowList(ssrfAllow);
  return {
    allowsRedirectHost: (host) => redirect.allows(host),
    allowsSSRFHost: (host) => ssrf.allowsHost(host),
    allowsSSRFAddr: (addr) => ssrf.allowsAddr(addr),
  };
}
