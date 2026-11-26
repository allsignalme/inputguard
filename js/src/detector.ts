// Built-in detectors: groups of rules with the contexts they run on, their fast-path bits and how a finding is
// cleaned. A build of the library registers the detectors it ships (see index.ts and balanced.ts).

import type { Normalized } from "./norm.js";
import { normalize } from "./norm.js";
import type { RuleID } from "./rule.js";
import { CTX_HEADER, CTX_IDENTIFIER, CTX_PATH, CTX_REDIRECT, CTX_TEXT, CTX_URL, maskOf } from "./rule.js";

/** How a finding is removed in clean mode. */
export const CLEAN_CUT = 0; // cut text at the finding; a URL loses the bad part; an identifier is emptied
export const CLEAN_CHARS = 1; // remove the offending characters only
export const CLEAN_PREFIX = 2; // neutralise by prefixing (formula injection)
export const CLEAN_EMPTY = 3; // empty the value

export const ALL_INSPECTED = maskOf(CTX_TEXT, CTX_URL, CTX_IDENTIFIER, CTX_PATH, CTX_HEADER, CTX_REDIRECT);

/** What detectors may read from the guard. */
export interface DetectorEnv {
  readonly strictProfile: boolean;
  /** Contexts the formula rule applies to (mask). */
  readonly formulaOn: number;
  allowsRedirectHost(host: string): boolean;
  allowsSSRFHost(host: string): boolean;
  allowsSSRFAddr(addr: IPAddr): boolean;
}

/** An IP address: 4 or 16 bytes, an IPv6 zone. */
export interface IPAddr {
  bytes: number[];
  zone: string;
}

/** One string value being inspected (byte strings). */
export class Input {
  private n: Normalized | null = null;

  constructor(
    readonly raw: string,
    readonly ctx: number,
    readonly key: string,
  ) {}

  get done(): boolean {
    return this.n !== null;
  }

  private norm(): Normalized {
    if (this.n === null) this.n = normalize(this.raw);
    return this.n;
  }

  decoded(): string {
    return this.norm().decoded;
  }

  folded(): string {
    return this.norm().folded;
  }
}

export type Emit = (id: RuleID, offset: number) => void;

export interface DetectorDef {
  name: string;
  rules: readonly RuleID[];
  contexts: number;
  /** Fast-path bits covering the group; 0: the group has its own mayMatch. */
  fast: number;
  /** Cheap check on the raw value for groups without fast bits; must be true for every value detect flags. */
  mayMatch?: (raw: string) => boolean;
  detect: (env: DetectorEnv, input: Input, emit: Emit) => void;
  clean: number;
}
