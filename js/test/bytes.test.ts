import { describe, expect, it } from "vitest";
import {
  decodeLastRune,
  decodeRune,
  encodeRune,
  fromBytes,
  RUNE_ERROR,
  toBytes,
  toValidUTF8,
  trimRightRunes,
  validUTF8,
} from "../src/bytes.js";

const b = (...xs: number[]): string => String.fromCharCode(...xs);

describe("byte strings", () => {
  it("round-trips text, emoji and long strings", () => {
    for (const s of ["", "abc", "Tiếng Việt có dấu", String.fromCodePoint(0x1f525, 0x10ffff), "é".repeat(20000)]) {
      expect(fromBytes(toBytes(s))).toBe(s);
      expect(validUTF8(toBytes(s))).toBe(true);
    }
    expect(toBytes("é")).toBe(b(0xc3, 0xa9));
  });

  it("decodes like utf8.DecodeRuneInString", () => {
    expect(decodeRune("", 0)).toEqual([RUNE_ERROR, 0]);
    expect(decodeRune(b(0xe0, 0x80, 0x80), 0)).toEqual([RUNE_ERROR, 1]); // overlong
    expect(decodeRune(b(0xed, 0xa0, 0x80), 0)).toEqual([RUNE_ERROR, 1]); // surrogate
    expect(decodeRune(b(0xf4, 0x90, 0x80, 0x80), 0)).toEqual([RUNE_ERROR, 1]); // past U+10FFFF
    expect(decodeRune(b(0xf0, 0x9f, 0x94, 0xa5), 0)).toEqual([0x1f525, 4]);
    expect(decodeRune(b(0xc3), 0)).toEqual([RUNE_ERROR, 1]);
    expect(decodeRune(b(0xe2, 0x82, 0x41), 0)).toEqual([RUNE_ERROR, 1]);
    expect(decodeRune(b(0xf0, 0x9f, 0x94, 0x41), 0)).toEqual([RUNE_ERROR, 1]);
    expect(decodeLastRune(b(0x61, 0xc3, 0xa9), 3)).toEqual([0xe9, 2]);
    expect(decodeLastRune(b(0x61, 0xa9), 2)).toEqual([RUNE_ERROR, 1]);
    expect(decodeLastRune("", 0)).toEqual([RUNE_ERROR, 0]);
    expect(decodeLastRune(b(0xa9, 0xa9, 0xa9, 0xa9, 0xa9), 5)).toEqual([RUNE_ERROR, 1]);
  });

  it("encodes invalid runes as U+FFFD and replaces runs of invalid bytes once", () => {
    expect(encodeRune(0xd800)).toBe(b(0xef, 0xbf, 0xbd));
    expect(encodeRune(-1)).toBe(b(0xef, 0xbf, 0xbd));
    expect(toValidUTF8(b(0x61, 0xff, 0xfe, 0x62, 0xc3, 0xa9, 0xff), "?")).toBe("a?b" + b(0xc3, 0xa9) + "?");
    expect(fromBytes(b(0x61, 0xff, 0x62))).toBe("a" + String.fromCharCode(0xfffd) + "b");
  });

  it("trims runes on the right", () => {
    expect(trimRightRunes("ab  " + b(0xc2, 0xa0), (r) => r === 0x20 || r === 0xa0)).toBe("ab");
    expect(trimRightRunes("ab" + b(0xff), (r) => r === RUNE_ERROR)).toBe("ab");
  });
});

describe("entity table", () => {
  it("expands to every name of Go's table", async () => {
    const { unescapeHTML } = await import("../src/norm.js");
    const { ENTITY_COUNT } = await import("../src/tables/entities.js");
    expect(ENTITY_COUNT).toBeGreaterThan(2000);
    expect(fromBytes(unescapeHTML("&amp; &AMP; &amp &notin; &NotEqualTilde; &Tab;x &ampx &#x41; &#65; &#128;"))).toBe(
      "& & & " + String.fromCodePoint(0x2209) + " " + String.fromCodePoint(0x2242, 0x338) + " \tx &x A A " + String.fromCodePoint(0x20ac),
    );
  });
});
