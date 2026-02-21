import { describe, it, expect, jest, beforeEach, afterEach } from "@jest/globals";
import { parseKeyRef, formatTtl } from "./helpers";

describe("parseKeyRef", () => {
  it("strips sirr: prefix", () => {
    expect(parseKeyRef("sirr:MY_KEY")).toBe("MY_KEY");
  });

  it("extracts key from hash format", () => {
    expect(parseKeyRef("MY_KEY#some-server")).toBe("MY_KEY");
  });

  it("returns bare key as-is", () => {
    expect(parseKeyRef("MY_KEY")).toBe("MY_KEY");
  });

  it("trims whitespace from bare keys", () => {
    expect(parseKeyRef("  MY_KEY  ")).toBe("MY_KEY");
  });

  it("handles sirr: with no key (edge case)", () => {
    expect(parseKeyRef("sirr:")).toBe("");
  });

  it("takes only the part before the first # in hash format", () => {
    expect(parseKeyRef("KEY#a#b")).toBe("KEY");
  });
});

describe("formatTtl", () => {
  const realDateNow = Date.now;

  beforeEach(() => {
    // Pin now to a fixed Unix timestamp (seconds = 1_000_000)
    jest.spyOn(Date, "now").mockReturnValue(1_000_000 * 1000);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("returns 'no expiry' for null", () => {
    expect(formatTtl(null)).toBe("no expiry");
  });

  it("returns 'expired' for past timestamp", () => {
    expect(formatTtl(999_999)).toBe("expired");
  });

  it("returns 'expired' for exactly now", () => {
    expect(formatTtl(1_000_000)).toBe("expired");
  });

  it("formats seconds (< 60s)", () => {
    expect(formatTtl(1_000_000 + 45)).toBe("45s");
  });

  it("formats minutes (60s – 3599s)", () => {
    expect(formatTtl(1_000_000 + 120)).toBe("2m");
    expect(formatTtl(1_000_000 + 3599)).toBe("59m");
  });

  it("formats hours (3600s – 86399s)", () => {
    expect(formatTtl(1_000_000 + 3600)).toBe("1h");
    expect(formatTtl(1_000_000 + 7200)).toBe("2h");
  });

  it("formats days (≥ 86400s)", () => {
    expect(formatTtl(1_000_000 + 86400)).toBe("1d");
    expect(formatTtl(1_000_000 + 86400 * 7)).toBe("7d");
  });
});
