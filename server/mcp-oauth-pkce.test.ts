import { describe, expect, it } from "vitest";

import { generatePkce, verifyPkce } from "./mcp-oauth-pkce.ts";

describe("MCP OAuth PKCE (RFC 7636, S256 only)", () => {
  it("generates a legal S256 verifier/challenge pair that round-trips", () => {
    const pkce = generatePkce();
    expect(pkce.codeChallengeMethod).toBe("S256");
    expect(pkce.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    expect(verifyPkce(pkce.codeVerifier, pkce.codeChallenge)).toBe(true);
  });

  it("generates a different verifier on every call", () => {
    const a = generatePkce();
    const b = generatePkce();
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
    expect(a.codeChallenge).not.toBe(b.codeChallenge);
  });

  it("rejects a tampered verifier against the original challenge", () => {
    const pkce = generatePkce();
    const other = generatePkce();
    expect(verifyPkce(other.codeVerifier, pkce.codeChallenge)).toBe(false);
  });

  it("rejects a verifier that is well-formed but simply wrong", () => {
    const pkce = generatePkce();
    // Same length/shape as a real verifier, but not the one that produced
    // this challenge.
    const wrongButLegal = "a".repeat(43);
    expect(verifyPkce(wrongButLegal, pkce.codeChallenge)).toBe(false);
  });

  it("rejects a verifier that is too short or has illegal characters", () => {
    const pkce = generatePkce();
    expect(verifyPkce("too-short", pkce.codeChallenge)).toBe(false);
    expect(verifyPkce("x".repeat(43) + "!", pkce.codeChallenge)).toBe(false);
  });

  it("rejects when the challenge itself was tampered with", () => {
    const pkce = generatePkce();
    const tamperedChallenge = pkce.codeChallenge.slice(0, -1) + (pkce.codeChallenge.at(-1) === "A" ? "B" : "A");
    expect(verifyPkce(pkce.codeVerifier, tamperedChallenge)).toBe(false);
  });
});
