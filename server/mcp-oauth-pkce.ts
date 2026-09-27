// RFC 7636 PKCE (Proof Key for Code Exchange), S256 only. A flow that cannot
// prove S256 support at discovery time must never reach here — see
// mcp-oauth-discovery.ts, which fails closed before any redirect is issued.
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export interface Pkce {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}

const CODE_VERIFIER = /^[A-Za-z0-9_-]{43,128}$/;

function base64UrlSha256(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}

/** 32 random bytes base64url-encode to exactly 43 characters — the shortest
 * length RFC 7636 §4.1 allows — so every verifier this generates is legal
 * without padding or truncation logic. */
export function generatePkce(): Pkce {
  const codeVerifier = randomBytes(32).toString("base64url");
  return { codeVerifier, codeChallenge: base64UrlSha256(codeVerifier), codeChallengeMethod: "S256" };
}

/** What a mock token endpoint (or a real one) checks: the verifier the client
 * presents at the token request must hash to the challenge it presented at
 * the authorization request. Constant-time on the digest so a byte-by-byte
 * timing probe cannot shortcut a guess. */
export function verifyPkce(codeVerifier: string, codeChallenge: string): boolean {
  if (!CODE_VERIFIER.test(codeVerifier)) return false;
  const expected = Buffer.from(base64UrlSha256(codeVerifier));
  const actual = Buffer.from(codeChallenge);
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}
