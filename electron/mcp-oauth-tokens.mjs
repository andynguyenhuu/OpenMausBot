// MCP OAuth connection records, kept in the same OS-encrypted document as
// every other desktop credential (credentials.bin via safeStorage — see
// electron/secure-credentials.mjs and electron/secure-credential-state.mjs).
// Shaped after electron/phone-secret-identity.mjs: one document key holding
// a plain object, read/written through updateSecureCredentialDocument so a
// concurrent mutation (a second connection completing at the same instant)
// can never clobber this one.
export const MCP_OAUTH_CREDENTIAL_KEY = "mcpOAuthTokens";

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The whole stored map: `{ [connectionId]: record }`. Never trusts a
 * malformed document into a crash — a document with a wrong shape (a stray
 * string, an old export) reads back as "no connections" rather than
 * throwing partway through a request. */
export function readMcpOauthTokens(credentials) {
  const stored = credentials?.[MCP_OAUTH_CREDENTIAL_KEY];
  if (!isRecord(stored)) return {};
  const out = {};
  for (const [connectionId, record] of Object.entries(stored)) {
    if (isRecord(record) && typeof record.connectionId === "string") out[connectionId] = record;
  }
  return out;
}

export function readMcpOauthToken(credentials, connectionId) {
  return readMcpOauthTokens(credentials)[connectionId] ?? null;
}

/** Pure reducer: the caller passes this to updateSecureCredentialDocument so
 * the read-modify-write happens under that module's queue, never here. */
export function withMcpOauthToken(credentials, connectionId, record) {
  const tokens = readMcpOauthTokens(credentials);
  return { ...credentials, [MCP_OAUTH_CREDENTIAL_KEY]: { ...tokens, [connectionId]: record } };
}

export function withoutMcpOauthToken(credentials, connectionId) {
  const tokens = { ...readMcpOauthTokens(credentials) };
  delete tokens[connectionId];
  return { ...credentials, [MCP_OAUTH_CREDENTIAL_KEY]: tokens };
}
