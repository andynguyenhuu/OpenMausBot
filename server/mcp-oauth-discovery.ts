// OAuth discovery for a remote MCP server: RFC 9728 (protected resource
// metadata) locates the authorization server, RFC 8414 (authorization server
// metadata, OIDC discovery as a fallback) locates its endpoints. Every
// function here fails closed with a plain-English error — a caller that
// cannot get a complete, S256-capable answer must never fall back to a
// partial one, because the next step is redirecting a phone out to it.
export class McpOAuthDiscoveryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "McpOAuthDiscoveryError";
  }
}

export interface ProtectedResourceMetadata {
  resource: string;
  authorizationServers: string[];
}

export interface AuthorizationServerMetadata {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  registrationEndpoint?: string;
  revocationEndpoint?: string;
  codeChallengeMethodsSupported: string[];
}

type Fetch = typeof fetch;

const FETCH_TIMEOUT_MS = 10_000;

async function fetchJson(url: string, fetchImpl: Fetch, init?: RequestInit): Promise<{ status: number; headers: Headers; body: unknown }> {
  let response: Response;
  try {
    response = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch (error) {
    throw new McpOAuthDiscoveryError(`Could not reach ${url}: ${error instanceof Error ? error.message : String(error)}`);
  }
  let body: unknown = null;
  const text = await response.text().catch(() => "");
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      if (response.ok) throw new McpOAuthDiscoveryError(`${url} did not return valid JSON.`);
    }
  }
  return { status: response.status, headers: response.headers, body };
}

/** RFC 9728 §3.1: the well-known path is `/.well-known/oauth-protected-resource`
 * with the resource's own path appended after it — falling back to no path
 * suffix, since several early server implementations only serve the root. */
function protectedResourceWellKnownUrls(resource: URL): string[] {
  const path = resource.pathname === "/" ? "" : resource.pathname.replace(/\/$/, "");
  const withPath = `${resource.origin}/.well-known/oauth-protected-resource${path}`;
  const root = `${resource.origin}/.well-known/oauth-protected-resource`;
  return path ? [withPath, root] : [root];
}

/** RFC 9728 §5.1: a resource server that requires a token answers an
 * unauthenticated request with `WWW-Authenticate: Bearer
 * resource_metadata="https://…"`. That header, when present, is more
 * authoritative than a guessed well-known path (it is the resource's own
 * declaration of where its metadata lives), so it is tried first. */
async function protectedResourceMetadataUrl(resourceUrl: string, fetchImpl: Fetch): Promise<string> {
  let probe: Response | null = null;
  try {
    probe = await fetchImpl(resourceUrl, { method: "GET", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  } catch {
    probe = null;
  }
  const header = probe?.headers.get("www-authenticate");
  if (header) {
    const match = /resource_metadata="([^"]+)"/.exec(header);
    if (match) return match[1]!;
  }
  return protectedResourceWellKnownUrls(new URL(resourceUrl))[0]!;
}

/** Discover the authorization server(s) that protect a remote MCP server.
 * Fails closed: any malformed or incomplete metadata is a thrown
 * McpOAuthDiscoveryError, never a partial result. */
export async function discoverProtectedResourceMetadata(
  resourceUrl: string,
  fetchImpl: Fetch = fetch,
): Promise<ProtectedResourceMetadata> {
  const resource = new URL(resourceUrl);
  const candidates = [await protectedResourceMetadataUrl(resourceUrl, fetchImpl), ...protectedResourceWellKnownUrls(resource)];
  let lastError: McpOAuthDiscoveryError | null = null;
  for (const url of Array.from(new Set(candidates))) {
    try {
      const { status, body } = await fetchJson(url, fetchImpl);
      if (status === 404) continue;
      if (status !== 200) throw new McpOAuthDiscoveryError(`${url} returned status ${status}.`);
      const record = body as Record<string, unknown> | null;
      const servers = record?.authorization_servers;
      if (!Array.isArray(servers) || servers.length === 0 || !servers.every((s) => typeof s === "string")) {
        throw new McpOAuthDiscoveryError(`${url} did not list an authorization_servers array.`);
      }
      return { resource: typeof record?.resource === "string" ? record.resource : resourceUrl, authorizationServers: servers };
    } catch (error) {
      lastError = error instanceof McpOAuthDiscoveryError ? error : new McpOAuthDiscoveryError(String(error));
    }
  }
  throw lastError ?? new McpOAuthDiscoveryError(
    `${resource.origin} did not publish OAuth protected-resource metadata (RFC 9728). This server may not support OAuth.`,
  );
}

/** RFC 8414 §3.1 inserts the well-known suffix before the issuer's own path;
 * OIDC Discovery 1.0 §4.2 appends it after the issuer instead. Both are
 * tried, RFC 8414 first since that is the spec the MCP OAuth profile names. */
function authorizationServerWellKnownUrls(issuer: URL): string[] {
  const path = issuer.pathname === "/" ? "" : issuer.pathname.replace(/\/$/, "");
  const urls = [`${issuer.origin}/.well-known/oauth-authorization-server${path}`];
  if (path) urls.push(`${issuer.origin}/.well-known/oauth-authorization-server`);
  urls.push(`${issuer.origin}${path}/.well-known/openid-configuration`);
  return urls;
}

function readEndpoint(record: Record<string, unknown>, field: string): string | undefined {
  const value = record[field];
  return typeof value === "string" && value ? value : undefined;
}

/** Discover an authorization server's endpoints. Fails closed if S256 PKCE
 * is not advertised in `code_challenge_methods_supported` — this app never
 * offers a fallback to the plain PKCE method or no PKCE at all. */
export async function discoverAuthorizationServerMetadata(
  authorizationServerUrl: string,
  fetchImpl: Fetch = fetch,
): Promise<AuthorizationServerMetadata> {
  const issuer = new URL(authorizationServerUrl);
  let lastError: McpOAuthDiscoveryError | null = null;
  for (const url of authorizationServerWellKnownUrls(issuer)) {
    try {
      const { status, body } = await fetchJson(url, fetchImpl);
      if (status === 404) continue;
      if (status !== 200) throw new McpOAuthDiscoveryError(`${url} returned status ${status}.`);
      const record = body as Record<string, unknown> | null;
      if (!record) throw new McpOAuthDiscoveryError(`${url} did not return an object.`);
      const authorizationEndpoint = readEndpoint(record, "authorization_endpoint");
      const tokenEndpoint = readEndpoint(record, "token_endpoint");
      if (!authorizationEndpoint || !tokenEndpoint) {
        throw new McpOAuthDiscoveryError(`${url} is missing authorization_endpoint or token_endpoint.`);
      }
      const methods = record.code_challenge_methods_supported;
      if (!Array.isArray(methods) || !methods.includes("S256")) {
        throw new McpOAuthDiscoveryError(
          `${issuer.origin} does not advertise S256 PKCE support (code_challenge_methods_supported). Refusing to start a connection without it.`,
        );
      }
      return {
        issuer: typeof record.issuer === "string" ? record.issuer : issuer.toString(),
        authorizationEndpoint,
        tokenEndpoint,
        registrationEndpoint: readEndpoint(record, "registration_endpoint"),
        revocationEndpoint: readEndpoint(record, "revocation_endpoint"),
        codeChallengeMethodsSupported: methods,
      };
    } catch (error) {
      lastError = error instanceof McpOAuthDiscoveryError ? error : new McpOAuthDiscoveryError(String(error));
    }
  }
  throw lastError ?? new McpOAuthDiscoveryError(
    `${issuer.origin} did not publish authorization server metadata (RFC 8414 or OIDC discovery).`,
  );
}

export interface DynamicClientRegistration {
  clientId: string;
  clientSecret?: string;
}

/** RFC 7591 dynamic client registration. One registration per connection —
 * the issued client_id/client_secret are never reused across servers or
 * organizations, so every new connection calls this again even against an
 * authorization server this app has registered with before. */
export async function registerDynamicClient(
  registrationEndpoint: string,
  redirectUri: string,
  clientName: string,
  fetchImpl: Fetch = fetch,
): Promise<DynamicClientRegistration> {
  const { status, body } = await fetchJson(registrationEndpoint, fetchImpl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: clientName,
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      application_type: "native",
    }),
  });
  if (status !== 200 && status !== 201) {
    throw new McpOAuthDiscoveryError(`Dynamic client registration failed with status ${status}.`);
  }
  const record = body as Record<string, unknown> | null;
  const clientId = record?.client_id;
  if (typeof clientId !== "string" || !clientId) {
    throw new McpOAuthDiscoveryError("Dynamic client registration did not return a client_id.");
  }
  const clientSecret = record?.client_secret;
  return { clientId, clientSecret: typeof clientSecret === "string" ? clientSecret : undefined };
}
