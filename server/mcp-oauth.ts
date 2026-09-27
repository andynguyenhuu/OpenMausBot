// Orchestrates an MCP OAuth 2.1 connection end to end: discovery (RFC 9728 +
// RFC 8414), dynamic client registration (RFC 7591), a PKCE S256
// authorization-code flow, token exchange, refresh, and disconnect. This is
// the module server/routes/mcp-oauth.ts and the pre-auth callback route in
// server/index.ts both call into — neither owns any OAuth protocol logic
// itself.
import {
  discoverAuthorizationServerMetadata,
  discoverProtectedResourceMetadata,
  McpOAuthDiscoveryError,
  registerDynamicClient,
} from "./mcp-oauth-discovery.ts";
import { McpOAuthFlowStore } from "./mcp-oauth-flows.ts";
import { generatePkce } from "./mcp-oauth-pkce.ts";
import {
  type McpOAuthConnectionRecord,
  type McpOAuthConnectionSummary,
  McpOAuthStore,
  summarizeConnection,
} from "./mcp-oauth-store.ts";

export class McpOAuthError extends Error {
  readonly status: number;
  constructor(message: string, status = 400) {
    super(message);
    this.name = "McpOAuthError";
    this.status = status;
  }
}

type Fetch = typeof fetch;

export interface McpOAuthConnectionsOptions {
  store: McpOAuthStore;
  flows?: McpOAuthFlowStore;
  fetchImpl?: Fetch;
  /** The public HTTPS origin the authorization server redirects back to —
   * e.g. the Cloudflare Tunnel managed-endpoint hostname. Computed fresh per
   * call (not captured at construction) since a managed endpoint can be
   * provisioned after boot. */
  callbackOrigin: () => string | null;
  now?: () => number;
  clientName?: string;
}

export interface StartMcpOAuthInput {
  connectionId: string;
  serverUrl: string;
  serverName?: string;
  ownerLabel?: string;
}

export interface StartMcpOAuthResult {
  connectionId: string;
  authorizationUrl: string;
  expiresAt: string;
}

export type CompleteMcpOAuthResult = { ok: true } | { ok: false; error: string };

function callbackUrl(origin: string, connectionId: string): string {
  return `${origin.replace(/\/$/, "")}/oauth/mcp/callback/${encodeURIComponent(connectionId)}`;
}

async function tokenRequest(
  fetchImpl: Fetch,
  tokenEndpoint: string,
  params: Record<string, string>,
): Promise<{ ok: true; body: Record<string, unknown> } | { ok: false; error: string }> {
  let response: Response;
  try {
    response = await fetchImpl(tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams(params),
      signal: AbortSignal.timeout(15_000),
    });
  } catch (error) {
    return { ok: false, error: `Could not reach the token endpoint: ${error instanceof Error ? error.message : String(error)}` };
  }
  const text = await response.text().catch(() => "");
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!response.ok || !body || typeof body !== "object") {
    const description = body && typeof body === "object" && typeof (body as { error_description?: unknown }).error_description === "string"
      ? (body as { error_description: string }).error_description
      : `status ${response.status}`;
    return { ok: false, error: `Token request failed (${description}).` };
  }
  return { ok: true, body: body as Record<string, unknown> };
}

export class McpOAuthConnections {
  private readonly store: McpOAuthStore;
  private readonly flows: McpOAuthFlowStore;
  private readonly fetchImpl: Fetch;
  private readonly callbackOrigin: () => string | null;
  private readonly now: () => number;
  private readonly clientName: string;
  private readonly refreshLocks = new Map<string, Promise<string | undefined>>();

  constructor(options: McpOAuthConnectionsOptions) {
    this.store = options.store;
    this.flows = options.flows ?? new McpOAuthFlowStore();
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.callbackOrigin = options.callbackOrigin;
    this.now = options.now ?? (() => Date.now());
    this.clientName = options.clientName ?? "OpenMausBot";
  }

  list(): McpOAuthConnectionSummary[] {
    return this.store.list().map(summarizeConnection);
  }

  getSummary(connectionId: string): McpOAuthConnectionSummary | undefined {
    const record = this.store.get(connectionId);
    return record ? summarizeConnection(record) : undefined;
  }

  async start(input: StartMcpOAuthInput): Promise<StartMcpOAuthResult> {
    const origin = this.callbackOrigin();
    if (!origin) {
      throw new McpOAuthError(
        "This install has no public address yet, so a remote OAuth provider cannot redirect back to it. Provision a managed endpoint first.",
        409,
      );
    }
    let resourceMeta: Awaited<ReturnType<typeof discoverProtectedResourceMetadata>>;
    try {
      resourceMeta = await discoverProtectedResourceMetadata(input.serverUrl, this.fetchImpl);
    } catch (error) {
      throw new McpOAuthError(error instanceof McpOAuthDiscoveryError ? error.message : String(error), 502);
    }
    const authorizationServerUrl = resourceMeta.authorizationServers[0];
    if (!authorizationServerUrl) throw new McpOAuthError("The server did not name an authorization server.", 502);
    let asMeta: Awaited<ReturnType<typeof discoverAuthorizationServerMetadata>>;
    try {
      asMeta = await discoverAuthorizationServerMetadata(authorizationServerUrl, this.fetchImpl);
    } catch (error) {
      throw new McpOAuthError(error instanceof McpOAuthDiscoveryError ? error.message : String(error), 502);
    }
    if (!asMeta.registrationEndpoint) {
      throw new McpOAuthError(
        "This authorization server does not support dynamic client registration (RFC 7591), so it cannot be connected from a phone.",
        502,
      );
    }
    const existing = this.store.get(input.connectionId);
    if (existing?.status === "pending" && existing.ownerLabel !== input.ownerLabel) {
      // A different owner already has an in-flight authorization for this
      // connectionId (e.g. two accounts both hit Connect on the same MCP
      // server entry). Invalidate their pending state so a late callback
      // cannot complete behind the new caller's back, then let this start()
      // proceed and become the flow of record.
      this.flows.discardForConnection(input.connectionId);
    }
    const redirectUri = callbackUrl(origin, input.connectionId);
    let client: Awaited<ReturnType<typeof registerDynamicClient>>;
    try {
      client = await registerDynamicClient(asMeta.registrationEndpoint, redirectUri, this.clientName, this.fetchImpl);
    } catch (error) {
      throw new McpOAuthError(error instanceof McpOAuthDiscoveryError ? error.message : String(error), 502);
    }
    const pkce = generatePkce();
    const flow = this.flows.create({
      connectionId: input.connectionId,
      codeVerifier: pkce.codeVerifier,
      redirectUri,
      tokenEndpoint: asMeta.tokenEndpoint,
      authorizationServerUrl: asMeta.issuer,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      resource: resourceMeta.resource,
      ownerLabel: input.ownerLabel,
    });

    const authorizationUrl = new URL(asMeta.authorizationEndpoint);
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set("client_id", client.clientId);
    authorizationUrl.searchParams.set("redirect_uri", redirectUri);
    authorizationUrl.searchParams.set("state", flow.state);
    authorizationUrl.searchParams.set("code_challenge", pkce.codeChallenge);
    authorizationUrl.searchParams.set("code_challenge_method", pkce.codeChallengeMethod);
    // RFC 8707 resource indicator: names the MCP server this token is for,
    // so an authorization server that issues audience-restricted tokens
    // does not hand back one scoped to something else entirely.
    authorizationUrl.searchParams.set("resource", resourceMeta.resource);

    const nowIso = new Date(this.now()).toISOString();
    const record: McpOAuthConnectionRecord = {
      connectionId: input.connectionId,
      serverName: input.serverName ?? existing?.serverName,
      serverUrl: input.serverUrl,
      resource: resourceMeta.resource,
      authorizationServerUrl: asMeta.issuer,
      authorizationEndpoint: asMeta.authorizationEndpoint,
      tokenEndpoint: asMeta.tokenEndpoint,
      revocationEndpoint: asMeta.revocationEndpoint,
      registrationEndpoint: asMeta.registrationEndpoint,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      ownerLabel: input.ownerLabel,
      status: "pending",
      createdAt: existing?.createdAt ?? nowIso,
      updatedAt: nowIso,
    };
    await this.store.upsert(record);
    return { connectionId: input.connectionId, authorizationUrl: authorizationUrl.toString(), expiresAt: new Date(flow.expiresAt).toISOString() };
  }

  /** Called from the pre-auth GET /oauth/mcp/callback/:connectionId route.
   * `state` is the entire security boundary here — there is no session to
   * check this request against, so it MUST be validated (and consumed,
   * single-use) before any branch below is allowed to mutate the stored
   * record. Without that ordering, anyone who knows or guesses a
   * connectionId could hit this route with `?error=x` and no state at all
   * and flip a working connection to `status: "error"` — an unauthenticated
   * way to break every bot mounting that MCP server. */
  async complete(connectionId: string, params: { code?: string; state?: string; error?: string; errorDescription?: string }): Promise<CompleteMcpOAuthResult> {
    if (!params.state) return { ok: false, error: "The callback did not include a state parameter." };
    const consumed = this.flows.consume(connectionId, params.state);
    if (!consumed.ok) return consumed;
    if (params.error) {
      await this.markError(connectionId, params.errorDescription || params.error);
      return { ok: false, error: params.errorDescription || params.error };
    }
    if (!params.code) {
      await this.markError(connectionId, "The callback did not include an authorization code.");
      return { ok: false, error: "The callback did not include an authorization code." };
    }
    const flow = consumed.flow;
    const record = this.store.get(connectionId);
    if (!record) return { ok: false, error: "This connection no longer exists." };

    const exchange = await tokenRequest(this.fetchImpl, flow.tokenEndpoint, {
      grant_type: "authorization_code",
      code: params.code,
      redirect_uri: flow.redirectUri,
      client_id: flow.clientId,
      ...(flow.clientSecret ? { client_secret: flow.clientSecret } : {}),
      code_verifier: flow.codeVerifier,
      resource: flow.resource,
    });
    if (!exchange.ok) {
      await this.markError(connectionId, exchange.error);
      return { ok: false, error: exchange.error };
    }
    const accessToken = exchange.body.access_token;
    if (typeof accessToken !== "string" || !accessToken) {
      await this.markError(connectionId, "The token endpoint did not return an access token.");
      return { ok: false, error: "The token endpoint did not return an access token." };
    }
    const refreshToken = typeof exchange.body.refresh_token === "string" ? exchange.body.refresh_token : undefined;
    const expiresIn = typeof exchange.body.expires_in === "number" ? exchange.body.expires_in : undefined;
    const scope = typeof exchange.body.scope === "string" ? exchange.body.scope : undefined;
    const nowIso = new Date(this.now()).toISOString();
    await this.store.upsert({
      ...record,
      accessToken,
      refreshToken,
      expiresAt: expiresIn !== undefined ? this.now() + expiresIn * 1000 : undefined,
      scope,
      status: "connected",
      error: undefined,
      updatedAt: nowIso,
    });
    return { ok: true };
  }

  private async markError(connectionId: string, error: string): Promise<void> {
    const record = this.store.get(connectionId);
    if (!record) return;
    await this.store.upsert({ ...record, status: "error", error, updatedAt: new Date(this.now()).toISOString() });
  }

  /** Live Authorization header for a connection, refreshing first if the
   * access token is near or past expiry. Returns undefined — never a stale
   * or missing token — when the connection is not connected or a refresh
   * fails; the caller (server/index.ts engineMcpServers) must skip mounting
   * the server in that case rather than mount it half-authenticated. */
  async resolveAuthorizationHeader(connectionId: string): Promise<string | undefined> {
    const record = this.store.get(connectionId);
    if (!record || record.status !== "connected" || !record.accessToken) return undefined;
    const nearExpiry = record.expiresAt !== undefined && record.expiresAt - this.now() < 60_000;
    if (!nearExpiry) return `Bearer ${record.accessToken}`;
    if (!record.refreshToken) {
      await this.markError(connectionId, "The access token expired and no refresh token is available. Reconnect required.");
      return undefined;
    }
    const refreshed = await this.refresh(connectionId);
    return refreshed ? `Bearer ${refreshed}` : undefined;
  }

  /** One refresh in flight per connection: two turns racing to mount the
   * same expired connection must not both spend the same refresh_token —
   * most authorization servers rotate it and invalidate the old one on use. */
  private refresh(connectionId: string): Promise<string | undefined> {
    const inFlight = this.refreshLocks.get(connectionId);
    if (inFlight) return inFlight;
    const promise = this.refreshOnce(connectionId).finally(() => this.refreshLocks.delete(connectionId));
    this.refreshLocks.set(connectionId, promise);
    return promise;
  }

  private async refreshOnce(connectionId: string): Promise<string | undefined> {
    const record = this.store.get(connectionId);
    if (!record?.refreshToken) return undefined;
    const result = await tokenRequest(this.fetchImpl, record.tokenEndpoint, {
      grant_type: "refresh_token",
      refresh_token: record.refreshToken,
      client_id: record.clientId,
      ...(record.clientSecret ? { client_secret: record.clientSecret } : {}),
    });
    if (!result.ok) {
      await this.markError(connectionId, `Refresh failed: ${result.error}. Reconnect required.`);
      return undefined;
    }
    const accessToken = result.body.access_token;
    if (typeof accessToken !== "string" || !accessToken) {
      await this.markError(connectionId, "Refresh did not return an access token. Reconnect required.");
      return undefined;
    }
    const refreshToken = typeof result.body.refresh_token === "string" ? result.body.refresh_token : record.refreshToken;
    const expiresIn = typeof result.body.expires_in === "number" ? result.body.expires_in : undefined;
    const nowIso = new Date(this.now()).toISOString();
    await this.store.upsert({
      ...record,
      accessToken,
      refreshToken,
      expiresAt: expiresIn !== undefined ? this.now() + expiresIn * 1000 : record.expiresAt,
      status: "connected",
      error: undefined,
      updatedAt: nowIso,
    });
    return accessToken;
  }

  async disconnect(connectionId: string): Promise<void> {
    const record = this.store.get(connectionId);
    this.flows.discardForConnection(connectionId);
    if (record?.revocationEndpoint && record.accessToken) {
      try {
        await this.fetchImpl(record.revocationEndpoint, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            token: record.accessToken,
            client_id: record.clientId,
            ...(record.clientSecret ? { client_secret: record.clientSecret } : {}),
          }),
          signal: AbortSignal.timeout(10_000),
        });
      } catch {
        // Best-effort: the server may be unreachable or not support
        // revocation. Deleting our own copy of the token is what actually
        // matters, and that happens unconditionally below.
      }
    }
    await this.store.delete(connectionId);
  }
}
