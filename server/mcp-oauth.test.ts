import { describe, expect, it } from "vitest";

import { McpOAuthConnections, McpOAuthError } from "./mcp-oauth.ts";
import { inMemoryMcpOAuthPersistence, McpOAuthStore } from "./mcp-oauth-store.ts";

const RESOURCE = "https://mcp.clickup.com/mcp";
const AS_ISSUER = "https://auth.clickup.com";
const CALLBACK_ORIGIN = "https://c-abc123.openmausbot-tunnel.example";

type Route = { status?: number; body?: unknown; headers?: Record<string, string> };

/** Keyed by exact URL, matching every discovery/registration/token/revoke
 * call this module makes — none of them vary the URL by method. */
function fakeFetch(routes: Record<string, Route>): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
    const route = routes[url];
    if (!route) return new Response("not found", { status: 404 });
    const body = route.body === undefined ? "" : JSON.stringify(route.body);
    return new Response(body, { status: route.status ?? 200, headers: route.headers });
  }) as typeof fetch;
}

function happyPathRoutes(overrides: Record<string, Route> = {}): Record<string, Route> {
  return {
    [RESOURCE]: { status: 401 },
    "https://mcp.clickup.com/.well-known/oauth-protected-resource/mcp": { status: 404 },
    "https://mcp.clickup.com/.well-known/oauth-protected-resource": {
      body: { resource: RESOURCE, authorization_servers: [AS_ISSUER] },
    },
    "https://auth.clickup.com/.well-known/oauth-authorization-server": {
      body: {
        issuer: AS_ISSUER,
        authorization_endpoint: `${AS_ISSUER}/authorize`,
        token_endpoint: `${AS_ISSUER}/token`,
        registration_endpoint: `${AS_ISSUER}/register`,
        revocation_endpoint: `${AS_ISSUER}/revoke`,
        code_challenge_methods_supported: ["S256"],
      },
    },
    [`${AS_ISSUER}/register`]: { status: 201, body: { client_id: "dyn-client-1", client_secret: "dyn-secret" } },
    ...overrides,
  };
}

function connections(routes: Record<string, Route>, now?: () => number) {
  const store = new McpOAuthStore(inMemoryMcpOAuthPersistence());
  const conn = new McpOAuthConnections({
    store,
    fetchImpl: fakeFetch(routes),
    callbackOrigin: () => CALLBACK_ORIGIN,
    now,
  });
  return { store, conn };
}

describe("McpOAuthConnections.start (discovery + DCR + PKCE)", () => {
  it("discovers, dynamically registers a client, and returns a PKCE authorization URL", async () => {
    const { conn, store } = connections(happyPathRoutes());
    const result = await conn.start({ connectionId: "conn-1", serverUrl: RESOURCE, serverName: "clickup" });
    const authUrl = new URL(result.authorizationUrl);
    expect(authUrl.origin + authUrl.pathname).toBe(`${AS_ISSUER}/authorize`);
    expect(authUrl.searchParams.get("response_type")).toBe("code");
    expect(authUrl.searchParams.get("client_id")).toBe("dyn-client-1");
    expect(authUrl.searchParams.get("redirect_uri")).toBe(`${CALLBACK_ORIGIN}/oauth/mcp/callback/conn-1`);
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authUrl.searchParams.get("resource")).toBe(RESOURCE);
    expect(authUrl.searchParams.get("code_challenge")).toBeTruthy();
    expect(authUrl.searchParams.get("state")).toBeTruthy();

    // pending record persisted, but with no token yet
    const record = store.get("conn-1");
    expect(record?.status).toBe("pending");
    expect(record?.accessToken).toBeUndefined();
    expect(record?.clientSecret).toBe("dyn-secret");
  });

  it("refuses to start when there is no public callback origin yet", async () => {
    const store = new McpOAuthStore(inMemoryMcpOAuthPersistence());
    const conn = new McpOAuthConnections({ store, fetchImpl: fakeFetch(happyPathRoutes()), callbackOrigin: () => null });
    await expect(conn.start({ connectionId: "conn-1", serverUrl: RESOURCE })).rejects.toThrow(McpOAuthError);
  });

  it("propagates a discovery failure as an McpOAuthError instead of starting a flow", async () => {
    const { conn, store } = connections({ [RESOURCE]: { status: 401 } }); // no well-known metadata anywhere
    await expect(conn.start({ connectionId: "conn-1", serverUrl: RESOURCE })).rejects.toThrow(McpOAuthError);
    expect(store.get("conn-1")).toBeUndefined();
  });

  it("refuses an authorization server with no dynamic client registration endpoint", async () => {
    const routes = happyPathRoutes({
      "https://auth.clickup.com/.well-known/oauth-authorization-server": {
        body: {
          issuer: AS_ISSUER,
          authorization_endpoint: `${AS_ISSUER}/authorize`,
          token_endpoint: `${AS_ISSUER}/token`,
          code_challenge_methods_supported: ["S256"],
        },
      },
    });
    const { conn } = connections(routes);
    await expect(conn.start({ connectionId: "conn-1", serverUrl: RESOURCE })).rejects.toThrow(/dynamic client registration/);
  });
});

describe("McpOAuthConnections.complete (callback + token exchange)", () => {
  it("exchanges the code with the PKCE verifier and marks the connection connected", async () => {
    const routes = happyPathRoutes({
      [`${AS_ISSUER}/token`]: {
        status: 200,
        body: { access_token: "at-1", refresh_token: "rt-1", expires_in: 3600, scope: "tasks:read" },
      },
    });
    const { conn, store } = connections(routes);
    const started = await conn.start({ connectionId: "conn-1", serverUrl: RESOURCE });
    const state = new URL(started.authorizationUrl).searchParams.get("state")!;

    const result = await conn.complete("conn-1", { code: "the-code", state });
    expect(result).toEqual({ ok: true });

    const record = store.get("conn-1");
    expect(record?.status).toBe("connected");
    expect(record?.accessToken).toBe("at-1");
    expect(record?.refreshToken).toBe("rt-1");

    // management-facing summary never carries the secrets
    const summary = conn.getSummary("conn-1");
    expect(summary).not.toHaveProperty("accessToken");
    expect(summary).not.toHaveProperty("refreshToken");
    expect(summary).not.toHaveProperty("clientSecret");
    expect(JSON.stringify(summary)).not.toContain("at-1");
  });

  it("rejects an unknown/expired/replayed state without exchanging a code", async () => {
    const { conn } = connections(happyPathRoutes());
    const result = await conn.complete("conn-1", { code: "x", state: "not-a-real-state" });
    expect(result).toEqual({ ok: false, error: "This authorization link was already used or has expired." });
  });

  it("rejects a callback state that does not belong to this connectionId", async () => {
    const { conn } = connections(happyPathRoutes());
    const started = await conn.start({ connectionId: "conn-1", serverUrl: RESOURCE });
    const state = new URL(started.authorizationUrl).searchParams.get("state")!;
    const result = await conn.complete("conn-2", { code: "x", state });
    expect(result).toEqual({ ok: false, error: "This authorization link does not belong to this connection." });
  });

  it("records an authorization-server error callback without ever calling the token endpoint", async () => {
    const { conn, store } = connections(happyPathRoutes());
    await conn.start({ connectionId: "conn-1", serverUrl: RESOURCE });
    const result = await conn.complete("conn-1", { error: "access_denied", errorDescription: "user declined" });
    expect(result).toEqual({ ok: false, error: "user declined" });
    expect(store.get("conn-1")?.status).toBe("error");
  });

  it("marks the connection errored when the token endpoint refuses the exchange", async () => {
    const routes = happyPathRoutes({ [`${AS_ISSUER}/token`]: { status: 400, body: { error: "invalid_grant" } } });
    const { conn, store } = connections(routes);
    const started = await conn.start({ connectionId: "conn-1", serverUrl: RESOURCE });
    const state = new URL(started.authorizationUrl).searchParams.get("state")!;
    const result = await conn.complete("conn-1", { code: "bad-code", state });
    expect(result.ok).toBe(false);
    expect(store.get("conn-1")?.status).toBe("error");
  });
});

describe("McpOAuthConnections.resolveAuthorizationHeader", () => {
  it("returns undefined for a connection that was never completed", async () => {
    const { conn } = connections(happyPathRoutes());
    await conn.start({ connectionId: "conn-1", serverUrl: RESOURCE });
    expect(await conn.resolveAuthorizationHeader("conn-1")).toBeUndefined();
  });

  it("returns undefined for a connection id that does not exist", async () => {
    const { conn } = connections(happyPathRoutes());
    expect(await conn.resolveAuthorizationHeader("no-such-connection")).toBeUndefined();
  });

  it("returns the live bearer token for a connected, non-expiring connection", async () => {
    const routes = happyPathRoutes({
      [`${AS_ISSUER}/token`]: { body: { access_token: "at-1", expires_in: 3600 } },
    });
    const { conn } = connections(routes);
    const started = await conn.start({ connectionId: "conn-1", serverUrl: RESOURCE });
    const state = new URL(started.authorizationUrl).searchParams.get("state")!;
    await conn.complete("conn-1", { code: "c", state });
    expect(await conn.resolveAuthorizationHeader("conn-1")).toBe("Bearer at-1");
  });

  it("refreshes a near-expiry token before returning it", async () => {
    let clock = 1_000_000;
    const routes = happyPathRoutes({
      [`${AS_ISSUER}/token`]: { body: { access_token: "at-1", refresh_token: "rt-1", expires_in: 30 } },
    });
    const { conn, store } = connections(routes, () => clock);
    const started = await conn.start({ connectionId: "conn-1", serverUrl: RESOURCE });
    const state = new URL(started.authorizationUrl).searchParams.get("state")!;
    await conn.complete("conn-1", { code: "c", state });
    // near expiry (within 60s) — swap the token-endpoint route to the refresh response
    clock += 25_000;
    routes[`${AS_ISSUER}/token`] = { body: { access_token: "at-2", refresh_token: "rt-2", expires_in: 3600 } };
    const header = await conn.resolveAuthorizationHeader("conn-1");
    expect(header).toBe("Bearer at-2");
    expect(store.get("conn-1")?.refreshToken).toBe("rt-2");
  });

  it("marks the connection errored and returns undefined when refresh fails", async () => {
    let clock = 1_000_000;
    const routes = happyPathRoutes({
      [`${AS_ISSUER}/token`]: { body: { access_token: "at-1", refresh_token: "rt-1", expires_in: 30 } },
    });
    const { conn, store } = connections(routes, () => clock);
    const started = await conn.start({ connectionId: "conn-1", serverUrl: RESOURCE });
    const state = new URL(started.authorizationUrl).searchParams.get("state")!;
    await conn.complete("conn-1", { code: "c", state });
    clock += 25_000;
    routes[`${AS_ISSUER}/token`] = { status: 400, body: { error: "invalid_grant" } };
    const header = await conn.resolveAuthorizationHeader("conn-1");
    expect(header).toBeUndefined();
    expect(store.get("conn-1")?.status).toBe("error");
  });
});

describe("McpOAuthConnections.disconnect", () => {
  it("revokes the token best-effort and always deletes the stored record", async () => {
    const routes = happyPathRoutes({
      [`${AS_ISSUER}/token`]: { body: { access_token: "at-1", expires_in: 3600 } },
      [`${AS_ISSUER}/revoke`]: { status: 200 },
    });
    const { conn, store } = connections(routes);
    const started = await conn.start({ connectionId: "conn-1", serverUrl: RESOURCE });
    const state = new URL(started.authorizationUrl).searchParams.get("state")!;
    await conn.complete("conn-1", { code: "c", state });
    await conn.disconnect("conn-1");
    expect(store.get("conn-1")).toBeUndefined();
  });

  it("still deletes the stored record when revocation is unreachable", async () => {
    const routes = happyPathRoutes({
      [`${AS_ISSUER}/token`]: { body: { access_token: "at-1", expires_in: 3600 } },
      // no route for the revoke endpoint — the fake fetch 404s it
    });
    const { conn, store } = connections(routes);
    const started = await conn.start({ connectionId: "conn-1", serverUrl: RESOURCE });
    const state = new URL(started.authorizationUrl).searchParams.get("state")!;
    await conn.complete("conn-1", { code: "c", state });
    await conn.disconnect("conn-1");
    expect(store.get("conn-1")).toBeUndefined();
  });
});
