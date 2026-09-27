// The /api/mcp-oauth/* management routes are exercised the way a request
// reaches them: through the table, on a real HTTP server, over a real
// McpOAuthConnections instance backed by an in-memory store and a fake
// fetch standing in for the remote authorization server.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import { json, readBody } from "../harness/http.ts";
import { McpOAuthConnections } from "../mcp-oauth.ts";
import { inMemoryMcpOAuthPersistence, McpOAuthStore } from "../mcp-oauth-store.ts";
import { createMcpOAuthRoutes } from "./mcp-oauth.ts";
import { dispatchRoutes } from "./table.ts";

const RESOURCE = "https://mcp.clickup.com/mcp";
const AS_ISSUER = "https://auth.clickup.com";
const CALLBACK_ORIGIN = "https://c-abc123.openmausbot-tunnel.example";

type Route = { status?: number; body?: unknown; headers?: Record<string, string> };

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

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise((done) => server.close(done))));
});

async function serve(routes: Record<string, Route> = happyPathRoutes(), callbackOrigin: () => string | null = () => CALLBACK_ORIGIN) {
  const store = new McpOAuthStore(inMemoryMcpOAuthPersistence());
  const connections = new McpOAuthConnections({ store, fetchImpl: fakeFetch(routes), callbackOrigin });
  const routeTable = [createMcpOAuthRoutes({ connections, ownerLabel: () => "andy" })];
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const handled = await dispatchRoutes(routeTable, {
      req, res, url, path: url.pathname, method: req.method ?? "GET",
      auth: { kind: "loopback", scopes: ["admin", "client"] }, json, readBody,
    });
    if (!handled) json(res, 404, { from: "inline routes" });
  });
  servers.push(server);
  await new Promise<void>((ready) => server.listen(0, "127.0.0.1", ready));
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, connections, store };
}

describe("/api/mcp-oauth/connections through the route table", () => {
  it("lists nothing with no connections, then the pending record start() created", async () => {
    const { base } = await serve();
    expect(await (await fetch(`${base}/api/mcp-oauth/connections`)).json()).toEqual({ connections: [] });

    const started = await fetch(`${base}/api/mcp-oauth/connections`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ serverUrl: RESOURCE, serverName: "clickup" }),
    });
    expect(started.status).toBe(201);
    const startedBody = (await started.json()) as { connectionId: string; authorizationUrl: string };
    expect(startedBody.connectionId).toBeTruthy();
    expect(new URL(startedBody.authorizationUrl).searchParams.get("code_challenge_method")).toBe("S256");

    const listed = (await (await fetch(`${base}/api/mcp-oauth/connections`)).json()) as { connections: Array<{ status: string }> };
    expect(listed.connections).toHaveLength(1);
    expect(listed.connections[0]!.status).toBe("pending");
  });

  it("never returns a secret from list, start, or a single connection's GET — even after a completed handshake", async () => {
    const routes = happyPathRoutes({
      [`${AS_ISSUER}/token`]: { body: { access_token: "at-1", refresh_token: "rt-1", expires_in: 3600 } },
    });
    const { base, connections } = await serve(routes);
    const started = await (
      await fetch(`${base}/api/mcp-oauth/connections`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ serverUrl: RESOURCE }),
      })
    ).json() as { connectionId: string; authorizationUrl: string };
    const state = new URL(started.authorizationUrl).searchParams.get("state")!;
    await connections.complete(started.connectionId, { code: "the-code", state });

    const list = await (await fetch(`${base}/api/mcp-oauth/connections`)).json();
    const single = await (await fetch(`${base}/api/mcp-oauth/connections/${started.connectionId}`)).json();
    for (const payload of [list, single]) {
      const text = JSON.stringify(payload);
      expect(text).not.toContain("at-1");
      expect(text).not.toContain("rt-1");
      expect(text).not.toContain("dyn-secret");
      expect(text).not.toMatch(/accessToken|refreshToken|clientSecret/);
    }
  });

  it("validates serverUrl before ever calling out to discovery", async () => {
    const { base } = await serve();
    const missing = await fetch(`${base}/api/mcp-oauth/connections`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(missing.status).toBe(400);
    expect(await missing.json()).toEqual({ error: "serverUrl is required." });

    const malformed = await fetch(`${base}/api/mcp-oauth/connections`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ serverUrl: "not-a-url" }),
    });
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toEqual({ error: "serverUrl must be a full address, like https://example.com/mcp." });
  });

  it("maps a discovery failure to the McpOAuthError's own status, not a bare 500", async () => {
    // No well-known metadata published anywhere for this resource.
    const { base } = await serve({ [RESOURCE]: { status: 401 } });
    const response = await fetch(`${base}/api/mcp-oauth/connections`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ serverUrl: RESOURCE }),
    });
    expect(response.status).toBe(502);
    const body = (await response.json()) as { error: string };
    expect(body.error).toMatch(/did not publish/);
  });

  it("refuses to start a connection when there is no public callback origin yet", async () => {
    const { base } = await serve(happyPathRoutes(), () => null);
    const response = await fetch(`${base}/api/mcp-oauth/connections`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ serverUrl: RESOURCE }),
    });
    expect(response.status).toBe(409);
    expect(((await response.json()) as { error: string }).error).toMatch(/no public address/);
  });

  it("404s a GET/DELETE for an unknown connection id, and leaves other paths to the next handler", async () => {
    const { base } = await serve();
    expect((await fetch(`${base}/api/mcp-oauth/connections/no-such-id`)).status).toBe(404);
    const deleted = await fetch(`${base}/api/mcp-oauth/connections/no-such-id`, { method: "DELETE" });
    // disconnect() on an unknown id is a no-op delete, not a 404 — it just
    // deletes an already-absent record.
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toEqual({ ok: true });
    expect(await (await fetch(`${base}/api/mcp-oauth/connections/bad.id`)).json()).toEqual({ from: "inline routes" });
  });

  it("GET returns the pending status, then DELETE removes the connection entirely", async () => {
    const { base, store } = await serve();
    const started = await (
      await fetch(`${base}/api/mcp-oauth/connections`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ serverUrl: RESOURCE }),
      })
    ).json() as { connectionId: string };
    expect(store.get(started.connectionId)).toBeTruthy();

    const single = await (await fetch(`${base}/api/mcp-oauth/connections/${started.connectionId}`)).json();
    expect((single as { status: string }).status).toBe("pending");

    const deleted = await fetch(`${base}/api/mcp-oauth/connections/${started.connectionId}`, { method: "DELETE" });
    expect(deleted.status).toBe(200);
    expect(store.get(started.connectionId)).toBeUndefined();
  });
});
