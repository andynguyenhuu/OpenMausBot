import { describe, expect, it } from "vitest";

import {
  discoverAuthorizationServerMetadata,
  discoverProtectedResourceMetadata,
  McpOAuthDiscoveryError,
  registerDynamicClient,
} from "./mcp-oauth-discovery.ts";

/** A minimal fetch stand-in keyed by exact URL. Any URL not listed 404s,
 * matching how these discovery functions treat an absent well-known path. */
function fakeFetch(routes: Record<string, { status?: number; body?: unknown; headers?: Record<string, string> }>): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : (input as Request).url;
    const route = routes[url];
    if (!route) {
      return new Response("not found", { status: 404 });
    }
    const body = route.body === undefined ? "" : JSON.stringify(route.body);
    return new Response(body, { status: route.status ?? 200, headers: route.headers });
  }) as typeof fetch;
}

const RESOURCE = "https://mcp.example.com/mcp";
const AS_ISSUER = "https://auth.example.com";

describe("discoverProtectedResourceMetadata (RFC 9728)", () => {
  it("finds authorization servers at the root well-known path", async () => {
    const fetchImpl = fakeFetch({
      [RESOURCE]: { status: 401 },
      "https://mcp.example.com/.well-known/oauth-protected-resource/mcp": { status: 404 },
      "https://mcp.example.com/.well-known/oauth-protected-resource": {
        body: { resource: RESOURCE, authorization_servers: [AS_ISSUER] },
      },
    });
    const meta = await discoverProtectedResourceMetadata(RESOURCE, fetchImpl);
    expect(meta).toEqual({ resource: RESOURCE, authorizationServers: [AS_ISSUER] });
  });

  it("prefers the resource_metadata URL named in WWW-Authenticate", async () => {
    const named = "https://mcp.example.com/custom/prm.json";
    const fetchImpl = fakeFetch({
      [RESOURCE]: { status: 401, headers: { "www-authenticate": `Bearer resource_metadata="${named}"` } },
      [named]: { body: { resource: RESOURCE, authorization_servers: [AS_ISSUER] } },
    });
    const meta = await discoverProtectedResourceMetadata(RESOURCE, fetchImpl);
    expect(meta.authorizationServers).toEqual([AS_ISSUER]);
  });

  it("fails closed when authorization_servers is missing", async () => {
    const fetchImpl = fakeFetch({
      [RESOURCE]: { status: 401 },
      "https://mcp.example.com/.well-known/oauth-protected-resource/mcp": { status: 404 },
      "https://mcp.example.com/.well-known/oauth-protected-resource": { body: { resource: RESOURCE } },
    });
    await expect(discoverProtectedResourceMetadata(RESOURCE, fetchImpl)).rejects.toThrow(McpOAuthDiscoveryError);
  });

  it("fails closed when no well-known metadata exists at all", async () => {
    const fetchImpl = fakeFetch({ [RESOURCE]: { status: 401 } });
    await expect(discoverProtectedResourceMetadata(RESOURCE, fetchImpl)).rejects.toThrow(/did not publish/);
  });

  it("fails closed on malformed JSON from an otherwise-200 well-known response", async () => {
    const fetchImpl: typeof fetch = (async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : String(input);
      if (url === RESOURCE) return new Response("", { status: 401 });
      if (url === "https://mcp.example.com/.well-known/oauth-protected-resource") {
        return new Response("{not json", { status: 200 });
      }
      return new Response("", { status: 404 });
    }) as typeof fetch;
    await expect(discoverProtectedResourceMetadata(RESOURCE, fetchImpl)).rejects.toThrow(McpOAuthDiscoveryError);
  });
});

describe("discoverAuthorizationServerMetadata (RFC 8414 + OIDC fallback)", () => {
  const withS256 = {
    issuer: AS_ISSUER,
    authorization_endpoint: `${AS_ISSUER}/authorize`,
    token_endpoint: `${AS_ISSUER}/token`,
    registration_endpoint: `${AS_ISSUER}/register`,
    code_challenge_methods_supported: ["S256"],
  };

  it("discovers endpoints via RFC 8414 when S256 is advertised", async () => {
    const fetchImpl = fakeFetch({
      "https://auth.example.com/.well-known/oauth-authorization-server": { body: withS256 },
    });
    const meta = await discoverAuthorizationServerMetadata(AS_ISSUER, fetchImpl);
    expect(meta).toEqual({
      issuer: AS_ISSUER,
      authorizationEndpoint: `${AS_ISSUER}/authorize`,
      tokenEndpoint: `${AS_ISSUER}/token`,
      registrationEndpoint: `${AS_ISSUER}/register`,
      revocationEndpoint: undefined,
      codeChallengeMethodsSupported: ["S256"],
    });
  });

  it("falls back to OIDC discovery when RFC 8414's path 404s", async () => {
    const fetchImpl = fakeFetch({
      "https://auth.example.com/.well-known/oauth-authorization-server": { status: 404 },
      "https://auth.example.com/.well-known/openid-configuration": { body: withS256 },
    });
    const meta = await discoverAuthorizationServerMetadata(AS_ISSUER, fetchImpl);
    expect(meta.tokenEndpoint).toBe(`${AS_ISSUER}/token`);
  });

  it("fails closed when S256 is not in code_challenge_methods_supported", async () => {
    const fetchImpl = fakeFetch({
      "https://auth.example.com/.well-known/oauth-authorization-server": {
        body: { ...withS256, code_challenge_methods_supported: ["plain"] },
      },
      "https://auth.example.com/.well-known/openid-configuration": {
        body: { ...withS256, code_challenge_methods_supported: ["plain"] },
      },
    });
    await expect(discoverAuthorizationServerMetadata(AS_ISSUER, fetchImpl)).rejects.toThrow(/S256/);
  });

  it("fails closed when code_challenge_methods_supported is entirely absent", async () => {
    const { code_challenge_methods_supported: _omit, ...withoutMethods } = withS256;
    const fetchImpl = fakeFetch({
      "https://auth.example.com/.well-known/oauth-authorization-server": { body: withoutMethods },
      "https://auth.example.com/.well-known/openid-configuration": { body: withoutMethods },
    });
    await expect(discoverAuthorizationServerMetadata(AS_ISSUER, fetchImpl)).rejects.toThrow(/S256/);
  });

  it("fails closed when required endpoints are missing", async () => {
    const fetchImpl = fakeFetch({
      "https://auth.example.com/.well-known/oauth-authorization-server": {
        body: { issuer: AS_ISSUER, code_challenge_methods_supported: ["S256"] },
      },
      "https://auth.example.com/.well-known/openid-configuration": {
        body: { issuer: AS_ISSUER, code_challenge_methods_supported: ["S256"] },
      },
    });
    await expect(discoverAuthorizationServerMetadata(AS_ISSUER, fetchImpl)).rejects.toThrow(McpOAuthDiscoveryError);
  });
});

describe("registerDynamicClient (RFC 7591)", () => {
  const registrationEndpoint = `${AS_ISSUER}/register`;

  it("registers and returns the issued client_id/client_secret", async () => {
    const fetchImpl = fakeFetch({
      [registrationEndpoint]: { status: 201, body: { client_id: "abc123", client_secret: "shh" } },
    });
    const client = await registerDynamicClient(registrationEndpoint, "https://app.example/callback", "OpenMausBot", fetchImpl);
    expect(client).toEqual({ clientId: "abc123", clientSecret: "shh" });
  });

  it("accepts a public client with no client_secret", async () => {
    const fetchImpl = fakeFetch({
      [registrationEndpoint]: { status: 200, body: { client_id: "abc123" } },
    });
    const client = await registerDynamicClient(registrationEndpoint, "https://app.example/callback", "OpenMausBot", fetchImpl);
    expect(client).toEqual({ clientId: "abc123", clientSecret: undefined });
  });

  it("fails closed when the endpoint refuses registration", async () => {
    const fetchImpl = fakeFetch({ [registrationEndpoint]: { status: 400, body: { error: "invalid_client_metadata" } } });
    await expect(registerDynamicClient(registrationEndpoint, "https://app.example/callback", "OpenMausBot", fetchImpl))
      .rejects.toThrow(McpOAuthDiscoveryError);
  });

  it("fails closed when no client_id is returned", async () => {
    const fetchImpl = fakeFetch({ [registrationEndpoint]: { status: 200, body: {} } });
    await expect(registerDynamicClient(registrationEndpoint, "https://app.example/callback", "OpenMausBot", fetchImpl))
      .rejects.toThrow(/client_id/);
  });
});
