import { describe, expect, it } from "vitest";

import { McpOAuthFlowStore } from "./mcp-oauth-flows.ts";

function baseFlow(connectionId: string) {
  return {
    connectionId,
    codeVerifier: "verifier-value",
    redirectUri: "https://app.example/oauth/mcp/callback/" + connectionId,
    tokenEndpoint: "https://auth.example.com/token",
    authorizationServerUrl: "https://auth.example.com",
    clientId: "client-1",
    resource: "https://mcp.example.com/mcp",
  };
}

describe("McpOAuthFlowStore state validation", () => {
  it("consumes a freshly created, correctly owned state exactly once", () => {
    const store = new McpOAuthFlowStore();
    const flow = store.create(baseFlow("conn-a"));
    const first = store.consume("conn-a", flow.state);
    expect(first).toEqual({ ok: true, flow });
    // replay of the exact same, previously-valid state
    const second = store.consume("conn-a", flow.state);
    expect(second).toEqual({ ok: false, error: "This authorization link was already used or has expired." });
  });

  it("rejects a state for the wrong connection, and burns the state so it cannot be reused by the right one", () => {
    const store = new McpOAuthFlowStore();
    const flow = store.create(baseFlow("conn-a"));
    const wrongOwner = store.consume("conn-b", flow.state);
    expect(wrongOwner).toEqual({ ok: false, error: "This authorization link does not belong to this connection." });
    // single-use even though the first lookup failed ownership: the
    // genuine owner cannot retry with the same (now-consumed) state
    const retryByOwner = store.consume("conn-a", flow.state);
    expect(retryByOwner).toEqual({ ok: false, error: "This authorization link was already used or has expired." });
  });

  it("rejects an unknown state", () => {
    const store = new McpOAuthFlowStore();
    expect(store.consume("conn-a", "not-a-real-state")).toEqual({
      ok: false,
      error: "This authorization link was already used or has expired.",
    });
  });

  it("expires a state after its TTL", () => {
    let clock = 1_000_000;
    const store = new McpOAuthFlowStore({ ttlMs: 60_000, now: () => clock });
    const flow = store.create(baseFlow("conn-a"));
    clock += 60_001; // past expiresAt
    const result = store.consume("conn-a", flow.state);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/already used or has expired/);
  });

  it("does not expire a state before its TTL elapses", () => {
    let clock = 1_000_000;
    const store = new McpOAuthFlowStore({ ttlMs: 60_000, now: () => clock });
    const flow = store.create(baseFlow("conn-a"));
    clock += 59_000; // still within TTL
    expect(store.consume("conn-a", flow.state)).toEqual({ ok: true, flow });
  });

  it("discards only the flows belonging to one connection", () => {
    const store = new McpOAuthFlowStore();
    const a = store.create(baseFlow("conn-a"));
    const b = store.create(baseFlow("conn-b"));
    store.discardForConnection("conn-a");
    expect(store.consume("conn-a", a.state)).toEqual({ ok: false, error: "This authorization link was already used or has expired." });
    expect(store.consume("conn-b", b.state)).toEqual({ ok: true, flow: b });
  });

  it("size() reports live pending flows and reflects sweeping of expired ones", () => {
    let clock = 1_000_000;
    const store = new McpOAuthFlowStore({ ttlMs: 1_000, now: () => clock });
    store.create(baseFlow("conn-a"));
    expect(store.size()).toBe(1);
    clock += 1_001;
    expect(store.size()).toBe(0);
  });
});
