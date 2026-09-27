// The in-memory pending-flow table for an MCP OAuth authorization-code
// exchange. This is deliberately NOT persisted: a server restart mid-flow
// invalidates it (the user just taps Connect again), which is a fine
// trade-off for the security property that actually matters — the random
// `state` value is the only thing standing between the anonymous, pre-auth
// callback route and an attacker replaying or forging a redirect.
import { randomBytes } from "node:crypto";

export interface PendingMcpOAuthFlow {
  connectionId: string;
  state: string;
  codeVerifier: string;
  redirectUri: string;
  tokenEndpoint: string;
  authorizationServerUrl: string;
  clientId: string;
  clientSecret?: string;
  resource: string;
  /** The account/session that started this flow, for audit only — the
   * pre-auth callback has no session to compare it against. Security here
   * comes from `state` being unguessable, connection-bound, and single-use. */
  ownerLabel?: string;
  createdAt: number;
  expiresAt: number;
}

export type FlowRejection = { ok: false; error: string };
export type FlowResult = { ok: true; flow: PendingMcpOAuthFlow } | FlowRejection;

const DEFAULT_TTL_MS = 10 * 60 * 1000;

export class McpOAuthFlowStore {
  private readonly flows = new Map<string, PendingMcpOAuthFlow>();
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(options: { ttlMs?: number; now?: () => number } = {}) {
    this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.now = options.now ?? (() => Date.now());
  }

  private sweep(): void {
    const now = this.now();
    for (const [state, flow] of this.flows) {
      if (flow.expiresAt <= now) this.flows.delete(state);
    }
  }

  create(input: Omit<PendingMcpOAuthFlow, "state" | "createdAt" | "expiresAt">): PendingMcpOAuthFlow {
    this.sweep();
    const now = this.now();
    const flow: PendingMcpOAuthFlow = {
      ...input,
      state: randomBytes(32).toString("base64url"),
      createdAt: now,
      expiresAt: now + this.ttlMs,
    };
    this.flows.set(flow.state, flow);
    return flow;
  }

  /** Single-use by construction: the record is removed on the FIRST lookup,
   * whether or not the caller's connectionId turns out to match. A replayed
   * `state` — valid or not — always finds nothing the second time. */
  consume(connectionId: string, state: string): FlowResult {
    this.sweep();
    const flow = this.flows.get(state);
    if (!flow) return { ok: false, error: "This authorization link was already used or has expired." };
    this.flows.delete(state);
    if (flow.connectionId !== connectionId) {
      return { ok: false, error: "This authorization link does not belong to this connection." };
    }
    if (flow.expiresAt <= this.now()) {
      return { ok: false, error: "This authorization link has expired. Start the connection again." };
    }
    return { ok: true, flow };
  }

  /** Drop a flow without consuming it (e.g. the connection was deleted while
   * a browser tab was still open). Not required for correctness — sweep()
   * would eventually reap it — but keeps memory bounded under churn. */
  discardForConnection(connectionId: string): void {
    for (const [state, flow] of this.flows) {
      if (flow.connectionId === connectionId) this.flows.delete(state);
    }
  }

  size(): number {
    this.sweep();
    return this.flows.size;
  }
}
