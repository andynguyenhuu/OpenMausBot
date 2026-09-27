// /api/mcp-oauth/*: management API for OAuth-backed remote MCP connections.
// Every route here runs behind the normal auth gate (server/routes/table.ts
// dispatches after it) — the ONE pre-auth route in this feature is the
// callback itself, registered directly in server/index.ts next to
// /api/health and /api/brand, not here.
import { randomUUID } from "node:crypto";

import type { RequestAuth } from "../request-auth.ts";
import { McpOAuthError, type McpOAuthConnections } from "../mcp-oauth.ts";
import { PASS, type RouteHandler } from "./table.ts";

export interface McpOAuthRouteDeps {
  connections: McpOAuthConnections;
  /** A stable identity for the session/account starting a connection: stored
   * on the record for audit, and compared by `mayManage` below to gate who
   * may later disconnect or restart it. */
  ownerLabel(auth: RequestAuth): string | undefined;
}

const CONNECTION_ID = /^[A-Za-z0-9_-]{1,64}$/;

function errorStatus(error: unknown): { status: number; message: string } {
  if (error instanceof McpOAuthError) return { status: error.status, message: error.message };
  return { status: 502, message: error instanceof Error ? error.message : "The connection could not be started." };
}

/** Whether `auth` may disconnect or restart a connection whose stored
 * ownerLabel is `recordOwner`. A loopback caller — the local operator on the
 * box itself — always may: it already holds full admin scope and, on the
 * box, there is no second identity to guard against. Otherwise only the same
 * identity that created it may act; a connection with no recorded owner
 * (created before this check existed, or by an account-less pairing) does
 * not lock every admin out of it. This matters on a hosted workspace, where
 * more than one email account can hold admin scope at once (see
 * server/people-invite.test.ts) — on a single-owner install every admin
 * session already resolves to the one owner, so this is a no-op there. */
function mayManage(auth: RequestAuth, currentOwner: string | undefined, recordOwner: string | undefined): boolean {
  if (auth.kind === "loopback") return true;
  if (!recordOwner) return true;
  return currentOwner === recordOwner;
}

export function createMcpOAuthRoutes(deps: McpOAuthRouteDeps): RouteHandler {
  return async ({ req, res, path, method, auth, json, readBody }) => {
    if (path === "/api/mcp-oauth/connections" && method === "GET") {
      return json(res, 200, { connections: deps.connections.list() });
    }

    if (path === "/api/mcp-oauth/connections" && method === "POST") {
      const body = (await readBody(req).catch(() => null)) as Record<string, unknown> | null;
      const serverUrl = typeof body?.serverUrl === "string" ? body.serverUrl.trim() : "";
      const serverName = typeof body?.serverName === "string" ? body.serverName : undefined;
      const connectionIdInput = typeof body?.connectionId === "string" ? body.connectionId : undefined;
      if (!serverUrl) return json(res, 400, { error: "serverUrl is required." });
      try {
        new URL(serverUrl);
      } catch {
        return json(res, 400, { error: "serverUrl must be a full address, like https://example.com/mcp." });
      }
      const connectionId = connectionIdInput && CONNECTION_ID.test(connectionIdInput) ? connectionIdInput : randomUUID();
      const currentOwner = deps.ownerLabel(auth);
      const existingForRestart = deps.connections.getSummary(connectionId);
      if (existingForRestart && !mayManage(auth, currentOwner, existingForRestart.ownerLabel)) {
        return json(res, 403, { error: "This connection belongs to a different account. Ask them to reconnect or disconnect it first." });
      }
      try {
        const result = await deps.connections.start({ connectionId, serverUrl, serverName, ownerLabel: currentOwner });
        return json(res, 201, result);
      } catch (error) {
        const { status, message } = errorStatus(error);
        return json(res, status, { error: message });
      }
    }

    const single = /^\/api\/mcp-oauth\/connections\/([A-Za-z0-9_-]{1,64})$/.exec(path);
    if (single) {
      const connectionId = single[1]!;
      if (method === "GET") {
        const summary = deps.connections.getSummary(connectionId);
        if (!summary) return json(res, 404, { error: "No such connection." });
        return json(res, 200, summary);
      }
      if (method === "DELETE") {
        const existing = deps.connections.getSummary(connectionId);
        if (existing && !mayManage(auth, deps.ownerLabel(auth), existing.ownerLabel)) {
          return json(res, 403, { error: "This connection belongs to a different account." });
        }
        await deps.connections.disconnect(connectionId);
        return json(res, 200, { ok: true });
      }
    }

    return PASS;
  };
}
