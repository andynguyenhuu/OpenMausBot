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
  /** A label for the session/account starting a connection — audit only. */
  ownerLabel(auth: RequestAuth): string | undefined;
}

const CONNECTION_ID = /^[A-Za-z0-9_-]{1,64}$/;

function errorStatus(error: unknown): { status: number; message: string } {
  if (error instanceof McpOAuthError) return { status: error.status, message: error.message };
  return { status: 502, message: error instanceof Error ? error.message : "The connection could not be started." };
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
      try {
        const result = await deps.connections.start({ connectionId, serverUrl, serverName, ownerLabel: deps.ownerLabel(auth) });
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
        await deps.connections.disconnect(connectionId);
        return json(res, 200, { ok: true });
      }
    }

    return PASS;
  };
}
