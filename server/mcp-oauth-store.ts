// Durable storage for MCP OAuth connections: one record per connection,
// holding both the non-secret status fields the management API may return
// and the secrets (client_secret, access/refresh tokens) it must never
// return. server/redact.ts's key-name matching (token/secret/authorization)
// already catches every secret field here by name.
import { writeFileAtomic } from "./atomic.ts";

export type McpOAuthConnectionStatus = "pending" | "connected" | "expired" | "error";

export interface McpOAuthConnectionRecord {
  connectionId: string;
  /** The mcpServers registry name this connection was started for, if any
   * — a connection can be created before the server entry exists. */
  serverName?: string;
  serverUrl: string;
  resource: string;
  authorizationServerUrl: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  revocationEndpoint?: string;
  registrationEndpoint: string;
  clientId: string;
  clientSecret?: string;
  accessToken?: string;
  refreshToken?: string;
  /** epoch ms */
  expiresAt?: number;
  scope?: string;
  ownerLabel?: string;
  status: McpOAuthConnectionStatus;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

/** What a management API response may say about a connection: everything
 * above minus every field that could authenticate as the user. */
export type McpOAuthConnectionSummary = Omit<
  McpOAuthConnectionRecord,
  "clientSecret" | "accessToken" | "refreshToken"
>;

export function summarizeConnection(record: McpOAuthConnectionRecord): McpOAuthConnectionSummary {
  const { clientSecret: _clientSecret, accessToken: _accessToken, refreshToken: _refreshToken, ...summary } = record;
  return summary;
}

export interface McpOAuthPersistence {
  load(): Promise<Record<string, McpOAuthConnectionRecord>>;
  save(records: Record<string, McpOAuthConnectionRecord>): Promise<void>;
}

/** Dev/test fallback: a local JSON file, mode 0600, atomic write. This is
 * NOT OS-encrypted-at-rest — on a packaged desktop build, McpOAuthStore is
 * constructed with the Electron secure-credential bridge instead (see
 * server/mcp-oauth-electron-bridge.ts and electron/mcp-oauth-tokens.mjs). A
 * plain `pnpm dev:server` launch or a test has no Electron parent to bridge
 * to, so this is the only persistence a local install without the desktop
 * shell can get — a known, documented limitation, not an oversight. */
export function localFileMcpOAuthPersistence(path: string): McpOAuthPersistence {
  return {
    async load() {
      try {
        const { readFileSync } = await import("node:fs");
        const text = readFileSync(path, "utf8");
        const parsed = JSON.parse(text);
        return parsed && typeof parsed === "object" ? parsed as Record<string, McpOAuthConnectionRecord> : {};
      } catch {
        return {};
      }
    },
    async save(records) {
      writeFileAtomic(path, `${JSON.stringify(records, null, 2)}\n`, { mode: 0o600 });
    },
  };
}

export function inMemoryMcpOAuthPersistence(
  seed: Record<string, McpOAuthConnectionRecord> = {},
): McpOAuthPersistence {
  let current = { ...seed };
  return {
    async load() {
      return { ...current };
    },
    async save(records) {
      current = { ...records };
    },
  };
}

/** The connection table server/mcp-oauth.ts operates on. Loads once (async,
 * awaited via `ready`), then serves reads from memory and serializes writes
 * through the same persistence, so two overlapping updates can never race
 * each other into a half-applied file. */
export class McpOAuthStore {
  private readonly persistence: McpOAuthPersistence;
  private records = new Map<string, McpOAuthConnectionRecord>();
  private queue: Promise<void> = Promise.resolve();
  readonly ready: Promise<void>;

  constructor(persistence: McpOAuthPersistence) {
    this.persistence = persistence;
    this.ready = persistence.load().then((loaded) => {
      for (const [id, record] of Object.entries(loaded)) this.records.set(id, record);
    });
  }

  list(): McpOAuthConnectionRecord[] {
    return [...this.records.values()];
  }

  get(connectionId: string): McpOAuthConnectionRecord | undefined {
    return this.records.get(connectionId);
  }

  private persist(): Promise<void> {
    const snapshot = Object.fromEntries(this.records);
    this.queue = this.queue.then(() => this.persistence.save(snapshot));
    return this.queue;
  }

  async upsert(record: McpOAuthConnectionRecord): Promise<void> {
    this.records.set(record.connectionId, record);
    await this.persist();
  }

  async delete(connectionId: string): Promise<void> {
    this.records.delete(connectionId);
    await this.persist();
  }
}
