// McpOAuthPersistence backed by Electron's OS-encrypted credential document,
// reached over the same utility-process parentPort bridge used elsewhere in
// server/index.ts (see postDesktopPrivateMessage / PhoneSecretBridge in
// server/phone-secret.ts, which this mirrors). The embedded server holds no
// secret store of its own: on construction it asks the parent for the
// current connection map, and every upsert/delete round-trips the WHOLE map
// back through the parent so credentials.bin stays the single source of
// truth. A plain Node launch (no Electron parent) never gets one of these —
// server/index.ts falls back to localFileMcpOAuthPersistence instead.
import { randomUUID } from "node:crypto";

import type { McpOAuthConnectionRecord, McpOAuthPersistence } from "./mcp-oauth-store.ts";

/** Structurally identical to the UtilityParentPort type in server/index.ts;
 * declared locally so this module has no import cycle with it. */
export type McpOAuthParentPort = {
  on(event: "message", listener: (event: { data?: object }) => void): void;
  postMessage(message: object): void;
};

type PendingLoad = {
  resolve: (tokens: Record<string, McpOAuthConnectionRecord>) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

type PendingSave = {
  resolve: () => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

function isConnectionRecordMap(value: unknown): value is Record<string, McpOAuthConnectionRecord> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export class McpOAuthElectronBridge implements McpOAuthPersistence {
  private readonly port: McpOAuthParentPort;
  private readonly pendingLoads = new Map<string, PendingLoad>();
  private readonly pendingSaves = new Map<string, PendingSave>();
  private readonly timeoutMs: number;

  constructor(port: McpOAuthParentPort, timeoutMs = 15_000) {
    this.port = port;
    this.timeoutMs = timeoutMs;
    this.port.on("message", (event) => this.receive(event));
  }

  private receive(raw: unknown): boolean {
    const message = (raw as { data?: unknown } | null)?.data ?? raw;
    if (!message || typeof message !== "object" || Array.isArray(message)) return false;
    const record = message as Record<string, unknown>;

    if (record.type === "openmausbot:mcp-oauth-load-result" && typeof record.requestId === "string") {
      const pending = this.pendingLoads.get(record.requestId);
      if (!pending) return true;
      this.pendingLoads.delete(record.requestId);
      clearTimeout(pending.timer);
      pending.resolve(isConnectionRecordMap(record.tokens) ? record.tokens : {});
      return true;
    }

    if (record.type === "openmausbot:mcp-oauth-save-result" && typeof record.requestId === "string") {
      const pending = this.pendingSaves.get(record.requestId);
      if (!pending) return true;
      this.pendingSaves.delete(record.requestId);
      clearTimeout(pending.timer);
      if (record.ok === true) pending.resolve();
      else pending.reject(new Error(typeof record.error === "string" ? record.error : "The connection could not be saved."));
      return true;
    }

    return false;
  }

  async load(): Promise<Record<string, McpOAuthConnectionRecord>> {
    const requestId = randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingLoads.delete(requestId);
        // No prior connections is a safe default: a slow/unavailable parent
        // must not stop the server from starting, only leave it with no
        // OAuth-backed servers mounted until the next successful load/save.
        resolve({});
      }, this.timeoutMs);
      timer.unref?.();
      this.pendingLoads.set(requestId, { resolve, reject, timer });
      try {
        this.port.postMessage({ type: "openmausbot:mcp-oauth-load", requestId });
      } catch (error) {
        clearTimeout(timer);
        this.pendingLoads.delete(requestId);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  async save(records: Record<string, McpOAuthConnectionRecord>): Promise<void> {
    const requestId = randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingSaves.delete(requestId);
        reject(new Error("The desktop credential store did not respond. Try again."));
      }, this.timeoutMs);
      timer.unref?.();
      this.pendingSaves.set(requestId, { resolve, reject, timer });
      try {
        this.port.postMessage({ type: "openmausbot:mcp-oauth-save", requestId, tokens: records });
      } catch (error) {
        clearTimeout(timer);
        this.pendingSaves.delete(requestId);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }
}
