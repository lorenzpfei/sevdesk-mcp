/**
 * Shared scaffolding for the HTTP transport tests: a fake sevDesk API, a
 * handler wired to it, and an MCP client that speaks to the handler in
 * process (no listening socket, so the suite stays deterministic).
 */

import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

import type { Config } from "../../src/config.js";
import { createSevdeskHttpHandler, type HttpHandlerOptions } from "../../src/http.js";

export const TEST_ORIGIN = "http://localhost:3000";
export const MCP_URL = `${TEST_ORIGIN}/mcp`;

export function testConfig(overrides: Partial<Config> = {}): Config {
  return {
    apiToken: "test-token",
    baseUrl: "https://sevdesk.test/api/v1",
    readOnly: false,
    dryRun: false,
    vatRegime: "regular",
    vatRegimeSource: "env",
    requestTimeoutMs: 5_000,
    maxRetries: 0,
    rateLimitPerSec: 0,
    debug: false,
    allowedReceiptDirs: [],
    ...overrides,
  };
}

/** Records every sevDesk call so a test can assert what did — and did not — reach the API. */
export interface FakeSevdesk {
  fetchFn: typeof fetch;
  calls: Array<{ method: string; url: string; token: string | null }>;
}

export function fakeSevdesk(
  respond: (url: URL, method: string) => { status?: number; body?: unknown } | undefined = () =>
    undefined,
): FakeSevdesk {
  const calls: FakeSevdesk["calls"] = [];
  const fetchFn: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : (input as Request).url);
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = new Headers(init?.headers);
    calls.push({ method, url: url.pathname, token: headers.get("authorization") });
    const answer = respond(url, method) ?? { status: 200, body: { objects: [] } };
    return new Response(JSON.stringify(answer.body ?? { objects: [] }), {
      status: answer.status ?? 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  return { fetchFn, calls };
}

export function createHandler(options: Partial<HttpHandlerOptions> = {}) {
  return createSevdeskHttpHandler({
    config: testConfig(),
    auth: { mode: "none" },
    publicUrl: new URL(MCP_URL),
    onerror: () => {},
    ...options,
  });
}

/** A `fetch` that dispatches straight into a handler, bypassing the network. */
export function handlerFetch(handler: { fetch: (r: Request) => Promise<Response> }): typeof fetch {
  return async (input, init) => {
    const request =
      input instanceof Request && init === undefined ? input : new Request(input as string, init);
    return handler.fetch(request);
  };
}

export interface ConnectOptions {
  /** `legacy` runs the 2025-era handshake, `auto` negotiates 2026-07-28. */
  era?: "legacy" | "auto";
  headers?: Record<string, string>;
}

export async function connectClient(
  handler: { fetch: (r: Request) => Promise<Response> },
  { era = "legacy", headers }: ConnectOptions = {},
): Promise<Client> {
  const client = new Client(
    { name: "sevdesk-mcp-test", version: "0.0.0" },
    { capabilities: {}, versionNegotiation: { mode: era } },
  );
  await client.connect(
    new StreamableHTTPClientTransport(new URL(MCP_URL), {
      fetch: handlerFetch(handler),
      ...(headers ? { requestInit: { headers } } : {}),
    }),
  );
  return client;
}

/** A bare JSON-RPC POST, for the protocol-level cases a client would never send. */
export function post(body: unknown, init: RequestInit = {}): Request {
  return new Request(MCP_URL, {
    ...init,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...(init.headers as Record<string, string> | undefined),
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

export function textOf(result: unknown): string {
  const content = (result as { content?: Array<{ type: string; text?: string }> }).content ?? [];
  return content
    .filter((c) => c.type === "text")
    .map((c) => c.text ?? "")
    .join("\n");
}

/**
 * Read a JSON-RPC reply from a response body. The 2025-era leg frames its
 * answer as a single SSE event, the modern leg as a plain JSON body; a test
 * asserting on the payload should not have to care which.
 */
export async function rpcBody(res: Response): Promise<Record<string, unknown>> {
  const text = await res.text();
  if (!text.startsWith("event:") && !text.startsWith("data:")) {
    return JSON.parse(text) as Record<string, unknown>;
  }
  const line = text
    .split(/\r?\n/)
    .find((l) => l.startsWith("data:"));
  if (!line) throw new Error(`No SSE data frame in response: ${text.slice(0, 200)}`);
  return JSON.parse(line.slice("data:".length).trim()) as Record<string, unknown>;
}
