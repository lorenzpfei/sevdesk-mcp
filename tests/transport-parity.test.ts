/**
 * Proof that stdio and Streamable HTTP offer the same tool contract.
 *
 * The stdio side is the real published entry point: a spawned
 * `node dist/index.js`, driven by the official client over pipes. That makes
 * this both the parity test and the regression test for the CLI itself — it
 * has to start, speak MCP on stdout only, and keep its diagnostics on stderr.
 */

import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { afterAll, describe, expect, it } from "vitest";

import { tools } from "../src/server.js";
import { MCP_URL, connectClient, createHandler, testConfig, textOf } from "./helpers/http.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cliEntry = join(repoRoot, "dist", "index.js");

/** An unroutable base URL: no tool in this suite may reach the network. */
const OFFLINE_BASE_URL = "http://127.0.0.1:9/api/v1";

function stdioEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    PATH: process.env.PATH ?? "",
    SEVDESK_API_TOKEN: "test-token",
    SEVDESK_BASE_URL: OFFLINE_BASE_URL,
    SEVDESK_VAT_REGIME: "regular",
    SEVDESK_RATE_LIMIT: "0",
    SEVDESK_MAX_RETRIES: "0",
    ...extra,
  };
}

interface StdioSession {
  client: Client;
  stderr: string;
  close: () => Promise<void>;
}

async function connectStdio(env: Record<string, string> = {}): Promise<StdioSession> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [cliEntry],
    env: stdioEnv(env),
    stderr: "pipe",
  });
  let stderr = "";
  transport.stderr?.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
  });
  const client = new Client({ name: "parity-test", version: "0.0.0" }, { capabilities: {} });
  await client.connect(transport);
  return {
    client,
    get stderr() {
      return stderr;
    },
    close: () => client.close(),
  } as StdioSession;
}

const built = existsSync(cliEntry);
const describeStdio = built ? describe : describe.skip;

if (!built) {
  // Skipping silently would let a missing build masquerade as a passing suite.
  console.error(
    `[parity] dist/index.js is missing — run \`npm run build\` before \`npm test\`. ` +
      `The stdio half of the parity suite is skipped.`,
  );
}

describeStdio("stdio and HTTP expose the same tool contract", () => {
  const httpHandlers: Array<{ close: () => Promise<void> }> = [];
  afterAll(async () => {
    await Promise.all(httpHandlers.map((h) => h.close()));
  });

  async function listBoth(env: Record<string, string> = {}, config = testConfig()) {
    const stdio = await connectStdio(env);
    const handler = createHandler({ config: { ...config, baseUrl: OFFLINE_BASE_URL } });
    httpHandlers.push(handler);
    const http = await connectClient(handler);
    try {
      return {
        stdio: (await stdio.client.listTools()).tools,
        http: (await http.listTools()).tools,
        stderr: stdio.stderr,
      };
    } finally {
      await http.close();
      await stdio.close();
    }
  }

  it("lists the same tool names in the same order", async () => {
    const { stdio, http } = await listBoth();
    expect(http.map((t) => t.name)).toEqual(stdio.map((t) => t.name));
    expect(stdio.map((t) => t.name)).toEqual(tools.map((t) => t.name));
    expect(stdio).toHaveLength(24);
  });

  it("serves byte-identical titles, descriptions, schemas and annotations", async () => {
    const { stdio, http } = await listBoth();
    expect(JSON.stringify(http)).toBe(JSON.stringify(stdio));
  });

  it("hides exactly the same write tools in read-only mode", async () => {
    const { stdio, http } = await listBoth(
      { SEVDESK_READ_ONLY: "true" },
      testConfig({ readOnly: true }),
    );
    expect(http.map((t) => t.name)).toEqual(stdio.map((t) => t.name));

    const readWrite = await listBoth();
    const hidden = readWrite.stdio
      .map((t) => t.name)
      .filter((n) => !stdio.some((t) => t.name === n));
    expect(hidden.length).toBeGreaterThan(0);
    // sevdesk_call decides per call, so it stays listed in both transports.
    expect(stdio.map((t) => t.name)).toContain("sevdesk_call");
    expect(hidden).not.toContain("sevdesk_call");
  });

  it("keeps protocol traffic off stderr and diagnostics off stdout", async () => {
    const session = await connectStdio();
    try {
      await session.client.listTools();
    } finally {
      await session.close();
    }
    // A readable banner is expected; JSON-RPC frames are not.
    expect(session.stderr).toContain("sevdesk-mcp");
    expect(session.stderr).not.toContain('"jsonrpc"');
    expect(session.stderr).not.toContain('"tools"');
  });

  it("refuses a hidden write tool identically over both transports", async () => {
    const stdio = await connectStdio({ SEVDESK_READ_ONLY: "true" });
    const handler = createHandler({
      config: testConfig({ readOnly: true, baseUrl: OFFLINE_BASE_URL }),
    });
    httpHandlers.push(handler);
    const http = await connectClient(handler);
    try {
      const args = {
        name: "sevdesk_create_voucher",
        arguments: { supplierName: "x", voucherDate: "2026-01-01", total: 1 },
      };
      const viaStdio = await stdio.client.callTool(args);
      const viaHttp = await http.callTool(args);
      expect(viaHttp.isError).toBe(viaStdio.isError);
      expect(textOf(viaHttp)).toBe(textOf(viaStdio));
      expect(textOf(viaHttp)).toContain("SEVDESK_READ_ONLY");
    } finally {
      await http.close();
      await stdio.close();
    }
  });

  it("previews a dry-run write identically over both transports", async () => {
    const stdio = await connectStdio({ SEVDESK_DRY_RUN: "true" });
    const handler = createHandler({
      config: testConfig({ dryRun: true, baseUrl: OFFLINE_BASE_URL }),
    });
    httpHandlers.push(handler);
    const http = await connectClient(handler);
    try {
      const args = {
        name: "sevdesk_call",
        arguments: { operationId: "createContact", body: { name: "Dry Run GmbH" } },
      };
      const viaStdio = await stdio.client.callTool(args);
      const viaHttp = await http.callTool(args);
      expect(textOf(viaHttp)).toBe(textOf(viaStdio));
      expect(textOf(viaHttp)).toContain("Nothing was sent");
    } finally {
      await http.close();
      await stdio.close();
    }
  });

  it("answers the discovery tools identically over both transports", async () => {
    const stdio = await connectStdio();
    const handler = createHandler({ config: testConfig({ baseUrl: OFFLINE_BASE_URL }) });
    httpHandlers.push(handler);
    const http = await connectClient(handler);
    try {
      for (const args of [
        { name: "sevdesk_list_operations", arguments: { query: "voucher pdf" } },
        { name: "sevdesk_describe_operation", arguments: { operationId: "invoiceGetPdf" } },
      ]) {
        expect(textOf(await http.callTool(args)), args.name).toBe(
          textOf(await stdio.client.callTool(args)),
        );
      }
    } finally {
      await http.close();
      await stdio.close();
    }
  });

  it("serves the same server instructions and capabilities", async () => {
    const stdio = await connectStdio();
    const handler = createHandler({ config: testConfig({ baseUrl: OFFLINE_BASE_URL }) });
    httpHandlers.push(handler);
    const http = await connectClient(handler);
    try {
      expect(http.getInstructions()).toBe(stdio.client.getInstructions());
      expect(http.getServerCapabilities()).toEqual(stdio.client.getServerCapabilities());
      expect(http.getServerVersion()).toEqual(stdio.client.getServerVersion());
    } finally {
      await http.close();
      await stdio.close();
    }
  });
});

describe("the canonical HTTP endpoint", () => {
  it("is /mcp", () => {
    expect(new URL(MCP_URL).pathname).toBe("/mcp");
  });
});
