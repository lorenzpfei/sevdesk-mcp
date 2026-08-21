/**
 * The deployment entry point is one root file. Small enough to look correct
 * and still take the whole deployment down — Vercel silently chose
 * `src/index.ts` (the stdio CLI) as the root entrypoint once already, and
 * every route answered 500 — so it gets exercised the way the platform does:
 * import the module, call its exported `fetch`.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

import { catalog } from "../src/catalog.js";
import { VERSION } from "../src/server.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const built = existsSync(join(repoRoot, "dist", "http.js"));
const describeEntry = built ? describe : describe.skip;

interface WebHandlerModule {
  default: { fetch: (request: Request) => Promise<Response> };
}

describeEntry("the deployment entry point", () => {
  const host = "sevdesk-mcp-ebon.vercel.app";
  let entry: WebHandlerModule;

  beforeAll(async () => {
    // Configuration is read on the first request, exactly as a cold start does.
    process.env.SEVDESK_API_TOKEN = "entry-test-token";
    process.env.SEVDESK_READ_ONLY = "true";
    process.env.MCP_AUTH_MODE = "none";
    process.env.MCP_PUBLIC_URL = `https://${host}/mcp`;
    entry = (await import("../index.js")) as unknown as WebHandlerModule;
  });

  it("exports the web-standard fetch shape Vercel looks for", () => {
    expect(typeof entry.default.fetch).toBe("function");
  });

  it("does not bind a port when imported", () => {
    // Importing must be side-effect free; only `node index.js` may listen.
    expect(entry.default.fetch).toBeTypeOf("function");
  });

  it("serves /health", async () => {
    const res = await entry.default.fetch(new Request(`https://${host}/health`));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      status: "ok",
      version: VERSION,
      transport: "streamable-http",
      operations: catalog.operationCount,
    });
  });

  it("serves the MCP endpoint on the canonical path, with no rewrite in between", async () => {
    const res = await entry.default.fetch(
      new Request(`https://${host}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      }),
    );
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain("sevdesk_ping");
    // SEVDESK_READ_ONLY is set, so the write tools must be absent.
    expect(text).not.toContain("sevdesk_create_voucher");
  });

  it("rejects a request forged onto another host", async () => {
    const res = await entry.default.fetch(
      new Request(`https://${host}/health`, { headers: { Host: "attacker.example" } }),
    );
    expect(res.status).toBe(403);
  });

  it("reuses one handler across warm invocations", async () => {
    // A second request must not rebuild the handler; both answer identically.
    const [a, b] = await Promise.all([
      entry.default.fetch(new Request(`https://${host}/health`)).then((r) => r.json()),
      entry.default.fetch(new Request(`https://${host}/health`)).then((r) => r.json()),
    ]);
    expect(a).toEqual(b);
  });
});

describe("vercel.json", () => {
  const config = JSON.parse(readFileSync(join(repoRoot, "vercel.json"), "utf8")) as {
    buildCommand: string;
    outputDirectory: string;
    rewrites?: unknown;
  };

  it("builds the package before the entrypoint is bundled", () => {
    expect(config.buildCommand).toBe("npm run build");
  });

  it("needs no rewrites, because the entrypoint sees the original path", () => {
    expect(config.rewrites).toBeUndefined();
  });

  it("points at an output directory that exists", () => {
    expect(existsSync(join(repoRoot, config.outputDirectory))).toBe(true);
  });

  it("keeps the deployment scaffolding out of the npm package", () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as {
      files: string[];
    };
    for (const entry of pkg.files) {
      expect(entry).not.toMatch(/^(index\.js|public|vercel\.json)/);
    }
  });
});
