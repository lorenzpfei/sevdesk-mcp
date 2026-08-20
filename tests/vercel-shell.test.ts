/**
 * The Vercel shell is three-line route files plus `vercel.json`. Small enough
 * to look correct and still break a deployment, so it gets exercised the way
 * the platform does: import the function module, call its exported `fetch`.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

import { catalog } from "../src/catalog.js";
import { VERSION } from "../src/server.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const built = existsSync(join(repoRoot, "dist", "http.js"));
const describeShell = built ? describe : describe.skip;

interface VercelFunction {
  default: { fetch: (request: Request) => Promise<Response> };
}

describeShell("the Vercel function shell", () => {
  const host = "sevdesk-mcp.vercel.app";
  let mcp: VercelFunction;
  let health: VercelFunction;
  let wellKnown: VercelFunction;

  beforeAll(async () => {
    // The shell reads its configuration from the environment on first call,
    // exactly as a cold-started invocation does.
    process.env.SEVDESK_API_TOKEN = "shell-test-token";
    process.env.SEVDESK_READ_ONLY = "true";
    process.env.MCP_AUTH_MODE = "none";
    process.env.MCP_PUBLIC_URL = `https://${host}/mcp`;
    mcp = (await import("../api/mcp.js")) as unknown as VercelFunction;
    health = (await import("../api/health.js")) as unknown as VercelFunction;
    wellKnown = (await import("../api/well-known.js")) as unknown as VercelFunction;
  });

  it("exports the web-standard fetch shape Vercel expects", () => {
    for (const mod of [mcp, health, wellKnown]) {
      expect(typeof mod.default.fetch).toBe("function");
    }
  });

  it("serves health from the function Vercel rewrites /health to", async () => {
    const res = await health.default.fetch(new Request(`https://${host}/api/health`));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      status: "ok",
      version: VERSION,
      transport: "streamable-http",
      operations: catalog.operationCount,
    });
  });

  it("serves MCP from the rewritten path, not only from /mcp", async () => {
    // Whether the rewrite shows the function `/mcp` or `/api/mcp` is the
    // platform's business; the route file must work either way.
    for (const path of ["/mcp", "/api/mcp"]) {
      const res = await mcp.default.fetch(
        new Request(`https://${host}${path}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json, text/event-stream",
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
        }),
      );
      expect(res.status, path).toBe(200);
      const text = await res.text();
      expect(text, path).toContain("sevdesk_ping");
      // SEVDESK_READ_ONLY is set, so the write tools must be absent.
      expect(text, path).not.toContain("sevdesk_create_voucher");
    }
  });

  it("accepts the public host it was configured with", async () => {
    const res = await health.default.fetch(
      new Request(`https://${host}/api/health`, { headers: { Host: host } }),
    );
    expect(res.status).toBe(200);
  });

  it("rejects a request forged onto another host", async () => {
    const res = await health.default.fetch(
      new Request(`https://${host}/api/health`, { headers: { Host: "attacker.example" } }),
    );
    expect(res.status).toBe(403);
  });

  it("has nothing to say about OAuth while auth is off", async () => {
    const res = await wellKnown.default.fetch(
      new Request(`https://${host}/.well-known/oauth-protected-resource/mcp`),
    );
    expect(res.status).toBe(404);
  });

  it("reuses one handler across warm invocations", async () => {
    const first = await import("../api/_handler.js");
    const second = await import("../api/_handler.js");
    expect(first.handler()).toBe(second.handler());
  });
});

describe("vercel.json", () => {
  const config = JSON.parse(readFileSync(join(repoRoot, "vercel.json"), "utf8")) as {
    buildCommand: string;
    outputDirectory: string;
    rewrites: Array<{ source: string; destination: string }>;
  };

  it("builds the package before the functions are bundled", () => {
    expect(config.buildCommand).toBe("npm run build");
  });

  it("maps the canonical public paths onto the function files", () => {
    const routes = new Map(config.rewrites.map((r) => [r.source, r.destination]));
    expect(routes.get("/mcp")).toBe("/api/mcp");
    expect(routes.get("/health")).toBe("/api/health");
    expect(routes.get("/.well-known/oauth-protected-resource/:path*")).toBe("/api/well-known");
  });

  it("points at an output directory that exists, so the build has something to publish", () => {
    expect(existsSync(join(repoRoot, config.outputDirectory))).toBe(true);
  });

  it("has a function file for every rewrite destination", () => {
    for (const { destination } of config.rewrites) {
      expect(existsSync(join(repoRoot, `${destination.replace(/^\//, "")}.js`)), destination).toBe(
        true,
      );
    }
  });

  it("keeps the deployment scaffolding out of the npm package", () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as {
      files: string[];
    };
    for (const entry of pkg.files) {
      expect(entry).not.toMatch(/^(api|public|vercel\.json)/);
    }
  });
});
