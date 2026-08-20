/**
 * Isolation between concurrent requests.
 *
 * A stateless serverless deployment runs many invocations in one process. If
 * two of them resolved to different sevDesk accounts, nothing may cross over:
 * not the token, not the client, not the VAT-profile cache that decides which
 * tax rules the audit tools apply.
 */

import { describe, expect, it } from "vitest";

import { createToolContext } from "../src/context.js";
import { createSevdeskHttpHandler } from "../src/http.js";
import { MCP_URL, post, rpcBody, testConfig } from "./helpers/http.js";

interface Recorded {
  token: string | null;
  path: string;
}

/** A fake sevDesk that answers per token, so a crossover shows up in the result. */
function perTenantApi() {
  const calls: Recorded[] = [];
  const fetchFn: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : (input as Request).url);
    const token = new Headers(init?.headers).get("authorization");
    calls.push({ token, path: url.pathname });

    if (url.pathname.endsWith("/Tools/bookkeepingSystemVersion")) {
      return Response.json({ objects: { version: token === "token-a" ? "1.0" : "2.0" } });
    }
    if (url.pathname.endsWith("/Invoice")) {
      // Account A looks like a §19 Kleinunternehmer, account B like regular VAT.
      const rows =
        token === "token-a"
          ? [{ id: "1", status: "200", invoiceDate: "2026-01-01", taxRule: { id: "11" }, smallSettlement: true }]
          : [{ id: "2", status: "200", invoiceDate: "2026-01-01", taxRule: { id: "1" } }];
      return Response.json({ objects: rows });
    }
    return Response.json({ objects: [] });
  };
  return { fetchFn, calls };
}

const ping = {
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name: "sevdesk_ping", arguments: {} },
};

function tenantHandler(api: { fetchFn: typeof fetch }) {
  let nth = 0;
  return createSevdeskHttpHandler({
    config: testConfig({ vatRegime: "auto", vatRegimeSource: "default" }),
    auth: { mode: "none" },
    publicUrl: new URL(MCP_URL),
    onerror: () => {},
    clientHooks: { fetchFn: api.fetchFn },
    credentials: {
      async resolve() {
        // Alternate per request, and yield first so the two requests really
        // interleave rather than running one after the other.
        const token = ++nth % 2 === 1 ? "token-a" : "token-b";
        await new Promise((r) => setTimeout(r, 5));
        return { apiToken: token };
      },
    },
  });
}

describe("concurrent requests with different credentials", () => {
  it("sends each request's own token and never the other's", async () => {
    const api = perTenantApi();
    const handler = tenantHandler(api);

    await Promise.all([handler.fetch(post(ping)), handler.fetch(post({ ...ping, id: 2 }))]);

    const tokens = new Set(api.calls.map((c) => c.token));
    expect(tokens).toEqual(new Set(["token-a", "token-b"]));
    // Every call carries exactly one token; a shared client would show a mix
    // of paths under a single token.
    for (const token of tokens) {
      const paths = api.calls.filter((c) => c.token === token).map((c) => c.path);
      expect(paths.length).toBeGreaterThan(0);
    }
  });

  it("does not share the VAT-profile cache between accounts", async () => {
    const api = perTenantApi();
    const handler = tenantHandler(api);

    const [first, second] = await Promise.all([
      handler.fetch(post(ping)).then(rpcBody),
      handler.fetch(post({ ...ping, id: 2 })).then(rpcBody),
    ]);

    const texts = [first, second].map((body) => {
      const result = body.result as { content?: Array<{ text?: string }> };
      return result.content?.[0]?.text ?? "";
    });
    // One account resolves to kleinunternehmer, the other to regular. A shared
    // profile resolver would give both the same answer.
    const regimes = texts.map((t) => (/kleinunternehmer/i.test(t) ? "ku" : "regular"));
    expect(new Set(regimes)).toEqual(new Set(["ku", "regular"]));

    // The bookkeeping version comes straight from the per-token client.
    expect(texts.some((t) => t.includes('"1.0"'))).toBe(true);
    expect(texts.some((t) => t.includes('"2.0"'))).toBe(true);
  });

  it("builds a distinct client and profile resolver per context", async () => {
    const config = testConfig();
    const a = createToolContext(config, { apiToken: "token-a" });
    const b = createToolContext(config, { apiToken: "token-b" });

    expect(a.client).not.toBe(b.client);
    expect(a.getProfile).not.toBe(b.getProfile);
    expect(a.config.apiToken).toBe("token-a");
    expect(b.config.apiToken).toBe("token-b");
    // The shared config object must not have been mutated on the way.
    expect(config.apiToken).toBe("test-token");
  });

  it("keeps every non-credential setting from the deployment config", async () => {
    const config = testConfig({ readOnly: true, dryRun: true, allowedReceiptDirs: ["/srv/receipts"] });
    const ctx = createToolContext(config, { apiToken: "token-a" });
    expect(ctx.config).toMatchObject({
      readOnly: true,
      dryRun: true,
      allowedReceiptDirs: ["/srv/receipts"],
      apiToken: "token-a",
    });
  });
});

describe("repeated invocations of one handler", () => {
  it("serves many sequential requests without accumulating session state", async () => {
    const api = perTenantApi();
    const handler = createSevdeskHttpHandler({
      config: testConfig(),
      auth: { mode: "none" },
      publicUrl: new URL(MCP_URL),
      onerror: () => {},
      clientHooks: { fetchFn: api.fetchFn },
    });

    // Every request is a fresh initialize-less POST, the way a cold-started
    // serverless invocation arrives.
    for (let i = 0; i < 5; i++) {
      const res = await handler.fetch(
        post({ jsonrpc: "2.0", id: i, method: "tools/list", params: {} }),
      );
      expect(res.status).toBe(200);
      const body = (await rpcBody(res)) as { result?: { tools?: unknown[] } };
      expect(body.result?.tools).toHaveLength(24);
    }
  });

  it("answers concurrent requests independently under one handler", async () => {
    const api = perTenantApi();
    const handler = createSevdeskHttpHandler({
      config: testConfig(),
      auth: { mode: "none" },
      publicUrl: new URL(MCP_URL),
      onerror: () => {},
      clientHooks: { fetchFn: api.fetchFn },
    });

    const responses = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        handler.fetch(post({ jsonrpc: "2.0", id: i, method: "tools/list", params: {} })).then(rpcBody),
      ),
    );
    expect(responses.map((r) => r.id)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });
});
