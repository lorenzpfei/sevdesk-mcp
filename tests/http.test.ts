import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createSevdeskHttpHandler } from "../src/http.js";
import { VERSION, tools } from "../src/server.js";
import { catalog } from "../src/catalog.js";
import {
  MCP_URL,
  TEST_ORIGIN,
  connectClient,
  createHandler,
  fakeSevdesk,
  post,
  testConfig,
  textOf,
} from "./helpers/http.js";

describe("routing", () => {
  it("answers /health without touching sevDesk", async () => {
    const api = fakeSevdesk();
    const handler = createHandler({ clientHooks: { fetchFn: api.fetchFn } });

    const res = await handler.fetch(new Request(`${TEST_ORIGIN}/health`));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      status: "ok",
      name: "sevdesk-mcp",
      version: VERSION,
      transport: "streamable-http",
      tools: tools.length,
      operations: catalog.operationCount,
    });
    expect(api.calls).toEqual([]);
  });

  it("leaks neither the token nor the mode through /health", async () => {
    const handler = createHandler({
      config: testConfig({ apiToken: "super-secret-token", readOnly: true }),
    });
    const body = await (await handler.fetch(new Request(`${TEST_ORIGIN}/health`))).text();
    expect(body).not.toContain("super-secret-token");
    expect(body.toLowerCase()).not.toContain("readonly");
  });

  it("refuses non-GET on /health with an Allow header", async () => {
    const handler = createHandler();
    const res = await handler.fetch(new Request(`${TEST_ORIGIN}/health`, { method: "POST" }));
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("GET, HEAD");
  });

  it("404s an unknown path and names the endpoints", async () => {
    const handler = createHandler();
    const res = await handler.fetch(new Request(`${TEST_ORIGIN}/nope`));
    expect(res.status).toBe(404);
    expect(await res.json()).toMatchObject({ endpoints: { mcp: "/mcp", health: "/health" } });
  });

  it("honours a custom mcpPath", async () => {
    const handler = createHandler({ mcpPath: "/api/mcp" });
    expect((await handler.fetch(new Request(`${TEST_ORIGIN}/mcp`))).status).toBe(404);
    const res = await handler.fetch(
      new Request(`${TEST_ORIGIN}/api/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      }),
    );
    expect(res.status).not.toBe(404);
  });
});

describe("origin and host validation", () => {
  it("rejects a Host header outside the allowlist", async () => {
    const handler = createHandler({ allowedHosts: ["mcp.example.test"] });
    const res = await handler.fetch(
      new Request(MCP_URL, { headers: { Host: "evil.example.test" } }),
    );
    expect(res.status).toBe(403);
  });

  it("rejects a cross-site Origin", async () => {
    const handler = createHandler({
      allowedHosts: ["localhost"],
      allowedOrigins: ["localhost"],
    });
    const res = await handler.fetch(
      post({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, {
        headers: { Origin: "https://evil.example.test" },
      }),
    );
    expect(res.status).toBe(403);
  });

  it("passes a request with no Origin header, as non-browser clients send", async () => {
    const handler = createHandler({ allowedOrigins: [] });
    const res = await handler.fetch(new Request(`${TEST_ORIGIN}/health`));
    expect(res.status).toBe(200);
  });

  it("guards the per-route entry points too, not just fetch", async () => {
    const handler = createHandler({ allowedHosts: ["mcp.example.test"] });
    const request = new Request(MCP_URL, { headers: { Host: "evil.example.test" } });
    expect((await handler.mcp(request)).status).toBe(403);
    expect((await handler.health(request)).status).toBe(403);
    expect((await handler.wellKnown(request)).status).toBe(403);
  });
});

describe("protocol handling", () => {
  it("rejects a POST that is not application/json", async () => {
    const handler = createHandler();
    const res = await handler.fetch(
      new Request(MCP_URL, {
        method: "POST",
        headers: { "Content-Type": "text/plain", Accept: "application/json" },
        body: "tools/list",
      }),
    );
    expect(res.status).toBe(415);
  });

  it("answers malformed JSON with a JSON-RPC parse error", async () => {
    const handler = createHandler();
    const res = await handler.fetch(post("{ not json"));
    const body = (await res.json()) as { error?: { code?: number } };
    expect(body.error?.code).toBe(-32700);
  });

  it("answers a well-formed body that is not a JSON-RPC message with an error", async () => {
    const handler = createHandler();
    const res = await handler.fetch(post({ hello: "world" }));
    const body = (await res.json()) as { error?: { code?: number } };
    expect(body.error?.code).toBeLessThan(0);
  });

  it("refuses GET and DELETE on the stateless endpoint", async () => {
    const handler = createHandler();
    for (const method of ["GET", "DELETE"]) {
      const res = await handler.fetch(new Request(MCP_URL, { method }));
      expect(res.status, method).toBe(405);
    }
  });

  it("needs no legacy /sse or /message route", async () => {
    const handler = createHandler();
    for (const path of ["/sse", "/message", "/messages"]) {
      expect((await handler.fetch(new Request(`${TEST_ORIGIN}${path}`))).status, path).toBe(404);
    }
  });

  it("maps an aborted request to a transport error, not a hung response", async () => {
    const handler = createHandler({
      clientHooks: {
        fetchFn: async () => {
          await new Promise((r) => setTimeout(r, 50));
          return new Response(JSON.stringify({ objects: [] }), { status: 200 });
        },
      },
    });
    const controller = new AbortController();
    const promise = handler.fetch(
      post(
        { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "sevdesk_ping", arguments: {} } },
        { signal: controller.signal },
      ),
    );
    controller.abort();
    // The handler must settle rather than wait forever on an abandoned request.
    await expect(Promise.race([promise, new Promise((_, r) => setTimeout(() => r(new Error("hung")), 2000))]))
      .resolves.toBeInstanceOf(Response);
  });
});

describe("end-to-end with the official MCP client", () => {
  for (const era of ["legacy", "auto"] as const) {
    it(`initializes and lists tools over the ${era} protocol negotiation`, async () => {
      const handler = createHandler();
      const client = await connectClient(handler, { era });
      try {
        const { tools: listed } = await client.listTools();
        expect(listed.map((t) => t.name)).toEqual(tools.map((t) => t.name));
      } finally {
        await client.close();
      }
    });
  }

  it("runs the discovery tools over HTTP", async () => {
    const handler = createHandler();
    const client = await connectClient(handler);
    try {
      const list = await client.callTool({
        name: "sevdesk_list_operations",
        arguments: { query: "voucher", kind: "read" },
      });
      expect(textOf(list)).toContain("Voucher");

      const describe = await client.callTool({
        name: "sevdesk_describe_operation",
        arguments: { operationId: "getVouchers" },
      });
      expect(textOf(describe)).toContain("GET /Voucher");
    } finally {
      await client.close();
    }
  });

  it("calls sevdesk_call against a mocked API over HTTP", async () => {
    const api = fakeSevdesk((url) =>
      url.pathname === "/api/v1/Voucher"
        ? { status: 200, body: { objects: [{ id: "42", description: "Mocked voucher" }] } }
        : undefined,
    );
    const handler = createHandler({ clientHooks: { fetchFn: api.fetchFn } });
    const client = await connectClient(handler);
    try {
      const result = await client.callTool({
        name: "sevdesk_call",
        arguments: { operationId: "getVouchers", params: { limit: 1 } },
      });
      expect(textOf(result)).toContain("Mocked voucher");
      expect(api.calls.map((c) => `${c.method} ${c.url}`)).toContain("GET /api/v1/Voucher");
      expect(api.calls[0]?.token).toBe("test-token");
    } finally {
      await client.close();
    }
  });

  it("runs a curated read tool over HTTP", async () => {
    const api = fakeSevdesk((url) => {
      if (url.pathname === "/api/v1/Tools/bookkeepingSystemVersion") {
        return { status: 200, body: { objects: { version: "2.0" } } };
      }
      return { status: 200, body: { objects: [] } };
    });
    const handler = createHandler({ clientHooks: { fetchFn: api.fetchFn } });
    const client = await connectClient(handler);
    try {
      const result = await client.callTool({ name: "sevdesk_ping", arguments: {} });
      expect(textOf(result)).toContain("2.0");
    } finally {
      await client.close();
    }
  });

  it("runs an audit tool over HTTP", async () => {
    const api = fakeSevdesk(() => ({ status: 200, body: { objects: [] } }));
    const handler = createHandler({ clientHooks: { fetchFn: api.fetchFn } });
    const client = await connectClient(handler);
    try {
      const result = await client.callTool({
        name: "sevdesk_audit_vat",
        arguments: { from: "2026-01-01", to: "2026-03-31" },
      });
      expect(result.isError ?? false).toBe(false);
      expect(api.calls.length).toBeGreaterThan(0);
    } finally {
      await client.close();
    }
  });

  it("runs the invoice PDF download path over HTTP", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sevdesk-http-pdf-"));
    const api = fakeSevdesk((url) =>
      url.pathname === "/api/v1/Invoice/7/getPdf"
        ? {
            status: 200,
            body: {
              objects: {
                filename: "invoice-7.pdf",
                content: Buffer.from("%PDF-1.7 test").toString("base64"),
                base64encoded: true,
              },
            },
          }
        : undefined,
    );
    const handler = createSevdeskHttpHandler({
      config: testConfig({ allowedReceiptDirs: [dir] }),
      auth: { mode: "none" },
      publicUrl: new URL(MCP_URL),
      onerror: () => {},
      clientHooks: { fetchFn: api.fetchFn },
    });
    const client = await connectClient(handler);
    try {
      const result = await client.callTool({
        name: "sevdesk_get_invoice_pdf",
        arguments: { invoiceId: "7", directory: dir },
      });
      expect(api.calls.map((c) => c.url)).toContain("/api/v1/Invoice/7/getPdf");
      expect(textOf(result)).toContain("invoice-7.pdf");
      expect(await readFile(join(dir, "invoice-7.pdf"), "utf8")).toBe("%PDF-1.7 test");
    } finally {
      await client.close();
    }
  });

  it("reports the missing allowlist for the receipt-folder diff instead of pretending", async () => {
    const handler = createHandler({ clientHooks: { fetchFn: fakeSevdesk().fetchFn } });
    const client = await connectClient(handler);
    try {
      const result = await client.callTool({
        name: "sevdesk_diff_receipt_folder",
        arguments: { directory: "/tmp/receipts", from: "2026-01-01", to: "2026-12-31" },
      });
      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain("SEVDESK_RECEIPT_DIRS");
    } finally {
      await client.close();
    }
  });

  it("previews a write as a dry run over HTTP without calling sevDesk", async () => {
    const api = fakeSevdesk();
    const handler = createHandler({ clientHooks: { fetchFn: api.fetchFn } });
    const client = await connectClient(handler);
    try {
      const result = await client.callTool({
        name: "sevdesk_call",
        arguments: {
          operationId: "createContact",
          body: { name: "Dry Run GmbH" },
          dryRun: true,
        },
      });
      expect(textOf(result)).toContain("Nothing was sent");
      expect(api.calls).toEqual([]);
    } finally {
      await client.close();
    }
  });

  it("refuses a write tool in read-only mode over HTTP", async () => {
    const api = fakeSevdesk();
    const handler = createSevdeskHttpHandler({
      config: testConfig({ readOnly: true }),
      auth: { mode: "none" },
      publicUrl: new URL(MCP_URL),
      onerror: () => {},
      clientHooks: { fetchFn: api.fetchFn },
    });
    const client = await connectClient(handler);
    try {
      const result = await client.callTool({
        name: "sevdesk_create_voucher",
        arguments: { supplierName: "x", voucherDate: "2026-01-01", total: 1 },
      });
      expect(result.isError).toBe(true);
      expect(textOf(result)).toContain("SEVDESK_READ_ONLY");
      expect(api.calls).toEqual([]);
    } finally {
      await client.close();
    }
  });
});
