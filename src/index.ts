#!/usr/bin/env node
import { serveStdio } from "@modelcontextprotocol/server/stdio";

import { catalog } from "./catalog.js";
import { loadConfig } from "./config.js";
import { createToolContext } from "./context.js";
import { loadDotEnv } from "./lib/env.js";
import { VERSION, buildServer, tools } from "./server.js";

async function main(): Promise<void> {
  // A .env beside package.json is a convenience for runs outside an MCP
  // client; the client's own env block still wins over anything in it.
  const envFile = loadDotEnv();
  const config = loadConfig();
  // One context for the process: the VAT-profile lookup stays cached for the
  // lifetime of the connection, as it always has over stdio.
  const ctx = createToolContext(config);

  // serveStdio negotiates the protocol era per connection: 2026-07-28
  // clients get the stateless envelope, 2025-era clients the classic
  // initialize handshake — same server instance either way.
  serveStdio(() => buildServer(ctx), {
    onerror: (err) => console.error(err.message),
  });

  // stderr only — stdout carries the MCP protocol.
  console.error(
    `sevdesk-mcp ${VERSION} ready · ${tools.length} tools · ` +
      `${catalog.operationCount} API operations · ` +
      `mode: ${config.readOnly ? "READ-ONLY" : config.dryRun ? "DRY-RUN" : "read/write"}` +
      (envFile ? ` · loaded ${envFile}` : ""),
  );
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
