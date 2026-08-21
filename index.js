#!/usr/bin/env node
/**
 * HTTP entry point: one server that routes every request.
 *
 * This file exists at the repository root on purpose. Vercel picks the root
 * entrypoint for the whole deployment — left to its own devices it picked
 * `src/index.ts`, the stdio CLI, and answered every route with a 500 because
 * that module exports no handler. Being the root `index.js` makes the choice
 * unambiguous, and it means the platform sees the original request path, so
 * `/mcp`, `/health` and the well-known routes need no rewrite rules.
 *
 * Two faces, one router:
 *   - `export default { fetch }` is what Vercel (and Workers, Deno, Bun) call;
 *   - run directly (`node index.js`) it listens, for local development.
 *
 * The stdio entry point remains `src/index.ts` / `dist/index.js` and is
 * untouched by any of this.
 */
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

import { createSevdeskHttpHandler } from "./dist/http.js";
import { loadDotEnv } from "./dist/lib/env.js";

let handler;

/** Built on first request: a cold start must not fail before it can answer. */
function router() {
  if (!handler) {
    loadDotEnv();
    handler = createSevdeskHttpHandler();
  }
  return handler;
}

export default {
  fetch: (request) => router().fetch(request),
};

/** Node's IncomingMessage → web Request. */
function toWebRequest(req, fallbackHost) {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? fallbackHost}`);
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    for (const v of Array.isArray(value) ? value : [value]) headers.append(key, v);
  }
  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  return new Request(url, {
    method: req.method,
    headers,
    ...(hasBody ? { body: req, duplex: "half" } : {}),
  });
}

async function listen() {
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? "127.0.0.1";

  const server = createServer(async (req, res) => {
    let response;
    try {
      response = await router().fetch(toWebRequest(req, `${host}:${port}`));
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err instanceof Error ? err.message : "Internal error" }));
      return;
    }
    res.writeHead(response.status, Object.fromEntries(response.headers));
    if (!response.body) {
      res.end();
      return;
    }
    for await (const chunk of response.body) res.write(chunk);
    res.end();
  });

  server.listen(port, host, () => {
    console.error(`sevdesk-mcp streamable http on http://${host}:${port}/mcp`);
  });
}

// Only when invoked as a script — an import (Vercel, a test) must not bind a port.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await listen();
}
