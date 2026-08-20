#!/usr/bin/env node
/**
 * Local Streamable HTTP server, for development and for pointing MCP
 * Inspector at something real. Not used in production: on Vercel the
 * platform provides the HTTP layer and `api/` is the entry point.
 *
 *   npm run dev:http            # http://127.0.0.1:3000/mcp
 *   PORT=8080 npm run dev:http
 */
import { createServer } from "node:http";

import { createSevdeskHttpHandler } from "../dist/http.js";
import { loadDotEnv } from "../dist/lib/env.js";

loadDotEnv();

const handler = createSevdeskHttpHandler();
const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? "127.0.0.1";

/** Node's IncomingMessage → web Request. */
function toWebRequest(req) {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? `${host}:${port}`}`);
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

const server = createServer(async (req, res) => {
  let response;
  try {
    response = await handler.fetch(toWebRequest(req));
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
