/**
 * The one place the Vercel shell touches sevdesk-mcp.
 *
 * Everything else in `api/` is a three-line route file, and nothing in `src/`
 * knows Vercel exists. The handler is built lazily and reused across warm
 * invocations; it holds no session state, so a cold start costs nothing but
 * the import.
 */
import { createSevdeskHttpHandler } from "../dist/http.js";

let instance;

export function handler() {
  return (instance ??= createSevdeskHttpHandler());
}
