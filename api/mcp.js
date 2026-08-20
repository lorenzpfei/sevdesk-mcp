// Vercel Function: the MCP endpoint. Public URL is /mcp (see vercel.json).
import { handler } from "./_handler.js";

export default { fetch: (request) => handler().mcp(request) };
