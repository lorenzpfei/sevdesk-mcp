// Vercel Function: liveness. Never calls sevDesk, never reports secrets.
import { handler } from "./_handler.js";

export default { fetch: (request) => handler().health(request) };
