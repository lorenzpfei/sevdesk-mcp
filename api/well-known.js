// Vercel Function: RFC 9728 protected-resource and RFC 8414 metadata.
import { handler } from "./_handler.js";

export default { fetch: (request) => handler().wellKnown(request) };
