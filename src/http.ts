/**
 * Stateless Streamable HTTP transport.
 *
 * Provider-neutral: everything here is web-standard `Request`/`Response`, so
 * the same handler runs on Vercel Functions, Cloudflare Workers, Deno, Bun,
 * or `node:http` through a small bridge. No Next.js, no Redis, no session
 * store — each request is served by a fresh server instance built from the
 * one `buildServer(ctx)` in `server.ts`, which is why the HTTP tool contract
 * cannot drift from the stdio one.
 *
 * Routes:
 *
 *   POST /mcp                                    the MCP endpoint
 *   GET  /health                                 liveness, no sevDesk call
 *   GET  /.well-known/oauth-protected-resource…  RFC 9728 (oauth mode only)
 *   GET  /.well-known/oauth-authorization-server RFC 8414 passthrough
 */

import {
  createMcpHandler,
  hostHeaderValidationResponse,
  localhostAllowedHostnames,
  oauthMetadataResponse,
  OAuthError,
  OAuthErrorCode,
  originValidationResponse,
  requireBearerAuth,
  type AuthInfo,
  type McpHttpHandler,
} from "@modelcontextprotocol/server";

import { catalog } from "./catalog.js";
import type { ClientHooks } from "./client.js";
import {
  bearerToken,
  createIssuerMetadataLoader,
  createJwtVerifier,
  createStaticTokenVerifier,
  loadAuthConfig,
  type AuthConfig,
  type JwtVerifierHooks,
  type VerifyToken,
} from "./auth.js";
import { loadConfig, type Config } from "./config.js";
import {
  createToolContext,
  envCredentialResolver,
  type SevdeskCredentialResolver,
} from "./context.js";
import { VERSION, buildServer, tools } from "./server.js";

export const DEFAULT_MCP_PATH = "/mcp";
export const DEFAULT_HEALTH_PATH = "/health";
const PROTECTED_RESOURCE_PREFIX = "/.well-known/oauth-protected-resource";
const AUTHORIZATION_SERVER_PATH = "/.well-known/oauth-authorization-server";

export interface HttpHandlerOptions {
  /** Defaults to {@link loadConfig} — the same environment stdio reads. */
  config?: Config;
  /** Defaults to {@link loadAuthConfig}. */
  auth?: AuthConfig;
  /**
   * Replaces the built-in JWT verification. Use it to plug in an IdP SDK,
   * RFC 7662 introspection, or any other token check; the sevDesk core is
   * unaffected either way.
   */
  verifyToken?: VerifyToken;
  /** Where a request's sevDesk token comes from. Defaults to `SEVDESK_API_TOKEN`. */
  credentials?: SevdeskCredentialResolver;
  /**
   * This server's canonical public MCP URL, used as the RFC 9728 `resource`
   * identifier and as the default Host/Origin allowlist. Defaults to
   * `MCP_PUBLIC_URL`, then to the Vercel deployment URL.
   */
  publicUrl?: URL;
  /** Hostnames accepted in the `Host` header. Defaults to the public URL plus localhost. */
  allowedHosts?: string[];
  /** Hostnames accepted in the `Origin` header. Defaults to {@link allowedHosts}. */
  allowedOrigins?: string[];
  /** Path the MCP endpoint answers on. Defaults to `/mcp`. */
  mcpPath?: string;
  /** Path the health check answers on. Defaults to `/health`. */
  healthPath?: string;
  /** Reporting only; never alters a response. Defaults to a stderr line. */
  onerror?: (error: Error) => void;
  /** Test seams for the JWT verifier and issuer-metadata loader. */
  hooks?: JwtVerifierHooks;
  /** Test seams handed to every sevDesk client this handler builds. */
  clientHooks?: ClientHooks;
}

/**
 * The composed transport. `fetch` is the whole router, for hosts that mount
 * one handler; `mcp`, `health` and `wellKnown` are the individual endpoints,
 * for hosts that route by filesystem (Vercel's `api/` directory) and would
 * otherwise have to guess how their rewrite rewrote the path.
 */
export interface SevdeskHttpHandler {
  fetch: (request: Request) => Promise<Response>;
  mcp: (request: Request) => Promise<Response>;
  health: (request: Request) => Promise<Response>;
  wellKnown: (request: Request) => Promise<Response>;
  close: () => Promise<void>;
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

/** The deployment URL Vercel injects, so a fresh import needs no extra variable. */
function vercelUrl(env: NodeJS.ProcessEnv): string | undefined {
  const host = env.VERCEL_PROJECT_PRODUCTION_URL ?? env.VERCEL_BRANCH_URL ?? env.VERCEL_URL;
  return host ? `https://${host}` : undefined;
}

function resolvePublicUrl(
  explicit: URL | undefined,
  mcpPath: string,
  env: NodeJS.ProcessEnv,
): URL | undefined {
  if (explicit) return explicit;
  const raw = env.MCP_PUBLIC_URL?.trim() || vercelUrl(env);
  if (!raw) return undefined;
  try {
    const url = new URL(raw);
    // A bare origin means "the MCP endpoint on this origin".
    if (url.pathname === "/" || url.pathname === "") url.pathname = mcpPath;
    return url;
  } catch {
    return undefined;
  }
}

/**
 * A header-only stand-in for the request, used for Host/Origin validation.
 *
 * Two reasons it exists. A `Request` that was handed to us directly rather
 * than parsed off a socket carries no `Host` header even though its URL names
 * the host, and rejecting those would make the handler unusable in-process.
 * And validating a copy keeps the real request's body untouched — re-wrapping
 * a `Request` marks its stream as consumed.
 */
function validationProbe(request: Request): Request {
  const headers = new Headers(request.headers);
  if (!headers.has("host")) headers.set("host", new URL(request.url).host);
  return new Request(request.url, { method: "GET", headers });
}

function hostnameList(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Turn a {@link VerifyToken} hook into the SDK's per-request bearer gate.
 * The hook returning `undefined` and the hook throwing both mean "refused";
 * the SDK renders the `WWW-Authenticate` challenge either way.
 */
async function authenticate(
  request: Request,
  verify: VerifyToken,
  requiredScopes: string[],
  resourceMetadataUrl: string | undefined,
): Promise<AuthInfo | Response> {
  const gate = requireBearerAuth({
    verifier: {
      async verifyAccessToken(token) {
        const info = await verify(request, token);
        if (!info) throw new OAuthError(OAuthErrorCode.InvalidToken, "Token was not accepted.");
        return info;
      },
    },
    requiredScopes,
    resourceMetadataUrl,
  });
  return gate(request);
}

export function createSevdeskHttpHandler(
  options: HttpHandlerOptions = {},
): SevdeskHttpHandler {
  const env = process.env;
  const config = options.config ?? loadConfig(env);
  const auth = options.auth ?? loadAuthConfig(env);
  const resolver = options.credentials ?? envCredentialResolver(config);
  const mcpPath = options.mcpPath ?? DEFAULT_MCP_PATH;
  const healthPath = options.healthPath ?? DEFAULT_HEALTH_PATH;
  const onerror =
    options.onerror ??
    ((error: Error) => {
      // stderr only, and only the message — a token or a request body must
      // never reach a log line.
      console.error(`[sevdesk-mcp:http] ${error.message}`);
    });

  const publicUrl = resolvePublicUrl(options.publicUrl, mcpPath, env);
  const derivedHosts = [
    ...(publicUrl ? [publicUrl.hostname] : []),
    ...(vercelUrl(env) ? [new URL(vercelUrl(env)!).hostname] : []),
    ...localhostAllowedHostnames(),
  ];
  const allowedHosts =
    options.allowedHosts ?? orDerived(hostnameList(env.MCP_ALLOWED_HOSTS), derivedHosts);
  const allowedOrigins =
    options.allowedOrigins ?? orDerived(hostnameList(env.MCP_ALLOWED_ORIGINS), allowedHosts);

  if (auth.mode !== "none" && !auth.oauth && !auth.staticToken && !options.verifyToken) {
    throw new Error(
      `Auth mode '${auth.mode}' needs something to verify with — an OAuth ` +
        `configuration, a static token, or a verifyToken hook. Refusing to ` +
        `serve unauthenticated.`,
    );
  }
  const verify: VerifyToken | undefined =
    options.verifyToken ??
    (auth.oauth
      ? createJwtVerifier(auth.oauth, options.hooks)
      : auth.staticToken
        ? createStaticTokenVerifier(auth.staticToken, options.hooks)
        : undefined);
  const issuerMetadata = auth.oauth
    ? createIssuerMetadataLoader(auth.oauth, options.hooks)
    : undefined;
  // A supplied verifier is the decision: it would be a trap to accept one and
  // then serve every request anonymously because the mode still said `none`.
  const authenticated = verify !== undefined;

  // One handler for the process. The factory runs per request and builds a
  // context from that request's own credentials, so two concurrent requests
  // share no token, no sevDesk client and no VAT-profile cache.
  const handler: McpHttpHandler = createMcpHandler(
    async ({ authInfo, requestInfo }) => {
      if (!requestInfo) {
        throw new Error("The HTTP transport served a request without a Request object.");
      }
      const credentials = await resolver.resolve({ request: requestInfo, authInfo });
      return buildServer(createToolContext(config, credentials, options.clientHooks));
    },
    { legacy: "stateless", onerror },
  );

  /**
   * The RFC 9728 URL to name in a `WWW-Authenticate` challenge — but only
   * when this deployment can actually serve that document. Pointing a client
   * at a 404 is worse than not pointing it anywhere.
   */
  function protectedResourceUrl(request: Request): string | undefined {
    if (!issuerMetadata) return undefined;
    const resource = publicUrl ?? new URL(mcpPath, new URL(request.url).origin);
    return `${resource.origin}${PROTECTED_RESOURCE_PREFIX}${resource.pathname}`;
  }

  /**
   * DNS-rebinding and cross-site protection, per the MCP specification's
   * requirement that a server validate `Origin` and, for local binds, `Host`.
   * Every entry point runs it — a host that mounts `mcp` directly must not
   * end up less protected than one that mounts `fetch`.
   */
  function guard(request: Request): Response | undefined {
    const probe = validationProbe(request);
    const rejected =
      hostHeaderValidationResponse(probe, allowedHosts) ??
      originValidationResponse(probe, allowedOrigins);
    if (!rejected) return undefined;
    onerror(
      new Error(
        `Rejected ${request.method} on Host='${request.headers.get("host") ?? ""}' ` +
          `Origin='${request.headers.get("origin") ?? ""}'. Allowed hosts: ` +
          `${allowedHosts.join(", ") || "(none)"}. Set MCP_PUBLIC_URL or ` +
          `MCP_ALLOWED_HOSTS/MCP_ALLOWED_ORIGINS for this deployment.`,
      ),
    );
    return rejected;
  }

  async function health(request: Request): Promise<Response> {
    const rejected = guard(request);
    if (rejected) return rejected;
    if (request.method !== "GET" && request.method !== "HEAD") {
      return json({ error: "Method not allowed." }, 405, { Allow: "GET, HEAD" });
    }
    // Deliberately says nothing about the account, the token or the mode.
    const body = json({
      status: "ok",
      name: "sevdesk-mcp",
      version: VERSION,
      transport: "streamable-http",
      tools: tools.length,
      operations: catalog.operationCount,
    });
    return request.method === "HEAD" ? new Response(null, { headers: body.headers }) : body;
  }

  async function wellKnown(request: Request): Promise<Response> {
    const rejected = guard(request);
    if (rejected) return rejected;
    if (!auth.oauth || !issuerMetadata) {
      return json(
        { error: "This deployment has no authorization server configured." },
        404,
      );
    }
    let oauthMetadata;
    try {
      oauthMetadata = await issuerMetadata();
    } catch (err) {
      onerror(err instanceof Error ? err : new Error(String(err)));
      return json({ error: "Authorization server metadata is unavailable." }, 502);
    }
    const resource = publicUrl ?? new URL(mcpPath, new URL(request.url).origin);
    return (
      oauthMetadataResponse(request, {
        oauthMetadata,
        resourceServerUrl: resource,
        resourceName: "sevDesk MCP",
        ...(auth.oauth.requiredScopes.length > 0
          ? { scopesSupported: auth.oauth.requiredScopes }
          : {}),
      }) ?? json({ error: "Not found." }, 404)
    );
  }

  async function mcp(request: Request): Promise<Response> {
    const rejected = guard(request);
    if (rejected) return rejected;
    if (!authenticated || !verify) return handler.fetch(request);

    const resourceMetadataUrl = protectedResourceUrl(request);
    const gated = await authenticate(
      request,
      verify,
      auth.oauth?.requiredScopes ?? [],
      resourceMetadataUrl,
    );
    if (gated instanceof Response) {
      onerror(
        new Error(
          `Refused ${request.method} ${new URL(request.url).pathname}: ` +
            `HTTP ${gated.status}${bearerToken(request) ? "" : " (no bearer token)"}`,
        ),
      );
      return gated;
    }
    return handler.fetch(request, { authInfo: gated });
  }

  async function fetchRoute(request: Request): Promise<Response> {
    const rejected = guard(request);
    if (rejected) return rejected;

    const { pathname } = new URL(request.url);
    if (pathname === mcpPath) return mcp(request);
    if (pathname === healthPath) return health(request);
    if (pathname === AUTHORIZATION_SERVER_PATH || pathname.startsWith(PROTECTED_RESOURCE_PREFIX)) {
      return wellKnown(request);
    }
    return json(
      {
        error: "Not found.",
        endpoints: { mcp: mcpPath, health: healthPath },
      },
      404,
    );
  }

  return {
    fetch: fetchRoute,
    mcp,
    health,
    wellKnown,
    close: () => handler.close(),
  };
}

function orDerived(configured: string[], derived: string[]): string[] {
  return configured.length > 0 ? configured : [...new Set(derived)];
}
