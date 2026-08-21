/**
 * Provider-neutral authentication for the HTTP transport.
 *
 * This server is a Resource Server, never an Authorization Server: it
 * verifies access tokens an external IdP issued and never mints, stores or
 * exchanges credentials of its own. Three modes ship:
 *
 *   - `oauth` — OAuth 2.1 bearer tokens verified as JWTs against the
 *     issuer's JWKS (signature, issuer, audience, expiry, optional scopes);
 *   - `token` — one shared secret, compared in constant time. No IdP to set
 *     up, so a single-operator deployment can be closed off immediately; the
 *     trade-off is no per-user identity, no expiry and no revocation short of
 *     rotating the secret. Clients that cannot send an `Authorization` header
 *     (ChatGPT Developer Mode among them) need `oauth`.
 *   - `none` — no authentication, for local development and tests only.
 *
 * Anything else plugs in through {@link VerifyToken}: return an `AuthInfo`
 * for a token you accept, `undefined` for one you don't. Introspection
 * (RFC 7662), an SDK from Auth0/Descope/WorkOS, or a static development
 * token are all a few lines in that hook, and none of them require a change
 * to the sevDesk core.
 *
 * The MCP access token is never the sevDesk API token. What a verified token
 * grants is a request to *this* server; which sevDesk account that request
 * reaches is decided by the credential resolver (see `context.ts`).
 */

import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthMetadata,
} from "@modelcontextprotocol/server";

export type AuthMode = "none" | "token" | "oauth";

/**
 * Verify one request's bearer token.
 *
 * Return the token's {@link AuthInfo} to accept it, `undefined` to refuse it
 * (the caller answers `401` with a `WWW-Authenticate` challenge). `expiresAt`
 * must be set — the SDK's bearer-auth layer refuses tokens without one.
 */
export type VerifyToken = (
  request: Request,
  bearerToken?: string,
) => Promise<AuthInfo | undefined> | AuthInfo | undefined;

export interface OAuthConfig {
  /** Issuer URL of the Authorization Server, matched against the `iss` claim. */
  issuer: string;
  /** Expected `aud` claim — normally this server's canonical MCP URL. */
  audience: string;
  /** JWKS endpoint. Discovered from the issuer's metadata when omitted. */
  jwksUri?: string;
  /** Scopes every token must carry. Empty means scopes are not checked. */
  requiredScopes: string[];
}

export interface AuthConfig {
  mode: AuthMode;
  oauth?: OAuthConfig;
  /** The shared secret for `token` mode. Never logged, never echoed. */
  staticToken?: string;
}

const AUTH_MODES: AuthMode[] = ["none", "token", "oauth"];

/**
 * Shortest shared secret accepted in `token` mode. A hand-typed password
 * would be brute-forceable against an endpoint that holds a whole ledger,
 * and there is no rate limiter in front of this one.
 */
export const MIN_STATIC_TOKEN_LENGTH = 32;

/** True for a deployment that must not serve accounting data anonymously by accident. */
export function isProductionLike(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.VERCEL_ENV === "production" || env.NODE_ENV === "production";
}

/**
 * Read the auth configuration from the environment.
 *
 * `MCP_AUTH_MODE` has no default in a production-like deployment: leaving it
 * unset there is the accident this refuses to make. Locally it defaults to
 * `none` so `npm run dev:http` and the tests need no setup.
 */
export function loadAuthConfig(env: NodeJS.ProcessEnv = process.env): AuthConfig {
  const raw = env.MCP_AUTH_MODE?.trim().toLowerCase();

  if (!raw) {
    if (isProductionLike(env)) {
      throw new Error(
        "MCP_AUTH_MODE is not set. A production deployment must choose its " +
          "authentication explicitly: MCP_AUTH_MODE=oauth (with " +
          "MCP_OAUTH_ISSUER and MCP_OAUTH_AUDIENCE) to require OAuth 2.1 " +
          "bearer tokens, MCP_AUTH_MODE=token (with MCP_STATIC_TOKEN) for one " +
          "shared secret, or MCP_AUTH_MODE=none to knowingly publish this " +
          "sevDesk account without any authentication.",
      );
    }
    return { mode: "none" };
  }

  if (!AUTH_MODES.includes(raw as AuthMode)) {
    throw new Error(
      `MCP_AUTH_MODE='${env.MCP_AUTH_MODE}' is not valid. Use ${AUTH_MODES.join(" or ")}.`,
    );
  }
  if (raw === "none") return { mode: "none" };

  if (raw === "token") {
    const staticToken = env.MCP_STATIC_TOKEN?.trim();
    if (!staticToken) {
      throw new Error(
        "MCP_AUTH_MODE=token requires MCP_STATIC_TOKEN — the shared secret " +
          "clients send as 'Authorization: Bearer <secret>'. Generate one with " +
          "`openssl rand -hex 32`.",
      );
    }
    if (staticToken.length < MIN_STATIC_TOKEN_LENGTH) {
      throw new Error(
        `MCP_STATIC_TOKEN is too short (${staticToken.length} characters). ` +
          `Use at least ${MIN_STATIC_TOKEN_LENGTH}: this single secret is the ` +
          `only thing between the internet and the account's books. ` +
          `Generate one with \`openssl rand -hex 32\`.`,
      );
    }
    return { mode: "token", staticToken };
  }

  const issuer = env.MCP_OAUTH_ISSUER?.trim();
  const audience = env.MCP_OAUTH_AUDIENCE?.trim();
  if (!issuer || !audience) {
    throw new Error(
      "MCP_AUTH_MODE=oauth requires MCP_OAUTH_ISSUER (your Authorization " +
        "Server's issuer URL) and MCP_OAUTH_AUDIENCE (the audience it issues " +
        "tokens for, normally this server's public /mcp URL).",
    );
  }
  return {
    mode: "oauth",
    oauth: {
      issuer: issuer.replace(/\/+$/, ""),
      audience,
      jwksUri: env.MCP_OAUTH_JWKS_URI?.trim() || undefined,
      requiredScopes: (env.MCP_OAUTH_SCOPES ?? "")
        .split(/[,\s]+/)
        .map((s) => s.trim())
        .filter(Boolean),
    },
  };
}

/** Pull the bearer token out of an `Authorization` header. */
export function bearerToken(request: Request): string | undefined {
  const header = request.headers.get("authorization");
  if (!header) return undefined;
  const match = /^Bearer[ \t]+(\S+)$/i.exec(header.trim());
  return match?.[1];
}

function invalidToken(message: string): OAuthError {
  return new OAuthError(OAuthErrorCode.InvalidToken, message);
}

/**
 * Compare two issuer identifiers. Only the trailing slash is normalized:
 * several major IdPs (Auth0 among them) publish `iss` with one while their
 * documented issuer URL is written without, and a byte comparison would
 * reject every token they sign. Host and path still have to match exactly.
 */
function sameIssuer(a: string, b: string): boolean {
  return a.replace(/\/+$/, "") === b.replace(/\/+$/, "");
}

/**
 * Compare two secrets without leaking their contents through timing.
 *
 * Both sides are hashed first, so the comparison runs over two fixed-length
 * digests and its duration reveals neither the secret's length nor how many
 * leading characters a guess got right.
 */
async function secretsMatch(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [left, right] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b)),
  ]);
  const x = new Uint8Array(left);
  const y = new Uint8Array(right);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i]! ^ y[i]!;
  return diff === 0;
}

/**
 * A {@link VerifyToken} that accepts exactly one shared secret.
 *
 * Deliberately minimal: there is no identity to report, so every accepted
 * request looks the same to the credential resolver. `expiresAt` is required
 * by the SDK's bearer layer and is set a short way ahead of now — the value
 * describes this one request's authorization, not a token lifetime, because a
 * shared secret has none.
 */
export function createStaticTokenVerifier(
  staticToken: string,
  hooks: Pick<JwtVerifierHooks, "now"> = {},
): VerifyToken {
  const now = hooks.now ?? (() => Date.now());
  return async (_request, token) => {
    if (!token) return undefined;
    if (!(await secretsMatch(token, staticToken))) return undefined;
    return {
      token,
      clientId: "static-token",
      scopes: [],
      expiresAt: Math.floor(now() / 1000) + 300,
    };
  };
}

// ---------------------------------------------------------------------------
// JWT verification
// ---------------------------------------------------------------------------

/**
 * Asymmetric algorithms only. A JWKS holds public keys, so accepting an HMAC
 * `alg` would let anyone who can read the JWKS sign their own tokens with a
 * published key as the shared secret — the classic algorithm-confusion
 * attack. `none` is rejected for the same reason.
 */
const JWS_ALGORITHMS: Record<string, { algorithm: EcKeyImportParams | RsaHashedImportParams; kty: string }> = {
  RS256: { algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, kty: "RSA" },
  RS384: { algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, kty: "RSA" },
  RS512: { algorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, kty: "RSA" },
  PS256: { algorithm: { name: "RSA-PSS", hash: "SHA-256" }, kty: "RSA" },
  PS384: { algorithm: { name: "RSA-PSS", hash: "SHA-384" }, kty: "RSA" },
  PS512: { algorithm: { name: "RSA-PSS", hash: "SHA-512" }, kty: "RSA" },
  ES256: { algorithm: { name: "ECDSA", namedCurve: "P-256" }, kty: "EC" },
  ES384: { algorithm: { name: "ECDSA", namedCurve: "P-384" }, kty: "EC" },
  ES512: { algorithm: { name: "ECDSA", namedCurve: "P-521" }, kty: "EC" },
};

/** Verification parameters differ from import parameters for PSS and ECDSA. */
function verifyParams(alg: string): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  if (alg.startsWith("PS")) return { name: "RSA-PSS", saltLength: Number(alg.slice(2)) / 8 };
  if (alg.startsWith("ES")) return { name: "ECDSA", hash: `SHA-${alg === "ES512" ? 512 : alg.slice(2)}` };
  return { name: "RSASSA-PKCS1-v1_5" };
}

/** Web-standard only, so the verifier also runs on non-Node hosts. */
function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "="));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function decodeJson(segment: string, what: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(base64UrlDecode(segment)));
  } catch {
    throw invalidToken(`Token ${what} is not valid base64url JSON.`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw invalidToken(`Token ${what} is not a JSON object.`);
  }
  return parsed as Record<string, unknown>;
}

interface Jwk extends JsonWebKey {
  kid?: string;
  use?: string;
}

/** Injectable seams so the verifier can be tested without a network. */
export interface JwtVerifierHooks {
  fetchFn?: typeof fetch;
  now?: () => number;
  /** Seconds of tolerated clock skew on `exp` and `nbf`. */
  clockSkewSec?: number;
  /** How long a fetched JWKS or discovery document is reused. */
  cacheTtlMs?: number;
  /** Minimum spacing between refetches triggered by an unknown key id. */
  refreshCooldownMs?: number;
}

/**
 * Fetch and cache an issuer's signing keys.
 */
class JwksCache {
  private keys: Jwk[] = [];
  private fetchedAt = 0;
  private inflight: Promise<Jwk[]> | null = null;
  private discovered: string | undefined;

  constructor(
    private readonly oauth: OAuthConfig,
    private readonly fetchFn: typeof fetch,
    private readonly now: () => number,
    private readonly ttlMs: number,
    private readonly cooldownMs: number,
  ) {}

  async get(kid: string | undefined, alg: string): Promise<Jwk[]> {
    const age = this.now() - this.fetchedAt;
    const known = selectKeys(this.keys, kid, alg);
    if (known.length > 0 && age < this.ttlMs) return known;

    // Either the cache expired or this `kid` is unknown to it. Refetching
    // picks up a key rotation promptly — but an attacker sending random
    // `kid`s must not turn this server into a load generator against the
    // authorization server, so unknown-key refetches are spaced out.
    if (this.keys.length > 0 && age < this.cooldownMs) return known;

    return selectKeys(await this.load(), kid, alg);
  }

  private load(): Promise<Jwk[]> {
    this.inflight ??= this.fetchKeys()
      .then((keys) => {
        this.keys = keys;
        this.fetchedAt = this.now();
        return keys;
      })
      .finally(() => {
        this.inflight = null;
      });
    return this.inflight;
  }

  private async fetchKeys(): Promise<Jwk[]> {
    const uri = this.oauth.jwksUri ?? (await this.discover());
    const body = await this.fetchJson(uri, "JWKS");
    const keys = (body as { keys?: unknown }).keys;
    if (!Array.isArray(keys)) {
      throw invalidToken(`The JWKS at ${uri} has no 'keys' array.`);
    }
    return keys.filter((k): k is Jwk => !!k && typeof k === "object");
  }

  /** RFC 8414 first, OpenID Connect Discovery second — IdPs publish one or the other. */
  private async discover(): Promise<string> {
    if (this.discovered) return this.discovered;
    const metadata = await fetchIssuerMetadata(this.oauth.issuer, this.fetchFn);
    const uri = (metadata as { jwks_uri?: unknown }).jwks_uri;
    if (typeof uri !== "string" || !uri) {
      throw invalidToken(
        `The metadata of ${this.oauth.issuer} advertises no jwks_uri. Set MCP_OAUTH_JWKS_URI.`,
      );
    }
    this.discovered = uri;
    return uri;
  }

  private async fetchJson(uri: string, what: string): Promise<unknown> {
    let res: Response;
    try {
      res = await this.fetchFn(uri, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(10_000),
      });
    } catch (err) {
      throw invalidToken(
        `${what} at ${uri} could not be fetched: ${err instanceof Error ? err.message : "unknown error"}.`,
      );
    }
    if (!res.ok) throw invalidToken(`${what} at ${uri} returned HTTP ${res.status}.`);
    try {
      return await res.json();
    } catch {
      throw invalidToken(`${what} at ${uri} is not valid JSON.`);
    }
  }
}

/**
 * Fetch an issuer's Authorization Server metadata, RFC 8414 route first and
 * OpenID Connect Discovery second. Exported because the protected-resource
 * metadata routes need the same document.
 */
export async function fetchIssuerMetadata(
  issuer: string,
  fetchFn: typeof fetch = fetch,
): Promise<Record<string, unknown>> {
  const base = issuer.replace(/\/+$/, "");
  const candidates = [
    `${base}/.well-known/oauth-authorization-server`,
    `${base}/.well-known/openid-configuration`,
  ];
  const failures: string[] = [];
  for (const uri of candidates) {
    try {
      const res = await fetchFn(uri, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) {
        failures.push(`${uri} → HTTP ${res.status}`);
        continue;
      }
      const body = (await res.json()) as unknown;
      if (body && typeof body === "object" && !Array.isArray(body)) {
        return body as Record<string, unknown>;
      }
      failures.push(`${uri} → not a JSON object`);
    } catch (err) {
      failures.push(`${uri} → ${err instanceof Error ? err.message : "unknown error"}`);
    }
  }
  throw new Error(`No usable metadata found for issuer ${issuer} (${failures.join("; ")}).`);
}

function selectKeys(keys: Jwk[], kid: string | undefined, alg: string): Jwk[] {
  const spec = JWS_ALGORITHMS[alg];
  const usable = keys.filter(
    (k) =>
      k.kty === spec?.kty &&
      (k.use === undefined || k.use === "sig") &&
      (k.alg === undefined || k.alg === alg),
  );
  if (kid === undefined) return usable;
  const matching = usable.filter((k) => k.kid === kid);
  // A JWKS with a single unnamed key is common; then the kid cannot narrow it.
  return matching.length > 0 ? matching : usable.filter((k) => k.kid === undefined);
}

function asStringArray(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  return [];
}

function scopesOf(payload: Record<string, unknown>): string[] {
  if (typeof payload.scope === "string") return payload.scope.split(/\s+/).filter(Boolean);
  return asStringArray(payload.scp);
}

/**
 * A {@link VerifyToken} that validates JWT access tokens against the
 * issuer's JWKS. Checks signature, `iss`, `aud`, `exp` and `nbf`; scope
 * enforcement is left to the SDK's bearer-auth layer, which knows the
 * configured `requiredScopes`.
 */
export function createJwtVerifier(oauth: OAuthConfig, hooks: JwtVerifierHooks = {}): VerifyToken {
  const fetchFn = hooks.fetchFn ?? fetch;
  const now = hooks.now ?? (() => Date.now());
  const skew = hooks.clockSkewSec ?? 60;
  const jwks = new JwksCache(
    oauth,
    fetchFn,
    now,
    hooks.cacheTtlMs ?? 300_000,
    hooks.refreshCooldownMs ?? 30_000,
  );

  return async (_request, token) => {
    if (!token) return undefined;

    const parts = token.split(".");
    if (parts.length !== 3) {
      throw invalidToken("Bearer token is not a JWT (expected three dot-separated segments).");
    }
    const [rawHeader, rawPayload, rawSignature] = parts as [string, string, string];

    const header = decodeJson(rawHeader, "header");
    const alg = typeof header.alg === "string" ? header.alg : "";
    const spec = JWS_ALGORITHMS[alg];
    if (!spec) {
      throw invalidToken(
        `Token algorithm '${alg || "(none)"}' is not accepted. ` +
          `Supported: ${Object.keys(JWS_ALGORITHMS).join(", ")}.`,
      );
    }

    const payload = decodeJson(rawPayload, "payload");
    let signature: Uint8Array<ArrayBuffer>;
    try {
      signature = base64UrlDecode(rawSignature);
    } catch {
      throw invalidToken("Token signature is not valid base64url.");
    }
    const signed = new TextEncoder().encode(`${rawHeader}.${rawPayload}`);

    const kid = typeof header.kid === "string" ? header.kid : undefined;
    const candidates = await jwks.get(kid, alg);
    if (candidates.length === 0) {
      throw invalidToken(
        `No ${alg} signing key${kid ? ` with kid '${kid}'` : ""} in the issuer's JWKS.`,
      );
    }

    let verified = false;
    for (const jwk of candidates) {
      let key: CryptoKey;
      try {
        key = await crypto.subtle.importKey("jwk", jwk, spec.algorithm, false, ["verify"]);
      } catch {
        continue; // a malformed or mismatched key in the set is not fatal
      }
      if (await crypto.subtle.verify(verifyParams(alg), key, signature, signed)) {
        verified = true;
        break;
      }
    }
    if (!verified) throw invalidToken("Token signature does not verify against the issuer's JWKS.");

    if (typeof payload.iss !== "string" || !sameIssuer(payload.iss, oauth.issuer)) {
      throw invalidToken(`Token issuer '${String(payload.iss)}' is not ${oauth.issuer}.`);
    }
    const audiences = asStringArray(payload.aud);
    if (!audiences.includes(oauth.audience)) {
      // Naming both sides turns the most common misconfiguration — an
      // authorization server that mints a different `aud` than the resource
      // identifier configured here — into a one-line fix instead of a guess.
      // An audience is a public identifier, so echoing it leaks nothing.
      throw invalidToken(
        `Token audience mismatch: expected '${oauth.audience}', token carries ` +
          `${audiences.length ? audiences.map((a) => `'${a}'`).join(", ") : "no 'aud' claim"}. ` +
          `Set MCP_OAUTH_AUDIENCE to the value your authorization server issues, ` +
          `or configure that server to use the resource identifier.`,
      );
    }

    const nowSec = now() / 1000;
    const exp = typeof payload.exp === "number" ? payload.exp : undefined;
    if (exp === undefined) throw invalidToken("Token has no 'exp' claim.");
    if (exp + skew < nowSec) throw invalidToken("Token has expired.");
    if (typeof payload.nbf === "number" && payload.nbf - skew > nowSec) {
      throw invalidToken("Token is not valid yet.");
    }

    const clientId =
      [payload.client_id, payload.azp, payload.sub].find((v) => typeof v === "string" && v) ?? "";
    let resource: URL | undefined;
    try {
      resource = new URL(oauth.audience);
    } catch {
      resource = undefined; // a non-URL audience is legal, just not an RFC 8707 resource
    }

    return {
      token,
      clientId: clientId as string,
      scopes: scopesOf(payload),
      expiresAt: exp,
      resource,
      extra: { sub: payload.sub, iss: payload.iss },
    };
  };
}

/**
 * Minimal RFC 8414 metadata for the Authorization Server, as the SDK's
 * metadata routes need it. Fetched from the issuer and cached; the endpoints
 * an IdP publishes are its own business, so nothing here is invented.
 */
export function createIssuerMetadataLoader(
  oauth: OAuthConfig,
  hooks: JwtVerifierHooks = {},
): () => Promise<OAuthMetadata> {
  const fetchFn = hooks.fetchFn ?? fetch;
  let cached: OAuthMetadata | null = null;
  let inflight: Promise<OAuthMetadata> | null = null;

  async function load(): Promise<OAuthMetadata> {
    const doc = await fetchIssuerMetadata(oauth.issuer, fetchFn);
    const issuer = typeof doc.issuer === "string" ? doc.issuer : oauth.issuer;
    const authorization = doc.authorization_endpoint;
    const tokenEndpoint = doc.token_endpoint;
    if (typeof authorization !== "string" || typeof tokenEndpoint !== "string") {
      throw new Error(
        `The metadata of ${oauth.issuer} lacks authorization_endpoint or token_endpoint.`,
      );
    }
    const responseTypes = asStringArray(doc.response_types_supported);
    const metadata = {
      ...doc,
      issuer,
      authorization_endpoint: authorization,
      token_endpoint: tokenEndpoint,
      response_types_supported: responseTypes.length > 0 ? responseTypes : ["code"],
    } as OAuthMetadata;
    cached = metadata;
    return metadata;
  }

  return () => {
    if (cached) return Promise.resolve(cached);
    inflight ??= load().finally(() => {
      inflight = null;
    });
    return inflight;
  };
}
