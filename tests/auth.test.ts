import { describe, expect, it } from "vitest";

import {
  MIN_STATIC_TOKEN_LENGTH,
  createJwtVerifier,
  createStaticTokenVerifier,
  loadAuthConfig,
  type OAuthConfig,
} from "../src/auth.js";
import { createSevdeskHttpHandler } from "../src/http.js";
import {
  MCP_URL,
  TEST_ORIGIN,
  createHandler,
  fakeSevdesk,
  post,
  rpcBody,
  testConfig,
} from "./helpers/http.js";
import { createIssuer, issuerFetch, type TestAlgorithm } from "./helpers/jwt.js";

const ISSUER = "https://idp.example.test";
const AUDIENCE = MCP_URL;

function oauthConfig(overrides: Partial<OAuthConfig> = {}): OAuthConfig {
  return {
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUri: `${ISSUER}/.well-known/jwks.json`,
    requiredScopes: [],
    ...overrides,
  };
}

const NOW = 1_800_000_000_000;
const now = () => NOW;

function claims(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: "user-1",
    client_id: "client-1",
    exp: NOW / 1000 + 3600,
    iat: NOW / 1000,
    ...extra,
  };
}

describe("loadAuthConfig", () => {
  it("defaults to no auth outside production", () => {
    expect(loadAuthConfig({} as NodeJS.ProcessEnv)).toEqual({ mode: "none" });
  });

  it("refuses to guess in a production deployment", () => {
    expect(() => loadAuthConfig({ VERCEL_ENV: "production" } as NodeJS.ProcessEnv)).toThrow(
      /MCP_AUTH_MODE is not set/,
    );
    expect(() => loadAuthConfig({ NODE_ENV: "production" } as NodeJS.ProcessEnv)).toThrow(
      /MCP_AUTH_MODE is not set/,
    );
  });

  it("accepts an explicit anonymous production deployment", () => {
    expect(
      loadAuthConfig({ VERCEL_ENV: "production", MCP_AUTH_MODE: "none" } as NodeJS.ProcessEnv),
    ).toEqual({ mode: "none" });
  });

  it("rejects an unknown mode instead of falling back", () => {
    expect(() => loadAuthConfig({ MCP_AUTH_MODE: "basic" } as NodeJS.ProcessEnv)).toThrow(
      /not valid/,
    );
  });

  it("requires an issuer and audience for oauth", () => {
    expect(() => loadAuthConfig({ MCP_AUTH_MODE: "oauth" } as NodeJS.ProcessEnv)).toThrow(
      /MCP_OAUTH_ISSUER/,
    );
  });

  it("reads the oauth settings, trimming the issuer's trailing slash", () => {
    expect(
      loadAuthConfig({
        MCP_AUTH_MODE: "oauth",
        MCP_OAUTH_ISSUER: `${ISSUER}/`,
        MCP_OAUTH_AUDIENCE: AUDIENCE,
        MCP_OAUTH_SCOPES: "mcp:read, mcp:write",
      } as NodeJS.ProcessEnv),
    ).toEqual({
      mode: "oauth",
      oauth: { issuer: ISSUER, audience: AUDIENCE, jwksUri: undefined, requiredScopes: ["mcp:read", "mcp:write"] },
    });
  });
});

describe("a production deployment that forgot to choose", () => {
  it("refuses to build a handler and says what to set", () => {
    const env = { ...process.env };
    try {
      process.env.VERCEL_ENV = "production";
      process.env.SEVDESK_API_TOKEN = "unused";
      delete process.env.MCP_AUTH_MODE;
      // No `auth` option: the handler reads the environment, as on Vercel.
      expect(() => createSevdeskHttpHandler({ config: testConfig(), onerror: () => {} })).toThrow(
        /MCP_AUTH_MODE is not set[\s\S]*MCP_AUTH_MODE=oauth[\s\S]*MCP_AUTH_MODE=none/,
      );
    } finally {
      process.env = env;
    }
  });
});

const SECRET = "a".repeat(16) + "b".repeat(16) + "c";

describe("token mode", () => {
  const listTools = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };

  it("requires a secret", () => {
    expect(() =>
      loadAuthConfig({ MCP_AUTH_MODE: "token" } as NodeJS.ProcessEnv),
    ).toThrow(/MCP_STATIC_TOKEN/);
  });

  it("refuses a secret short enough to brute-force", () => {
    expect(() =>
      loadAuthConfig({ MCP_AUTH_MODE: "token", MCP_STATIC_TOKEN: "hunter2" } as NodeJS.ProcessEnv),
    ).toThrow(new RegExp(`too short.*${MIN_STATIC_TOKEN_LENGTH}`, "s"));
  });

  it("accepts a long secret", () => {
    expect(
      loadAuthConfig({ MCP_AUTH_MODE: "token", MCP_STATIC_TOKEN: SECRET } as NodeJS.ProcessEnv),
    ).toEqual({ mode: "token", staticToken: SECRET });
  });

  it("accepts the secret and refuses everything else", async () => {
    const verify = createStaticTokenVerifier(SECRET, { now });
    expect(await verify(new Request(MCP_URL), SECRET)).toMatchObject({
      clientId: "static-token",
      expiresAt: NOW / 1000 + 300,
    });
    for (const wrong of [undefined, "", "wrong", SECRET.slice(0, -1), SECRET + "x", SECRET.toUpperCase()]) {
      expect(await verify(new Request(MCP_URL), wrong), String(wrong)).toBeUndefined();
    }
  });

  function tokenHandler() {
    return createSevdeskHttpHandler({
      config: testConfig(),
      auth: { mode: "token", staticToken: SECRET },
      publicUrl: new URL(MCP_URL),
      onerror: () => {},
      clientHooks: { fetchFn: fakeSevdesk().fetchFn },
    });
  }

  it("challenges a request with no secret", async () => {
    const res = await tokenHandler().fetch(post(listTools));
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toMatch(/^Bearer/);
  });

  it("refuses a wrong secret", async () => {
    const res = await tokenHandler().fetch(
      post(listTools, { headers: { Authorization: "Bearer nope" } }),
    );
    expect(res.status).toBe(401);
  });

  it("serves the right secret", async () => {
    const res = await tokenHandler().fetch(
      post(listTools, { headers: { Authorization: `Bearer ${SECRET}` } }),
    );
    expect(res.status).toBe(200);
    const body = (await rpcBody(res)) as { result?: { tools?: unknown[] } };
    expect(body.result?.tools).toHaveLength(24);
  });

  it("never echoes the secret back", async () => {
    const handler = tokenHandler();
    for (const request of [post(listTools), new Request(`${TEST_ORIGIN}/health`)]) {
      const res = await handler.fetch(request);
      const seen = `${[...res.headers].join(" ")} ${await res.text()}`;
      expect(seen).not.toContain(SECRET);
    }
  });

  it("advertises no OAuth metadata, since there is no authorization server", async () => {
    const res = await tokenHandler().fetch(
      new Request(`${TEST_ORIGIN}/.well-known/oauth-protected-resource/mcp`),
    );
    expect(res.status).toBe(404);
  });
});

describe("JWT verification", () => {
  for (const alg of ["RS256", "PS256", "ES256"] as TestAlgorithm[]) {
    it(`accepts a valid ${alg} token`, async () => {
      const issuer = await createIssuer(alg);
      const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
      const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
      const info = await verify(new Request(MCP_URL), await issuer.sign(claims()));
      expect(info).toMatchObject({ clientId: "client-1", expiresAt: NOW / 1000 + 3600 });
    });
  }

  it("refuses a missing token without calling the issuer", async () => {
    const issuer = await createIssuer();
    const { fetchFn, requests } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    expect(await verify(new Request(MCP_URL), undefined)).toBeUndefined();
    expect(requests).toEqual([]);
  });

  it("refuses a token that is not a JWT", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    await expect(verify(new Request(MCP_URL), "not-a-jwt")).rejects.toThrow(/not a JWT/);
  });

  it("refuses a tampered payload", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    const [head, , sig] = (await issuer.sign(claims())).split(".");
    const forged = btoa(JSON.stringify(claims({ sub: "attacker" })))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    await expect(verify(new Request(MCP_URL), `${head}.${forged}.${sig}`)).rejects.toThrow(
      /signature does not verify/,
    );
  });

  it("refuses an expired token", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    const token = await issuer.sign(claims({ exp: NOW / 1000 - 3600 }));
    await expect(verify(new Request(MCP_URL), token)).rejects.toThrow(/expired/);
  });

  it("refuses a token issued for another audience", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    const token = await issuer.sign(claims({ aud: "https://someone-else.example.test/mcp" }));
    await expect(verify(new Request(MCP_URL), token)).rejects.toThrow(/audience/);
  });

  it("refuses a token from another issuer even when correctly signed", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    const token = await issuer.sign(claims({ iss: "https://evil.example.test" }));
    await expect(verify(new Request(MCP_URL), token)).rejects.toThrow(/issuer/);
  });

  it("refuses a token that is not valid yet", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    const token = await issuer.sign(claims({ nbf: NOW / 1000 + 3600 }));
    await expect(verify(new Request(MCP_URL), token)).rejects.toThrow(/not valid yet/);
  });

  it("refuses alg=none", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    const unsigned = `${btoa(JSON.stringify({ alg: "none", typ: "JWT" }))}.${btoa(
      JSON.stringify(claims()),
    )}.`;
    await expect(verify(new Request(MCP_URL), unsigned)).rejects.toThrow(/not accepted/);
  });

  it("refuses an HMAC alg, closing the JWKS-as-shared-secret confusion", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    const head = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    const body = btoa(JSON.stringify(claims()))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
    await expect(verify(new Request(MCP_URL), `${head}.${body}.AAAA`)).rejects.toThrow(
      /not accepted/,
    );
  });

  it("refuses a token with no exp claim", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    const { exp: _exp, ...rest } = claims();
    await expect(verify(new Request(MCP_URL), await issuer.sign(rest))).rejects.toThrow(
      /no 'exp' claim/,
    );
  });

  it("discovers the JWKS from the issuer's metadata when none is configured", async () => {
    const issuer = await createIssuer();
    const { fetchFn, requests } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig({ jwksUri: undefined }), { fetchFn, now });
    await verify(new Request(MCP_URL), await issuer.sign(claims()));
    expect(requests).toContain(`${ISSUER}/.well-known/oauth-authorization-server`);
    expect(requests).toContain(`${ISSUER}/.well-known/jwks.json`);
  });

  it("caches the JWKS across tokens", async () => {
    const issuer = await createIssuer("RS256", "key-1");
    const { fetchFn, requests } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    await verify(new Request(MCP_URL), await issuer.sign(claims()));
    await verify(new Request(MCP_URL), await issuer.sign(claims()));
    expect(requests).toHaveLength(1);
  });

  it("refetches once the cooldown has passed, to pick up a key rotation", async () => {
    const issuer = await createIssuer("RS256", "key-1");
    const { fetchFn, requests } = issuerFetch(ISSUER, issuer.jwks);
    let clock = NOW;
    const verify = createJwtVerifier(oauthConfig(), {
      fetchFn,
      now: () => clock,
      refreshCooldownMs: 30_000,
    });
    await verify(new Request(MCP_URL), await issuer.sign(claims({ exp: NOW / 1000 + 86_400 })));
    expect(requests).toHaveLength(1);

    clock = NOW + 60_000;
    const unknownKid = await issuer.sign(claims({ exp: NOW / 1000 + 86_400 }), { kid: "key-2" });
    await expect(verify(new Request(MCP_URL), unknownKid)).rejects.toThrow(/kid 'key-2'/);
    expect(requests).toHaveLength(2);
  });

  it("does not refetch per unknown kid inside the cooldown", async () => {
    const issuer = await createIssuer("RS256", "key-1");
    const { fetchFn, requests } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now, refreshCooldownMs: 30_000 });
    await verify(new Request(MCP_URL), await issuer.sign(claims()));
    expect(requests).toHaveLength(1);

    // A flood of forged key ids must not become a flood of JWKS fetches.
    for (let i = 0; i < 20; i++) {
      const forged = await issuer.sign(claims(), { kid: `forged-${i}` });
      await expect(verify(new Request(MCP_URL), forged)).rejects.toThrow();
    }
    expect(requests).toHaveLength(1);
  });

  it("accepts an issuer that publishes iss with a trailing slash", async () => {
    // Auth0 and friends: the documented issuer has no trailing slash, the
    // `iss` claim does.
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    const info = await verify(new Request(MCP_URL), await issuer.sign(claims({ iss: `${ISSUER}/` })));
    expect(info?.clientId).toBe("client-1");
  });

  it("still rejects a different host that only looks similar", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    for (const iss of [`${ISSUER}.evil.test`, `${ISSUER}/tenant2`, "https://idp.example.test.evil"]) {
      await expect(verify(new Request(MCP_URL), await issuer.sign(claims({ iss })))).rejects.toThrow(
        /issuer/,
      );
    }
  });

  it("extracts scopes from both the scope string and the scp array", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const verify = createJwtVerifier(oauthConfig(), { fetchFn, now });
    const fromString = await verify(
      new Request(MCP_URL),
      await issuer.sign(claims({ scope: "mcp:read mcp:write" })),
    );
    expect(fromString?.scopes).toEqual(["mcp:read", "mcp:write"]);
    const fromArray = await verify(
      new Request(MCP_URL),
      await issuer.sign(claims({ scp: ["mcp:read"] })),
    );
    expect(fromArray?.scopes).toEqual(["mcp:read"]);
  });
});

describe("the authenticated MCP endpoint", () => {
  async function authenticatedHandler(overrides: Partial<OAuthConfig> = {}) {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const oauth = oauthConfig(overrides);
    const api = fakeSevdesk();
    const handler = createSevdeskHttpHandler({
      config: testConfig(),
      auth: { mode: "oauth", oauth },
      publicUrl: new URL(MCP_URL),
      onerror: () => {},
      hooks: { fetchFn, now },
      clientHooks: { fetchFn: api.fetchFn },
    });
    return { handler, issuer, api };
  }

  const listTools = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };

  it("challenges an unauthenticated request with WWW-Authenticate", async () => {
    const { handler } = await authenticatedHandler();
    const res = await handler.fetch(post(listTools));
    expect(res.status).toBe(401);
    const challenge = res.headers.get("www-authenticate") ?? "";
    expect(challenge).toMatch(/^Bearer/);
    expect(challenge).toContain(
      `resource_metadata="${TEST_ORIGIN}/.well-known/oauth-protected-resource/mcp"`,
    );
  });

  it("rejects an invalid, expired and wrong-audience token alike", async () => {
    const { handler, issuer } = await authenticatedHandler();
    const cases = [
      "garbage",
      await issuer.sign(claims({ exp: NOW / 1000 - 3600 })),
      await issuer.sign(claims({ aud: "https://elsewhere.example.test/mcp" })),
    ];
    for (const token of cases) {
      const res = await handler.fetch(
        post(listTools, { headers: { Authorization: `Bearer ${token}` } }),
      );
      expect(res.status, token.slice(0, 12)).toBe(401);
    }
  });

  it("serves a valid token", async () => {
    const { handler, issuer } = await authenticatedHandler();
    const res = await handler.fetch(
      post(listTools, { headers: { Authorization: `Bearer ${await issuer.sign(claims())}` } }),
    );
    expect(res.status).toBe(200);
    const body = (await rpcBody(res)) as { result?: { tools?: unknown[] } };
    expect(body.result?.tools).toHaveLength(24);
  });

  it("refuses a token that is missing a configured scope", async () => {
    const { handler, issuer } = await authenticatedHandler({ requiredScopes: ["mcp:write"] });
    const short = await issuer.sign(claims({ scope: "mcp:read" }));
    const res = await handler.fetch(
      post(listTools, { headers: { Authorization: `Bearer ${short}` } }),
    );
    expect(res.status).toBe(403);
    expect(res.headers.get("www-authenticate")).toContain("insufficient_scope");

    const full = await issuer.sign(claims({ scope: "mcp:read mcp:write" }));
    expect(
      (await handler.fetch(post(listTools, { headers: { Authorization: `Bearer ${full}` } })))
        .status,
    ).toBe(200);
  });

  it("never reaches sevDesk for a refused request", async () => {
    const { handler, api } = await authenticatedHandler();
    await handler.fetch(
      post({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "sevdesk_ping", arguments: {} },
      }),
    );
    expect(api.calls).toEqual([]);
  });

  it("keeps the sevDesk token out of challenges, metadata and health", async () => {
    const secret = "sevdesk-secret-0123456789";
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const handler = createSevdeskHttpHandler({
      config: testConfig({ apiToken: secret }),
      auth: { mode: "oauth", oauth: oauthConfig() },
      publicUrl: new URL(MCP_URL),
      onerror: () => {},
      hooks: { fetchFn, now },
    });
    const bodies = await Promise.all(
      [
        post(listTools),
        new Request(`${TEST_ORIGIN}/health`),
        new Request(`${TEST_ORIGIN}/.well-known/oauth-protected-resource/mcp`),
        new Request(`${TEST_ORIGIN}/.well-known/oauth-authorization-server`),
      ].map(async (request) => {
        const res = await handler.fetch(request);
        return `${res.status} ${[...res.headers].join(" ")} ${await res.text()}`;
      }),
    );
    for (const body of bodies) expect(body).not.toContain(secret);
  });

  it("hands the verified AuthInfo to the credential resolver", async () => {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    const seen: Array<{ sub: unknown; url: string }> = [];
    const handler = createSevdeskHttpHandler({
      config: testConfig(),
      auth: { mode: "oauth", oauth: oauthConfig() },
      publicUrl: new URL(MCP_URL),
      onerror: () => {},
      hooks: { fetchFn, now },
      clientHooks: { fetchFn: fakeSevdesk().fetchFn },
      credentials: {
        async resolve({ request, authInfo }) {
          seen.push({ sub: authInfo?.extra?.sub, url: request.url });
          return { apiToken: "per-user-token" };
        },
      },
    });
    const token = await issuer.sign(claims({ sub: "user-42" }));
    await handler.fetch(post(listTools, { headers: { Authorization: `Bearer ${token}` } }));
    expect(seen).toEqual([{ sub: "user-42", url: MCP_URL }]);
  });
});

describe("a supplied verifyToken hook", () => {
  const listTools = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };

  function hookHandler(verifyToken: Parameters<typeof createSevdeskHttpHandler>[0]["verifyToken"]) {
    return createSevdeskHttpHandler({
      config: testConfig(),
      // Deliberately the local default: passing a verifier must not be
      // silently ignored just because the mode still says `none`.
      auth: { mode: "none" },
      publicUrl: new URL(MCP_URL),
      onerror: () => {},
      verifyToken,
      clientHooks: { fetchFn: fakeSevdesk().fetchFn },
    });
  }

  it("guards the endpoint even when the mode says none", async () => {
    const handler = hookHandler(() => undefined);
    expect((await handler.fetch(post(listTools))).status).toBe(401);
  });

  it("serves a request the hook accepts", async () => {
    const handler = hookHandler((_request, token) =>
      token === "let-me-in"
        ? { token, clientId: "hook", scopes: [], expiresAt: Math.floor(Date.now() / 1000) + 600 }
        : undefined,
    );
    const res = await handler.fetch(
      post(listTools, { headers: { Authorization: "Bearer let-me-in" } }),
    );
    expect(res.status).toBe(200);
  });

  it("omits resource_metadata when no document is served there", async () => {
    const handler = hookHandler(() => undefined);
    const res = await handler.fetch(post(listTools));
    expect(res.headers.get("www-authenticate")).not.toContain("resource_metadata");
  });

  it("refuses to build an oauth handler with nothing to verify with", () => {
    expect(() =>
      createSevdeskHttpHandler({
        config: testConfig(),
        auth: { mode: "oauth" },
        publicUrl: new URL(MCP_URL),
        onerror: () => {},
      }),
    ).toThrow(/Refusing to serve unauthenticated/);
  });
});

describe("protected resource metadata", () => {
  async function metadataHandler() {
    const issuer = await createIssuer();
    const { fetchFn } = issuerFetch(ISSUER, issuer.jwks);
    return createSevdeskHttpHandler({
      config: testConfig(),
      auth: { mode: "oauth", oauth: oauthConfig({ requiredScopes: ["mcp:read"] }) },
      publicUrl: new URL(MCP_URL),
      onerror: () => {},
      hooks: { fetchFn, now },
    });
  }

  it("serves RFC 9728 metadata pointing at the authorization server", async () => {
    const handler = await metadataHandler();
    const res = await handler.fetch(
      new Request(`${TEST_ORIGIN}/.well-known/oauth-protected-resource/mcp`),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      resource: MCP_URL,
      authorization_servers: [ISSUER],
      scopes_supported: ["mcp:read"],
    });
  });

  it("passes the RFC 8414 authorization server metadata through", async () => {
    const handler = await metadataHandler();
    const res = await handler.fetch(
      new Request(`${TEST_ORIGIN}/.well-known/oauth-authorization-server`),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({
      issuer: ISSUER,
      token_endpoint: `${ISSUER}/token`,
    });
  });

  it("has no metadata to serve when auth is off", async () => {
    const handler = createHandler();
    const res = await handler.fetch(
      new Request(`${TEST_ORIGIN}/.well-known/oauth-protected-resource/mcp`),
    );
    expect(res.status).toBe(404);
  });
});
