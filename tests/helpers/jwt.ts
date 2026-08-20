/**
 * Minimal JWT issuer for the auth tests: real key pairs, real signatures, no
 * dependency. A verifier tested against hand-written fixtures would only
 * prove that the fixtures match the implementation.
 */

function base64Url(bytes: Uint8Array | string): string {
  const binary =
    typeof bytes === "string"
      ? bytes
      : Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

const ALGORITHMS = {
  RS256: {
    generate: { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSASSA-PKCS1-v1_5" },
  },
  PS256: {
    generate: { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    sign: { name: "RSA-PSS", saltLength: 32 },
  },
  ES256: {
    generate: { name: "ECDSA", namedCurve: "P-256" },
    sign: { name: "ECDSA", hash: "SHA-256" },
  },
} as const;

export type TestAlgorithm = keyof typeof ALGORITHMS;

export interface TestIssuer {
  alg: TestAlgorithm;
  kid: string;
  jwks: { keys: unknown[] };
  sign: (payload: Record<string, unknown>, header?: Record<string, unknown>) => Promise<string>;
}

export async function createIssuer(alg: TestAlgorithm = "RS256", kid = "test-key"): Promise<TestIssuer> {
  const spec = ALGORITHMS[alg];
  const pair = (await crypto.subtle.generateKey(spec.generate, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);

  return {
    alg,
    kid,
    jwks: { keys: [{ ...publicJwk, kid, alg, use: "sig" }] },
    async sign(payload, header = {}) {
      const head = base64Url(JSON.stringify({ alg, typ: "JWT", kid, ...header }));
      const body = base64Url(JSON.stringify(payload));
      const signature = await crypto.subtle.sign(
        spec.sign,
        pair.privateKey,
        new TextEncoder().encode(`${head}.${body}`),
      );
      return `${head}.${body}.${base64Url(new Uint8Array(signature))}`;
    },
  };
}

/** An `fetch` that serves an issuer's discovery document and JWKS, nothing else. */
export function issuerFetch(
  issuer: string,
  jwks: { keys: unknown[] },
  options: { jwksPath?: string; metadata?: Record<string, unknown> } = {},
): { fetchFn: typeof fetch; requests: string[] } {
  const jwksPath = options.jwksPath ?? "/.well-known/jwks.json";
  const requests: string[] = [];
  const fetchFn: typeof fetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : (input as Request).url);
    requests.push(url.toString());
    if (url.pathname === jwksPath) {
      return Response.json(jwks);
    }
    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return Response.json({
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}${jwksPath}`,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
        ...options.metadata,
      });
    }
    return new Response("not found", { status: 404 });
  };
  return { fetchFn, requests };
}
