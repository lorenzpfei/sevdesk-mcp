# Security

## Threat model in one paragraph

This server sits between an LLM client and your sevDesk account. The two assets
that matter are your **API token** (sevDesk tokens have no scopes — a token can
do everything your login can) and your **books** (an unwanted write is worse
than a failed read). The design treats the LLM as a fallible operator: every
guard lives in this server, not in the model's goodwill.

Run locally over stdio, the server is a child process of your MCP client and
reachable by nobody else. Deployed remotely over Streamable HTTP it gains a
network boundary, and with it a third asset: **who may talk to the endpoint at
all**. The guarantees below hold for both shapes; the remote-only ones say
so.

## Guarantees

- **The token stays in one place.** It is read from `SEVDESK_API_TOKEN`, sent
  only as the `Authorization` header to `SEVDESK_BASE_URL` (default
  `https://my.sevdesk.de/api/v1`), and appears in no log line, error message or
  tool output. Error messages carry the HTTP status, method, path and response
  body — never request headers.
- **Read-only by default is enforced twice.** With `SEVDESK_READ_ONLY=true`,
  write tools are hidden from the tool list *and* every mutating request is
  refused inside the HTTP client — a hallucinated tool call cannot bypass it.
- **Writes are guarded even when enabled.** `sevdesk_create_voucher` defaults
  to draft status (nothing is booked silently), `sevdesk_set_tax_rule` refuses
  enshrined vouchers and wrong-side rules and verifies its own result, and
  `SEVDESK_DRY_RUN=true` (or a per-call `dryRun`) previews any payload without
  sending it.
- **No filesystem access unless you grant it.** The receipt file tools are
  disabled until `SEVDESK_RECEIPT_DIRS` names an explicit directory allowlist;
  paths outside it are refused.
- **Minimal supply chain.** One runtime dependency
  (`@modelcontextprotocol/server`, the official MCP SDK), a committed lockfile,
  `npm ci` in CI, and GitHub Actions pinned to commit SHAs. No postinstall
  scripts, no telemetry, no network calls except to the sevDesk API — and, in
  OAuth mode, to your own authorization server's metadata and JWKS endpoints.
- **A remote deployment cannot be anonymous by accident.** `MCP_AUTH_MODE` has
  no default in a production deployment: unset, the endpoint refuses every
  request rather than publish your books. `MCP_AUTH_MODE=none` stays available for
  local development and has to be chosen deliberately.
- **`token` mode trades identity for immediacy, not for safety.** The shared
  secret must be at least 32 characters and is compared in constant time over
  hashed values, so neither its length nor a partial guess leaks through
  timing. What it cannot give you is per-user identity, expiry, or revocation
  without rotating the secret — so treat it as a lock on a door, not as an
  audit trail, and prefer `oauth` when more than one person holds the key.
- **Remote tokens are verified, not trusted.** In `oauth` mode a bearer token
  must be a JWT that verifies against the issuer's JWKS, with a matching
  `iss`, an `aud` naming this server, and an unexpired `exp` (plus configured
  scopes). Only asymmetric algorithms are accepted — an `HS*` or `none` `alg`
  is refused, so a published public key can never double as a shared secret.
  Verification is provider-neutral: this server is a Resource Server and
  issues no tokens of its own.
- **The MCP token is never the sevDesk token.** They are separate credentials
  with separate lifetimes. Authenticating grants a request to this server;
  which sevDesk account it reaches is decided server-side by the credential
  resolver. The sevDesk token never leaves the server, and appears in no
  challenge, metadata document, health response or log line.
- **Remote requests are isolated.** Each HTTP request builds its own tool
  context, sevDesk client and VAT-profile resolver, so two concurrent requests
  cannot share a token, a connection or a cached profile.
- **Origin and Host are validated** per the MCP specification, against the
  deployment's own public URL by default, so a browser on another site cannot
  drive the endpoint through a visitor's credentials.

## What this server cannot protect you from

- A compromised machine or MCP client config — the token lives in your client
  configuration; protect that file like a password.
- Whatever your authorization server lets through. In OAuth mode this server
  verifies tokens; it does not decide who may hold one. Anyone your IdP issues
  a token for reaches every tool the deployment's `SEVDESK_READ_ONLY` and
  `SEVDESK_DRY_RUN` settings allow. Scope access at the IdP, and keep
  `SEVDESK_READ_ONLY=true` on a remote deployment unless you need writes.
- Your hosting provider. A remote deployment trusts the platform that holds
  the environment variable and terminates TLS.
- Prompt injection via your own bookkeeping data: supplier names and voucher
  descriptions flow into tool output that the LLM reads. Keep write mode off
  unless you are actively using it.

## Reporting a vulnerability

Open a [GitHub security advisory](https://github.com/joosthel/sevdesk-mcp/security/advisories/new)
or an issue (for non-sensitive reports). Please include the tool name, the
request that triggers the problem, and what you expected to happen.
