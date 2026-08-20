/**
 * Tool-context construction, shared by every transport.
 *
 * stdio builds one context per process; the HTTP transport builds one per
 * request, because a request's sevDesk credentials come from a resolver and
 * two concurrent requests may resolve to different accounts. Nothing here is
 * cached across calls: every context owns its own client, its own token and
 * its own profile resolver, so contexts cannot leak into each other.
 */

import type { AuthInfo } from "@modelcontextprotocol/server";

import { SevdeskClient, type ClientHooks } from "./client.js";
import type { Config } from "./config.js";
import { createProfileResolver } from "./lib/profile.js";
import type { ToolContext } from "./lib/tool.js";

/** What a resolver has to produce for a request to reach sevDesk. */
export interface SevdeskCredentials {
  apiToken: string;
}

export interface CredentialResolverInput {
  request: Request;
  authInfo?: AuthInfo;
}

/**
 * Where the sevDesk API token for one request comes from.
 *
 * The shipped default is single-tenant: `SEVDESK_API_TOKEN` from the
 * environment, ignoring the request entirely. A host that authenticates
 * several users against several sevDesk accounts can supply its own resolver
 * without touching the sevDesk core — the token it returns is used for that
 * request and nothing else.
 */
export interface SevdeskCredentialResolver {
  resolve(input: CredentialResolverInput): Promise<SevdeskCredentials>;
}

/** Single-tenant default: the process's own configured token. */
export function envCredentialResolver(config: Config): SevdeskCredentialResolver {
  return {
    async resolve() {
      return { apiToken: config.apiToken };
    },
  };
}

/**
 * Build a tool context. `credentials` overrides the token the config was
 * loaded with — everything else (read-only, dry-run, timeouts, rate limit,
 * receipt directories) is deployment configuration and applies unchanged.
 */
export function createToolContext(
  config: Config,
  credentials?: SevdeskCredentials,
  hooks?: ClientHooks,
): ToolContext {
  const effective: Config =
    credentials && credentials.apiToken !== config.apiToken
      ? { ...config, apiToken: credentials.apiToken }
      : config;
  const client = new SevdeskClient(effective, hooks);
  return {
    client,
    config: effective,
    getProfile: createProfileResolver(client, effective),
  };
}
