import type { Config } from "../config.ts";

export function getAuthServerMetadata(config: Config): Record<string, unknown> {
  return {
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/authorize`,
    token_endpoint: `${config.issuer}/token`,
    registration_endpoint: `${config.issuer}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: ["notify.write"],
    resource_parameter_supported: true,
  };
}

export function getProtectedResourceMetadata(config: Config): Record<string, unknown> {
  return {
    resource: config.mcpResource,
    authorization_servers: [config.issuer],
    scopes_supported: ["notify.write"],
    bearer_methods_supported: ["header"],
    resource_name: "ntfy MCP notification server",
  };
}
