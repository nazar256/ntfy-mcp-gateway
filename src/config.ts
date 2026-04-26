export interface Env {
  NTFY_CONFIG_ENC_KEY_B64: string;
  OAUTH_JWT_SIGNING_KEY_B64: string;
  CSRF_SIGNING_KEY_B64: string;
  OAUTH_ISSUER: string;
  MCP_RESOURCE: string;
  MCP_AUDIENCE: string;
  AUTH_CODE_TTL_SECONDS: string;
  ACCESS_TOKEN_TTL_SECONDS: string;
  AUTHORIZE_RATE_LIMIT_PER_MINUTE: string;
  TOKEN_RATE_LIMIT_PER_MINUTE: string;
  MCP_RATE_LIMIT_PER_MINUTE: string;
  OAUTH_REDIRECT_HTTPS_HOSTS: string;
}

export interface Config {
  encKeyB64: string;
  jwtSigningKeyB64: string;
  csrfSigningKeyB64: string;
  issuer: string;
  mcpResource: string;
  mcpAudience: string;
  authCodeTtl: number;
  accessTokenTtl: number;
  authorizeRateLimit: number;
  tokenRateLimit: number;
  mcpRateLimit: number;
  redirectHttpsHosts: string[];
}

export function loadConfig(env: Env): Config {
  return {
    encKeyB64: env.NTFY_CONFIG_ENC_KEY_B64,
    jwtSigningKeyB64: env.OAUTH_JWT_SIGNING_KEY_B64,
    csrfSigningKeyB64: env.CSRF_SIGNING_KEY_B64,
    issuer: env.OAUTH_ISSUER || "http://localhost:8787",
    mcpResource: env.MCP_RESOURCE || "http://localhost:8787/mcp",
    mcpAudience: env.MCP_AUDIENCE || env.MCP_RESOURCE || "http://localhost:8787/mcp",
    authCodeTtl: parseInt(env.AUTH_CODE_TTL_SECONDS || "300", 10),
    accessTokenTtl: parseInt(env.ACCESS_TOKEN_TTL_SECONDS || "3600", 10),
    authorizeRateLimit: parseInt(env.AUTHORIZE_RATE_LIMIT_PER_MINUTE || "20", 10),
    tokenRateLimit: parseInt(env.TOKEN_RATE_LIMIT_PER_MINUTE || "20", 10),
    mcpRateLimit: parseInt(env.MCP_RATE_LIMIT_PER_MINUTE || "60", 10),
    redirectHttpsHosts: (env.OAUTH_REDIRECT_HTTPS_HOSTS || "chatgpt.com,*.chatgpt.com,chat.openai.com,*.chat.openai.com").split(",").map(h => h.trim()),
  };
}
