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

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const LOCAL_DEV_ORIGINS = new Set([
  "http://localhost:8787",
  "http://127.0.0.1:8787",
]);

function decodeBase64Secret(name: string, value: string, expectedBytes: number): void {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = (4 - (normalized.length % 4)) % 4;
  const paddedValue = normalized + "=".repeat(paddingLength);

  let decoded: string;
  try {
    decoded = atob(paddedValue);
  } catch {
    throw new ConfigError(`${name} must be valid base64 or base64url`);
  }

  if (decoded.length !== expectedBytes) {
    throw new ConfigError(`${name} must decode to exactly ${expectedBytes} bytes`);
  }
}

function getTrimmedValue(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function getRequiredSecret(name: keyof Env, value: string | undefined): string {
  const trimmedValue = getTrimmedValue(value);
  if (!trimmedValue) {
    throw new ConfigError(`${name} is required`);
  }
  decodeBase64Secret(name, trimmedValue, 32);
  return trimmedValue;
}

function toRequestOrigin(requestUrl?: string | URL): string | undefined {
  if (!requestUrl) return undefined;
  return new URL(requestUrl).origin;
}

function normalizeIssuer(rawIssuer: string | undefined, requestOrigin: string | undefined): string {
  const fallbackIssuer = requestOrigin ?? "http://localhost:8787";
  const issuerValue = rawIssuer ?? fallbackIssuer;

  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuerValue);
  } catch {
    throw new ConfigError(`OAUTH_ISSUER must be a valid absolute URL; received "${issuerValue}"`);
  }

  if (issuerUrl.pathname !== "/" || issuerUrl.search || issuerUrl.hash) {
    throw new ConfigError(`OAUTH_ISSUER must contain origin only and must not include /mcp or any other path; received "${issuerValue}"`);
  }

  const normalizedIssuer = issuerUrl.origin;
  const isLocalIssuer = LOCAL_DEV_ORIGINS.has(normalizedIssuer);
  if (!isLocalIssuer && issuerUrl.protocol !== "https:") {
    throw new ConfigError(`OAUTH_ISSUER must use https in production; received "${issuerValue}"`);
  }

  return normalizedIssuer;
}

function normalizeMcpResource(rawResource: string | undefined, issuer: string): string {
  const resourceValue = rawResource ?? `${issuer}/mcp`;

  let resourceUrl: URL;
  try {
    resourceUrl = new URL(resourceValue);
  } catch {
    throw new ConfigError(`MCP_RESOURCE must be an absolute URL ending with /mcp; received "${resourceValue}"`);
  }

  if (resourceUrl.search || resourceUrl.hash) {
    throw new ConfigError(`MCP_RESOURCE must not include query or hash; received "${resourceValue}"`);
  }

  const expectedResource = `${issuer}/mcp`;
  if (resourceUrl.toString() !== expectedResource) {
    throw new ConfigError(`MCP_RESOURCE must equal "${expectedResource}"; received "${resourceValue}"`);
  }

  return resourceUrl.toString();
}

function normalizeMcpAudience(rawAudience: string | undefined, mcpResource: string): string {
  const audience = rawAudience ?? mcpResource;
  if (audience !== mcpResource) {
    throw new ConfigError(`MCP_AUDIENCE must equal MCP_RESOURCE; received "${audience}"`);
  }
  return audience;
}

export function loadConfig(env: Env, requestUrl?: string | URL): Config {
  const requestOrigin = toRequestOrigin(requestUrl);
  const encKeyB64 = getRequiredSecret("NTFY_CONFIG_ENC_KEY_B64", env.NTFY_CONFIG_ENC_KEY_B64);
  const jwtSigningKeyB64 = getRequiredSecret("OAUTH_JWT_SIGNING_KEY_B64", env.OAUTH_JWT_SIGNING_KEY_B64);
  const csrfSigningKeyB64 = getRequiredSecret("CSRF_SIGNING_KEY_B64", env.CSRF_SIGNING_KEY_B64);
  const issuer = normalizeIssuer(getTrimmedValue(env.OAUTH_ISSUER), requestOrigin);
  const mcpResource = normalizeMcpResource(getTrimmedValue(env.MCP_RESOURCE), issuer);
  const mcpAudience = normalizeMcpAudience(getTrimmedValue(env.MCP_AUDIENCE), mcpResource);

  return {
    encKeyB64,
    jwtSigningKeyB64,
    csrfSigningKeyB64,
    issuer,
    mcpResource,
    mcpAudience,
    authCodeTtl: parseInt(env.AUTH_CODE_TTL_SECONDS || "300", 10),
    accessTokenTtl: parseInt(env.ACCESS_TOKEN_TTL_SECONDS || "3600", 10),
    authorizeRateLimit: parseInt(env.AUTHORIZE_RATE_LIMIT_PER_MINUTE || "20", 10),
    tokenRateLimit: parseInt(env.TOKEN_RATE_LIMIT_PER_MINUTE || "20", 10),
    mcpRateLimit: parseInt(env.MCP_RATE_LIMIT_PER_MINUTE || "60", 10),
    redirectHttpsHosts: (env.OAUTH_REDIRECT_HTTPS_HOSTS || "chatgpt.com,*.chatgpt.com,chat.openai.com,*.chat.openai.com").split(",").map(h => h.trim()),
  };
}
