import type { Config } from "../config.ts";
import { base64ToBytes, bytesToBase64Url } from "../security/crypto.ts";

const SUPPORTED_SCOPE = "notify.write";
const SUPPORTED_GRANT_TYPES = ["authorization_code", "refresh_token"] as const;
const SUPPORTED_RESPONSE_TYPES = ["code"] as const;
const REGISTER_CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "600",
};

interface RedirectUriValidationSuccess {
  ok: true;
  normalizedUri: string;
}

interface RedirectUriValidationFailure {
  ok: false;
  hostname: string | null;
  reason: string;
}

type RedirectUriValidationResult = RedirectUriValidationSuccess | RedirectUriValidationFailure;

interface RegistrationMetadata {
  redirect_uris: string[];
  client_name?: string;
  client_uri?: string;
  logo_uri?: string;
  contacts?: string[];
  tos_uri?: string;
  policy_uri?: string;
  jwks_uri?: string;
  scope: string;
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: "none";
  application_type?: string;
}

class RegisterMetadataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegisterMetadataError";
  }
}

class RedirectUriError extends RegisterMetadataError {
  hostname: string | null;

  constructor(message: string, hostname: string | null) {
    super(message);
    this.name = "RedirectUriError";
    this.hostname = hostname;
  }
}

function registerHeaders(extraHeaders?: HeadersInit): Headers {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    ...REGISTER_CORS_HEADERS,
  });
  if (extraHeaders) {
    new Headers(extraHeaders).forEach((value, key) => headers.set(key, value));
  }
  return headers;
}

function registerJson(body: Record<string, unknown>, status: number, extraHeaders?: HeadersInit): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: registerHeaders(extraHeaders),
  });
}

function logRegisterDiagnostic(reason: string, details?: { hostname?: string | null; field?: string }): void {
  console.warn("DCR rejected registration", JSON.stringify({
    reason,
    hostname: details?.hostname ?? null,
    field: details?.field ?? null,
  }));
}

function invalidClientMetadata(description: string, details?: { hostname?: string | null; field?: string }): Response {
  logRegisterDiagnostic(description, details);
  return registerJson({ error: "invalid_client_metadata", error_description: description }, 400);
}

function invalidRedirectUri(description: string, hostname?: string | null): Response {
  logRegisterDiagnostic(description, { hostname, field: "redirect_uris" });
  return registerJson({ error: "invalid_redirect_uri", error_description: description }, 400);
}

function isJsonContentType(contentType: string | null): boolean {
  if (!contentType) return false;
  const mediaType = contentType.split(";")[0]?.trim().toLowerCase();
  return mediaType === "application/json" || mediaType.endsWith("+json");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function uniqueSorted(values: string[]): string[] {
  return Array.from(new Set(values)).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function parseScope(scope: string | undefined): string[] {
  if (scope === undefined) return [SUPPORTED_SCOPE];
  const trimmedScope = scope.trim();
  if (!trimmedScope) return [];
  const scopes = trimmedScope.split(/\s+/);
  return scopes.length > 0 ? uniqueSorted(scopes) : [];
}

function validateScope(scope: string | undefined): string {
  const scopes = parseScope(scope);
  const unsupportedScopes = scopes.filter(candidate => candidate !== SUPPORTED_SCOPE);
  if (unsupportedScopes.length > 0 || scopes.length === 0) {
    throw new RegisterMetadataError("Only scope notify.write is supported");
  }
  return SUPPORTED_SCOPE;
}

function readOptionalString(body: Record<string, unknown>, field: string): string | undefined {
  const value = body[field];
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw new RegisterMetadataError(`${field} must be a string`);
  }
  return value;
}

function readOptionalStringArray(body: Record<string, unknown>, field: string): string[] | undefined {
  const value = body[field];
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new RegisterMetadataError(`${field} must be an array of strings`);
  }
  return value;
}

function validateGrantTypes(rawGrantTypes: string[] | undefined): string[] {
  const grantTypes = rawGrantTypes ? uniqueSorted(rawGrantTypes) : [...SUPPORTED_GRANT_TYPES];
  if (
    grantTypes.length === 0 ||
    !grantTypes.includes("authorization_code") ||
    grantTypes.some((grantType) => !SUPPORTED_GRANT_TYPES.includes(grantType as (typeof SUPPORTED_GRANT_TYPES)[number]))
  ) {
    throw new RegisterMetadataError("Supported grant_types are [authorization_code, refresh_token], and authorization_code is required");
  }
  return [...SUPPORTED_GRANT_TYPES];
}

function validateResponseTypes(rawResponseTypes: string[] | undefined): string[] {
  const responseTypes = rawResponseTypes ? uniqueSorted(rawResponseTypes) : [...SUPPORTED_RESPONSE_TYPES];
  if (
    responseTypes.length !== SUPPORTED_RESPONSE_TYPES.length ||
    responseTypes.some((responseType, index) => responseType !== SUPPORTED_RESPONSE_TYPES[index])
  ) {
    throw new RegisterMetadataError("Only response_types [code] are supported");
  }
  return [...SUPPORTED_RESPONSE_TYPES];
}

function matchAllowedHttpsHost(host: string, httpsHosts: string[]): boolean {
  return httpsHosts.some((pattern) => {
    const normalizedPattern = pattern.toLowerCase();
    if (normalizedPattern.startsWith("*.")) {
      const suffix = normalizedPattern.slice(2);
      return host.endsWith(`.${suffix}`);
    }
    return host === normalizedPattern;
  });
}

export function validateRedirectUri(uri: string, httpsHosts: string[]): RedirectUriValidationResult {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return { ok: false, hostname: null, reason: "Redirect URI must be a valid absolute URL" };
  }

  const hostname = parsed.hostname.toLowerCase();

  if (parsed.username || parsed.password) {
    return { ok: false, hostname, reason: "Redirect URI must not include username or password" };
  }

  if (parsed.hash) {
    return { ok: false, hostname, reason: "Redirect URI must not include a fragment" };
  }

  if (hostname === "localhost" || hostname === "127.0.0.1") {
    if (parsed.protocol !== "http:") {
      return { ok: false, hostname, reason: "Local development redirect URIs must use http" };
    }
    if (!parsed.port) {
      return { ok: false, hostname, reason: "Local development redirect URIs must include an explicit port" };
    }
    return { ok: true, normalizedUri: parsed.toString() };
  }

  if (parsed.protocol !== "https:") {
    return { ok: false, hostname, reason: "Redirect URI must use https" };
  }

  if (!matchAllowedHttpsHost(hostname, httpsHosts)) {
    return { ok: false, hostname, reason: "Redirect URI host is not allowlisted" };
  }

  return { ok: true, normalizedUri: parsed.toString() };
}

export function isAllowedRedirectUri(uri: string, httpsHosts: string[]): boolean {
  return validateRedirectUri(uri, httpsHosts).ok;
}

function normalizeRedirectUris(redirectUris: string[], httpsHosts: string[]): string[] {
  const normalizedUris: string[] = [];

  for (const uri of redirectUris) {
    const result = validateRedirectUri(uri, httpsHosts);
    if (!result.ok) {
      throw new RedirectUriError(result.reason, result.hostname);
    }
    normalizedUris.push(result.normalizedUri);
  }

  return uniqueSorted(normalizedUris);
}

async function importClientIdKey(keyB64: string): Promise<CryptoKey> {
  const raw = base64ToBytes(keyB64);
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

async function signClientIdPayload(payloadB64: string, keyB64: string): Promise<string> {
  const key = await importClientIdKey(keyB64);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`client_id:${payloadB64}`));
  return bytesToBase64Url(new Uint8Array(signature));
}

async function deterministicLegacyClientId(redirectUri: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("client:" + redirectUri));
  return bytesToBase64Url(new Uint8Array(hash)).slice(0, 22);
}

export async function deriveClientId(redirectUris: string[], config: Config): Promise<string> {
  const normalizedRedirectUris = normalizeRedirectUris(redirectUris, config.redirectHttpsHosts);
  const payloadB64 = bytesToBase64Url(new TextEncoder().encode(JSON.stringify({ redirect_uris: normalizedRedirectUris })));
  const signatureB64 = await signClientIdPayload(payloadB64, config.jwtSigningKeyB64);
  return `ntfy.${payloadB64}.${signatureB64}`;
}

async function decodeClientId(clientId: string, keyB64: string): Promise<string[] | null> {
  if (!clientId.startsWith("ntfy.")) return null;

  const parts = clientId.split(".");
  if (parts.length !== 3) return null;

  const [, payloadB64, signatureB64] = parts;
  const expectedSignature = await signClientIdPayload(payloadB64, keyB64);
  if (signatureB64 !== expectedSignature) return null;

  try {
    const payloadText = new TextDecoder().decode(base64ToBytes(payloadB64));
    const payload = JSON.parse(payloadText) as { redirect_uris?: unknown };
    if (!Array.isArray(payload.redirect_uris) || payload.redirect_uris.some((value) => typeof value !== "string")) {
      return null;
    }
    return uniqueSorted(payload.redirect_uris);
  } catch {
    return null;
  }
}

export async function isValidClientIdForRedirectUri(clientId: string, redirectUri: string, config: Config): Promise<boolean> {
  const redirectValidation = validateRedirectUri(redirectUri, config.redirectHttpsHosts);
  if (!redirectValidation.ok) return false;

  const normalizedRedirectUri = redirectValidation.normalizedUri;
  const structuredRedirectUris = await decodeClientId(clientId, config.jwtSigningKeyB64);
  if (structuredRedirectUris) {
    return structuredRedirectUris.includes(normalizedRedirectUri);
  }

  const legacyClientId = await deterministicLegacyClientId(normalizedRedirectUri);
  return clientId === legacyClientId;
}

function parseRegistrationMetadata(body: Record<string, unknown>, config: Config): RegistrationMetadata {
  const rawRedirectUris = body["redirect_uris"];
  if (!Array.isArray(rawRedirectUris) || rawRedirectUris.length === 0 || rawRedirectUris.some((entry) => typeof entry !== "string")) {
    throw new RegisterMetadataError("redirect_uris must be a non-empty array of strings");
  }

  const normalizedRedirectUris = normalizeRedirectUris(rawRedirectUris, config.redirectHttpsHosts);
  const authMethod = readOptionalString(body, "token_endpoint_auth_method") ?? "none";
  if (authMethod !== "none") {
    throw new RegisterMetadataError("Only token_endpoint_auth_method=none is supported");
  }

  return {
    redirect_uris: normalizedRedirectUris,
    client_name: readOptionalString(body, "client_name"),
    client_uri: readOptionalString(body, "client_uri"),
    logo_uri: readOptionalString(body, "logo_uri"),
    contacts: readOptionalStringArray(body, "contacts"),
    tos_uri: readOptionalString(body, "tos_uri"),
    policy_uri: readOptionalString(body, "policy_uri"),
    jwks_uri: readOptionalString(body, "jwks_uri"),
    scope: validateScope(readOptionalString(body, "scope")),
    grant_types: validateGrantTypes(readOptionalStringArray(body, "grant_types")),
    response_types: validateResponseTypes(readOptionalStringArray(body, "response_types")),
    token_endpoint_auth_method: "none",
    application_type: readOptionalString(body, "application_type"),
  };
}

export async function handleRegister(request: Request, config: Config): Promise<Response> {
  if (!isJsonContentType(request.headers.get("content-type"))) {
    return invalidClientMetadata("Content-Type must be application/json", { field: "content-type" });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return invalidClientMetadata("Invalid JSON", { field: "body" });
  }

  if (!isRecord(body)) {
    return invalidClientMetadata("Client metadata must be a JSON object", { field: "body" });
  }

  let metadata: RegistrationMetadata;
  try {
    metadata = parseRegistrationMetadata(body, config);
  } catch (error) {
    if (error instanceof RedirectUriError) {
      return invalidRedirectUri(error.message, error.hostname);
    }
    if (error instanceof RegisterMetadataError) {
      return invalidClientMetadata(error.message);
    }
    throw error;
  }

  const clientId = await deriveClientId(metadata.redirect_uris, config);
  const responseBody: Record<string, unknown> = {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: metadata.redirect_uris,
    token_endpoint_auth_method: metadata.token_endpoint_auth_method,
    grant_types: metadata.grant_types,
    response_types: metadata.response_types,
    scope: metadata.scope,
  };

  if (metadata.client_name !== undefined) responseBody.client_name = metadata.client_name;
  if (metadata.client_uri !== undefined) responseBody.client_uri = metadata.client_uri;
  if (metadata.logo_uri !== undefined) responseBody.logo_uri = metadata.logo_uri;
  if (metadata.contacts !== undefined) responseBody.contacts = metadata.contacts;
  if (metadata.tos_uri !== undefined) responseBody.tos_uri = metadata.tos_uri;
  if (metadata.policy_uri !== undefined) responseBody.policy_uri = metadata.policy_uri;
  if (metadata.jwks_uri !== undefined) responseBody.jwks_uri = metadata.jwks_uri;
  if (metadata.application_type !== undefined) responseBody.application_type = metadata.application_type;

  return registerJson(responseBody, 201);
}

export function registerPreflightResponse(): Response {
  return new Response(null, {
    status: 204,
    headers: new Headers({
      Allow: "POST, OPTIONS",
      ...REGISTER_CORS_HEADERS,
    }),
  });
}
