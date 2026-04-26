import type { Config } from "../config.ts";
import { verifyJwt, signJwt, bytesToBase64Url } from "../security/crypto.ts";
import { isValidClientIdForRedirectUri } from "./register.ts";

const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30;

async function verifyPkceS256(verifier: string, challenge: string): Promise<boolean> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const computed = bytesToBase64Url(new Uint8Array(hash));
  return computed === challenge;
}

interface TokenState {
  clientId: string;
  scope: string;
  resource: string;
  ntfyEnc: unknown;
  ntfyIv: unknown;
  ntfyAad: unknown;
}

function buildTokenState(payload: Record<string, unknown>, clientId: string, config: Config): TokenState {
  return {
    clientId,
    scope: typeof payload["scope"] === "string" ? payload["scope"] : "notify.write",
    resource: config.mcpResource,
    ntfyEnc: payload["ntfy_enc"],
    ntfyIv: payload["ntfy_iv"],
    ntfyAad: payload["ntfy_aad"],
  };
}

async function issueTokens(state: TokenState, config: Config): Promise<{ accessToken: string; refreshToken: string }> {
  const accessToken = await signJwt(
    {
      iss: config.issuer,
      aud: config.mcpAudience,
      type: "access_token",
      client_id: state.clientId,
      scope: state.scope,
      resource: state.resource,
      ntfy_enc: state.ntfyEnc,
      ntfy_iv: state.ntfyIv,
      ntfy_aad: state.ntfyAad,
    },
    config.jwtSigningKeyB64,
    config.accessTokenTtl
  );

  const refreshToken = await signJwt(
    {
      iss: config.issuer,
      type: "refresh_token",
      client_id: state.clientId,
      scope: state.scope,
      resource: state.resource,
      ntfy_enc: state.ntfyEnc,
      ntfy_iv: state.ntfyIv,
      ntfy_aad: state.ntfyAad,
    },
    config.jwtSigningKeyB64,
    REFRESH_TOKEN_TTL_SECONDS
  );

  return { accessToken, refreshToken };
}

function tokenJson(body: Record<string, unknown>, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Pragma": "no-cache",
    },
  });
}

export async function handleToken(request: Request, config: Config): Promise<Response> {
  let params: URLSearchParams;
  const contentType = request.headers.get("content-type") || "";
  if (contentType.includes("application/x-www-form-urlencoded")) {
    const body = await request.text();
    params = new URLSearchParams(body);
  } else {
    try {
      const json = await request.json() as Record<string, string>;
      params = new URLSearchParams(json);
    } catch {
      return tokenError("invalid_request", "Invalid request body", 400);
    }
  }

  const grantType = params.get("grant_type");
  const clientId = params.get("client_id");
  if (!clientId) return tokenError("invalid_request", "client_id required", 400);

  if (grantType === "authorization_code") {
    const code = params.get("code");
    if (!code) return tokenError("invalid_request", "code required", 400);

    const redirectUri = params.get("redirect_uri");
    if (!redirectUri) return tokenError("invalid_request", "redirect_uri required", 400);

    const clientIdValid = await isValidClientIdForRedirectUri(clientId, redirectUri, config);
    if (!clientIdValid) {
      return tokenError("invalid_grant", "client_id does not match redirect_uri", 400);
    }

    const codeVerifier = params.get("code_verifier");
    if (!codeVerifier) return tokenError("invalid_request", "code_verifier required", 400);

    const resource = params.get("resource");

    let authCodePayload: Record<string, unknown>;
    try {
      const verified = await verifyJwt(code, config.jwtSigningKeyB64, { issuer: config.issuer });
      authCodePayload = verified.payload;
    } catch {
      return tokenError("invalid_grant", "Invalid or expired authorization code", 400);
    }

    if (authCodePayload["type"] !== "auth_code") {
      return tokenError("invalid_grant", "Invalid authorization code type", 400);
    }

    if (authCodePayload["client_id"] !== clientId) {
      return tokenError("invalid_grant", "client_id mismatch", 400);
    }

    if (authCodePayload["redirect_uri"] !== redirectUri) {
      return tokenError("invalid_grant", "redirect_uri mismatch", 400);
    }

    const codeResource = authCodePayload["resource"] as string | undefined;
    if (resource && resource !== config.mcpResource) {
      return tokenError("invalid_target", "Unknown resource", 400);
    }
    if (resource && codeResource && resource !== codeResource) {
      return tokenError("invalid_target", "resource mismatch with authorization code", 400);
    }

    const codeChallenge = authCodePayload["code_challenge"] as string;
    const pkceValid = await verifyPkceS256(codeVerifier, codeChallenge);
    if (!pkceValid) {
      return tokenError("invalid_grant", "Invalid code_verifier", 400);
    }

    const { accessToken, refreshToken } = await issueTokens(buildTokenState(authCodePayload, clientId, config), config);

    return tokenJson({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in: config.accessTokenTtl,
      scope: typeof authCodePayload["scope"] === "string" ? authCodePayload["scope"] : "notify.write",
    }, 200);
  }

  if (grantType === "refresh_token") {
    const refreshToken = params.get("refresh_token");
    if (!refreshToken) return tokenError("invalid_request", "refresh_token required", 400);

    const resource = params.get("resource");
    let refreshTokenPayload: Record<string, unknown>;
    try {
      const verified = await verifyJwt(refreshToken, config.jwtSigningKeyB64, { issuer: config.issuer });
      refreshTokenPayload = verified.payload;
    } catch {
      return tokenError("invalid_grant", "Invalid or expired refresh token", 400);
    }

    if (refreshTokenPayload["type"] !== "refresh_token") {
      return tokenError("invalid_grant", "Invalid refresh token type", 400);
    }

    if (refreshTokenPayload["client_id"] !== clientId) {
      return tokenError("invalid_grant", "client_id mismatch", 400);
    }

    const refreshResource = refreshTokenPayload["resource"] as string | undefined;
    if (resource && resource !== config.mcpResource) {
      return tokenError("invalid_target", "Unknown resource", 400);
    }
    if (resource && refreshResource && resource !== refreshResource) {
      return tokenError("invalid_target", "resource mismatch with refresh token", 400);
    }

    const { accessToken, refreshToken: nextRefreshToken } = await issueTokens(
      buildTokenState(refreshTokenPayload, clientId, config),
      config
    );

    return tokenJson({
      access_token: accessToken,
      refresh_token: nextRefreshToken,
      token_type: "Bearer",
      expires_in: config.accessTokenTtl,
      scope: typeof refreshTokenPayload["scope"] === "string" ? refreshTokenPayload["scope"] : "notify.write",
    }, 200);
  }

  return tokenError("unsupported_grant_type", "Supported grant_type values are authorization_code and refresh_token", 400);
}

function tokenError(error: string, description: string, status: number): Response {
  return tokenJson({ error, error_description: description }, status);
}
