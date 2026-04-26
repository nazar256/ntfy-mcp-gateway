import type { Config } from "../config.ts";
import { verifyJwt, signJwt, bytesToBase64Url } from "../security/crypto.ts";

async function verifyPkceS256(verifier: string, challenge: string): Promise<boolean> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const computed = bytesToBase64Url(new Uint8Array(hash));
  return computed === challenge;
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
  if (grantType !== "authorization_code") {
    return tokenError("unsupported_grant_type", "Only authorization_code supported", 400);
  }

  const code = params.get("code");
  if (!code) return tokenError("invalid_request", "code required", 400);

  const clientId = params.get("client_id");
  if (!clientId) return tokenError("invalid_request", "client_id required", 400);

  const redirectUri = params.get("redirect_uri");
  if (!redirectUri) return tokenError("invalid_request", "redirect_uri required", 400);

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

  const accessToken = await signJwt(
    {
      iss: config.issuer,
      aud: config.mcpAudience,
      type: "access_token",
      client_id: clientId,
      scope: (authCodePayload["scope"] as string) || "notify.write",
      resource: config.mcpResource,
      ntfy_enc: authCodePayload["ntfy_enc"],
      ntfy_iv: authCodePayload["ntfy_iv"],
      ntfy_aad: authCodePayload["ntfy_aad"],
    },
    config.jwtSigningKeyB64,
    config.accessTokenTtl
  );

  return new Response(
    JSON.stringify({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: config.accessTokenTtl,
      scope: authCodePayload["scope"] || "notify.write",
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
      },
    }
  );
}

function tokenError(error: string, description: string, status: number): Response {
  return new Response(JSON.stringify({ error, error_description: description }), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Pragma": "no-cache",
    },
  });
}
