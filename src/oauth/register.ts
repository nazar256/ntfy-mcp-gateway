import type { Config } from "../config.ts";
import { bytesToBase64Url } from "../security/crypto.ts";

function isAllowedRedirectUri(uri: string, httpsHosts: string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }

  if (
    (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") &&
    (parsed.protocol === "http:" || parsed.protocol === "https:")
  ) {
    return true;
  }

  if (parsed.protocol !== "https:") {
    return false;
  }

  const host = parsed.hostname.toLowerCase();
  for (const pattern of httpsHosts) {
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(2);
      if (host === suffix || host.endsWith("." + suffix)) return true;
    } else {
      if (host === pattern.toLowerCase()) return true;
    }
  }
  return false;
}

async function deterministicClientId(redirectUri: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("client:" + redirectUri));
  return bytesToBase64Url(new Uint8Array(hash)).slice(0, 22);
}

export async function handleRegister(request: Request, config: Config): Promise<Response> {
  let body: Record<string, unknown>;
  try {
    body = await request.json() as Record<string, unknown>;
  } catch {
    return Response.json({ error: "invalid_client_metadata", error_description: "Invalid JSON" }, { status: 400 });
  }

  const redirectUris = body["redirect_uris"];
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    return Response.json({ error: "invalid_client_metadata", error_description: "redirect_uris required" }, { status: 400 });
  }

  const redirectUri = String(redirectUris[0]);
  if (!isAllowedRedirectUri(redirectUri, config.redirectHttpsHosts)) {
    return Response.json({ error: "invalid_redirect_uri", error_description: "Redirect URI not allowed" }, { status: 400 });
  }

  const authMethod = body["token_endpoint_auth_method"];
  if (authMethod !== undefined && authMethod !== "none") {
    return Response.json({ error: "invalid_client_metadata", error_description: "Only token_endpoint_auth_method=none supported" }, { status: 400 });
  }

  const clientId = await deterministicClientId(redirectUri);

  return Response.json({
    client_id: clientId,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code"],
    response_types: ["code"],
  }, { status: 201 });
}

export { isAllowedRedirectUri };
