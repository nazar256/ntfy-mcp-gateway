import type { Config } from "../config.ts";
import { signJwt, signCsrf, verifyCsrf, encryptPayload } from "../security/crypto.ts";
import { validateNtfyConfig } from "../security/validators.ts";
import type { NtfyConfig } from "../security/validators.ts";

interface AuthorizeParams {
  response_type: string;
  client_id: string;
  redirect_uri: string;
  state: string;
  code_challenge: string;
  code_challenge_method: string;
  scope?: string;
  resource?: string;
}

function validateAuthorizeParams(params: URLSearchParams, config: Config): AuthorizeParams | Response {
  const responseType = params.get("response_type");
  if (responseType !== "code") {
    return Response.json({ error: "unsupported_response_type" }, { status: 400 });
  }
  const clientId = params.get("client_id");
  if (!clientId) {
    return Response.json({ error: "invalid_request", error_description: "client_id required" }, { status: 400 });
  }
  const redirectUri = params.get("redirect_uri");
  if (!redirectUri) {
    return Response.json({ error: "invalid_request", error_description: "redirect_uri required" }, { status: 400 });
  }
  const state = params.get("state");
  if (!state) {
    return Response.json({ error: "invalid_request", error_description: "state required" }, { status: 400 });
  }
  const codeChallenge = params.get("code_challenge");
  if (!codeChallenge) {
    return Response.json({ error: "invalid_request", error_description: "code_challenge required" }, { status: 400 });
  }
  const codeChallengeMethod = params.get("code_challenge_method");
  if (codeChallengeMethod !== "S256") {
    return Response.json({ error: "invalid_request", error_description: "Only S256 code_challenge_method supported" }, { status: 400 });
  }
  const scope = params.get("scope");
  if (scope && !scope.split(" ").includes("notify.write")) {
    return Response.json({ error: "invalid_scope", error_description: "Unsupported scope" }, { status: 400 });
  }
  const resource = params.get("resource");
  if (resource && resource !== config.mcpResource) {
    return Response.json({ error: "invalid_target", error_description: "Unknown resource" }, { status: 400 });
  }
  return {
    response_type: responseType,
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
    scope: scope ?? undefined,
    resource: resource ?? undefined,
  };
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

function renderConsentForm(params: AuthorizeParams, csrfToken: string, error?: string): string {
  const escapedState = escapeHtml(params.state);
  const escapedRedirect = escapeHtml(params.redirect_uri);
  const escapedClientId = escapeHtml(params.client_id);
  const escapedChallenge = escapeHtml(params.code_challenge);
  const escapedResource = escapeHtml(params.resource || "");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ntfy MCP Gateway – Connect</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 480px; margin: 40px auto; padding: 20px; }
  h1 { font-size: 1.4rem; margin-bottom: 8px; }
  label { display: block; margin: 12px 0 4px; font-weight: 500; }
  input[type=text], input[type=password], input[type=url] {
    width: 100%; box-sizing: border-box; padding: 8px; border: 1px solid #ccc; border-radius: 4px; font-size: 1rem;
  }
  .checkbox-row { display: flex; align-items: center; gap: 8px; margin: 12px 0; }
  .checkbox-row input { width: auto; }
  button { margin-top: 20px; width: 100%; padding: 10px; background: #2563eb; color: #fff; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
  .error { color: #dc2626; margin-bottom: 12px; padding: 8px; background: #fee2e2; border-radius: 4px; }
  .hint { font-size: 0.8rem; color: #6b7280; margin-top: 2px; }
</style>
</head>
<body>
<h1>Connect ntfy Notifications</h1>
<p>Configure your ntfy push notification settings to authorize this connection.</p>
${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}
<form method="POST">
  <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
  <input type="hidden" name="response_type" value="code">
  <input type="hidden" name="client_id" value="${escapedClientId}">
  <input type="hidden" name="redirect_uri" value="${escapedRedirect}">
  <input type="hidden" name="state" value="${escapedState}">
  <input type="hidden" name="code_challenge" value="${escapedChallenge}">
  <input type="hidden" name="code_challenge_method" value="S256">
  <input type="hidden" name="resource" value="${escapedResource}">
  <label for="ntfy_base_url">ntfy Server URL</label>
  <input type="url" id="ntfy_base_url" name="ntfy_base_url" value="https://ntfy.sh" required>
  <div class="hint">Default: https://ntfy.sh. Use your self-hosted URL if applicable.</div>
  <label for="default_topic">Default Topic</label>
  <input type="text" id="default_topic" name="default_topic" required placeholder="my-random-topic-abc123">
  <div class="hint">8–128 chars, A-Za-z0-9._- only. Use a random unique topic. Public topics are shared!</div>
  <div class="checkbox-row">
    <input type="checkbox" id="allow_topic_override" name="allow_topic_override" value="1">
    <label for="allow_topic_override" style="margin:0; font-weight:400;">Allow topic override per message</label>
  </div>
  <label for="ntfy_access_token">Access Token (optional)</label>
  <input type="password" id="ntfy_access_token" name="ntfy_access_token" placeholder="(leave blank for public topics)">
  <div class="hint">Only needed for protected topics or self-hosted servers.</div>
  <button type="submit">Authorize &amp; Connect</button>
</form>
</body>
</html>`;
}

export async function handleAuthorizeGet(request: Request, config: Config): Promise<Response> {
  const url = new URL(request.url);
  const params = url.searchParams;
  const result = validateAuthorizeParams(params, config);
  if (result instanceof Response) return result;

  const csrfToken = await signCsrf(result.state, config.csrfSigningKeyB64);

  const html = renderConsentForm(result, csrfToken);
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

export async function handleAuthorizePost(request: Request, config: Config): Promise<Response> {
  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return Response.json({ error: "invalid_request", error_description: "Invalid form data" }, { status: 400 });
  }

  const params = new URLSearchParams();
  for (const [k, v] of formData.entries()) {
    params.set(k, String(v));
  }

  const result = validateAuthorizeParams(params, config);
  if (result instanceof Response) return result;

  const csrfToken = params.get("csrf_token") || "";
  const csrfValid = await verifyCsrf(result.state, csrfToken, config.csrfSigningKeyB64);
  if (!csrfValid) {
    return new Response(renderConsentForm(result, csrfToken, "Invalid CSRF token. Please try again."), {
      status: 400,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const ntfyBaseUrl = params.get("ntfy_base_url") || "";
  const defaultTopic = params.get("default_topic") || "";
  const allowTopicOverride = params.get("allow_topic_override") === "1";
  const ntfyAccessToken = params.get("ntfy_access_token") || undefined;

  let ntfyConfig: NtfyConfig;
  try {
    const rawConfig: NtfyConfig = {
      ntfyBaseUrl,
      defaultTopic,
      allowTopicOverride,
      ntfyAccessToken: ntfyAccessToken || undefined,
    };
    ntfyConfig = validateNtfyConfig(rawConfig);
  } catch (e) {
    const newCsrf = await signCsrf(result.state, config.csrfSigningKeyB64);
    return new Response(renderConsentForm(result, newCsrf, (e as Error).message), {
      status: 400,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const aad = `${result.client_id}:${result.redirect_uri}`;
  const encrypted = await encryptPayload(JSON.stringify(ntfyConfig), aad, config.encKeyB64);

  const authCode = await signJwt(
    {
      iss: config.issuer,
      type: "auth_code",
      client_id: result.client_id,
      redirect_uri: result.redirect_uri,
      code_challenge: result.code_challenge,
      scope: result.scope || "notify.write",
      resource: result.resource || config.mcpResource,
      ntfy_enc: encrypted.ct,
      ntfy_iv: encrypted.iv,
      ntfy_aad: encrypted.aad,
    },
    config.jwtSigningKeyB64,
    config.authCodeTtl
  );

  const redirectUrl = new URL(result.redirect_uri);
  redirectUrl.searchParams.set("code", authCode);
  redirectUrl.searchParams.set("state", result.state);

  return Response.redirect(redirectUrl.toString(), 302);
}
