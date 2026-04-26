import { describe, it, expect } from "vitest";
import worker from "../index.ts";
import type { Env } from "../config.ts";
import { bytesToBase64Url } from "../security/crypto.ts";

const TEST_KEY_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const ISSUER = "https://example.workers.dev";
const MCP_RESOURCE = "https://example.workers.dev/mcp";

const testEnv: Env = {
  NTFY_CONFIG_ENC_KEY_B64: TEST_KEY_B64,
  OAUTH_JWT_SIGNING_KEY_B64: TEST_KEY_B64,
  CSRF_SIGNING_KEY_B64: TEST_KEY_B64,
  OAUTH_ISSUER: ISSUER,
  MCP_RESOURCE,
  MCP_AUDIENCE: MCP_RESOURCE,
  AUTH_CODE_TTL_SECONDS: "300",
  ACCESS_TOKEN_TTL_SECONDS: "3600",
  AUTHORIZE_RATE_LIMIT_PER_MINUTE: "20",
  TOKEN_RATE_LIMIT_PER_MINUTE: "20",
  MCP_RATE_LIMIT_PER_MINUTE: "60",
  OAUTH_REDIRECT_HTTPS_HOSTS: "chatgpt.com,*.chatgpt.com,chat.openai.com,*.chat.openai.com",
};

async function sha256Base64Url(input: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return bytesToBase64Url(new Uint8Array(hash));
}

function extractCsrfToken(html: string): string {
  const match = html.match(/name="csrf_token" value="([^"]+)"/);
  if (!match?.[1]) {
    throw new Error("csrf token not found in authorize form");
  }
  return match[1];
}

async function registerClient(body?: Record<string, unknown>) {
  const response = await worker.fetch(
    new Request(`${ISSUER}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({
        redirect_uris: ["https://chatgpt.com/aip/callback"],
        client_name: "ChatGPT",
        token_endpoint_auth_method: "none",
        ...body,
      }),
    }),
    testEnv
  );

  return response;
}

async function authorizeAndGetCode(options: { clientId: string; redirectUri?: string; resource?: string; codeChallenge?: string; state?: string }) {
  const codeVerifier = "verifier-1234567890verifier-1234567890";
  const codeChallenge = options.codeChallenge ?? await sha256Base64Url(codeVerifier);
  const state = options.state ?? "state-123";
  const clientId = options.clientId;
  const redirectUri = options.redirectUri ?? "https://chatgpt.com/aip/callback";

  const authUrl = new URL(`${ISSUER}/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("scope", "notify.write");
  if (options.resource !== undefined) {
    authUrl.searchParams.set("resource", options.resource);
  }

  const getRes = await worker.fetch(new Request(authUrl.toString(), { method: "GET" }), testEnv);
  if (getRes.status !== 200) {
    return { getRes, postRes: null as Response | null, code: null as string | null, state, codeVerifier };
  }

  const html = await getRes.text();
  const csrfToken = extractCsrfToken(html);
  const form = new URLSearchParams();
  form.set("csrf_token", csrfToken);
  form.set("response_type", "code");
  form.set("client_id", clientId);
  form.set("redirect_uri", redirectUri);
  form.set("state", state);
  form.set("code_challenge", codeChallenge);
  form.set("code_challenge_method", "S256");
  if (options.resource !== undefined) {
    form.set("resource", options.resource);
  }
  form.set("ntfy_base_url", "https://ntfy.sh");
  form.set("default_topic", "topic-abc12345");

  const postRes = await worker.fetch(
    new Request(`${ISSUER}/authorize`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
      redirect: "manual",
    }),
    testEnv
  );

  if (postRes.status !== 302) {
    return { getRes, postRes, code: null as string | null, state, codeVerifier };
  }

  const location = postRes.headers.get("Location") || "";
  const callbackUrl = new URL(location);
  const code = callbackUrl.searchParams.get("code");
  return { getRes, postRes, code, state, codeVerifier };
}

async function exchangeToken(code: string, clientId: string, redirectUri: string, codeVerifier: string, resource?: string): Promise<Response> {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: clientId,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  });
  if (resource) {
    params.set("resource", resource);
  }

  return worker.fetch(
    new Request(`${ISSUER}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    }),
    testEnv
  );
}

describe("OAuth compatibility flow", () => {
  it("DCR accepts a ChatGPT-style payload and returns RFC 7591 fields", async () => {
    const chatgptRes = await registerClient({
      redirect_uris: [
        "https://chatgpt.com/aip/callback",
        "https://chat.openai.com/aip/callback",
      ],
      client_uri: "https://chatgpt.com",
      logo_uri: "https://chatgpt.com/logo.png",
      contacts: ["security@openai.com"],
      tos_uri: "https://chatgpt.com/tos",
      policy_uri: "https://chatgpt.com/privacy",
      scope: "notify.write",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      application_type: "web",
      ignored_by_server: true,
    });
    expect(chatgptRes.status).toBe(201);
    expect(chatgptRes.headers.get("Content-Type")).toContain("application/json");
    expect(chatgptRes.headers.get("Cache-Control")).toBe("no-store");
    expect(chatgptRes.headers.get("Access-Control-Allow-Origin")).toBe("*");

    const json = await chatgptRes.json() as Record<string, unknown>;
    expect(json.client_id).toBeTypeOf("string");
    expect(json.client_id_issued_at).toBeTypeOf("number");
    expect(json.redirect_uris).toEqual([
      "https://chat.openai.com/aip/callback",
      "https://chatgpt.com/aip/callback",
    ]);
    expect(json.token_endpoint_auth_method).toBe("none");
    expect(json.grant_types).toEqual(["authorization_code"]);
    expect(json.response_types).toEqual(["code"]);
    expect(json.scope).toBe("notify.write");
    expect(json.client_name).toBe("ChatGPT");

    const localRes = await registerClient({ redirect_uris: ["http://localhost:3333/callback"] });
    expect(localRes.status).toBe(201);
  });

  it("DCR rejects unsafe redirect", async () => {
    const res = await registerClient({ redirect_uris: ["https://evil.example/callback"] });

    expect(res.status).toBe(400);
    const json = await res.json() as { error: string };
    expect(json.error).toBe("invalid_redirect_uri");
  });

  it("DCR rejects unsupported client metadata", async () => {
    const res = await registerClient({
      token_endpoint_auth_method: "client_secret_post",
      scope: "notify.write notify.read",
    });

    expect(res.status).toBe(400);
    const json = await res.json() as { error: string; error_description: string };
    expect(json.error).toBe("invalid_client_metadata");
    expect(json.error_description).toContain("token_endpoint_auth_method");
  });

  it("DCR rejects non-JSON content types", async () => {
    const res = await worker.fetch(
      new Request(`${ISSUER}/register`, {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({ redirect_uris: ["https://chatgpt.com/aip/callback"] }),
      }),
      testEnv
    );

    expect(res.status).toBe(400);
    const json = await res.json() as { error: string };
    expect(json.error).toBe("invalid_client_metadata");
  });

  it("authorize rejects wrong resource", async () => {
    const registration = await registerClient();
    const { client_id } = await registration.json() as { client_id: string };
    const { getRes } = await authorizeAndGetCode({
      clientId: client_id,
      redirectUri: "https://chatgpt.com/aip/callback",
      resource: "https://example.workers.dev/not-mcp",
    });
    expect(getRes.status).toBe(400);
    const json = await getRes.json() as { error: string };
    expect(json.error).toBe("invalid_target");
  });

  it("token exchange rejects wrong resource", async () => {
    const registration = await registerClient();
    const { client_id } = await registration.json() as { client_id: string };
    const auth = await authorizeAndGetCode({
      clientId: client_id,
      redirectUri: "https://chatgpt.com/aip/callback",
      resource: MCP_RESOURCE,
    });
    expect(auth.code).toBeTruthy();

    const tokenRes = await exchangeToken(auth.code!, client_id, "https://chatgpt.com/aip/callback", auth.codeVerifier, "https://example.workers.dev/wrong");
    expect(tokenRes.status).toBe(400);
    const json = await tokenRes.json() as { error: string };
    expect(json.error).toBe("invalid_target");
  });

  it("token exchange rejects PKCE mismatch", async () => {
    const registration = await registerClient();
    const { client_id } = await registration.json() as { client_id: string };
    const auth = await authorizeAndGetCode({
      clientId: client_id,
      redirectUri: "https://chatgpt.com/aip/callback",
      resource: MCP_RESOURCE,
    });
    expect(auth.code).toBeTruthy();

    const tokenRes = await exchangeToken(auth.code!, client_id, "https://chatgpt.com/aip/callback", "definitely-the-wrong-verifier", MCP_RESOURCE);
    expect(tokenRes.status).toBe(400);
    const json = await tokenRes.json() as { error: string };
    expect(json.error).toBe("invalid_grant");
  });

  it("token response includes no-store headers", async () => {
    const registration = await registerClient();
    const { client_id } = await registration.json() as { client_id: string };
    const auth = await authorizeAndGetCode({
      clientId: client_id,
      redirectUri: "https://chatgpt.com/aip/callback",
      resource: MCP_RESOURCE,
    });
    expect(auth.code).toBeTruthy();

    const tokenRes = await exchangeToken(auth.code!, client_id, "https://chatgpt.com/aip/callback", auth.codeVerifier, MCP_RESOURCE);
    expect(tokenRes.status).toBe(200);
    expect(tokenRes.headers.get("Cache-Control")).toBe("no-store");
    expect(tokenRes.headers.get("Pragma")).toBe("no-cache");
  });

  it("authorize rejects a client_id that does not match redirect_uri", async () => {
    const registration = await registerClient({ redirect_uris: ["https://chatgpt.com/aip/callback"] });
    const { client_id } = await registration.json() as { client_id: string };
    const { getRes } = await authorizeAndGetCode({
      clientId: client_id,
      redirectUri: "https://chat.openai.com/aip/callback",
      resource: MCP_RESOURCE,
    });

    expect(getRes.status).toBe(400);
    const json = await getRes.json() as { error: string };
    expect(json.error).toBe("invalid_request");
  });
});
