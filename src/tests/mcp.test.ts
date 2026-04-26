import { describe, it, expect } from "vitest";
import { encryptPayload, signJwt } from "../security/crypto.ts";
import worker from "../index.ts";
import type { Env } from "../config.ts";

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
  OAUTH_REDIRECT_HTTPS_HOSTS: "chatgpt.com,*.chatgpt.com",
};

async function makeAccessToken(ntfyConfig: object): Promise<string> {
  const aad = "testclient:https://chatgpt.com/cb";
  const enc = await encryptPayload(JSON.stringify(ntfyConfig), aad, TEST_KEY_B64);
  return signJwt(
    {
      iss: ISSUER,
      aud: MCP_RESOURCE,
      type: "access_token",
      client_id: "testclient",
      scope: "notify.write",
      resource: MCP_RESOURCE,
      ntfy_enc: enc.ct,
      ntfy_iv: enc.iv,
      ntfy_aad: enc.aad,
    },
    TEST_KEY_B64,
    3600
  );
}

describe("MCP endpoint with valid token", () => {
  it("tools/list returns send_notification", async () => {
    const token = await makeAccessToken({
      ntfyBaseUrl: "https://ntfy.sh",
      defaultTopic: "test-topic-abc123",
      allowTopicOverride: false,
    });

    const r = await worker.fetch(
      new Request(`${ISSUER}/mcp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json, text/event-stream",
          "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }),
      }),
      testEnv
    );

    expect(r.status).toBe(200);
    const json = await r.json() as { result?: { tools?: Array<{ name: string }> } };
    const tools = json?.result?.tools ?? [];
    expect(tools.some((t) => t.name === "send_notification")).toBe(true);
  });
});
