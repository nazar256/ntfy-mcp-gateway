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

async function makeAccessToken(ntfyConfig: object, aad = "testclient:https://chatgpt.com/cb"): Promise<string> {
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

async function mcpRequest(token: string, body: Record<string, unknown>, method = "POST"): Promise<Response> {
  return worker.fetch(
    new Request(`${ISSUER}/mcp`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    }),
    testEnv
  );
}

describe("MCP endpoint with valid token", () => {
  it("initialize, tools/list and tools/call work", async () => {
    const token = await makeAccessToken({
      ntfyBaseUrl: "https://ntfy.sh",
      defaultTopic: "test-topic-abc123",
      allowTopicOverride: false,
    });

    const initializeRes = await mcpRequest(token, {
      jsonrpc: "2.0",
      method: "initialize",
      id: 1,
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "vitest", version: "1.0.0" },
      },
    });
    expect(initializeRes.status).toBe(200);

    const listRes = await mcpRequest(token, { jsonrpc: "2.0", method: "tools/list", id: 2 });
    expect(listRes.status).toBe(200);
    const listJson = await listRes.json() as { result?: { tools?: Array<{ name: string }> } };
    expect(listJson?.result?.tools?.map((t) => t.name)).toEqual(["send_notification"]);

    const callRes = await mcpRequest(token, {
      jsonrpc: "2.0",
      method: "tools/call",
      id: 3,
      params: {
        name: "send_notification",
        arguments: {
          message: "hello",
          topic: "override-topic-xyz",
        },
      },
    });
    expect(callRes.status).toBe(200);
    const callJson = await callRes.json() as {
      result?: { isError?: boolean; content?: Array<{ text?: string }> };
    };
    expect(callJson.result?.isError).toBe(true);
    expect(callJson.result?.content?.[0]?.text).toMatch(/override/i);
  });

  it("rejects token encrypted with wrong AAD in payload", async () => {
    const enc = await encryptPayload(
      JSON.stringify({ ntfyBaseUrl: "https://ntfy.sh", defaultTopic: "test-topic-abc123", allowTopicOverride: false }),
      "good-aad",
      TEST_KEY_B64
    );

    const tampered = await signJwt(
      {
        iss: ISSUER,
        aud: MCP_RESOURCE,
        type: "access_token",
        client_id: "testclient",
        scope: "notify.write",
        resource: MCP_RESOURCE,
        ntfy_enc: enc.ct,
        ntfy_iv: enc.iv,
        ntfy_aad: "d3JvbmctYWFk",
      },
      TEST_KEY_B64,
      3600
    );

    const res = await mcpRequest(tampered, { jsonrpc: "2.0", method: "tools/list", id: 10 });
    expect(res.status).toBe(401);
  });
});
