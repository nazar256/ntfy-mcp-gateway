import { describe, it, expect } from "vitest";
import worker from "../index.ts";
import type { Env } from "../config.ts";

const testEnv: Env = {
  NTFY_CONFIG_ENC_KEY_B64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  OAUTH_JWT_SIGNING_KEY_B64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  CSRF_SIGNING_KEY_B64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  OAUTH_ISSUER: "https://example.workers.dev",
  MCP_RESOURCE: "https://example.workers.dev/mcp",
  MCP_AUDIENCE: "https://example.workers.dev/mcp",
  AUTH_CODE_TTL_SECONDS: "300",
  ACCESS_TOKEN_TTL_SECONDS: "3600",
  AUTHORIZE_RATE_LIMIT_PER_MINUTE: "20",
  TOKEN_RATE_LIMIT_PER_MINUTE: "20",
  MCP_RATE_LIMIT_PER_MINUTE: "60",
  OAUTH_REDIRECT_HTTPS_HOSTS: "chatgpt.com,*.chatgpt.com,chat.openai.com,*.chat.openai.com",
};

async function req(method: string, path: string, body?: BodyInit, headers?: Record<string, string>): Promise<Response> {
  return worker.fetch(
    new Request(`https://example.workers.dev${path}`, { method, body, headers }),
    testEnv
  );
}

describe("Route method checks (405)", () => {
  it("GET / returns 200", async () => {
    const r = await req("GET", "/");
    expect(r.status).toBe(200);
  });

  it("POST / returns 405", async () => {
    const r = await req("POST", "/");
    expect(r.status).toBe(405);
    expect(r.headers.get("Allow")).toContain("GET");
  });

  it("GET /health returns 200", async () => {
    const r = await req("GET", "/health");
    expect(r.status).toBe(200);
  });

  it("POST /.well-known/oauth-authorization-server returns 405", async () => {
    const r = await req("POST", "/.well-known/oauth-authorization-server");
    expect(r.status).toBe(405);
  });

  it("GET /.well-known/oauth-authorization-server returns 200", async () => {
    const r = await req("GET", "/.well-known/oauth-authorization-server");
    expect(r.status).toBe(200);
    const json = await r.json() as Record<string, unknown>;
    expect(json.issuer).toBe("https://example.workers.dev");
  });

  it("GET /.well-known/oauth-protected-resource returns 200", async () => {
    const r = await req("GET", "/.well-known/oauth-protected-resource");
    expect(r.status).toBe(200);
  });

  it("GET /.well-known/oauth-protected-resource/mcp returns 200", async () => {
    const r = await req("GET", "/.well-known/oauth-protected-resource/mcp");
    expect(r.status).toBe(200);
  });

  it("GET /register returns 405", async () => {
    const r = await req("GET", "/register");
    expect(r.status).toBe(405);
  });

  it("DELETE /mcp returns 401 (not 405)", async () => {
    const r = await req("DELETE", "/mcp");
    expect(r.status).toBe(401);
  });

  it("PUT /mcp returns 405", async () => {
    const r = await req("PUT", "/mcp");
    expect(r.status).toBe(405);
  });
});

describe("Unauthenticated /mcp returns 401", () => {
  it("POST /mcp without token returns 401", async () => {
    const r = await req("POST", "/mcp", JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }), { "Content-Type": "application/json" });
    expect(r.status).toBe(401);
  });

  it("WWW-Authenticate header includes resource_metadata", async () => {
    const r = await req("POST", "/mcp", JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }), { "Content-Type": "application/json" });
    const wwwAuth = r.headers.get("WWW-Authenticate") || "";
    expect(wwwAuth).toContain("resource_metadata");
    expect(wwwAuth).toContain("notify.write");
  });
});
