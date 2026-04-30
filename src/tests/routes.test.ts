import { describe, it, expect, vi, afterEach } from "vitest";
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

const blankUrlEnv: Env = {
  ...testEnv,
  OAUTH_ISSUER: "",
  MCP_RESOURCE: "",
  MCP_AUDIENCE: "",
};
const testBaseUrl = "https://deployed-example.workers.dev";

async function req(method: string, path: string, body?: BodyInit, headers?: Record<string, string>): Promise<Response> {
  return worker.fetch(
    new Request(`https://example.workers.dev${path}`, { method, body, headers }),
    testEnv
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

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

  it("derives deployed issuer and resource from request URL when vars are blank", async () => {
    const request = new Request(`${testBaseUrl}/.well-known/oauth-authorization-server`);
    const r = await worker.fetch(request, blankUrlEnv);
    expect(r.status).toBe(200);

    const json = await r.json() as Record<string, unknown>;
    expect(json.issuer).toBe(testBaseUrl);
    expect(json.authorization_endpoint).toBe(`${testBaseUrl}/authorize`);
    expect(json.token_endpoint).toBe(`${testBaseUrl}/token`);
    expect(json.registration_endpoint).toBe(`${testBaseUrl}/register`);
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
    expect(r.headers.get("Allow")).toBe("POST, OPTIONS");
  });

  it("OPTIONS /register returns 204 with CORS headers", async () => {
    const r = await req("OPTIONS", "/register");
    expect(r.status).toBe(204);
    expect(r.headers.get("Allow")).toBe("POST, OPTIONS");
    expect(r.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("GET /token returns 405 with OPTIONS allowed", async () => {
    const r = await req("GET", "/token");
    expect(r.status).toBe(405);
    expect(r.headers.get("Allow")).toBe("POST, OPTIONS");
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
  it("GET /mcp without token returns 401", async () => {
    const r = await req("GET", "/mcp", undefined, { "Accept": "text/event-stream" });
    expect(r.status).toBe(401);
  });

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

  it("blank vars still advertise deployed protected resource metadata on /mcp", async () => {
    const r = await worker.fetch(
      new Request(`${testBaseUrl}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }),
      }),
      blankUrlEnv
    );

    expect(r.status).toBe(401);
    const wwwAuth = r.headers.get("WWW-Authenticate") || "";
    expect(wwwAuth).toContain(`resource_metadata="${testBaseUrl}/.well-known/oauth-protected-resource"`);
    expect(wwwAuth).toContain('scope="notify.write"');
  });

  it("returns a clear config error instead of advertising an invalid issuer path", async () => {
    const r = await worker.fetch(
      new Request(`${testBaseUrl}/.well-known/oauth-authorization-server`),
      { ...blankUrlEnv, OAUTH_ISSUER: `${testBaseUrl}/mcp` }
    );

    expect(r.status).toBe(500);
    const json = await r.json() as Record<string, unknown>;
    expect(json.error).toBe("invalid_config");
    expect(json.error_description).toBeTypeOf("string");
  });

  it("logs request context when /register fails because a secret is missing", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const r = await worker.fetch(
      new Request(`${testBaseUrl}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ redirect_uris: ["https://chatgpt.com/aip/callback"] }),
      }),
      { ...blankUrlEnv, OAUTH_JWT_SIGNING_KEY_B64: "" }
    );

    expect(r.status).toBe(500);
    const json = await r.json() as Record<string, unknown>;
    expect(json.error).toBe("invalid_config");
    expect(json.error_description).toBe("OAUTH_JWT_SIGNING_KEY_B64 is required");
    expect(errorSpy).toHaveBeenCalledWith(
      "Request failed due to invalid config",
      expect.stringContaining("\"path\":\"/register\"")
    );
  });

  it("POST /mcp with access_token query param still returns 401", async () => {
    const r = await req("POST", "/mcp?access_token=fake-token", JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }), { "Content-Type": "application/json" });
    expect(r.status).toBe(401);
  });

  it("GET /mcp with invalid access_token query param returns 401", async () => {
    const r = await req("GET", "/mcp?access_token=fake-token", undefined, { "Accept": "text/event-stream" });
    expect(r.status).toBe(401);
  });
});
