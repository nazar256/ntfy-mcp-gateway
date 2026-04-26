import { describe, expect, it } from "vitest";
import type { Env } from "../config.ts";
import { ConfigError, loadConfig } from "../config.ts";

const baseEnv: Env = {
  NTFY_CONFIG_ENC_KEY_B64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  OAUTH_JWT_SIGNING_KEY_B64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  CSRF_SIGNING_KEY_B64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  OAUTH_ISSUER: "",
  MCP_RESOURCE: "",
  MCP_AUDIENCE: "",
  AUTH_CODE_TTL_SECONDS: "300",
  ACCESS_TOKEN_TTL_SECONDS: "3600",
  AUTHORIZE_RATE_LIMIT_PER_MINUTE: "20",
  TOKEN_RATE_LIMIT_PER_MINUTE: "20",
  MCP_RATE_LIMIT_PER_MINUTE: "60",
  OAUTH_REDIRECT_HTTPS_HOSTS: "chatgpt.com,*.chatgpt.com,chat.openai.com,*.chat.openai.com",
};

describe("loadConfig", () => {
  it("uses deployed request origin when OAuth URLs are blank", () => {
    const config = loadConfig(baseEnv, "https://ntfy-mcp-gateway.xyofn8h7t.workers.dev/mcp");

    expect(config.issuer).toBe("https://ntfy-mcp-gateway.xyofn8h7t.workers.dev");
    expect(config.mcpResource).toBe("https://ntfy-mcp-gateway.xyofn8h7t.workers.dev/mcp");
    expect(config.mcpAudience).toBe("https://ntfy-mcp-gateway.xyofn8h7t.workers.dev/mcp");
  });

  it("keeps localhost defaults for local worker requests", () => {
    const config = loadConfig(baseEnv, "http://127.0.0.1:8787/mcp");

    expect(config.issuer).toBe("http://127.0.0.1:8787");
    expect(config.mcpResource).toBe("http://127.0.0.1:8787/mcp");
    expect(config.mcpAudience).toBe("http://127.0.0.1:8787/mcp");
  });

  it("rejects issuer values that include a path", () => {
    expect(() =>
      loadConfig({ ...baseEnv, OAUTH_ISSUER: "https://example.workers.dev/mcp" })
    ).toThrowError(ConfigError);
  });

  it("rejects audiences that do not match the MCP resource", () => {
    expect(() =>
      loadConfig({
        ...baseEnv,
        OAUTH_ISSUER: "https://example.workers.dev",
        MCP_RESOURCE: "https://example.workers.dev/mcp",
        MCP_AUDIENCE: "https://example.workers.dev/other",
      })
    ).toThrowError(/MCP_AUDIENCE must equal MCP_RESOURCE/);
  });

  it("requires runtime secrets to be present", () => {
    expect(() =>
      loadConfig({ ...baseEnv, OAUTH_JWT_SIGNING_KEY_B64: "" })
    ).toThrowError(/OAUTH_JWT_SIGNING_KEY_B64 is required/);
  });

  it("rejects runtime secrets that are not valid base64", () => {
    expect(() =>
      loadConfig({ ...baseEnv, NTFY_CONFIG_ENC_KEY_B64: "!!!!" })
    ).toThrowError(/NTFY_CONFIG_ENC_KEY_B64 must be valid base64 or base64url/);
  });

  it("rejects runtime secrets with the wrong decoded length", () => {
    expect(() =>
      loadConfig({ ...baseEnv, NTFY_CONFIG_ENC_KEY_B64: "AAAA" })
    ).toThrowError(/NTFY_CONFIG_ENC_KEY_B64 must decode to exactly 32 bytes/);
  });
});
