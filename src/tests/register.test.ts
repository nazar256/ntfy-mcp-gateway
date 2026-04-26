import { describe, it, expect } from "vitest";
import type { Config } from "../config.ts";
import { deriveClientId, isAllowedRedirectUri, isValidClientIdForRedirectUri, validateRedirectUri } from "../oauth/register.ts";

const HTTPS_HOSTS = ["chatgpt.com", "*.chatgpt.com", "chat.openai.com", "*.chat.openai.com"];
const config: Config = {
  encKeyB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  jwtSigningKeyB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  csrfSigningKeyB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  issuer: "https://example.workers.dev",
  mcpResource: "https://example.workers.dev/mcp",
  mcpAudience: "https://example.workers.dev/mcp",
  authCodeTtl: 300,
  accessTokenTtl: 3600,
  authorizeRateLimit: 20,
  tokenRateLimit: 20,
  mcpRateLimit: 60,
  redirectHttpsHosts: HTTPS_HOSTS,
};

describe("DCR redirect URI validation", () => {
  it("allows chatgpt.com redirect", () => {
    expect(isAllowedRedirectUri("https://chatgpt.com/callback", HTTPS_HOSTS)).toBe(true);
  });

  it("allows subdomain of chatgpt.com", () => {
    expect(isAllowedRedirectUri("https://app.chatgpt.com/callback", HTTPS_HOSTS)).toBe(true);
  });

  it("allows localhost http", () => {
    expect(isAllowedRedirectUri("http://localhost:3000/cb", HTTPS_HOSTS)).toBe(true);
  });

  it("allows 127.0.0.1", () => {
    expect(isAllowedRedirectUri("http://127.0.0.1:8080/cb", HTTPS_HOSTS)).toBe(true);
  });

  it("rejects fragments", () => {
    const result = validateRedirectUri("https://chatgpt.com/callback#fragment", HTTPS_HOSTS);
    expect(result.ok).toBe(false);
  });

  it("rejects userinfo", () => {
    const result = validateRedirectUri("https://user:pass@chatgpt.com/callback", HTTPS_HOSTS);
    expect(result.ok).toBe(false);
  });

  it("rejects http non-localhost", () => {
    expect(isAllowedRedirectUri("http://evil.com/callback", HTTPS_HOSTS)).toBe(false);
  });

  it("rejects unknown https host", () => {
    expect(isAllowedRedirectUri("https://evil.com/callback", HTTPS_HOSTS)).toBe(false);
  });

  it("rejects invalid URL", () => {
    expect(isAllowedRedirectUri("not-a-url", HTTPS_HOSTS)).toBe(false);
  });
});

describe("DCR client ID derivation", () => {
  it("derives the same client_id regardless of redirect URI order", async () => {
    const a = await deriveClientId([
      "https://chatgpt.com/aip/callback",
      "https://chat.openai.com/aip/callback",
    ], config);
    const b = await deriveClientId([
      "https://chat.openai.com/aip/callback",
      "https://chatgpt.com/aip/callback",
    ], config);

    expect(a).toBe(b);
  });

  it("validates a structured client_id for any registered redirect URI", async () => {
    const clientId = await deriveClientId([
      "https://chatgpt.com/aip/callback",
      "http://localhost:3333/callback",
    ], config);

    await expect(isValidClientIdForRedirectUri(clientId, "https://chatgpt.com/aip/callback", config)).resolves.toBe(true);
    await expect(isValidClientIdForRedirectUri(clientId, "http://localhost:3333/callback", config)).resolves.toBe(true);
    await expect(isValidClientIdForRedirectUri(clientId, "https://chat.openai.com/aip/callback", config)).resolves.toBe(false);
  });
});
