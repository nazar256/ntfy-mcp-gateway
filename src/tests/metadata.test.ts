import { describe, it, expect } from "vitest";
import { getAuthServerMetadata, getProtectedResourceMetadata } from "../oauth/metadata.ts";
import type { Config } from "../config.ts";

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
  redirectHttpsHosts: ["chatgpt.com", "*.chatgpt.com"],
};

describe("OAuth Authorization Server Metadata", () => {
  it("includes resource_parameter_supported", () => {
    const meta = getAuthServerMetadata(config);
    expect(meta.resource_parameter_supported).toBe(true);
  });

  it("includes notify.write scope", () => {
    const meta = getAuthServerMetadata(config);
    expect((meta.scopes_supported as string[]).includes("notify.write")).toBe(true);
  });

  it("includes required endpoints", () => {
    const meta = getAuthServerMetadata(config);
    expect(meta.authorization_endpoint).toBe("https://example.workers.dev/authorize");
    expect(meta.token_endpoint).toBe("https://example.workers.dev/token");
    expect(meta.registration_endpoint).toBe("https://example.workers.dev/register");
    expect(meta.issuer).toBe("https://example.workers.dev");
  });

  it("includes S256 code challenge method", () => {
    const meta = getAuthServerMetadata(config);
    expect((meta.code_challenge_methods_supported as string[]).includes("S256")).toBe(true);
  });
});

describe("Protected Resource Metadata", () => {
  it("root path returns correct resource", () => {
    const meta = getProtectedResourceMetadata(config);
    expect(meta.resource).toBe("https://example.workers.dev/mcp");
  });

  it("includes notify.write scope", () => {
    const meta = getProtectedResourceMetadata(config);
    expect((meta.scopes_supported as string[]).includes("notify.write")).toBe(true);
  });

  it("includes authorization server", () => {
    const meta = getProtectedResourceMetadata(config);
    expect((meta.authorization_servers as string[]).includes("https://example.workers.dev")).toBe(true);
  });
});
