import { describe, it, expect } from "vitest";
import { isAllowedRedirectUri } from "../oauth/register.ts";

const HTTPS_HOSTS = ["chatgpt.com", "*.chatgpt.com", "chat.openai.com", "*.chat.openai.com"];

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
