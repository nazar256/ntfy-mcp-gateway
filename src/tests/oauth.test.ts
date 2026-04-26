import { describe, it, expect } from "vitest";
import { encryptPayload, decryptPayload, signJwt, verifyJwt } from "../security/crypto.ts";

const TEST_KEY_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

describe("AES-GCM encryption", () => {
  it("encrypts and decrypts correctly", async () => {
    const plaintext = JSON.stringify({ ntfyBaseUrl: "https://ntfy.sh", defaultTopic: "test-topic-123456" });
    const aad = "client123:https://chatgpt.com/cb";
    const enc = await encryptPayload(plaintext, aad, TEST_KEY_B64);
    const dec = await decryptPayload(enc, TEST_KEY_B64);
    expect(dec).toBe(plaintext);
  });

  it("fails decryption with wrong AAD", async () => {
    const plaintext = "test";
    const enc = await encryptPayload(plaintext, "correct-aad", TEST_KEY_B64);
    const tamperedEnc = { ...enc, aad: "d3Jvbmctc2FsdA==" };
    await expect(decryptPayload(tamperedEnc, TEST_KEY_B64)).rejects.toThrow();
  });
});

describe("JWT sign/verify", () => {
  it("signs and verifies JWT", async () => {
    const token = await signJwt({ sub: "test", type: "test" }, TEST_KEY_B64, 60);
    const verified = await verifyJwt(token, TEST_KEY_B64);
    expect(verified.payload["sub"]).toBe("test");
  });

  it("verifies issuer", async () => {
    const token = await signJwt({ iss: "https://example.com", type: "test" }, TEST_KEY_B64, 60);
    await expect(
      verifyJwt(token, TEST_KEY_B64, { issuer: "https://wrong.com" })
    ).rejects.toThrow();
  });

  it("rejects expired token", async () => {
    const token = await signJwt({ sub: "test" }, TEST_KEY_B64, -1);
    await expect(verifyJwt(token, TEST_KEY_B64)).rejects.toThrow();
  });
});
