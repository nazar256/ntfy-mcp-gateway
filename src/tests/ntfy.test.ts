import { describe, it, expect, vi } from "vitest";
import { publishNotification } from "../ntfy/client.ts";
import { validateNtfyBaseUrl, validateTopic, validateMessageBytes } from "../security/validators.ts";
import type { NtfyConfig } from "../security/validators.ts";

const baseConfig: NtfyConfig = {
  ntfyBaseUrl: "https://ntfy.sh",
  defaultTopic: "test-topic-abc123",
  allowTopicOverride: false,
};

describe("ntfy URL validation", () => {
  it("accepts https://ntfy.sh", () => {
    expect(validateNtfyBaseUrl("https://ntfy.sh")).toBe("https://ntfy.sh");
  });

  it("strips trailing slash", () => {
    expect(validateNtfyBaseUrl("https://ntfy.sh/")).toBe("https://ntfy.sh");
  });

  it("rejects http", () => {
    expect(() => validateNtfyBaseUrl("http://ntfy.sh")).toThrow("HTTPS");
  });

  it("rejects localhost", () => {
    expect(() => validateNtfyBaseUrl("https://localhost")).toThrow();
  });

  it("rejects .local", () => {
    expect(() => validateNtfyBaseUrl("https://server.local")).toThrow();
  });

  it("rejects private IP 192.168.x.x", () => {
    expect(() => validateNtfyBaseUrl("https://192.168.1.1")).toThrow("private");
  });

  it("rejects credentials in URL", () => {
    expect(() => validateNtfyBaseUrl("https://user:pass@ntfy.sh")).toThrow("credentials");
  });
});

describe("ntfy topic validation", () => {
  it("accepts valid topic", () => {
    expect(validateTopic("my-topic-abc123")).toBe("my-topic-abc123");
  });

  it("rejects short topic", () => {
    expect(() => validateTopic("abc")).toThrow("8 characters");
  });

  it("rejects topic with spaces", () => {
    expect(() => validateTopic("my topic abc12")).toThrow("invalid characters");
  });

  it("rejects topic with slash", () => {
    expect(() => validateTopic("my/topic/path1")).toThrow("invalid characters");
  });

  it("trims topic", () => {
    expect(validateTopic("  validtopic1  ")).toBe("validtopic1");
  });
});

describe("ntfy message validation", () => {
  it("accepts normal message", () => {
    expect(() => validateMessageBytes("Hello world")).not.toThrow();
  });

  it("rejects message over 4096 bytes", () => {
    expect(() => validateMessageBytes("x".repeat(4097))).toThrow("4096");
  });
});

describe("ntfy client publishNotification", () => {
  it("sends to default topic", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    const result = await publishNotification({ message: "Hello ntfy!" }, baseConfig, mockFetch);
    expect(result.success).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith(
      "https://ntfy.sh/test-topic-abc123",
      expect.objectContaining({ method: "POST", body: "Hello ntfy!" })
    );
  });

  it("rejects topic override when disabled", async () => {
    const mockFetch = vi.fn();
    const result = await publishNotification(
      { message: "Hello", topic: "override-topic-xyz" },
      baseConfig,
      mockFetch
    );
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/override/i);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("allows topic override when enabled", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    const config: NtfyConfig = { ...baseConfig, allowTopicOverride: true };
    const result = await publishNotification(
      { message: "Hello", topic: "override-topic-xyz" },
      config,
      mockFetch
    );
    expect(result.success).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith(
      "https://ntfy.sh/override-topic-xyz",
      expect.anything()
    );
  });

  it("sets Title header when provided", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    await publishNotification({ message: "Hello", title: "My Title" }, baseConfig, mockFetch);
    const callArgs = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = callArgs[1].headers as Record<string, string>;
    expect(headers["Title"]).toBe("My Title");
  });

  it("sets Priority header when provided", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    await publishNotification({ message: "Hello", priority: 4 }, baseConfig, mockFetch);
    const callArgs = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = callArgs[1].headers as Record<string, string>;
    expect(headers["Priority"]).toBe("4");
  });

  it("returns error on ntfy non-2xx", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("Forbidden", { status: 403 }));
    const result = await publishNotification({ message: "Hello" }, baseConfig, mockFetch);
    expect(result.success).toBe(false);
    expect(result.status).toBe(403);
  });

  it("sets Authorization header when access token configured", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    const config: NtfyConfig = { ...baseConfig, ntfyAccessToken: "secret-token" };
    await publishNotification({ message: "Hello" }, config, mockFetch);
    const callArgs = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = callArgs[1].headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer secret-token");
  });

  it("sets Tags header", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    await publishNotification({ message: "Hello", tags: ["warning", "computer"] }, baseConfig, mockFetch);
    const callArgs = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = callArgs[1].headers as Record<string, string>;
    expect(headers["Tags"]).toBe("warning,computer");
  });
  it("maps optional ntfy headers for publish", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("", { status: 200 }));
    await publishNotification(
      {
        message: "Header test",
        title: "Title",
        tags: ["a", "b"],
        priority: 5,
        click: "https://example.com",
        delay: "10min",
        markdown: true,
        attach: "https://example.com/file.png",
        filename: "file.png",
      },
      baseConfig,
      mockFetch
    );

    const [, reqInit] = mockFetch.mock.calls[0] as [string, RequestInit];
    const headers = reqInit.headers as Record<string, string>;
    expect(headers["Title"]).toBe("Title");
    expect(headers["Tags"]).toBe("a,b");
    expect(headers["Priority"]).toBe("5");
    expect(headers["Click"]).toBe("https://example.com");
    expect(headers["Delay"]).toBe("10min");
    expect(headers["Markdown"]).toBe("yes");
    expect(headers["Attach"]).toBe("https://example.com/file.png");
    expect(headers["Filename"]).toBe("file.png");
  });

  it("rejects CR/LF header injection", async () => {
    const mockFetch = vi.fn();
    const result = await publishNotification({ message: "Hello", title: "bad\nheader" }, baseConfig, mockFetch);
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/CR\/LF/);
    expect(mockFetch).not.toHaveBeenCalled();
  });

});
