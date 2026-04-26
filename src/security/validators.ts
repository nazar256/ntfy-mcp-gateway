export interface NtfyConfig {
  ntfyBaseUrl: string;
  defaultTopic: string;
  allowTopicOverride: boolean;
  ntfyAccessToken?: string;
}

const PRIVATE_IP_PATTERNS = [
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^127\.\d+\.\d+\.\d+$/,
  /^0\.0\.0\.0$/,
  /^169\.254\.\d+\.\d+$/,
  /^::1$/,
  /^fc[0-9a-f]{2}:/i,
  /^fd[0-9a-f]{2}:/i,
  /^fe80:/i,
];

export function validateNtfyBaseUrl(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Invalid ntfy base URL");
  }
  if (parsed.protocol !== "https:") {
    throw new Error("ntfy base URL must use HTTPS");
  }
  if (parsed.username || parsed.password) {
    throw new Error("ntfy base URL must not contain credentials");
  }
  if (parsed.search || parsed.hash) {
    throw new Error("ntfy base URL must not contain query or hash");
  }
  const host = parsed.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    throw new Error("ntfy base URL hostname is not allowed (SSRF protection)");
  }
  for (const pattern of PRIVATE_IP_PATTERNS) {
    if (pattern.test(host)) {
      throw new Error("ntfy base URL points to a private/loopback address (SSRF protection)");
    }
  }
  return parsed.origin;
}

const TOPIC_REGEX = /^[A-Za-z0-9._-]+$/;

export function validateTopic(topic: string): string {
  const t = topic.trim();
  if (!t) throw new Error("Topic is required");
  if (t.length < 8) throw new Error("Topic must be at least 8 characters");
  if (t.length > 128) throw new Error("Topic must be at most 128 characters");
  if (!TOPIC_REGEX.test(t)) {
    throw new Error("Topic contains invalid characters (allowed: A-Za-z0-9._-)");
  }
  return t;
}

export function validateMessageBytes(message: string): void {
  const bytes = new TextEncoder().encode(message);
  if (bytes.length > 4096) {
    throw new Error("Message exceeds 4096 UTF-8 bytes");
  }
}

const CRLF_REGEX = /[\r\n]/;
const MAX_HEADER_LENGTH = 2048;

export function validateHeaderValue(value: string, name: string): void {
  if (CRLF_REGEX.test(value)) {
    throw new Error(`Header ${name} contains CR/LF`);
  }
  if (value.length > MAX_HEADER_LENGTH) {
    throw new Error(`Header ${name} exceeds max length`);
  }
}

export function validateNtfyConfig(config: NtfyConfig): NtfyConfig {
  const validatedUrl = validateNtfyBaseUrl(config.ntfyBaseUrl);
  const validatedTopic = validateTopic(config.defaultTopic);
  return {
    ntfyBaseUrl: validatedUrl,
    defaultTopic: validatedTopic,
    allowTopicOverride: config.allowTopicOverride,
    ntfyAccessToken: config.ntfyAccessToken,
  };
}
