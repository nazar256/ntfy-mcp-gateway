import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import type { Config } from "../config.ts";
import { verifyJwt, decryptPayload } from "../security/crypto.ts";
import { validateNtfyConfig } from "../security/validators.ts";
import type { NtfyConfig } from "../security/validators.ts";
import { publishNotification } from "../ntfy/client.ts";

async function extractBearerToken(request: Request): Promise<string | null> {
  const auth = request.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return null;
  return auth.slice(7);
}

function unauthorizedResponse(issuer: string, error = "invalid_token"): Response {
  return new Response(
    JSON.stringify({ error, error_description: "Bearer token required" }),
    {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        "WWW-Authenticate": `Bearer realm="${issuer}", error="${error}", resource_metadata="${issuer}/.well-known/oauth-protected-resource", scope="notify.write"`,
      },
    }
  );
}

export async function handleMcp(request: Request, config: Config): Promise<Response> {
  const token = await extractBearerToken(request);
  if (!token) {
    return unauthorizedResponse(config.issuer);
  }

  let tokenPayload: Record<string, unknown>;
  try {
    const verified = await verifyJwt(token, config.jwtSigningKeyB64, {
      issuer: config.issuer,
      audience: config.mcpAudience,
    });
    tokenPayload = verified.payload;
  } catch {
    return unauthorizedResponse(config.issuer);
  }

  if (tokenPayload["type"] !== "access_token") {
    return unauthorizedResponse(config.issuer);
  }

  const tokenResource = tokenPayload["resource"] as string | undefined;
  if (tokenResource && tokenResource !== config.mcpResource) {
    return unauthorizedResponse(config.issuer);
  }

  const ntfyEnc = tokenPayload["ntfy_enc"] as string | undefined;
  const ntfyIv = tokenPayload["ntfy_iv"] as string | undefined;
  const ntfyAad = tokenPayload["ntfy_aad"] as string | undefined;

  if (!ntfyEnc || !ntfyIv || !ntfyAad) {
    return unauthorizedResponse(config.issuer, "invalid_token");
  }

  let ntfyConfig: NtfyConfig;
  try {
    const plaintext = await decryptPayload({ iv: ntfyIv, ct: ntfyEnc, aad: ntfyAad }, config.encKeyB64);
    const parsed = JSON.parse(plaintext) as NtfyConfig;
    ntfyConfig = validateNtfyConfig(parsed);
  } catch {
    return unauthorizedResponse(config.issuer, "invalid_token");
  }

  const server = new McpServer({
    name: "ntfy-mcp-gateway",
    version: "1.0.0",
  });

  server.tool(
    "send_notification",
    "Send a push notification through the user-configured ntfy server.",
    {
      message: z.string().max(4096).describe("The notification message body (max 4096 UTF-8 bytes)"),
      title: z.string().optional().describe("Optional notification title"),
      topic: z.string().optional().describe("Optional topic override (only if allowed by authorization settings)"),
      tags: z.array(z.string()).optional().describe("Optional tags/emojis for the notification"),
      priority: z.number().int().min(1).max(5).optional().describe("Notification priority 1 (min) to 5 (max)"),
      click: z.string().url().optional().describe("URL to open when notification is clicked"),
      delay: z.string().optional().describe("Delay delivery (e.g. '30min', '9am')"),
      markdown: z.boolean().optional().describe("Render message as Markdown"),
      attach: z.string().url().optional().describe("URL of attachment"),
      filename: z.string().optional().describe("Filename for attachment"),
    },
    async (args) => {
      const result = await publishNotification(args, ntfyConfig);
      if (!result.success) {
        return {
          isError: true,
          content: [{ type: "text" as const, text: result.error || "Failed to send notification" }],
        };
      }
      return {
        content: [{ type: "text" as const, text: "Notification sent successfully" }],
      };
    }
  );

  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  await server.connect(transport);
  try {
    const response = await transport.handleRequest(request);
    return response;
  } finally {
    await server.close().catch(() => {});
  }
}
