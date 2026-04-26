import type { Env } from "./config.ts";
import { ConfigError, loadConfig } from "./config.ts";
import { getAuthServerMetadata, getProtectedResourceMetadata } from "./oauth/metadata.ts";
import { handleRegister } from "./oauth/register.ts";
import { handleAuthorizeGet, handleAuthorizePost } from "./oauth/authorize.ts";
import { handleToken } from "./oauth/token.ts";
import { handleMcp } from "./mcp/server.ts";

function notFound(): Response {
  return Response.json({ error: "not_found" }, { status: 404 });
}

function methodNotAllowed(allowed: string): Response {
  return new Response(null, {
    status: 405,
    headers: { Allow: allowed },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      const config = loadConfig(env, url);
      const path = url.pathname;
      const method = request.method.toUpperCase();

      if (path === "/") {
        if (method !== "GET") return methodNotAllowed("GET");
        return Response.json({
          service: "ntfy-mcp-gateway",
          mcp_endpoint: "/mcp",
          docs: "See /.well-known/oauth-authorization-server",
        });
      }

      if (path === "/health") {
        if (method !== "GET") return methodNotAllowed("GET");
        return Response.json({ status: "ok" });
      }

      if (path === "/.well-known/oauth-authorization-server") {
        if (method !== "GET") return methodNotAllowed("GET");
        return Response.json(getAuthServerMetadata(config));
      }

      if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp") {
        if (method !== "GET") return methodNotAllowed("GET");
        return Response.json(getProtectedResourceMetadata(config));
      }

      if (path === "/register") {
        if (method !== "POST") return methodNotAllowed("POST");
        return handleRegister(request, config);
      }

      if (path === "/authorize") {
        if (method === "GET") return handleAuthorizeGet(request, config);
        if (method === "POST") return handleAuthorizePost(request, config);
        return methodNotAllowed("GET, POST");
      }

      if (path === "/token") {
        if (method !== "POST") return methodNotAllowed("POST");
        return handleToken(request, config);
      }

      if (path === "/mcp") {
        if (method === "POST" || method === "GET" || method === "DELETE") {
          return handleMcp(request, config);
        }
        return methodNotAllowed("GET, POST, DELETE");
      }

      return notFound();
    } catch (e) {
      if (e instanceof ConfigError) {
        return Response.json(
          { error: "invalid_config", error_description: e.message },
          { status: 500 }
        );
      }
      console.error("Unhandled error:", (e as Error).message);
      return Response.json({ error: "internal_server_error" }, { status: 500 });
    }
  },
};
