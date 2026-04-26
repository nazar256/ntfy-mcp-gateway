# ntfy-mcp-gateway

A remote [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server running on Cloudflare Workers that lets AI assistants (e.g. ChatGPT) send push notifications via [ntfy](https://ntfy.sh).

## Features

- **OAuth 2.0 Authorization Code + PKCE + Refresh Token** flow (no server-side session storage)
- **Stateless design** — ntfy config is AES-GCM encrypted inside the access token
- **Dynamic Client Registration** (RFC 7591)
- **MCP Streamable HTTP transport** via `WebStandardStreamableHTTPServerTransport`
- **`send_notification` MCP tool** with ntfy header support (title, priority, tags, click, delay, markdown, attach)
- **SSRF protection** — validates ntfy base URL against private/loopback ranges
- **Input validation** — topic length/charset, message size, header injection prevention
- **ChatGPT-compatible** — includes OAuth metadata, refresh tokens, and protected resource discovery

## Architecture

```
ChatGPT / MCP client
    │
    │  OAuth PKCE flow
    ▼
/register   → Dynamic Client Registration
/authorize  → Consent form (ntfy server URL, topic, access token)
/token      → Exchange auth code for access token (ntfy config encrypted inside)
    │
    │  Bearer token on every request
    ▼
/mcp        → MCP endpoint (decrypts ntfy config, handles tool calls)
    │
    ▼
ntfy server (push notifications)
```

## Endpoints

| Path | Description |
|---|---|
| `GET /` | Service info |
| `GET /health` | Health check |
| `GET /.well-known/oauth-authorization-server` | OAuth metadata |
| `GET /.well-known/oauth-protected-resource` | Protected resource metadata |
| `GET /.well-known/oauth-protected-resource/mcp` | Protected resource metadata for MCP path |
| `POST /register` | Dynamic Client Registration |
| `GET /authorize` | OAuth consent form |
| `POST /authorize` | Submit consent form |
| `POST /token` | Token exchange |
| `GET,POST,DELETE /mcp` | MCP Streamable HTTP endpoint |

## ChatGPT Connector Values

When creating the ChatGPT custom MCP connector, use these exact values:

- **MCP Server URL:** `https://your-worker-domain.workers.dev/mcp`
- **Authorization server base URL:** `https://your-worker-domain.workers.dev`
- **Resource:** `https://your-worker-domain.workers.dev/mcp`

Do not use the Worker origin alone as the MCP Server URL; it must include `/mcp`.
Clients only receive refresh tokens if they register `grant_types` including `refresh_token`.

## MCP Tool

### `send_notification`

Sends a push notification through the user's configured ntfy server.

| Parameter | Type | Description |
|---|---|---|
| `message` | string (required) | Notification body (max 4096 bytes) |
| `title` | string | Notification title |
| `topic` | string | Topic override (if allowed) |
| `tags` | string[] | Tags / emoji shortcuts |
| `priority` | 1–5 | Notification priority |
| `click` | URL | URL to open on click |
| `delay` | string | Delivery delay (e.g. `30min`, `9am`) |
| `markdown` | boolean | Render body as Markdown |
| `attach` | URL | Attachment URL |
| `filename` | string | Attachment filename |

## Production Deployment

### 1) Generate keys/secrets

```bash
openssl rand -base64 32   # NTFY_CONFIG_ENC_KEY_B64
openssl rand -base64 32   # OAUTH_JWT_SIGNING_KEY_B64
openssl rand -base64 32   # CSRF_SIGNING_KEY_B64
```

### 2) Set Worker runtime secrets (one-time per environment)

```bash
wrangler secret put NTFY_CONFIG_ENC_KEY_B64
wrangler secret put OAUTH_JWT_SIGNING_KEY_B64
wrangler secret put CSRF_SIGNING_KEY_B64
```

### 3) Configure Worker vars in `wrangler.toml`

Use your deployed Worker URL consistently:

```toml
[vars]
OAUTH_ISSUER = "https://your-worker-domain.workers.dev"
MCP_RESOURCE = "https://your-worker-domain.workers.dev/mcp"
MCP_AUDIENCE = "https://your-worker-domain.workers.dev/mcp"
```

`MCP_RESOURCE` and `MCP_AUDIENCE` should normally match exactly.

### 4) Configure GitHub Actions deployment secrets

Set repository secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

Create a **least-privilege** API token in Cloudflare with only permissions needed to deploy Workers (for a specific account and, ideally, scoped resources).

### 5) Manual deploy (optional)

```bash
npm run deploy
```

### 6) Automatic deploy on merge to `main`

This repo includes `.github/workflows/deploy.yml` that:

1. Runs tests and typecheck on push to `main`.
2. Deploys with Wrangler only if checks pass.

## Local Development

```bash
npm install
npm run dev
```

The worker is available at `http://127.0.0.1:8787`.

## Test commands

```bash
npm test
npm run typecheck
```

## Manual Smoke Tests

### Local metadata/auth smoke

```bash
npm run dev
curl -i http://127.0.0.1:8787/health
curl -i http://127.0.0.1:8787/.well-known/oauth-authorization-server
curl -i http://127.0.0.1:8787/.well-known/oauth-protected-resource
curl -i http://127.0.0.1:8787/.well-known/oauth-protected-resource/mcp
curl -i http://127.0.0.1:8787/mcp
```

Expected results:

- health is `200` with `{ "status": "ok" }`.
- metadata routes return JSON.
- unauthenticated `/mcp` returns `401` and `WWW-Authenticate` includes `resource_metadata` and `scope="notify.write"`.

### Direct ntfy smoke

```bash
TEST_NTFY_TOPIC="<random-topic-subscribed-on-phone-or-browser>"
curl -d "direct ntfy smoke $(date -Iseconds)" "https://ntfy.sh/$TEST_NTFY_TOPIC"
```

### ChatGPT smoke (after deploy)

1. Subscribe to a random ntfy topic on phone/browser.
2. Deploy Worker with production vars/secrets.
3. In ChatGPT custom MCP connector UI, use:

    ```text
    MCP Server URL: https://your-worker-domain.workers.dev/mcp
    Authorization server base URL: https://your-worker-domain.workers.dev
    Resource: https://your-worker-domain.workers.dev/mcp
    ```

4. Complete OAuth form:

   ```text
   ntfyBaseUrl: https://ntfy.sh
   defaultTopic: <random topic>
   allowTopicOverride: false
   ntfyAccessToken: blank
   ```

5. Refresh tools/actions if ChatGPT does not show the tool.
6. Ask ChatGPT:

   ```text
   Use my ntfy connector to send me a notification saying: ChatGPT MCP smoke test <current time>.
   ```

7. Confirm ChatGPT asks for write-action approval and notification arrives.
8. Test forbidden override:

   ```text
   Send a notification to topic other-topic saying: should be blocked.
   ```

   Expected: tool error because override is disabled.
9. Reconnect with override enabled and verify override works only then.

## Security Notes

- The ntfy access token and server config are encrypted with AES-256-GCM inside the JWT access token.
- PKCE S256 is required.
- SSRF protection blocks local/private targets for `ntfyBaseUrl`.
- **Use random, hard-to-guess public ntfy topics**. Public topics are shared/guessable if names are predictable.
- CSRF protection is enforced on the consent form.
