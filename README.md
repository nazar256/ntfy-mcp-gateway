# ntfy-mcp-gateway

A remote [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server running on Cloudflare Workers that lets AI assistants (e.g. ChatGPT) send push notifications via [ntfy](https://ntfy.sh).

## Features

- **OAuth 2.0 Authorization Code + PKCE** flow (no server-side session storage)
- **Stateless design** — ntfy config is AES-GCM encrypted inside the access token
- **Dynamic Client Registration** (RFC 7591)
- **MCP Streamable HTTP transport** via `WebStandardStreamableHTTPServerTransport`
- **`send_notification` MCP tool** with full ntfy header support (title, priority, tags, click, delay, markdown, attach)
- **SSRF protection** — validates ntfy base URL against private/loopback ranges
- **Input validation** — topic length/charset, message size, header injection prevention
- **ChatGPT-compatible** — implements the `resource_metadata` discovery required by ChatGPT's connector flow

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
| `POST /register` | Dynamic Client Registration |
| `GET /authorize` | OAuth consent form |
| `POST /authorize` | Submit consent form |
| `POST /token` | Token exchange |
| `GET,POST,DELETE /mcp` | MCP Streamable HTTP endpoint |

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

## Deployment

### Prerequisites

- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) (`npm install -g wrangler`)
- A Cloudflare account

### 1. Generate secrets

```bash
# 32-byte AES key for encrypting ntfy config in tokens
openssl rand -base64 32   # → NTFY_CONFIG_ENC_KEY_B64

# 32-byte key for signing JWTs
openssl rand -base64 32   # → OAUTH_JWT_SIGNING_KEY_B64

# 32-byte key for CSRF token HMAC
openssl rand -base64 32   # → CSRF_SIGNING_KEY_B64
```

### 2. Set secrets in Wrangler

```bash
wrangler secret put NTFY_CONFIG_ENC_KEY_B64
wrangler secret put OAUTH_JWT_SIGNING_KEY_B64
wrangler secret put CSRF_SIGNING_KEY_B64
```

### 3. Configure wrangler.toml

```toml
[vars]
OAUTH_ISSUER = "https://your-worker.your-subdomain.workers.dev"
MCP_RESOURCE = "https://your-worker.your-subdomain.workers.dev/mcp"
MCP_AUDIENCE = "https://your-worker.your-subdomain.workers.dev/mcp"
```

### 4. Deploy

```bash
npm run deploy
```

## Local Development

```bash
# Install dependencies
npm install

# Start local dev server
npm run dev
```

The worker will be available at `http://localhost:8787`.

## Testing

```bash
npm test
```

## Security Notes

- The ntfy access token and server config are encrypted with AES-256-GCM inside the JWT access token. The encryption key never leaves the Worker environment.
- PKCE S256 is required — plain `code_challenge_method` is rejected.
- SSRF protection prevents configuring private/loopback addresses as the ntfy server.
- Topics must be at least 8 characters to discourage guessable names on public ntfy.sh.
- CSRF protection on the consent form via HMAC-signed state token.
