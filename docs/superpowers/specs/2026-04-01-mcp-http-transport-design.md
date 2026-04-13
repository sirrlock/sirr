# MCP HTTP Transport for sirrd

**Date:** 2026-04-01
**Status:** Draft
**Scope:** New `/mcp` route in sirrd implementing MCP Streamable HTTP transport

---

## Problem

The `@sirrlock/mcp` npm package (stdio transport) requires Node.js on the user's machine. Users must run `npx` or install globally. This adds friction for Cloud users who just want to point Claude at their vault.

Other MCP servers (Zapier, Notion, Stripe, PayPal) offer HTTP transport — a single URL, no local install. Claude Code recommends HTTP as the preferred transport.

## Solution

Add a `/mcp` HTTP endpoint directly to sirrd that speaks the MCP Streamable HTTP protocol. Since sirrd already runs at `sirr.sirrlock.com` for Cloud users and on `localhost:39999` for self-hosted, the endpoint is automatically available everywhere sirrd runs.

### Install experience

```bash
# Cloud — zero install
claude mcp add --transport http sirr https://sirr.sirrlock.com/mcp \
  --header "Authorization: Bearer your-principal-key"

# Self-hosted — zero install
claude mcp add --transport http sirr http://localhost:39999/mcp \
  --header "Authorization: Bearer your-key"
```

No npm. No npx. No Node.js. Works with Claude Code, VS Code Copilot, OpenAI Agents SDK, Cursor, Windsurf, Gemini CLI — any client that speaks MCP over HTTP.

### Coexistence with stdio

The `@sirrlock/mcp` npm package (stdio transport) remains for:
- Offline / air-gapped environments
- Users who prefer local execution
- Backwards compatibility

Both transports expose the same 5 tools, same behavior. Different wire protocol.

---

## Architecture

### Core principle: protocol adapter, not new API

The MCP handler is a **thin JSON-RPC → HTTP translator**. It never touches the store directly. Every tool call is mapped to an internal HTTP request against sirrd's existing REST endpoints. This means:

- Zero duplicated security logic (auth, validation, permissions, rate limiting)
- Every audit event fires identically regardless of entry point (REST vs MCP)
- Future handler improvements apply to MCP automatically
- Attack surface is limited to JSON-RPC parsing — everything else is delegated

### Request flow

```
Client                          sirrd /mcp handler                    sirrd REST API
──────                          ───────────────                       ──────────────
POST /mcp                   →   parse JSON-RPC envelope
Authorization: Bearer key       extract auth via require_auth middleware

tools/call "read_secret"    →   map to: GET /orgs/{org_id}/secrets/DB_URL
  {name: "DB_URL"}              (internal HTTP to 127.0.0.1, same Bearer token)

                                                                  →   require_auth middleware
                                                                  →   permission check
                                                                  →   store.org_get()
                                                                  →   audit log
                                                                  ←   200 {value: "postgres://..."}

                            ←   translate to JSON-RPC result
←  {jsonrpc: "2.0",
    id: 3,
    result: {content: [{type: "text", text: "postgres://..."}]}}
```

### HTTP methods on `/mcp`

| Method | Behavior |
|--------|----------|
| POST   | Accept JSON-RPC request, return JSON response |
| GET    | 405 Method Not Allowed (no server-initiated messages) |
| DELETE | 200 OK (session cleanup no-op, stateless) |

Since Sirr's 5 tools are all request/response with no server push, the full SSE streaming machinery is unnecessary. The endpoint uses JSON response mode only.

---

## Feature flag

| Env Var | Default | Description |
|---------|---------|-------------|
| `SIRR_MCP` | `false` | Enable MCP HTTP endpoint at `/mcp`. When `false`, `/mcp` returns 404. |

Added to `ServerConfig` alongside existing env vars. Logged at startup when enabled.

---

## Tool → REST mapping

Each MCP tool call translates to exactly one internal HTTP request:

### store_secret

**Without `name` (anonymous dead drop):**

```
tools/call "store_secret" {value: "bar", max_reads: 1}
→ POST /secrets
  Body: {"value": "bar", "max_reads": 1}
← 201 {"id": "a1b2c3..."} → "Secret pushed. ID: a1b2c3..."
```

**With `name` (org-scoped, requires principal auth):**

```
tools/call "store_secret" {value: "bar", name: "FOO", ttl_seconds: 3600}
→ POST /orgs/{auth.org_id}/secrets
  Body: {"key": "FOO", "value": "bar", "ttl_seconds": 3600}
← 201 {"key": "FOO"} → "Secret 'FOO' stored in org."
← 409 → "Secret 'FOO' already exists. Delete it first or choose a different name."
```

### read_secret

**By ID (public dead drop):**

```
tools/call "read_secret" {id: "a1b2c3"}
→ GET /secrets/a1b2c3
← 200 {"value": "bar"} → "bar"
← 404 → "Secret not found, expired, or already burned."
← 410 → "Secret not found, expired, or already burned."
```

**By name (org-scoped):**

```
tools/call "read_secret" {name: "FOO"}
→ GET /orgs/{auth.org_id}/secrets/FOO
← 200 {"value": "bar"} → "bar"
← 404 → "Secret 'FOO' not found, expired, or already burned."
```

### check_secret

```
tools/call "check_secret" {name: "FOO"}
→ HEAD /orgs/{auth.org_id}/secrets/FOO
← 200 → "Secret 'FOO' is active."
← 404 → "Secret 'FOO' not found."
← 410 → "Secret 'FOO' is sealed (reads exhausted, not yet deleted)."
```

### share_secret

```
tools/call "share_secret" {value: "hunter2"}
→ POST https://sirrlock.com/api/public/secret
  Body: {"value": "hunter2"}
← 200 {"key": "x9f2..."} → "Share link: https://sirr.sirrlock.com/s/x9f2... (burns after one read)"
```

Note: this is the only tool that makes an **external** HTTP call (to sirrlock.com). All others are internal to sirrd.

### audit

```
tools/call "audit" {since: 1700000000, action: "secret.read", limit: 10}
→ GET /orgs/{auth.org_id}/audit?since=1700000000&action=secret.read&limit=10
← 200 {"events": [...]} → formatted table
← 200 {"events": []} → "No audit events found."
```

---

## JSON-RPC protocol

### Requests the handler must support

| Method | Purpose | Response |
|--------|---------|----------|
| `initialize` | Protocol handshake | Server info + capabilities |
| `notifications/initialized` | Client ack (notification) | 202 Accepted (no body) |
| `tools/list` | Enumerate available tools | 5 tool definitions with schemas |
| `tools/call` | Execute a tool | Tool result (text content) |

### initialize response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2025-11-05",
    "capabilities": {
      "tools": {}
    },
    "serverInfo": {
      "name": "sirr",
      "version": "1.x.y"
    }
  }
}
```

### tools/list response

Returns the same 5 tool definitions as the stdio transport (name, description, inputSchema). Tool descriptions include the instruction for Claude not to memorize or repeat secret values.

### tools/call response (success)

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {"type": "text", "text": "the secret value or status message"}
    ]
  }
}
```

### tools/call response (tool error)

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {"type": "text", "text": "Error: 401 — unauthorized"}
    ],
    "isError": true
  }
}
```

Note: tool-level errors are **not** JSON-RPC errors. They return a normal `result` with `isError: true`. JSON-RPC `error` is reserved for protocol-level failures (malformed request, unknown method).

### Protocol-level errors

```json
{
  "jsonrpc": "2.0",
  "id": null,
  "error": {
    "code": -32601,
    "message": "Method not found: resources/list"
  }
}
```

| Code | Meaning |
|------|---------|
| -32700 | Parse error (invalid JSON) |
| -32600 | Invalid request (missing jsonrpc/method) |
| -32601 | Method not found |
| -32602 | Invalid params |

---

## Auth

Uses the **existing `require_auth` middleware** on the `/mcp` route. The `Authorization: Bearer` header resolves to:

- `ResolvedAuth::Principal { org_id, permissions, ... }` — org context available, permission checks apply
- `ResolvedAuth::Master` — full access, no org context (self-hosted single-user)

For `store_secret`/`read_secret` with a name, the handler reads `auth.org_id()` to construct the internal URL. If auth is Master (no org), the handler returns an error: "Named secrets require a principal key with an org. Use an anonymous dead drop or configure a principal."

For anonymous dead drops (`store_secret` without name, `read_secret` by ID) and `share_secret`, auth is not strictly required but the middleware still runs (the existing REST endpoints handle this).

---

## Security considerations

### Attack surface

The MCP handler introduces exactly one new code path: **JSON-RPC parsing**. All business logic is delegated to existing handlers via internal HTTP.

| Threat | Mitigation |
|--------|-----------|
| JSON-RPC injection | Standard serde_json deserialization, no eval |
| Auth bypass | Same `require_auth` middleware as all other routes |
| Permission escalation | Internal HTTP requests carry the same auth context |
| DoS via large payloads | Existing Axum body size limits apply |
| Rate limiting bypass | Same `tower_governor` rate limiter applies to `/mcp` |
| SSRF via share_secret | Hardcoded sirrlock.com URL, not user-controllable |
| Replay attacks | Same as REST API — stateless, no sessions to hijack |

### Internal HTTP requests

The MCP handler makes requests to `http://127.0.0.1:{port}` with the **same Bearer token** from the original request. This means:

- The internal request passes through the full middleware stack
- No privilege escalation is possible — the internal call has identical auth context
- Rate limiting applies twice (once on `/mcp`, once on the internal endpoint) — acceptable, could exempt internal calls later if needed

### What the MCP handler does NOT do

- Does not read from or write to the store directly
- Does not construct SQL/redb queries
- Does not decrypt secrets
- Does not evaluate expressions from user input
- Does not maintain state between requests
- Does not open persistent connections

---

## Implementation scope

### New files

| File | Purpose |
|------|---------|
| `crates/sirr-server/src/mcp.rs` | MCP handler: JSON-RPC parsing, tool dispatch, response formatting |

### Modified files

| File | Change |
|------|--------|
| `crates/sirr-server/src/server.rs` | Add `SIRR_MCP` to `ServerConfig`, conditionally mount `/mcp` route |
| `crates/sirr-server/src/lib.rs` | Add `mcp_enabled: bool` to `AppState` (or just read from config) |

### No new dependencies

JSON-RPC is plain JSON — `serde_json` handles it. Internal HTTP uses the existing `reqwest` dependency. No MCP SDK crate needed.

### Estimated size

~200-300 lines of Rust in `mcp.rs`:
- ~30 lines: JSON-RPC types (Request, Response, Error structs)
- ~40 lines: tool definitions (name, description, inputSchema for 5 tools)
- ~20 lines: POST handler (parse, dispatch, respond)
- ~100 lines: tool dispatch (5 match arms, each mapping to an internal HTTP call)
- ~30 lines: response translation (HTTP status → JSON-RPC result/error)
- ~20 lines: GET/DELETE handlers (trivial)

---

## Documentation updates

After implementation, update all 4 doc sites to add the HTTP transport option:

| Site | File | Change |
|------|------|--------|
| mcp/ | README.md | Add HTTP transport install section |
| sirrlock.com | docs/mcp/page.tsx | Add HTTP transport as primary install method |
| sirrlock.com | mcp/page.tsx | Update "One line" setup to show HTTP transport |
| sirr.dev | mcp/page.mdx | Add HTTP transport config section |

The HTTP transport becomes the **recommended** method for Cloud users. stdio remains for self-hosted/offline.

---

## Testing

### Unit tests

In `crates/sirr-server/src/mcp.rs` (or a test module):
- JSON-RPC parsing: valid request, batch, notification, malformed
- Tool dispatch: each of the 5 tools with valid args
- Error handling: unknown tool, missing required params, unknown method
- Auth: missing token → 401, master key → works, principal → org resolved

### Integration tests

Extend existing integration test suite:
- Start sirrd with `SIRR_MCP=true`
- POST JSON-RPC `initialize` → get server info
- POST `tools/call` store_secret → verify secret created via REST API
- POST `tools/call` read_secret → verify value returned and burned
- POST `tools/call` audit → verify events listed
- Verify `/mcp` returns 404 when `SIRR_MCP=false`

### Manual testing

```bash
# Start sirrd with MCP enabled
SIRR_MCP=true SIRR_MASTER_API_KEY=test sirrd serve

# Test with curl
curl -X POST http://localhost:39999/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}'

# Test with Claude Code
claude mcp add --transport http sirr http://localhost:39999/mcp \
  --header "Authorization: Bearer test"
```

---

## Out of scope

- **OAuth flow** — Bearer token auth only for v1. OAuth can be added later.
- **SSE streaming** — No server-initiated messages, so JSON response mode only.
- **Session management** — Stateless. No session IDs.
- **Resumability / event store** — Not needed without SSE.
- **Channels** — Could be added later (e.g., secret expiry notifications).
- **Batch requests** — Single request per POST for v1. Batch can be added later.
- **`@sirrlock/mcp` changes** — The npm package stays as-is (stdio transport).

---

## Rollout

1. Ship with `SIRR_MCP=false` default — zero impact on existing users
2. Test on `sirr.sirrlock.com` by setting `SIRR_MCP=true` in Docker Compose
3. Update docs to show HTTP transport as recommended for Cloud
4. Flip `SIRR_MCP` default to `true` in a future release once proven stable
