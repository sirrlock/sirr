# Sirr

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![CI](https://github.com/sirrlock/sirr/actions/workflows/ci.yml/badge.svg)](https://github.com/sirrlock/sirr/actions/workflows/ci.yml)

**The secret manager built for the AI era. Every secret expires. By design.**

Sirr is a self-hosted vault where secrets are ephemeral by default — not as a feature you opt into, but as the core philosophy. Set a TTL, a read limit, or both. Once the condition is met, the secret is gone. No cleanup, no stale credentials, no blast radius.

Single binary. Single file database. Zero runtime dependencies.

---

## The AI-Era Credential Problem

Every time you paste a database URL, API key, or token into an AI assistant, you face a hard choice: productivity now vs. security debt forever.

With ChatGPT, Copilot, Claude, or any AI coding tool:
- The credential appears in your conversation history
- It may be retained by the provider for fine-tuning or review
- Even if you delete the chat, you can't guarantee deletion from their side
- The credential itself persists in your vault until you manually revoke it
- You probably won't remember to revoke it

**Traditional secret managers don't solve this.** Vault, AWS Secrets Manager, 1Password — all of them are permanent stores with optional rotation. They're excellent at what they do, but they treat secrets as assets to preserve, not liabilities to eliminate.

**Sirr is different.** The secret is born dying.

```bash
# Dead drop — push a one-time credential, get a URL back
sirr push "postgres://user:pass@host/db" --reads 1 --ttl 1h
# → https://sirrlock.com/secret/a3f8...c9d1

# Tell Claude: "analyze the schema at this URL"
# Claude reads it via MCP → read counter hits limit → credential deleted
# The conversation gets retained. The credential doesn't.
```

This isn't paranoia. This is correct threat modeling for an age where your coding assistant is a third party.

---

## Why Not Vault or AWS Secrets Manager?

**HashiCorp Vault** is infrastructure secret management. It's designed for long-lived service credentials, PKI, dynamic database roles at scale. It requires cluster setup, unseal keys, policy authoring, and significant operational investment. It has TTLs and lease mechanisms, but the mental model is preservation: secrets are assets to be rotated, not destroyed. There is no "burn after N reads." The complexity is justified when you're managing secrets for hundreds of services in a regulated enterprise. It's overkill when a developer needs to share a credential with an AI agent for one task.

**AWS Secrets Manager** is a managed permanent store with automated rotation. At $0.40/secret/month plus API call charges, with no read-count enforcement, no single-binary self-hosting, and deep AWS lock-in, it solves a different problem: "keep this secret, rotate it automatically, and integrate it with our IAM policies." It is not designed to answer: "how do I give an AI agent exactly one use of this credential?"

**Sirr** occupies a different position: ephemeral credentials for humans and AI agents working in the short term. The comparison isn't Sirr vs. Vault — it's Sirr vs. the current practice of pasting credentials into chat windows and hoping for the best.

| | Sirr | HashiCorp Vault | AWS Secrets Manager |
|---|---|---|---|
| Setup | Single binary | Cluster + unsealing | AWS account + IAM |
| Mental model | Secrets die | Secrets rotate | Secrets persist |
| Burn-after-N-reads | Yes | No | No |
| AI/MCP integration | Native | No | No |
| Self-hosted | Yes | Yes | No |
| Price | Free (honor system) | OSS free / Enterprise $$ | $0.40/secret/month |
| Operational burden | Near zero | High | Medium |

---

## Quick Start

### Run the server

**Docker:**

```bash
docker run -d \
  -p 7843:7843 \
  -v ./sirr-data:/data \
  ghcr.io/sirrlock/sirrd
```

**Binary:**

```bash
# Default: public mode (anyone can push and read)
./sirrd serve

# Private mode (only API key holders can push; reads are still open)
./sirrd serve --visibility private

# Create your first API key via the admin socket
./sirrd keys create my-key
# → token: abc123...  (shown once, not stored)
```

The admin socket lives at `/tmp/sirrd.sock` by default. All admin commands use it — no master API key, no network exposure.

---

## The Model

- **Visibility** controls who can create secrets:
  - `public` — anyone can push, anyone can read
  - `private` — only API key holders can push; reads remain open
  - `both` — same as private (keyed pushes create owned secrets; anonymous still allowed)
  - `none` — lockdown: all five endpoints return 503
- **Reads are universal** — knowing the hash IS the capability. No permission letters.
- **Keys are credentials, period.** A valid key makes you the owner. Only owners can patch, burn, or view the audit trail of their secrets.
- **Anonymous secrets** can be burned by anyone (public dead drops, self-service model).

---

## CLI Usage

### `sirr` — client commands

```bash
# Push a secret, get a hash back
sirr push "postgres://user:pass@host/db"
sirr push "some-secret" --reads 1 --ttl 1h
sirr push "secret" --key <api-token> --prefix db-

# Read a secret (consumes a read if read-limited)
sirr get <hash>
sirr get <hash> --json

# Inspect metadata without consuming a read
sirr inspect <hash>

# View the audit trail (requires owner key)
sirr audit <hash> --key <api-token>

# Patch a secret's value (requires owner key)
sirr patch <hash> "new-value" --key <api-token>

# Burn a secret immediately
sirr burn <hash> [--key <api-token>]

# Global flags
sirr --server http://localhost:7843 push "value"
sirr --key <api-token> <command>
# or: SIRR_SERVER=http://... SIRR_KEY=<token> sirr push "value"
```

### `sirrd` — admin commands (via Unix socket)

```bash
# Start the server
sirrd serve [--visibility public|private|both|none] [--port 7843] [--socket /tmp/sirrd.sock]

# Change visibility at runtime (no restart needed)
sirrd visibility set private

# API key management
sirrd keys create <name> [--webhook-url https://...] [--valid-after <unix>] [--valid-before <unix>]
sirrd keys list
sirrd keys delete <name>

# View all audit events
sirrd audit [--limit 100]
```

---

## HTTP API

Five endpoints over one resource path `/secret/:hash`:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/secret` | optional | Create a secret. Auth → owned; anonymous → dead drop. |
| `GET` | `/secret/:hash` | none | Read value. Consumes a read. Burns if last read. |
| `HEAD` | `/secret/:hash` | none | Inspect metadata. Does NOT consume a read. |
| `PATCH` | `/secret/:hash` | required (owner) | Update value, reset TTL / read count. |
| `DELETE` | `/secret/:hash` | owner or anonymous | Burn immediately. |
| `GET` | `/secret/:hash/audit` | required (owner) | Full event history for this secret. |

### Create a secret

```http
POST /secret
Authorization: Bearer <api-key>   (optional)
Content-Type: application/json

{
  "value": "postgres://...",
  "ttl_seconds": 3600,
  "reads": 1,
  "prefix": "db-"
}
```

```json
// 201
{
  "hash": "db-a3f8c9d1...",
  "url": "https://sirrlock.com/secret/db-a3f8c9d1...",
  "expires_at": 1700003600,
  "reads_remaining": 1,
  "owned": true
}
```

### Read a secret

```http
GET /secret/:hash
Accept: application/json   (optional; plain text returned by default)
```

```json
// 200: {"value": "postgres://..."}
// 410: {"error": "secret is gone"}   (burned, expired, or not found)
```

### Inspect metadata (HEAD)

```
HEAD /secret/:hash

// Response headers (200 if active, 410 if gone):
X-Sirr-Created: 2024-01-15T10:00:00Z
X-Sirr-TTL-Expires: 2024-01-15T11:00:00Z
X-Sirr-Reads-Remaining: 3
X-Sirr-Owned: true
```

### Audit trail

```http
GET /secret/:hash/audit
Authorization: Bearer <owner-key>
```

```json
// 200
{
  "hash": "db-a3f8c9d1...",
  "created_at": 1700000000,
  "events": [
    {"type": "secret.create", "at": 1700000000, "ip": ""},
    {"type": "secret.read",   "at": 1700001234, "ip": ""}
  ]
}
// 404 if not found or wrong owner key
```

---

## Webhooks

Each API key can have an optional `webhook_url`. When set, the server POSTs a JSON event to that URL after each lifecycle event for secrets owned by that key. Fire-and-forget — the webhook never blocks the HTTP response.

```bash
sirrd keys create my-key --webhook-url https://hooks.example.com/sirr
```

Event payload:

```json
{
  "type": "secret.created",
  "hash": "db-a3f8c9d1...",
  "at": 1700000000,
  "ip": ""
}
```

Event types: `secret.created`, `secret.read`, `secret.patched`, `secret.burned`.

Anonymous secrets never fire webhooks — there is no key to attach a URL to.

---

## AI Workflows

### Claude Code (MCP)

Install the MCP server so Claude can read and write secrets directly:

```bash
npm install -g @sirrlock/mcp
```

**.mcp.json:**

```json
{
  "mcpServers": {
    "sirr": {
      "command": "sirr-mcp",
      "env": {
        "SIRR_SERVER": "http://localhost:7843",
        "SIRR_KEY": "your-api-key"
      }
    }
  }
}
```

Once connected:

```
You: "Push my Stripe test key to sirr, one read only, 30 minutes"
Claude: [calls push_secret("sk_test_...", reads=1, ttl=1800)] → returns URL
```

### Python AI Agents (LangChain, CrewAI, AutoGen)

```python
from sirr import SirrClient

sirr = SirrClient(server="https://sirrlock.com", api_key=os.environ.get("SIRR_KEY"))

# Dead drop — push a value, get back a hash
result = sirr.push(connection_string, reads=1, ttl=3600)
# result.hash, result.url

# Agent reads it — credential is gone regardless of what the agent logs or retains
```

### CI/CD One-Time Tokens

```yaml
# GitHub Actions: deploy token that can only be used once
- run: |
    HASH=$(sirr push "${{ secrets.DEPLOY_TOKEN }}" --reads 1 --key "${{ secrets.SIRR_KEY }}")
    DEPLOY_TOKEN=$(sirr get "$HASH") ./deploy.sh
    # Token is gone after one read
```

---

## Configuration

### Server (`sirrd`)

| Variable | Default | Description |
|---|---|---|
| `SIRR_VISIBILITY` | `public` | Starting visibility: `public`, `private`, `both`, or `none` |
| `SIRR_PORT` | `7843` | HTTP listen port |
| `SIRR_HOST` | `0.0.0.0` | Bind address |
| `SIRR_DATA_DIR` | platform default¹ | Storage directory |
| `SIRR_ADMIN_SOCKET` | `/tmp/sirrd.sock` | Unix domain socket path for admin commands |
| `SIRR_RETENTION_DAYS` | `30` | Days to keep tombstones before pruning |
| `SIRR_LOG_LEVEL` | `info` | `trace` / `debug` / `info` / `warn` / `error` |

### Client (`sirr`)

| Variable | Default | Description |
|---|---|---|
| `SIRR_SERVER` | `https://sirrlock.com` | Server base URL |
| `SIRR_KEY` | — | Bearer API token for authenticated operations |

¹ `~/.local/share/sirr/` (Linux), `~/Library/Application Support/sirr/` (macOS). Docker: mount `/data` and set `SIRR_DATA_DIR=/data`.

---

## Architecture

```
sirr CLI / Node SDK / Python SDK / .NET SDK / MCP Server
              ↓  HTTP (optional Bearer token for owned secrets)
         axum REST API (Rust) — 5 endpoints over /secret/:hash
              ↓
     redb embedded database (sirr.db)
              ↓
   ChaCha20Poly1305 encrypted values
   (key = random 32 bytes in sirr.key)

sirrd CLI ←→ Unix domain socket (/tmp/sirrd.sock)
                ↓ admin commands
              Store (keys, visibility, audit)
```

- `sirr.key` — random 32-byte encryption key, generated on first run, stored beside `sirr.db`
- Per-record random 12-byte nonce; value field is encrypted, metadata is not
- Reads are universal (no auth). Owned operations require the owner key.
- Admin authenticates via filesystem permissions on the Unix domain socket — no master API key.

---

## Licensing

**Business Source License 1.1**

Honor-system licensing. No enforcement code. No license server calls. The server runs at any scale — the license is a matter of integrity.

| | |
|---|---|
| Free | All use up to whatever you need |
| Commercial | License available at [sirrlock.com/pricing](https://sirrlock.com/pricing) |
| Source available | Forks and modifications permitted |
| Converts to Apache 2.0 | **February 20, 2028** |

---

## Roadmap

- [ ] Web UI
- [x] Webhooks on lifecycle events (per-key, fire-and-forget)
- [x] Audit log
- [ ] Kubernetes operator
- [ ] Terraform provider
- [x] Patchable secrets (update value without changing hash)
- [ ] Secret versioning

---

## Related

| Package | Description |
|---------|-------------|
| [@sirrlock/mcp](https://github.com/sirrlock/mcp) | MCP server for AI assistants |
| [@sirrlock/node](https://github.com/sirrlock/node) | Node.js / TypeScript SDK |
| [sirr (PyPI)](https://github.com/sirrlock/python) | Python SDK |
| [Sirr.Client (NuGet)](https://github.com/sirrlock/dotnet) | .NET SDK |
| [sirr.dev](https://sirr.dev) | Documentation |
| [sirrlock.com](https://sirrlock.com) | Hosted service + license keys |

---

*Secrets that whisper and disappear.*
