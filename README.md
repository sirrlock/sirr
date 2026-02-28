# Sirr

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![CI](https://github.com/SirrVault/sirr/actions/workflows/ci.yml/badge.svg)](https://github.com/SirrVault/sirr/actions/workflows/ci.yml)

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
# Give Claude exactly one read window — 1 hour, 1 read
sirr push PROD_DB="postgres://user:pass@host/db" --reads 1 --ttl 1h

# Tell Claude: "analyze the schema at PROD_DB"
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
| Price | Free ≤100 secrets | OSS free / Enterprise $$ | $0.40/secret/month |
| Operational burden | Near zero | High | Medium |

---

## Quick Start

### Run the server

**With a key file (recommended for production):**

```bash
# Generate the master key file once.
openssl rand -hex 32 > master.key
chmod 400 master.key

docker run -d \
  -p 39999:39999 \
  -v ./sirr-data:/data \
  -v ./master.key:/run/secrets/master.key:ro \
  -e SIRR_MASTER_KEY_FILE=/run/secrets/master.key \
  ghcr.io/sirrvault/sirr
```

Or with an environment variable (development only — visible via `docker inspect`):

```bash
docker run -d \
  -p 39999:39999 \
  -v ./sirr-data:/data \
  ghcr.io/sirrvault/sirr
```

Or as a binary:

```bash
./sirr serve
# Optionally protect writes: SIRR_API_KEY=my-key ./sirr serve
```

### Push and retrieve

```bash
# One-time credential (burns after 1 read)
sirr push DB_URL="postgres://..." --reads 1 --ttl 1h
sirr get DB_URL      # returns value
sirr get DB_URL      # 404 — burned

# Patchable secret (keeps the key, allows value updates)
sirr push CF_TOKEN=abc123 --reads 5 --no-delete
sirr get CF_TOKEN    # returns value, reads remaining: 4

# Expiring .env for your team
sirr push .env --ttl 24h
sirr pull .env       # on the other machine

# Run a process with secrets injected as env vars
sirr run -- node app.js
```

---

## AI Workflows

### Claude Code (MCP)

Install the MCP server so Claude can read and write secrets directly:

```bash
npm install -g @sirr/mcp
```

**.mcp.json:**

```json
{
  "mcpServers": {
    "sirr": {
      "command": "sirr-mcp",
      "env": {
        "SIRR_SERVER": "http://localhost:39999",
        "SIRR_API_KEY": "your-api-key"
      }
    }
  }
}
```

Once connected:

```
You: "I need you to analyze the schema at PROD_DB. It's in sirr, burn it after you read it."
Claude: [reads PROD_DB via MCP] → [credential auto-deleted] → [analyzes schema]

You: "Push my Stripe test key to sirr, one read only, 30 minutes"
Claude: [calls push_secret("STRIPE_KEY", "sk_test_...", reads=1, ttl=1800)]
```

### Python AI Agents (LangChain, CrewAI, AutoGen)

```python
from sirr import SirrClient

sirr = SirrClient(server="http://localhost:39999", api_key=os.environ.get("SIRR_API_KEY"))

# Give an agent a one-use credential
sirr.push("DB_URL", connection_string, reads=1, ttl=3600)

# Agent reads it — credential is gone regardless of what the agent logs or retains
```

### CI/CD One-Time Tokens

```yaml
# GitHub Actions: deploy token that can only be used once
- run: |
    sirr push DEPLOY_TOKEN="${{ secrets.DEPLOY_TOKEN }}" --reads 1
    sirr run -- ./deploy.sh
    # DEPLOY_TOKEN is gone after deploy.sh runs
```

---

## Full Usage

```bash
# Push
sirr push KEY=VALUE [--ttl <duration>] [--reads <n>] [--no-delete]
sirr push .env [--ttl <duration>]          # push entire .env file

# Retrieve
sirr get KEY                               # stdout, burns if read limit hit
sirr pull .env                             # pull all secrets into .env
sirr run -- <command>                      # inject all secrets as env vars

# Manage
sirr list                                  # metadata only, no values shown
sirr delete KEY
sirr prune                                 # delete all expired secrets now
sirr share KEY                             # print reference URL

# Key rotation (offline — stop the server first)
sirr rotate                                # re-encrypts all records with new key
```

TTL format: `30s`, `5m`, `2h`, `7d`, `30d`

`--no-delete`: Secret is sealed (reads blocked) when `max_reads` is hit, but stays in the database. Can be updated via `PATCH /secrets/:key` and unsealed.

---

## HTTP API

**Public routes** (no auth required):

### `GET /secrets/:key`
Retrieves value. Increments read counter. Burns or seals record if read limit reached.
```json
{ "key": "DB_URL", "value": "postgres://..." }
// 404 if expired, burned, or not found
// 410 if sealed (delete=false, reads exhausted)
```

### `HEAD /secrets/:key`
Returns metadata via headers. Does NOT increment read counter.
```
X-Sirr-Read-Count: 3
X-Sirr-Reads-Remaining: 7    (or "unlimited")
X-Sirr-Delete: false
X-Sirr-Created-At: 1700000000
X-Sirr-Expires-At: 1700003600  (if TTL set)
X-Sirr-Status: active          (or "sealed")
// 200, 404 (not found), or 410 (sealed)
```

### `GET /health` → `{ "status": "ok" }`

**Protected routes** (require `Authorization: Bearer <SIRR_API_KEY>` if `SIRR_API_KEY` is set):

### `POST /secrets`
```json
{ "key": "DB_URL", "value": "postgres://...", "ttl_seconds": 3600, "max_reads": 1, "delete": true }
// delete defaults to true. Set false for patchable secrets.
// 201: { "key": "DB_URL" }
// 402: license required (>100 secrets without SIRR_LICENSE_KEY)
```

### `PATCH /secrets/:key`
Update value, max_reads, or TTL. Only works on `delete=false` secrets. Resets read_count to 0.
```json
{ "value": "new-value", "max_reads": 10, "ttl_seconds": 3600 }
// All fields optional. Omitted fields keep current values.
// 200: updated metadata
// 409: cannot patch a delete=true secret
// 404: not found or expired
```

### `GET /secrets`
Returns metadata only — values are never included in list responses.
```json
{
  "secrets": [
    { "key": "DB_URL", "created_at": 1700000000, "expires_at": 1700003600, "max_reads": 1, "read_count": 0, "delete": true }
  ]
}
```

### `DELETE /secrets/:key` → `{ "deleted": true }`
### `POST /prune` → `{ "pruned": 3 }`

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SIRR_API_KEY` | — | Optional. Protects write endpoints (POST/PATCH/DELETE/list) |
| `SIRR_LICENSE_KEY` | — | Required for >100 active secrets |
| `SIRR_PORT` | `39999` | HTTP listen port |
| `SIRR_HOST` | `0.0.0.0` | Bind address |
| `SIRR_DATA_DIR` | platform default¹ | Storage directory |
| `SIRR_CORS_ORIGINS` | `*` (all) | Comma-separated allowed origins |
| `SIRR_LOG_LEVEL` | `info` | `trace` / `debug` / `info` / `warn` / `error` |

One of `SIRR_MASTER_KEY_FILE` or `SIRR_MASTER_KEY` is required. If both are set, the file takes precedence. File-based key delivery is recommended for production because environment variables are visible via `docker inspect` and `/proc`.

**CLI / client variables:**

| Variable | Default | Description |
|---|---|---|
| `SIRR_SERVER` | `http://localhost:39999` | Server base URL |
| `SIRR_API_KEY` | — | Same value as server's `SIRR_API_KEY` (for write ops) |

**Key rotation variables** (used by `sirr rotate`):

| Variable | Description |
|---|---|
| `SIRR_NEW_MASTER_KEY_FILE` | Path to file containing the new master key |
| `SIRR_NEW_MASTER_KEY` | New master key value (prefer `_FILE`) |

¹ `~/.local/share/sirr/` (Linux), `~/Library/Application Support/sirr/` (macOS), `%APPDATA%\sirr\` (Windows). Docker: mount `/data` and set `SIRR_DATA_DIR=/data`.

---

## Architecture

```
CLI / Node SDK / Python SDK / .NET SDK / MCP Server
              ↓  HTTP (optional API key for writes)
         axum REST API (Rust)
              ↓
     redb embedded database (sirr.db)
              ↓
   ChaCha20Poly1305 encrypted values
   (key = random 32 bytes in sirr.key)
```

- `sirr.key` — random 32-byte encryption key, generated on first run, stored beside `sirr.db`
- Per-record random 12-byte nonce; value field is encrypted, metadata is not
- Reads are public (no auth). Writes optionally protected by `SIRR_API_KEY`

---

## Licensing

**Business Source License 1.1**

| | |
|---|---|
| Free | Up to **100 active secrets** per instance |
| Free | All non-production use (dev, staging, CI) |
| Source available | Forks and modifications permitted |
| Converts to Apache 2.0 | **February 20, 2028** |
| Commercial license | Required for >100 active secrets in production |

License keys at [secretdrop.app/sirr](https://secretdrop.app/sirr).

```bash
SIRR_LICENSE_KEY=sirr_lic_... ./sirr serve
```

---

## Roadmap

- [ ] Web UI
- [ ] Webhooks on expiry / burn
- [ ] Team namespaces
- [x] Audit log
- [ ] Kubernetes operator
- [ ] Terraform provider
- [x] Patchable secrets (update value without changing key)
- [ ] Secret versioning

---

*Secrets that whisper and disappear.*
