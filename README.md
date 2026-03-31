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
# → https://sirrlock.com/secrets/a3f8...c9d1

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
  -e SIRR_MASTER_ENCRYPTION_KEY_FILE=/run/secrets/master.key \
  ghcr.io/sirrlock/sirrd
```

Or with an environment variable (development only — visible via `docker inspect`):

```bash
docker run -d \
  -p 39999:39999 \
  -v ./sirr-data:/data \
  ghcr.io/sirrlock/sirrd
```

Or as a binary:

```bash
./sirrd serve
# Optionally protect writes: SIRR_MASTER_API_KEY=my-key ./sirrd serve
```

### Public dead drop (push)

```bash
# Push a value, get a URL with a server-generated 256-bit hex ID
sirr push "postgres://user:pass@host/db" --reads 1 --ttl 1h
# → https://sirrlock.com/secrets/a3f8...c9d1

sirr get a3f8...c9d1   # returns value
sirr get a3f8...c9d1   # 404 — burned
```

### Org team secrets (set)

```bash
# Named slot in an org — requires --org or $SIRR_ORG
sirr set DB_URL "postgres://..." --org acme --reads 5 --ttl 24h
sirr get DB_URL --org acme         # returns value, reads remaining: 4
sirr set DB_URL "new-value" --org acme   # 409 Conflict — duplicates rejected

# Pull all org secrets into .env
sirr pull .env --org acme

# Run a process with org secrets injected as env vars
sirr run --org acme -- node app.js
```

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
        "SIRR_SERVER": "http://localhost:39999",
        "SIRR_MASTER_API_KEY": "your-api-key"
      }
    }
  }
}
```

Once connected:

```
You: "Push my Stripe test key to sirr, one read only, 30 minutes"
Claude: [calls push_secret("sk_test_...", reads=1, ttl=1800)] → returns URL

You: "Store DB_URL in the acme org"
Claude: [calls set_secret("DB_URL", "postgres://...", org="acme")]
```

### Python AI Agents (LangChain, CrewAI, AutoGen)

```python
from sirr import SirrClient

sirr = SirrClient(server="https://sirrlock.com", api_key=os.environ.get("SIRR_MASTER_API_KEY"))

# Dead drop — push a value, get back an ID
result = sirr.push(connection_string, reads=1, ttl=3600)
# result.id → "a3f8...c9d1", result.url → "https://sirrlock.com/secrets/a3f8...c9d1"

# Agent reads it — credential is gone regardless of what the agent logs or retains
```

### CI/CD One-Time Tokens

```yaml
# GitHub Actions: deploy token that can only be used once
- run: |
    URL=$(sirr push "${{ secrets.DEPLOY_TOKEN }}" --reads 1)
    DEPLOY_TOKEN=$(sirr get "$URL") ./deploy.sh
    # Token is gone after one read
```

---

## Full Usage

```bash
# Public dead drop — value only, returns {id, url}
sirr push <value> [--ttl <duration>] [--reads <n>]

# Org named secrets — requires --org or $SIRR_ORG
sirr set KEY VALUE [--org <org>] [--ttl <duration>] [--reads <n>]

# Retrieve
sirr get <id-or-key> [--org <org>]         # stdout, burns if read limit hit
sirr pull .env [--org <org>]               # pull all secrets into .env
sirr run [--org <org>] -- <command>        # inject all secrets as env vars

# Manage
sirr list [--org <org>]                    # metadata only, no values shown
sirr delete <id-or-key> [--org <org>]
sirr prune                                 # delete all expired secrets now
sirr audit [--key <key>] [--org <org>]     # audit log (--key filters by secret)
sirr me                                    # show current identity (works anonymously)

# Key rotation (offline — stop the server first)
sirr rotate                                # re-encrypts all records with new key

# Global flags
sirr -v                                    # print version
sirr --org <org> <command>                 # or set $SIRR_ORG
```

TTL format: `30s`, `5m`, `2h`, `7d`, `30d`

---

## Multi-Tenant Mode

Sirr supports org-scoped secrets with role-based access control. Each org has principals (identities) with named API keys and roles that control permissions.

### Bootstrap

```bash
# Auto-create a default org + admin principal + temporary keys on first boot:
sirrd serve --init
# Or: SIRR_AUTOINIT=true sirrd serve
```

The bootstrap prints org ID, principal ID, and two temporary API keys (valid 30 minutes). Use those keys to create permanent ones.

### Org management (requires master key)

```bash
export SIRR_MASTER_API_KEY=<master-key>

sirr orgs create "My Team"
sirr orgs list
sirr principals create <org_id> alice --role writer
sirr me create-key --name deploy-key    # using a principal key
```

### Using org-scoped secrets

```bash
# With a principal API key:
export SIRR_MASTER_API_KEY=<principal-key>
export SIRR_ORG=<org_id>

sirr set DB_URL "postgres://..."           # named slot (duplicates → 409 Conflict)
sirr get DB_URL                            # retrieve by name
sirr list                                  # list org secrets
```

### Built-in roles

| Role | Permissions | Description |
|------|-------------|-------------|
| reader | `rla` | Read own secrets, list own, read own account |
| writer | `rlcpdam` | Read/list/create/patch/delete own secrets + manage account |
| admin | `rRlLcCpPaAmMdD` | Full org access (all secrets, manage principals/roles) |
| owner | `rRlLcCpPaAmMSdD` | Admin + SirrAdmin (can create/delete orgs) |

Custom roles can be created per-org with any combination of the 15 permission bits.

### Disabling the public bucket

Set `SIRR_ENABLE_PUBLIC_BUCKET=false` to serve only org-scoped routes.

---

## HTTP API

**Public routes** (no auth required):

### `GET /secrets/:id`
Retrieves value by server-generated 256-bit hex ID. Increments read counter. Burns record if read limit reached.
```json
{ "id": "a3f8...c9d1", "value": "postgres://..." }
// 404 if expired, burned, or not found
```

### `HEAD /secrets/:id`
Returns metadata via headers. Does NOT increment read counter.
```
X-Sirr-Read-Count: 3
X-Sirr-Reads-Remaining: 7    (or "unlimited")
X-Sirr-Created-At: 1700000000
X-Sirr-Expires-At: 1700003600  (if TTL set)
X-Sirr-Status: active
// 200 or 404 (not found)
```

### `GET /health` → `{ "status": "ok" }`

**Protected routes** (require `Authorization: Bearer <SIRR_MASTER_API_KEY>` if `SIRR_MASTER_API_KEY` is set):

### `POST /secrets`
Public dead drop. Accepts value only — no key field. Server generates a 256-bit hex ID.
```json
{ "value": "postgres://...", "ttl_seconds": 3600, "max_reads": 1 }
// 201: { "id": "a3f8...c9d1", "url": "https://sirrlock.com/secrets/a3f8...c9d1" }
// 402: license required (>100 secrets without SIRR_LICENSE_KEY)
```

### `POST /orgs/{org}/secrets`
Org-scoped named secret. Rejects duplicates.
```json
{ "key": "DB_URL", "value": "postgres://...", "ttl_seconds": 3600, "max_reads": 5 }
// 201: { "key": "DB_URL" }
// 409: Conflict — duplicate key (+ secret.create_rejected audit event)
// 402: license required
```

### `GET /secrets`
Returns metadata only — values are never included in list responses.
```json
{
  "secrets": [
    { "id": "a3f8...c9d1", "created_at": 1700000000, "expires_at": 1700003600, "max_reads": 1, "read_count": 0 }
  ]
}
```

### `DELETE /secrets/:id` → `{ "deleted": true }`
### `POST /prune` → `{ "pruned": 3 }`

---

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SIRR_MASTER_API_KEY` | auto-generated | Protects all authenticated endpoints. Printed at startup if not set — copy and persist it. |
| `SIRR_LICENSE_KEY` | — | Required for >100 active secrets |
| `SIRR_PORT` | `39999` | HTTP listen port |
| `SIRR_HOST` | `0.0.0.0` | Bind address |
| `SIRR_DATA_DIR` | platform default¹ | Storage directory |
| `SIRR_CORS_ORIGINS` | `*` (all) | Comma-separated allowed origins for management endpoints |
| `SIRR_LOG_LEVEL` | `info` | `trace` / `debug` / `info` / `warn` / `error` |
| `SIRR_RATE_LIMIT_PER_SECOND` | `10` | Per-IP request rate (steady-state, all routes) |
| `SIRR_RATE_LIMIT_BURST` | `30` | Per-IP burst allowance |
| `SIRR_NO_BANNER` | `0` | Set to `1` to suppress the startup banner |
| `SIRR_NO_SECURITY_BANNER` | `0` | Set to `1` to suppress the auto-generated key notice |
| `SIRR_ENABLE_PUBLIC_BUCKET` | `true` | Set to `false` to disable legacy `/secrets` routes |
| `SIRR_AUTOINIT` | `false` | Set to `true` to auto-create default org on first boot |

**CORS design note:** sirrd is a backend service, not a browser API. `GET /secrets/{key}` deliberately returns **no** `Access-Control-Allow-Origin` header — browsers block cross-origin reads of secret values by design, regardless of `SIRR_CORS_ORIGINS`. Management endpoints (create, list, delete, keys) do respect `SIRR_CORS_ORIGINS` so a trusted admin UI on a different origin can talk to them. If you need browser clients to read secrets, run them on the same origin as sirrd or proxy through your own backend.

One of `SIRR_MASTER_ENCRYPTION_KEY_FILE` or `SIRR_MASTER_ENCRYPTION_KEY` is required. If both are set, the file takes precedence. File-based key delivery is recommended for production because environment variables are visible via `docker inspect` and `/proc`.

**CLI / client variables:**

| Variable | Default | Description |
|---|---|---|
| `SIRR_SERVER` | `https://sirrlock.com` | Server base URL |
| `SIRR_MASTER_API_KEY` | — | Same value as server's `SIRR_MASTER_API_KEY` (for write ops) |
| `SIRR_ORG` | — | Default org for `set`/`get`/`list` commands (avoids `--org` flag) |

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
- Reads are public (no auth). Writes optionally protected by `SIRR_MASTER_API_KEY`

---

## Licensing

**Business Source License 1.1**

| | |
|---|---|
| Solo (free) | 1 org, 3 principals, unlimited secrets |
| Team | 5 orgs, 25 principals |
| Business | Unlimited orgs and principals |
| Free | All non-production use (dev, staging, CI) |
| Source available | Forks and modifications permitted |
| Converts to Apache 2.0 | **February 20, 2028** |

License keys at [sirrlock.com/pricing](https://sirrlock.com/pricing).

```bash
SIRR_LICENSE_KEY=sirr_lic_... ./sirr serve
```

---

## Roadmap

- [ ] Web UI
- [x] Webhooks on expiry / burn
- [x] Team namespaces (multi-tenant orgs)
- [x] Audit log
- [ ] Kubernetes operator
- [ ] Terraform provider
- [x] Patchable secrets (update value without changing key)
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

