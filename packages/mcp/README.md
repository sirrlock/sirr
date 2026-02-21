# @sirr/mcp — Sirr MCP Server for Claude Code

Gives Claude Code direct access to your Sirr secret vault. Claude can read secrets by name, push new secrets with expiry constraints, and list what's in the vault — without ever seeing your `SIRR_TOKEN` directly.

## Install

```bash
npm install -g @sirr/mcp
```

## Configure

Add to your project's `.mcp.json` (or `~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "sirr": {
      "command": "sirr-mcp",
      "env": {
        "SIRR_SERVER": "http://localhost:8080",
        "SIRR_TOKEN": "your-sirr-master-key"
      }
    }
  }
}
```

Or using `npx` without global install:

```json
{
  "mcpServers": {
    "sirr": {
      "command": "npx",
      "args": ["-y", "@sirr/mcp"],
      "env": {
        "SIRR_SERVER": "http://localhost:8080",
        "SIRR_TOKEN": "your-sirr-master-key"
      }
    }
  }
}
```

## Usage in Claude Code

Once configured, Claude understands natural language secret references:

```
"Get me the DATABASE_URL secret"
→ calls get_secret("DATABASE_URL")

"Push STRIPE_KEY=sk_live_... to sirr, burn after 1 read"
→ calls push_secret("STRIPE_KEY", "sk_live_...", max_reads=1)

"What secrets do I have expiring today?"
→ calls list_secrets() and filters by expires_at

"Delete the old DEPLOY_TOKEN"
→ calls delete_secret("DEPLOY_TOKEN")
```

### Inline Secret References

You can reference secrets inline in any prompt:

```
"Use sirr:DATABASE_URL to run a migration"
"Deploy with sirr:DEPLOY_TOKEN"
```

The `sirr:KEYNAME` prefix tells Claude to fetch from the vault.

## Available Tools

| Tool | Description |
|---|---|
| `get_secret(key)` | Retrieve a secret (increments read counter, may burn) |
| `push_secret(key, value, ttl_seconds?, max_reads?)` | Store a secret |
| `list_secrets()` | List all active secrets (metadata only, no values) |
| `delete_secret(key)` | Burn a secret immediately |
| `prune_secrets()` | Delete all expired secrets |
| `health_check()` | Verify the Sirr server is reachable |

## Security Notes

- Claude only sees secret **values** when explicitly fetching via `get_secret`
- `list_secrets` never returns values — metadata only
- Set `max_reads=1` on any secret you share for AI debugging sessions
- The MCP server never logs secret values
- `SIRR_TOKEN` is in your MCP config's `env` block — not passed as arguments, not in prompts

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SIRR_SERVER` | `http://localhost:8080` | Sirr server URL |
| `SIRR_TOKEN` | — | Bearer token (same as `SIRR_MASTER_KEY` on the server) |
