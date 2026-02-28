#!/usr/bin/env node
/**
 * @sirr/mcp — MCP server for Sirr secret vault
 *
 * Exposes Sirr as MCP tools so Claude Code can read/write ephemeral secrets.
 *
 * Configuration (env vars):
 *   SIRR_SERVER  — Sirr server URL (default: http://localhost:8080)
 *   SIRR_TOKEN   — Bearer token (SIRR_MASTER_KEY on the server)
 *
 * Install:  npm install -g @sirr/mcp
 * Configure in .mcp.json:
 *   {
 *     "mcpServers": {
 *       "sirr": {
 *         "command": "sirr-mcp",
 *         "env": { "SIRR_SERVER": "...", "SIRR_TOKEN": "..." }
 *       }
 *     }
 *   }
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

// ── Config ────────────────────────────────────────────────────────────────────

const SIRR_SERVER = (
  process.env["SIRR_SERVER"] ?? "http://localhost:8080"
).replace(/\/$/, "");
const SIRR_TOKEN = process.env["SIRR_TOKEN"] ?? "";

// ── Sirr HTTP client ──────────────────────────────────────────────────────────

interface SecretMeta {
  key: string;
  created_at: number;
  expires_at: number | null;
  max_reads: number | null;
  read_count: number;
}

async function sirrRequest<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await fetch(`${SIRR_SERVER}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${SIRR_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const json = (await res.json()) as Record<string, unknown>;

  if (!res.ok) {
    throw new Error(
      `Sirr API ${res.status}: ${(json["error"] as string) ?? "unknown"}`,
    );
  }

  return json as T;
}

import { parseKeyRef, formatTtl } from "./helpers";

// ── Tool definitions ──────────────────────────────────────────────────────────

const TOOLS: Tool[] = [
  {
    name: "get_secret",
    description:
      "Retrieve a secret from the Sirr vault by key name. " +
      "The secret's read counter is incremented — if it was set with max_reads=1 it will be deleted after this call. " +
      "Returns null if the secret does not exist, has expired, or has been burned. " +
      "Accepts bare key names, 'sirr:KEYNAME' references, or 'KEYNAME#id' format.",
    inputSchema: {
      type: "object" as const,
      properties: {
        key: {
          type: "string",
          description:
            "Secret key name. Accepts 'sirr:KEYNAME', 'KEYNAME#id', or bare key name.",
        },
      },
      required: ["key"],
    },
  },
  {
    name: "push_secret",
    description:
      "Store a secret in the Sirr vault. Optionally set a TTL (seconds) and/or a max read limit. " +
      "Use max_reads=1 for one-time credentials that burn after first access. " +
      "Use ttl_seconds for time-expiring secrets.",
    inputSchema: {
      type: "object" as const,
      properties: {
        key: {
          type: "string",
          description: "Key name to store the secret under.",
        },
        value: {
          type: "string",
          description: "Secret value.",
        },
        ttl_seconds: {
          type: "number",
          description:
            "Optional TTL in seconds. Examples: 3600 (1h), 86400 (1d), 604800 (7d).",
        },
        max_reads: {
          type: "number",
          description:
            "Optional maximum read count. Set to 1 for a one-time secret.",
        },
      },
      required: ["key", "value"],
    },
  },
  {
    name: "list_secrets",
    description:
      "List all active secrets in the Sirr vault. Returns metadata only — values are never included. " +
      "Shows key name, expiry time, and read count for each secret.",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "delete_secret",
    description:
      "Immediately delete (burn) a secret from the Sirr vault, regardless of TTL or read count.",
    inputSchema: {
      type: "object" as const,
      properties: {
        key: {
          type: "string",
          description: "Key name to delete.",
        },
      },
      required: ["key"],
    },
  },
  {
    name: "prune_secrets",
    description:
      "Trigger an immediate sweep of all expired secrets on the server. " +
      "Returns the count of secrets that were deleted.",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "health_check",
    description: "Check if the Sirr server is reachable and healthy.",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "sirr_audit",
    description:
      "Query the Sirr audit log. Returns recent events like secret creates, reads, deletes. " +
      "Useful for security monitoring and debugging access patterns.",
    inputSchema: {
      type: "object" as const,
      properties: {
        since: {
          type: "number",
          description: "Only return events after this Unix timestamp.",
        },
        action: {
          type: "string",
          description: "Filter by action type (e.g. secret.create, secret.read, key.create).",
        },
        limit: {
          type: "number",
          description: "Maximum events to return (default: 50).",
        },
      },
    },
  },
  {
    name: "sirr_webhook_create",
    description:
      "Register a webhook URL to receive Sirr event notifications. " +
      "Returns the webhook ID and signing secret (shown once — save it).",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "Webhook endpoint URL (must start with http:// or https://).",
        },
        events: {
          type: "array",
          items: { type: "string" },
          description: "Event types to subscribe to (default: all). Examples: secret.created, secret.burned.",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "sirr_webhook_list",
    description: "List all registered webhooks on the Sirr server. Signing secrets are redacted.",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "sirr_webhook_delete",
    description: "Remove a webhook registration by its ID.",
    inputSchema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "Webhook ID to delete.",
        },
      },
      required: ["id"],
    },
  },
  {
    name: "sirr_key_create",
    description:
      "Create a scoped API key with specific permissions. " +
      "The raw key is returned once — save it immediately. " +
      "Permissions: read, write, delete, admin. Optional prefix scoping limits access to secrets matching the prefix.",
    inputSchema: {
      type: "object" as const,
      properties: {
        label: {
          type: "string",
          description: "Human-readable label for the key.",
        },
        permissions: {
          type: "array",
          items: { type: "string" },
          description: "Permissions to grant: read, write, delete, admin.",
        },
        prefix: {
          type: "string",
          description: "Optional prefix scope — key can only access secrets starting with this prefix.",
        },
      },
      required: ["label", "permissions"],
    },
  },
  {
    name: "sirr_key_list",
    description: "List all scoped API keys. Key hashes are never returned.",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "sirr_key_delete",
    description: "Delete a scoped API key by its ID.",
    inputSchema: {
      type: "object" as const,
      properties: {
        id: {
          type: "string",
          description: "API key ID to delete.",
        },
      },
      required: ["id"],
    },
  },
];

// ── MCP Server ────────────────────────────────────────────────────────────────

const server = new Server(
  { name: "sirr", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "get_secret": {
        const rawKey = (args as { key: string }).key;
        const key = parseKeyRef(rawKey);

        const res = await fetch(`${SIRR_SERVER}/secrets/${encodeURIComponent(key)}`, {
          headers: { Authorization: `Bearer ${SIRR_TOKEN}` },
        });

        if (res.status === 404) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Secret '${key}' not found, expired, or already burned.`,
              },
            ],
          };
        }

        const data = (await res.json()) as { value: string };

        return {
          content: [
            {
              type: "text" as const,
              text: data.value,
            },
          ],
        };
      }

      case "push_secret": {
        const { key, value, ttl_seconds, max_reads } = args as {
          key: string;
          value: string;
          ttl_seconds?: number;
          max_reads?: number;
        };

        await sirrRequest("POST", "/secrets", {
          key,
          value,
          ttl_seconds: ttl_seconds ?? null,
          max_reads: max_reads ?? null,
        });

        const parts: string[] = [`Stored secret '${key}'.`];
        if (ttl_seconds) parts.push(`Expires in ${formatTtl(Math.floor(Date.now() / 1000) + ttl_seconds)}.`);
        if (max_reads) parts.push(`Burns after ${max_reads} read(s).`);

        return {
          content: [{ type: "text" as const, text: parts.join(" ") }],
        };
      }

      case "list_secrets": {
        const data = await sirrRequest<{ secrets: SecretMeta[] }>(
          "GET",
          "/secrets",
        );

        if (data.secrets.length === 0) {
          return {
            content: [{ type: "text" as const, text: "No active secrets." }],
          };
        }

        const lines = data.secrets.map((m) => {
          const expiry = formatTtl(m.expires_at);
          const reads =
            m.max_reads != null
              ? `${m.read_count}/${m.max_reads} reads`
              : `${m.read_count} reads`;
          return `• ${m.key} — ${expiry} — ${reads}`;
        });

        return {
          content: [
            {
              type: "text" as const,
              text: `${data.secrets.length} active secret(s):\n${lines.join("\n")}`,
            },
          ],
        };
      }

      case "delete_secret": {
        const { key } = args as { key: string };

        const res = await fetch(
          `${SIRR_SERVER}/secrets/${encodeURIComponent(key)}`,
          {
            method: "DELETE",
            headers: { Authorization: `Bearer ${SIRR_TOKEN}` },
          },
        );

        if (res.status === 404) {
          return {
            content: [
              { type: "text" as const, text: `Secret '${key}' not found.` },
            ],
          };
        }

        return {
          content: [
            {
              type: "text" as const,
              text: `Secret '${key}' deleted.`,
            },
          ],
        };
      }

      case "prune_secrets": {
        const data = await sirrRequest<{ pruned: number }>("POST", "/prune");
        return {
          content: [
            {
              type: "text" as const,
              text: `Pruned ${data.pruned} expired secret(s).`,
            },
          ],
        };
      }

      case "health_check": {
        const res = await fetch(`${SIRR_SERVER}/health`);
        const data = (await res.json()) as { status: string };
        return {
          content: [
            {
              type: "text" as const,
              text: `Sirr server status: ${data.status} (${SIRR_SERVER})`,
            },
          ],
        };
      }

      case "sirr_audit": {
        const { since, action, limit } = args as {
          since?: number;
          action?: string;
          limit?: number;
        };
        const params = new URLSearchParams();
        if (since != null) params.set("since", String(since));
        if (action != null) params.set("action", action);
        if (limit != null) params.set("limit", String(limit));
        const qs = params.toString();
        const data = await sirrRequest<{ events: Array<{ id: number; timestamp: number; action: string; key: string | null; source_ip: string; success: boolean }> }>(
          "GET",
          `/audit${qs ? `?${qs}` : ""}`,
        );

        if (data.events.length === 0) {
          return {
            content: [{ type: "text" as const, text: "No audit events found." }],
          };
        }

        const lines = data.events.map(
          (e) =>
            `[${e.timestamp}] ${e.action} key=${e.key ?? "-"} ip=${e.source_ip} ${e.success ? "ok" : "FAIL"}`,
        );

        return {
          content: [
            {
              type: "text" as const,
              text: `${data.events.length} audit event(s):\n${lines.join("\n")}`,
            },
          ],
        };
      }

      case "sirr_webhook_create": {
        const { url, events } = args as { url: string; events?: string[] };
        const body: Record<string, unknown> = { url };
        if (events) body.events = events;
        const data = await sirrRequest<{ id: string; secret: string }>(
          "POST",
          "/webhooks",
          body,
        );

        return {
          content: [
            {
              type: "text" as const,
              text: `Webhook registered.\n  ID: ${data.id}\n  Secret: ${data.secret}\n  (Save the secret — it won't be shown again)`,
            },
          ],
        };
      }

      case "sirr_webhook_list": {
        const data = await sirrRequest<{
          webhooks: Array<{ id: string; url: string; events: string[]; created_at: number }>;
        }>("GET", "/webhooks");

        if (data.webhooks.length === 0) {
          return {
            content: [{ type: "text" as const, text: "No webhooks registered." }],
          };
        }

        const lines = data.webhooks.map(
          (w) => `• ${w.id} — ${w.url} [${w.events.join(",")}]`,
        );

        return {
          content: [
            {
              type: "text" as const,
              text: `${data.webhooks.length} webhook(s):\n${lines.join("\n")}`,
            },
          ],
        };
      }

      case "sirr_webhook_delete": {
        const { id } = args as { id: string };
        await sirrRequest("DELETE", `/webhooks/${encodeURIComponent(id)}`);
        return {
          content: [
            { type: "text" as const, text: `Webhook '${id}' deleted.` },
          ],
        };
      }

      case "sirr_key_create": {
        const { label, permissions, prefix } = args as {
          label: string;
          permissions: string[];
          prefix?: string;
        };
        const body: Record<string, unknown> = { label, permissions };
        if (prefix) body.prefix = prefix;
        const data = await sirrRequest<{
          id: string;
          key: string;
          label: string;
          permissions: string[];
          prefix: string | null;
        }>("POST", "/keys", body);

        return {
          content: [
            {
              type: "text" as const,
              text: `API key created.\n  ID: ${data.id}\n  Key: ${data.key}\n  Permissions: ${data.permissions.join(", ")}\n  Prefix: ${data.prefix ?? "(none)"}\n  (Save the key — it won't be shown again)`,
            },
          ],
        };
      }

      case "sirr_key_list": {
        const data = await sirrRequest<{
          keys: Array<{
            id: string;
            label: string;
            permissions: string[];
            prefix: string | null;
            created_at: number;
          }>;
        }>("GET", "/keys");

        if (data.keys.length === 0) {
          return {
            content: [{ type: "text" as const, text: "No API keys." }],
          };
        }

        const lines = data.keys.map(
          (k) =>
            `• ${k.id} — ${k.label} [${k.permissions.join(",")}] prefix=${k.prefix ?? "*"}`,
        );

        return {
          content: [
            {
              type: "text" as const,
              text: `${data.keys.length} API key(s):\n${lines.join("\n")}`,
            },
          ],
        };
      }

      case "sirr_key_delete": {
        const { id } = args as { id: string };
        await sirrRequest("DELETE", `/keys/${encodeURIComponent(id)}`);
        return {
          content: [
            { type: "text" as const, text: `API key '${id}' deleted.` },
          ],
        };
      }

      default:
        return {
          content: [{ type: "text" as const, text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      content: [{ type: "text" as const, text: `Error: ${message}` }],
      isError: true,
    };
  }
});

// ── Start ─────────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // MCP servers communicate via stdio — no console output here
}

main().catch((e) => {
  process.stderr.write(`sirr-mcp fatal: ${e}\n`);
  process.exit(1);
});
