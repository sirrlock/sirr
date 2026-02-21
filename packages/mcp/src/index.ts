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

// Parse a secret reference from natural language.
// Supports:
//   - "sirr:KEYNAME"          explicit prefix
//   - "KEY#server"            legacy hash format (extracts KEY part)
//   - bare key name           returned as-is
function parseKeyRef(ref: string): string {
  if (ref.startsWith("sirr:")) return ref.slice(5);
  if (ref.includes("#")) return ref.split("#")[0]!;
  return ref.trim();
}

function formatTtl(expiresAt: number | null): string {
  if (expiresAt === null) return "no expiry";
  const now = Math.floor(Date.now() / 1000);
  const secs = expiresAt - now;
  if (secs <= 0) return "expired";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
  return `${Math.floor(secs / 86400)}d`;
}

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
