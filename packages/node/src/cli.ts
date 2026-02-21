#!/usr/bin/env node
/**
 * Sirr CLI — thin Node.js wrapper for use via `npx sirr` or `npm i -g sirr`.
 *
 * Reads SIRR_SERVER (default: http://localhost:8080) and SIRR_TOKEN.
 */

import { SirrClient } from "./index.js";

const server = process.env["SIRR_SERVER"] ?? "http://localhost:8080";
const token = process.env["SIRR_TOKEN"] ?? "";

function usage(): void {
  console.error(`
Usage: sirr <command> [options]

Commands:
  push KEY=value [--ttl <secs>] [--reads <n>]
  get KEY
  list
  delete KEY
  prune
  health

Environment:
  SIRR_SERVER   Server URL (default: http://localhost:8080)
  SIRR_TOKEN    Bearer token
`);
  process.exit(1);
}

function parseArgs(argv: string[]): Record<string, string | number | boolean> {
  const result: Record<string, string | number | boolean> = {};
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        result[key] = next;
        i++;
      } else {
        result[key] = true;
      }
    } else {
      positional.push(arg);
      result[`_${positional.length - 1}`] = arg;
    }
  }
  result["_count"] = positional.length;
  return result;
}

async function main() {
  const [, , subcmd, ...rest] = process.argv;
  if (!subcmd) usage();

  const args = parseArgs(rest);
  const client = new SirrClient({ server, token });

  try {
    switch (subcmd) {
      case "health": {
        const r = await client.health();
        console.log(JSON.stringify(r));
        break;
      }

      case "push": {
        const target = args["_0"] as string | undefined;
        if (!target) usage();
        const ttlArg = args["ttl"] as string | undefined;
        const readsArg = args["reads"] as string | undefined;

        if (!target!.includes("=")) {
          console.error("push: expected KEY=value");
          process.exit(1);
        }
        const eqIdx = target!.indexOf("=");
        const key = target!.slice(0, eqIdx);
        const value = target!.slice(eqIdx + 1);
        await client.push(key, value, {
          ttl: ttlArg ? parseInt(ttlArg, 10) : undefined,
          reads: readsArg ? parseInt(readsArg, 10) : undefined,
        });
        console.log(`✓ pushed ${key}`);
        break;
      }

      case "get": {
        const key = args["_0"] as string | undefined;
        if (!key) usage();
        const value = await client.get(key!);
        if (value === null) {
          console.error("not found or expired");
          process.exit(1);
        }
        console.log(value);
        break;
      }

      case "list": {
        const metas = await client.list();
        if (metas.length === 0) {
          console.log("(no active secrets)");
        } else {
          for (const m of metas) {
            console.log(
              `  ${m.key} — reads: ${m.read_count}${m.max_reads != null ? `/${m.max_reads}` : ""}`,
            );
          }
        }
        break;
      }

      case "delete": {
        const key = args["_0"] as string | undefined;
        if (!key) usage();
        const existed = await client.delete(key!);
        console.log(existed ? `✓ deleted ${key}` : "not found");
        break;
      }

      case "prune": {
        const n = await client.prune();
        console.log(`pruned ${n} expired secret(s)`);
        break;
      }

      default:
        usage();
    }
  } catch (e: unknown) {
    console.error((e as Error).message ?? String(e));
    process.exit(1);
  }
}

main();
