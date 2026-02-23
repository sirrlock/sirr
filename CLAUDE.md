# Sirr — Claude Development Guide

## Project Overview

Sirr (سر) is a self-hosted ephemeral secret vault. Single Rust binary, zero runtime deps.
Stack: Rust (axum + redb + ChaCha20Poly1305) + Node.js SDK + MCP server.

BSL 1.1 license — free ≤100 secrets/instance, license required above that.

## Monorepo Layout

```
sirr/
├── Cargo.toml                  # Rust workspace
├── crates/
│   ├── sirr/                   # CLI binary (clap)
│   └── sirr-server/            # Library: axum server, redb store, crypto
├── packages/
│   ├── node/                   # @sirr/node — TypeScript fetch wrapper
│   └── mcp/                    # @sirr/mcp — MCP server for Claude Code
├── Formula/sirr.rb             # Homebrew formula
├── Dockerfile                  # FROM scratch + musl binary
└── .github/workflows/
    ├── ci.yml                  # fmt + clippy + test (3 OS) + npm build/test
    └── release.yml             # cross-platform binaries + Docker + npm publish
```

## Commands

```bash
# Rust
cargo build --release --bin sirr   # Production binary
cargo test --all                   # All unit tests
cargo clippy --all-targets         # Linter
cargo fmt --all                    # Formatter

# Node SDK
cd packages/node && npm install && npm run build && npm test

# MCP server
cd packages/mcp && npm install && npm run build

# Run server locally
./target/release/sirr serve
# Optionally protect writes: SIRR_API_KEY=my-key ./target/release/sirr serve
```

## Architecture

```
sirr.key (random 32 bytes, generated on first boot)
key + per-record nonce --ChaCha20Poly1305--> encrypted value stored in redb
```

- `crates/sirr-server/src/store/crypto.rs` — ChaCha20Poly1305 encrypt/decrypt + key generation
- `crates/sirr-server/src/store/db.rs` — redb open/read/write/patch/head/prune + GetResult enum (watch borrow lifetimes — AccessGuard must be dropped before mutating the table)
- `crates/sirr-server/src/store/model.rs` — SecretRecord with `delete` flag, is_expired/is_burned/is_sealed checks
- `crates/sirr-server/src/server.rs` — axum router, CORS, key management (sirr.key)
- `crates/sirr-server/src/auth.rs` — optional API key middleware (SIRR_API_KEY)
- `crates/sirr/src/main.rs` — clap CLI dispatch + reqwest HTTP client

## Key Constraints

- `AccessGuard` from redb borrows the table immutably. Always `.to_vec()` the bytes before any mutation on the same table.
- License check: >100 active secrets requires a valid `SIRR_LICENSE_KEY`. The check runs at secret creation time, not at startup.
- `delete` flag on SecretRecord: `true` (default) = burn on max_reads, `false` = seal (block reads, allow PATCH). PATCH only works on `delete=false` secrets.
- `Store::get()` returns `GetResult` enum: `Value(String)`, `Sealed`, or `NotFound` — handler maps to 200, 410, 404.
- Encryption key is a random 32-byte key stored as `sirr.key` (no more Argon2id derivation).
- Auth is optional: `SIRR_API_KEY` env var protects write endpoints (POST/PATCH/DELETE/list). GET and HEAD are always public.

## Testing

```bash
cargo test --all                   # 23 unit tests

# Manual smoke test
./target/release/sirr serve &
sleep 1

# Store and retrieve (burn after 1 read)
sirr push DB_URL="postgres://..." --reads 1
sirr get DB_URL                    # Returns value
sirr get DB_URL                    # 404 — burned

# Patchable secret (no auto-delete)
sirr push CF_TOKEN=abc123 --reads 5 --no-delete
sirr get CF_TOKEN                  # Returns value, read_count = 1

# TTL test
sirr push TEMP=val --ttl 2s
sleep 3
sirr get TEMP                      # 404 — expired
```

## Pre-Commit Checklist

**After a successful build and before every commit, review and update if needed:**

1. **README.md** — Does it reflect any new commands, env vars, or API changes?
2. **CLAUDE.md** (this file) — Are there new architectural constraints or gotchas worth recording?
3. **llms.txt** — Does it reflect the current feature set? (LLMs may use this to understand the project)

This applies to all packages — Rust crates, Node SDK, and MCP server.

## License Key System

- Free tier: ≤100 active secrets per instance (no license key required)
- Licensed: unlimited secrets with valid `SIRR_LICENSE_KEY`
- License keys are issued at [secretdrop.app/sirr](https://secretdrop.app/sirr)
- Key format: `sirr_lic_<40-hex-chars>` (validated against secretdrop.app API or offline)
- Server behavior: at >100 secrets without a valid license, POST /secrets returns 402 Payment Required

## Crate Versions (pinned)

```
axum = "0.8"
redb = "2"          # NOT v3 — API changed significantly
bincode = "2" with serde feature
chacha20poly1305 = "0.10"
```

## Release Process

1. Update versions: `Cargo.toml` workspace version + `packages/node/package.json`
2. Review README.md, CLAUDE.md, llms.txt
3. Tag: `git tag v0.x.0 && git push --tags`
4. CI/release.yml builds all targets, publishes Docker + npm automatically
5. Update SHA256 hashes in `Formula/sirr.rb` with values from the release artifacts
