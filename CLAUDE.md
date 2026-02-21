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
SIRR_MASTER_KEY=dev ./target/release/sirr serve
```

## Architecture

```
SIRR_MASTER_KEY --Argon2id--> 32-byte encryption key (derived once at startup)
key + per-record nonce --ChaCha20Poly1305--> encrypted value stored in redb
```

- `crates/sirr-server/src/store/crypto.rs` — Argon2id + ChaCha20Poly1305
- `crates/sirr-server/src/store/db.rs` — redb open/read/write/prune (watch borrow lifetimes — AccessGuard must be dropped before mutating the table)
- `crates/sirr-server/src/store/model.rs` — SecretRecord (bincode+serde)
- `crates/sirr-server/src/server.rs` — axum router + salt management
- `crates/sirr-server/src/auth.rs` — constant-time bearer token middleware
- `crates/sirr/src/main.rs` — clap CLI dispatch + reqwest HTTP client

## Key Constraints

- `AccessGuard` from redb borrows the table immutably. Always `.to_vec()` the bytes before any mutation on the same table.
- `argon2::Error` and `password_hash::Error` don't implement `std::error::Error`. Use `.map_err(|e| anyhow::anyhow!("{e}"))` — not `.context()`.
- License check: >100 active secrets requires a valid `SIRR_LICENSE_KEY`. The check runs at secret creation time, not at startup.
- The `SIRR_MASTER_KEY` serves double duty: Argon2id seed AND bearer token. This is intentional — one env var to configure.

## Testing

```bash
cargo test --all                   # 6 unit tests (crypto round-trip, TTL, burn, list)

# Manual smoke test
SIRR_MASTER_KEY=test ./target/release/sirr serve &
sleep 1

# Store and retrieve
sirr push DB_URL="postgres://..." --reads 1 --token test
sirr get DB_URL --token test       # Returns value
sirr get DB_URL --token test       # 404 — burned

# TTL test
sirr push TEMP=val --ttl 2s --token test
sleep 3
sirr get TEMP --token test         # 404 — expired
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
argon2 = "0.5"
chacha20poly1305 = "0.10"
```

## Release Process

1. Update versions: `Cargo.toml` workspace version + `packages/node/package.json`
2. Review README.md, CLAUDE.md, llms.txt
3. Tag: `git tag v0.x.0 && git push --tags`
4. CI/release.yml builds all targets, publishes Docker + npm automatically
5. Update SHA256 hashes in `Formula/sirr.rb` with values from the release artifacts
