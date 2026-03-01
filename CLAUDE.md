# Sirr — Claude Development Guide

## Project Overview

Sirr is a self-hosted ephemeral secret vault. Two binaries: `sirrd` (server) and `sirr` (CLI client).
Stack: Rust (axum + redb + ChaCha20Poly1305).

BSL 1.1 license on `sirrd` — free ≤100 secrets/instance, license required above that.
MIT license on `sirr` CLI client.

## Monorepo Layout

```
sirr/                           # github.com/SirrVault/sirr
├── Cargo.toml                  # Rust workspace
├── crates/
│   ├── sirr/                   # sirr CLI client binary (MIT, reqwest-based, no server deps)
│   ├── sirrd/                  # sirrd daemon binary (BSL-1.1, axum server, redb store, crypto)
│   └── sirr-server/            # Library: axum server, redb store, crypto
├── Dockerfile                  # FROM scratch + musl binary
├── Dockerfile.release          # Used by CI release workflow
├── docker-compose.yml          # Production setup with key file mount
└── .github/workflows/
    ├── ci.yml                  # fmt + clippy + test (3 OS)
    └── release.yml             # cross-platform binaries + Docker + crates.io + package managers
```

## Commands

```bash
# Rust
cargo build --release --bin sirrd --bin sirr   # Both binaries
cargo build --release --bin sirrd              # Server only
cargo build --release --bin sirr               # CLI client only
cargo test --all                               # All unit tests
cargo clippy --all-targets                     # Linter
cargo fmt --all                                # Formatter

# Run server locally
./target/release/sirrd serve
# Optionally protect writes: SIRR_API_KEY=my-key ./target/release/sirrd serve

# Use CLI client
./target/release/sirr push FOO=bar
./target/release/sirr get FOO
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
- `crates/sirrd/src/main.rs` — clap CLI: `serve` + `rotate` subcommands (server-side ops only)
- `crates/sirr/src/main.rs` — clap CLI: `push`, `get`, `pull`, `run`, `share`, `list`, `delete`, `prune`, `webhooks`, `audit`, `keys`

## Key Constraints

- `AccessGuard` from redb borrows the table immutably. Always `.to_vec()` the bytes before any mutation on the same table.
- License check: >100 active secrets requires a valid `SIRR_LICENSE_KEY`. The check runs at secret creation time, not at startup.
- `delete` flag on SecretRecord: `true` (default) = burn on max_reads, `false` = seal (block reads, allow PATCH). PATCH only works on `delete=false` secrets.
- `Store::get()` returns `GetResult` enum: `Value(String)`, `Sealed`, or `NotFound` — handler maps to 200, 410, 404.
- Encryption key is a random 32-byte key stored as `sirr.key` (no more Argon2id derivation).
- Auth is optional: `SIRR_API_KEY` env var protects write endpoints (POST/PATCH/DELETE/list). GET and HEAD are always public.

## Testing

```bash
cargo test --all                   # unit tests

# Manual smoke test
./target/release/sirrd serve &
sleep 1

# Store and retrieve (burn after 1 read)
# (requires sirr CLI from separate client)
```

## Pre-Commit Checklist

**After a successful build and before every commit, review and update if needed:**

1. **README.md** — Does it reflect any new commands, env vars, or API changes?
2. **CLAUDE.md** (this file) — Are there new architectural constraints or gotchas worth recording?
3. **llms.txt** — Does it reflect the current feature set? (LLMs may use this to understand the project)

## License Key System

- Free tier: ≤100 active secrets per instance (no license key required)
- Licensed: unlimited secrets with valid `SIRR_LICENSE_KEY`
- License keys are issued at [sirrlock.com/pricing](https://sirrlock.com/pricing)
- Key format: `sirr_lic_<40-hex-chars>` (validated against sirrlock.com API or offline)
- Server behavior: at >100 secrets without a valid license, POST /secrets returns 402 Payment Required

## Crate Versions (pinned)

```
axum = "0.8"
redb = "2"          # NOT v3 — API changed significantly
bincode = "2" with serde feature
chacha20poly1305 = "0.10"
```

## Release Process

CI releases on every push to main. Version: `1.0.<run_number>`.

1. Push to main → CI builds all targets, publishes Docker + crates.io + updates Homebrew/Scoop
2. To publish to crates.io: bump `version` in workspace `Cargo.toml` (CI skips if version already published)
3. Secrets needed in repo settings: `CRATES_IO_TOKEN`, `SIRR_PACKAGE_MANAGERS_KEY`, `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`
