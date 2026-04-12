# Sirr — Claude Development Guide

## Project Overview

Sirr is a self-hosted ephemeral secret vault. Two binaries: `sirrd` (server) and `sirr` (CLI client).
Stack: Rust (axum + redb + ChaCha20Poly1305).

BSL 1.1 license on `sirrd`. MIT license on `sirr` CLI client.

## Monorepo Layout

```
sirr/                           # github.com/sirrlock/sirr
├── Cargo.toml                  # Rust workspace
├── crates/
│   ├── sirr/                   # sirr CLI client binary (MIT, reqwest-based)
│   ├── sirrd/                  # sirrd daemon binary (BSL-1.1)
│   └── sirr-server/            # Library: axum server, redb store, crypto
│       └── src/
│           ├── lib.rs          # pub mod declarations and re-exports
│           ├── server.rs       # Bootstrap, key file, store open, spawn server + admin socket
│           ├── handlers.rs     # Five HTTP endpoints over /secret/:hash + AppState
│           ├── authz.rs        # Single authorize() function with ~20-row decision table
│           ├── admin.rs        # Unix domain socket server + admin command dispatch
│           ├── webhooks.rs     # WebhookSender — fire-and-forget per-key webhooks
│           ├── dirs.rs         # data_dir() resolution honoring SIRR_DATA_DIR
│           └── store/
│               ├── mod.rs      # Re-exports
│               ├── db.rs       # redb store: secrets, keys, audit, config tables
│               ├── model.rs    # SecretRecord (hash, ciphertext, owner_key_id, ...)
│               ├── keys.rs     # KeyRecord with webhook_url, validity window, blake3 hash
│               ├── audit.rs    # AuditEvent, AuditQuery, ACTION_* constants
│               ├── visibility.rs  # Visibility enum (Public/Private/Both/None)
│               └── crypto.rs   # ChaCha20Poly1305 encrypt/decrypt + key generation
├── tests/
│   └── http_api.rs             # Integration tests for 5 HTTP endpoints
├── Dockerfile                  # FROM scratch + musl binary
├── Dockerfile.release          # Used by CI release workflow
├── docker-compose.yml          # Production setup
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
cargo test --all                               # All tests
cargo clippy --all-targets                     # Linter
cargo fmt --all                                # Formatter

# Run server locally
./target/release/sirrd serve
./target/release/sirrd serve --visibility private
./target/release/sirrd serve --visibility both

# Admin commands (via Unix socket, sirrd must be running)
./target/release/sirrd keys create my-key
./target/release/sirrd keys list
./target/release/sirrd keys delete my-key
./target/release/sirrd visibility set private
./target/release/sirrd visibility get

# Use CLI client
./target/release/sirr push "some-secret-value"
./target/release/sirr push "value" --reads 1 --ttl 1h --key <token>
./target/release/sirr get <hash>
./target/release/sirr inspect <hash>
./target/release/sirr audit <hash> --key <token>
./target/release/sirr patch <hash> "new-value" --key <token>
./target/release/sirr burn <hash> [--key <token>]
```

## Architecture

```
sirr.key (random 32 bytes, generated on first boot)
key + per-record nonce --ChaCha20Poly1305--> encrypted value stored in redb
```

### Authorization model

The `authorize()` function in `authz.rs` takes `(Action, Option<&SecretRecord>, &Caller, Visibility, now)` and returns `AuthDecision`. The decision matrix:

- **Create**: public → anyone; private/both → keyed only; none → 503
- **Read (GET)**: public/private/both → anyone (reads are universal); none → 503
- **Inspect (HEAD)**: same as read
- **Patch**: keyed caller must be owner; record must exist + not burned/expired
- **Burn**: keyed caller must be owner; anonymous caller can burn anonymous secret
- **Audit**: keyed caller must be owner; record must exist

### Visibility

`Visibility` is an `Arc<RwLock<Visibility>>` shared between handlers and the admin socket. Changed at runtime by the admin socket — no restart needed.

### Admin socket

Unix domain socket at `SIRR_ADMIN_SOCKET` (default `/tmp/sirrd.sock`). Authenticated by filesystem permissions (only users who can write to the socket can issue commands). Framed protocol: newline-delimited JSON.

### Webhooks

`WebhookSender` holds a shared `reqwest::Client` (10-second timeout). `fire()` spawns a tokio task and never blocks. Only keyed secrets trigger webhooks (anonymous dead drops have no key to attach a URL to). Fires after: `secret.created`, `secret.read`, `secret.patched`, `secret.burned`.

## Key Constraints

- `AccessGuard` from redb borrows the table immutably. Always `.to_vec()` the bytes before any mutation on the same table.
- The `store/crypto.rs` module is load-bearing — do not modify the encrypt/decrypt interface.
- `dirs.rs` is load-bearing — do not change the data_dir resolution logic.
- Schema version is stored in the `config` table. Current version: `"2"`. Stale version (from old org model) exits with an error message and code 1.
- `find_key_by_id()` performs two separate read transactions (id→hash→record). This is intentional to avoid redb borrow lifetime issues with multi-table access.
- Keys are stored in three parallel tables: `keys_by_id` (ULID → record), `keys_by_hash` (blake3 hash → ULID), `keys_by_name` (name → ULID). All three must be kept in sync on create/delete.
- The bearer token is shown exactly once at key creation and is never stored — only the blake3 hash.
- Webhook URLs are stored on the `KeyRecord` — not as a separate table. Each key has at most one webhook URL.
- Anonymous secrets (`owner_key_id: None`) never trigger webhooks.

## New Architecture vs Old

**Removed entirely:**
- `org_handlers.rs` — all org-scoped CRUD
- `auth.rs` — master key + principal resolution middleware
- `store/org.rs` — OrgRecord, PrincipalRecord, RoleRecord
- `store/permissions.rs` — 15-bit bitflag
- `store/webhooks.rs` — webhook subscription model (replaced by `webhook_url` on KeyRecord)
- `validator.rs` — online license validator
- `license.rs` — no licensing enforcement; honor system only

**Replaced:**
- `webhooks.rs` (403 LOC complex subscription model) → `webhooks.rs` (60 LOC fire-and-forget)

**New:**
- `authz.rs` — single `authorize()` function
- `admin.rs` — Unix domain socket admin server
- `store/visibility.rs` — Visibility enum + persistence
- `store/keys.rs` — KeyRecord with webhook_url field

## Testing

```bash
cargo test --all   # 115+ tests across 8 suites

# Test suites:
# - store/model.rs unit tests
# - store/keys.rs unit tests
# - store/audit.rs unit tests
# - store/visibility.rs unit tests
# - authz.rs unit tests
# - tests/authz_matrix.rs — full decision table
# - tests/http_api.rs — 5-endpoint HTTP integration
# - tests/webhooks.rs — wiremock-based webhook delivery
# - tests/end_to_end.rs — full lifecycle, visibility, lockdown, prune
```

## Crate Versions (pinned)

```
axum = "0.8"
redb = "2"          # NOT v3 — API changed significantly
bincode = "2" with serde feature
chacha20poly1305 = "0.10"
reqwest = "0.12"    # webhook HTTP client (rustls-tls, no default features)
wiremock = "0.6"    # dev-dependency for webhook tests
```

## Pre-Commit Checklist

**After a successful build and before every commit, review and update if needed:**

1. **README.md** — Does it reflect any new commands, env vars, or API changes?
2. **CLAUDE.md** (this file) — Are there new architectural constraints or gotchas worth recording?
3. **llms.txt** — Does it reflect the current feature set? (LLMs may use this to understand the project)

## Release Process

CI releases on every push to main. Version: `1.0.<run_number>`.

1. Push to main → CI builds all targets, publishes Docker + crates.io + updates Homebrew/Scoop
2. Windows targets build `sirr` CLI only (no `sirrd` — it requires a Unix socket)
3. Secrets needed in repo settings: `CRATES_IO_TOKEN`, `SIRR_PACKAGE_MANAGERS_KEY`, `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`
