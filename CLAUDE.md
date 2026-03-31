# Sirr — Claude Development Guide

## Project Overview

Sirr is a self-hosted ephemeral secret vault. Two binaries: `sirrd` (server) and `sirr` (CLI client).
Stack: Rust (axum + redb + ChaCha20Poly1305).

BSL 1.1 license on `sirrd` — free ≤100 secrets/instance, license required above that.
MIT license on `sirr` CLI client.

## Monorepo Layout

```
sirr/                           # github.com/sirrlock/sirr
├── Cargo.toml                  # Rust workspace
├── crates/
│   ├── sirr/                   # sirr CLI client binary (MIT, reqwest-based, no server deps)
│   ├── sirrd/                  # sirrd daemon binary (BSL-1.1, axum server, redb store, crypto)
│   └── sirr-server/            # Library: axum server, redb store, crypto
│       └── src/
│           ├── server.rs       # axum router, CORS, auto-init bootstrap
│           ├── auth.rs         # ResolvedAuth middleware (master key + principal key)
│           ├── handlers.rs     # public-bucket handlers
│           ├── org_handlers.rs # org-scoped CRUD handlers (secrets, principals, roles, keys)
│           └── store/
│               ├── db.rs       # redb store (secrets + org tables)
│               ├── org.rs      # OrgRecord, PrincipalRecord, PrincipalKeyRecord, RoleRecord
│               ├── permissions.rs  # PermBit + Permissions 15-bit bitflag
│               ├── model.rs    # SecretRecord, SecretMeta (owner_id, org_id, allowed_keys)
│               └── crypto.rs   # ChaCha20Poly1305 encrypt/decrypt
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
# With auto-init (creates default org + admin principal + temp keys):
./target/release/sirrd serve --init
# Or via env: SIRR_AUTOINIT=true ./target/release/sirrd serve
# Optionally protect writes: SIRR_MASTER_API_KEY=my-key ./target/release/sirrd serve

# Use CLI client
./target/release/sirr push "some-secret-value"   # public dead drop → returns URL
./target/release/sirr set FOO bar --org acme      # org named slot
./target/release/sirr get FOO --org acme
```

## Architecture

```
sirr.key (random 32 bytes, generated on first boot)
key + per-record nonce --ChaCha20Poly1305--> encrypted value stored in redb
```

- `crates/sirr-server/src/store/crypto.rs` — ChaCha20Poly1305 encrypt/decrypt + key generation
- `crates/sirr-server/src/store/db.rs` — redb open/read/write/patch/head/prune + GetResult enum + org/principal/role/key CRUD (watch borrow lifetimes — AccessGuard must be dropped before mutating the table)
- `crates/sirr-server/src/store/model.rs` — SecretRecord with `delete` flag, `owner_id`, `org_id`, `allowed_keys`; is_expired/is_burned/is_sealed checks
- `crates/sirr-server/src/store/org.rs` — OrgRecord, PrincipalRecord, PrincipalKeyRecord, RoleRecord structs + built-in role definitions
- `crates/sirr-server/src/store/permissions.rs` — PermBit enum (15 bits) + Permissions bitflag with letter-string serde
- `crates/sirr-server/src/server.rs` — axum router, CORS, auto-init bootstrap, key management (sirr.key)
- `crates/sirr-server/src/auth.rs` — ResolvedAuth middleware: master key + principal key lookup + role resolution
- `crates/sirr-server/src/org_handlers.rs` — org-scoped CRUD handlers (orgs, principals, roles, keys, secrets, webhooks, audit)
- `crates/sirrd/src/main.rs` — clap CLI: `serve` (with `--init`) + `rotate` subcommands (server-side ops only)
- `crates/sirr/src/main.rs` — clap CLI: `push` (public dead drop), `set` (org named slot), `get`, `pull`, `run`, `list`, `delete`, `prune`, `audit` (`--key` filter), `webhooks`, `keys`, `orgs`, `principals`, `roles`, `me` (works anonymously). Global `--org` / `$SIRR_ORG` flag, `-v` for version. Default server: `https://sirrlock.com`

## Key Constraints

- `AccessGuard` from redb borrows the table immutably. Always `.to_vec()` the bytes before any mutation on the same table.
- License tiers are now org/principal-count based (Solo: 1 org / 1 principal, Solo+: 1 / 5, Team: 1 / unlimited, Business: unlimited / unlimited). Free tier = Solo.
- **Public bucket** is value-only: `POST /secrets` accepts `{value}` (no `key` field), returns `{id, url}` with a server-generated 256-bit hex ID.
- **Org secrets** reject duplicates: `POST /orgs/{org}/secrets` returns 409 Conflict + `secret.create_rejected` audit event on duplicate key.
- **CLI split**: `push` = public dead drop (value only, returns URL), `set` = org named slot (requires `--org` / `$SIRR_ORG`). The `share` command has been removed — `push`/`set` return URLs directly.
- Default server is `https://sirrlock.com`. Global `--org` / `$SIRR_ORG` flag. `-v` for version. `me` works anonymously. `audit --key` filters by secret key.
- `Store::get()` returns `GetResult` enum: `Value(String)`, `Sealed`, or `NotFound` — handler maps to 200, 410, 404.
- Encryption key is a random 32-byte key stored as `sirr.key`. No KDF — Argon2id is unnecessary when keys are already 256-bit random from OsRng.
- Auth: `SIRR_MASTER_API_KEY` env var acts as master key. Org routes require either master key or principal key (via `require_auth` middleware). Public bucket reads are unauthenticated.
- Deleting an org requires no principals; deleting a principal requires no active keys (cascading deletes not allowed).

## Multi-Tenant Architecture

- **Public bucket** (`/secrets/*`): value-only dead drops with server-generated 256-bit hex IDs, no auth for reads, master key for writes
- **Org buckets** (`/orgs/{org_id}/secrets/*`): named key slots, 409 Conflict on duplicates, require principal auth via `require_auth` middleware
- **Roles**: reader, writer, admin, owner (built-in) + custom per-org. Permissions are a 15-bit bitflag serialized as a letter string (e.g. `"rRlLcCpPaAmMdD"`)
- **Keys**: unlimited named keys per principal, time-windowed (`valid_after`/`valid_before`), hard-deletable
- **`SIRR_ENABLE_PUBLIC_BUCKET`**: env var to disable public bucket (default: true)
- **`SIRR_AUTOINIT`** / `--init`: auto-create default org + admin principal + 2 temporary keys on first boot

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
