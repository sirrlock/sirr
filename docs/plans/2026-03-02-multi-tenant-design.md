# Multi-Tenant Org/Principal System for Sirr

## Context

Sirr currently has no tenant model — one master key, anyone can post/read. Enterprise self-hosted deployments need organizational boundaries, service account management, and granular permissions. This design adds a full org/principal hierarchy with role-based permissions, named API keys, and a dual-mode architecture (public bucket + private org buckets).

**Outcome**: Sirr becomes multi-tenant at the server level, with role-based permissions, unlimited named keys per principal, and full backward compatibility via the public bucket.

---

## Dual-Mode Architecture

The server operates in two modes simultaneously:

### Public Bucket (`/secrets/*`)
- No auth required for reads (GET, HEAD)
- Writes (POST, PATCH, DELETE, list, prune) require master key (`SIRR_API_KEY`)
- Fully backward compatible with all existing clients
- Can be disabled with `ENABLE_PUBLIC_BUCKET=false` (default: `true`)
- Secrets in the public bucket have `org_id: None`

### Org Buckets (`/orgs/{org_id}/secrets/*`)
- All operations require principal auth
- Secrets scoped per-org (compound key `{org_id}:{secret_name}`)
- Two orgs can have the same secret name without conflict
- Optional key-name binding: secrets can restrict access to specific named keys

---

## Data Model

### Entities

**Org** — tenant boundary
```rust
pub struct OrgRecord {
    pub id: String,                          // uuid v4
    pub name: String,
    pub metadata: HashMap<String, String>,   // max 10 props, 100 bytes each
    pub created_at: i64,
}
```

**Principal** — service account / credential (covers humans, CI, AI agents)
```rust
pub struct PrincipalRecord {
    pub id: String,                          // uuid v4
    pub org_id: String,                      // FK → Org
    pub name: String,
    pub role: String,                        // role name (built-in or custom)
    pub metadata: HashMap<String, String>,   // max 10 props, 100 bytes each
    pub created_at: i64,
}
```

**PrincipalKey** — unlimited named keys per principal, hard-deletable
```rust
pub struct PrincipalKeyRecord {
    pub id: String,                          // uuid v4
    pub principal_id: String,
    pub org_id: String,                      // denormalized for auth hot path
    pub name: String,                        // human-readable (e.g., "github_cicd_key")
    pub key_hash: Vec<u8>,                   // SHA-256 of raw key
    pub valid_after: i64,
    pub valid_before: i64,
    pub created_at: i64,
}
```

**Role** — permission template (built-in + custom per-org)
```rust
pub struct RoleRecord {
    pub name: String,                        // unique within org (or global for built-in)
    pub org_id: Option<String>,              // None = built-in, Some = custom per-org
    pub permissions: u16,                    // bitflag
    pub built_in: bool,
    pub created_at: i64,
}
```

**SecretRecord** — existing fields + new additions
```rust
// New fields added to existing SecretRecord:
pub owner_id: Option<String>,               // principal who created it
pub org_id: Option<String>,                 // None = public bucket, Some = org-scoped
pub allowed_keys: Option<Vec<String>>,      // optional key-name binding
```

### redb Tables

```
ORGS:            TableDefinition<&str, &[u8]>     // org_id → bincode(OrgRecord)
PRINCIPALS:      TableDefinition<&str, &[u8]>     // "{org_id}:{principal_id}" → bincode(PrincipalRecord)
PRINCIPAL_KEYS:  TableDefinition<&[u8], &[u8]>    // sha256_hash (32 bytes) → bincode(PrincipalKeyRecord)
PRINCIPAL_KEY_IX: TableDefinition<&str, &[u8]>    // "{principal_id}:{key_id}" → key_hash (32 bytes)
ROLES:           TableDefinition<&str, &[u8]>     // "{org_id}:{role_name}" or "builtin:{role_name}" → bincode(RoleRecord)
SECRETS:         (unchanged for public bucket; "{org_id}:{key}" for org secrets)
```

---

## Permission Model

### Bitflags (internal, 15-bit u16)

Users interact through roles, not raw bitflags. Lowercase = my scope, uppercase = org scope.

| Bit | Letter | Meaning |
|-----|--------|---------|
| 0   | r      | read my secrets |
| 1   | R      | read org secrets |
| 2   | l      | list my secrets |
| 3   | L      | list org secrets |
| 4   | c      | create secrets (owned by me) |
| 5   | C      | create secrets on behalf of others in org |
| 6   | p      | patch my secrets |
| 7   | P      | patch org secrets |
| 8   | a      | read my account (see my keys) |
| 9   | A      | read org accounts |
| 10  | m      | manage my account (create/delete keys, update metadata) |
| 11  | M      | manage org principals/roles |
| 12  | S      | sirr admin (create/delete orgs) — reserved, cannot be used in custom roles |
| 13  | d      | delete my secrets |
| 14  | D      | delete org secrets |

Serialized as letter string in JSON (e.g., `"rlcd"`), stored as u16 in bincode.

### Built-in Roles

| Role | Letters | Use case |
|------|---------|----------|
| `reader` | r, l, a | Read-only agent, monitoring |
| `writer` | r, l, c, p, d, a, m | CI/CD, applications |
| `admin` | r, R, l, L, c, C, p, P, a, A, m, M, d, D | Org admin |
| `owner` | all 15 bits | Org owner (full control) |

### Custom Roles

- Created per-org via API
- Body: `{ "name": "deployer", "permissions": "rlcd" }`
- Cannot include `S` bit (reserved for master key)
- Cannot be deleted if any principal uses it

---

## Auth Model

### Auth Flow

```
Request arrives
  ├─ /secrets/* (public bucket)
  │    ├─ GET/HEAD → no auth needed
  │    └─ POST/PATCH/DELETE/list/prune → requires SIRR_API_KEY (master)
  ├─ /health, /robots.txt → no auth
  ├─ Authorization: Bearer <SIRR_API_KEY>
  │    → ResolvedAuth::Master
  ├─ Authorization: Bearer sirr_key_<hex>
  │    → SHA-256 → PRINCIPAL_KEYS lookup
  │    → check valid_after ≤ now < valid_before
  │    → resolve Principal → resolve Role
  │    → ResolvedAuth::Principal { ... }
  └─ No auth on protected route → 401
```

### ResolvedAuth Enum

```rust
pub enum ResolvedAuth {
    Master,
    Principal {
        principal_id: String,
        org_id: String,
        key_id: String,
        key_name: String,
        permissions: u16,
    },
}
```

### Secret Access with Key Binding

When a secret has `allowed_keys: Some(["github_cicd_key"])`:
1. Principal must have appropriate permission (r/R)
2. The authenticating key's name must be in the `allowed_keys` list
3. If `allowed_keys` is `None`, any key from an authorized principal works

### Master Key Scope

- Can only manage orgs and create first principals
- Cannot directly access secrets or audit logs
- For emergency access: create a temporary principal in the org, do the work, clean up
- All actions audited

---

## API Endpoints

### Public Bucket (disabled by `ENABLE_PUBLIC_BUCKET=false`)

```
POST   /secrets                    Create public secret (master key)
GET    /secrets/{key}              Read public secret (no auth)
HEAD   /secrets/{key}              Metadata (no auth)
GET    /secrets                    List public secrets (master key)
PATCH  /secrets/{key}              Patch public secret (master key)
DELETE /secrets/{key}              Delete public secret (master key)
POST   /prune                      Prune expired (master key)
```

### Master-Only (S permission)

```
POST   /orgs                       Create org
GET    /orgs                       List orgs
DELETE /orgs/{org_id}              Delete org (must have no principals)
POST   /orgs/{org_id}/principals   Create first principal (also M permission)
```

### Org Management (principal auth)

```
GET    /orgs/{org_id}/principals           List principals (A)
POST   /orgs/{org_id}/principals           Create principal (M)
DELETE /orgs/{org_id}/principals/{id}      Delete principal (M, no active keys)
POST   /orgs/{org_id}/roles                Create custom role (M)
GET    /orgs/{org_id}/roles                List roles (A)
DELETE /orgs/{org_id}/roles/{name}         Delete custom role (M)
```

### Principal Self-Service

```
GET    /me                                 My account + keys (a)
PATCH  /me                                 Update my metadata (m)
POST   /me/keys                            Create new named key (m)
DELETE /me/keys/{key_id}                   Delete key (m)
```

### Org Secrets (principal auth, scoped to org)

```
POST   /orgs/{org_id}/secrets              Create (c)
GET    /orgs/{org_id}/secrets              List (l = mine, L = org)
GET    /orgs/{org_id}/secrets/{key}        Read (r = mine, R = org; + key binding)
HEAD   /orgs/{org_id}/secrets/{key}        Metadata (same auth as GET)
PATCH  /orgs/{org_id}/secrets/{key}        Update (p = mine, P = org)
DELETE /orgs/{org_id}/secrets/{key}        Delete (d = mine, D = org)
POST   /orgs/{org_id}/prune               Prune expired (M)
```

### Audit (org-scoped)

```
GET    /orgs/{org_id}/audit                Query audit log (A)
```

### Webhooks (org-scoped)

```
POST   /orgs/{org_id}/webhooks             Register webhook (M)
GET    /orgs/{org_id}/webhooks             List webhooks (A)
DELETE /orgs/{org_id}/webhooks/{id}        Delete webhook (M)
```

---

## Key Lifecycle

- Principals create unlimited named keys via `POST /me/keys`
- Keys have `valid_after` and `valid_before` timestamps
- Keys are hard-deleted via `DELETE /me/keys/{key_id}`
- Key deletion is recorded in audit log
- No auto-rotation — manual create/delete workflow
- Key format: `sirr_key_<32 hex chars>` (displayed once at creation, never stored plaintext)

---

## Cascading Constraints

- Org cannot be deleted if it has principals
- Principal cannot be deleted if it has active (unexpired) keys
- Custom role cannot be deleted if any principal uses it
- Keys can be hard-deleted at any time

---

## Licensing Tiers (replaces 100-secret limit)

| Tier | Orgs | Principals | Secrets | Notes |
|------|------|------------|---------|-------|
| Solo (free) | 1 | 1 | unlimited | No license key needed |
| Team | 1 | unlimited | unlimited | |
| Business | unlimited | unlimited | unlimited | |
| Enterprise | unlimited | unlimited | unlimited | Self-hosted, one-time purchase |

Enforced at org/principal creation time (not secret creation). Public bucket is always free and unlimited.

---

## Files to Modify/Create

### New files
- `crates/sirr-server/src/store/permissions.rs` — `Permissions` bitflag struct, parse/display/serde
- `crates/sirr-server/src/store/org.rs` — OrgRecord, PrincipalRecord, PrincipalKeyRecord, RoleRecord structs + Store CRUD
- `crates/sirr-server/src/org_handlers.rs` — handlers for org/principal/role/key/me endpoints

### Modified files
- `crates/sirr-server/src/store/model.rs` — add `owner_id`, `org_id`, `allowed_keys` to SecretRecord
- `crates/sirr-server/src/store/db.rs` — add new tables to `open_versioned`, add scoped methods
- `crates/sirr-server/src/auth.rs` — replace with `ResolvedAuth` enum (Master/Principal)
- `crates/sirr-server/src/handlers.rs` — refactor to `ResolvedAuth`, public bucket auth logic
- `crates/sirr-server/src/server.rs` — restructure router, wire new endpoints, `ENABLE_PUBLIC_BUCKET`
- `crates/sirr-server/src/lib.rs` — update AppState
- `crates/sirr-server/src/license.rs` — replace `FREE_TIER_LIMIT` with `LicenseTier` enum
- `crates/sirr-server/src/store/audit.rs` — add `org_id`, `principal_id` to AuditEvent
- `crates/sirr-server/src/store/webhooks.rs` — add `org_id` to WebhookRecord
- `crates/sirrd/src/main.rs` — add `--init` flag, autoinit logic
- `crates/sirr/src/main.rs` — add `orgs`, `principals`, `me`, `keys` subcommands

### Removed files
- `crates/sirr-server/src/store/api_keys.rs` — replaced by `org.rs`

---

## Implementation Phases

### Phase 1: Foundation (no behavioral changes)
1. Create `store/permissions.rs` — Permissions bitflag with parse/display/serde
2. Create `store/org.rs` — record structs + table definitions + RoleRecord
3. Add `owner_id`, `org_id`, `allowed_keys` to SecretRecord (Option fields, backward compat)
4. Add new tables to `Store::open_versioned`
5. Seed built-in roles on store open
6. Unit tests for Permissions round-trip

### Phase 2: Store Layer
7. Org CRUD methods
8. Principal CRUD methods
9. Role CRUD methods (built-in + custom)
10. PrincipalKey CRUD methods + secondary index
11. Scoped secret methods (put with owner/org tagging, list_my, list_org, key-binding check)
12. Unit tests for all store methods

### Phase 3: Auth
13. Replace `ResolvedPermissions` → `ResolvedAuth` in auth.rs
14. New auth middleware (master check → principal key lookup → time validation → role resolution)
15. Secret access helpers with key-binding check

### Phase 4: Handlers + Router
16. Org/principal/role/key/me handler functions
17. Refactor existing secret handlers to `ResolvedAuth`
18. Add `ENABLE_PUBLIC_BUCKET` toggle
19. Restructure router in server.rs
20. Integration tests

### Phase 5: License Tiers
21. `LicenseTier` enum replacing `FREE_TIER_LIMIT`
22. Enforce at org/principal creation

### Phase 6: CLI Client
23. Add `orgs`, `principals`, `me`, `keys` subcommands
24. Update existing commands for new auth flow

### Phase 7: Cleanup
25. Remove `store/api_keys.rs` and old Permission enum
26. Update README.md, CLAUDE.md, llms.txt

---

## Verification

### Unit tests
```bash
cargo test --all
```
- Permissions parse/display round-trip
- Role CRUD (built-in immutable, custom deletable, deletion blocked if in use)
- Org/Principal/Key CRUD in store
- Cascading constraint enforcement
- Secret ownership + key-binding checks
- Public bucket vs org bucket isolation

### Manual smoke test
```bash
# 1. Start server
./target/release/sirrd serve

# 2. Public bucket (backward compatible)
curl -X POST localhost:4891/secrets \
  -H "Authorization: Bearer $SIRR_API_KEY" \
  -d '{"key":"PUBLIC_TOKEN","value":"abc123"}'
curl localhost:4891/secrets/PUBLIC_TOKEN  # → no auth needed

# 3. Create org with master key
curl -X POST -H "Authorization: Bearer $SIRR_API_KEY" \
  localhost:4891/orgs -d '{"name":"acme"}'

# 4. Create principal in org
curl -X POST -H "Authorization: Bearer $SIRR_API_KEY" \
  localhost:4891/orgs/$ORG_ID/principals \
  -d '{"name":"ci-bot","role":"writer"}'

# 5. Create named key for principal
curl -X POST -H "Authorization: Bearer $PRINCIPAL_KEY" \
  localhost:4891/me/keys \
  -d '{"name":"deploy_key","valid_before":"2026-04-01T00:00:00Z"}'

# 6. Push org secret with key binding
curl -X POST -H "Authorization: Bearer $DEPLOY_KEY" \
  localhost:4891/orgs/$ORG_ID/secrets \
  -d '{"key":"DATABASE_URL","value":"postgres://...","allowed_keys":["deploy_key"]}'

# 7. Read org secret (only works with deploy_key)
curl -H "Authorization: Bearer $DEPLOY_KEY" \
  localhost:4891/orgs/$ORG_ID/secrets/DATABASE_URL

# 8. Different key from same principal fails key binding
curl -H "Authorization: Bearer $OTHER_KEY" \
  localhost:4891/orgs/$ORG_ID/secrets/DATABASE_URL  # → 403
```

### CI
- `cargo clippy --all-targets` must pass
- `cargo fmt --all --check` must pass
- All existing tests must pass (backward compat via Option fields)
