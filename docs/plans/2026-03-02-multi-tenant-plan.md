# Multi-Tenant Org/Principal System — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add multi-tenant org/principal system with dual-mode architecture (public bucket + private org buckets), role-based permissions, and unlimited named keys per principal.

**Architecture:** Public bucket at `/secrets/*` stays backward-compatible (no auth for reads). New org buckets at `/orgs/{org_id}/secrets/*` require principal auth. Roles (built-in + custom) map to 15-bit permission bitflags internally. Keys are unlimited, named, hard-deletable.

**Tech Stack:** Rust, axum 0.8, redb 2, bincode 2, chacha20poly1305 0.10, SHA-256 for key hashing

**Design doc:** `docs/plans/2026-03-02-multi-tenant-design.md`

---

## Task 1: Permissions Bitflag Module

**Files:**
- Create: `crates/sirr-server/src/store/permissions.rs`
- Modify: `crates/sirr-server/src/store/mod.rs`

**Step 1: Write the failing test**

Create `crates/sirr-server/src/store/permissions.rs` with test module only:

```rust
/// 15-bit permission bitflag system.
/// Lowercase = my scope, uppercase = org scope.
///
/// | Bit | Letter | Meaning |
/// |-----|--------|---------|
/// | 0   | r      | read my secrets |
/// | 1   | R      | read org secrets |
/// | 2   | l      | list my secrets |
/// | 3   | L      | list org secrets |
/// | 4   | c      | create secrets |
/// | 5   | C      | create on behalf of others |
/// | 6   | p      | patch my secrets |
/// | 7   | P      | patch org secrets |
/// | 8   | a      | read my account |
/// | 9   | A      | read org accounts |
/// | 10  | m      | manage my account |
/// | 11  | M      | manage org principals/roles |
/// | 12  | S      | sirr admin (create/delete orgs) |
/// | 13  | d      | delete my secrets |
/// | 14  | D      | delete org secrets |

use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_permissions() {
        let all = "rRlLcCpPaAmMSdD";
        let perms = Permissions::parse(all).unwrap();
        assert_eq!(perms.to_letter_string(), all);
        assert_eq!(perms.bits(), 0x7FFF); // all 15 bits set
    }

    #[test]
    fn round_trip_reader() {
        let perms = Permissions::parse("rla").unwrap();
        assert_eq!(perms.to_letter_string(), "rla");
        assert!(perms.has(PermBit::ReadMy));
        assert!(perms.has(PermBit::ListMy));
        assert!(perms.has(PermBit::AccountRead));
        assert!(!perms.has(PermBit::ReadOrg));
    }

    #[test]
    fn invalid_letter_rejected() {
        assert!(Permissions::parse("rxl").is_err());
    }

    #[test]
    fn empty_string_is_zero() {
        let perms = Permissions::parse("").unwrap();
        assert_eq!(perms.bits(), 0);
        assert_eq!(perms.to_letter_string(), "");
    }

    #[test]
    fn serde_json_round_trip() {
        let perms = Permissions::parse("rlcd").unwrap();
        let json = serde_json::to_string(&perms).unwrap();
        assert_eq!(json, r#""rlcd""#);
        let back: Permissions = serde_json::from_str(&json).unwrap();
        assert_eq!(back, perms);
    }

    #[test]
    fn bitwise_subset_check() {
        let admin = Permissions::parse("rRlLcCpPaAmMdD").unwrap();
        let reader = Permissions::parse("rla").unwrap();
        assert!(reader.is_subset_of(&admin));
        assert!(!admin.is_subset_of(&reader));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sirr-server store::permissions::tests --no-run 2>&1 | head -20`
Expected: Compilation errors (Permissions, PermBit not defined)

**Step 3: Write the implementation**

Add above the test module in the same file:

```rust
use std::fmt;

/// Ordered list of permission letters for consistent display.
const LETTER_ORDER: &[(char, u8)] = &[
    ('r', 0), ('R', 1), ('l', 2), ('L', 3),
    ('c', 4), ('C', 5), ('p', 6), ('P', 7),
    ('a', 8), ('A', 9), ('m', 10), ('M', 11),
    ('S', 12), ('d', 13), ('D', 14),
];

/// Individual permission bit identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermBit {
    ReadMy = 0,
    ReadOrg = 1,
    ListMy = 2,
    ListOrg = 3,
    Create = 4,
    CreateOnBehalf = 5,
    PatchMy = 6,
    PatchOrg = 7,
    AccountRead = 8,
    AccountReadOrg = 9,
    AccountManage = 10,
    ManageOrg = 11,
    SirrAdmin = 12,
    DeleteMy = 13,
    DeleteOrg = 14,
}

/// 15-bit permission bitflag. Serializes as letter string in JSON, stored as u16 in bincode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions(u16);

impl Permissions {
    pub fn none() -> Self {
        Self(0)
    }

    pub fn all() -> Self {
        Self(0x7FFF)
    }

    pub fn bits(&self) -> u16 {
        self.0
    }

    pub fn from_bits(bits: u16) -> Self {
        Self(bits & 0x7FFF)
    }

    pub fn has(&self, bit: PermBit) -> bool {
        self.0 & (1 << bit as u8) != 0
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0 & other.0 == self.0
    }

    /// Parse a letter string like "rRlLcC" into a Permissions bitflag.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut bits: u16 = 0;
        for ch in s.chars() {
            match LETTER_ORDER.iter().find(|(c, _)| *c == ch) {
                Some((_, bit)) => bits |= 1 << bit,
                None => return Err(format!("invalid permission letter: '{ch}'")),
            }
        }
        Ok(Self(bits))
    }

    /// Display as ordered letter string (e.g., "rRlLcC").
    pub fn to_letter_string(&self) -> String {
        let mut s = String::new();
        for &(ch, bit) in LETTER_ORDER {
            if self.0 & (1 << bit) != 0 {
                s.push(ch);
            }
        }
        s
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_letter_string())
    }
}

impl Serialize for Permissions {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_letter_string())
    }
}

impl<'de> Deserialize<'de> for Permissions {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Permissions::parse(&s).map_err(serde::de::Error::custom)
    }
}
```

**Step 4: Register the module**

In `crates/sirr-server/src/store/mod.rs`, add after existing modules:

```rust
pub mod permissions;
```

And add to re-exports:

```rust
pub use permissions::{PermBit, Permissions};
```

**Step 5: Run tests to verify they pass**

Run: `cargo test -p sirr-server store::permissions::tests -v`
Expected: All 6 tests PASS

**Step 6: Commit**

```bash
git add crates/sirr-server/src/store/permissions.rs crates/sirr-server/src/store/mod.rs
git commit -m "feat: add Permissions bitflag module with parse/display/serde"
```

---

## Task 2: Org/Principal/Key Record Structs

**Files:**
- Create: `crates/sirr-server/src/store/org.rs`
- Modify: `crates/sirr-server/src/store/mod.rs`

**Step 1: Write the record structs with test**

Create `crates/sirr-server/src/store/org.rs`:

```rust
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::permissions::Permissions;

/// redb table definitions for the multi-tenant system.
pub const ORGS: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("orgs");
pub const PRINCIPALS: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("principals");
pub const PRINCIPAL_KEYS: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("principal_keys");
pub const PRINCIPAL_KEY_IX: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("principal_key_ix");
pub const ROLES: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("roles");

const MAX_METADATA_PROPS: usize = 10;
const MAX_METADATA_VALUE_BYTES: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgRecord {
    pub id: String,
    pub name: String,
    pub metadata: HashMap<String, String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalRecord {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub role: String,
    pub metadata: HashMap<String, String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalKeyRecord {
    pub id: String,
    pub principal_id: String,
    pub org_id: String,
    pub name: String,
    pub key_hash: Vec<u8>,
    pub valid_after: i64,
    pub valid_before: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleRecord {
    pub name: String,
    pub org_id: Option<String>,
    pub permissions: Permissions,
    pub built_in: bool,
    pub created_at: i64,
}

/// Validate metadata: max 10 props, each value max 100 bytes.
pub fn validate_metadata(metadata: &HashMap<String, String>) -> Result<(), String> {
    if metadata.len() > MAX_METADATA_PROPS {
        return Err(format!("metadata exceeds {MAX_METADATA_PROPS} properties"));
    }
    for (k, v) in metadata {
        if v.len() > MAX_METADATA_VALUE_BYTES {
            return Err(format!("metadata value for '{k}' exceeds {MAX_METADATA_VALUE_BYTES} bytes"));
        }
    }
    Ok(())
}

/// Built-in role definitions. These are seeded on store open.
pub fn builtin_roles() -> Vec<RoleRecord> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    vec![
        RoleRecord {
            name: "reader".to_owned(),
            org_id: None,
            permissions: Permissions::parse("rla").unwrap(),
            built_in: true,
            created_at: now,
        },
        RoleRecord {
            name: "writer".to_owned(),
            org_id: None,
            permissions: Permissions::parse("rlcpdam").unwrap(),
            built_in: true,
            created_at: now,
        },
        RoleRecord {
            name: "admin".to_owned(),
            org_id: None,
            permissions: Permissions::parse("rRlLcCpPaAmMdD").unwrap(),
            built_in: true,
            created_at: now,
        },
        RoleRecord {
            name: "owner".to_owned(),
            org_id: None,
            permissions: Permissions::all(),
            built_in: true,
            created_at: now,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_metadata_ok() {
        let mut m = HashMap::new();
        m.insert("team".into(), "platform".into());
        assert!(validate_metadata(&m).is_ok());
    }

    #[test]
    fn validate_metadata_too_many_props() {
        let m: HashMap<String, String> = (0..11).map(|i| (format!("k{i}"), "v".into())).collect();
        assert!(validate_metadata(&m).is_err());
    }

    #[test]
    fn validate_metadata_value_too_long() {
        let mut m = HashMap::new();
        m.insert("k".into(), "x".repeat(101));
        assert!(validate_metadata(&m).is_err());
    }

    #[test]
    fn builtin_roles_created() {
        let roles = builtin_roles();
        assert_eq!(roles.len(), 4);
        assert_eq!(roles[0].name, "reader");
        assert_eq!(roles[3].name, "owner");
        assert!(roles[3].permissions.has(super::super::permissions::PermBit::SirrAdmin));
    }

    #[test]
    fn bincode_round_trip_org() {
        let org = OrgRecord {
            id: "test-id".into(),
            name: "acme".into(),
            metadata: HashMap::new(),
            created_at: 1234567890,
        };
        let bytes = bincode::serde::encode_to_vec(&org, bincode::config::standard()).unwrap();
        let (decoded, _): (OrgRecord, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(decoded.id, org.id);
        assert_eq!(decoded.name, org.name);
    }

    #[test]
    fn bincode_round_trip_principal_key() {
        let key = PrincipalKeyRecord {
            id: "key-id".into(),
            principal_id: "p-id".into(),
            org_id: "o-id".into(),
            name: "deploy_key".into(),
            key_hash: vec![1, 2, 3],
            valid_after: 100,
            valid_before: 200,
            created_at: 100,
        };
        let bytes = bincode::serde::encode_to_vec(&key, bincode::config::standard()).unwrap();
        let (decoded, _): (PrincipalKeyRecord, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(decoded.name, "deploy_key");
        assert_eq!(decoded.valid_before, 200);
    }
}
```

**Step 2: Register the module**

In `crates/sirr-server/src/store/mod.rs`, add:

```rust
pub mod org;
```

And add to re-exports:

```rust
pub use org::{OrgRecord, PrincipalRecord, PrincipalKeyRecord, RoleRecord, validate_metadata, builtin_roles};
```

**Step 3: Run tests**

Run: `cargo test -p sirr-server store::org::tests -v`
Expected: All 6 tests PASS

**Step 4: Commit**

```bash
git add crates/sirr-server/src/store/org.rs crates/sirr-server/src/store/mod.rs
git commit -m "feat: add org/principal/key/role record structs with validation"
```

---

## Task 3: Add New Fields to SecretRecord

**Files:**
- Modify: `crates/sirr-server/src/store/model.rs:4-17` (SecretRecord struct)

**Step 1: Write the failing test**

Add to the existing test module in `crates/sirr-server/src/store/model.rs` (after existing tests):

```rust
#[test]
fn new_fields_default_to_none() {
    // Simulate deserializing a v1 record (no new fields)
    let old_record = SecretRecord {
        value_encrypted: vec![1, 2, 3],
        nonce: [0u8; 12],
        created_at: 1000,
        expires_at: None,
        max_reads: None,
        read_count: 0,
        delete: true,
        webhook_url: None,
        owner_id: None,
        org_id: None,
        allowed_keys: None,
    };
    assert!(old_record.owner_id.is_none());
    assert!(old_record.org_id.is_none());
    assert!(old_record.allowed_keys.is_none());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sirr-server store::model::tests::new_fields_default_to_none --no-run 2>&1 | head -20`
Expected: Compilation error (fields don't exist yet)

**Step 3: Add new fields to SecretRecord**

In `crates/sirr-server/src/store/model.rs`, add these fields to the `SecretRecord` struct after `webhook_url`:

```rust
    /// Principal who created this secret (None for public bucket).
    #[serde(default)]
    pub owner_id: Option<String>,
    /// Org this secret belongs to (None = public bucket).
    #[serde(default)]
    pub org_id: Option<String>,
    /// Optional key-name binding. If set, only keys with matching names can access.
    #[serde(default)]
    pub allowed_keys: Option<Vec<String>>,
```

Also add `owner_id` and `org_id` to `SecretMeta`:

```rust
    pub owner_id: Option<String>,
    pub org_id: Option<String>,
```

**Step 4: Fix all existing code that constructs SecretRecord or SecretMeta**

In `crates/sirr-server/src/store/db.rs`, find every place `SecretRecord` or `SecretMeta` is constructed and add the new fields with default values:
- `put()` method (around line 82): The `SecretRecord` is passed in by the handler — no change needed in store.
- `list()` method (around line 205): Add `owner_id: rec.owner_id.clone(), org_id: rec.org_id.clone()` to `SecretMeta` construction.
- `head()` method (around line 275): Same as list.

In `crates/sirr-server/src/handlers.rs`, find `create_secret()` (around line 250-270) where `SecretRecord` is constructed:
- Add `owner_id: None, org_id: None, allowed_keys: None` to the struct literal.

In test helper `make_store()` usage in `db.rs` tests: the `store.put()` calls pass `SecretRecord` — add new fields.

**Step 5: Run all tests to verify nothing breaks**

Run: `cargo test --all -v`
Expected: All tests PASS (serde defaults ensure backward compat)

**Step 6: Commit**

```bash
git add crates/sirr-server/src/store/model.rs crates/sirr-server/src/store/db.rs crates/sirr-server/src/handlers.rs
git commit -m "feat: add owner_id, org_id, allowed_keys to SecretRecord"
```

---

## Task 4: Register New Tables in Store

**Files:**
- Modify: `crates/sirr-server/src/store/db.rs:53-72` (open_versioned function)

**Step 1: Write the failing test**

Add to `crates/sirr-server/src/store/db.rs` test module:

```rust
#[test]
fn new_tables_created_on_open() {
    let (store, _dir) = make_store();
    let read_txn = store.db.begin_read().unwrap();
    // These should not panic — tables exist
    read_txn.open_table(super::super::org::ORGS).unwrap();
    read_txn.open_table(super::super::org::PRINCIPALS).unwrap();
    read_txn.open_table(super::super::org::PRINCIPAL_KEYS).unwrap();
    read_txn.open_table(super::super::org::PRINCIPAL_KEY_IX).unwrap();
    read_txn.open_table(super::super::org::ROLES).unwrap();
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sirr-server store::db::tests::new_tables_created_on_open -v`
Expected: FAIL (tables don't exist yet)

**Step 3: Add tables to open_versioned**

In `crates/sirr-server/src/store/db.rs`, inside `open_versioned()` (around line 63), add after the existing `write_txn.open_table()` calls:

```rust
    write_txn.open_table(super::org::ORGS)?;
    write_txn.open_table(super::org::PRINCIPALS)?;
    write_txn.open_table(super::org::PRINCIPAL_KEYS)?;
    write_txn.open_table(super::org::PRINCIPAL_KEY_IX)?;
    write_txn.open_table(super::org::ROLES)?;
```

**Step 4: Seed built-in roles**

After `write_txn.commit()?;` in `open_versioned()`, add:

```rust
    // Seed built-in roles if not already present.
    {
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(super::org::ROLES)?;
            for role in super::org::builtin_roles() {
                let key = format!("builtin:{}", role.name);
                if table.get(key.as_str())?.is_none() {
                    let bytes = bincode::serde::encode_to_vec(&role, bincode::config::standard())
                        .context("encode builtin role")?;
                    table.insert(key.as_str(), bytes.as_slice())?;
                }
            }
        }
        write_txn.commit()?;
    }
```

**Step 5: Run tests**

Run: `cargo test --all -v`
Expected: All tests PASS

**Step 6: Commit**

```bash
git add crates/sirr-server/src/store/db.rs
git commit -m "feat: register org/principal/key/role tables and seed built-in roles"
```

---

## Task 5: Org CRUD Store Methods

**Files:**
- Modify: `crates/sirr-server/src/store/db.rs`

**Step 1: Write failing tests**

Add to `crates/sirr-server/src/store/db.rs` test module:

```rust
#[test]
fn org_crud() {
    let (store, _dir) = make_store();
    let org = super::super::org::OrgRecord {
        id: "org-1".into(),
        name: "acme".into(),
        metadata: std::collections::HashMap::new(),
        created_at: 1000,
    };

    // Create
    store.put_org(&org).unwrap();

    // Read
    let fetched = store.get_org("org-1").unwrap().unwrap();
    assert_eq!(fetched.name, "acme");

    // List
    let all = store.list_orgs().unwrap();
    assert_eq!(all.len(), 1);

    // Delete (no principals)
    assert!(store.delete_org("org-1").unwrap());

    // Gone
    assert!(store.get_org("org-1").unwrap().is_none());
}

#[test]
fn delete_org_blocked_by_principals() {
    let (store, _dir) = make_store();
    let org = super::super::org::OrgRecord {
        id: "org-1".into(),
        name: "acme".into(),
        metadata: std::collections::HashMap::new(),
        created_at: 1000,
    };
    store.put_org(&org).unwrap();

    let principal = super::super::org::PrincipalRecord {
        id: "p-1".into(),
        org_id: "org-1".into(),
        name: "bot".into(),
        role: "writer".into(),
        metadata: std::collections::HashMap::new(),
        created_at: 1000,
    };
    store.put_principal(&principal).unwrap();

    // Should fail — org has principals
    let result = store.delete_org("org-1");
    assert!(result.is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sirr-server store::db::tests::org_crud --no-run 2>&1 | head -20`
Expected: Compilation error (methods don't exist)

**Step 3: Implement org CRUD methods**

Add to `impl Store` in `crates/sirr-server/src/store/db.rs`:

```rust
    // ── Org CRUD ──────────────────────────────────────────────

    pub fn put_org(&self, org: &super::org::OrgRecord) -> Result<()> {
        let bytes = bincode::serde::encode_to_vec(org, bincode::config::standard())
            .context("encode org")?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(super::org::ORGS)?;
            table.insert(org.id.as_str(), bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_org(&self, id: &str) -> Result<Option<super::org::OrgRecord>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(super::org::ORGS)?;
        match table.get(id)? {
            Some(guard) => {
                let bytes = guard.value().to_vec();
                let (record, _) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                    .context("decode org")?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    pub fn list_orgs(&self) -> Result<Vec<super::org::OrgRecord>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(super::org::ORGS)?;
        let mut orgs = Vec::new();
        for entry in table.iter()? {
            let (_, v) = entry?;
            let bytes = v.value().to_vec();
            let (record, _): (super::org::OrgRecord, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                    .context("decode org")?;
            orgs.push(record);
        }
        Ok(orgs)
    }

    /// Delete org. Fails if org has any principals.
    pub fn delete_org(&self, id: &str) -> Result<bool> {
        // Check for principals first
        let prefix = format!("{id}:");
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(super::org::PRINCIPALS)?;
        for entry in table.iter()? {
            let (k, _) = entry?;
            if k.value().starts_with(&prefix) {
                anyhow::bail!("cannot delete org with existing principals");
            }
        }
        drop(table);
        drop(read_txn);

        let write_txn = self.db.begin_write()?;
        let existed = {
            let mut table = write_txn.open_table(super::org::ORGS)?;
            table.remove(id)?.is_some()
        };
        write_txn.commit()?;
        Ok(existed)
    }
```

**Step 4: Run tests**

Run: `cargo test -p sirr-server store::db::tests::org_crud store::db::tests::delete_org_blocked_by_principals -v`
Expected: Both PASS

**Step 5: Commit**

```bash
git add crates/sirr-server/src/store/db.rs
git commit -m "feat: add org CRUD store methods with cascading delete constraint"
```

---

## Task 6: Principal CRUD Store Methods

**Files:**
- Modify: `crates/sirr-server/src/store/db.rs`

**Step 1: Write failing tests**

Add to test module in `db.rs`:

```rust
#[test]
fn principal_crud() {
    let (store, _dir) = make_store();
    let org = super::super::org::OrgRecord {
        id: "org-1".into(), name: "acme".into(),
        metadata: std::collections::HashMap::new(), created_at: 1000,
    };
    store.put_org(&org).unwrap();

    let principal = super::super::org::PrincipalRecord {
        id: "p-1".into(), org_id: "org-1".into(), name: "bot".into(),
        role: "writer".into(), metadata: std::collections::HashMap::new(),
        created_at: 1000,
    };
    store.put_principal(&principal).unwrap();

    let fetched = store.get_principal("org-1", "p-1").unwrap().unwrap();
    assert_eq!(fetched.name, "bot");

    let all = store.list_principals("org-1").unwrap();
    assert_eq!(all.len(), 1);

    // No active keys → can delete
    assert!(store.delete_principal("org-1", "p-1").unwrap());
    assert!(store.get_principal("org-1", "p-1").unwrap().is_none());
}

#[test]
fn delete_principal_blocked_by_active_keys() {
    let (store, _dir) = make_store();
    let org = super::super::org::OrgRecord {
        id: "org-1".into(), name: "acme".into(),
        metadata: std::collections::HashMap::new(), created_at: 1000,
    };
    store.put_org(&org).unwrap();

    let principal = super::super::org::PrincipalRecord {
        id: "p-1".into(), org_id: "org-1".into(), name: "bot".into(),
        role: "writer".into(), metadata: std::collections::HashMap::new(),
        created_at: 1000,
    };
    store.put_principal(&principal).unwrap();

    // Create a key valid for 1 hour in the future
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    let key_record = super::super::org::PrincipalKeyRecord {
        id: "k-1".into(), principal_id: "p-1".into(), org_id: "org-1".into(),
        name: "deploy".into(), key_hash: vec![1, 2, 3],
        valid_after: now - 100, valid_before: now + 3600, created_at: now,
    };
    store.put_principal_key(&key_record).unwrap();

    // Should fail — principal has active keys
    let result = store.delete_principal("org-1", "p-1");
    assert!(result.is_err());
}
```

**Step 2: Implement principal CRUD**

Add to `impl Store`:

```rust
    // ── Principal CRUD ────────────────────────────────────────

    pub fn put_principal(&self, principal: &super::org::PrincipalRecord) -> Result<()> {
        let bytes = bincode::serde::encode_to_vec(principal, bincode::config::standard())
            .context("encode principal")?;
        let compound = format!("{}:{}", principal.org_id, principal.id);
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(super::org::PRINCIPALS)?;
            table.insert(compound.as_str(), bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_principal(&self, org_id: &str, principal_id: &str) -> Result<Option<super::org::PrincipalRecord>> {
        let compound = format!("{org_id}:{principal_id}");
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(super::org::PRINCIPALS)?;
        match table.get(compound.as_str())? {
            Some(guard) => {
                let bytes = guard.value().to_vec();
                let (record, _) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                    .context("decode principal")?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    pub fn list_principals(&self, org_id: &str) -> Result<Vec<super::org::PrincipalRecord>> {
        let prefix = format!("{org_id}:");
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(super::org::PRINCIPALS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            if k.value().starts_with(&prefix) {
                let bytes = v.value().to_vec();
                let (record, _): (super::org::PrincipalRecord, _) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                        .context("decode principal")?;
                out.push(record);
            }
        }
        Ok(out)
    }

    /// Delete principal. Fails if principal has active (unexpired) keys.
    pub fn delete_principal(&self, org_id: &str, principal_id: &str) -> Result<bool> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Check for active keys via the index
        let ix_prefix = format!("{principal_id}:");
        let read_txn = self.db.begin_read()?;
        let ix_table = read_txn.open_table(super::org::PRINCIPAL_KEY_IX)?;
        let keys_table = read_txn.open_table(super::org::PRINCIPAL_KEYS)?;
        for entry in ix_table.iter()? {
            let (k, v) = entry?;
            if k.value().starts_with(&ix_prefix) {
                let hash = v.value().to_vec();
                if let Some(key_guard) = keys_table.get(hash.as_slice())? {
                    let key_bytes = key_guard.value().to_vec();
                    let (key_rec, _): (super::org::PrincipalKeyRecord, _) =
                        bincode::serde::decode_from_slice(&key_bytes, bincode::config::standard())?;
                    if key_rec.valid_before > now {
                        anyhow::bail!("cannot delete principal with active (unexpired) keys");
                    }
                }
            }
        }
        drop(keys_table);
        drop(ix_table);
        drop(read_txn);

        let compound = format!("{org_id}:{principal_id}");
        let write_txn = self.db.begin_write()?;
        let existed = {
            let mut table = write_txn.open_table(super::org::PRINCIPALS)?;
            table.remove(compound.as_str())?.is_some()
        };
        write_txn.commit()?;
        Ok(existed)
    }
```

**Step 3: Run tests**

Run: `cargo test -p sirr-server store::db::tests::principal_crud store::db::tests::delete_principal_blocked_by_active_keys -v`
Expected: Both PASS

**Step 4: Commit**

```bash
git add crates/sirr-server/src/store/db.rs
git commit -m "feat: add principal CRUD store methods with active-key constraint"
```

---

## Task 7: PrincipalKey CRUD Store Methods

**Files:**
- Modify: `crates/sirr-server/src/store/db.rs`

**Step 1: Write failing tests**

```rust
#[test]
fn principal_key_crud() {
    let (store, _dir) = make_store();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

    let key_record = super::super::org::PrincipalKeyRecord {
        id: "k-1".into(), principal_id: "p-1".into(), org_id: "org-1".into(),
        name: "deploy".into(), key_hash: vec![0xAA; 32],
        valid_after: now - 100, valid_before: now + 3600, created_at: now,
    };
    store.put_principal_key(&key_record).unwrap();

    // Lookup by hash
    let found = store.find_principal_key_by_hash(&[0xAA; 32]).unwrap().unwrap();
    assert_eq!(found.name, "deploy");
    assert_eq!(found.org_id, "org-1");

    // List keys for principal
    let keys = store.list_principal_keys("p-1").unwrap();
    assert_eq!(keys.len(), 1);

    // Delete
    assert!(store.delete_principal_key("p-1", "k-1").unwrap());
    assert!(store.find_principal_key_by_hash(&[0xAA; 32]).unwrap().is_none());
    assert!(store.list_principal_keys("p-1").unwrap().is_empty());
}
```

**Step 2: Implement key CRUD**

Add to `impl Store`:

```rust
    // ── PrincipalKey CRUD ─────────────────────────────────────

    pub fn put_principal_key(&self, key: &super::org::PrincipalKeyRecord) -> Result<()> {
        let bytes = bincode::serde::encode_to_vec(key, bincode::config::standard())
            .context("encode principal key")?;
        let ix_key = format!("{}:{}", key.principal_id, key.id);
        let write_txn = self.db.begin_write()?;
        {
            let mut keys_table = write_txn.open_table(super::org::PRINCIPAL_KEYS)?;
            keys_table.insert(key.key_hash.as_slice(), bytes.as_slice())?;

            let mut ix_table = write_txn.open_table(super::org::PRINCIPAL_KEY_IX)?;
            ix_table.insert(ix_key.as_str(), key.key_hash.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn find_principal_key_by_hash(&self, hash: &[u8]) -> Result<Option<super::org::PrincipalKeyRecord>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(super::org::PRINCIPAL_KEYS)?;
        match table.get(hash)? {
            Some(guard) => {
                let bytes = guard.value().to_vec();
                let (record, _) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                    .context("decode principal key")?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    pub fn list_principal_keys(&self, principal_id: &str) -> Result<Vec<super::org::PrincipalKeyRecord>> {
        let prefix = format!("{principal_id}:");
        let read_txn = self.db.begin_read()?;
        let ix_table = read_txn.open_table(super::org::PRINCIPAL_KEY_IX)?;
        let keys_table = read_txn.open_table(super::org::PRINCIPAL_KEYS)?;
        let mut out = Vec::new();
        for entry in ix_table.iter()? {
            let (k, v) = entry?;
            if k.value().starts_with(&prefix) {
                let hash = v.value().to_vec();
                if let Some(guard) = keys_table.get(hash.as_slice())? {
                    let bytes = guard.value().to_vec();
                    let (record, _): (super::org::PrincipalKeyRecord, _) =
                        bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?;
                    out.push(record);
                }
            }
        }
        Ok(out)
    }

    /// Delete a key by principal_id + key_id. Removes from both tables.
    pub fn delete_principal_key(&self, principal_id: &str, key_id: &str) -> Result<bool> {
        let ix_key = format!("{principal_id}:{key_id}");
        let write_txn = self.db.begin_write()?;
        let existed = {
            let mut ix_table = write_txn.open_table(super::org::PRINCIPAL_KEY_IX)?;
            let hash = match ix_table.remove(ix_key.as_str())? {
                Some(guard) => guard.value().to_vec(),
                None => return Ok(false),
            };
            let mut keys_table = write_txn.open_table(super::org::PRINCIPAL_KEYS)?;
            keys_table.remove(hash.as_slice())?.is_some()
        };
        write_txn.commit()?;
        Ok(existed)
    }
```

**Step 3: Run tests**

Run: `cargo test -p sirr-server store::db::tests::principal_key_crud -v`
Expected: PASS

**Step 4: Commit**

```bash
git add crates/sirr-server/src/store/db.rs
git commit -m "feat: add principal key CRUD with hash lookup and secondary index"
```

---

## Task 8: Role CRUD Store Methods

**Files:**
- Modify: `crates/sirr-server/src/store/db.rs`

**Step 1: Write failing tests**

```rust
#[test]
fn custom_role_crud() {
    let (store, _dir) = make_store();
    let role = super::super::org::RoleRecord {
        name: "deployer".into(),
        org_id: Some("org-1".into()),
        permissions: super::super::permissions::Permissions::parse("rlcd").unwrap(),
        built_in: false,
        created_at: 1000,
    };
    store.put_role(&role).unwrap();

    let fetched = store.get_role(Some("org-1"), "deployer").unwrap().unwrap();
    assert_eq!(fetched.permissions.to_letter_string(), "rlcd");

    let all = store.list_roles(Some("org-1")).unwrap();
    // 4 built-in + 1 custom
    assert!(all.len() >= 5);

    // Built-in reader should be accessible
    let reader = store.get_role(None, "reader").unwrap().unwrap();
    assert!(reader.built_in);

    // Delete custom role
    assert!(store.delete_role(Some("org-1"), "deployer").unwrap());
    assert!(store.get_role(Some("org-1"), "deployer").unwrap().is_none());
}

#[test]
fn cannot_delete_builtin_role() {
    let (store, _dir) = make_store();
    let result = store.delete_role(None, "reader");
    assert!(result.is_err());
}

#[test]
fn cannot_delete_role_in_use() {
    let (store, _dir) = make_store();

    let org = super::super::org::OrgRecord {
        id: "org-1".into(), name: "acme".into(),
        metadata: std::collections::HashMap::new(), created_at: 1000,
    };
    store.put_org(&org).unwrap();

    let role = super::super::org::RoleRecord {
        name: "deployer".into(), org_id: Some("org-1".into()),
        permissions: super::super::permissions::Permissions::parse("rlcd").unwrap(),
        built_in: false, created_at: 1000,
    };
    store.put_role(&role).unwrap();

    let principal = super::super::org::PrincipalRecord {
        id: "p-1".into(), org_id: "org-1".into(), name: "bot".into(),
        role: "deployer".into(), metadata: std::collections::HashMap::new(),
        created_at: 1000,
    };
    store.put_principal(&principal).unwrap();

    // Should fail — role is in use
    let result = store.delete_role(Some("org-1"), "deployer");
    assert!(result.is_err());
}
```

**Step 2: Implement role CRUD**

Add to `impl Store`:

```rust
    // ── Role CRUD ─────────────────────────────────────────────

    fn role_table_key(org_id: Option<&str>, name: &str) -> String {
        match org_id {
            Some(id) => format!("{id}:{name}"),
            None => format!("builtin:{name}"),
        }
    }

    pub fn put_role(&self, role: &super::org::RoleRecord) -> Result<()> {
        let bytes = bincode::serde::encode_to_vec(role, bincode::config::standard())
            .context("encode role")?;
        let key = Self::role_table_key(role.org_id.as_deref(), &role.name);
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(super::org::ROLES)?;
            table.insert(key.as_str(), bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_role(&self, org_id: Option<&str>, name: &str) -> Result<Option<super::org::RoleRecord>> {
        let key = Self::role_table_key(org_id, name);
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(super::org::ROLES)?;
        match table.get(key.as_str())? {
            Some(guard) => {
                let bytes = guard.value().to_vec();
                let (record, _) = bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                    .context("decode role")?;
                Ok(Some(record))
            }
            None => Ok(None),
        }
    }

    /// List roles visible to an org: built-in + custom for that org.
    pub fn list_roles(&self, org_id: Option<&str>) -> Result<Vec<super::org::RoleRecord>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(super::org::ROLES)?;
        let mut out = Vec::new();
        let org_prefix = org_id.map(|id| format!("{id}:"));
        for entry in table.iter()? {
            let (k, v) = entry?;
            let key_str = k.value();
            if key_str.starts_with("builtin:") || org_prefix.as_ref().map_or(false, |p| key_str.starts_with(p.as_str())) {
                let bytes = v.value().to_vec();
                let (record, _): (super::org::RoleRecord, _) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?;
                out.push(record);
            }
        }
        Ok(out)
    }

    /// Delete custom role. Fails if built-in or if any principal uses it.
    pub fn delete_role(&self, org_id: Option<&str>, name: &str) -> Result<bool> {
        // Check built-in
        let key = Self::role_table_key(org_id, name);
        if key.starts_with("builtin:") {
            anyhow::bail!("cannot delete built-in role");
        }

        // Check if any principal in this org uses this role
        if let Some(oid) = org_id {
            let principals = self.list_principals(oid)?;
            for p in &principals {
                if p.role == name {
                    anyhow::bail!("cannot delete role '{}' — in use by principal '{}'", name, p.name);
                }
            }
        }

        let write_txn = self.db.begin_write()?;
        let existed = {
            let mut table = write_txn.open_table(super::org::ROLES)?;
            table.remove(key.as_str())?.is_some()
        };
        write_txn.commit()?;
        Ok(existed)
    }
```

**Step 3: Run tests**

Run: `cargo test -p sirr-server store::db::tests::custom_role_crud store::db::tests::cannot_delete_builtin_role store::db::tests::cannot_delete_role_in_use -v`
Expected: All 3 PASS

**Step 4: Commit**

```bash
git add crates/sirr-server/src/store/db.rs
git commit -m "feat: add role CRUD with built-in protection and in-use constraint"
```

---

## Task 9: Org-Scoped Secret Store Methods

**Files:**
- Modify: `crates/sirr-server/src/store/db.rs`

**Step 1: Write failing tests**

```rust
#[test]
fn org_scoped_secret_put_and_get() {
    let (store, _dir) = make_store();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

    // Push org-scoped secret
    store.put_org_secret("org-1", "DATABASE_URL", "postgres://...", now + 3600,
        None, true, None, Some("p-1"), None).unwrap();

    // Get it back
    let result = store.get_org_secret("org-1", "DATABASE_URL");
    assert!(matches!(result, Ok(GetResult::Value(v, _)) if v == "postgres://..."));

    // Same key in different org
    store.put_org_secret("org-2", "DATABASE_URL", "mysql://...", now + 3600,
        None, true, None, Some("p-2"), None).unwrap();
    let result2 = store.get_org_secret("org-2", "DATABASE_URL");
    assert!(matches!(result2, Ok(GetResult::Value(v, _)) if v == "mysql://..."));
}

#[test]
fn org_scoped_list_my_vs_org() {
    let (store, _dir) = make_store();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

    store.put_org_secret("org-1", "MY_SECRET", "val1", now + 3600,
        None, true, None, Some("p-1"), None).unwrap();
    store.put_org_secret("org-1", "OTHER_SECRET", "val2", now + 3600,
        None, true, None, Some("p-2"), None).unwrap();

    let my = store.list_org_secrets("org-1", Some("p-1")).unwrap();
    assert_eq!(my.len(), 1);
    assert_eq!(my[0].key, "MY_SECRET");

    let all = store.list_org_secrets("org-1", None).unwrap();
    assert_eq!(all.len(), 2);
}

#[test]
fn key_binding_check() {
    let (store, _dir) = make_store();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

    store.put_org_secret("org-1", "RESTRICTED", "secret", now + 3600,
        None, true, None, Some("p-1"),
        Some(vec!["deploy_key".into()])).unwrap();

    // Check binding
    assert!(store.check_key_binding("org-1", "RESTRICTED", "deploy_key").unwrap());
    assert!(!store.check_key_binding("org-1", "RESTRICTED", "other_key").unwrap());
}
```

**Step 2: Implement org-scoped secret methods**

Add to `impl Store`:

```rust
    // ── Org-Scoped Secrets ────────────────────────────────────

    /// Compound key for org-scoped secrets.
    fn org_secret_key(org_id: &str, secret_key: &str) -> String {
        format!("{org_id}:{secret_key}")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn put_org_secret(
        &self,
        org_id: &str,
        secret_key: &str,
        value: &str,
        expires_at: i64,
        max_reads: Option<u32>,
        delete: bool,
        webhook_url: Option<String>,
        owner_id: Option<&str>,
        allowed_keys: Option<Vec<String>>,
    ) -> Result<()> {
        let (ciphertext, nonce) = super::crypto::encrypt(value.as_bytes(), &self.key)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let record = super::model::SecretRecord {
            value_encrypted: ciphertext,
            nonce,
            created_at: now,
            expires_at: Some(expires_at),
            max_reads,
            read_count: 0,
            delete,
            webhook_url,
            owner_id: owner_id.map(|s| s.to_owned()),
            org_id: Some(org_id.to_owned()),
            allowed_keys,
        };

        let compound = Self::org_secret_key(org_id, secret_key);
        let bytes = encode(&record, self.key_version)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SECRETS)?;
            table.insert(compound.as_str(), bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_org_secret(&self, org_id: &str, secret_key: &str) -> Result<GetResult> {
        let compound = Self::org_secret_key(org_id, secret_key);
        // Reuse existing get logic but with compound key
        self.get_by_compound_key(&compound)
    }

    pub fn head_org_secret(&self, org_id: &str, secret_key: &str) -> Result<Option<(super::model::SecretMeta, bool)>> {
        let compound = Self::org_secret_key(org_id, secret_key);
        self.head_by_compound_key(&compound, secret_key)
    }

    pub fn delete_org_secret(&self, org_id: &str, secret_key: &str) -> Result<bool> {
        let compound = Self::org_secret_key(org_id, secret_key);
        let write_txn = self.db.begin_write()?;
        let existed = {
            let mut table = write_txn.open_table(SECRETS)?;
            table.remove(compound.as_str())?.is_some()
        };
        write_txn.commit()?;
        Ok(existed)
    }

    /// List org secrets. If owner_id is Some, only return secrets owned by that principal.
    pub fn list_org_secrets(&self, org_id: &str, owner_id: Option<&str>) -> Result<Vec<super::model::SecretMeta>> {
        let prefix = format!("{org_id}:");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SECRETS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            let key_str = k.value();
            if !key_str.starts_with(&prefix) {
                continue;
            }
            let bytes = v.value().to_vec();
            let (record, _) = decode(&bytes)?;
            if record.is_expired(now) {
                continue;
            }
            // Extract the secret name (after org_id:)
            let secret_name = &key_str[prefix.len()..];
            if let Some(oid) = owner_id {
                if record.owner_id.as_deref() != Some(oid) {
                    continue;
                }
            }
            out.push(super::model::SecretMeta {
                key: secret_name.to_owned(),
                created_at: record.created_at,
                expires_at: record.expires_at,
                max_reads: record.max_reads,
                read_count: record.read_count,
                delete: record.delete,
                owner_id: record.owner_id.clone(),
                org_id: record.org_id.clone(),
            });
        }
        Ok(out)
    }

    /// Check if a key name is allowed to access a secret.
    /// Returns true if no binding exists (open access) or if key_name is in allowed_keys.
    pub fn check_key_binding(&self, org_id: &str, secret_key: &str, key_name: &str) -> Result<bool> {
        let compound = Self::org_secret_key(org_id, secret_key);
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SECRETS)?;
        match table.get(compound.as_str())? {
            Some(guard) => {
                let bytes = guard.value().to_vec();
                let (record, _) = decode(&bytes)?;
                match &record.allowed_keys {
                    None => Ok(true),
                    Some(keys) => Ok(keys.iter().any(|k| k == key_name)),
                }
            }
            None => Ok(false),
        }
    }
```

Note: This requires extracting the core get/head logic into internal methods (`get_by_compound_key`, `head_by_compound_key`) that both the public-bucket and org-scoped paths can call. Refactor the existing `get()` and `head()` to delegate to these internal methods.

**Step 3: Run tests**

Run: `cargo test -p sirr-server store::db::tests::org_scoped -v`
Expected: All 3 PASS

**Step 4: Run all existing tests to ensure no regressions**

Run: `cargo test --all -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add crates/sirr-server/src/store/db.rs
git commit -m "feat: add org-scoped secret methods with key binding checks"
```

---

## Task 10: Replace Auth System with ResolvedAuth

**Files:**
- Modify: `crates/sirr-server/src/auth.rs`

**Step 1: Write failing tests**

Add test module to `auth.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_auth_master_has_no_secret_perms() {
        let auth = ResolvedAuth::Master;
        assert!(auth.is_master());
        assert!(!auth.can_read_my());
    }

    #[test]
    fn resolved_auth_principal_checks() {
        let auth = ResolvedAuth::Principal {
            principal_id: "p1".into(),
            org_id: "o1".into(),
            key_id: "k1".into(),
            key_name: "deploy".into(),
            permissions: crate::store::Permissions::parse("rlcd").unwrap(),
        };
        assert!(auth.can_read_my());
        assert!(auth.can_list_my());
        assert!(auth.can_create());
        assert!(auth.can_delete_my());
        assert!(!auth.can_read_org());
        assert!(!auth.can_manage_org());
        assert!(!auth.is_master());
    }
}
```

**Step 2: Implement new ResolvedAuth**

Replace the contents of `auth.rs` with the new auth system. Keep the existing `require_api_key` middleware but refactor it to produce `ResolvedAuth` instead of `ResolvedPermissions`:

```rust
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

use crate::store::permissions::PermBit;
use crate::store::Permissions;
use crate::AppState;

/// Resolved authentication context, injected as Extension.
#[derive(Debug, Clone)]
pub enum ResolvedAuth {
    /// Root SIRR_API_KEY holder. Can manage orgs, cannot touch secrets.
    Master,
    /// Authenticated principal with resolved permissions from role.
    Principal {
        principal_id: String,
        org_id: String,
        key_id: String,
        key_name: String,
        permissions: Permissions,
    },
}

impl ResolvedAuth {
    pub fn is_master(&self) -> bool {
        matches!(self, Self::Master)
    }

    pub fn org_id(&self) -> Option<&str> {
        match self {
            Self::Master => None,
            Self::Principal { org_id, .. } => Some(org_id),
        }
    }

    pub fn principal_id(&self) -> Option<&str> {
        match self {
            Self::Master => None,
            Self::Principal { principal_id, .. } => Some(principal_id),
        }
    }

    pub fn key_name(&self) -> Option<&str> {
        match self {
            Self::Master => None,
            Self::Principal { key_name, .. } => Some(key_name),
        }
    }

    fn has(&self, bit: PermBit) -> bool {
        match self {
            Self::Master => bit == PermBit::SirrAdmin,
            Self::Principal { permissions, .. } => permissions.has(bit),
        }
    }

    // Convenience methods
    pub fn can_read_my(&self) -> bool { self.has(PermBit::ReadMy) }
    pub fn can_read_org(&self) -> bool { self.has(PermBit::ReadOrg) }
    pub fn can_list_my(&self) -> bool { self.has(PermBit::ListMy) }
    pub fn can_list_org(&self) -> bool { self.has(PermBit::ListOrg) }
    pub fn can_create(&self) -> bool { self.has(PermBit::Create) }
    pub fn can_create_on_behalf(&self) -> bool { self.has(PermBit::CreateOnBehalf) }
    pub fn can_patch_my(&self) -> bool { self.has(PermBit::PatchMy) }
    pub fn can_patch_org(&self) -> bool { self.has(PermBit::PatchOrg) }
    pub fn can_account_read(&self) -> bool { self.has(PermBit::AccountRead) }
    pub fn can_account_read_org(&self) -> bool { self.has(PermBit::AccountReadOrg) }
    pub fn can_account_manage(&self) -> bool { self.has(PermBit::AccountManage) }
    pub fn can_manage_org(&self) -> bool { self.has(PermBit::ManageOrg) }
    pub fn can_sirr_admin(&self) -> bool { self.has(PermBit::SirrAdmin) }
    pub fn can_delete_my(&self) -> bool { self.has(PermBit::DeleteMy) }
    pub fn can_delete_org(&self) -> bool { self.has(PermBit::DeleteOrg) }

    /// Check if principal can access a secret based on ownership.
    /// Returns true if principal owns the secret (my-bit) or has org-wide access (org-bit).
    pub fn can_access_secret(&self, secret_owner_id: Option<&str>, my_bit: PermBit, org_bit: PermBit) -> bool {
        match self {
            Self::Master => false,
            Self::Principal { principal_id, permissions, .. } => {
                if permissions.has(org_bit) {
                    return true;
                }
                if permissions.has(my_bit) {
                    return secret_owner_id == Some(principal_id.as_str());
                }
                false
            }
        }
    }
}

/// Auth middleware. Extracts Bearer token, resolves to ResolvedAuth.
pub async fn require_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_owned());

    let token = match auth_header {
        Some(t) if !t.is_empty() => t,
        _ => return unauthorized(),
    };

    // Check master key first
    if let Some(ref master) = state.api_key {
        if constant_time_eq::constant_time_eq(token.as_bytes(), master.as_bytes()) {
            request.extensions_mut().insert(ResolvedAuth::Master);
            return next.run(request).await;
        }
    }

    // Hash and look up principal key
    let hash = hash_token(&token);
    match state.store.find_principal_key_by_hash(&hash) {
        Ok(Some(key_record)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            // Check time validity
            if now < key_record.valid_after || now >= key_record.valid_before {
                return unauthorized();
            }

            // Resolve principal → role → permissions
            match state.store.get_principal(&key_record.org_id, &key_record.principal_id) {
                Ok(Some(principal)) => {
                    // Try org-specific role first, then built-in
                    let permissions = match state.store.get_role(Some(&key_record.org_id), &principal.role) {
                        Ok(Some(role)) => role.permissions,
                        _ => match state.store.get_role(None, &principal.role) {
                            Ok(Some(role)) => role.permissions,
                            _ => return unauthorized(),
                        },
                    };

                    request.extensions_mut().insert(ResolvedAuth::Principal {
                        principal_id: principal.id,
                        org_id: key_record.org_id,
                        key_id: key_record.id,
                        key_name: key_record.name,
                        permissions,
                    });
                    next.run(request).await
                }
                _ => unauthorized(),
            }
        }
        // Fall back to legacy API key lookup for backward compat during transition
        Ok(None) => {
            // Check old API keys table
            match state.store.find_api_key_by_hash(&hash) {
                Ok(Some(_api_key_record)) => {
                    // Legacy path: use old ResolvedPermissions behavior
                    // This will be removed in Task 25 (cleanup)
                    // For now, map old permissions to master-like access for protected routes
                    request.extensions_mut().insert(ResolvedAuth::Master);
                    next.run(request).await
                }
                _ => unauthorized(),
            }
        }
        Err(_) => unauthorized(),
    }
}

/// Optional auth middleware for public bucket protected endpoints.
/// Like require_auth but only checks master key (no principal keys needed).
pub async fn require_master_key(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_owned());

    // Open mode: no master key configured → allow
    if state.api_key.is_none() && !state.store.has_api_keys().unwrap_or(false) {
        request.extensions_mut().insert(ResolvedAuth::Master);
        return next.run(request).await;
    }

    let token = match auth_header {
        Some(t) if !t.is_empty() => t,
        _ => return unauthorized(),
    };

    if let Some(ref master) = state.api_key {
        if constant_time_eq::constant_time_eq(token.as_bytes(), master.as_bytes()) {
            request.extensions_mut().insert(ResolvedAuth::Master);
            return next.run(request).await;
        }
    }

    // Also accept legacy API keys for backward compat
    let hash = hash_token(&token);
    if let Ok(Some(_)) = state.store.find_api_key_by_hash(&hash) {
        request.extensions_mut().insert(ResolvedAuth::Master);
        return next.run(request).await;
    }

    unauthorized()
}

fn hash_token(token: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": "unauthorized"})),
    )
        .into_response()
}
```

**Step 3: Temporarily keep old types**

During the transition, the old `ResolvedPermissions` and `Permission` types are still used by handlers. We'll keep both systems working during transition. The old `require_api_key` middleware stays but delegates to `require_master_key`. Handlers will be updated in Task 14-15.

**Step 4: Run tests**

Run: `cargo test -p sirr-server auth::tests -v`
Expected: 2 tests PASS

**Step 5: Run full test suite**

Run: `cargo test --all`
Expected: All PASS (old handlers still use old middleware — both coexist)

**Step 6: Commit**

```bash
git add crates/sirr-server/src/auth.rs
git commit -m "feat: add ResolvedAuth enum with principal key resolution and role lookup"
```

---

## Task 11: Add org_id/principal_id to AuditEvent

**Files:**
- Modify: `crates/sirr-server/src/store/audit.rs:22-55`

**Step 1: Add new fields to AuditEvent**

Add `org_id` and `principal_id` fields with `#[serde(default)]`:

```rust
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub principal_id: Option<String>,
```

Update `AuditEvent::new()` to accept these:

```rust
pub fn new(
    action: &str,
    key: Option<String>,
    source_ip: String,
    success: bool,
    detail: Option<String>,
    org_id: Option<String>,
    principal_id: Option<String>,
) -> Self
```

**Step 2: Fix all callers of AuditEvent::new()**

Search handlers.rs for all `AuditEvent::new(` calls and add `None, None` for the new params (public bucket events have no org/principal context).

**Step 3: Run all tests**

Run: `cargo test --all`
Expected: All PASS

**Step 4: Commit**

```bash
git add crates/sirr-server/src/store/audit.rs crates/sirr-server/src/handlers.rs
git commit -m "feat: add org_id and principal_id to AuditEvent"
```

---

## Task 12: Add org_id to WebhookRecord

**Files:**
- Modify: `crates/sirr-server/src/webhooks.rs:17-24` (WebhookRegistration)
- Modify: `crates/sirr-server/src/store/webhooks.rs`

**Step 1: Add org_id field**

Add to `WebhookRegistration`:
```rust
    #[serde(default)]
    pub org_id: Option<String>,
```

Add org-scoped webhook store methods: `list_webhooks_for_org()`, `count_webhooks_for_org()`.

Update `WebhookSender::fire()` to optionally filter by org_id.

**Step 2: Fix all callers**

Update webhook creation in handlers.rs to pass `org_id: None` for public bucket.

**Step 3: Run all tests**

Run: `cargo test --all`
Expected: All PASS

**Step 4: Commit**

```bash
git add crates/sirr-server/src/webhooks.rs crates/sirr-server/src/store/webhooks.rs crates/sirr-server/src/handlers.rs
git commit -m "feat: add org_id to WebhookRegistration for org-scoped webhooks"
```

---

## Task 13: Org/Principal/Role/Key Handler Functions

**Files:**
- Create: `crates/sirr-server/src/org_handlers.rs`
- Modify: `crates/sirr-server/src/lib.rs` (add module)

**Step 1: Create org_handlers.rs**

This is a large file. Create handlers for:

```rust
// Master-only endpoints
pub async fn create_org(...)    // POST /orgs
pub async fn list_orgs(...)     // GET /orgs
pub async fn delete_org(...)    // DELETE /orgs/{id}

// Org management (M or A permission)
pub async fn create_principal(...)    // POST /orgs/{org_id}/principals
pub async fn list_principals(...)     // GET /orgs/{org_id}/principals
pub async fn delete_principal(...)    // DELETE /orgs/{org_id}/principals/{id}
pub async fn create_role(...)         // POST /orgs/{org_id}/roles
pub async fn list_roles(...)          // GET /orgs/{org_id}/roles
pub async fn delete_role(...)         // DELETE /orgs/{org_id}/roles/{name}

// Principal self-service
pub async fn get_me(...)              // GET /me
pub async fn patch_me(...)            // PATCH /me
pub async fn create_key(...)          // POST /me/keys
pub async fn delete_key(...)          // DELETE /me/keys/{key_id}

// Org secrets
pub async fn create_org_secret(...)   // POST /orgs/{org_id}/secrets
pub async fn list_org_secrets(...)    // GET /orgs/{org_id}/secrets
pub async fn get_org_secret(...)      // GET /orgs/{org_id}/secrets/{key}
pub async fn head_org_secret(...)     // HEAD /orgs/{org_id}/secrets/{key}
pub async fn patch_org_secret(...)    // PATCH /orgs/{org_id}/secrets/{key}
pub async fn delete_org_secret(...)   // DELETE /orgs/{org_id}/secrets/{key}
pub async fn prune_org_secrets(...)   // POST /orgs/{org_id}/prune

// Org audit
pub async fn org_audit_events(...)    // GET /orgs/{org_id}/audit

// Org webhooks
pub async fn create_org_webhook(...)  // POST /orgs/{org_id}/webhooks
pub async fn list_org_webhooks(...)   // GET /orgs/{org_id}/webhooks
pub async fn delete_org_webhook(...)  // DELETE /orgs/{org_id}/webhooks/{id}
```

Each handler should:
1. Extract `Extension(auth)` as `ResolvedAuth`
2. Check permissions (e.g., `auth.can_manage_org()`)
3. Verify the principal's org matches the path org_id
4. Call the corresponding store method
5. Record audit event with org_id + principal_id
6. Return appropriate JSON response

Key implementation details:
- `create_key()`: generates `sirr_key_<32 hex chars>`, hashes with SHA-256, stores hash, returns raw key once
- `get_org_secret()`: checks key binding via `store.check_key_binding()` before returning value
- Org verification: `auth.org_id() == Some(org_id)` for principal endpoints

**Step 2: Register module in lib.rs**

Add `pub mod org_handlers;` to `crates/sirr-server/src/lib.rs`.

**Step 3: Run clippy**

Run: `cargo clippy --all-targets`
Expected: No errors

**Step 4: Commit**

```bash
git add crates/sirr-server/src/org_handlers.rs crates/sirr-server/src/lib.rs
git commit -m "feat: add org/principal/role/key/secret handler functions"
```

---

## Task 14: Refactor Existing Handlers to ResolvedAuth

**Files:**
- Modify: `crates/sirr-server/src/handlers.rs`

**Step 1: Update handler signatures**

Replace all `Extension(perms): Extension<ResolvedPermissions>` with `Extension(auth): Extension<ResolvedAuth>` in:
- `list_secrets()` — check `auth.is_master()` (public bucket admin)
- `create_secret()` — check `auth.is_master()` (public bucket admin)
- `patch_secret()` — check `auth.is_master()`
- `delete_secret()` — check `auth.is_master()`
- `prune_secrets()` — check `auth.is_master()`
- `audit_events()` — check `auth.is_master()`
- `create_webhook()` — check `auth.is_master()`
- `list_webhooks()` — check `auth.is_master()`
- `delete_webhook()` — check `auth.is_master()`
- `create_api_key()` — check `auth.is_master()`
- `list_api_keys()` — check `auth.is_master()`
- `delete_api_key()` — check `auth.is_master()`

For public bucket handlers, all protected endpoints now just need master key auth. The old prefix-scoping logic is removed (orgs replace that functionality).

**Step 2: Update imports**

Replace `use crate::auth::ResolvedPermissions;` with `use crate::auth::ResolvedAuth;`.

**Step 3: Run all tests**

Run: `cargo test --all`
Expected: All PASS

**Step 4: Commit**

```bash
git add crates/sirr-server/src/handlers.rs
git commit -m "refactor: update existing handlers to use ResolvedAuth"
```

---

## Task 15: Restructure Router with New Endpoints

**Files:**
- Modify: `crates/sirr-server/src/server.rs:340-385` (router setup)
- Modify: `crates/sirr-server/src/lib.rs` (AppState)

**Step 1: Add ENABLE_PUBLIC_BUCKET to ServerConfig**

Add field to ServerConfig:
```rust
pub enable_public_bucket: bool,
```

In Default impl, read from env:
```rust
enable_public_bucket: std::env::var("ENABLE_PUBLIC_BUCKET")
    .map(|v| v != "false" && v != "0")
    .unwrap_or(true),
```

Add to AppState:
```rust
pub enable_public_bucket: bool,
```

**Step 2: Restructure router**

Replace the router section in `run()` with:

```rust
    // ── Public bucket routes (backward compatible) ──
    let secret_read = if state.enable_public_bucket {
        Router::new()
            .route("/secrets/{key}", get(handlers::get_secret).head(handlers::head_secret))
    } else {
        Router::new()
    };

    let public = Router::new()
        .route("/health", get(handlers::health))
        // ... robots.txt, security.txt ...
        ;

    let protected_public_bucket = if state.enable_public_bucket {
        Router::new()
            .route("/secrets", get(handlers::list_secrets).post(handlers::create_secret))
            .route("/secrets/{key}", patch(handlers::patch_secret).delete(handlers::delete_secret))
            .route("/prune", post(handlers::prune_secrets))
            .layer(axum::middleware::from_fn_with_state(state.clone(), auth::require_master_key))
    } else {
        Router::new()
    };

    // ── Org routes (new multi-tenant endpoints) ──
    let org_protected = Router::new()
        // Master-only
        .route("/orgs", get(org_handlers::list_orgs).post(org_handlers::create_org))
        .route("/orgs/{org_id}", delete(org_handlers::delete_org))
        // Principal management
        .route("/orgs/{org_id}/principals", get(org_handlers::list_principals).post(org_handlers::create_principal))
        .route("/orgs/{org_id}/principals/{id}", delete(org_handlers::delete_principal))
        // Roles
        .route("/orgs/{org_id}/roles", get(org_handlers::list_roles).post(org_handlers::create_role))
        .route("/orgs/{org_id}/roles/{name}", delete(org_handlers::delete_role))
        // Self-service
        .route("/me", get(org_handlers::get_me).patch(org_handlers::patch_me))
        .route("/me/keys", post(org_handlers::create_key))
        .route("/me/keys/{key_id}", delete(org_handlers::delete_key))
        // Org secrets
        .route("/orgs/{org_id}/secrets", get(org_handlers::list_org_secrets).post(org_handlers::create_org_secret))
        .route("/orgs/{org_id}/secrets/{key}", get(org_handlers::get_org_secret).head(org_handlers::head_org_secret).patch(org_handlers::patch_org_secret).delete(org_handlers::delete_org_secret))
        .route("/orgs/{org_id}/prune", post(org_handlers::prune_org_secrets))
        // Org audit
        .route("/orgs/{org_id}/audit", get(org_handlers::org_audit_events))
        // Org webhooks
        .route("/orgs/{org_id}/webhooks", get(org_handlers::list_org_webhooks).post(org_handlers::create_org_webhook))
        .route("/orgs/{org_id}/webhooks/{id}", delete(org_handlers::delete_org_webhook))
        // Legacy API keys (backward compat)
        .route("/keys", get(handlers::list_api_keys).post(handlers::create_api_key))
        .route("/keys/{id}", delete(handlers::delete_api_key))
        // Legacy audit/webhooks (backward compat)
        .route("/audit", get(handlers::audit_events))
        .route("/webhooks", get(handlers::list_webhooks).post(handlers::create_webhook))
        .route("/webhooks/{id}", delete(handlers::delete_webhook))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth::require_auth));

    let app = secret_read
        .merge(public)
        .merge(protected_public_bucket)
        .merge(org_protected)
        .with_state(state)
        // ... rate limiting, security headers, trace ...
        ;
```

**Step 3: Run clippy + tests**

Run: `cargo clippy --all-targets && cargo test --all`
Expected: All PASS

**Step 4: Commit**

```bash
git add crates/sirr-server/src/server.rs crates/sirr-server/src/lib.rs
git commit -m "feat: restructure router with org endpoints and ENABLE_PUBLIC_BUCKET toggle"
```

---

## Task 16: License Tiers

**Files:**
- Modify: `crates/sirr-server/src/license.rs`

**Step 1: Replace FREE_TIER_LIMIT with LicenseTier**

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum LicenseTier {
    Solo,       // 1 org, 1 principal, unlimited secrets
    Team,       // 1 org, unlimited principals
    Business,   // unlimited orgs, unlimited principals
    Enterprise, // unlimited, self-hosted, one-time purchase
}

impl LicenseTier {
    pub fn max_orgs(&self) -> Option<usize> {
        match self {
            Self::Solo | Self::Team => Some(1),
            Self::Business | Self::Enterprise => None,
        }
    }

    pub fn max_principals_per_org(&self) -> Option<usize> {
        match self {
            Self::Solo => Some(1),
            _ => None,
        }
    }
}
```

Update `LicenseStatus` to carry the tier:
```rust
pub enum LicenseStatus {
    Free,                    // Solo tier, no key needed
    Licensed(LicenseTier),   // Tier determined by validation response
    Invalid(String),
}
```

**Step 2: Update enforcement**

Enforcement moves from secret creation to org/principal creation. Update `org_handlers::create_org()` and `org_handlers::create_principal()` to check tier limits.

Remove the old secret-count check from `handlers::create_secret()`.

**Step 3: Run all tests**

Run: `cargo test --all`
Expected: All PASS

**Step 4: Commit**

```bash
git add crates/sirr-server/src/license.rs crates/sirr-server/src/org_handlers.rs crates/sirr-server/src/handlers.rs
git commit -m "feat: replace secret-count licensing with org/principal tier system"
```

---

## Task 17: CLI Client — Org/Principal/Key Subcommands

**Files:**
- Modify: `crates/sirr/src/main.rs`

**Step 1: Add new subcommands to clap**

Add to `Commands` enum:

```rust
    /// Manage organizations
    Orgs {
        #[command(subcommand)]
        command: OrgCommand,
    },
    /// Manage principals
    Principals {
        #[command(subcommand)]
        command: PrincipalCommand,
    },
    /// View/manage my account
    Me {
        #[command(subcommand)]
        command: MeCommand,
    },
```

Define the subcommand enums:

```rust
#[derive(Subcommand)]
enum OrgCommand {
    /// List organizations
    List,
    /// Create organization
    Create {
        /// Organization name
        name: String,
    },
    /// Delete organization
    Delete {
        /// Organization ID
        id: String,
    },
}

#[derive(Subcommand)]
enum PrincipalCommand {
    /// List principals in an org
    List {
        /// Organization ID
        #[arg(long)]
        org: String,
    },
    /// Create a principal
    Create {
        /// Organization ID
        #[arg(long)]
        org: String,
        /// Principal name
        name: String,
        /// Role name
        #[arg(long, default_value = "writer")]
        role: String,
    },
    /// Delete a principal
    Delete {
        /// Organization ID
        #[arg(long)]
        org: String,
        /// Principal ID
        id: String,
    },
}

#[derive(Subcommand)]
enum MeCommand {
    /// Show my account info
    Info,
    /// List my keys
    Keys,
    /// Create a new named key
    CreateKey {
        /// Key name
        name: String,
        /// Valid for (e.g., "30d", "1h")
        #[arg(long, default_value = "365d")]
        valid_for: String,
    },
    /// Delete a key
    DeleteKey {
        /// Key ID
        id: String,
    },
}
```

**Step 2: Implement command handlers**

Each command makes HTTP requests to the corresponding API endpoints using the existing reqwest client pattern in the file.

**Step 3: Update existing push/get/list commands**

Add `--org` flag to push, get, list, delete, patch commands:

```rust
    /// Push a secret
    Push {
        // ... existing fields ...
        /// Organization ID (if pushing to an org bucket)
        #[arg(long)]
        org: Option<String>,
    },
```

When `--org` is provided, use `/orgs/{org}/secrets` instead of `/secrets`.

**Step 4: Build and test**

Run: `cargo build --bin sirr`
Expected: Compiles successfully

Run: `cargo build --bin sirrd`
Expected: Compiles successfully

**Step 5: Commit**

```bash
git add crates/sirr/src/main.rs
git commit -m "feat: add org, principals, and me subcommands to CLI client"
```

---

## Task 18: Auto-Init Bootstrap

**Files:**
- Modify: `crates/sirrd/src/main.rs`

**Step 1: Add --init flag**

Add to the `Serve` command:

```rust
    /// Auto-initialize: generate master key, create default org and principal
    #[arg(long)]
    init: bool,
```

Add `SIRR_AUTOINIT` env var check:

```rust
let auto_init = serve.init || std::env::var("SIRR_AUTOINIT")
    .map(|v| v == "true" || v == "1")
    .unwrap_or(false);
```

**Step 2: Implement init logic**

After store is opened but before server starts:

```rust
if auto_init {
    // 1. Generate SIRR_API_KEY if not set
    if config.api_key.is_none() {
        let key = sirr_server::store::api_keys::generate_api_key();
        println!("Generated SIRR_API_KEY: {key}");
        config.api_key = Some(key.clone());
        config.auto_generated_key = Some(key);
    }

    // 2. Create default org if none exist
    if store.list_orgs().unwrap_or_default().is_empty() {
        let org = OrgRecord { id: uuid(), name: "default".into(), .. };
        store.put_org(&org).unwrap();
        println!("Created default org: {}", org.id);

        // 3. Create admin principal
        let principal = PrincipalRecord { id: uuid(), org_id: org.id.clone(), name: "admin".into(), role: "admin".into(), .. };
        store.put_principal(&principal).unwrap();

        // 4. Create 2 keys valid for 30 minutes
        for i in 0..2 {
            let raw_key = generate_api_key();
            let hash = hash_key(&raw_key);
            let key_record = PrincipalKeyRecord {
                name: format!("bootstrap-key-{i}"),
                valid_before: now + 1800,
                ..
            };
            store.put_principal_key(&key_record).unwrap();
            println!("Principal key {i}: {raw_key} (expires in 30 minutes)");
        }
        eprintln!("WARNING: Default keys expire in 30 minutes. Create permanent keys via the API.");
    }
}
```

**Step 3: Build and test manually**

Run: `cargo build --bin sirrd && SIRR_AUTOINIT=true ./target/debug/sirrd serve --init`
Expected: Prints master key, org ID, 2 principal keys

**Step 4: Commit**

```bash
git add crates/sirrd/src/main.rs
git commit -m "feat: add --init flag and SIRR_AUTOINIT for zero-config bootstrap"
```

---

## Task 19: Update mod.rs Exports

**Files:**
- Modify: `crates/sirr-server/src/store/mod.rs`

**Step 1: Clean up exports**

Ensure all new types are properly re-exported:

```rust
pub mod api_keys;    // kept for backward compat
pub mod audit;
pub mod crypto;
pub mod db;
pub mod model;
pub mod org;
pub mod permissions;
pub mod webhooks;

pub use api_keys::{ApiKeyRecord, Permission};
pub use audit::{AuditEvent, AuditQuery};
pub use db::{GetResult, Store};
pub use model::{SecretMeta, SecretRecord};
pub use org::{OrgRecord, PrincipalRecord, PrincipalKeyRecord, RoleRecord, validate_metadata, builtin_roles};
pub use permissions::{PermBit, Permissions};
```

**Step 2: Run tests**

Run: `cargo test --all && cargo clippy --all-targets`
Expected: All PASS, no warnings

**Step 3: Commit**

```bash
git add crates/sirr-server/src/store/mod.rs
git commit -m "chore: clean up store module exports"
```

---

## Task 20: Full Integration Test

**Files:**
- Create: `crates/sirr-server/tests/multi_tenant.rs` (integration test)

**Step 1: Write integration test**

```rust
//! Integration test for multi-tenant org/principal system.

use axum_test::TestServer;
use sirr_server::store::crypto::generate_key;
use tempfile::tempdir;

async fn make_server() -> TestServer {
    // Setup: create store, generate master key, build app
    // ...
}

#[tokio::test]
async fn public_bucket_backward_compat() {
    let server = make_server().await;
    // POST /secrets with master key → 201
    // GET /secrets/{key} without auth → 200
    // Verify value matches
}

#[tokio::test]
async fn org_lifecycle() {
    let server = make_server().await;
    // POST /orgs with master key → create org
    // POST /orgs/{org_id}/principals with master key → create principal
    // POST /me/keys with principal key → create named key
    // POST /orgs/{org_id}/secrets with new key → create org secret
    // GET /orgs/{org_id}/secrets/{key} with key → read secret
    // Verify two orgs can have same secret name
}

#[tokio::test]
async fn key_binding_enforcement() {
    let server = make_server().await;
    // Create secret with allowed_keys: ["deploy_key"]
    // GET with deploy_key → 200
    // GET with other_key → 403
}

#[tokio::test]
async fn role_permission_enforcement() {
    let server = make_server().await;
    // Create principal with "reader" role
    // POST /orgs/{org_id}/secrets → 403 (no create permission)
    // GET /orgs/{org_id}/secrets/{key} → 200 (has read permission)
}

#[tokio::test]
async fn public_bucket_disabled() {
    // Build server with enable_public_bucket=false
    // GET /secrets/{key} → 404 (route doesn't exist)
    // Org endpoints still work
}
```

**Step 2: Run integration tests**

Run: `cargo test -p sirr-server --test multi_tenant -v`
Expected: All PASS

**Step 3: Commit**

```bash
git add crates/sirr-server/tests/multi_tenant.rs
git commit -m "test: add multi-tenant integration tests"
```

---

## Task 21: Run Full CI Suite Locally

**Step 1: Format**

Run: `cargo fmt --all`

**Step 2: Clippy**

Run: `cargo clippy --all-targets`
Expected: No errors

**Step 3: All tests**

Run: `cargo test --all`
Expected: All PASS

**Step 4: Build both binaries**

Run: `cargo build --release --bin sirrd --bin sirr`
Expected: Compiles successfully

**Step 5: Commit any fixes**

```bash
git add -A
git commit -m "chore: fix clippy warnings and formatting"
```

---

## Task 22: Update Documentation

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

**Step 1: Update README.md**

Add sections for:
- Multi-tenant mode (orgs, principals, roles, keys)
- Public bucket vs org buckets
- `ENABLE_PUBLIC_BUCKET` env var
- `SIRR_AUTOINIT` env var
- New CLI commands (orgs, principals, me)
- License tiers table

**Step 2: Update CLAUDE.md**

Add to Architecture section:
- New modules (org_handlers.rs, store/org.rs, store/permissions.rs)
- ResolvedAuth enum
- Dual-mode architecture
- New env vars
- New tables

Update Key Constraints:
- License enforcement moved from secret-count to org/principal-count
- Describe key binding check

**Step 3: Update llms.txt if it exists**

**Step 4: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: update README and CLAUDE.md for multi-tenant system"
```

---

## Task 23: Remove Legacy API Keys Module (Cleanup)

**Files:**
- Delete: `crates/sirr-server/src/store/api_keys.rs`
- Modify: `crates/sirr-server/src/store/mod.rs`
- Modify: `crates/sirr-server/src/auth.rs` (remove legacy fallback)
- Modify: `crates/sirr-server/src/handlers.rs` (remove /keys endpoints)
- Modify: `crates/sirr-server/src/server.rs` (remove /keys routes)

**Only do this task after confirming all tests pass and the new system is working.**

**Step 1: Remove api_keys.rs**

Delete the file and remove from mod.rs.

**Step 2: Remove legacy fallback in auth.rs**

Remove the `find_api_key_by_hash` fallback in `require_auth` and `require_master_key`.

**Step 3: Remove /keys endpoints from handlers.rs and router**

Remove `create_api_key()`, `list_api_keys()`, `delete_api_key()` handlers and their routes.

**Step 4: Remove API_KEYS table from open_versioned**

Remove `write_txn.open_table(super::api_keys::API_KEYS)?;` line.

**Step 5: Run all tests**

Run: `cargo test --all && cargo clippy --all-targets`
Expected: All PASS

**Step 6: Commit**

```bash
git add -A
git commit -m "chore: remove legacy api_keys module, replaced by org/principal system"
```

---

## Dependency Graph

```
Task 1 (Permissions) ──┐
                        ├── Task 2 (Record Structs) ──┐
Task 3 (SecretRecord)──┤                              ├── Task 4 (Register Tables)
                        │                              │
                        └──────────────────────────────┤
                                                       ├── Task 5 (Org CRUD)
                                                       ├── Task 6 (Principal CRUD)
                                                       ├── Task 7 (Key CRUD)
                                                       └── Task 8 (Role CRUD)
                                                            │
Task 9 (Org Secrets) ──────────────────────────────────────┘
Task 10 (Auth ResolvedAuth) ───────────────────────────────┘
Task 11 (Audit org_id) ──┐
Task 12 (Webhook org_id) ┤
                          ├── Task 13 (Org Handlers) ──── Task 14 (Refactor Handlers)
                          │                                    │
                          └────────────────────────────── Task 15 (Router) ──── Task 16 (License)
                                                                                    │
Task 17 (CLI) ─────────────────────────────────────────────────────────────────────┘
Task 18 (Auto-Init) ──────────────────────────────────────────────────────────────┘
Task 19 (Exports) ──── Task 20 (Integration Test) ──── Task 21 (CI Suite)
                                                            │
Task 22 (Docs) ────────────────────────────────────────────┘
Task 23 (Cleanup) ─────────────────────────────────────────┘
```

---

## Verification Checklist

After all tasks:
- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --all-targets` passes
- [ ] `cargo test --all` passes
- [ ] `cargo build --release --bin sirrd --bin sirr` succeeds
- [ ] Manual smoke test with SIRR_AUTOINIT works
- [ ] Public bucket backward compatible (existing client tests pass)
- [ ] Org-scoped secrets isolated between orgs
- [ ] Key binding restricts access correctly
- [ ] Role permissions enforced
- [ ] ENABLE_PUBLIC_BUCKET=false disables public endpoints
- [ ] License tier enforced at org/principal creation
- [ ] README.md and CLAUDE.md updated
