use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::permissions::Permissions;

// ── Table definitions ────────────────────────────────────────────────────────

pub const ORGS: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("orgs");
pub const PRINCIPALS: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("principals");
pub const PRINCIPAL_KEYS: redb::TableDefinition<&[u8], &[u8]> =
    redb::TableDefinition::new("principal_keys");
pub const PRINCIPAL_KEY_IX: redb::TableDefinition<&str, &[u8]> =
    redb::TableDefinition::new("principal_key_ix");
pub const ROLES: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("roles");

// ── Record structs ───────────────────────────────────────────────────────────

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

// ── Validation ───────────────────────────────────────────────────────────────

/// Maximum number of metadata properties per record.
const MAX_METADATA_PROPS: usize = 10;
/// Maximum byte length of a single metadata value.
const MAX_METADATA_VALUE_BYTES: usize = 100;

/// Validate a metadata map: at most 10 properties, each value at most 100 bytes.
pub fn validate_metadata(metadata: &HashMap<String, String>) -> Result<(), String> {
    if metadata.len() > MAX_METADATA_PROPS {
        return Err(format!(
            "metadata has {} properties, max is {MAX_METADATA_PROPS}",
            metadata.len()
        ));
    }
    for (key, value) in metadata {
        if value.len() > MAX_METADATA_VALUE_BYTES {
            return Err(format!(
                "metadata key \"{key}\" value is {} bytes, max is {MAX_METADATA_VALUE_BYTES}",
                value.len()
            ));
        }
    }
    Ok(())
}

// ── Built-in roles ───────────────────────────────────────────────────────────

/// Returns the four built-in roles: reader, writer, admin, owner.
pub fn builtin_roles() -> Vec<RoleRecord> {
    vec![
        RoleRecord {
            name: "reader".to_string(),
            org_id: None,
            permissions: Permissions::parse("rla").unwrap(),
            built_in: true,
            created_at: 0,
        },
        RoleRecord {
            name: "writer".to_string(),
            org_id: None,
            permissions: Permissions::parse("rlcpdam").unwrap(),
            built_in: true,
            created_at: 0,
        },
        RoleRecord {
            name: "admin".to_string(),
            org_id: None,
            permissions: Permissions::parse("rRlLcCpPaAmMdD").unwrap(),
            built_in: true,
            created_at: 0,
        },
        RoleRecord {
            name: "owner".to_string(),
            org_id: None,
            permissions: Permissions::all(),
            built_in: true,
            created_at: 0,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_metadata_ok() {
        let mut m = HashMap::new();
        for i in 0..10 {
            m.insert(format!("k{i}"), "x".repeat(100));
        }
        assert!(validate_metadata(&m).is_ok());
    }

    #[test]
    fn validate_metadata_too_many_props() {
        let mut m = HashMap::new();
        for i in 0..11 {
            m.insert(format!("k{i}"), "v".into());
        }
        let err = validate_metadata(&m).unwrap_err();
        assert!(err.contains("11 properties"));
    }

    #[test]
    fn validate_metadata_value_too_long() {
        let mut m = HashMap::new();
        m.insert("big".into(), "x".repeat(101));
        let err = validate_metadata(&m).unwrap_err();
        assert!(err.contains("101 bytes"));
    }

    #[test]
    fn builtin_roles_count_and_names() {
        let roles = builtin_roles();
        assert_eq!(roles.len(), 4);
        let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["reader", "writer", "admin", "owner"]);
        assert!(roles.iter().all(|r| r.built_in));
    }

    #[test]
    fn builtin_reader_permissions() {
        let roles = builtin_roles();
        let reader = &roles[0];
        assert_eq!(reader.permissions.to_letter_string(), "rla");
    }

    #[test]
    fn builtin_owner_has_all() {
        let roles = builtin_roles();
        let owner = &roles[3];
        assert_eq!(owner.permissions, Permissions::all());
    }

    #[test]
    fn org_record_bincode_round_trip() {
        let rec = OrgRecord {
            id: "org_1".into(),
            name: "Acme".into(),
            metadata: HashMap::from([("env".into(), "prod".into())]),
            created_at: 1700000000,
        };
        let bytes = bincode::serde::encode_to_vec(&rec, bincode::config::standard()).unwrap();
        let (decoded, _): (OrgRecord, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(decoded.id, rec.id);
        assert_eq!(decoded.name, rec.name);
        assert_eq!(decoded.metadata, rec.metadata);
        assert_eq!(decoded.created_at, rec.created_at);
    }

    #[test]
    fn principal_record_bincode_round_trip() {
        let rec = PrincipalRecord {
            id: "p_1".into(),
            org_id: "org_1".into(),
            name: "alice".into(),
            role: "admin".into(),
            metadata: HashMap::new(),
            created_at: 1700000000,
        };
        let bytes = bincode::serde::encode_to_vec(&rec, bincode::config::standard()).unwrap();
        let (decoded, _): (PrincipalRecord, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(decoded.id, rec.id);
        assert_eq!(decoded.org_id, rec.org_id);
        assert_eq!(decoded.name, rec.name);
        assert_eq!(decoded.role, rec.role);
    }

    #[test]
    fn principal_key_record_bincode_round_trip() {
        let rec = PrincipalKeyRecord {
            id: "pk_1".into(),
            principal_id: "p_1".into(),
            org_id: "org_1".into(),
            name: "default".into(),
            key_hash: vec![0xAA; 32],
            valid_after: 1700000000,
            valid_before: 1800000000,
            created_at: 1700000000,
        };
        let bytes = bincode::serde::encode_to_vec(&rec, bincode::config::standard()).unwrap();
        let (decoded, _): (PrincipalKeyRecord, _) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(decoded.id, rec.id);
        assert_eq!(decoded.key_hash, rec.key_hash);
        assert_eq!(decoded.valid_after, rec.valid_after);
        assert_eq!(decoded.valid_before, rec.valid_before);
    }

    #[test]
    fn role_record_bincode_round_trip() {
        for role in builtin_roles() {
            let bytes = bincode::serde::encode_to_vec(&role, bincode::config::standard()).unwrap();
            let (decoded, _): (RoleRecord, _) =
                bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
            assert_eq!(decoded.name, role.name);
            assert_eq!(decoded.permissions, role.permissions);
            assert_eq!(decoded.built_in, role.built_in);
        }
    }
}
