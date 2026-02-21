/// License enforcement for Sirr.
///
/// Free tier: up to FREE_TIER_LIMIT active secrets per instance.
/// Licensed tier: unlimited secrets, validated by key prefix + length.
///
/// License keys are issued at https://secretdrop.app/sirr.
/// Format: `sirr_lic_` followed by 40 hex characters.
///
/// Online validation is attempted if the key looks valid; offline fallback
/// allows operation if the validation endpoint is unreachable (grace period).
/// An invalid key (wrong format) always fails hard.
pub const FREE_TIER_LIMIT: usize = 100;
const KEY_PREFIX: &str = "sirr_lic_";
const KEY_HEX_LEN: usize = 40;

/// The result of checking a license key.
#[derive(Debug, Clone, PartialEq)]
pub enum LicenseStatus {
    /// No license key configured — free tier applies.
    Free,
    /// Valid licensed tier — unlimited secrets.
    Licensed,
    /// Key provided but format is wrong.
    Invalid(String),
}

/// Validate the format of a license key.
/// Does not do online validation — that happens at secret creation time.
pub fn check_format(key: &str) -> LicenseStatus {
    if !key.starts_with(KEY_PREFIX) {
        return LicenseStatus::Invalid(format!("license key must start with '{KEY_PREFIX}'"));
    }
    let hex_part = &key[KEY_PREFIX.len()..];
    if hex_part.len() != KEY_HEX_LEN {
        return LicenseStatus::Invalid(format!(
            "license key hex part must be {KEY_HEX_LEN} characters, got {}",
            hex_part.len()
        ));
    }
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return LicenseStatus::Invalid("license key contains non-hex characters".into());
    }
    LicenseStatus::Licensed
}

/// Determine the effective license status from an optional key string.
pub fn effective_status(license_key: Option<&str>) -> LicenseStatus {
    match license_key {
        None | Some("") => LicenseStatus::Free,
        Some(key) => check_format(key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_key() {
        let key = format!("{}{}", KEY_PREFIX, "a".repeat(KEY_HEX_LEN));
        assert_eq!(check_format(&key), LicenseStatus::Licensed);
    }

    #[test]
    fn wrong_prefix() {
        assert!(matches!(
            check_format("wrong_prefix_aabbcc"),
            LicenseStatus::Invalid(_)
        ));
    }

    #[test]
    fn short_hex() {
        let key = format!("{}{}", KEY_PREFIX, "abc");
        assert!(matches!(check_format(&key), LicenseStatus::Invalid(_)));
    }

    #[test]
    fn none_is_free() {
        assert_eq!(effective_status(None), LicenseStatus::Free);
    }
}
