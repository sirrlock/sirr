/// License enforcement for Sirr.
///
/// License tiers control org and principal limits.
/// License keys are issued at https://sirrlock.com/pricing.
/// Format: `sirr_lic_` followed by 40 hex characters.
///
/// Online validation is attempted if the key looks valid; offline fallback
/// allows operation if the validation endpoint is unreachable (grace period).
/// An invalid key (wrong format) always fails hard.
const KEY_PREFIX: &str = "sirr_lic_";
const KEY_HEX_LEN: usize = 40;

/// License tier determines org and principal limits.
#[derive(Debug, Clone, PartialEq)]
pub enum LicenseTier {
    /// 1 org, 1 principal, unlimited secrets
    Solo,
    /// 1 org, unlimited principals
    Team,
    /// Unlimited orgs, unlimited principals
    Business,
    /// Unlimited everything
    Enterprise,
}

impl LicenseTier {
    /// Maximum number of orgs allowed for this tier. `None` = unlimited.
    pub fn max_orgs(&self) -> Option<usize> {
        match self {
            Self::Solo | Self::Team => Some(1),
            _ => None,
        }
    }

    /// Maximum principals per org for this tier. `None` = unlimited.
    pub fn max_principals_per_org(&self) -> Option<usize> {
        match self {
            Self::Solo => Some(1),
            _ => None,
        }
    }
}

/// The result of checking a license key.
#[derive(Debug, Clone, PartialEq)]
pub enum LicenseStatus {
    /// No license key configured — Solo tier limits apply.
    Free,
    /// Valid licensed tier.
    Licensed(LicenseTier),
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
    // Default to Business tier until online validation confirms the actual tier.
    LicenseStatus::Licensed(LicenseTier::Business)
}

/// Determine the effective license status from an optional key string.
pub fn effective_status(license_key: Option<&str>) -> LicenseStatus {
    match license_key {
        None | Some("") => LicenseStatus::Free,
        Some(key) => check_format(key),
    }
}

/// Return the effective tier for a given license status.
/// Free maps to Solo limits.
pub fn effective_tier(status: &LicenseStatus) -> &LicenseTier {
    // We use a static Solo for the Free case.
    static SOLO: LicenseTier = LicenseTier::Solo;
    match status {
        LicenseStatus::Free => &SOLO,
        LicenseStatus::Licensed(tier) => tier,
        LicenseStatus::Invalid(_) => &SOLO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_key() {
        let key = format!("{}{}", KEY_PREFIX, "a".repeat(KEY_HEX_LEN));
        assert_eq!(
            check_format(&key),
            LicenseStatus::Licensed(LicenseTier::Business)
        );
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

    #[test]
    fn tier_limits() {
        assert_eq!(LicenseTier::Solo.max_orgs(), Some(1));
        assert_eq!(LicenseTier::Solo.max_principals_per_org(), Some(1));
        assert_eq!(LicenseTier::Team.max_orgs(), Some(1));
        assert_eq!(LicenseTier::Team.max_principals_per_org(), None);
        assert_eq!(LicenseTier::Business.max_orgs(), None);
        assert_eq!(LicenseTier::Business.max_principals_per_org(), None);
        assert_eq!(LicenseTier::Enterprise.max_orgs(), None);
        assert_eq!(LicenseTier::Enterprise.max_principals_per_org(), None);
    }

    #[test]
    fn effective_tier_free_is_solo() {
        let tier = effective_tier(&LicenseStatus::Free);
        assert_eq!(tier, &LicenseTier::Solo);
    }
}
