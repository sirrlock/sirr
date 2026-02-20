use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Canonical order of permission letters (bit 0 → bit 14).
const LETTER_ORDER: &[u8; 15] = b"rRlLcCpPaAmMSdD";

/// Individual permission bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PermBit {
    /// Bit 0 — read my secrets
    ReadMy = 0,
    /// Bit 1 — read org secrets
    ReadOrg = 1,
    /// Bit 2 — list my secrets
    ListMy = 2,
    /// Bit 3 — list org secrets
    ListOrg = 3,
    /// Bit 4 — create secrets
    Create = 4,
    /// Bit 5 — create on behalf of others
    CreateOnBehalf = 5,
    /// Bit 6 — patch my secrets
    PatchMy = 6,
    /// Bit 7 — patch org secrets
    PatchOrg = 7,
    /// Bit 8 — read my account
    AccountRead = 8,
    /// Bit 9 — read org accounts
    AccountReadOrg = 9,
    /// Bit 10 — manage my account
    AccountManage = 10,
    /// Bit 11 — manage org principals/roles
    ManageOrg = 11,
    /// Bit 12 — sirr admin (create/delete orgs)
    SirrAdmin = 12,
    /// Bit 13 — delete my secrets
    DeleteMy = 13,
    /// Bit 14 — delete org secrets
    DeleteOrg = 14,
}

impl PermBit {
    /// Convert a single permission letter to its `PermBit`.
    fn from_letter(ch: u8) -> Option<Self> {
        LETTER_ORDER.iter().position(|&c| c == ch).map(|i| {
            // SAFETY: i is in 0..15 which are all valid discriminants.
            unsafe { std::mem::transmute::<u8, PermBit>(i as u8) }
        })
    }

    fn as_mask(self) -> u16 {
        1u16 << (self as u8)
    }
}

/// A 15-bit permission bitflag.
///
/// Internally stored as a `u16`; serialised to/from a letter string in JSON.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Permissions(u16);

/// Mask covering all 15 valid bits.
const ALL_BITS: u16 = (1u16 << 15) - 1; // 0x7FFF

impl Permissions {
    // ── constructors ──

    /// No permissions.
    pub fn none() -> Self {
        Self(0)
    }

    /// All 15 permissions.
    pub fn all() -> Self {
        Self(ALL_BITS)
    }

    /// Build from a raw `u16`. Bits above bit 14 are silently masked off.
    pub fn from_bits(bits: u16) -> Self {
        Self(bits & ALL_BITS)
    }

    /// Parse a permission letter string (e.g. `"rRlLcC"`).
    ///
    /// Returns `Err` if any character is not a recognised permission letter.
    pub fn parse(s: &str) -> Result<Self, PermParseError> {
        let mut bits: u16 = 0;
        for &ch in s.as_bytes() {
            match PermBit::from_letter(ch) {
                Some(pb) => bits |= pb.as_mask(),
                None => return Err(PermParseError::InvalidLetter(ch as char)),
            }
        }
        Ok(Self(bits))
    }

    // ── queries ──

    /// Check whether a single permission is set.
    pub fn has(self, bit: PermBit) -> bool {
        self.0 & bit.as_mask() != 0
    }

    /// `true` if every bit in `self` is also present in `other`.
    pub fn is_subset_of(self, other: Permissions) -> bool {
        self.0 & other.0 == self.0
    }

    /// The raw `u16` value.
    pub fn bits(self) -> u16 {
        self.0
    }

    // ── display ──

    /// Render to the canonical letter string (bit-0 first).
    pub fn to_letter_string(self) -> String {
        let mut s = String::with_capacity(15);
        for (i, &ch) in LETTER_ORDER.iter().enumerate() {
            if self.0 & (1u16 << i) != 0 {
                s.push(ch as char);
            }
        }
        s
    }
}

// ── Display ──

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_letter_string())
    }
}

impl fmt::Debug for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Permissions(\"{}\")", self.to_letter_string())
    }
}

// ── Serde: serialise as letter string ──

impl Serialize for Permissions {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_letter_string())
    }
}

impl<'de> Deserialize<'de> for Permissions {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        Permissions::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ── Error type ──

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermParseError {
    InvalidLetter(char),
}

impl fmt::Display for PermParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PermParseError::InvalidLetter(ch) => write!(f, "invalid permission letter: '{ch}'"),
        }
    }
}

impl std::error::Error for PermParseError {}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_permissions() {
        let s = "rRlLcCpPaAmMSdD";
        let p = Permissions::parse(s).unwrap();
        assert_eq!(p.bits(), 0x7FFF);
        assert_eq!(p.to_letter_string(), s);
        // parse again to confirm true round-trip
        let p2 = Permissions::parse(&p.to_letter_string()).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn round_trip_reader() {
        let p = Permissions::parse("rla").unwrap();
        assert!(p.has(PermBit::ReadMy));
        assert!(p.has(PermBit::ListMy));
        assert!(p.has(PermBit::AccountRead));
        assert!(!p.has(PermBit::ReadOrg));
        assert!(!p.has(PermBit::Create));
        // canonical order: r then l then a
        assert_eq!(p.to_letter_string(), "rla");
    }

    #[test]
    fn invalid_letter_rejected() {
        let err = Permissions::parse("rxl").unwrap_err();
        assert_eq!(err, PermParseError::InvalidLetter('x'));
    }

    #[test]
    fn empty_string_is_zero() {
        let p = Permissions::parse("").unwrap();
        assert_eq!(p.bits(), 0);
        assert_eq!(p.to_letter_string(), "");
    }

    #[test]
    fn serde_json_round_trip() {
        let original = Permissions::parse("rlcd").unwrap();
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"rlcd\"");
        let back: Permissions = serde_json::from_str(&json).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn bitwise_subset_check() {
        let reader = Permissions::parse("rla").unwrap();
        let admin = Permissions::all();
        assert!(reader.is_subset_of(admin));
        assert!(!admin.is_subset_of(reader));
    }

    #[test]
    fn display_trait() {
        let p = Permissions::parse("cCpP").unwrap();
        assert_eq!(format!("{p}"), "cCpP");
    }

    #[test]
    fn from_bits_masks_high_bits() {
        let p = Permissions::from_bits(0xFFFF);
        assert_eq!(p.bits(), 0x7FFF);
    }

    #[test]
    fn duplicate_letters_are_idempotent() {
        let p = Permissions::parse("rrr").unwrap();
        assert_eq!(p.bits(), 1);
        assert_eq!(p.to_letter_string(), "r");
    }
}
