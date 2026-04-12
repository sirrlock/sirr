use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Server-wide mode controlling which write paths are enabled.
/// Persisted in the `config` redb table under key `"visibility"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Visibility {
    /// Pure dead-drop. Anonymous writes only. No keys. Default.
    Public,
    /// Managed mode. All writes require a key. Reads still work via hash capability.
    Private,
    /// Mixed. Anonymous dead-drops AND keyed managed secrets coexist.
    Both,
    /// Emergency lockdown. All requests rejected except admin socket operations.
    None,
}

impl Visibility {
    /// True when anonymous (unauthenticated) secret creation is allowed.
    pub fn allows_anonymous_write(&self) -> bool {
        matches!(self, Visibility::Public | Visibility::Both)
    }

    /// True when keyed (authenticated) secret creation is allowed.
    pub fn allows_keyed_write(&self) -> bool {
        matches!(self, Visibility::Private | Visibility::Both)
    }

    /// True when ANY request (reads or writes) may proceed. False only for `None`.
    pub fn allows_any_request(&self) -> bool {
        !matches!(self, Visibility::None)
    }
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Visibility::Public => write!(f, "public"),
            Visibility::Private => write!(f, "private"),
            Visibility::Both => write!(f, "both"),
            Visibility::None => write!(f, "none"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ParseVisibilityError(String);

impl fmt::Display for ParseVisibilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown visibility mode {:?}; expected public|private|both|none",
            self.0
        )
    }
}

impl std::error::Error for ParseVisibilityError {}

impl FromStr for Visibility {
    type Err = ParseVisibilityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "public" => Ok(Visibility::Public),
            "private" => Ok(Visibility::Private),
            "both" => Ok(Visibility::Both),
            "none" => Ok(Visibility::None),
            other => Err(ParseVisibilityError(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_round_trip() {
        for v in [
            Visibility::Public,
            Visibility::Private,
            Visibility::Both,
            Visibility::None,
        ] {
            let s = v.to_string();
            let parsed: Visibility = s.parse().unwrap();
            assert_eq!(v, parsed, "round-trip failed for {v}");
        }
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!("PUBLIC".parse::<Visibility>().unwrap(), Visibility::Public);
        assert_eq!(
            "Private".parse::<Visibility>().unwrap(),
            Visibility::Private
        );
        assert_eq!("BOTH".parse::<Visibility>().unwrap(), Visibility::Both);
        assert_eq!("None".parse::<Visibility>().unwrap(), Visibility::None);
    }

    #[test]
    fn parse_unknown_returns_error() {
        let err = "foobar".parse::<Visibility>().unwrap_err();
        assert!(err.to_string().contains("foobar"));
    }

    #[test]
    fn allows_anonymous_write() {
        assert!(Visibility::Public.allows_anonymous_write());
        assert!(!Visibility::Private.allows_anonymous_write());
        assert!(Visibility::Both.allows_anonymous_write());
        assert!(!Visibility::None.allows_anonymous_write());
    }

    #[test]
    fn allows_keyed_write() {
        assert!(!Visibility::Public.allows_keyed_write());
        assert!(Visibility::Private.allows_keyed_write());
        assert!(Visibility::Both.allows_keyed_write());
        assert!(!Visibility::None.allows_keyed_write());
    }

    #[test]
    fn allows_any_request() {
        assert!(Visibility::Public.allows_any_request());
        assert!(Visibility::Private.allows_any_request());
        assert!(Visibility::Both.allows_any_request());
        assert!(!Visibility::None.allows_any_request());
    }

    #[test]
    fn bincode_round_trip() {
        for v in [
            Visibility::Public,
            Visibility::Private,
            Visibility::Both,
            Visibility::None,
        ] {
            let encoded = bincode::serde::encode_to_vec(v, bincode::config::standard()).unwrap();
            let (decoded, _): (Visibility, _) =
                bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
            assert_eq!(v, decoded);
        }
    }
}
