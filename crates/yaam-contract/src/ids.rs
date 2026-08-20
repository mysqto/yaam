//! Newtypes for the identifiers that flow through every layer.

use serde::{Deserialize, Serialize};

/// Length of a ULID in its canonical textual form.
const ULID_LEN: usize = 26;
/// Length of a subject hash: the `s_` prefix plus 64 hex digits.
const SUBJECT_HASH_LEN: usize = 2 + 64;
/// Prefix that marks a string as a subject pseudonym rather than a raw identifier.
const SUBJECT_PREFIX: &str = "s_";

/// Whether a byte is a Crockford base32 digit as ULID spells it: uppercase, with `I`, `L`, `O` and
/// `U` excluded so a transcription slip cannot turn one valid id into another.
const fn is_crockford_digit(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'A'..=b'H' | b'J' | b'K' | b'M' | b'N' | b'P'..=b'T' | b'V'..=b'Z')
}

/// Whether a byte is a lowercase hex digit.
const fn is_lower_hex(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'f')
}

/// A record's ULID. Doubles as the idempotency key for its write.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecordId(String);

impl RecordId {
    /// Mints a new identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(ulid::Ulid::new().to_string())
    }

    /// Parses an existing identifier, rejecting anything that is not a ULID.
    ///
    /// The accepted set is exactly the `record` kind in `spec/entities.yaml`, so this and
    /// [`Registry::canonicalise`] cannot disagree about what names a record.
    ///
    /// # Examples
    /// ```
    /// use yaam_contract::RecordId;
    ///
    /// assert!(RecordId::parse("01ARZ3NDEKTSV4RRFFQ69G5FAV").is_ok());
    /// // `I` is not a Crockford digit, however much it looks like one.
    /// assert!(RecordId::parse("01ARZ3NDEKTSV4RRFFQ69G5FAI").is_err());
    /// ```
    ///
    /// [`Registry::canonicalise`]: crate::entity::Registry::canonicalise
    pub fn parse(s: &str) -> crate::Result<Self> {
        if s.len() == ULID_LEN && s.bytes().all(is_crockford_digit) {
            Ok(Self(s.to_owned()))
        } else {
            Err(crate::Error::NotCanonical {
                kind: "record".to_owned(),
                id: s.to_owned(),
            })
        }
    }

    /// The identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A keyed pseudonym for an erasable data subject.
///
/// Never a direct identifier: it is an HMAC over a canonical subject ID, so it is safe in paths,
/// indexes and tombstones. It is *pseudonymous*, not anonymous — the holder of the key can still
/// relink it, which is a property callers must reason about rather than forget.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubjectHash(String);

impl SubjectHash {
    /// Parses a subject hash, requiring the `s_` prefix and 64 hex digits.
    ///
    /// Hex must be lowercase. One spelling per hash is what lets a pseudonym serve as a map key
    /// and a path component without a normalisation step every caller could forget.
    ///
    /// # Examples
    /// ```
    /// use yaam_contract::SubjectHash;
    ///
    /// let hex = "0".repeat(64);
    /// assert!(SubjectHash::parse(&format!("s_{hex}")).is_ok());
    /// assert!(SubjectHash::parse(&hex).is_err()); // the prefix is not optional
    /// ```
    pub fn parse(s: &str) -> crate::Result<Self> {
        let digits = s.strip_prefix(SUBJECT_PREFIX);
        if s.len() == SUBJECT_HASH_LEN && digits.is_some_and(|d| d.bytes().all(is_lower_hex)) {
            Ok(Self(s.to_owned()))
        } else {
            Err(crate::Error::NotCanonical {
                kind: "subject".to_owned(),
                id: s.to_owned(),
            })
        }
    }

    /// The hash as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Version of the record schema a row was written under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaVer(pub u32);

/// Version of the canonicalisation ruleset that produced a subject hash.
///
/// Stamped per subject rather than per record: a re-keyed record can legitimately carry subjects
/// resolved under different rulesets. Lookups fan out across live versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonVer(pub u32);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    const VALID_ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    fn hex64() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn generated_ids_parse_and_differ() {
        let a = RecordId::generate();
        let b = RecordId::generate();
        assert!(RecordId::parse(a.as_str()).is_ok());
        assert_ne!(a, b);
    }

    #[test]
    fn parse_accepts_canonical_ulid() {
        let id = RecordId::parse(VALID_ULID).expect("canonical ULID");
        assert_eq!(id.as_str(), VALID_ULID);
    }

    #[test]
    fn parse_rejects_excluded_letters() {
        for bad in ['I', 'L', 'O', 'U'] {
            let mut s = VALID_ULID.to_owned();
            s.pop();
            s.push(bad);
            assert!(RecordId::parse(&s).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(RecordId::parse("").is_err());
        assert!(RecordId::parse(&VALID_ULID[..25]).is_err());
        assert!(RecordId::parse(&format!("{VALID_ULID}0")).is_err());
    }

    #[test]
    fn parse_rejects_lowercase_and_non_ascii() {
        assert!(RecordId::parse(&VALID_ULID.to_lowercase()).is_err());
        // 26 bytes but 25 characters: length alone must not be the whole check.
        assert!(RecordId::parse("é123456789012345678901234").is_err());
    }

    #[test]
    fn record_parse_error_names_the_kind() {
        let err = RecordId::parse("nope").expect_err("not a ULID");
        assert!(
            matches!(err, Error::NotCanonical { ref kind, ref id } if kind == "record" && id == "nope")
        );
        assert!(err.to_string().contains("nope"));
    }

    #[test]
    fn subject_hash_accepts_prefixed_hex() {
        let s = format!("s_{}", hex64());
        assert_eq!(SubjectHash::parse(&s).expect("valid").as_str(), s);
    }

    #[test]
    fn subject_hash_rejects_bad_shapes() {
        let hex = hex64();
        for bad in [
            hex.clone(),                     // no prefix
            format!("x_{hex}"),              // wrong prefix
            format!("s_{}", &hex[..63]),     // too short
            format!("s_{hex}0"),             // too long
            format!("s_{}F", &hex[..63]),    // uppercase hex
            format!("s_{}g", &hex[..63]),    // not hex
            "s_".to_owned(),                 // prefix only
            format!("s_{}", "é".repeat(32)), // 64 bytes, 32 characters
        ] {
            assert!(SubjectHash::parse(&bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn subject_parse_error_names_the_kind() {
        let err = SubjectHash::parse("s_short").expect_err("not a hash");
        assert!(matches!(err, Error::NotCanonical { ref kind, .. } if kind == "subject"));
    }

    #[test]
    fn version_newtypes_are_transparent() {
        assert_eq!(SchemaVer(1).0, 1);
        assert_eq!(CanonVer(2), CanonVer(2));
        assert_ne!(CanonVer(2), CanonVer(3));
    }
}
