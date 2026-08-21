//! Newtypes for the identifiers that flow through every layer.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

/// Length of a ULID in its canonical textual form.
const ULID_LEN: usize = 26;
/// Length of a subject hash: the `s_` prefix plus 64 hex digits.
const SUBJECT_HASH_LEN: usize = 2 + 64;
/// Prefix that marks a string as a subject pseudonym rather than a raw identifier.
const SUBJECT_PREFIX: &str = "s_";

/// The set [`RecordId`] admits, as a JSON Schema `pattern`.
///
/// One rule needs two spellings: a regex cannot be a `const fn` and a byte match cannot be a
/// schema. [`crate::schema`] emits this into the published schema, and a test drives the pattern and
/// [`RecordId::try_from`] over the same corpus — two spellings agree only until one is edited alone.
pub const RECORD_ID_PATTERN: &str = "^[0-9A-HJKMNP-TV-Z]{26}$";

/// The set [`SubjectHash`] admits, as a JSON Schema `pattern`. Paired with its parser the way
/// [`RECORD_ID_PATTERN`] is.
pub const SUBJECT_HASH_PATTERN: &str = "^s_[0-9a-f]{64}$";

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
///
/// Deserialisation goes through [`RecordId::parse`]. A newtype whose invariant held only on the
/// `parse` path would be decorative: records arrive as JSON and as frontmatter, so the shape has to
/// be checked wherever one is read, not only where one is minted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
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
        Self::try_from(s.to_owned())
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
///
/// Deserialisation goes through [`SubjectHash::parse`], so a hash read from a file or a sealed
/// block cannot smuggle in a shape the rest of the system would reject — and a path built from one
/// cannot climb out of its directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
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
        Self::try_from(s.to_owned())
    }

    /// The hash as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RecordId {
    type Error = crate::Error;

    /// Takes ownership when the string is already canonical, so no copy is made on the read path.
    fn try_from(value: String) -> crate::Result<Self> {
        if value.len() == ULID_LEN && value.bytes().all(is_crockford_digit) {
            Ok(Self(value))
        } else {
            Err(crate::Error::NotCanonical {
                kind: "record".to_owned(),
                id: value,
            })
        }
    }
}

impl TryFrom<String> for SubjectHash {
    type Error = crate::Error;

    /// As [`RecordId::try_from`]: validate, then keep the caller's allocation.
    fn try_from(value: String) -> crate::Result<Self> {
        let digits = value.strip_prefix(SUBJECT_PREFIX);
        if value.len() == SUBJECT_HASH_LEN && digits.is_some_and(|d| d.bytes().all(is_lower_hex)) {
            Ok(Self(value))
        } else {
            Err(crate::Error::NotCanonical {
                kind: "subject".to_owned(),
                id: value,
            })
        }
    }
}

/// Describes an identifier as the string it is on the wire, not as the struct that holds it.
///
/// Needed because both newtypes deserialise `try_from = "String"`, which schemars cannot see: the
/// derive would describe the private `String` field and publish an object where the wire carries a
/// scalar. The constraint is the `pattern`, so it is stated rather than lost.
macro_rules! string_schema {
    ($type:ident, $pattern:expr, $description:expr) => {
        impl JsonSchema for $type {
            fn schema_name() -> Cow<'static, str> {
                stringify!($type).into()
            }

            fn schema_id() -> Cow<'static, str> {
                concat!(module_path!(), "::", stringify!($type)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "pattern": $pattern,
                    "description": $description,
                })
            }
        }
    };
}

string_schema!(
    RecordId,
    RECORD_ID_PATTERN,
    "A ULID, and the write's idempotency key. Crockford base32: uppercase, without `I`, `L`, `O` \
     or `U`, so a transcription slip cannot turn one valid identifier into another."
);

string_schema!(
    SubjectHash,
    SUBJECT_HASH_PATTERN,
    "Keyed pseudonym for an erasable data subject — an HMAC over a canonical subject identifier, \
     never a direct identifier, so it is safe in paths, indexes and tombstones. Pseudonymous, not \
     anonymous: whoever holds the keying secret can still relink it. Hex is lowercase, because one \
     spelling per hash is what lets it serve as both a map key and a path component with no \
     normalisation step a caller could forget."
);

/// Version of the record schema a row was written under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SchemaVer(pub u32);

/// Version of the canonicalisation ruleset that produced a subject hash.
///
/// Stamped per subject rather than per record: a re-keyed record can legitimately carry subjects
/// resolved under different rulesets. Lookups fan out across live versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    fn deserialisation_enforces_the_same_rule_as_parse() {
        // The reason this exists: a record arrives as JSON or as frontmatter far more often than it
        // is minted, so a check that only guarded `parse` would guard almost nothing.
        let valid = format!("\"{VALID_ULID}\"");
        assert_eq!(
            serde_json::from_str::<RecordId>(&valid).unwrap(),
            RecordId::parse(VALID_ULID).unwrap()
        );
        for bad in ["\"\"", "\"nope\"", "\"01ARZ3NDEKTSV4RRFFQ69G5FAI\""] {
            assert!(serde_json::from_str::<RecordId>(bad).is_err(), "{bad}");
        }

        let hash = format!("s_{}", hex64());
        assert_eq!(
            serde_json::from_str::<SubjectHash>(&format!("\"{hash}\"")).unwrap(),
            SubjectHash::parse(&hash).unwrap()
        );
        // The shape that mattered: a traversal a filesystem key store would otherwise be handed.
        for bad in ["\"../../escape\"", "\"s_short\"", "\"\""] {
            assert!(serde_json::from_str::<SubjectHash>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ids_round_trip_through_json() {
        let id = RecordId::generate();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", id.as_str()));
        assert_eq!(serde_json::from_str::<RecordId>(&json).unwrap(), id);

        let hash = SubjectHash::parse(&format!("s_{}", hex64())).unwrap();
        let json = serde_json::to_string(&hash).unwrap();
        assert_eq!(serde_json::from_str::<SubjectHash>(&json).unwrap(), hash);
    }

    #[test]
    fn errors_compare_by_value() {
        // Without `PartialEq` on `Error` this assertion does not compile, and every consumer falls
        // back to `matches!`.
        assert_eq!(
            RecordId::parse("nope"),
            Err(Error::NotCanonical {
                kind: "record".to_owned(),
                id: "nope".to_owned(),
            })
        );
    }

    #[test]
    fn version_newtypes_are_transparent() {
        assert_eq!(SchemaVer(1).0, 1);
        assert_eq!(CanonVer(2), CanonVer(2));
        assert_ne!(CanonVer(2), CanonVer(3));
    }

    /// Every input either parser or pattern could disagree about, in one corpus.
    ///
    /// A vendored schema is the only description a foreign implementation gets. If its `pattern`
    /// admitted one string this parser refuses, that implementation would emit records this service
    /// rejects, and the schema would be the thing at fault.
    #[test]
    fn the_published_patterns_admit_exactly_what_the_parsers_do() {
        let hex = hex64();
        let hash = format!("s_{hex}");
        let corpus = [
            String::new(),
            VALID_ULID.to_owned(),
            VALID_ULID.to_lowercase(),
            VALID_ULID[..25].to_owned(),
            format!("{VALID_ULID}0"),
            "01ARZ3NDEKTSV4RRFFQ69G5FAI".to_owned(),
            "01ARZ3NDEKTSV4RRFFQ69G5FAL".to_owned(),
            "01ARZ3NDEKTSV4RRFFQ69G5FAO".to_owned(),
            "01ARZ3NDEKTSV4RRFFQ69G5FAU".to_owned(),
            "é123456789012345678901234".to_owned(),
            hash.clone(),
            hex.clone(),
            hash.to_uppercase(),
            format!("s_{}", &hex[..63]),
            "s_short".to_owned(),
            "../../escape".to_owned(),
        ];

        let record = regex::Regex::new(RECORD_ID_PATTERN).expect("a valid pattern");
        let subject = regex::Regex::new(SUBJECT_HASH_PATTERN).expect("a valid pattern");
        for candidate in &corpus {
            assert_eq!(
                record.is_match(candidate),
                RecordId::parse(candidate).is_ok(),
                "RECORD_ID_PATTERN and RecordId::parse disagree about {candidate:?}"
            );
            assert_eq!(
                subject.is_match(candidate),
                SubjectHash::parse(candidate).is_ok(),
                "SUBJECT_HASH_PATTERN and SubjectHash::parse disagree about {candidate:?}"
            );
        }
    }
}
