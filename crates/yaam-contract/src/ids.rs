//! Newtypes for the identifiers that flow through every layer.

use serde::{Deserialize, Serialize};

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
    pub fn parse(_s: &str) -> crate::Result<Self> {
        todo!("validate ULID form")
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
    pub fn parse(_s: &str) -> crate::Result<Self> {
        todo!("validate `s_` + 64 hex")
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
