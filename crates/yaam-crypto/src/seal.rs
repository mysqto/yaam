//! The sealing primitives.

use yaam_contract::{RecordId, SubjectHash};

/// A single-use 96-bit nonce.
///
/// Constructible only from a CSPRNG. Nonce reuse under one key leaks the plaintext difference *and*
/// the authentication subkey, so there is deliberately no way to supply your own — and no way to
/// reproduce a previous sealing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce([u8; 12]);

impl Nonce {
    /// Draws a fresh nonce.
    #[must_use]
    pub fn generate() -> Self {
        todo!("CSPRNG fill")
    }

    /// Reconstructs a nonce read from a stored block, for unsealing only.
    #[must_use]
    pub fn from_stored(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// The calendar epoch a subject's key belongs to.
///
/// Keys are per subject *and* per epoch so retention can be enforced by destroying an epoch's keys.
/// Granularity is therefore one epoch, not one record — callers should not promise finer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Epoch(String);

impl Epoch {
    /// Derives the epoch containing a server-stamped instant.
    #[must_use]
    pub fn containing(_received_ms: i64) -> Self {
        todo!("quarter of received_ms")
    }

    /// The epoch label, e.g. `2026-Q3`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One subject's share of a record's data key. Useless alone.
#[derive(Debug, Clone)]
pub struct DekShare {
    /// Whose share this is.
    pub subject: SubjectHash,
    /// The wrapped share as stored.
    pub wrapped: Vec<u8>,
}

/// A record's data key. Only obtainable from a complete share set.
///
/// Deriving rather than reconstructing is deliberate: an implementation that wrapped the whole key
/// per subject — so any one subject could unseal — cannot produce a valid `Dek` at all, instead of
/// appearing to work.
#[derive(Debug)]
#[expect(dead_code, reason = "read once the implementation lands")]
pub struct Dek(Vec<u8>);

impl Dek {
    /// Mints a fresh key for a new record.
    #[must_use]
    pub fn generate() -> Self {
        todo!("CSPRNG fill")
    }

    /// Derives the key from every share, bound to the record and its subject set.
    pub fn derive(_record: &RecordId, _shares: &[DekShare]) -> crate::Result<Self> {
        todo!("HKDF over the combined shares, bound to record identity")
    }

    /// Splits into one share per subject.
    pub fn split(&self, _subjects: &[SubjectHash]) -> crate::Result<Vec<DekShare>> {
        todo!("split so that all shares are required")
    }
}

/// A sealed record body, as stored.
#[derive(Debug, Clone)]
pub struct SealedBody {
    /// Nonce used for this sealing.
    pub nonce: Nonce,
    /// Epoch whose subject keys wrap the shares.
    pub epoch: Epoch,
    /// Wrapped shares, one per subject.
    pub shares: Vec<DekShare>,
    /// Ciphertext with its authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Seals a body for a record's subjects.
pub fn seal(
    _record: &RecordId,
    _subjects: &[SubjectHash],
    _epoch: &Epoch,
    _plaintext: &[u8],
) -> crate::Result<SealedBody> {
    todo!("fresh dek + nonce, split, wrap, encrypt with recomputed aad")
}

/// Unseals a body, given every share.
///
/// Associated data is recomputed from the record's own identity and subject set — never read from
/// the stored block, since a stored copy travels with a swapped body and would authenticate it.
pub fn unseal(_record: &RecordId, _body: &SealedBody) -> crate::Result<Vec<u8>> {
    todo!("recompute aad, unwrap shares, derive dek, decrypt")
}
