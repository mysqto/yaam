//! Protecting key material at rest.
//!
//! [`crate::keystore::Passthrough`] writes keys as handed to it, which makes a key file a usable key
//! to anyone who can read it. This module is what a deployment uses instead.
//!
//! # The header, and why every blob carries one
//!
//! A wrapped blob names the scheme that produced it, the salt and the cost parameters. That is
//! redundant per blob and bought deliberately:
//!
//! - **A wrong wrapper errors instead of guessing.** [`crate::keystore::KeyWrapper::unwrap`] promises that key
//!   material it cannot recover is an error and not an erasure, and the store keeps destroyed keys and
//!   unreadable keys apart on the strength of that promise. Without a scheme byte, a store opened
//!   under the wrong wrapper would hand plausible garbage to the unwrap step and be indistinguishable
//!   from a key that was shredded.
//! - **There is no second file to lose.** A blob plus the passphrase is enough to recover the key.
//!   A salt kept beside the store would be one more thing a backup could exclude by accident, and
//!   the backup exclusion list is where the key store is *supposed* to be.
//! - **Cost parameters can rise.** Argon2 parameters age. Recording them per blob means a wrapper
//!   configured with today's cost still reads what yesterday's wrote, so raising them is a
//!   re-wrap at leisure rather than a flag day.
//!
//! # Where a key service plugs in
//!
//! [`crate::keystore::KeyWrapper`] is the seam; this is one implementation of it. An implementation backed by a
//! key service replaces the derivation and keeps everything else, and [`Scheme`] reserves a
//! discriminant for it so blobs from the two are told apart rather than silently misread. Such an
//! implementation owes the same contract this one meets: a failure to reach the service must surface
//! as an error, never as absent key material.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::Error;

/// Bytes of the format marker leading every wrapped blob.
const MAGIC: &[u8; 6] = b"YAAMKW";

/// Format version of the header.
const FORMAT_VER: u8 = 1;

/// Bytes of salt drawn per wrapper.
const SALT_LEN: usize = 16;

/// Bytes of key-encryption key the derivation produces.
const KEK_LEN: usize = 32;

/// Header bytes before the wrapped key material.
const HEADER_LEN: usize = MAGIC.len() + 2 + SALT_LEN + 12;

/// How a blob's key-encryption key was produced.
///
/// Stored as one byte so a blob written by one scheme is refused by another rather than decoded as
/// though it belonged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Scheme {
    /// Argon2id over a passphrase, then AES-256 key wrap with padding.
    PassphraseArgon2id = 1,
}

impl Scheme {
    /// The scheme a discriminant names, or `None` if nothing does.
    ///
    /// Discriminant 2 is reserved for a key-service-backed wrapper and deliberately unhandled: a
    /// blob written by one is refused here, which is the intended answer until such a wrapper exists.
    const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::PassphraseArgon2id),
            _ => None,
        }
    }

    /// How this scheme protects key material, in the words a report uses.
    ///
    /// Here rather than on the wrapper, because a blob read off disk names its scheme by a byte and
    /// nothing else: a report that could only get this prose from a live wrapper could only describe
    /// the wrapper the reading process happens to hold.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PassphraseArgon2id => "argon2id over a passphrase, then AES-256 key wrap",
        }
    }
}

/// What the front of stored key material says about its own protection.
///
/// The header sits outside the ciphertext exactly so this question has an answer without the
/// passphrase: reading a marker is not decrypting, and a report that needed the key in order to say
/// whether the key was protected could only ever describe its own configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrapping {
    /// Marked, under a scheme this build can name.
    Named(Scheme),
    /// Marked, under something this build cannot name — a newer format version, or the discriminant
    /// reserved for a key service. Wrapped all the same: the marker is the claim, and naming the
    /// scheme is the separate question.
    Unnamed,
    /// No marker. The bytes are key material as written, and the file is a usable key.
    Absent,
}

/// What the leading bytes of `stored` say about how it was wrapped.
///
/// Deliberately more forgiving than the header parse on the unwrap path: that one gates a blob about
/// to be unwrapped and owes an error naming the cause, this one only has to tell a marked blob from
/// an unmarked one. A header this build cannot read is still a header, and calling it unwrapped would
/// be the more dangerous mistake of the two — it is the one that says a protected store is in the
/// clear.
///
/// A 32-byte random key that happens to open with the marker would be misread here, at one chance in
/// 2^48; the same coincidence makes [`crate::keystore::KeyWrapper::unwrap`] fail loudly, so nothing
/// acts on it silently.
#[must_use]
pub fn wrapping_of(stored: &[u8]) -> Wrapping {
    if stored.len() < MAGIC.len() || &stored[..MAGIC.len()] != MAGIC {
        return Wrapping::Absent;
    }
    if stored.len() <= MAGIC.len() + 1 || stored[MAGIC.len()] != FORMAT_VER {
        return Wrapping::Unnamed;
    }
    match Scheme::from_byte(stored[MAGIC.len() + 1]) {
        Some(scheme) => Wrapping::Named(scheme),
        None => Wrapping::Unnamed,
    }
}

/// Argon2id cost, as recorded in every blob this wrapper writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    /// Memory in kibibytes.
    pub memory_kib: u32,
    /// Passes over memory.
    pub passes: u32,
    /// Degree of parallelism.
    pub lanes: u32,
}

impl Default for Cost {
    /// The current recommended baseline: 19 MiB, two passes, one lane.
    ///
    /// Chosen over a heavier setting because this runs once per store open on whatever host the
    /// service runs on, and a parameter set that makes a service slow to start is a parameter set
    /// someone turns off.
    fn default() -> Self {
        Self {
            memory_kib: 19 * 1024,
            passes: 2,
            lanes: 1,
        }
    }
}

impl Cost {
    /// The twelve bytes recording this cost in a header.
    fn to_bytes(self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[..4].copy_from_slice(&self.memory_kib.to_le_bytes());
        out[4..8].copy_from_slice(&self.passes.to_le_bytes());
        out[8..].copy_from_slice(&self.lanes.to_le_bytes());
        out
    }

    /// Reads back [`Cost::to_bytes`].
    fn from_bytes(bytes: &[u8]) -> Self {
        let word = |at: usize| {
            let mut four = [0u8; 4];
            four.copy_from_slice(&bytes[at..at + 4]);
            u32::from_le_bytes(four)
        };
        Self {
            memory_kib: word(0),
            passes: word(4),
            lanes: word(8),
        }
    }

    /// The Argon2 parameters this cost describes.
    fn params(self) -> crate::Result<Params> {
        Params::new(self.memory_kib, self.passes, self.lanes, Some(KEK_LEN))
            .map_err(|e| Error::MalformedBlock(format!("unusable argon2 cost: {e}")))
    }
}

/// Wraps key material under a key derived from a passphrase.
///
/// Holds the passphrase rather than only the derived key, so a blob written under different cost
/// parameters can still be read — see the module note on parameters ageing. Both live in memory
/// zeroized on drop, and both are equally sensitive: whoever can read one can read the keys.
pub struct PassphraseWrapper {
    passphrase: Zeroizing<Vec<u8>>,
    salt: [u8; SALT_LEN],
    cost: Cost,
    kek: Zeroizing<[u8; KEK_LEN]>,
}

/// Written by hand so a passphrase cannot reach a log through a derive.
impl std::fmt::Debug for PassphraseWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassphraseWrapper")
            .field("cost", &self.cost)
            .finish_non_exhaustive()
    }
}

impl PassphraseWrapper {
    /// Derives a wrapper from `passphrase` with a fresh random salt and the default cost.
    ///
    /// Runs the derivation once here rather than per wrap, so opening a store pays for it and
    /// individual key operations do not.
    pub fn new(passphrase: &[u8]) -> crate::Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        crate::seal::fill_random(&mut salt);
        Self::with_salt(passphrase, salt, Cost::default())
    }

    /// Derives a wrapper from a known salt and cost.
    ///
    /// The path that reads an existing blob, and the only way to reproduce a wrapper exactly.
    pub fn with_salt(passphrase: &[u8], salt: [u8; SALT_LEN], cost: Cost) -> crate::Result<Self> {
        let kek = derive(passphrase, &salt, cost)?;
        Ok(Self {
            passphrase: Zeroizing::new(passphrase.to_vec()),
            salt,
            cost,
            kek,
        })
    }

    /// The cost this wrapper writes with.
    #[must_use]
    pub fn cost(&self) -> Cost {
        self.cost
    }

    /// The key-encryption key for a blob's own salt and cost.
    ///
    /// Reuses the derived key when the blob matches this wrapper, and derives afresh when it does
    /// not, which is what lets a wrapper configured with a raised cost still read older blobs.
    fn kek_for(
        &self,
        salt: &[u8; SALT_LEN],
        cost: Cost,
    ) -> crate::Result<Zeroizing<[u8; KEK_LEN]>> {
        if *salt == self.salt && cost == self.cost {
            return Ok(self.kek.clone());
        }
        derive(&self.passphrase, salt, cost)
    }
}

impl crate::keystore::KeyWrapper for PassphraseWrapper {
    fn scheme(&self) -> &'static str {
        // The same words a blob's own header resolves to, from the same place: a wrapper that
        // described itself differently from what it writes is a mismatch nobody would see until
        // two reports of one store disagreed.
        Scheme::PassphraseArgon2id.name()
    }

    fn wrap(&self, key: &[u8]) -> crate::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(HEADER_LEN + key.len() + 16);
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VER);
        out.push(Scheme::PassphraseArgon2id as u8);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.cost.to_bytes());
        out.extend_from_slice(&kwp_wrap(&self.kek, key)?);
        Ok(out)
    }

    fn unwrap(&self, wrapped: &[u8]) -> crate::Result<Vec<u8>> {
        let header = Header::parse(wrapped)?;
        let kek = self.kek_for(&header.salt, header.cost)?;
        kwp_unwrap(&kek, &wrapped[HEADER_LEN..])
    }
}

/// A parsed blob header.
struct Header {
    salt: [u8; SALT_LEN],
    cost: Cost,
}

impl Header {
    /// Reads the header, refusing anything this wrapper did not write.
    fn parse(blob: &[u8]) -> crate::Result<Self> {
        // The marker is checked before the length, because the likeliest wrong input is a bare
        // 32-byte key from an unwrapped store -- shorter than a header, and a length complaint
        // would name the symptom while the marker names the cause.
        if blob.len() < MAGIC.len() || &blob[..MAGIC.len()] != MAGIC {
            return Err(Error::MalformedBlock(
                "not a wrapped key: no format marker. An unwrapped store opened under a wrapper \
                 looks exactly like this."
                    .into(),
            ));
        }
        if blob.len() < HEADER_LEN {
            return Err(Error::MalformedBlock(format!(
                "wrapped key is {} bytes, too short for a header",
                blob.len()
            )));
        }
        let mut at = MAGIC.len();
        if blob[at] != FORMAT_VER {
            return Err(Error::MalformedBlock(format!(
                "wrapped key format {} is not the {FORMAT_VER} this build writes",
                blob[at]
            )));
        }
        at += 1;
        let Some(scheme) = Scheme::from_byte(blob[at]) else {
            return Err(Error::MalformedBlock(format!(
                "wrapped key names scheme {}, which this build cannot derive. Key material this \
                 cannot recover is not key material that was erased.",
                blob[at]
            )));
        };
        debug_assert_eq!(scheme, Scheme::PassphraseArgon2id);
        at += 1;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&blob[at..at + SALT_LEN]);
        at += SALT_LEN;
        Ok(Self {
            salt,
            cost: Cost::from_bytes(&blob[at..at + 12]),
        })
    }
}

/// Argon2id over `passphrase` and `salt`.
fn derive(passphrase: &[u8], salt: &[u8], cost: Cost) -> crate::Result<Zeroizing<[u8; KEK_LEN]>> {
    let mut kek = Zeroizing::new([0u8; KEK_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, cost.params()?)
        .hash_password_into(passphrase, salt, kek.as_mut())
        .map_err(|e| Error::MalformedBlock(format!("cannot derive a key: {e}")))?;
    Ok(kek)
}

/// AES-256 key wrap with padding, so key material of any length is accepted.
fn kwp_wrap(kek: &[u8; KEK_LEN], key: &[u8]) -> crate::Result<Vec<u8>> {
    use aes_kw::{KeyInit, KwpAes256};
    let kw = KwpAes256::new_from_slice(kek)
        .map_err(|_| Error::MalformedBlock("derived key is not 32 bytes".into()))?;
    let mut out = vec![0u8; key.len() + 8 + 7];
    let n = kw
        .wrap_key(key, &mut out)
        .map_err(|_| Error::MalformedBlock(format!("cannot wrap {} bytes", key.len())))?
        .len();
    out.truncate(n);
    Ok(out)
}

/// The inverse of [`kwp_wrap`]. A failed integrity check is authentication failure, not corruption.
fn kwp_unwrap(kek: &[u8; KEK_LEN], wrapped: &[u8]) -> crate::Result<Vec<u8>> {
    use aes_kw::{KeyInit, KwpAes256};
    let kw = KwpAes256::new_from_slice(kek)
        .map_err(|_| Error::MalformedBlock("derived key is not 32 bytes".into()))?;
    let mut out = vec![0u8; wrapped.len()];
    let n = kw
        .unwrap_key(wrapped, &mut out)
        .map_err(|_| Error::Authentication)?
        .len();
    out.truncate(n);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::{KeyWrapper, Passthrough};

    const PASS: &[u8] = b"correct horse battery staple";
    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    /// A cheap cost, so the tests are not an argon2 benchmark. Never use this for a real store.
    fn cheap() -> Cost {
        Cost {
            memory_kib: 32,
            passes: 1,
            lanes: 1,
        }
    }

    fn wrapper(passphrase: &[u8]) -> PassphraseWrapper {
        PassphraseWrapper::with_salt(passphrase, [7u8; SALT_LEN], cheap()).expect("derived")
    }

    #[test]
    fn key_material_survives_a_round_trip() {
        let w = wrapper(PASS);
        let wrapped = w.wrap(KEY).expect("wrapped");
        assert_ne!(wrapped, KEY, "the blob must not be the key");
        assert_eq!(w.unwrap(&wrapped).expect("unwrapped"), KEY);
    }

    #[test]
    fn key_material_of_any_length_survives() {
        // AES-KW takes multiples of eight; the padded variant is here so callers need not care.
        let w = wrapper(PASS);
        for len in [1usize, 7, 8, 15, 16, 31, 32, 33, 64] {
            let key = vec![0xABu8; len];
            let wrapped = w.wrap(&key).expect("wrapped");
            assert_eq!(
                w.unwrap(&wrapped).expect("unwrapped"),
                key,
                "at {len} bytes"
            );
        }
    }

    #[test]
    fn a_wrong_passphrase_fails_authentication_rather_than_returning_rubbish() {
        // The contract the store depends on: material this cannot recover is an error, never a
        // plausible-looking key and never an absence that reads as erasure.
        let wrapped = wrapper(PASS).wrap(KEY).expect("wrapped");
        let err = wrapper(b"not the passphrase").unwrap(&wrapped).unwrap_err();
        assert!(matches!(err, Error::Authentication), "{err:?}");
    }

    #[test]
    fn an_unwrapped_store_opened_under_a_wrapper_is_an_error() {
        // The migration nobody plans: a store written under Passthrough, later opened wrapped. The
        // bytes are a valid key, so only the format marker can tell the difference.
        let plain = Passthrough.wrap(KEY).expect("passed through");
        let err = wrapper(PASS).unwrap(&plain).unwrap_err();
        let Error::MalformedBlock(why) = &err else {
            panic!("{err:?}");
        };
        assert!(why.contains("no format marker"), "{why}");
    }

    #[test]
    fn a_blob_from_another_scheme_is_refused_not_decoded() {
        // Discriminant 2 is reserved for a key-service wrapper. Until one exists, its blobs are
        // refused here rather than run through a derivation that was never theirs.
        let mut blob = wrapper(PASS).wrap(KEY).expect("wrapped");
        blob[MAGIC.len() + 1] = 2;
        let err = wrapper(PASS).unwrap(&blob).unwrap_err();
        let Error::MalformedBlock(why) = &err else {
            panic!("{err:?}");
        };
        assert!(why.contains("scheme 2"), "{why}");
        assert!(why.contains("not key material that was erased"), "{why}");
    }

    #[test]
    fn a_future_format_version_is_refused() {
        let mut blob = wrapper(PASS).wrap(KEY).expect("wrapped");
        blob[MAGIC.len()] = FORMAT_VER + 1;
        let err = wrapper(PASS).unwrap(&blob).unwrap_err();
        assert!(
            matches!(&err, Error::MalformedBlock(why) if why.contains("format")),
            "{err:?}"
        );
    }

    #[test]
    fn a_blob_too_short_to_hold_a_header_is_refused() {
        let err = wrapper(PASS).unwrap(b"YAAMKW\x01\x01").unwrap_err();
        assert!(
            matches!(&err, Error::MalformedBlock(why) if why.contains("too short")),
            "{err:?}"
        );
    }

    #[test]
    fn a_truncated_body_fails_authentication() {
        let wrapped = wrapper(PASS).wrap(KEY).expect("wrapped");
        let err = wrapper(PASS)
            .unwrap(&wrapped[..wrapped.len() - 8])
            .unwrap_err();
        assert!(matches!(err, Error::Authentication), "{err:?}");
    }

    #[test]
    fn a_raised_cost_still_reads_what_the_old_cost_wrote() {
        // Why the parameters live in the blob. Raising cost is otherwise a flag day: every existing
        // key becomes unreadable at the moment the parameter changes.
        let old = wrapper(PASS).wrap(KEY).expect("wrapped");
        let raised = PassphraseWrapper::with_salt(
            PASS,
            [7u8; SALT_LEN],
            Cost {
                memory_kib: 64,
                passes: 3,
                lanes: 1,
            },
        )
        .expect("derived");
        assert_eq!(raised.unwrap(&old).expect("unwrapped"), KEY);
        // And the other way: the raised wrapper writes what it configured, not what it read.
        assert_eq!(raised.cost().passes, 3);
    }

    #[test]
    fn a_different_salt_is_read_from_the_blob_not_the_wrapper() {
        // The recovery property: passphrase plus blob is enough. No separate salt file to lose --
        // which matters because the key store is what a backup is meant to exclude.
        let theirs =
            PassphraseWrapper::with_salt(PASS, [99u8; SALT_LEN], cheap()).expect("derived");
        let blob = theirs.wrap(KEY).expect("wrapped");
        assert_eq!(wrapper(PASS).unwrap(&blob).expect("unwrapped"), KEY);
    }

    #[test]
    fn a_fresh_wrapper_draws_its_own_salt() {
        let a = PassphraseWrapper::new(PASS).expect("derived");
        let b = PassphraseWrapper::new(PASS).expect("derived");
        assert_ne!(a.salt, b.salt, "two opens must not share a salt");
        assert_eq!(a.cost(), Cost::default());
    }

    #[test]
    fn the_debug_rendering_holds_no_passphrase_and_no_key() {
        let shown = format!("{:?}", wrapper(PASS));
        assert!(!shown.contains("horse"), "{shown}");
        assert!(!shown.contains("staple"), "{shown}");
        assert!(shown.contains("Cost"), "{shown}");
    }

    #[test]
    fn an_unusable_cost_is_an_error_and_not_a_panic() {
        let err = PassphraseWrapper::with_salt(
            PASS,
            [0u8; SALT_LEN],
            Cost {
                memory_kib: 0,
                passes: 0,
                lanes: 0,
            },
        )
        .unwrap_err();
        assert!(
            matches!(&err, Error::MalformedBlock(why) if why.contains("argon2 cost")),
            "{err:?}"
        );
    }

    #[test]
    fn every_scheme_byte_round_trips_through_its_discriminant() {
        assert_eq!(
            Scheme::from_byte(Scheme::PassphraseArgon2id as u8),
            Some(Scheme::PassphraseArgon2id)
        );
        assert_eq!(Scheme::from_byte(0), None);
        assert_eq!(Scheme::from_byte(2), None, "reserved, not yet implemented");
    }

    #[test]
    fn a_blob_names_its_scheme_to_a_reader_holding_no_passphrase() {
        // The property a health read stands on: the header is outside the ciphertext, so what wrote
        // a key file can be read without the key. Nothing derived here, and nothing unwrapped.
        let blob = wrapper(PASS).wrap(KEY).expect("wrapped");
        assert_eq!(
            wrapping_of(&blob),
            Wrapping::Named(Scheme::PassphraseArgon2id)
        );
        assert_eq!(
            Scheme::PassphraseArgon2id.name(),
            wrapper(PASS).scheme(),
            "one spelling for the header's scheme and the wrapper's own"
        );
    }

    #[test]
    fn key_material_written_as_it_came_carries_no_marker() {
        // A bare key, which is what Passthrough leaves on disk, and the state the marker exists to
        // tell apart from a blob.
        assert_eq!(
            wrapping_of(&Passthrough.wrap(KEY).expect("passed through")),
            Wrapping::Absent
        );
        assert_eq!(wrapping_of(b""), Wrapping::Absent);
        assert_eq!(wrapping_of(b"YAAMK"), Wrapping::Absent, "a partial marker");
    }

    #[test]
    fn a_header_this_build_cannot_read_still_reads_as_wrapped() {
        // Wrapped-but-unnameable is the safer of the two errors: calling it unwrapped would tell an
        // operator that a protected store is in the clear.
        let blob = wrapper(PASS).wrap(KEY).expect("wrapped");
        let mut future = blob.clone();
        future[MAGIC.len()] = FORMAT_VER + 1;
        assert_eq!(wrapping_of(&future), Wrapping::Unnamed);

        let mut reserved = blob.clone();
        reserved[MAGIC.len() + 1] = 2;
        assert_eq!(wrapping_of(&reserved), Wrapping::Unnamed);

        assert_eq!(
            wrapping_of(&blob[..=MAGIC.len()]),
            Wrapping::Unnamed,
            "a marker with nothing behind it is still a marker"
        );
    }

    #[test]
    fn a_cost_survives_its_own_encoding() {
        let cost = Cost {
            memory_kib: 19 * 1024,
            passes: 2,
            lanes: 4,
        };
        assert_eq!(Cost::from_bytes(&cost.to_bytes()), cost);
    }
}
