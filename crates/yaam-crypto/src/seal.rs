//! The sealing primitives.
//!
//! Layering, because the type names alone do not say it: a record is encrypted under a key that
//! exists nowhere on disk. What is stored is one *wrapped share* per subject, and the key is
//! re-derived from all of them. [`Dek::split`] and [`Dek::derive`] speak in [`BareShare`]s;
//! [`SealedBody`] only ever holds [`WrappedShare`]s. [`seal`] and [`unseal`] are the sole crossings
//! between the two, which is why they are the only functions here that take a key store.

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload, array::Array},
};
use aes_kw::{IV_LEN, KwAes256};
use hkdf::Hkdf;
use rand::CryptoRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use yaam_contract::{RecordId, SubjectHash};
use zeroize::Zeroizing;

use crate::block::FORMAT_VERSION;
use crate::error::Error;
use crate::keystore::KeyStore;

/// Length of a data key, a share, and a subject key encryption key.
const KEY_LEN: usize = 32;

/// Domain separation for the extract step, so a share set can never be re-used as another KDF's
/// input material without changing the output.
const HKDF_SALT: &[u8] = b"yaam/dek/v1/salt";

/// Draws from the operating system CSPRNG.
///
/// Used for nonces, data keys and subject keys alike, so every secret in the crate has one origin.
///
/// The `CryptoRng` bound is the point: it is a compile error to pass a reproducible generator here,
/// which is what keeps [`Nonce`] and [`Dek`] honest.
pub(crate) fn fill_random(dst: &mut [u8]) {
    fn draw<R: CryptoRng>(rng: &mut R, dst: &mut [u8]) {
        rng.fill_bytes(dst);
    }
    draw(&mut rand::rng(), dst);
}

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
        let mut bytes = [0u8; 12];
        fill_random(&mut bytes);
        Self(bytes)
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
    ///
    /// The stamp is milliseconds since the Unix epoch, UTC. Client clocks never reach this: an
    /// epoch that a caller could choose would let it park a record in an already-destroyed quarter.
    #[must_use]
    pub fn containing(received_ms: i64) -> Self {
        let (year, month) = civil_from_millis(received_ms);
        let quarter = (month - 1) / 3 + 1;
        Self(format!("{year:04}-Q{quarter}"))
    }

    /// The epoch label, e.g. `2026-Q3`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reconstructs an epoch label read from a stored block.
    ///
    /// Only the label is stored, so parsing is deliberately lenient about *which* labels exist:
    /// rejecting a label a future version minted would make old records unreadable rather than
    /// safe. Emptiness is still refused, since it would collide with a missing field.
    pub fn from_stored(label: &str) -> crate::Result<Self> {
        if label.is_empty() || label.contains(['/', '\\']) || label.contains("..") {
            return Err(Error::MalformedBlock(format!("bad epoch label `{label}`")));
        }
        Ok(Self(label.to_owned()))
    }
}

/// Civil year and month (1-12) of a millisecond stamp, UTC.
///
/// Hinnant's `civil_from_days`, in i64 with Euclidean division: flooring keeps a pre-1970 stamp on
/// its own side of the boundary instead of rounding it into the following quarter.
fn civil_from_millis(ms: i64) -> (i64, i64) {
    let days = ms.div_euclid(86_400_000);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month)
}

/// One subject's bare share of a record's data key. Useless alone, and secret while held.
///
/// Separate from [`WrappedShare`] because the two are interchangeable only by accident: a bare
/// share handed to a key store, or a wrapped one fed to [`Dek::derive`], is a silently wrong key
/// rather than an error. Two types make that unrepresentable instead of length-checked.
///
/// Zeroized on drop through the field's own type rather than a `Drop` impl on the struct, so moving
/// the share — into a collection, out of a function — still works and stays protected.
pub struct BareShare {
    /// Whose share this is.
    subject: SubjectHash,
    /// The share itself. Exactly one data key's worth, so a wrong length cannot be built.
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for BareShare {
    /// Redacted: n-1 shares carry no information, but the last one completes the set.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BareShare({}, <redacted>)", self.subject.as_str())
    }
}

impl BareShare {
    /// Whose share this is.
    #[must_use]
    pub fn subject(&self) -> &SubjectHash {
        &self.subject
    }
}

/// One subject's share as it is stored: wrapped under that subject's key for an epoch.
///
/// Safe to write to disk — destroying the subject's key makes it undecipherable — and therefore the
/// only share shape [`SealedBody`] carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedShare {
    /// Whose share this is.
    pub subject: SubjectHash,
    /// The wrapped bytes, as the key store returned them.
    pub bytes: Vec<u8>,
}

/// A record's data key. Only obtainable from a complete share set.
///
/// Deriving rather than reconstructing is deliberate: an implementation that wrapped the whole key
/// per subject — so any one subject could unseal — cannot produce a valid `Dek` at all, instead of
/// appearing to work.
///
/// [`Dek::generate`] mints the *root* that gets split; [`Dek::derive`] returns the key a record is
/// actually encrypted under. Both are this one type because a root is never used as a key: nothing
/// public encrypts with a `Dek`, and in-crate only [`seal`] and [`unseal`] hold one.
pub struct Dek(Zeroizing<[u8; KEY_LEN]>);

impl std::fmt::Debug for Dek {
    /// Redacted: a key that reaches a log line is a key that reaches a backup.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek(<redacted>)")
    }
}

impl PartialEq for Dek {
    /// Constant time, so comparing keys cannot become a way to learn one byte at a time.
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl Eq for Dek {}

impl Dek {
    /// Mints a fresh key for a new record.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        fill_random(bytes.as_mut());
        Self(bytes)
    }

    /// Derives the key from every share, bound to the record and its subject set.
    ///
    /// HKDF over the XOR of the shares, never the XOR itself: an any-one-suffices misbuild hands
    /// this function one share where it needs all of them, and gets an unrelated key rather than a
    /// working one.
    ///
    /// Takes [`BareShare`]s only: a [`SealedBody`]'s shares are still wrapped, and the type system
    /// refuses them rather than deriving an unrelated key from them.
    pub fn derive(record: &RecordId, shares: &[BareShare]) -> crate::Result<Self> {
        let owned: Vec<SubjectHash> = shares.iter().map(|s| s.subject.clone()).collect();
        let subjects = canonical_subjects(&owned)?;

        let mut combined = Zeroizing::new([0u8; KEY_LEN]);
        for share in shares {
            for (acc, byte) in combined.iter_mut().zip(share.bytes.iter()) {
                *acc ^= byte;
            }
        }

        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), combined.as_ref());
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        hk.expand(&dek_info(record, &subjects), key.as_mut())
            .map_err(|_| Error::MalformedBlock("hkdf expand rejected the output length".into()))?;
        Ok(Self(key))
    }

    /// Splits into one share per subject.
    ///
    /// n-of-n: the shares XOR to this key, so n-1 of them carry no information about it.
    pub fn split(&self, subjects: &[SubjectHash]) -> crate::Result<Vec<BareShare>> {
        let subjects = canonical_subjects(subjects)?;
        let (last_subject, leading) = subjects.split_last().ok_or(Error::ShareCount {
            expected: 1,
            got: 0,
        })?;

        let mut shares = Vec::with_capacity(subjects.len());
        // The running remainder is the key itself until the last share carries what is left of it.
        let mut remainder = Zeroizing::new(*self.0);
        for subject in leading {
            let mut share = Zeroizing::new([0u8; KEY_LEN]);
            fill_random(share.as_mut());
            for (rem, byte) in remainder.iter_mut().zip(share.iter()) {
                *rem ^= byte;
            }
            shares.push(BareShare {
                subject: subject.clone(),
                bytes: share,
            });
        }
        shares.push(BareShare {
            subject: last_subject.clone(),
            bytes: remainder,
        });
        Ok(shares)
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
    pub shares: Vec<WrappedShare>,
    /// Ciphertext with its authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Seals a body, wrapping each share under the subject's key for `epoch`.
///
/// The store is a parameter rather than something ambient. It has to be: the callers are async, and
/// a store installed in a thread-local by a synchronous closure is invisible after an `.await`
/// moves the task to another worker — so the dependency would vanish exactly where it is needed.
/// An invisible dependency in a sealing API is also a misuse waiting to happen.
///
/// Minting is lazy and goes through the store, so a tombstoned subject fails the whole sealing
/// rather than quietly getting a fresh key.
pub fn seal(
    store: &dyn KeyStore,
    record: &RecordId,
    subjects: &[SubjectHash],
    epoch: &Epoch,
    plaintext: &[u8],
) -> crate::Result<SealedBody> {
    let subjects = canonical_subjects(subjects)?;
    let bare = Dek::generate().split(&subjects)?;
    let dek = Dek::derive(record, &bare)?;

    let nonce = Nonce::generate();
    let aad = associated_data(record, &subjects);
    let ciphertext = encrypt(&dek, &nonce, &aad, plaintext)?;

    let mut shares = Vec::with_capacity(bare.len());
    for share in &bare {
        let kek = Zeroizing::new(store.mint(&share.subject, epoch)?);
        shares.push(WrappedShare {
            subject: share.subject.clone(),
            bytes: wrap_share(&kek, share.bytes.as_ref())?,
        });
    }

    Ok(SealedBody {
        nonce,
        epoch: epoch.clone(),
        shares,
        ciphertext,
    })
}

/// Unseals a body, unwrapping every share from the store.
///
/// Associated data is recomputed from the record's own identity and subject set — never read from
/// the stored block, since a stored copy travels with a swapped body and would authenticate it.
///
/// A destroyed subject key surfaces as [`Error::KeyAbsent`], which is the erasure working. The
/// epoch needs no place in the associated data: it selects the wrapping key, so a block whose epoch
/// was edited fails the wrap's own integrity check.
pub fn unseal(
    store: &dyn KeyStore,
    record: &RecordId,
    body: &SealedBody,
) -> crate::Result<Vec<u8>> {
    let mut bare = Vec::with_capacity(body.shares.len());
    for share in &body.shares {
        let kek = store.get(&share.subject, &body.epoch)?.ok_or_else(|| {
            Error::KeyAbsent(
                share.subject.as_str().to_owned(),
                body.epoch.as_str().to_owned(),
            )
        })?;
        let unwrapped = unwrap_share(&Zeroizing::new(kek), &share.bytes)?;
        // A share that unwraps cleanly but is not a key's worth of bytes came from a block this
        // build did not write. Refused, rather than XORed in at whatever length it happens to be.
        let bytes: [u8; KEY_LEN] = unwrapped.as_slice().try_into().map_err(|_| {
            Error::MalformedBlock(format!(
                "share for `{}` unwrapped to {} bytes, expected {KEY_LEN}",
                share.subject.as_str(),
                unwrapped.len()
            ))
        })?;
        bare.push(BareShare {
            subject: share.subject.clone(),
            bytes: Zeroizing::new(bytes),
        });
    }

    let owned: Vec<SubjectHash> = bare.iter().map(|s| s.subject.clone()).collect();
    let subjects = canonical_subjects(&owned)?;
    let dek = Dek::derive(record, &bare)?;
    let aad = associated_data(record, &subjects);
    decrypt(&dek, &body.nonce, &aad, &body.ciphertext)
}

/// Sorts and validates a subject set.
///
/// Sorting makes the derivation order-independent; rejecting duplicates stops a repeated subject
/// from cancelling itself out of the XOR and shrinking the key space.
fn canonical_subjects(subjects: &[SubjectHash]) -> crate::Result<Vec<SubjectHash>> {
    if subjects.is_empty() {
        return Err(Error::ShareCount {
            expected: 1,
            got: 0,
        });
    }
    let mut sorted = subjects.to_vec();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let unique = 1 + sorted
        .windows(2)
        .filter(|w| w[0].as_str() != w[1].as_str())
        .count();
    if unique != sorted.len() {
        return Err(Error::ShareCount {
            expected: unique,
            got: sorted.len(),
        });
    }
    Ok(sorted)
}

/// Digest of the sorted subject set, used to bind both the key and the ciphertext to it.
fn subject_digest(subjects: &[SubjectHash]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for subject in subjects {
        hasher.update(subject.as_str().as_bytes());
        hasher.update(b"\n");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// HKDF `info`: binds the derived key to this record and this exact subject set.
fn dek_info(record: &RecordId, subjects: &[SubjectHash]) -> Vec<u8> {
    let mut info = b"yaam/dek/v1".to_vec();
    info.push(0);
    info.extend_from_slice(record.as_str().as_bytes());
    info.push(0);
    info.extend_from_slice(&subject_digest(subjects));
    info
}

/// Associated data: record id, format version, digest of the sorted subject set.
///
/// Recomputed at both ends and never stored. Without it, two records sharing a subject could have
/// their bodies swapped and both would decrypt cleanly; with a *stored* copy the swap would carry
/// its own authentication and the check would pass anyway.
fn associated_data(record: &RecordId, subjects: &[SubjectHash]) -> Vec<u8> {
    let mut aad = record.as_str().as_bytes().to_vec();
    aad.push(0);
    aad.extend_from_slice(FORMAT_VERSION.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&subject_digest(subjects));
    aad
}

/// AES-256-GCM over the plaintext, authenticating `aad`.
fn encrypt(dek: &Dek, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(dek.0.as_ref())
        .map_err(|_| Error::MalformedBlock("data key is not 32 bytes".into()))?;
    cipher
        .encrypt(
            &Array::from(*nonce.as_bytes()),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Authentication)
}

/// The inverse of [`encrypt`]. Any mismatch — key, nonce, ciphertext or `aad` — lands here.
fn decrypt(dek: &Dek, nonce: &Nonce, aad: &[u8], ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(dek.0.as_ref())
        .map_err(|_| Error::MalformedBlock("data key is not 32 bytes".into()))?;
    cipher
        .decrypt(
            &Array::from(*nonce.as_bytes()),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Authentication)
}

/// AES-KW wrap of one share under a subject key.
///
/// Deterministic and nonce-free by construction, which matters because the same share is wrapped
/// once and never rewrapped — a nonce here would be one more thing to keep unique.
fn wrap_share(kek: &[u8], share: &[u8]) -> crate::Result<Vec<u8>> {
    let kw = KwAes256::new_from_slice(kek)
        .map_err(|_| Error::MalformedBlock("subject key is not 32 bytes".into()))?;
    let mut out = vec![0u8; share.len() + IV_LEN];
    kw.wrap_key(share, &mut out)
        .map_err(|_| Error::MalformedBlock(format!("cannot wrap a {}-byte share", share.len())))?;
    Ok(out)
}

/// The inverse of [`wrap_share`]. A failed integrity check reads as authentication failure.
fn unwrap_share(kek: &[u8], wrapped: &[u8]) -> crate::Result<Vec<u8>> {
    let kw = KwAes256::new_from_slice(kek)
        .map_err(|_| Error::MalformedBlock("subject key is not 32 bytes".into()))?;
    if wrapped.len() < 2 * IV_LEN {
        return Err(Error::MalformedBlock(format!(
            "wrapped share is {} bytes",
            wrapped.len()
        )));
    }
    let mut out = vec![0u8; wrapped.len() - IV_LEN];
    kw.unwrap_key(wrapped, &mut out)
        .map_err(|_| Error::Authentication)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::keystore::FsKeyStore;

    const BODY: &[u8] = b"the record body, which is the part that must become unreadable";

    /// A distinct, well-formed subject hash per index.
    fn subject(n: u8) -> SubjectHash {
        SubjectHash::parse(&format!("s_{:064x}", u32::from(n) + 1)).unwrap()
    }

    fn store() -> (TempDir, FsKeyStore) {
        let dir = TempDir::new().unwrap();
        let store = FsKeyStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn epoch() -> Epoch {
        Epoch::containing(1_770_000_000_000)
    }

    /// A bare share of no value, for the paths that only care about the subject association.
    fn bare_share(subject: SubjectHash) -> BareShare {
        BareShare {
            subject,
            bytes: Zeroizing::new([0u8; KEY_LEN]),
        }
    }

    #[test]
    fn round_trip_with_one_subject() {
        let (_dir, store) = store();
        let record = RecordId::generate();
        let subjects = [subject(0)];

        let body = seal(&store, &record, &subjects, &epoch(), BODY).unwrap();
        assert_eq!(body.shares.len(), 1);
        assert_ne!(body.ciphertext, BODY);
        assert_eq!(unseal(&store, &record, &body).unwrap(), BODY);
    }

    #[test]
    fn round_trip_with_three_subjects() {
        let (_dir, store) = store();
        let record = RecordId::generate();
        let subjects = [subject(2), subject(0), subject(1)];

        let body = seal(&store, &record, &subjects, &epoch(), BODY).unwrap();
        assert_eq!(body.shares.len(), 3);
        assert_eq!(unseal(&store, &record, &body).unwrap(), BODY);
    }

    #[test]
    fn share_order_does_not_change_the_key() {
        let (_dir, store) = store();
        let record = RecordId::generate();
        let subjects = [subject(0), subject(1), subject(2)];

        let mut body = seal(&store, &record, &subjects, &epoch(), BODY).unwrap();
        body.shares.reverse();
        assert_eq!(unseal(&store, &record, &body).unwrap(), BODY);
    }

    #[test]
    fn unsealing_needs_every_share() {
        let (_dir, store) = store();
        let record = RecordId::generate();
        let subjects = [subject(0), subject(1), subject(2)];
        let body = seal(&store, &record, &subjects, &epoch(), BODY).unwrap();

        for drop_index in 0..body.shares.len() {
            let mut short = body.clone();
            short.shares.remove(drop_index);
            assert!(
                matches!(unseal(&store, &record, &short), Err(Error::Authentication)),
                "n-1 shares unsealed the body"
            );
        }
    }

    #[test]
    fn envelope_misbuild_cannot_decrypt() {
        // The misbuild: wrap the whole key per subject, so any one of them would suffice. On the
        // wire this is indistinguishable from a single wrapped share, which is why it must fail
        // outright rather than work for one subject and silently under-protect the rest.
        for count in 1..4u8 {
            let (_dir, store) = store();
            let record = RecordId::generate();
            let subjects: Vec<SubjectHash> = (0..count).map(subject).collect();
            let epoch = epoch();

            let key = Dek::generate();
            let nonce = Nonce::generate();
            let aad = associated_data(&record, &canonical_subjects(&subjects).unwrap());
            let ciphertext = encrypt(&key, &nonce, &aad, BODY).unwrap();
            let shares = subjects
                .iter()
                .map(|s| WrappedShare {
                    subject: s.clone(),
                    bytes: wrap_share(&store.mint(s, &epoch).unwrap(), key.0.as_ref()).unwrap(),
                })
                .collect();

            let body = SealedBody {
                nonce,
                epoch,
                shares,
                ciphertext,
            };
            assert!(
                matches!(unseal(&store, &record, &body), Err(Error::Authentication)),
                "an any-one-suffices block decrypted with {count} subject(s)"
            );
        }
    }

    #[test]
    fn a_bare_share_is_not_the_data_key() {
        // The reader-side half of the same mistake: unwrap the share, use it as the key.
        let (_dir, store) = store();
        let record = RecordId::generate();
        let subjects = [subject(0)];
        let epoch = epoch();
        let body = seal(&store, &record, &subjects, &epoch, BODY).unwrap();

        let kek = store.get(&subjects[0], &epoch).unwrap().unwrap();
        let bare = unwrap_share(&kek, &body.shares[0].bytes).unwrap();
        let misread = Dek(Zeroizing::new(bare.try_into().unwrap()));
        let aad = associated_data(&record, &subjects);
        assert!(decrypt(&misread, &body.nonce, &aad, &body.ciphertext).is_err());
    }

    #[test]
    fn derived_key_is_not_the_raw_xor() {
        let record = RecordId::generate();
        let root = Dek::generate();
        let shares = root.split(&[subject(0)]).unwrap();
        // One subject means one share equal to the root, so raw-XOR reconstruction would hand back
        // the root itself.
        assert_eq!(shares[0].bytes.as_slice(), root.0.as_slice());
        assert_ne!(Dek::derive(&record, &shares).unwrap(), root);
    }

    #[test]
    fn derivation_is_bound_to_the_record() {
        let shares = Dek::generate().split(&[subject(0), subject(1)]).unwrap();
        let one = Dek::derive(&RecordId::generate(), &shares).unwrap();
        let two = Dek::derive(&RecordId::generate(), &shares).unwrap();
        assert_ne!(one, two);
    }

    #[test]
    fn identical_plaintext_seals_differently() {
        let (_dir, store) = store();
        let record = RecordId::generate();
        let subjects = [subject(0)];

        let first = seal(&store, &record, &subjects, &epoch(), BODY).unwrap();
        let second = seal(&store, &record, &subjects, &epoch(), BODY).unwrap();

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
        // Same subject key, so a repeated nonce would be a two-time pad.
        assert_eq!(
            store.get(&subjects[0], &epoch()).unwrap(),
            store.get(&subjects[0], &epoch()).unwrap()
        );
    }

    #[test]
    fn swapped_bodies_fail_authentication() {
        let (_dir, store) = store();
        let subjects = [subject(0), subject(1)];
        let epoch = epoch();
        let left = RecordId::generate();
        let right = RecordId::generate();

        let mut left_body = seal(&store, &left, &subjects, &epoch, b"left").unwrap();
        let mut right_body = seal(&store, &right, &subjects, &epoch, b"right").unwrap();

        // Swap ciphertext and nonce, leaving each record's own shares in place: the substitution a
        // stored copy of the associated data would have authenticated.
        std::mem::swap(&mut left_body.ciphertext, &mut right_body.ciphertext);
        std::mem::swap(&mut left_body.nonce, &mut right_body.nonce);

        assert!(matches!(
            unseal(&store, &left, &left_body),
            Err(Error::Authentication)
        ));
        assert!(matches!(
            unseal(&store, &right, &right_body),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (_dir, store) = store();
        let record = RecordId::generate();
        let mut body = seal(&store, &record, &[subject(0)], &epoch(), BODY).unwrap();
        body.ciphertext[0] ^= 0x01;
        assert!(matches!(
            unseal(&store, &record, &body),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn tampered_share_fails_the_wrap_check() {
        let (_dir, store) = store();
        let record = RecordId::generate();
        let mut body = seal(&store, &record, &[subject(0)], &epoch(), BODY).unwrap();
        body.shares[0].bytes[0] ^= 0x01;
        assert!(matches!(
            unseal(&store, &record, &body),
            Err(Error::Authentication)
        ));
    }

    #[test]
    fn destroying_a_subject_makes_the_body_unreadable() {
        let (_dir, store) = store();
        let record = RecordId::generate();
        let subjects = [subject(0), subject(1)];
        let body = seal(&store, &record, &subjects, &epoch(), BODY).unwrap();
        assert_eq!(unseal(&store, &record, &body).unwrap(), BODY);

        store.destroy_subject(&subjects[1]).unwrap();

        assert!(matches!(
            unseal(&store, &record, &body),
            Err(Error::KeyAbsent(_, _))
        ));
    }

    #[test]
    fn destroying_an_epoch_leaves_other_epochs_readable() {
        let (_dir, store) = store();
        let subjects = [subject(0)];
        let old = Epoch::containing(1_700_000_000_000);
        let new = epoch();
        let kept = RecordId::generate();
        let doomed = RecordId::generate();

        let kept_body = seal(&store, &kept, &subjects, &new, BODY).unwrap();
        let doomed_body = seal(&store, &doomed, &subjects, &old, BODY).unwrap();

        store.destroy_epoch(&subjects[0], &old).unwrap();

        assert_eq!(unseal(&store, &kept, &kept_body).unwrap(), BODY);
        assert!(unseal(&store, &doomed, &doomed_body).is_err());
    }

    #[test]
    fn sealing_refuses_a_tombstoned_subject() {
        let (_dir, store) = store();
        let record = RecordId::generate();
        let subjects = [subject(0)];
        store.tombstone(&subjects[0]).unwrap();

        assert!(matches!(
            seal(&store, &record, &subjects, &epoch(), BODY),
            Err(Error::Tombstoned(_))
        ));
    }

    #[test]
    fn subject_sets_must_be_non_empty_and_distinct() {
        let record = RecordId::generate();
        assert!(matches!(
            canonical_subjects(&[]),
            Err(Error::ShareCount {
                expected: 1,
                got: 0
            })
        ));
        assert!(matches!(
            Dek::generate().split(&[]),
            Err(Error::ShareCount {
                expected: 1,
                got: 0
            })
        ));
        assert!(matches!(
            Dek::generate().split(&[subject(0), subject(0)]),
            Err(Error::ShareCount {
                expected: 1,
                got: 2
            })
        ));
        let repeated = [bare_share(subject(0)), bare_share(subject(0))];
        assert!(Dek::derive(&record, &repeated).is_err());
    }

    #[test]
    fn a_share_that_unwraps_to_the_wrong_length_is_refused() {
        // Reachable only from a block this build did not write: the wrap protects the length, so
        // the check is about a foreign block rather than a tampered one.
        let (_dir, store) = store();
        let record = RecordId::generate();
        let subjects = [subject(0)];
        let epoch = epoch();
        let mut body = seal(&store, &record, &subjects, &epoch, BODY).unwrap();

        let kek = store.get(&subjects[0], &epoch).unwrap().unwrap();
        body.shares[0].bytes = wrap_share(&kek, &[0u8; 2 * KEY_LEN]).unwrap();

        assert!(matches!(
            unseal(&store, &record, &body),
            Err(Error::MalformedBlock(_))
        ));
    }

    #[test]
    fn a_bare_share_redacts_its_bytes_but_names_its_subject() {
        let share = bare_share(subject(0));
        let rendered = format!("{share:?}");
        assert!(rendered.contains(subject(0).as_str()), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert_eq!(share.subject(), &subject(0));
    }

    #[test]
    fn wrapping_rejects_bad_lengths() {
        assert!(matches!(
            wrap_share(&[0; 8], &[0; KEY_LEN]),
            Err(Error::MalformedBlock(_))
        ));
        assert!(matches!(
            wrap_share(&[0; KEY_LEN], &[0; 7]),
            Err(Error::MalformedBlock(_))
        ));
        assert!(matches!(
            unwrap_share(&[0; 8], &[0; 40]),
            Err(Error::MalformedBlock(_))
        ));
        assert!(matches!(
            unwrap_share(&[0; KEY_LEN], &[0; 8]),
            Err(Error::MalformedBlock(_))
        ));
    }

    #[test]
    fn nonces_are_fresh_and_survive_storage() {
        let one = Nonce::generate();
        let two = Nonce::generate();
        assert_ne!(one, two);
        assert_eq!(Nonce::from_stored(*one.as_bytes()), one);
        assert_eq!(one.as_bytes().len(), 12);
    }

    #[test]
    fn epochs_are_calendar_quarters() {
        for (ms, label) in [
            (0_i64, "1970-Q1"),
            (1_704_067_199_999, "2023-Q4"),
            (1_704_067_200_000, "2024-Q1"),
            (1_711_929_600_000, "2024-Q2"),
            (1_719_792_000_000, "2024-Q3"),
            (1_727_740_800_000, "2024-Q4"),
            (-1, "1969-Q4"),
            (-86_400_000, "1969-Q4"),
            // The extremes of the calendar the label format can express.
            (-62_135_596_800_000, "0001-Q1"),
            (253_402_300_799_000, "9999-Q4"),
        ] {
            assert_eq!(Epoch::containing(ms).as_str(), label, "at {ms}");
        }
    }

    #[test]
    fn stored_epoch_labels_cannot_escape_the_key_store() {
        assert_eq!(Epoch::from_stored("2024-Q2").unwrap().as_str(), "2024-Q2");
        for bad in ["", "../2024-Q2", "a/b", "a\\b"] {
            assert!(matches!(
                Epoch::from_stored(bad),
                Err(Error::MalformedBlock(_))
            ));
        }
    }

    #[test]
    fn a_dek_never_prints_its_bytes() {
        let rendered = format!("{:?}", Dek::generate());
        assert_eq!(rendered, "Dek(<redacted>)");
    }

    #[test]
    fn a_body_is_readable_only_where_its_keys_are() {
        // The store is a parameter, so which keys a body needs is visible at the call site: the
        // same block handed a different store is unreadable, and says so.
        let record = RecordId::generate();
        let subjects = [subject(0)];
        let (_here_dir, here) = store();
        let (_elsewhere_dir, elsewhere) = store();

        let body = seal(&here, &record, &subjects, &epoch(), BODY).unwrap();
        assert_eq!(unseal(&here, &record, &body).unwrap(), BODY);
        assert!(matches!(
            unseal(&elsewhere, &record, &body),
            Err(Error::KeyAbsent(_, _))
        ));
    }

    #[test]
    fn any_key_store_will_do() {
        // Taken as `&dyn KeyStore`, so a deployment can hold keys in an HSM or a remote service
        // without this module knowing. The test doubles as proof the trait is object-safe.
        let (_dir, store) = store();
        let by_ref: &dyn crate::keystore::KeyStore = &store;
        let record = RecordId::generate();
        let body = seal(by_ref, &record, &[subject(0)], &epoch(), BODY).unwrap();
        assert_eq!(unseal(by_ref, &record, &body).unwrap(), BODY);
    }
}
