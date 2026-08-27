//! Naming an erasure unit: the keyed pseudonym a subject's keys are filed under.
//!
//! Everything else in this crate protects a body once its subjects are known. This is the step
//! before — turning an identifier into the opaque tag that [`crate::keystore`] files keys under and
//! that key destruction later addresses. It lives here rather than beside the write pipeline because
//! [`SubjectKey`] is a second master secret: it cannot be rotated once its outputs are in filenames
//! and in tombstones that are never deleted, and a leak de-pseudonymises every backup ever taken.
//! Types holding a secret of that standing belong with the ones holding the master key, where the
//! review that covers key custody covers them too.
//!
//! # What a pseudonym is a function of
//!
//! `HMAC-SHA256(key, DOMAIN ‖ canon_ver ‖ canonical_id)`, rendered as `s_` and 64 lowercase hex
//! digits. A pure function, which is the property it is chosen for: there is no mapping store to
//! restore short, so one subject cannot acquire two pseudonyms because a row went missing — the
//! failure that makes every later erasure miss half of a subject's records with nothing to signal
//! it. What it costs is that the whole accuracy burden lands on canonicalisation, in two failure
//! modes that are not the same severity:
//!
//! - **Two spellings of one subject under one version — unrecoverable.** Without case folding,
//!   `Ref-A` and `ref-a` are two subjects for ever. The hashes are unrelatable, nothing marks them
//!   as one, and an erasure reaches half the records. This is what [`Canon::Minimal`] exists to
//!   prevent.
//! - **Changing the rules later — expensive, not fatal.** The same identifier hashes differently
//!   across the bump, and hashes already in paths cannot be recomputed. They need not be: a lookup
//!   derives under every live version and unions the results. The cost is that fan-out, for ever.
//!
//! Which is why [`CanonVer`] travels with every hash, and why it is an *input* to the HMAC rather
//! than a label beside it: two rulesets that happened to agree on some identifier would otherwise
//! emit one tag for it, making a version bump a real migration for some subjects and a no-op for
//! others — so a fan-out would return one hash where its caller reasons about two.
//!
//! The fan-out itself is deliberately not here. `erase` takes one hash and the key-minting blocklist
//! is an exact-match check on one hash, so deriving every live version of a subject's pseudonym is
//! an operator's step outside the store — which is also true of resolving a person to the references
//! this store keys on. [`Canon::LIVE`] is what such a step enumerates.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use yaam_contract::{CanonVer, SubjectHash};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// Required length of the keying secret, in bytes — SHA-256's own output size.
///
/// Fixed rather than "at least": a fixed size is what lets the secret live in an array whose `Drop`
/// reliably clears it, where a `Vec` may have reallocated and left a copy behind.
pub const SUBJECT_KEY_LEN: usize = 32;

/// Prefix that marks a string as a pseudonym rather than a raw identifier.
const PREFIX: &str = "s_";

/// Lowercase hex alphabet. [`SubjectHash`] admits no other case.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Domain separator, so this key cannot be made to produce a tag that another use of the same key
/// would also produce. Fixed length, which is what makes the framing below unambiguous.
const DOMAIN: &[u8; 16] = b"subject-pseudo:1";

/// Domain separator for [`SubjectKey::check_value`], and the whole of its HMAC input.
///
/// Its own separator rather than [`DOMAIN`], and the same fixed 16 bytes wide, so a check value can
/// never be a tag some identifier would also produce: the two inputs differ inside the first
/// fixed-width field, whatever follows it. Versioned like the other, because a build that took the
/// check over something else would refuse every store this one armed — so this string changes only
/// alongside a way to re-record what armed stores already hold.
const CHECK_DOMAIN: &[u8; 16] = b"subject-keychk:1";

/// Length of a check value in bytes — SHA-256's own output size.
const CHECK_LEN: usize = 32;

/// A versioned ruleset for reducing an identifier to the form that gets hashed.
///
/// An enum rather than a trait, because the set of live versions is the thing callers need: an
/// erasure sweep and a blocklist check have to enumerate them, and a `match` is what makes adding
/// one a compile error at every place that enumerates rather than a silent omission at some of them.
/// It also means no out-of-tree ruleset can appear without a version, which is the state
/// [`CanonVer`] exists to rule out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Canon {
    /// Trim, NFC, lowercase, NFC again — and nothing else.
    Minimal,
}

impl Canon {
    /// Every ruleset that has ever been live, ascending by version.
    ///
    /// Superseded rulesets are never retired: a record filed under one keeps a hash only that
    /// ruleset can reproduce, so dropping it from here would make those records unreachable by an
    /// erasure and unrecognisable to the blocklist that stops a key being minted for an erased
    /// subject.
    pub const LIVE: [Self; 1] = [Self::Minimal];

    /// The ruleset new pseudonyms are derived under.
    ///
    /// The highest version, by the same rule that makes [`Canon::LIVE`] ascending. Named so a caller
    /// deriving a fresh pseudonym does not have to pick from the list and cannot pick a superseded
    /// one.
    pub const CURRENT: Self = Self::Minimal;

    /// The version this ruleset realises.
    ///
    /// Owned by the ruleset, never passed in by a caller: a caller able to supply one could stamp a
    /// record with a number that does not describe how its hash was produced, which is exactly the
    /// state the field exists to prevent.
    #[must_use]
    pub const fn version(self) -> CanonVer {
        match self {
            Self::Minimal => CanonVer(1),
        }
    }

    /// Reduces an identifier to its canonical form.
    ///
    /// Idempotent — canonicalising a canonical form returns it unchanged — because a re-derivation
    /// on a value already through this function would otherwise yield a second pseudonym for one
    /// subject.
    ///
    /// [`Canon::Minimal`] stops at the three differences that are pure spelling: surrounding
    /// whitespace, letter case, and which Unicode encoding of one character was typed. Every rule
    /// beyond those is a version, and every version is fan-out paid on every lookup for ever. What
    /// it deliberately leaves alone, so a later reader knows these were choices:
    ///
    /// - **Interior whitespace.** `"a b"` and `"a  b"` stay distinct.
    /// - **Compatibility normalisation.** A non-breaking space or a full-width digit inside the
    ///   value stays as typed; NFKC would fold those and also fold distinctions that matter in some
    ///   identifier spaces, which is not a trade to make before knowing the space.
    /// - **Case folding, as opposed to lowercasing.** They differ for a few characters — `ß`
    ///   lowercases to itself where folding maps it to `ss`. Lowercasing merges strictly fewer
    ///   identifiers, so moving to folding later merges subjects this version kept apart, which is a
    ///   migration rather than a repair.
    ///
    /// # Errors
    /// [`Error::SubjectIdEmpty`] if nothing survives the rules. An empty canonical form would give
    /// every such identifier one shared pseudonym, so every one of their bodies would be erasable by
    /// any one of their subjects' requests.
    pub fn canonicalise(self, raw: &str) -> Result<String> {
        let out = match self {
            // NFC runs twice because lowercasing maps per character and can emit a composed
            // sequence, so normalising last makes "the output is NFC" a property of this function
            // rather than an observation about today's Unicode tables. NFC is idempotent, so the
            // second pass changes nothing when the first already settled it.
            Self::Minimal => raw
                .trim()
                .nfc()
                .collect::<String>()
                .to_lowercase()
                .nfc()
                .collect::<String>(),
        };
        if out.is_empty() {
            return Err(Error::SubjectIdEmpty(self.version().0));
        }
        Ok(out)
    }
}

/// A derived pseudonym and the ruleset version that produced it.
///
/// The two travel together so the version cannot be dropped between derivation and the record: a
/// hash whose ruleset is unknown is the one unrecoverable state, because a lookup then has to guess
/// which function to invert rather than enumerate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pseudonym {
    /// The opaque tag.
    pub hash: SubjectHash,
    /// The ruleset that produced `hash`.
    pub canon_ver: CanonVer,
}

/// A non-secret value that says *which* subject key a set of pseudonyms was derived from.
///
/// `HMAC-SHA256` of one fixed label — [`CHECK_DOMAIN`] — under the subject key, and nothing else in
/// the input, so the value is a function of the key alone. That is the property it is for. A store records the check value of the key
/// it was armed with, and a later process can then tell that key from a substitute — which nothing
/// else here can do, because the key's only other observable is a pseudonym, and a pseudonym is only
/// comparable to somebody who has the identifier it was taken over.
///
/// Publishable, unlike everything else this key touches, and deliberately so: it is written into the
/// tree, travels in a backup, and is printed in a startup log so an operator can compare it against
/// what a store holds. What that costs is worth saying rather than glossing — anyone holding a check
/// value can test candidate keys against it offline. Against 32 bytes from a CSPRNG that is not a
/// test at all, and a subject key guessable in an offline search has a worse problem than this value
/// being readable.
///
/// Comparison is ordinary equality. There is no secret on either side of it: the recorded value is
/// in the tree and the derived one is a one-way function of a key nothing here reveals, so there is
/// nothing for a timing side channel to leak.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyCheck([u8; CHECK_LEN]);

impl KeyCheck {
    /// Reads a check value back from its hex form.
    ///
    /// # Errors
    /// [`Error::SubjectKeyCheckMalformed`] on anything that is not [`CHECK_LEN`] bytes of hex. A
    /// value that cannot be read is deliberately not treated as a value that does not match: one
    /// says the key is wrong, the other says nothing at all, and the caller acts differently on
    /// each.
    pub fn parse(text: &str) -> Result<Self> {
        let bytes = hex::decode(text).map_err(|_| Error::SubjectKeyCheckMalformed)?;
        let bytes: [u8; CHECK_LEN] = bytes
            .try_into()
            .map_err(|_| Error::SubjectKeyCheckMalformed)?;
        Ok(Self(bytes))
    }
}

impl core::fmt::Display for KeyCheck {
    /// Lowercase hex, untruncated: one spelling per value, so a recorded one and a derived one
    /// compare as text wherever they meet.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for KeyCheck {
    /// Shows the value, unlike [`SubjectKey`]'s own `Debug`. A check value in a log line is the
    /// point of having one.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyCheck({self})")
    }
}

/// The keying secret that turns a canonical identifier into a pseudonym.
///
/// Held as hard to print as it is easy to use, because a leak is retroactive across every copy of
/// the store that has ever existed:
///
/// - [`Debug`] is hand-written and redacts. A derived one on any struct holding this would dump the
///   secret into the first log line that formatted it.
/// - There is no `Display`, no accessor for the bytes, and no [`Clone`]. Bytes go in; tags come out.
/// - The bytes are cleared on drop.
///
/// Where they come from is [`crate::custody`]: a process fetches one of these at startup through
/// [`crate::custody::SubjectKeySource`] and hands it to the resolver that derives with it. The
/// constructors here take bytes and hex because that is what a source has to hand over.
#[derive(ZeroizeOnDrop)]
pub struct SubjectKey {
    /// Raw HMAC key material.
    key: [u8; SUBJECT_KEY_LEN],
}

impl SubjectKey {
    /// Takes the secret from raw bytes.
    ///
    /// # Errors
    /// [`Error::SubjectKeyLength`] unless exactly [`SUBJECT_KEY_LEN`] bytes are supplied. Padding a
    /// short secret to length would hide that a deployment is running on less entropy than it thinks
    /// it configured.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key: [u8; SUBJECT_KEY_LEN] = bytes.try_into().map_err(|_| Error::SubjectKeyLength {
            expected: SUBJECT_KEY_LEN,
            got: bytes.len(),
        })?;
        Ok(Self { key })
    }

    /// Takes the secret from hex, which is how a key store or a secret manager hands one over.
    ///
    /// # Errors
    /// [`Error::SubjectKeyNotHex`] on a non-hex digit or an odd length, [`Error::SubjectKeyLength`]
    /// on the wrong number of bytes.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let mut bytes = hex::decode(hex).map_err(|_| Error::SubjectKeyNotHex)?;
        let out = Self::from_bytes(&bytes);
        // The decode buffer held the secret too, and it outlives the borrow above.
        bytes.zeroize();
        out
    }

    /// The value that says which key this is, without saying what it is.
    ///
    /// Derived rather than stored, and cheap, so the caller that checks a store's record against it
    /// need hold nothing between fetching the key and asking. See [`KeyCheck`] for why a value
    /// derived from an unrotatable secret is nevertheless one to publish.
    #[must_use]
    pub fn check_value(&self) -> KeyCheck {
        let mut mac = self.mac();
        mac.update(CHECK_DOMAIN);
        let mut value = [0u8; CHECK_LEN];
        value.copy_from_slice(&mac.finalize().into_bytes());
        KeyCheck(value)
    }

    /// Canonicalises under `canon`, then derives the pseudonym.
    ///
    /// The version is read off the ruleset that actually ran and travels with the tag, so a hash
    /// cannot be recorded under a version that did not produce it.
    ///
    /// # Errors
    /// Whatever `canon` refuses.
    pub fn derive(&self, canon: Canon, raw: &str) -> Result<Pseudonym> {
        let canonical = canon.canonicalise(raw)?;
        Ok(self.tag(canon.version(), &canonical))
    }

    /// A fresh HMAC keyed with the secret.
    ///
    /// The one place the key reaches the construction, so the two values taken under it — a
    /// pseudonym and a check value — cannot come to disagree about how it is keyed. Private, which
    /// is also what keeps the length invariant an `expect` here rather than a panic a caller has to
    /// be warned about: 32 bytes is checked at construction and HMAC accepts any length anyway.
    fn mac(&self) -> Hmac<Sha256> {
        <Hmac<Sha256>>::new_from_slice(&self.key).expect("HMAC-SHA256 accepts a key of any length")
    }

    /// HMAC-SHA256 over the domain, the version and the canonical identifier.
    ///
    /// Framed by fixed width rather than by a separator: the first 16 bytes are the domain, the next
    /// 4 are the version big-endian, the rest is the identifier. A separator byte would have to be
    /// one no identifier can contain, and nothing about the identifier space is settled.
    fn tag(&self, ver: CanonVer, canonical: &str) -> Pseudonym {
        let mut mac = self.mac();
        mac.update(DOMAIN);
        mac.update(&ver.0.to_be_bytes());
        mac.update(canonical.as_bytes());

        let mut hash = String::with_capacity(PREFIX.len() + 64);
        hash.push_str(PREFIX);
        for byte in mac.finalize().into_bytes() {
            // Lowercase hex, untruncated: one spelling per hash is what lets a pseudonym serve as a
            // map key and a path component with no normalisation step a caller could forget.
            hash.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            hash.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        Pseudonym {
            hash: SubjectHash::parse(&hash).expect("32 bytes of lowercase hex behind an `s_`"),
            canon_ver: ver,
        }
    }
}

impl core::fmt::Debug for SubjectKey {
    /// Redacts. The length is safe to print and is what an operator is actually debugging.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SubjectKey({SUBJECT_KEY_LEN} bytes, redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key with no structure to it. Any 32 bytes derive; these are not special.
    fn key() -> SubjectKey {
        SubjectKey::from_bytes(&[0x5a; SUBJECT_KEY_LEN]).expect("32 bytes")
    }

    #[test]
    fn a_pseudonym_is_the_shape_the_contract_admits() {
        let derived = key()
            .derive(Canon::CURRENT, "order_ref:abcd1234")
            .expect("derived");
        assert!(derived.hash.as_str().starts_with("s_"));
        assert_eq!(derived.hash.as_str().len(), 66);
        assert_eq!(derived.canon_ver, CanonVer(1));
    }

    /// The failure that has no repair: two spellings of one reference, two subjects, for ever.
    #[test]
    fn spelling_differences_are_not_different_subjects() {
        let key = key();
        let plain = key
            .derive(Canon::Minimal, "order_ref:abcd1234")
            .expect("derived");
        for spelling in [
            "  order_ref:abcd1234  ",
            "ORDER_REF:ABCD1234",
            "Order_Ref:AbCd1234",
        ] {
            let other = key.derive(Canon::Minimal, spelling).expect("derived");
            assert_eq!(
                plain, other,
                "{spelling} must be one subject with the canonical form"
            );
        }
    }

    /// Two encodings of one character are one identifier, which is the whole reason NFC is here.
    #[test]
    fn unicode_forms_of_one_character_are_one_subject() {
        let key = key();
        let composed = key
            .derive(Canon::Minimal, "order_ref:caf\u{e9}")
            .expect("derived");
        let decomposed = key
            .derive(Canon::Minimal, "order_ref:cafe\u{301}")
            .expect("derived");
        assert_eq!(composed, decomposed);
    }

    #[test]
    fn canonicalising_a_canonical_form_returns_it() {
        let once = Canon::Minimal
            .canonicalise("  Order_Ref:ABCD  ")
            .expect("canonical");
        let twice = Canon::Minimal.canonicalise(&once).expect("canonical");
        assert_eq!(
            once, twice,
            "a re-derivation must not produce a second pseudonym"
        );
    }

    #[test]
    fn distinct_identifiers_derive_distinct_pseudonyms() {
        let key = key();
        let one = key
            .derive(Canon::Minimal, "order_ref:abcd1234")
            .expect("derived");
        let two = key
            .derive(Canon::Minimal, "order_ref:abcd1235")
            .expect("derived");
        assert_ne!(one, two);
    }

    /// The property the domain separator buys: the same key used for anything else cannot be made to
    /// produce a tag this function would also produce.
    #[test]
    fn two_keys_disagree_about_one_identifier() {
        let other = SubjectKey::from_bytes(&[0x5b; SUBJECT_KEY_LEN]).expect("32 bytes");
        assert_ne!(
            key()
                .derive(Canon::Minimal, "order_ref:abcd1234")
                .expect("derived"),
            other
                .derive(Canon::Minimal, "order_ref:abcd1234")
                .expect("derived")
        );
    }

    /// Known answers, so a change to the framing, the domain separator or the ruleset fails here
    /// rather than in a deployment whose existing pseudonyms have quietly stopped being reproducible
    /// — which is unrecoverable: the records are filed under hashes the new rules cannot make again.
    ///
    /// The second vector uses a non-uniform key, so a byte-order slip in the framing shows up as a
    /// changed tag, and it is the vector an independent implementation of this scheme holds too. Any
    /// tool that derives the same pseudonym off the write path — an erasure-time fan-out over a list
    /// of references, a migration script — is checked against these, so the two cannot drift apart
    /// unnoticed and leave an erasure asking for a hash no record carries.
    #[test]
    fn the_derivation_is_the_one_that_wrote_the_records_already_in_a_store() {
        let key = SubjectKey::from_hex(&"5a".repeat(SUBJECT_KEY_LEN)).expect("hex key");
        assert_eq!(
            key.derive(Canon::Minimal, "order_ref:abcd1234")
                .expect("derived")
                .hash
                .as_str(),
            "s_fea92042d09db802208eceb305b1dc4238b77f2be0e41f1d16ed489b0eecb902"
        );

        let stepped = SubjectKey::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .expect("hex key");
        assert_eq!(
            stepped
                .derive(Canon::Minimal, " Subject-A ")
                .expect("derived")
                .hash
                .as_str(),
            "s_a3d76dc902b38605bdde755c1b13e0a8215a82a003e74d3d815b98376b09ead0"
        );
    }

    /// Known answers for the check value, held to the same standard as the pseudonym vectors above
    /// and for the same reason: a store records one of these and refuses a key that does not
    /// reproduce it, so a build that computed them differently would refuse every store armed by
    /// this one — with the operator's obvious remedy being to delete the record that was protecting
    /// them.
    #[test]
    fn the_check_value_is_the_one_an_armed_store_already_recorded() {
        let key = SubjectKey::from_hex(&"5a".repeat(SUBJECT_KEY_LEN)).expect("hex key");
        assert_eq!(
            key.check_value().to_string(),
            "927ac81cde7a2d453ee3bb93e10cc4722245b8d3d91095be54b8953257794010"
        );

        let stepped = SubjectKey::from_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .expect("hex key");
        assert_eq!(
            stepped.check_value().to_string(),
            "62005efe8e233ca87b258c310eff06b6364dd8a933c9e062b774eea178b5bc51"
        );
    }

    /// The property the whole mechanism rests on: a key that is not this store's own does not
    /// reproduce this store's check value.
    #[test]
    fn two_keys_disagree_about_their_check_value() {
        let other = SubjectKey::from_bytes(&[0x5b; SUBJECT_KEY_LEN]).expect("32 bytes");
        assert_ne!(key().check_value(), other.check_value());
        assert_eq!(
            key().check_value(),
            key().check_value(),
            "one key has one check value, however often it is asked"
        );
    }

    /// A check value and a pseudonym are taken under separate domains, so neither can be mistaken
    /// for the other: a value recorded in the tree can never be a subject's tag, and no tag a
    /// caller can steer the store into deriving is the value that would pass the check.
    #[test]
    fn a_check_value_is_not_a_pseudonym_of_anything() {
        let key = key();
        let check = key.check_value().to_string();
        for identifier in ["", " ", "subject-keychk:1", "order_ref:abcd1234"] {
            if let Ok(derived) = key.derive(Canon::CURRENT, identifier) {
                assert_ne!(derived.hash.as_str(), format!("s_{check}"), "{identifier}");
            }
        }
    }

    /// Unlike the key, a check value is meant to be read: it reaches a startup log and a file in the
    /// tree, and an operator compares it by eye.
    #[test]
    fn a_check_value_reads_back_from_its_own_text() {
        let check = key().check_value();
        let text = check.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(KeyCheck::parse(&text).expect("parsed"), check);
        assert_eq!(format!("{check:?}"), format!("KeyCheck({text})"));
    }

    #[test]
    fn a_recorded_value_that_is_not_a_check_value_is_refused_rather_than_guessed() {
        for text in ["", "not hex", "5a5a", &"5a".repeat(33)] {
            assert!(
                matches!(KeyCheck::parse(text), Err(Error::SubjectKeyCheckMalformed)),
                "{text:?}"
            );
        }
    }

    #[test]
    fn an_identifier_that_canonicalises_to_nothing_is_refused() {
        let err = key()
            .derive(Canon::Minimal, "   ")
            .expect_err("nothing survives");
        assert!(matches!(err, Error::SubjectIdEmpty(1)), "{err}");
    }

    #[test]
    fn a_secret_of_the_wrong_length_is_refused_rather_than_padded() {
        assert!(matches!(
            SubjectKey::from_bytes(&[0u8; 16]),
            Err(Error::SubjectKeyLength {
                expected: 32,
                got: 16
            })
        ));
        assert!(matches!(
            SubjectKey::from_hex("5a5a"),
            Err(Error::SubjectKeyLength { .. })
        ));
        assert!(matches!(
            SubjectKey::from_hex("not hex"),
            Err(Error::SubjectKeyNotHex)
        ));
    }

    #[test]
    fn the_secret_is_not_printable() {
        let printed = format!("{:?}", key());
        assert_eq!(printed, "SubjectKey(32 bytes, redacted)");
        assert!(
            !printed.contains("5a"),
            "the bytes must not reach a log line"
        );
    }

    /// Every live ruleset is enumerable, because an erasure-time fan-out has to enumerate them.
    #[test]
    fn every_live_ruleset_has_a_distinct_version_and_the_current_one_is_among_them() {
        let mut versions: Vec<_> = Canon::LIVE.iter().map(|c| c.version().0).collect();
        let count = versions.len();
        versions.sort_unstable();
        versions.dedup();
        assert_eq!(
            versions.len(),
            count,
            "two rulesets claiming one version cannot be told apart"
        );
        assert!(Canon::LIVE.contains(&Canon::CURRENT));
    }
}
