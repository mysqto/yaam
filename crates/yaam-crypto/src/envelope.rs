//! Sealing a record to the service's public key.
//!
//! One direction only, and that is the point: a sidecar holds the public half, so it can seal an
//! entry it will never be able to read back — on its spool or on the wire. A symmetric key would
//! mean that anything with read access to the sidecar's host — a backup, a core dump, an operator
//! — could recover every record that ever passed through it.
//!
//! Both halves of the scheme live here rather than in the sidecar, because the service is the side
//! that opens what the sidecar sealed. A second implementation of the layout below, one per side,
//! is how the two stop agreeing.
//!
//! The construction is ephemeral-static X25519, HKDF-SHA256, AES-256-GCM: a fresh key pair per
//! entry whose private half is dropped as soon as the shared secret is derived, so even the process
//! that sealed the entry cannot re-derive the key a moment later.
//!
//! Wire layout, one entry:
//!
//! ```text
//! byte  0        format version (1)
//! bytes 1..33    ephemeral X25519 public key
//! bytes 33..45   AES-GCM nonce
//! bytes 45..     ciphertext with its authentication tag
//! ```
//!
//! Nothing in the header is used as associated data. It does not need to be: the ephemeral public
//! key is bound into the key derivation, so editing it derives a different key rather than
//! authenticating an edited header, and the nonce is covered by GCM itself.

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload, array::Array},
};
use hkdf::Hkdf;
use rand::CryptoRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::Error as CryptoError;

/// Length of an X25519 key, public or secret.
pub const KEY_LEN: usize = 32;

/// Media type a sealed envelope is posted under.
///
/// A distinct type rather than a sniffed body: the service has to know whether to open the bytes or
/// parse them, and guessing from the first byte is a decision that can be wrong.
pub const CONTENT_TYPE: &str = "application/vnd.yaam.envelope";

/// Current envelope format version.
const FORMAT_VERSION: u8 = 1;

/// Length of the AES-GCM nonce.
const NONCE_LEN: usize = 12;

/// Offset of the nonce within an envelope.
const NONCE_AT: usize = 1 + KEY_LEN;

/// Offset of the ciphertext within an envelope.
const CIPHERTEXT_AT: usize = NONCE_AT + NONCE_LEN;

/// Domain separation for the HKDF extract step, so a shared secret cannot be re-used as another
/// derivation's input material without changing the output.
const HKDF_SALT: &[u8] = b"yaam/spool/v1/salt";

/// Associated data: a constant label that ties a ciphertext to this format and no other.
const AAD: &[u8] = b"yaam/spool/v1";

/// Draws from the operating system CSPRNG.
///
/// The `CryptoRng` bound is the point: a reproducible generator here would make every ephemeral key
/// predictable, and it is a compile error to pass one.
fn fill_random(dst: &mut [u8]) {
    fn draw<R: CryptoRng>(rng: &mut R, dst: &mut [u8]) {
        rng.fill_bytes(dst);
    }
    draw(&mut rand::rng(), dst);
}

/// Mints a service key pair, returning `(secret, public)`.
///
/// The sidecar is configured with the public half alone. The secret half belongs to the service and
/// exists here only so that tests, and the service itself, can open what a sidecar sealed.
#[must_use]
pub fn generate_keypair() -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut seed = Zeroizing::new([0u8; KEY_LEN]);
    fill_random(seed.as_mut());
    let secret = StaticSecret::from(*seed);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

/// The public half of a service secret key.
///
/// A service holds the secret and has to publish the public half for sidecars to seal to; deriving
/// it here means the two halves cannot be configured out of step.
pub fn public_key(service_secret_key: &[u8]) -> crate::Result<[u8; KEY_LEN]> {
    let secret = StaticSecret::from(key_bytes(service_secret_key, "service secret key")?);
    Ok(PublicKey::from(&secret).to_bytes())
}

/// Seals `plaintext` to the service's public key.
///
/// Fails only on a malformed key: the sidecar has no other way to get this wrong, and a wrong-length
/// key must not be padded into something that appears to work.
pub fn seal(service_public_key: &[u8], plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let recipient = PublicKey::from(key_bytes(service_public_key, "service public key")?);

    let mut seed = Zeroizing::new([0u8; KEY_LEN]);
    fill_random(seed.as_mut());
    let ephemeral = StaticSecret::from(*seed);
    let ephemeral_public = PublicKey::from(&ephemeral);

    let key = derive(
        &ephemeral.diffie_hellman(&recipient).to_bytes(),
        &ephemeral_public.to_bytes(),
        &recipient.to_bytes(),
    );

    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce);

    let ciphertext = cipher(&key)
        .encrypt(
            &Array::from(nonce),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| CryptoError::Authentication)?;

    let mut out = Vec::with_capacity(CIPHERTEXT_AT + ciphertext.len());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&ephemeral_public.to_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens an envelope with the service's secret key.
///
/// Present for the service side and for tests. It needs the secret half, which is exactly what a
/// sidecar never holds — so this is not a way for a sidecar to read its own spool.
pub fn open(service_secret_key: &[u8], sealed: &[u8]) -> crate::Result<Vec<u8>> {
    let secret = StaticSecret::from(key_bytes(service_secret_key, "service secret key")?);

    if sealed.len() < CIPHERTEXT_AT {
        return Err(CryptoError::MalformedBlock(format!(
            "envelope is {} bytes, shorter than its header",
            sealed.len()
        )));
    }
    if sealed[0] != FORMAT_VERSION {
        return Err(CryptoError::MalformedBlock(format!(
            "unsupported envelope version `{}`",
            sealed[0]
        )));
    }

    let mut ephemeral_public = [0u8; KEY_LEN];
    ephemeral_public.copy_from_slice(&sealed[1..NONCE_AT]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&sealed[NONCE_AT..CIPHERTEXT_AT]);

    let key = derive(
        &secret
            .diffie_hellman(&PublicKey::from(ephemeral_public))
            .to_bytes(),
        &ephemeral_public,
        &PublicKey::from(&secret).to_bytes(),
    );

    cipher(&key)
        .decrypt(
            &Array::from(nonce),
            Payload {
                msg: &sealed[CIPHERTEXT_AT..],
                aad: AAD,
            },
        )
        .map_err(|_| CryptoError::Authentication)
}

/// Derives the content key from a shared secret, binding it to both public keys.
///
/// Binding the recipient in means an envelope sealed to one service cannot be replayed as one
/// sealed to another, even if an attacker could substitute the ephemeral half.
fn derive(
    shared: &[u8; KEY_LEN],
    ephemeral_public: &[u8; KEY_LEN],
    recipient_public: &[u8; KEY_LEN],
) -> Zeroizing<[u8; KEY_LEN]> {
    let mut info = Vec::with_capacity(2 * KEY_LEN);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_public);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(HKDF_SALT), shared)
        .expand(&info, key.as_mut())
        .expect("HKDF expands up to 255 hash lengths and this asks for one, so it cannot fail");
    key
}

/// AES-256-GCM under a derived content key.
fn cipher(key: &Zeroizing<[u8; KEY_LEN]>) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key.as_ref())
        .expect("the derived key is exactly one AES-256 key long, by construction")
}

/// Checks a configured key is exactly one X25519 key long.
fn key_bytes(bytes: &[u8], what: &str) -> crate::Result<[u8; KEY_LEN]> {
    bytes.try_into().map_err(|_| {
        CryptoError::MalformedBlock(format!(
            "{what} is {} bytes, expected {KEY_LEN}",
            bytes.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD: &[u8] = br#"{"agent":"writer","summary":"the part that must stay unreadable"}"#;

    #[test]
    fn a_sealed_entry_round_trips_with_the_secret_key() {
        let (secret, public) = generate_keypair();
        let sealed = seal(&public, RECORD).unwrap();
        assert_eq!(open(&secret, &sealed).unwrap(), RECORD);
    }

    #[test]
    fn the_public_half_is_derivable_from_the_secret_one() {
        let (secret, public) = generate_keypair();
        assert_eq!(public_key(&secret).unwrap(), public);
        assert!(public_key(b"short").is_err());
    }

    #[test]
    fn the_plaintext_never_appears_in_the_envelope() {
        let (_, public) = generate_keypair();
        let sealed = seal(&public, RECORD).unwrap();
        assert!(
            !sealed.windows(RECORD.len()).any(|w| w == RECORD),
            "plaintext leaked into the envelope"
        );
    }

    #[test]
    fn the_sealing_key_cannot_open_what_it_sealed() {
        let (_, public) = generate_keypair();
        let sealed = seal(&public, RECORD).unwrap();
        // The public key is the whole of the sidecar's key material. Used as a secret it is a
        // different, unrelated key, so this must fail rather than round-trip.
        assert!(open(&public, &sealed).is_err());
    }

    #[test]
    fn another_services_key_cannot_open_it() {
        let (_, public) = generate_keypair();
        let (other_secret, _) = generate_keypair();
        let sealed = seal(&public, RECORD).unwrap();
        assert!(open(&other_secret, &sealed).is_err());
    }

    #[test]
    fn every_sealing_is_fresh() {
        let (_, public) = generate_keypair();
        let a = seal(&public, RECORD).unwrap();
        let b = seal(&public, RECORD).unwrap();
        assert_ne!(a, b, "two sealings of one plaintext must differ");
    }

    #[test]
    fn a_tampered_envelope_is_refused() {
        let (secret, public) = generate_keypair();
        let sealed = seal(&public, RECORD).unwrap();

        for at in [0, 1, NONCE_AT, CIPHERTEXT_AT, sealed.len() - 1] {
            let mut edited = sealed.clone();
            edited[at] ^= 0x01;
            assert!(open(&secret, &edited).is_err(), "byte {at} went unnoticed");
        }
    }

    #[test]
    fn a_truncated_envelope_is_refused() {
        let (secret, public) = generate_keypair();
        let sealed = seal(&public, RECORD).unwrap();
        for len in [0, 1, CIPHERTEXT_AT - 1] {
            assert!(open(&secret, &sealed[..len]).is_err(), "length {len}");
        }
        // Header intact, tag gone.
        assert!(open(&secret, &sealed[..CIPHERTEXT_AT]).is_err());
    }

    #[test]
    fn a_wrong_length_key_is_an_error_not_a_padded_key() {
        assert!(seal(b"short", RECORD).is_err());
        assert!(open(b"short", &[0u8; 64]).is_err());
        assert!(seal(&[0u8; KEY_LEN + 1], RECORD).is_err());
    }

    #[test]
    fn an_empty_body_still_seals() {
        let (secret, public) = generate_keypair();
        let sealed = seal(&public, b"").unwrap();
        assert!(open(&secret, &sealed).unwrap().is_empty());
    }
}
