//! Serialisation of the sealed block, as it appears in a Markdown body.
//!
//! The format is specified rather than incidental so that a second implementation, or `reindex`,
//! agrees byte for byte. Associated data is deliberately *not* stored.
//!
//! ````text
//! ```sealed
//! v1
//! alg=A256GCM+A256KW+HKDF-SHA256
//! nonce=<24 lowercase hex digits>
//! epoch=<label>
//! shares=<subject>:<hex>,<subject>:<hex>
//! ct=<lowercase hex>
//! ```
//! ````
//!
//! Fields appear in that order, one per line, and shares are sorted by subject — a canonical
//! rendering is what lets two implementations compare blocks by equality.

use serde::Deserialize;
use serde::de::value::{Error as DeError, SeqDeserializer};
use yaam_contract::SubjectHash;

use crate::error::Error;
use crate::seal::{DekShare, Epoch, Nonce};
use crate::{SealedBody, error};

/// Current block format version.
pub const FORMAT_VERSION: &str = "v1";

/// The only algorithm suite `v1` defines.
///
/// AES-256-GCM over the body, AES-256 key wrap over each share, HKDF-SHA256 for the derivation.
pub const ALG: &str = "A256GCM+A256KW+HKDF-SHA256";

/// Fence that opens a sealed block.
const FENCE_OPEN: &str = "```sealed";

/// Fence that closes it.
const FENCE_CLOSE: &str = "```";

/// Renders a sealed body as the fenced block stored in a record file.
#[must_use]
pub fn render(body: &SealedBody) -> String {
    let mut shares: Vec<&DekShare> = body.shares.iter().collect();
    shares.sort_by(|a, b| a.subject.as_str().cmp(b.subject.as_str()));
    let shares: Vec<String> = shares
        .iter()
        .map(|s| format!("{}:{}", s.subject.as_str(), hex::encode(&s.wrapped)))
        .collect();

    format!(
        "{FENCE_OPEN}\n{FORMAT_VERSION}\nalg={ALG}\nnonce={}\nepoch={}\nshares={}\nct={}\n{FENCE_CLOSE}",
        hex::encode(body.nonce.as_bytes()),
        body.epoch.as_str(),
        shares.join(","),
        hex::encode(&body.ciphertext),
    )
}

/// Parses a fenced sealed block.
///
/// Strict on shape and on version: a block written by a future version is refused rather than
/// half-understood, because a partially parsed block is a body decrypted under the wrong rules.
pub fn parse(text: &str) -> error::Result<SealedBody> {
    // Lines are trimmed on both sides: a block nested in a list arrives indented, and no field
    // value contains whitespace, so there is nothing to lose.
    let lines: Vec<&str> = text.trim().lines().map(str::trim).collect();
    let (first, rest) = lines
        .split_first()
        .ok_or_else(|| malformed("block is empty"))?;
    if *first != FENCE_OPEN {
        return Err(malformed(format!("expected `{FENCE_OPEN}` fence")));
    }
    let (last, fields) = rest
        .split_last()
        .ok_or_else(|| malformed("block is unterminated"))?;
    if *last != FENCE_CLOSE {
        return Err(malformed(format!("expected `{FENCE_CLOSE}` fence")));
    }
    let [version, alg, nonce, epoch, shares, ciphertext] = fields else {
        return Err(malformed(format!(
            "expected 6 field lines, got {}",
            fields.len()
        )));
    };

    if *version != FORMAT_VERSION {
        return Err(malformed(format!("unsupported format version `{version}`")));
    }
    if value(alg, "alg")? != ALG {
        return Err(malformed(format!("unsupported algorithm `{alg}`")));
    }

    let nonce: [u8; 12] = decode_hex(nonce, "nonce")?
        .try_into()
        .map_err(|_| malformed("nonce is not 12 bytes"))?;

    Ok(SealedBody {
        nonce: Nonce::from_stored(nonce),
        epoch: Epoch::from_stored(value(epoch, "epoch")?)?,
        shares: parse_shares(value(shares, "shares")?)?,
        ciphertext: decode_hex(ciphertext, "ct")?,
    })
}

/// Splits `key=value`, requiring the expected key.
fn value<'a>(line: &'a str, key: &str) -> error::Result<&'a str> {
    line.strip_prefix(key)
        .and_then(|rest| rest.strip_prefix('='))
        .ok_or_else(|| malformed(format!("expected `{key}=`, found `{line}`")))
}

/// Decodes a hex-valued field.
fn decode_hex(line: &str, key: &str) -> error::Result<Vec<u8>> {
    hex::decode(value(line, key)?).map_err(|e| malformed(format!("{key}: {e}")))
}

/// Parses the comma-separated `subject:wrapped` pairs.
fn parse_shares(field: &str) -> error::Result<Vec<DekShare>> {
    if field.is_empty() {
        return Err(malformed(
            "no shares: a body with no shares is unrecoverable",
        ));
    }
    field
        .split(',')
        .map(|pair| {
            let (subject, wrapped) = pair
                .split_once(':')
                .ok_or_else(|| malformed(format!("share `{pair}` is not `subject:wrapped`")))?;
            Ok(DekShare {
                subject: parse_subject(subject)?,
                wrapped: hex::decode(wrapped)
                    .map_err(|e| malformed(format!("share for `{subject}`: {e}")))?,
            })
        })
        .collect()
}

/// Reads a subject hash from a block.
///
/// The shape rule — `s_` then 64 lowercase hex digits — is the contract's, checked here because a
/// block must not be able to smuggle in a subject shape the rest of the system would reject. The
/// value is then built through `serde`, the only constructor `SubjectHash` exposes today; once
/// `SubjectHash::parse` is implemented upstream, call it instead so the rule lives in one place.
pub(crate) fn parse_subject(text: &str) -> error::Result<SubjectHash> {
    let hex_digits = text.strip_prefix("s_").unwrap_or_default();
    if hex_digits.len() != 64 || !hex_digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(malformed(format!(
            "subject `{text}` is not `s_` and 64 hex digits"
        )));
    }
    let de = SeqDeserializer::<_, DeError>::new(std::iter::once(text));
    SubjectHash::deserialize(de).map_err(|e| malformed(format!("subject `{text}`: {e}")))
}

/// Shorthand for the one error kind this module produces.
fn malformed(reason: impl Into<String>) -> Error {
    Error::MalformedBlock(reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(n: u8) -> SubjectHash {
        parse_subject(&format!("s_{:064x}", u32::from(n) + 1)).unwrap()
    }

    fn body() -> SealedBody {
        SealedBody {
            nonce: Nonce::from_stored([7; 12]),
            epoch: Epoch::from_stored("2026-Q3").unwrap(),
            shares: vec![
                DekShare {
                    subject: subject(1),
                    wrapped: vec![0xbb; 40],
                },
                DekShare {
                    subject: subject(0),
                    wrapped: vec![0xaa; 40],
                },
            ],
            ciphertext: vec![0xcd; 5],
        }
    }

    #[test]
    fn render_is_canonical() {
        let text = render(&body());
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "```sealed");
        assert_eq!(lines[1], "v1");
        assert_eq!(lines[2], "alg=A256GCM+A256KW+HKDF-SHA256");
        assert_eq!(lines[3], format!("nonce={}", "07".repeat(12)));
        assert_eq!(lines[4], "epoch=2026-Q3");
        assert_eq!(lines[6], "ct=cdcdcdcdcd");
        assert_eq!(lines[7], "```");
        // Shares are sorted by subject regardless of the order they were held in.
        let shares = lines[5].strip_prefix("shares=").unwrap();
        let first = shares.split(',').next().unwrap();
        assert!(first.starts_with(subject(0).as_str()));
        assert!(first.ends_with(&"aa".repeat(40)));
    }

    #[test]
    fn render_then_parse_round_trips() {
        let original = body();
        let parsed = parse(&render(&original)).unwrap();

        assert_eq!(parsed.nonce, original.nonce);
        assert_eq!(parsed.epoch, original.epoch);
        assert_eq!(parsed.ciphertext, original.ciphertext);
        assert_eq!(parsed.shares.len(), 2);
        // Parsed in canonical order, so compare against the sorted original.
        let mut expected = original.shares;
        expected.sort_by(|a, b| a.subject.as_str().cmp(b.subject.as_str()));
        for (got, want) in parsed.shares.iter().zip(expected.iter()) {
            assert_eq!(got.subject, want.subject);
            assert_eq!(got.wrapped, want.wrapped);
        }
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let text = format!("\n  {}\n\n", render(&body()).replace('\n', "\n  "));
        assert!(parse(&text).is_ok());
    }

    #[test]
    fn unknown_version_is_rejected() {
        let text = render(&body()).replace("\nv1\n", "\nv2\n");
        let err = parse(&text).unwrap_err();
        assert!(
            format!("{err}").contains("unsupported format version `v2`"),
            "{err}"
        );
    }

    #[test]
    fn unknown_algorithm_is_rejected() {
        let text = render(&body()).replace(ALG, "A128GCM");
        assert!(format!("{}", parse(&text).unwrap_err()).contains("unsupported algorithm"));
    }

    #[test]
    fn malformed_blocks_are_rejected() {
        let good = render(&body());
        let cases = [
            String::new(),
            "```sealed".to_owned(),
            good.replace("```sealed", "```json"),
            good.replace("\n```", "\nEOF"),
            good.replace("epoch=2026-Q3\n", ""),
            good.replace("alg=", "algorithm="),
            good.replace("nonce=", "n="),
            good.replace("ct=cdcdcdcdcd", "ct=notes"),
            good.replace("nonce=0707", "nonce=0708aa"),
        ];
        for case in &cases {
            assert!(
                matches!(parse(case), Err(Error::MalformedBlock(_))),
                "{case}"
            );
        }
        // A block with no shares at all: nothing could ever unseal it.
        let empty = good
            .lines()
            .map(|l| {
                if l.starts_with("shares=") {
                    "shares="
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(matches!(parse(&empty), Err(Error::MalformedBlock(_))));
    }

    #[test]
    fn malformed_shares_are_rejected() {
        let good = render(&body());
        for broken in [
            good.replace(&format!("{}:", subject(0).as_str()), "nocolon"),
            good.replace(subject(0).as_str(), "s_zz"),
            good.replace(&"aa".repeat(40), "notes"),
        ] {
            assert!(
                matches!(parse(&broken), Err(Error::MalformedBlock(_))),
                "{broken}"
            );
        }
    }

    #[test]
    fn subject_shapes_are_checked() {
        assert!(parse_subject(&format!("s_{}", "0".repeat(64))).is_ok());
        for bad in [
            "",
            "s_",
            "s_00",
            &format!("x_{}", "0".repeat(64)),
            &"0".repeat(66),
        ] {
            assert!(parse_subject(bad).is_err(), "{bad}");
        }
    }
}
