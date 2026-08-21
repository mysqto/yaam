//! Masking a body before it is submitted.
//!
//! The service *checks* bodies against the redaction policy and refuses one that still matches. It
//! does not mask: masking inside the service would leave the caller believing it wrote what it
//! sent, and the record's `fields_masked` would disagree with the writer's own account of what it
//! redacted. Masking is therefore the writer's job — and this is the one implementation of it, so a
//! missed pattern is fixed once rather than once per writer, and so no writer's mistake becomes an
//! unerasable plaintext copy in an immutable tree.
//!
//! It lives beside the wire types because both halves must read the *same* policy file: a writer
//! masking against a different spelling of the policy than the service validates against is the
//! failure this exists to prevent.
//!
//! Patterns are configuration, so nothing here names anything a policy might match.

use regex::Regex;
use saphyr::Yaml;

use crate::{Error, spec_yaml};

/// How many times the pattern set is applied before the body is taken as settled.
///
/// One round is normally enough. A second only matters when a replacement ends up beside text that
/// together completes another pattern, and repeating until nothing changes is what makes the result
/// a fixed point — which is what makes masking it again a no-op. The cap bounds a pathological
/// policy rather than marking a limit anyone should reach.
const MAX_ROUNDS: usize = 4;

/// A loaded redaction policy, in the format `spec/redaction/*.yaml` uses.
///
/// Built from text rather than a path so a writer can source the policy however it ships one —
/// beside the binary, from the tree it writes to, or embedded — without this crate reaching for a
/// filesystem it otherwise never touches.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Policy name, which a record must declare for the service to accept it.
    name: String,
    /// Named patterns, in the order the file declares them.
    patterns: Vec<(String, Regex)>,
}

/// A masked body, and the account of what was taken out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Masked {
    /// The body to submit.
    pub text: String,
    /// Names of the patterns that masked something, in the order they did.
    ///
    /// Goes straight into [`crate::ActionRecord::fields_masked`], which is the point: that field is
    /// the writer's account of its own redaction, and a writer that has to guess writes fiction.
    pub fields_masked: Vec<String>,
}

impl Policy {
    /// Loads a policy from `redaction/*.yaml` content.
    ///
    /// # Examples
    /// ```
    /// use yaam_contract::mask::Policy;
    ///
    /// let policy = Policy::from_yaml(concat!(
    ///     "version: 1\n",
    ///     "policy: example-v1\n",
    ///     "patterns:\n",
    ///     "  - name: token\n",
    ///     "    regex: '(?i)\\btoken=\\S{8,}'\n",
    ///     "    action: mask\n",
    /// ))?;
    ///
    /// let masked = policy.mask("ran with token=not-a-real-value and finished");
    /// assert_eq!(masked.text, "ran with [masked:token] and finished");
    /// assert_eq!(masked.fields_masked, ["token"]);
    /// assert!(policy.first_match(&masked.text).is_none());
    /// # Ok::<(), yaam_contract::Error>(())
    /// ```
    pub fn from_yaml(yaml: &str) -> crate::Result<Self> {
        let doc = spec_yaml::single_document(yaml)?;
        spec_yaml::check_version(&doc)?;
        let name = spec_yaml::required_str(&doc, "policy", "redaction policy")?.to_owned();

        let mut patterns = Vec::new();
        if let Some(Yaml::Sequence(items)) = doc.as_mapping_get("patterns") {
            for item in items {
                // An entry with no `mask` action describes something the policy tolerates.
                if item.as_mapping_get("action").and_then(Yaml::as_str) != Some("mask") {
                    continue;
                }
                let label = spec_yaml::required_str(item, "name", "pattern")?;
                let source = spec_yaml::required_str(item, "regex", label)?;
                let compiled = Regex::new(source)
                    .map_err(|e| spec(format!("pattern `{label}` is not a usable regex: {e}")))?;
                patterns.push((label.to_owned(), compiled));
            }
        }

        let policy = Self { name, patterns };
        policy.check_replacements_are_inert()?;
        Ok(policy)
    }

    /// The policy name a record must declare.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Masks every match in `body`, naming the patterns that matched.
    ///
    /// Idempotent: the result is a fixed point of the pattern set, so masking it again returns it
    /// unchanged and a writer's retry cannot mask into gibberish. A body with nothing to mask comes
    /// back as it arrived, with an empty account.
    ///
    /// Only what a pattern actually matched is replaced. Widening a replacement past its match
    /// would take out text the service's check never looked at, and then the two halves would no
    /// longer be reading one policy.
    #[must_use]
    pub fn mask(&self, body: &str) -> Masked {
        let mut text = body.to_owned();
        let mut fields_masked = Vec::new();
        for _ in 0..MAX_ROUNDS {
            let mut changed = false;
            for (label, pattern) in &self.patterns {
                let replaced = pattern
                    .replace_all(&text, |caps: &regex::Captures| {
                        let found = &caps[0];
                        if maskable(found) {
                            replacement(label)
                        } else {
                            found.to_owned()
                        }
                    })
                    .into_owned();
                if replaced != text {
                    text = replaced;
                    changed = true;
                    if !fields_masked.contains(label) {
                        fields_masked.push(label.clone());
                    }
                }
            }
            if !changed {
                break;
            }
        }
        Masked {
            text,
            fields_masked,
        }
    }

    /// The first pattern `text` still matches, if any.
    ///
    /// The same question the service asks before accepting a body, so a writer can check its own
    /// work without a round trip. A match this policy would not mask is not reported either, since
    /// reporting one would demand a redaction that [`Policy::mask`] does not make.
    #[must_use]
    pub fn first_match(&self, text: &str) -> Option<&str> {
        self.patterns
            .iter()
            .find(|(_, pattern)| pattern.find_iter(text).any(|m| maskable(m.as_str())))
            .map(|(label, _)| label.as_str())
    }

    /// Rejects a policy that would match its own replacements.
    ///
    /// A replacement a pattern matches would be masked again on the next round, so the text would
    /// never settle and a retry would nest placeholders. Checked once at load, where the fix is to
    /// rename a pattern, rather than discovered as corrupted prose in an immutable record.
    fn check_replacements_are_inert(&self) -> crate::Result<()> {
        for (label, _) in &self.patterns {
            if let Some(hit) = self.first_match(&replacement(label)) {
                return Err(spec(format!(
                    "pattern `{hit}` matches the text that replaces `{label}`; rename one of them"
                )));
            }
        }
        Ok(())
    }
}

/// What replaces a match.
///
/// Named, so a reader of the body learns what was taken out and not merely that something was.
fn replacement(label: &str) -> String {
    format!("[masked:{label}]")
}

/// Whether a match is worth masking, or is a digit run that only resembles one.
///
/// A match carrying no letters is nothing but digits and separators, and there is no keyword in it
/// to tell a card number from an order reference, a timestamp or a build number. Masking those
/// unchecked would redact ordinary references, so such a match is masked only if it satisfies Luhn.
fn maskable(text: &str) -> bool {
    if text.chars().any(char::is_alphabetic) {
        return true;
    }
    !text.chars().any(|c| c.is_ascii_digit()) || luhn(text)
}

/// Whether the digits in `text` satisfy the Luhn checksum. Anything that is not a digit is ignored.
fn luhn(text: &str) -> bool {
    let digits: Vec<u32> = text.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 2 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(place, digit)| match (place % 2, digit * 2) {
            (0, _) => *digit,
            (_, doubled) if doubled > 9 => doubled - 9,
            (_, doubled) => doubled,
        })
        .sum();
    sum.is_multiple_of(10)
}

/// A malformed policy file means the deployment is misconfigured, not that a body is bad.
fn spec(detail: String) -> Error {
    Error::Spec { detail }
}

#[cfg(test)]
mod tests {
    use super::{Policy, luhn};
    use crate::Error;

    /// The patterns `spec/redaction/default.yaml` declares, copied so this module's tests do not
    /// depend on a path outside the crate. `yaam-server`'s integration tests load the real file and
    /// check the service accepts what it produces, which is what keeps the two in step.
    const DEFAULT: &str = concat!(
        "version: 1\n",
        "policy: default-v1\n",
        "patterns:\n",
        "  - name: private_key_block\n",
        "    regex: '-----BEGIN [A-Z ]*PRIVATE KEY-----'\n",
        "    action: mask\n",
        "  - name: bearer_token\n",
        "    regex: '(?i)\\bbearer\\s+[A-Za-z0-9._~+/-]{16,}'\n",
        "    action: mask\n",
        "  - name: generic_api_key\n",
        "    regex: '(?i)\\b(?:api[_-]?key|secret|passwd|password)\\s*[:=]\\s*\\S{8,}'\n",
        "    action: mask\n",
        "  - name: email\n",
        "    regex: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b'\n",
        "    action: mask\n",
        "  - name: card_like\n",
        "    regex: '\\b(?:\\d[ -]?){13,19}\\b'\n",
        "    action: mask\n",
    );

    /// One instance of every pattern the default policy names. The secrets are obviously fake and
    /// the surrounding prose names nothing but neutral vocabulary.
    const DIRTY: &str = concat!(
        "Rolled out the api service to staging.\n",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        "authorization: Bearer not-a-real-token-0123456789\n",
        "api_key: not-a-real-key-value\n",
        "contact: someone@example.test\n",
        "card: 4111 1111 1111 1111\n",
        "order_ref: ord10014721, 12 shards\n",
    );

    #[test]
    fn every_default_pattern_is_masked_and_named() {
        let policy = Policy::from_yaml(DEFAULT).expect("loads");
        assert_eq!(policy.name(), "default-v1");

        let masked = policy.mask(DIRTY);
        assert_eq!(
            masked.fields_masked,
            [
                "private_key_block",
                "bearer_token",
                "generic_api_key",
                "email",
                "card_like"
            ]
        );
        assert_eq!(
            masked.text,
            concat!(
                "Rolled out the api service to staging.\n",
                "[masked:private_key_block]\n",
                "authorization: [masked:bearer_token]\n",
                "[masked:generic_api_key]\n",
                "contact: [masked:email]\n",
                "card: [masked:card_like]\n",
                "order_ref: ord10014721, 12 shards\n",
            )
        );
    }

    #[test]
    fn masked_output_matches_no_pattern() {
        // The invariant the whole design rests on: a replacement no pattern matches is what lets
        // the service accept the result, and what makes a second pass a no-op.
        let policy = Policy::from_yaml(DEFAULT).expect("loads");
        assert_eq!(policy.first_match(DIRTY), Some("private_key_block"));
        assert_eq!(policy.first_match(&policy.mask(DIRTY).text), None);
    }

    #[test]
    fn masking_twice_changes_nothing() {
        let policy = Policy::from_yaml(DEFAULT).expect("loads");
        let once = policy.mask(DIRTY);
        let twice = policy.mask(&once.text);
        assert_eq!(twice.text, once.text);
        assert!(
            twice.fields_masked.is_empty(),
            "a retry masked nothing, so it claims nothing: {:?}",
            twice.fields_masked
        );
    }

    #[test]
    fn a_body_with_nothing_to_mask_comes_back_unchanged() {
        let policy = Policy::from_yaml(DEFAULT).expect("loads");
        let clean = "Rolled out the api service to staging across two of three shards.";
        let masked = policy.mask(clean);
        assert_eq!(masked.text, clean);
        assert!(masked.fields_masked.is_empty());
    }

    #[test]
    fn a_digit_run_is_masked_only_when_its_checksum_holds() {
        let policy = Policy::from_yaml(DEFAULT).expect("loads");

        let valid = policy.mask("card: 4111 1111 1111 1111\n");
        assert_eq!(valid.text, "card: [masked:card_like]\n");
        assert_eq!(valid.fields_masked, ["card_like"]);

        // An order reference or a build number is the false positive this guard is for.
        let invalid = "order_ref: 1234567890123\n";
        let left = policy.mask(invalid);
        assert_eq!(left.text, invalid);
        assert!(left.fields_masked.is_empty());
        assert_eq!(policy.first_match(invalid), None);
    }

    #[test]
    fn luhn_needs_more_than_one_digit_and_a_match_without_digits_is_masked_outright() {
        assert!(!luhn("7"), "one digit is not a checksummed run");
        let policy = Policy::from_yaml(concat!(
            "policy: shapes-v1\n",
            "patterns:\n",
            "  - name: single_digit\n",
            "    regex: '\\d'\n",
            "    action: mask\n",
            "  - name: rule\n",
            "    regex: '={5}'\n",
            "    action: mask\n",
        ))
        .expect("loads");
        assert_eq!(policy.mask("7 =====").text, "7 [masked:rule]");
    }

    #[test]
    fn a_second_round_runs_when_a_replacement_completes_another_pattern() {
        // Why masking iterates: the assignment is too short to match until the digit run beside it
        // has been replaced. A single pass would hand the service a body it still refuses.
        let policy = Policy::from_yaml(concat!(
            "policy: two-step-v1\n",
            "patterns:\n",
            "  - name: assignment\n",
            "    regex: 'secret\\s*=\\s*\\S{8,}'\n",
            "    action: mask\n",
            "  - name: short_run\n",
            "    regex: '\\b\\d{5}\\b'\n",
            "    action: mask\n",
        ))
        .expect("loads");

        let masked = policy.mask("secret = 12344");
        assert_eq!(masked.text, "[masked:assignment]");
        assert_eq!(masked.fields_masked, ["short_run", "assignment"]);
        assert_eq!(policy.mask(&masked.text).text, masked.text);
    }

    #[test]
    fn an_entry_the_policy_only_notes_is_not_masked() {
        let policy = Policy::from_yaml(concat!(
            "policy: noted-v1\n",
            "patterns:\n",
            "  - name: tolerated\n",
            "    regex: 'tolerated'\n",
            "    action: note\n",
        ))
        .expect("loads");
        assert_eq!(
            policy.mask("a tolerated thing").fields_masked,
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_policy_declaring_no_patterns_masks_nothing() {
        let policy = Policy::from_yaml("policy: none-v1\n").expect("loads");
        assert_eq!(policy.name(), "none-v1");
        assert_eq!(policy.mask(DIRTY).text, DIRTY);
        assert_eq!(policy.first_match(DIRTY), None);
    }

    #[test]
    fn a_policy_that_would_match_its_own_replacement_is_refused() {
        let error = Policy::from_yaml(concat!(
            "policy: circular-v1\n",
            "patterns:\n",
            "  - name: masked\n",
            "    regex: 'masked'\n",
            "    action: mask\n",
        ))
        .expect_err("a policy that never settles is unusable");
        assert!(error.to_string().contains("rename one of them"), "{error}");
    }

    #[test]
    fn a_broken_policy_file_reads_as_a_misconfiguration() {
        for text in [
            "policy: [\n",
            "",
            "policy: p\n---\npolicy: q\n",
            "version: 1\n",
            "version: 2\npolicy: p\n",
            "policy: p\npatterns:\n  - regex: 'x'\n    action: mask\n",
            "policy: p\npatterns:\n  - name: x\n    action: mask\n",
            "policy: p\npatterns:\n  - name: x\n    regex: '('\n    action: mask\n",
        ] {
            assert!(
                matches!(Policy::from_yaml(text), Err(Error::Spec { .. })),
                "{text:?} should read as a spec failure"
            );
        }
    }
}
