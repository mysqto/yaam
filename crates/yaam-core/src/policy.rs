//! The redaction policy, as `spec/redaction/` configures it.
//!
//! The policy is checked here, never applied. Masking a body in the service would leave the caller
//! believing it wrote what it sent, and the record's `fields_masked` would disagree with the
//! writer's own account of what it redacted. So a body that still matches is refused, and the
//! writer — which knows what the value was — is the one that masks it.
//!
//! The patterns, and the rule about which matches count, come from [`yaam_contract::mask`]: the
//! same policy a writer masks with. One parser, two callers. Two parsers produced a service that
//! refused a digit run no masker would touch, which left the writer with nothing to do about it.

use std::path::Path;

use yaam_contract::mask::Policy;

use crate::fsutil;

/// A loaded redaction policy.
#[derive(Debug, Clone)]
pub(crate) struct Redaction {
    /// `None` when the deployment configures no policy at all.
    policy: Option<Policy>,
}

impl Redaction {
    /// Loads the policy file, or reports the deployment as configuring none.
    ///
    /// An absent file is not an error: a deployment that declares no policy declares no patterns.
    /// It is logged, because the difference between "no policy" and "the policy file is not where
    /// this build looks for it" is invisible from the outcome.
    pub(crate) fn load(path: &Path) -> crate::Result<Self> {
        let Some(text) = fsutil::read_to_string_opt(path)? else {
            tracing::warn!(
                path = %path.display(),
                "no redaction policy configured; bodies are written unchecked"
            );
            return Ok(Self { policy: None });
        };
        Self::parse(&text)
    }

    /// Parses policy YAML.
    pub(crate) fn parse(text: &str) -> crate::Result<Self> {
        Ok(Self {
            policy: Some(Policy::from_yaml(text)?),
        })
    }

    /// The policy name records must declare.
    pub(crate) fn name(&self) -> &str {
        self.policy.as_ref().map_or("", Policy::name)
    }

    /// The first pattern `text` matches, if any.
    ///
    /// Applied to every body, sealed or not: a secret in a sealed body is still a secret retained
    /// for as long as the subject's key lives, and sealing is not a reason to keep one.
    pub(crate) fn first_match(&self, text: &str) -> Option<&str> {
        self.policy.as_ref()?.first_match(text)
    }
}

#[cfg(test)]
mod tests {
    use super::Redaction;

    /// A policy with one pattern that no test body matches by accident.
    const POLICY: &str = concat!(
        "version: 1\n",
        "policy: default-v1\n",
        "patterns:\n",
        "  - name: bearer_token\n",
        "    regex: '(?i)\\bbearer\\s+[A-Za-z0-9._~+/-]{16,}'\n",
        "    action: mask\n",
        "  - name: tolerated\n",
        "    regex: 'tolerated'\n",
        "    action: note\n",
    );

    #[test]
    fn a_masked_pattern_is_reported_and_a_noted_one_is_not() {
        let policy = Redaction::parse(POLICY).expect("loads");
        assert_eq!(policy.name(), "default-v1");
        assert_eq!(
            policy.first_match("authorization: Bearer abcdefghijklmnopqrst"),
            Some("bearer_token")
        );
        assert!(
            policy
                .first_match("a body mentioning tolerated things")
                .is_none()
        );
        assert!(policy.first_match("deploy of the api service").is_none());
    }

    #[test]
    fn an_absent_policy_file_configures_no_patterns() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let policy =
            Redaction::load(&dir.path().join("nothing.yaml")).expect("absence is not an error");
        assert_eq!(policy.name(), "");
        assert!(policy.first_match("anything at all").is_none());
    }

    #[test]
    fn a_policy_file_on_disk_loads() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("default.yaml");
        std::fs::write(&path, POLICY).expect("write");
        assert_eq!(Redaction::load(&path).expect("loads").name(), "default-v1");
    }

    #[test]
    fn a_broken_policy_file_is_a_misconfiguration_not_a_bad_record() {
        for text in [
            "policy: [\n",
            "version: 1\n",
            "policy: p\npatterns:\n  - name: x\n    action: mask\n",
            "policy: p\npatterns:\n  - regex: 'x'\n    action: mask\n",
            "policy: p\npatterns:\n  - name: x\n    regex: '('\n    action: mask\n",
            "",
        ] {
            let error = Redaction::parse(text).expect_err("rejected");
            assert!(
                matches!(
                    error,
                    crate::Error::Invalid(yaam_contract::Error::Spec { .. })
                ),
                "{text:?}: {error}"
            );
        }
    }
}

#[cfg(test)]
mod shared_policy {
    use super::Redaction;

    /// The repository's own policy, so this test fails if the shipped file and the service diverge.
    fn shipped() -> Redaction {
        Redaction::parse(include_str!("../../../spec/redaction/default.yaml")).expect("policy")
    }

    #[test]
    fn a_digit_run_that_is_not_a_card_is_not_refused() {
        // The dead end this delegation closes: the service used to refuse any long digit run while
        // no masker would touch a Luhn-invalid one, leaving the writer nothing to do about it.
        assert_eq!(shipped().first_match("order_ref: 1234567890123"), None);
    }

    #[test]
    fn a_card_shaped_run_that_passes_luhn_is_still_refused() {
        assert_eq!(
            shipped().first_match("card 4111 1111 1111 1111"),
            Some("card_like")
        );
    }
}
