//! The redaction policy, as `spec/redaction/` configures it.
//!
//! The policy is checked, never applied. Masking a body here would leave the caller believing it
//! wrote what it sent, and the record's `fields_masked` would disagree with the writer's own
//! account of what it redacted. So a body that still matches a policy pattern is refused, and the
//! writer — which knows what the value was — is the one that masks it.
//!
//! Patterns are configuration, so nothing in this module names anything a policy might match.

use std::path::Path;

use regex::Regex;
use saphyr::{LoadableYamlNode as _, Yaml};

use crate::fsutil;

/// A loaded redaction policy.
#[derive(Debug, Clone)]
pub(crate) struct Redaction {
    /// Policy name, as records must declare it.
    name: String,
    /// Named patterns a body may not match.
    patterns: Vec<(String, Regex)>,
}

impl Redaction {
    /// Loads the policy file, or reports the deployment as configuring none.
    ///
    /// An absent file is not an error: a deployment that declares no policy declares no patterns.
    /// It is logged at warning level, because the difference between "no policy" and "the policy
    /// file is not where this build looks for it" is invisible from the outcome.
    pub(crate) fn load(path: &Path) -> crate::Result<Self> {
        let Some(text) = fsutil::read_to_string_opt(path)? else {
            tracing::warn!(
                path = %path.display(),
                "no redaction policy configured; bodies are written unchecked"
            );
            return Ok(Self {
                name: String::new(),
                patterns: Vec::new(),
            });
        };
        Self::parse(&text)
    }

    /// Parses policy YAML.
    pub(crate) fn parse(text: &str) -> crate::Result<Self> {
        let docs = Yaml::load_from_str(text).map_err(|e| spec(format!("not valid YAML: {e}")))?;
        let doc = docs
            .first()
            .ok_or_else(|| spec("policy file is empty".to_owned()))?;
        let name = doc
            .as_mapping_get("policy")
            .and_then(Yaml::as_str)
            .ok_or_else(|| spec("policy file has no string `policy`".to_owned()))?
            .to_owned();

        let mut patterns = Vec::new();
        if let Some(Yaml::Sequence(items)) = doc.as_mapping_get("patterns") {
            for item in items {
                // A pattern with no `mask` action describes something the policy tolerates.
                if item.as_mapping_get("action").and_then(Yaml::as_str) != Some("mask") {
                    continue;
                }
                let label = field(item, "name")?;
                let source = field(item, "regex")?;
                let compiled = Regex::new(source)
                    .map_err(|e| spec(format!("pattern `{label}` is not a usable regex: {e}")))?;
                patterns.push((label.to_owned(), compiled));
            }
        }
        Ok(Self { name, patterns })
    }

    /// The policy name records must declare.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The first pattern `text` matches, if any.
    ///
    /// Applied to every body, sealed or not: a secret in a sealed body is still a secret retained
    /// for as long as the subject's key lives, and sealing is not a reason to keep one.
    pub(crate) fn first_match(&self, text: &str) -> Option<&str> {
        self.patterns
            .iter()
            .find(|(_, pattern)| pattern.is_match(text))
            .map(|(label, _)| label.as_str())
    }
}

/// Reads a required string field of a pattern entry.
fn field<'a>(item: &'a Yaml<'_>, key: &str) -> crate::Result<&'a str> {
    item.as_mapping_get(key)
        .and_then(Yaml::as_str)
        .ok_or_else(|| spec(format!("a pattern has no string `{key}`")))
}

/// A malformed policy file means this deployment is misconfigured, not that a record is bad.
fn spec(detail: String) -> crate::Error {
    crate::Error::Invalid(yaam_contract::Error::Spec { detail })
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
