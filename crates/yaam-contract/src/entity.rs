//! Entity kinds and canonicalisation.
//!
//! Entities are the join keys across records. Kinds are configuration (`spec/entities.yaml`), not
//! hardcoded vocabulary, so a deployment defines the kinds its domain needs.

use std::collections::BTreeMap;

use regex::Regex;
use saphyr::Yaml;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Error, spec_yaml};

/// Characters that structure an identifier. The prefix is everything before the first of them.
const PREFIX_SEPARATORS: [char; 5] = ['-', '/', ':', '#', '@'];

/// Characters that end an identifier's path-like head. `/` is part of a path, not a terminator.
const PATH_TERMINATORS: [char; 3] = [':', '#', '@'];

/// The character that escapes itself and the specials in a path segment.
const ESCAPE: char = '~';

/// Characters legal in an identifier but hostile in a filename, paired with their escape code.
///
/// `~` is in the table, which is what makes the encoding injective: it is escaped by the same
/// single pass as everything else, so it can never be introduced after escaping is done.
const ESCAPES: [(char, char); 5] = [('~', '~'), ('/', 's'), (':', 'c'), ('#', 'h'), ('@', 'a')];

/// A reference from a record to an entity, with the role the entity played.
///
/// Unknown fields are refused for the reason [`ActionRecord`] refuses them: an entity reference is
/// a join key, and a field that silently vanished here would leave the record joining on something
/// other than what was sent.
///
/// [`ActionRecord`]: crate::ActionRecord
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EntityRef {
    /// The entity kind, e.g. `order_ref`.
    pub kind: String,
    /// The canonical identifier.
    pub id: String,
    /// How the entity relates to the record.
    pub role: Role,
    /// Extraction confidence. Below `1.0` means inferred from text rather than a structured field.
    ///
    /// The bound is published because `ActionRecord::validate` enforces it: a caller that can read
    /// the schema can fail before sending rather than after.
    #[schemars(range(min = 0.0, max = 1.0))]
    pub confidence: f32,
}

/// The part an entity plays in a record.
// Renamed for the schema: a record names two kinds of role, and one `Role` in the published bundle
// would leave a vendoring implementation to guess which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(rename = "EntityRole")]
pub enum Role {
    /// The record is chiefly about this entity.
    Primary,
    /// Supporting context.
    Context,
    /// Mentioned, related but not central.
    Related,
}

/// Normalisation steps a kind applies before matching its pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Normalise {
    /// Strip surrounding whitespace.
    Trim,
    /// Lowercase the whole identifier.
    Lowercase,
    /// Uppercase the portion before the first separator.
    UppercasePrefix,
    /// Lowercase the path-like portion only.
    LowercasePath,
}

impl Normalise {
    /// Reads the step's name as `spec/entities.yaml` spells it.
    fn from_name(name: &str) -> crate::Result<Self> {
        match name {
            "trim" => Ok(Self::Trim),
            "lowercase" => Ok(Self::Lowercase),
            "uppercase_prefix" => Ok(Self::UppercasePrefix),
            "lowercase_path" => Ok(Self::LowercasePath),
            other => Err(spec(format!("unknown normalise step `{other}`"))),
        }
    }

    /// Applies one step.
    ///
    /// The two partial-case steps leave the tail alone: a path segment is conventionally
    /// case-insensitive, while the locator after it — a build number, a commit hash, a thread
    /// timestamp — is not ours to rewrite.
    fn apply(self, id: &str) -> String {
        match self {
            Self::Trim => id.trim().to_owned(),
            Self::Lowercase => id.to_lowercase(),
            Self::UppercasePrefix => recase(id, &PREFIX_SEPARATORS, str::to_uppercase),
            Self::LowercasePath => recase(id, &PATH_TERMINATORS, str::to_lowercase),
        }
    }
}

/// Recases the head of `id` up to the first of `separators`, or all of it if there is none.
fn recase(id: &str, separators: &[char], f: impl Fn(&str) -> String) -> String {
    match id.find(|c: char| separators.contains(&c)) {
        Some(at) => {
            let (head, tail) = id.split_at(at);
            f(head) + tail
        }
        None => f(id),
    }
}

/// One configured entity kind.
#[derive(Debug, Clone)]
pub struct KindSpec {
    /// Kind name.
    pub name: String,
    /// Regex the canonical form must match.
    pub pattern: String,
    /// Normalisation applied before matching.
    pub normalise: Vec<Normalise>,
}

/// A kind alongside the compiled form of its pattern.
#[derive(Debug, Clone)]
struct CompiledKind {
    /// The kind as configured.
    spec: KindSpec,
    /// `spec.pattern`, anchored and compiled.
    pattern: Regex,
}

/// The loaded set of entity kinds.
///
/// Holds the configured kinds twice over: a map for lookup, and a slice in name order for callers
/// that need to enumerate them. A slice cannot be borrowed out of a map, and the alternative — a
/// `Vec<&KindSpec>` — would allocate on every call to describe configuration that never changes.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    kinds: BTreeMap<String, CompiledKind>,
    specs: Vec<KindSpec>,
}

impl Registry {
    /// Loads a registry from `entities.yaml` content.
    ///
    /// Patterns are compiled here, so a broken one fails at load rather than on the first record
    /// that happens to use that kind.
    ///
    /// # Examples
    /// ```
    /// use yaam_contract::entity::Registry;
    ///
    /// let registry = Registry::from_yaml(
    ///     "kinds:\n  ticket:\n    pattern: '^[A-Z]+-[0-9]+$'\n    normalise: [trim, uppercase_prefix]\n",
    /// )?;
    /// assert_eq!(registry.canonicalise("ticket", "  proj-42 ")?, "PROJ-42");
    /// # Ok::<(), yaam_contract::Error>(())
    /// ```
    pub fn from_yaml(yaml: &str) -> crate::Result<Self> {
        let doc = spec_yaml::single_document(yaml)?;
        spec_yaml::check_version(&doc)?;

        let mut kinds = BTreeMap::new();
        for (key, value) in spec_yaml::required_mapping(&doc, "kinds")? {
            let name = spec_yaml::key_name(key, "entity kind")?;
            let pattern = spec_yaml::required_str(value, "pattern", name)?;
            let normalise = parse_steps(value.as_mapping_get("normalise"), name)?;
            // Anchored so a kind that forgot `^…$` cannot accept junk wrapped around a matching
            // substring. The spec's own anchors make the added assertions inert.
            let compiled = Regex::new(&format!("^(?:{pattern})$"))
                .map_err(|e| spec(format!("entity kind `{name}` has an unusable pattern: {e}")))?;
            kinds.insert(
                name.to_owned(),
                CompiledKind {
                    spec: KindSpec {
                        name: name.to_owned(),
                        pattern: pattern.to_owned(),
                        normalise,
                    },
                    pattern: compiled,
                },
            );
        }
        // The map is already in name order, which is what makes the two views agree.
        let specs = kinds.values().map(|k| k.spec.clone()).collect();
        Ok(Self { kinds, specs })
    }

    /// Every configured kind, in name order.
    ///
    /// [`KindSpec`] was public from the start with nothing on the surface handing one out, so a
    /// caller could not list the kinds a deployment configured — which is what a `yaam kinds`
    /// listing, or any validation of a kind name before use, needs.
    #[must_use]
    pub fn kinds(&self) -> &[KindSpec] {
        &self.specs
    }

    /// Normalises then validates an identifier, returning its canonical form.
    ///
    /// Rejects rather than repairs: an identifier that cannot be canonicalised is a caller bug, and
    /// silently accepting it would put an unjoinable row in the index.
    ///
    /// The error quotes the identifier as it was passed in, not its normalised form — the caller can
    /// only act on the string it holds.
    pub fn canonicalise(&self, kind: &str, id: &str) -> crate::Result<String> {
        let entry = self
            .kinds
            .get(kind)
            .ok_or_else(|| Error::UnknownEntityKind(kind.to_owned()))?;

        let mut candidate = id.to_owned();
        for step in &entry.spec.normalise {
            candidate = step.apply(&candidate);
        }

        if entry.pattern.is_match(&candidate) {
            Ok(candidate)
        } else {
            Err(Error::NotCanonical {
                kind: kind.to_owned(),
                id: id.to_owned(),
            })
        }
    }

    /// Filename-safe encoding of an identifier.
    ///
    /// Injective: `~` escapes itself first, so distinct identifiers cannot collide on a path. `/`,
    /// `:`, `#` and `@` are all legal in identifiers and hostile in filenames.
    ///
    /// "First" here is structural rather than sequential — one pass rewrites each input character
    /// independently, so an emitted `~` is never re-read as an escape introducer.
    ///
    /// # Examples
    /// ```
    /// use yaam_contract::entity::Registry;
    ///
    /// // A literal `~s` and an encoded `/` stay distinguishable.
    /// assert_eq!(Registry::to_path_segment("a~sb"), "a~~sb");
    /// assert_eq!(Registry::to_path_segment("a/b"), "a~sb");
    /// ```
    #[must_use]
    pub fn to_path_segment(id: &str) -> String {
        let mut out = String::with_capacity(id.len());
        for c in id.chars() {
            if let Some((_, code)) = ESCAPES.iter().find(|(from, _)| *from == c) {
                out.push(ESCAPE);
                out.push(*code);
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Inverse of [`Registry::to_path_segment`].
    ///
    /// Accepts only what the encoder can emit. An unescaped special, an unknown escape code or a
    /// trailing `~` cannot have come from an identifier, and guessing what was meant would mint one.
    pub fn from_path_segment(segment: &str) -> crate::Result<String> {
        let mut out = String::with_capacity(segment.len());
        let mut chars = segment.chars();
        while let Some(c) = chars.next() {
            if c != ESCAPE {
                if ESCAPES.iter().any(|(from, _)| *from == c) {
                    return Err(Error::Invalid(format!(
                        "path segment `{segment}` holds an unescaped `{c}`"
                    )));
                }
                out.push(c);
                continue;
            }
            let Some(code) = chars.next() else {
                return Err(Error::Invalid(format!(
                    "path segment `{segment}` ends in a dangling `~`"
                )));
            };
            let (decoded, _) = ESCAPES
                .iter()
                .find(|(_, candidate)| *candidate == code)
                .ok_or_else(|| {
                    Error::Invalid(format!(
                        "path segment `{segment}` holds an unknown escape `~{code}`"
                    ))
                })?;
            out.push(*decoded);
        }
        Ok(out)
    }
}

/// A malformed `entities.yaml`, distinct from a malformed identifier.
fn spec(detail: String) -> Error {
    Error::Spec { detail }
}

/// Reads a kind's `normalise` list. Absent means the identifier is taken as given.
fn parse_steps(node: Option<&Yaml<'_>>, kind: &str) -> crate::Result<Vec<Normalise>> {
    let Some(node) = node else {
        return Ok(Vec::new());
    };
    let steps = node
        .as_vec()
        .ok_or_else(|| spec(format!("entity kind `{kind}` has a non-list `normalise`")))?;
    steps
        .iter()
        .map(|step| {
            let name = step.as_str().ok_or_else(|| {
                spec(format!(
                    "entity kind `{kind}` has a non-string normalise step"
                ))
            })?;
            Normalise::from_name(name)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// The registry the workspace ships, so a spec edit that breaks a rule fails here.
    const SHIPPED: &str = include_str!("../../../spec/entities.yaml");

    fn shipped() -> Registry {
        Registry::from_yaml(SHIPPED).expect("the shipped spec must load")
    }

    #[test]
    fn shipped_spec_canonicalises_every_kind() {
        let r = shipped();
        for (kind, input, want) in [
            ("order_ref", "  AB12CD34  ", "ab12cd34"),
            ("ticket", " proj-42 ", "PROJ-42"),
            ("pull_request", " Owner/Repo#7 ", "owner/repo#7"),
            ("commit", " Owner/Repo@ABCDEF1 ", "owner/repo@abcdef1"),
            ("chat_user", "  member.01  ", "member.01"),
            ("chat_channel", " general ", "general"),
            (
                "chat_thread",
                " general/1700000000.0001 ",
                "general/1700000000.0001",
            ),
            ("deploy", " Api/Prod#12 ", "api/prod#12"),
        ] {
            assert_eq!(
                r.canonicalise(kind, input).expect(kind),
                want,
                "kind {kind}"
            );
        }
    }

    #[test]
    fn canonicalisation_is_idempotent() {
        let r = shipped();
        let once = r.canonicalise("ticket", " proj-42 ").unwrap();
        assert_eq!(r.canonicalise("ticket", &once).unwrap(), once);
    }

    #[test]
    fn shipped_spec_agrees_with_the_id_newtypes() {
        let r = shipped();
        let id = crate::RecordId::generate();
        assert_eq!(r.canonicalise("record", id.as_str()).unwrap(), id.as_str());
        let hash = format!("s_{}", "ab".repeat(32));
        assert_eq!(r.canonicalise("subject", &hash).unwrap(), hash);
        assert!(r.canonicalise("subject", "s_short").is_err());
    }

    #[test]
    fn unknown_kind_is_named_in_the_error() {
        let err = shipped()
            .canonicalise("no_such_kind", "x")
            .expect_err("kind is absent");
        assert!(matches!(err, Error::UnknownEntityKind(ref k) if k == "no_such_kind"));
    }

    #[test]
    fn non_canonical_error_quotes_the_callers_string() {
        let err = shipped()
            .canonicalise("ticket", " not a key ")
            .expect_err("not a ticket key");
        assert!(matches!(err, Error::NotCanonical { ref id, .. } if id == " not a key "));
    }

    #[test]
    fn canonicalise_never_repairs() {
        let r = shipped();
        // Too short, too long, and structurally wrong: rejected, never padded or truncated.
        assert!(r.canonicalise("order_ref", "abc").is_err());
        assert!(r.canonicalise("order_ref", &"a".repeat(25)).is_err());
        assert!(r.canonicalise("pull_request", "owner/repo").is_err());
        assert!(r.canonicalise("chat_thread", "general").is_err());
    }

    #[test]
    fn patterns_are_anchored_even_when_the_spec_forgets() {
        let r = Registry::from_yaml("kinds:\n  loose:\n    pattern: '[a-z]+'\n").unwrap();
        assert_eq!(r.canonicalise("loose", "abc").unwrap(), "abc");
        assert!(r.canonicalise("loose", "!abc!").is_err());
    }

    #[test]
    fn recase_steps_handle_a_missing_separator() {
        let r = Registry::from_yaml(concat!(
            "kinds:\n",
            "  up:\n    pattern: '^[A-Z]+$'\n    normalise: [uppercase_prefix]\n",
            "  down:\n    pattern: '^[a-z]+$'\n    normalise: [lowercase_path]\n",
        ))
        .unwrap();
        assert_eq!(r.canonicalise("up", "abc").unwrap(), "ABC");
        assert_eq!(r.canonicalise("down", "ABC").unwrap(), "abc");
    }

    #[test]
    fn recase_steps_leave_the_tail_alone() {
        let r = Registry::from_yaml(concat!(
            "kinds:\n",
            "  up:\n    pattern: '^.+$'\n    normalise: [uppercase_prefix]\n",
            "  down:\n    pattern: '^.+$'\n    normalise: [lowercase_path]\n",
        ))
        .unwrap();
        assert_eq!(r.canonicalise("up", "ab-Cd").unwrap(), "AB-Cd");
        assert_eq!(r.canonicalise("down", "AB/CD#Ef").unwrap(), "ab/cd#Ef");
    }

    #[test]
    fn steps_apply_in_the_order_given() {
        // `lowercase` then `uppercase_prefix` differs from the reverse, so order is observable.
        let forwards = Registry::from_yaml(
            "kinds:\n  k:\n    pattern: '^.+$'\n    normalise: [lowercase, uppercase_prefix]\n",
        )
        .unwrap();
        let backwards = Registry::from_yaml(
            "kinds:\n  k:\n    pattern: '^.+$'\n    normalise: [uppercase_prefix, lowercase]\n",
        )
        .unwrap();
        assert_eq!(forwards.canonicalise("k", "aB-cD").unwrap(), "AB-cd");
        assert_eq!(backwards.canonicalise("k", "aB-cD").unwrap(), "ab-cd");
    }

    #[test]
    fn a_kind_without_normalise_takes_the_id_as_given() {
        let r = Registry::from_yaml("kinds:\n  k:\n    pattern: '^[A-Z]+$'\n").unwrap();
        assert_eq!(r.canonicalise("k", "AB").unwrap(), "AB");
        assert!(r.canonicalise("k", " AB ").is_err());
    }

    #[test]
    fn default_registry_knows_nothing() {
        assert!(
            Registry::default()
                .canonicalise("ticket", "PROJ-1")
                .is_err()
        );
    }

    #[test]
    fn from_yaml_rejects_malformed_specs() {
        for (label, yaml) in [
            ("not yaml", "kinds: [\n"),
            ("no kinds", "version: 1\n"),
            ("kinds not a mapping", "kinds: []\n"),
            ("non-string kind name", "kinds:\n  1:\n    pattern: '^a$'\n"),
            ("missing pattern", "kinds:\n  k:\n    normalise: [trim]\n"),
            ("pattern not a string", "kinds:\n  k:\n    pattern: 7\n"),
            ("unusable pattern", "kinds:\n  k:\n    pattern: '['\n"),
            (
                "unknown step",
                "kinds:\n  k:\n    pattern: '^a$'\n    normalise: [squash]\n",
            ),
            (
                "steps not a list",
                "kinds:\n  k:\n    pattern: '^a$'\n    normalise: trim\n",
            ),
            (
                "step not a string",
                "kinds:\n  k:\n    pattern: '^a$'\n    normalise: [1]\n",
            ),
            ("future version", "version: 99\nkinds: {}\n"),
        ] {
            assert!(
                Registry::from_yaml(yaml).is_err(),
                "{label} must be rejected"
            );
        }
    }

    #[test]
    fn from_yaml_keeps_the_configured_kind_verbatim() {
        let r = Registry::from_yaml("kinds:\n  k:\n    pattern: '^a$'\n    normalise: [trim]\n")
            .unwrap();
        let [spec] = r.kinds() else {
            panic!("one kind was configured");
        };
        assert_eq!(spec.name, "k");
        assert_eq!(spec.pattern, "^a$");
        assert_eq!(spec.normalise, vec![Normalise::Trim]);
    }

    #[test]
    fn kinds_lists_every_configured_kind_in_name_order() {
        let r = shipped();
        let names: Vec<&str> = r.kinds().iter().map(|k| k.name.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "the listing must be stable");
        assert!(names.contains(&"ticket") && names.contains(&"subject"));
        // The listing and the matcher are two views of one thing, so every listed name resolves.
        for spec in r.kinds() {
            assert!(
                !matches!(
                    r.canonicalise(&spec.name, "x"),
                    Err(Error::UnknownEntityKind(_))
                ),
                "kind `{}` is listed but unknown to the matcher",
                spec.name
            );
        }
        assert!(Registry::default().kinds().is_empty());
    }

    #[test]
    fn a_malformed_registry_is_a_spec_failure() {
        for yaml in [
            "kinds:\n  k:\n    pattern: '['\n",
            "kinds:\n  k:\n    pattern: '^a$'\n    normalise: [squash]\n",
            "kinds:\n  k:\n    pattern: '^a$'\n    normalise: trim\n",
            "kinds:\n  k:\n    pattern: '^a$'\n    normalise: [1]\n",
        ] {
            assert!(
                matches!(Registry::from_yaml(yaml), Err(Error::Spec { .. })),
                "{yaml} must read as a spec failure"
            );
        }
        // A path segment, by contrast, is data rather than configuration.
        assert!(matches!(
            Registry::from_path_segment("a~"),
            Err(Error::Invalid(_))
        ));
    }

    /// The alphabet that can possibly collide: the escape, every special, every escape code, and
    /// one ordinary character.
    const ADVERSARIAL_ALPHABET: [char; 10] = ['~', '/', ':', '#', '@', 's', 'c', 'h', 'a', 'x'];

    /// Every string of length `len` over [`ADVERSARIAL_ALPHABET`].
    fn words(len: usize) -> Vec<String> {
        if len == 0 {
            return vec![String::new()];
        }
        words(len - 1)
            .into_iter()
            .flat_map(|prefix| {
                ADVERSARIAL_ALPHABET.iter().map(move |c| {
                    let mut w = prefix.clone();
                    w.push(*c);
                    w
                })
            })
            .collect()
    }

    #[test]
    fn path_encoding_is_injective_and_round_trips() {
        let mut seen: HashMap<String, String> = HashMap::new();
        for len in 0..=3 {
            for input in words(len) {
                let encoded = Registry::to_path_segment(&input);
                let decoded = Registry::from_path_segment(&encoded)
                    .unwrap_or_else(|e| panic!("{input:?} encoded to {encoded:?}: {e}"));
                assert_eq!(decoded, input, "round trip failed for {input:?}");
                assert!(
                    !encoded.contains(['/', ':', '#', '@']),
                    "{encoded:?} is not filename-safe"
                );
                if let Some(other) = seen.insert(encoded.clone(), input.clone()) {
                    panic!("{input:?} and {other:?} both encode to {encoded:?}");
                }
            }
        }
    }

    #[test]
    fn adversarial_pairs_stay_distinct() {
        for (left, right) in [
            ("~s", "/"),
            ("a/b", "a~sb"),
            ("tap:x", "tap/x"),
            ("~~", "~"),
        ] {
            let (l, r) = (
                Registry::to_path_segment(left),
                Registry::to_path_segment(right),
            );
            assert_ne!(l, r, "{left:?} and {right:?} collided on {l:?}");
            assert_eq!(Registry::from_path_segment(&l).unwrap(), left);
            assert_eq!(Registry::from_path_segment(&r).unwrap(), right);
        }
    }

    #[test]
    fn escaping_the_specials_first_would_collide() {
        // Why the escape character cannot be handled last: replace `/` first and the escape it
        // introduces gets escaped again, mapping two identifiers onto one segment.
        fn naive(id: &str) -> String {
            id.replace('/', "~s").replace('~', "~~")
        }
        assert_eq!(naive("a/b"), naive("a~sb"));
        assert_ne!(
            Registry::to_path_segment("a/b"),
            Registry::to_path_segment("a~sb")
        );
    }

    #[test]
    fn encoding_leaves_ordinary_characters_alone() {
        assert_eq!(Registry::to_path_segment("order_ref-1.2"), "order_ref-1.2");
        assert_eq!(Registry::to_path_segment(""), "");
        assert_eq!(Registry::from_path_segment("").unwrap(), "");
    }

    #[test]
    fn from_path_segment_rejects_what_no_encoder_emits() {
        for bad in ["a~", "~", "a~zb", "a/b", "a:b", "a#b", "a@b"] {
            assert!(
                Registry::from_path_segment(bad).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn from_path_segment_errors_quote_the_segment() {
        let err = Registry::from_path_segment("a~zb").expect_err("unknown escape");
        assert!(err.to_string().contains("a~zb"), "{err}");
    }
}
