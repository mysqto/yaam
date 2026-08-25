//! Inferring entity references from free text.
//!
//! [`entity::Registry`] answers whether a string *is* a canonical identifier. That is not the same
//! question as whether prose *meant* one: `background` is a canonical `order_ref`, `UTF-8` is a
//! canonical `ticket`, and a twelve-digit run is a canonical anything that admits digits. Shape is
//! necessary and nowhere near sufficient.
//!
//! So the bar here is precision rather than recall, and the asymmetry is the whole design. An
//! inferred reference becomes a join key: get one wrong and every question touching that key gets
//! a wrong answer, silently, because nobody reads the entity graph looking for a reference that
//! should not be there. Get one missing and a single query lacks a single fact, which the next
//! anchor added to `spec/extractors.yaml` buys back. Three gates therefore have to agree before
//! anything is emitted: the registry's own pattern, the configured shape guards, and a configured
//! keyword close enough in front of the candidate to be talking about it.
//!
//! Nothing inferred reaches [`FIELD_CONFIDENCE`]. A reference read out of a structured field is a
//! caller stating a fact and is `1.0`; a reference lifted from prose sits below
//! [`HIGH_CONFIDENCE_FLOOR`], where it is stored and searchable but not joined on by default.
//!
//! [`entity::Registry`]: crate::entity::Registry

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use saphyr::Yaml;

use crate::entity::{EntityRef, Registry, Role};
use crate::{Error, spec_yaml};

/// Confidence carried by a reference read out of a structured field.
///
/// A field states its kind, so there is nothing to infer and nothing to be wrong about.
pub const FIELD_CONFIDENCE: f32 = 1.0;

/// Confidence at or above which a reference is joined on rather than merely stored.
///
/// Published because it is what bounds a configured confidence: a rule that could reach this floor
/// would make prose indistinguishable from a structured field at exactly the point where the
/// difference starts to matter, so [`Extractor::from_yaml`] refuses one.
pub const HIGH_CONFIDENCE_FLOOR: f32 = 0.9;

/// The part an inferred reference is allowed to claim.
///
/// Never [`Role::Primary`]: a record's subject is decided by whoever wrote it, and a mention in
/// prose is evidence of relevance, not of centrality.
const INFERRED_ROLE: Role = Role::Related;

/// Largest window a rule may configure.
///
/// A window wide enough to span a paragraph is not an anchor, it is a coincidence detector.
const MAX_WINDOW: usize = 32;

/// Characters stripped from a token's edges before it is read as a candidate or as an anchor.
///
/// Sentence and layout punctuation. `.`, `:` and `-` are legal *inside* identifiers, and are
/// stripped at the edges alone — no configured pattern in the shipped spec begins or ends with one,
/// and a bullet or an em dash between an anchor and its identifier is layout rather than a word.
const EDGE_PUNCTUATION: [char; 23] = [
    '(', ')', '[', ']', '{', '}', '<', '>', '"', '\'', '`', '*', ',', '.', ';', ':', '!', '?', '|',
    '-', '\u{2014}', '\u{2013}', '\u{2026}',
];

/// A malformed `extractors.yaml`, distinct from text that yields nothing.
fn spec(detail: String) -> Error {
    Error::Spec { detail }
}

/// One word of the text, as the matcher reads it.
#[derive(Debug)]
struct Token<'a> {
    /// Edge punctuation stripped, case as written — what a candidate is tested as.
    text: &'a str,
    /// The same, case-folded — what an anchor is compared against.
    folded: String,
}

impl<'a> Token<'a> {
    /// Reads one whitespace-delimited word.
    fn new(word: &'a str) -> Self {
        let text = word.trim_matches(|c| EDGE_PUNCTUATION.contains(&c));
        Self {
            folded: text.to_lowercase(),
            text,
        }
    }
}

/// What one kind needs before a run of characters counts as a reference to it.
#[derive(Debug, Clone)]
pub struct KindRules {
    /// The entity kind, as `spec/entities.yaml` names it.
    kind: String,
    /// Case-folded keywords, any one of which anchors a candidate.
    anchors: Vec<String>,
    /// How many preceding words are searched for an anchor.
    window: usize,
    /// Confidence a match carries. Below [`HIGH_CONFIDENCE_FLOOR`] by construction.
    confidence: f32,
    /// Shape guards; every one must match the canonical identifier.
    require: Vec<Regex>,
    /// Shape refusals; none may match the canonical identifier.
    refuse: Vec<Regex>,
    /// Canonical identifiers this kind refuses however well anchored, case-folded.
    stopwords: BTreeSet<String>,
}

impl KindRules {
    /// The entity kind these rules are for.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// The configured anchors, case-folded.
    #[must_use]
    pub fn anchors(&self) -> &[String] {
        &self.anchors
    }

    /// How many preceding words are searched for an anchor.
    #[must_use]
    pub fn window(&self) -> usize {
        self.window
    }

    /// Confidence a match carries.
    #[must_use]
    pub fn confidence(&self) -> f32 {
        self.confidence
    }

    /// The canonical form of `word` if this kind admits it, ignoring context.
    ///
    /// Guards, refusals and stopwords are applied to the *canonical* form rather than to the word
    /// as written, so a rule cannot be defeated by the casing or padding a kind normalises away.
    fn candidate(&self, registry: &Registry, word: &str) -> Option<String> {
        let id = registry.canonicalise(&self.kind, word).ok()?;
        if self.stopwords.contains(&id.to_lowercase())
            || self.refuse.iter().any(|guard| guard.is_match(&id))
        {
            return None;
        }
        self.require
            .iter()
            .all(|guard| guard.is_match(&id))
            .then_some(id)
    }

    /// Distance in words back to the nearest anchor, if one is in reach.
    ///
    /// Preceding words only. English puts the keyword before the identifier often enough for that
    /// to be most of the recall, and looking forwards as well would double the surface on which a
    /// coincidence can pass for evidence.
    fn anchor_distance(&self, tokens: &[Token<'_>], at: usize) -> Option<usize> {
        (1..=self.window.min(at)).find(|back| self.anchors.contains(&tokens[at - back].folded))
    }
}

/// Words of `text`, with punctuation-only runs dropped.
///
/// A word that is nothing but punctuation is no word at all, and dropping it before distances are
/// counted stops a dash between an anchor and its identifier from consuming window.
fn tokens(text: &str) -> Vec<Token<'_>> {
    text.split_whitespace()
        .map(Token::new)
        .filter(|token| !token.text.is_empty())
        .collect()
}

/// Values a kind inherits when it does not state its own.
#[derive(Debug, Clone, Copy)]
struct Defaults {
    /// Fallback for [`KindRules::window`].
    window: usize,
    /// Fallback for [`KindRules::confidence`].
    confidence: f32,
}

impl Defaults {
    /// Reads the `defaults` section, which the spec must state.
    ///
    /// Required rather than baked in here: a default in the file and a default in the code are two
    /// spellings of one number, and the file is the one a deployment can read.
    fn read(doc: &Yaml<'_>) -> crate::Result<Self> {
        let node = doc
            .as_mapping_get("defaults")
            .ok_or_else(|| spec("spec has no `defaults` section".to_owned()))?;
        if node.as_mapping().is_none() {
            return Err(spec("spec `defaults` must be a mapping".to_owned()));
        }
        Ok(Self {
            window: read_window(node.as_mapping_get("window"), "defaults", None)?,
            confidence: read_confidence(node.as_mapping_get("confidence"), "defaults", None)?,
        })
    }
}

/// The loaded extraction rules, and the registry they canonicalise against.
///
/// Holds the registry rather than borrowing one, because the two are one configuration: rules
/// naming a kind the registry does not have are refused at load, and an extractor that could be
/// asked to canonicalise against a *different* registry afterwards would lose that guarantee.
#[derive(Debug, Clone)]
pub struct Extractor {
    /// The kinds an identifier is canonicalised and validated against.
    registry: Registry,
    /// Rules in kind-name order.
    kinds: Vec<KindRules>,
}

impl Extractor {
    /// Loads rules from `extractors.yaml` content.
    ///
    /// Every kind named must be one the registry configures, every rule must carry at least one
    /// anchor, and every confidence must sit below [`HIGH_CONFIDENCE_FLOOR`]. All three are load
    /// failures rather than silent no-ops: a rule that cannot fire, and a rule that fires too
    /// confidently, are both invisible once the file is deployed.
    ///
    /// # Examples
    /// ```
    /// use yaam_contract::entity::Registry;
    /// use yaam_contract::extract::Extractor;
    ///
    /// let registry = Registry::from_yaml(
    ///     "kinds:\n  ticket:\n    pattern: '^[A-Z][A-Z0-9]+-[0-9]+$'\n    normalise: [trim, uppercase_prefix]\n",
    /// )?;
    /// let extractor = Extractor::from_yaml(
    ///     registry,
    ///     concat!(
    ///         "defaults:\n  window: 4\n  confidence: 0.7\n",
    ///         "kinds:\n  ticket:\n    anchors: [ticket, issue]\n",
    ///     ),
    /// )?;
    ///
    /// let found = extractor.from_text("reopened the ticket proj-42 this morning");
    /// assert_eq!(found[0].id, "PROJ-42");
    /// // Inferred, so it is stored without being joined on by a high-confidence query.
    /// assert!(found[0].confidence < 0.9);
    ///
    /// // The same identifier with nothing vouching for it stays out of the graph.
    /// assert!(extractor.from_text("proj-42 came up again").is_empty());
    /// # Ok::<(), yaam_contract::Error>(())
    /// ```
    pub fn from_yaml(registry: Registry, yaml: &str) -> crate::Result<Self> {
        let doc = spec_yaml::single_document(yaml)?;
        spec_yaml::check_version(&doc)?;
        let defaults = Defaults::read(&doc)?;

        let mut kinds = BTreeMap::new();
        for (key, value) in spec_yaml::required_mapping(&doc, "kinds")? {
            let name = spec_yaml::key_name(key, "extractor kind")?;
            // Reuse rather than re-state: the registry already knows which kinds exist, and a rule
            // for a kind it does not have could only ever produce an unjoinable reference.
            if !registry.kinds().iter().any(|kind| kind.name == name) {
                return Err(Error::UnknownEntityKind(name.to_owned()));
            }
            kinds.insert(
                name.to_owned(),
                read_rules(name, value, &defaults, &registry)?,
            );
        }
        Ok(Self {
            registry,
            kinds: kinds.into_values().collect(),
        })
    }

    /// The registry these rules canonicalise against.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Every configured rule, in kind-name order.
    ///
    /// A kind absent from the listing is never inferred, which is the question an operator asks of
    /// this file first.
    #[must_use]
    pub fn kinds(&self) -> &[KindRules] {
        &self.kinds
    }

    /// Entity references inferred from free text, in order of first appearance.
    ///
    /// Deduplicated by kind and identifier: a body naming an entity three times is three pieces of
    /// evidence for one join key, not three keys. Each carries [`Role::Related`] — prose that
    /// mentions an entity is evidence of relevance, not a claim about what the record is *about*.
    ///
    /// A word two kinds claim with equally near anchors is dropped rather than guessed at. Two
    /// kinds in the shipped spec share one pattern, so the anchor is the only thing separating
    /// them; where it separates nothing, a coin toss would put a plausible wrong key in the index.
    #[must_use]
    pub fn from_text(&self, text: &str) -> Vec<EntityRef> {
        let tokens = tokens(text);

        let mut found: Vec<EntityRef> = Vec::new();
        for at in 0..tokens.len() {
            let Some(entity) = self.resolve(&tokens, at) else {
                continue;
            };
            if !found
                .iter()
                .any(|seen| seen.kind == entity.kind && seen.id == entity.id)
            {
                found.push(entity);
            }
        }
        found
    }

    /// Entity references read out of a *question*, where nothing has to vouch for them.
    ///
    /// The same rules as [`Self::from_text`] minus the anchor: pattern, `require`, `refuse` and
    /// `stopwords` all still apply, and a kind with no rule is still never inferred — that is what
    /// keeps a kind whose pattern admits any ordinary word out of this entirely.
    ///
    /// # Why the anchor goes
    ///
    /// An anchor is evidence, and evidence is what the write path needs: a reference inferred there
    /// *becomes* a stored join key, and a wrong key is a wrong answer to every later question that
    /// touches it, silently. A key built for a lookup is the opposite kind of object. It is matched
    /// against what records state and then discarded; a wrong one asks about an entity nobody wrote
    /// anything under and costs one lookup that returns nothing.
    ///
    /// So requiring evidence for a lookup buys nothing and loses answers. `any knowledge about this?
    /// WUPGHGJ7ELJM626` carries no anchor a rule would recognise and every reader would call it a
    /// booking; anchored extraction reads it as prose about nothing.
    ///
    /// # Where [`Self::from_text`] drops, this keeps both
    ///
    /// Two kinds sharing one pattern are told apart by their anchors, so with the anchors gone they
    /// cannot be told apart at all. Both keys are returned rather than neither: for a lookup the
    /// wrong one matches nothing, which is a cost worth paying to stop the right one being dropped.
    /// The returned confidences are the rules' own and mean nothing to a lookup, which matches on
    /// the identifier alone.
    #[must_use]
    pub fn from_query(&self, text: &str) -> Vec<EntityRef> {
        let mut found: Vec<EntityRef> = Vec::new();
        for token in tokens(text) {
            for rules in &self.kinds {
                let Some(id) = rules.candidate(&self.registry, token.text) else {
                    continue;
                };
                if !found
                    .iter()
                    .any(|seen| seen.kind == rules.kind && seen.id == id)
                {
                    found.push(EntityRef {
                        kind: rules.kind.clone(),
                        id,
                        role: INFERRED_ROLE,
                        confidence: rules.confidence,
                    });
                }
            }
        }
        found
    }

    /// An entity reference read out of a structured field.
    ///
    /// Any kind the registry configures, not only the ones with extraction rules: a field naming
    /// its kind needs no evidence beyond canonicalisation, which is why this is the path that
    /// reaches [`FIELD_CONFIDENCE`].
    ///
    /// # Errors
    /// If the kind is unknown, or the value is not canonical for it.
    pub fn from_field(&self, kind: &str, value: &str, role: Role) -> crate::Result<EntityRef> {
        Ok(EntityRef {
            id: self.registry.canonicalise(kind, value)?,
            kind: kind.to_owned(),
            role,
            confidence: FIELD_CONFIDENCE,
        })
    }

    /// The one reference the word at `at` supports, if the kinds agree on which.
    fn resolve(&self, tokens: &[Token<'_>], at: usize) -> Option<EntityRef> {
        let mut best: Option<(usize, EntityRef)> = None;
        let mut tied = false;
        for rules in &self.kinds {
            let Some(id) = rules.candidate(&self.registry, tokens[at].text) else {
                continue;
            };
            let Some(distance) = rules.anchor_distance(tokens, at) else {
                continue;
            };
            match best {
                Some((nearest, _)) if nearest < distance => {}
                Some((nearest, _)) if nearest == distance => tied = true,
                _ => {
                    best = Some((
                        distance,
                        EntityRef {
                            kind: rules.kind.clone(),
                            id,
                            role: INFERRED_ROLE,
                            confidence: rules.confidence,
                        },
                    ));
                    tied = false;
                }
            }
        }
        if tied {
            return None;
        }
        best.map(|(_, entity)| entity)
    }
}

/// Reads one kind's rules, inheriting what it does not state.
fn read_rules(
    name: &str,
    node: &Yaml<'_>,
    defaults: &Defaults,
    registry: &Registry,
) -> crate::Result<KindRules> {
    let anchors = string_list(node.as_mapping_get("anchors"), "anchors", name)?;
    if anchors.is_empty() {
        return Err(spec(format!(
            "extractor kind `{name}` has no anchors, so it would match on shape alone"
        )));
    }
    let mut folded = Vec::with_capacity(anchors.len());
    for anchor in anchors {
        if anchor.split_whitespace().count() != 1 {
            return Err(spec(format!(
                "extractor kind `{name}` has an anchor that is not a single word: `{anchor}`"
            )));
        }
        folded.push(anchor.to_lowercase());
    }

    // Unanchored on purpose: a guard says what a candidate must or must not *contain*. The kind's
    // own pattern, which the registry anchors, is what says what it must *be*.
    let require = guards(node.as_mapping_get("require"), "require", name)?;
    let refuse = guards(node.as_mapping_get("refuse"), "refuse", name)?;

    let mut stopwords = BTreeSet::new();
    for word in string_list(node.as_mapping_get("stopwords"), "stopwords", name)? {
        // A stopword that the kind would never admit anyway is a typo or a stale entry, and either
        // way it is a rule that reads as protection while protecting nothing.
        if registry.canonicalise(name, &word).is_err() {
            return Err(spec(format!(
                "extractor kind `{name}` lists stopword `{word}`, which the kind cannot match"
            )));
        }
        stopwords.insert(word.to_lowercase());
    }

    Ok(KindRules {
        kind: name.to_owned(),
        anchors: folded,
        window: read_window(node.as_mapping_get("window"), name, Some(defaults.window))?,
        confidence: read_confidence(
            node.as_mapping_get("confidence"),
            name,
            Some(defaults.confidence),
        )?,
        require,
        refuse,
        stopwords,
    })
}

/// Compiles one list of shape guards.
fn guards(node: Option<&Yaml<'_>>, field: &str, owner: &str) -> crate::Result<Vec<Regex>> {
    string_list(node, field, owner)?
        .into_iter()
        .map(|pattern| {
            Regex::new(&pattern).map_err(|e| {
                spec(format!(
                    "extractor kind `{owner}` has an unusable `{field}` pattern `{pattern}`: {e}"
                ))
            })
        })
        .collect()
}

/// Reads a window, falling back to `inherited` when absent.
fn read_window(
    node: Option<&Yaml<'_>>,
    owner: &str,
    inherited: Option<usize>,
) -> crate::Result<usize> {
    let Some(node) = node else {
        return inherited.ok_or_else(|| spec(format!("`{owner}` has no `window`")));
    };
    let width = node
        .as_integer()
        .ok_or_else(|| spec(format!("`{owner}` has a non-integer `window`")))?;
    match usize::try_from(width) {
        Ok(width) if (1..=MAX_WINDOW).contains(&width) => Ok(width),
        _ => Err(spec(format!(
            "`{owner}` has a `window` of {width}, outside 1..={MAX_WINDOW}"
        ))),
    }
}

/// Reads a confidence, falling back to `inherited` when absent.
///
/// The upper bound is the point of the check: an inferred reference that reads as confidently as
/// one from a structured field defeats every filter downstream that exists to tell them apart.
fn read_confidence(
    node: Option<&Yaml<'_>>,
    owner: &str,
    inherited: Option<f32>,
) -> crate::Result<f32> {
    let Some(node) = node else {
        return inherited.ok_or_else(|| spec(format!("`{owner}` has no `confidence`")));
    };
    // A whole number is a legal YAML spelling of a confidence and never a legal value of one: the
    // only integers in reach are `0` and `1`, and both are outside the range this check enforces.
    if let Some(whole) = node.as_integer() {
        return Err(out_of_range(owner, &whole.to_string()));
    }
    let written = node
        .as_floating_point()
        .ok_or_else(|| spec(format!("`{owner}` has a non-numeric `confidence`")))?;
    // Re-read the decimal as `f32` rather than narrowing the `f64` the parser built: the wire
    // carries `f32`, and the nearest `f32` to what the file says is not always the nearest `f32` to
    // the nearest `f64` to what the file says. `.nan` re-reads as NaN and fails the range check.
    let confidence: f32 = written.to_string().parse().unwrap_or(f32::NAN);
    if confidence > 0.0 && confidence < HIGH_CONFIDENCE_FLOOR {
        Ok(confidence)
    } else {
        Err(out_of_range(owner, &confidence.to_string()))
    }
}

/// The one confidence failure worth its own spelling, since two paths reach it.
fn out_of_range(owner: &str, value: &str) -> Error {
    spec(format!(
        "`{owner}` has a `confidence` of {value}, outside 0.0 < c < {HIGH_CONFIDENCE_FLOOR}"
    ))
}

/// Reads an optional list of strings. Absent is empty.
fn string_list(node: Option<&Yaml<'_>>, field: &str, owner: &str) -> crate::Result<Vec<String>> {
    let Some(node) = node else {
        return Ok(Vec::new());
    };
    let items = node
        .as_vec()
        .ok_or_else(|| spec(format!("extractor kind `{owner}` has a non-list `{field}`")))?;
    items
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                spec(format!(
                    "extractor kind `{owner}` has a non-string entry in `{field}`"
                ))
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kinds the workspace ships.
    const ENTITIES: &str = include_str!("../../../spec/entities.yaml");

    /// The rules the workspace ships, so a spec edit that breaks one fails here.
    const EXTRACTORS: &str = include_str!("../../../spec/extractors.yaml");

    fn shipped() -> Extractor {
        let registry = Registry::from_yaml(ENTITIES).expect("the shipped kinds load");
        Extractor::from_yaml(registry, EXTRACTORS).expect("the shipped rules load")
    }

    /// A two-kind registry for tests that need a shape to be ambiguous.
    fn registry(yaml: &str) -> Registry {
        Registry::from_yaml(yaml).expect("the test registry loads")
    }

    /// One kind, one anchor, everything else defaulted.
    fn simple() -> Extractor {
        Extractor::from_yaml(
            registry("kinds:\n  ticket:\n    pattern: '^[A-Z][A-Z0-9]+-[0-9]+$'\n    normalise: [trim, uppercase_prefix]\n"),
            "defaults:\n  window: 4\n  confidence: 0.7\nkinds:\n  ticket:\n    anchors: [ticket]\n",
        )
        .expect("the test rules load")
    }

    /// `kind:id` for every reference found, which is how the corpus test reads them too.
    fn found(extractor: &Extractor, text: &str) -> Vec<String> {
        extractor
            .from_text(text)
            .iter()
            .map(|entity| format!("{}:{}", entity.kind, entity.id))
            .collect()
    }

    #[test]
    fn an_anchor_is_what_turns_a_shape_into_a_reference() {
        let extractor = simple();
        assert_eq!(found(&extractor, "ticket PROJ-42"), ["ticket:PROJ-42"]);
        // The same characters, the same pattern, no anchor: nothing.
        assert!(found(&extractor, "PROJ-42 came up again").is_empty());
        assert!(found(&extractor, "the release PROJ-42").is_empty());
    }

    #[test]
    fn the_window_is_the_edge_it_says_it_is() {
        let extractor = simple();
        assert_eq!(
            found(&extractor, "ticket one two three PROJ-42"),
            ["ticket:PROJ-42"],
            "an anchor exactly at the window must count"
        );
        assert!(
            found(&extractor, "ticket one two three four PROJ-42").is_empty(),
            "one word further is out of reach"
        );
    }

    #[test]
    fn an_anchor_after_the_identifier_does_not_count() {
        // A known recall cost, asserted so that changing it is a decision rather than an accident.
        assert!(found(&simple(), "PROJ-42 is the ticket").is_empty());
    }

    #[test]
    fn a_reference_named_twice_is_one_join_key() {
        assert_eq!(
            found(&simple(), "ticket PROJ-42, and again ticket PROJ-42"),
            ["ticket:PROJ-42"]
        );
    }

    #[test]
    fn an_inferred_reference_is_related_and_below_the_high_confidence_floor() {
        let [entity] = simple()
            .from_text("ticket PROJ-42")
            .try_into()
            .expect("one");
        assert_eq!(entity.role, Role::Related);
        assert_eq!(entity.confidence.to_bits(), 0.7_f32.to_bits());
        assert!(entity.confidence < HIGH_CONFIDENCE_FLOOR);
        assert!(entity.confidence < FIELD_CONFIDENCE);
    }

    #[test]
    fn edge_punctuation_is_stripped_and_a_bare_mark_is_not_a_word() {
        let extractor = simple();
        for text in [
            "ticket \"PROJ-42\"",
            "(ticket PROJ-42).",
            "*ticket* PROJ-42!",
            "| ticket | PROJ-42 |",
            "ticket \u{2014} PROJ-42",
            "- ticket: PROJ-42;",
        ] {
            assert_eq!(found(&extractor, text), ["ticket:PROJ-42"], "{text:?}");
        }
        // A dash between anchor and identifier is layout, so it must not consume the window.
        assert_eq!(
            found(&extractor, "ticket - - - - PROJ-42"),
            ["ticket:PROJ-42"]
        );
    }

    #[test]
    fn text_is_read_across_lines_and_runs_of_whitespace() {
        assert_eq!(
            found(&simple(), "the ticket\n\n  PROJ-42\twas closed"),
            ["ticket:PROJ-42"]
        );
    }

    #[test]
    fn nothing_at_all_yields_nothing() {
        let extractor = simple();
        for text in ["", "   ", "\n", "...", "no identifiers here"] {
            assert!(found(&extractor, text).is_empty(), "{text:?}");
        }
    }

    #[test]
    fn a_stopword_is_refused_however_well_anchored() {
        let extractor = Extractor::from_yaml(
            registry("kinds:\n  ticket:\n    pattern: '^[A-Z][A-Z0-9]+-[0-9]+$'\n    normalise: [trim, uppercase_prefix]\n"),
            concat!(
                "defaults:\n  window: 4\n  confidence: 0.7\n",
                "kinds:\n  ticket:\n    anchors: [ticket]\n    stopwords: [utf-8]\n",
            ),
        )
        .unwrap();
        assert!(found(&extractor, "the ticket UTF-8").is_empty());
        // Case-folded against the canonical form, so the casing in the text cannot evade it.
        assert!(found(&extractor, "the ticket utf-8").is_empty());
        assert_eq!(found(&extractor, "the ticket UTF-9"), ["ticket:UTF-9"]);
    }

    #[test]
    fn shape_guards_admit_and_refuse_by_content() {
        let extractor = Extractor::from_yaml(
            registry("kinds:\n  order_ref:\n    pattern: '^[a-z0-9]{8,24}$'\n    normalise: [trim, lowercase]\n"),
            concat!(
                "defaults:\n  window: 4\n  confidence: 0.6\n",
                "kinds:\n  order_ref:\n    anchors: [order]\n",
                "    require: ['[a-z]', '[0-9]']\n    refuse: ['^[0-9]+[a-z]+$']\n",
            ),
        )
        .unwrap();
        assert_eq!(found(&extractor, "order ab12cd34"), ["order_ref:ab12cd34"]);
        assert!(found(&extractor, "order javascript").is_empty(), "no digit");
        assert!(
            found(&extractor, "order 170000000000").is_empty(),
            "no letter"
        );
        assert!(
            found(&extractor, "order 1250items").is_empty(),
            "a quantity"
        );
    }

    #[test]
    fn two_kinds_claiming_one_word_equally_are_both_dropped() {
        // The shipped spec has two kinds with one pattern, so this is not a hypothetical. Where
        // the anchor separates them the nearer one wins; where it does not, a guess would be a
        // plausible wrong join key, which is the one outcome worse than no key at all.
        let extractor = Extractor::from_yaml(
            registry(concat!(
                "kinds:\n",
                "  pull_request:\n    pattern: '^[a-z0-9._-]+/[a-z0-9._-]+#[0-9]+$'\n    normalise: [trim, lowercase_path]\n",
                "  deploy:\n    pattern: '^[a-z0-9._-]+/[a-z0-9._-]+#[0-9]+$'\n    normalise: [trim, lowercase]\n",
            )),
            concat!(
                "defaults:\n  window: 4\n  confidence: 0.7\n",
                "kinds:\n",
                "  pull_request:\n    anchors: [merged, shipped]\n",
                "  deploy:\n    anchors: [deployed, shipped]\n",
            ),
        )
        .unwrap();
        assert_eq!(
            found(&extractor, "merged owner/repo#7"),
            ["pull_request:owner/repo#7"]
        );
        assert_eq!(
            found(&extractor, "deployed api/prod#12"),
            ["deploy:api/prod#12"]
        );
        // `shipped` anchors both at the same distance.
        assert!(found(&extractor, "shipped api/prod#12").is_empty());
        // The nearer anchor decides, whichever kind it belongs to.
        assert_eq!(
            found(&extractor, "merged and then deployed api/prod#12"),
            ["deploy:api/prod#12"]
        );
        assert_eq!(
            found(&extractor, "deployed and then merged api/prod#12"),
            ["pull_request:api/prod#12"]
        );
    }

    #[test]
    fn a_field_is_worth_more_than_prose() {
        let extractor = shipped();
        let entity = extractor
            .from_field("ticket", " proj-42 ", Role::Primary)
            .expect("canonical");
        assert_eq!(entity.id, "PROJ-42");
        assert_eq!(entity.role, Role::Primary);
        assert_eq!(entity.confidence.to_bits(), FIELD_CONFIDENCE.to_bits());

        // Any configured kind, including the ones deliberately left out of the extraction rules:
        // a field states its kind, so there is nothing left to infer.
        assert!(extractor.kinds().iter().all(|r| r.kind() != "chat_user"));
        assert_eq!(
            extractor
                .from_field("chat_user", " member.01 ", Role::Context)
                .expect("canonical")
                .id,
            "member.01"
        );

        assert!(matches!(
            extractor.from_field("no_such_kind", "x", Role::Related),
            Err(Error::UnknownEntityKind(_))
        ));
        assert!(matches!(
            extractor.from_field("ticket", "not a key", Role::Related),
            Err(Error::NotCanonical { .. })
        ));
    }

    #[test]
    fn a_rule_may_override_the_defaults_it_inherits() {
        let extractor = Extractor::from_yaml(
            registry(concat!(
                "kinds:\n",
                "  ticket:\n    pattern: '^[A-Z][A-Z0-9]+-[0-9]+$'\n    normalise: [trim, uppercase_prefix]\n",
                "  order_ref:\n    pattern: '^[a-z0-9]{8,24}$'\n    normalise: [trim, lowercase]\n",
            )),
            concat!(
                "defaults:\n  window: 2\n  confidence: 0.7\n",
                "kinds:\n",
                "  order_ref:\n    anchors: [order]\n    window: 6\n    confidence: 0.6\n",
                "  ticket:\n    anchors: [ticket]\n",
            ),
        )
        .unwrap();
        let (order, ticket) = (&extractor.kinds()[0], &extractor.kinds()[1]);
        assert_eq!((order.kind(), order.window()), ("order_ref", 6));
        assert_eq!(order.confidence().to_bits(), 0.6_f32.to_bits());
        assert_eq!((ticket.kind(), ticket.window()), ("ticket", 2));
        assert_eq!(ticket.confidence().to_bits(), 0.7_f32.to_bits());
        assert_eq!(ticket.anchors(), ["ticket"]);
        // The wider window is the kind's own, not the default's.
        assert_eq!(
            found(&extractor, "order one two three four five ab12cd34"),
            ["order_ref:ab12cd34"]
        );
        assert!(found(&extractor, "ticket one two PROJ-42").is_empty());
    }

    #[test]
    fn anchors_are_matched_case_folded_and_whole() {
        let extractor = simple();
        assert_eq!(found(&extractor, "TICKET PROJ-42"), ["ticket:PROJ-42"]);
        assert_eq!(found(&extractor, "Ticket PROJ-42"), ["ticket:PROJ-42"]);
        // A word that merely contains the anchor is not the anchor.
        assert!(found(&extractor, "ticketing PROJ-42").is_empty());
    }

    #[test]
    fn the_registry_travels_with_the_rules() {
        assert!(
            shipped()
                .registry()
                .kinds()
                .iter()
                .any(|k| k.name == "ticket")
        );
    }

    #[test]
    fn an_explicit_wikilink_is_not_re_derived_at_a_lower_confidence() {
        // `[[kind:id]]` is a caller declaring a reference, and it is parsed elsewhere. What matters
        // here is that this module does not also emit a second, weaker copy of the same key.
        assert!(found(&shipped(), "closed [[ticket:PROJ-42]] today").is_empty());
    }

    #[test]
    fn the_shipped_rules_name_only_configured_kinds_and_stay_under_the_floor() {
        let extractor = shipped();
        let registry = extractor.registry();
        for rules in extractor.kinds() {
            let kind = rules.kind();
            let configured = registry.kinds().iter().any(|k| k.name == kind);
            assert!(configured, "`{kind}` is not a configured kind");
            assert!(!rules.anchors().is_empty(), "`{kind}` has no anchors");
            let joinable = rules.confidence() >= HIGH_CONFIDENCE_FLOOR;
            assert!(!joinable, "`{kind}` would be joined on");
        }
    }

    #[test]
    fn a_standards_name_the_denylist_misses_is_the_known_precision_limit() {
        // Recorded rather than hidden: tracker keys and standards names have the same shape, so the
        // only defence is the list in `spec/extractors.yaml`, and the list is over an open class.
        // What bounds the damage is the confidence, which keeps this out of every default join.
        let [entity] = shipped()
            .from_text("the issue is BLAKE-3 support")
            .try_into()
            .expect("one, wrongly");
        assert_eq!(
            (entity.kind.as_str(), entity.id.as_str()),
            ("ticket", "BLAKE-3")
        );
        assert!(entity.confidence < HIGH_CONFIDENCE_FLOOR);
    }

    #[test]
    fn rules_for_a_kind_the_registry_does_not_configure_are_refused() {
        let err = Extractor::from_yaml(
            registry("kinds:\n  ticket:\n    pattern: '^[A-Z]+-[0-9]+$'\n"),
            "defaults:\n  window: 4\n  confidence: 0.7\nkinds:\n  invented:\n    anchors: [x]\n",
        )
        .expect_err("no such kind");
        assert!(matches!(err, Error::UnknownEntityKind(ref k) if k == "invented"));
    }

    #[test]
    fn a_stopword_the_kind_cannot_match_is_a_spec_failure() {
        // A stopword that could never fire reads as protection while protecting nothing.
        let err = Extractor::from_yaml(
            registry("kinds:\n  ticket:\n    pattern: '^[A-Z]+-[0-9]+$'\n"),
            "defaults:\n  window: 4\n  confidence: 0.7\nkinds:\n  ticket:\n    anchors: [t]\n    stopwords: [not-a-key]\n",
        )
        .expect_err("the stopword cannot match");
        assert!(err.to_string().contains("not-a-key"), "{err}");
    }

    /// Asserts that each spec is refused as misconfiguration rather than loaded.
    fn all_refused(cases: &[(&str, String)]) {
        let entities = "kinds:\n  ticket:\n    pattern: '^[A-Z]+-[0-9]+$'\n";
        for (label, yaml) in cases {
            let loaded = Extractor::from_yaml(registry(entities), yaml);
            assert!(matches!(loaded, Err(Error::Spec { .. })), "{label} stands");
        }
    }

    #[test]
    fn from_yaml_rejects_malformed_defaults() {
        all_refused(&[
            ("not yaml", "kinds: [\n".to_owned()),
            (
                "no defaults",
                "kinds:\n  ticket:\n    anchors: [t]\n".to_owned(),
            ),
            (
                "defaults not a mapping",
                "defaults: []\nkinds: {}\n".to_owned(),
            ),
            (
                "no window",
                "defaults:\n  confidence: 0.7\nkinds: {}\n".to_owned(),
            ),
            (
                "no confidence",
                "defaults:\n  window: 4\nkinds: {}\n".to_owned(),
            ),
            (
                "window not an integer",
                "defaults:\n  window: wide\n  confidence: 0.7\nkinds: {}\n".to_owned(),
            ),
            (
                "window of zero",
                "defaults:\n  window: 0\n  confidence: 0.7\nkinds: {}\n".to_owned(),
            ),
            (
                "negative window",
                "defaults:\n  window: -1\n  confidence: 0.7\nkinds: {}\n".to_owned(),
            ),
            (
                "window too wide",
                format!(
                    "defaults:\n  window: {}\n  confidence: 0.7\nkinds: {{}}\n",
                    MAX_WINDOW + 1
                ),
            ),
            (
                "confidence not numeric",
                "defaults:\n  window: 4\n  confidence: high\nkinds: {}\n".to_owned(),
            ),
            (
                "confidence of zero",
                "defaults:\n  window: 4\n  confidence: 0.0\nkinds: {}\n".to_owned(),
            ),
            (
                "confidence at the floor",
                "defaults:\n  window: 4\n  confidence: 0.9\nkinds: {}\n".to_owned(),
            ),
            (
                "confidence of one",
                "defaults:\n  window: 4\n  confidence: 1\nkinds: {}\n".to_owned(),
            ),
        ]);
    }

    #[test]
    fn from_yaml_rejects_malformed_kinds() {
        let head = "defaults:\n  window: 4\n  confidence: 0.7\n";
        all_refused(&[
            ("no kinds", head.to_owned()),
            ("kinds not a mapping", format!("{head}kinds: []\n")),
            (
                "non-string kind name",
                format!("{head}kinds:\n  1:\n    anchors: [t]\n"),
            ),
            // A rule with no anchor would match on shape alone, which is the failure this module
            // exists to prevent — so it is refused rather than left quietly matching everything.
            (
                "no anchors at all",
                format!("{head}kinds:\n  ticket:\n    stopwords: [PROJ-1]\n"),
            ),
            (
                "anchors not a list",
                format!("{head}kinds:\n  ticket:\n    anchors: t\n"),
            ),
            (
                "anchor not a string",
                format!("{head}kinds:\n  ticket:\n    anchors: [1]\n"),
            ),
            (
                "anchor of two words",
                format!("{head}kinds:\n  ticket:\n    anchors: ['the ticket']\n"),
            ),
            (
                "anchor of no words",
                format!("{head}kinds:\n  ticket:\n    anchors: ['']\n"),
            ),
            (
                "unusable require",
                format!("{head}kinds:\n  ticket:\n    anchors: [t]\n    require: ['[']\n"),
            ),
            (
                "unusable refuse",
                format!("{head}kinds:\n  ticket:\n    anchors: [t]\n    refuse: ['[']\n"),
            ),
            (
                "require not a list",
                format!("{head}kinds:\n  ticket:\n    anchors: [t]\n    require: '[0-9]'\n"),
            ),
            (
                "per-kind window of zero",
                format!("{head}kinds:\n  ticket:\n    anchors: [t]\n    window: 0\n"),
            ),
            (
                "per-kind confidence of one",
                format!("{head}kinds:\n  ticket:\n    anchors: [t]\n    confidence: 1.0\n"),
            ),
            (
                "future version",
                format!("version: 99\n{head}kinds: {{}}\n"),
            ),
        ]);
    }

    /// The case that sent this method into being: a real question, with no anchor in it.
    #[test]
    fn a_question_needs_no_anchor() {
        let unanchored = "any knowledge abou this? PROJ-42";
        assert!(
            simple().from_text(unanchored).is_empty(),
            "the write path requires evidence, and this carries none"
        );
        let asked = simple().from_query(unanchored);
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].id, "PROJ-42");
    }

    /// Everything except the anchor still refuses.
    #[test]
    fn a_query_still_obeys_pattern_require_refuse_and_stopwords() {
        let extractor = Extractor::from_yaml(
            registry("kinds:\n  ref:\n    pattern: '^[a-z0-9]{4,12}$'\n    normalise: [trim, lowercase]\n"),
            concat!(
                "defaults:\n  window: 4\n  confidence: 0.7\n",
                "kinds:\n  ref:\n    anchors: [ref]\n    require: ['[0-9]']\n",
                "    refuse: ['^[0-9]+[a-z]+$']\n    stopwords: [utf8bom]\n",
            ),
        )
        .expect("the test rules load");

        let found: Vec<String> = extractor
            .from_query("p60y9 background 12items utf8bom")
            .into_iter()
            .map(|entity| entity.id)
            .collect();
        assert_eq!(
            found,
            vec!["p60y9".to_owned()],
            "only the candidate that clears every guard"
        );
    }

    /// A kind with no rule is not inferable, and a question does not change that. This is what keeps
    /// a pattern admitting any ordinary word from turning every word into a key.
    #[test]
    fn a_kind_with_no_rule_is_never_asked_about() {
        let asked = shipped().from_query("the user reported a fault in checkout");
        assert!(
            asked.iter().all(|entity| entity.kind != "chat_user"),
            "chat_user has no rule and must stay out: {asked:?}"
        );
    }

    /// Where `from_text` drops an ambiguous shape, a query keeps both candidates: the wrong key
    /// matches nothing, and dropping would lose the right one too.
    #[test]
    fn an_ambiguous_shape_yields_every_candidate_kind() {
        let extractor = Extractor::from_yaml(
            registry(concat!(
                "kinds:\n",
                "  one:\n    pattern: '^[a-z]+/[a-z]+#[0-9]+$'\n    normalise: [trim, lowercase]\n",
                "  two:\n    pattern: '^[a-z]+/[a-z]+#[0-9]+$'\n    normalise: [trim, lowercase]\n",
            )),
            concat!(
                "defaults:\n  window: 4\n  confidence: 0.7\n",
                "kinds:\n  one:\n    anchors: [shipped]\n  two:\n    anchors: [shipped]\n",
            ),
        )
        .expect("the test rules load");

        assert!(
            extractor.from_text("shipped svc/prod#7").is_empty(),
            "one anchor, two kinds, one distance: a tie the write path drops"
        );
        let mut kinds: Vec<String> = extractor
            .from_query("svc/prod#7")
            .into_iter()
            .map(|entity| entity.kind)
            .collect();
        kinds.sort();
        assert_eq!(kinds, vec!["one".to_owned(), "two".to_owned()]);
    }

    /// One mention, one key, however many times it is written.
    #[test]
    fn a_query_deduplicates_its_keys() {
        assert_eq!(simple().from_query("PROJ-42 PROJ-42 proj-42").len(), 1);
    }

    /// The shipped rules, on a bare identifier with nothing vouching for it.
    ///
    /// `PAY-2087` unanchored is the whole point: `from_text` reads it as prose and returns nothing,
    /// because a tracker key is exactly the shape a standards name has.
    #[test]
    fn the_shipped_rules_read_a_bare_identifier() {
        assert!(shipped().from_text("PAY-2087").is_empty());
        let asked: Vec<String> = shipped()
            .from_query("PAY-2087")
            .into_iter()
            .map(|entity| format!("{}:{}", entity.kind, entity.id))
            .collect();
        assert!(asked.contains(&"ticket:PAY-2087".to_owned()), "{asked:?}");
    }

    #[test]
    fn error_messages_name_what_is_wrong() {
        let entities = "kinds:\n  ticket:\n    pattern: '^[A-Z]+-[0-9]+$'\n";
        for (yaml, needle) in [
            (
                "defaults:\n  window: 99\n  confidence: 0.7\nkinds: {}\n",
                "outside 1..=32",
            ),
            (
                "defaults:\n  window: 4\n  confidence: 0.95\nkinds: {}\n",
                "0.9",
            ),
            (
                "defaults:\n  window: 4\n  confidence: 0.7\nkinds:\n  ticket:\n    anchors: [t]\n    require: ['(']\n",
                "unusable `require`",
            ),
            (
                "defaults:\n  window: 4\n  confidence: 0.7\nkinds:\n  ticket:\n    anchors: [t]\n    refuse: ['(']\n",
                "unusable `refuse`",
            ),
            (
                "defaults:\n  window: 4\n  confidence: 0.7\nkinds:\n  ticket:\n    anchors: []\n",
                "shape alone",
            ),
        ] {
            let err = Extractor::from_yaml(registry(entities), yaml).expect_err(yaml);
            assert!(err.to_string().contains(needle), "{err} lacks {needle}");
        }
    }
}
