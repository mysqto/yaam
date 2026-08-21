//! The lockstep rule: four shapes, one record.
//!
//! The wire record, the Markdown frontmatter (`yaam-md`), the columns of the store's record table
//! (`yaam-store`) and [`RecordStructure`] — what a read hands back — are projections of
//! [`ActionRecord`]. Divergence between them is not a cosmetic problem: a frontmatter key no field
//! feeds is a value no `yaam reindex` can recover, and a column no field feeds breaks invariant 2
//! outright.
//!
//! The read projection is the strict one. It must be the frontmatter key set exactly, and
//! [`EXEMPTIONS`] cannot excuse a divergence there, because the read shape is the whole of "a caller
//! receives structure and never a body": a key it dropped is structure the design promised and no
//! caller can ask for, and a key it added is a value frontmatter does not hold.
//!
//! The rule used to be enforced by review, and review missed it twice — `redaction` was an object
//! on the wire and a scalar in frontmatter, and `backfilled` was a column and a paragraph of prose
//! with no field anywhere behind it. Both were caught by a person noticing, which is not a
//! mechanism. This module is the mechanism. It compares sets of names, so it lives here, in the
//! crate that owns the record; the crates that own the other two shapes hand it their own
//! enumerations rather than being described from a distance.
//!
//! Where the three shapes are *meant* to differ, [`EXEMPTIONS`] says so and says why. That list is
//! the only way past the check, so adding a divergence is a visible edit to a table of reasons.
//!
//! [`ActionRecord`]: crate::ActionRecord
//! [`RecordStructure`]: crate::RecordStructure

use std::collections::BTreeSet;
use std::fmt;

use serde_json::Value as Json;

/// Which comparison an exemption excuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// A wire field that is deliberately not a frontmatter key.
    WireOnly,
    /// A frontmatter key that deliberately has no field on the wire record.
    FrontmatterOnly,
    /// A column of the record table that is deliberately not named after a wire field.
    Column {
        /// The wire field it is computed from, or `None` when it is computed from the record as a
        /// whole.
        ///
        /// Named rather than left implicit: an exemption that pointed at nothing would go on
        /// excusing the column after the field it projects had been renamed away.
        from: Option<&'static str>,
    },
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WireOnly => f.write_str("a wire field with no frontmatter key"),
            Self::FrontmatterOnly => f.write_str("a frontmatter key with no wire field"),
            Self::Column { from: Some(field) } => write!(f, "a column projected from `{field}`"),
            Self::Column { from: None } => f.write_str("a column projected from the whole record"),
        }
    }
}

/// One place the three shapes are allowed to disagree, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exemption {
    /// The field, key or column name the check would otherwise report.
    pub name: &'static str,
    /// Which comparison it excuses.
    pub side: Side,
    /// Why the divergence is intended. Written for whoever adds the next one.
    pub reason: &'static str,
}

/// Every intended divergence between the three shapes.
///
/// One list, in one place, because the alternative is what this repository already tried: the reason
/// living in a comment beside each shape, where nobody compares them. An entry no longer needed is
/// reported as an error, so the list cannot quietly accumulate permission nobody uses.
pub const EXEMPTIONS: &[Exemption] = &[
    Exemption {
        name: "summary",
        side: Side::WireOnly,
        reason: "Prose. It becomes the Markdown body, and is sealed with it for erasable records; \
                 frontmatter is always plaintext and survives in copies key destruction cannot \
                 reach, so putting prose there would put unerasable data in every one of them.",
    },
    Exemption {
        name: "id",
        side: Side::Column { from: None },
        reason: "Surrogate primary key. Explicit rather than an implicit rowid, which VACUUM may \
                 renumber — that would repoint every full-text row at the wrong record. It \
                 identifies a row, not a field of the record.",
    },
    Exemption {
        name: "frontmatter",
        side: Side::Column { from: None },
        reason: "The canonical JSON projection, stored whole. Every generated column below is \
                 extracted from it, which is what keeps the index reproducible from the tree.",
    },
    Exemption {
        name: "body",
        side: Side::Column {
            from: Some("summary"),
        },
        reason: "The record body: `summary`, or the longer prose a write may send instead. Empty \
                 when the record is sealed, enforced by a CHECK, so a sealed body cannot become \
                 searchable.",
    },
    Exemption {
        name: "at_ms",
        side: Side::Column { from: Some("at") },
        reason: "`at` in epoch milliseconds. Text cannot be range-scanned, and the contract carries \
                 the timestamp as text so a human can read a record without a tool.",
    },
    Exemption {
        name: "received_ms",
        side: Side::Column {
            from: Some("received_at"),
        },
        reason: "`received_at` in epoch milliseconds, for the reason `at_ms` is. Authoritative for \
                 every ordering and window, so it is the one column every read touches.",
    },
    Exemption {
        name: "sealed",
        side: Side::Column {
            from: Some("data_class"),
        },
        reason: "Whether `data_class` is `subject_derived`, promoted to a column because erasure \
                 and every scoped read test it. A boolean the record states in words.",
    },
];

/// The four shapes, as the crates that own them enumerate them.
#[derive(Debug, Clone, Copy)]
pub struct Shapes<'a> {
    /// Field names of the wire record.
    pub wire: &'a BTreeSet<String>,
    /// Frontmatter keys the renderer emits and the parser accepts.
    pub frontmatter: &'a [&'a str],
    /// Column names of the store's record table, generated columns included.
    pub columns: &'a [String],
    /// Field names a read hands back, from `RecordStructure`.
    ///
    /// Compared against `frontmatter` alone and with no exemption available: the read projection is
    /// the frontmatter key set or it is wrong.
    pub read: &'a BTreeSet<String>,
}

/// One way the three shapes disagree.
///
/// Each variant names the offending field and the side that is missing it, because a check whose
/// message sends the reader back to the source has only told them that something is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// A field on the wire record with no frontmatter key.
    WireWithoutKey(String),
    /// A frontmatter key with no field on the wire record.
    KeyWithoutField(String),
    /// A column with no field behind it.
    ColumnWithoutField(String),
    /// A field a read returns that frontmatter does not carry.
    ReadFieldWithoutKey(String),
    /// A frontmatter key a read does not hand back.
    KeyMissingFromRead(String),
    /// A column exempted as a projection of a field the record no longer has.
    ProjectionOfNothing {
        /// The exempted column.
        column: String,
        /// The field it claims to project.
        from: String,
    },
    /// An exemption for a divergence that no longer exists.
    UnusedExemption {
        /// The name it excuses.
        name: String,
        /// The comparison it excuses.
        side: Side,
    },
    /// A key whose value differs between the wire record and its frontmatter projection.
    ValueDiverged {
        /// The key both shapes carry.
        key: String,
        /// What the wire record holds.
        wire: String,
        /// What the frontmatter projection holds.
        frontmatter: String,
    },
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WireWithoutKey(field) => write!(
                f,
                "wire field `{field}` has no frontmatter key: add it to `yaam_md::frontmatter` \
                 (both `KEYS` and `project`), or add an `Exemption` for it with \
                 `side: Side::WireOnly` saying why the record's plaintext face leaves it out"
            ),
            Self::KeyWithoutField(key) => write!(
                f,
                "frontmatter key `{key}` has no field on the wire record: add the field to \
                 `ActionRecord`, or drop the key — a key no field feeds holds a value no \
                 `yaam reindex` can recover"
            ),
            Self::ReadFieldWithoutKey(field) => write!(
                f,
                "`RecordStructure` returns `{field}`, which frontmatter does not carry: a read hands \
                 back stored frontmatter, so a field with no key behind it is one no stored record \
                 can fill — drop it, or add the key to `yaam_md::frontmatter`"
            ),
            Self::KeyMissingFromRead(key) => write!(
                f,
                "frontmatter key `{key}` is not a field of `RecordStructure`: a read returns the \
                 record's structure, and a key it leaves out is structure the design promised and \
                 no caller can ask for. There is deliberately no exemption for this side"
            ),
            Self::ColumnWithoutField(column) => write!(
                f,
                "store column `{column}` has no field behind it: every column must be reproducible \
                 from the record, so add the field to `ActionRecord`, or add an `Exemption` with \
                 `side: Side::Column {{ from }}` naming what the column is computed from"
            ),
            Self::ProjectionOfNothing { column, from } => write!(
                f,
                "store column `{column}` is exempt as a projection of `{from}`, and the record has \
                 no field `{from}`: the column and its exemption have to move together"
            ),
            Self::UnusedExemption { name, side } => write!(
                f,
                "`EXEMPTIONS` still excuses `{name}` as {side}, and the shapes no longer diverge \
                 there: delete the entry — an exemption nobody needs is one nobody reads"
            ),
            Self::ValueDiverged {
                key,
                wire,
                frontmatter,
            } => write!(
                f,
                "`{key}` is {wire} on the wire and {frontmatter} in the frontmatter projection: \
                 frontmatter is the wire record minus its exempt fields, verbatim, so one field \
                 now has two shapes"
            ),
        }
    }
}

/// Every way the three shapes currently disagree, against the declared exemptions.
///
/// An empty result is the rule holding.
#[must_use]
pub fn check(shapes: &Shapes<'_>) -> Vec<Divergence> {
    check_against(shapes, EXEMPTIONS)
}

/// As [`check`], against a given exemption table.
///
/// Separate so the check can be tested against drift that is not in this repository: a mechanism
/// nobody has watched fail is a mechanism nobody knows works.
#[must_use]
pub fn check_against(shapes: &Shapes<'_>, exemptions: &[Exemption]) -> Vec<Divergence> {
    let keys: BTreeSet<&str> = shapes.frontmatter.iter().copied().collect();
    let excused = |name: &str, side: Side| {
        exemptions
            .iter()
            .any(|e| e.name == name && matches_side(e.side, side))
    };
    let mut found = Vec::new();

    for field in shapes.wire {
        if !keys.contains(field.as_str()) && !excused(field, Side::WireOnly) {
            found.push(Divergence::WireWithoutKey(field.clone()));
        }
    }

    for key in &keys {
        if !shapes.wire.contains(*key) && !excused(key, Side::FrontmatterOnly) {
            found.push(Divergence::KeyWithoutField((*key).to_owned()));
        }
    }

    // No exemption is consulted: the read projection is frontmatter exactly, so there is nothing
    // to excuse and no entry anybody could add to excuse it.
    for field in shapes.read {
        if !keys.contains(field.as_str()) {
            found.push(Divergence::ReadFieldWithoutKey(field.clone()));
        }
    }

    for key in &keys {
        if !shapes.read.contains(*key) {
            found.push(Divergence::KeyMissingFromRead((*key).to_owned()));
        }
    }

    for column in shapes.columns {
        if shapes.wire.contains(column) {
            continue;
        }
        match exemptions
            .iter()
            .find(|e| e.name == column && matches!(e.side, Side::Column { .. }))
        {
            Some(Exemption {
                side: Side::Column { from: Some(field) },
                ..
            }) if !shapes.wire.contains(*field) => {
                found.push(Divergence::ProjectionOfNothing {
                    column: column.clone(),
                    from: (*field).to_owned(),
                });
            }
            Some(_) => {}
            None => found.push(Divergence::ColumnWithoutField(column.clone())),
        }
    }

    for exemption in exemptions {
        if !still_needed(exemption, shapes, &keys) {
            found.push(Divergence::UnusedExemption {
                name: exemption.name.to_owned(),
                side: exemption.side,
            });
        }
    }

    found
}

/// Compares one record's wire JSON against the frontmatter projection of the same record.
///
/// The projection is the wire record minus its exempt fields, value for value — which is what makes
/// this a single comparison rather than a per-field ruleset, and what catches the divergence the set
/// comparison above cannot see: a field that kept its name and changed its shape.
///
/// Keys only one side carries are [`check`]'s business, not this one's.
#[must_use]
pub fn check_projection(wire: &Json, frontmatter: &Json) -> Vec<Divergence> {
    let (Some(wire), Some(frontmatter)) = (wire.as_object(), frontmatter.as_object()) else {
        return vec![Divergence::ValueDiverged {
            key: "<document>".to_owned(),
            wire: kind(wire),
            frontmatter: kind(frontmatter),
        }];
    };
    wire.iter()
        .filter_map(|(key, left)| {
            let right = frontmatter.get(key)?;
            (left != right).then(|| Divergence::ValueDiverged {
                key: key.clone(),
                wire: describe(left),
                frontmatter: describe(right),
            })
        })
        .collect()
}

/// Whether an exemption still excuses something the shapes actually do.
fn still_needed(exemption: &Exemption, shapes: &Shapes<'_>, keys: &BTreeSet<&str>) -> bool {
    let name = exemption.name;
    match exemption.side {
        Side::WireOnly => shapes.wire.contains(name) && !keys.contains(name),
        Side::FrontmatterOnly => keys.contains(name) && !shapes.wire.contains(name),
        Side::Column { .. } => {
            shapes.columns.iter().any(|c| c == name) && !shapes.wire.contains(name)
        }
    }
}

/// Whether two sides name the same comparison, ignoring what a column projects.
fn matches_side(declared: Side, wanted: Side) -> bool {
    std::mem::discriminant(&declared) == std::mem::discriminant(&wanted)
}

/// A value's JSON type, for a message about two shapes of one field.
fn kind(value: &Json) -> String {
    match value {
        Json::Null => "null",
        Json::Bool(_) => "a boolean",
        Json::Number(_) => "a number",
        Json::String(_) => "a string",
        Json::Array(_) => "an array",
        Json::Object(_) => "an object",
    }
    .to_owned()
}

/// A value's type and content, clipped so a long array does not bury the field name.
fn describe(value: &Json) -> String {
    const LIMIT: usize = 60;
    let mut text = value.to_string();
    if text.len() > LIMIT {
        text.truncate(LIMIT);
        text.push('…');
    }
    format!("{} ({text})", kind(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four shapes as they stand when nothing has drifted.
    fn agreeing() -> (
        BTreeSet<String>,
        Vec<&'static str>,
        Vec<String>,
        BTreeSet<String>,
    ) {
        let wire = ["record_id", "at", "action", "summary"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let frontmatter = vec!["record_id", "at", "action"];
        let columns = ["id", "record_id", "at_ms", "action"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let read = frontmatter.iter().map(|s| (*s).to_owned()).collect();
        (wire, frontmatter, columns, read)
    }

    /// The exemptions the fixture above needs, and no others.
    const FIXTURE: &[Exemption] = &[
        Exemption {
            name: "summary",
            side: Side::WireOnly,
            reason: "prose, stored as the body",
        },
        Exemption {
            name: "id",
            side: Side::Column { from: None },
            reason: "surrogate key",
        },
        Exemption {
            name: "at_ms",
            side: Side::Column { from: Some("at") },
            reason: "`at` in milliseconds",
        },
    ];

    /// One message, for a fixture expected to produce exactly one divergence.
    fn only(found: &[Divergence]) -> String {
        assert_eq!(found.len(), 1, "{found:?}");
        found[0].to_string()
    }

    #[test]
    fn shapes_that_agree_report_nothing() {
        let (wire, frontmatter, columns, read) = agreeing();
        let found = check_against(
            &Shapes {
                wire: &wire,
                frontmatter: &frontmatter,
                columns: &columns,
                read: &read,
            },
            FIXTURE,
        );
        assert!(found.is_empty(), "{found:?}");
    }

    /// The first historical failure, in the shape it would take today.
    #[test]
    fn a_wire_field_with_no_frontmatter_key_is_named() {
        let (mut wire, frontmatter, columns, read) = agreeing();
        wire.insert("redaction".to_owned());
        let found = check_against(
            &Shapes {
                wire: &wire,
                frontmatter: &frontmatter,
                columns: &columns,
                read: &read,
            },
            FIXTURE,
        );
        let message = only(&found);
        assert!(message.contains("wire field `redaction`"), "{message}");
        assert!(message.contains("no frontmatter key"), "{message}");
    }

    #[test]
    fn a_frontmatter_key_with_no_field_is_named() {
        let (wire, mut frontmatter, columns, mut read) = agreeing();
        // Mirrored into the read shape: what this fixture is about is the wire side, and a read
        // projection left behind would report a second, unrelated divergence.
        frontmatter.push("redaction");
        read.insert("redaction".to_owned());
        let found = check_against(
            &Shapes {
                wire: &wire,
                frontmatter: &frontmatter,
                columns: &columns,
                read: &read,
            },
            FIXTURE,
        );
        let message = only(&found);
        assert!(message.contains("frontmatter key `redaction`"), "{message}");
        assert!(message.contains("no field on the wire record"), "{message}");
    }

    /// The second historical failure: a column, and prose about it, and nothing else.
    #[test]
    fn a_column_with_no_field_behind_it_is_named() {
        let (wire, frontmatter, mut columns, read) = agreeing();
        columns.push("backfilled".to_owned());
        let found = check_against(
            &Shapes {
                wire: &wire,
                frontmatter: &frontmatter,
                columns: &columns,
                read: &read,
            },
            FIXTURE,
        );
        let message = only(&found);
        assert!(message.contains("store column `backfilled`"), "{message}");
        assert!(message.contains("no field behind it"), "{message}");
    }

    /// A read that drops a frontmatter key hands back less structure than the design promises, and
    /// no caller has a second endpoint to ask for the rest.
    #[test]
    fn a_frontmatter_key_a_read_leaves_out_is_named() {
        let (wire, frontmatter, columns, mut read) = agreeing();
        read.remove("action");
        let found = check_against(
            &Shapes {
                wire: &wire,
                frontmatter: &frontmatter,
                columns: &columns,
                read: &read,
            },
            FIXTURE,
        );
        let message = only(&found);
        assert!(message.contains("frontmatter key `action`"), "{message}");
        assert!(message.contains("no exemption"), "{message}");
    }

    /// The other direction: a field with no key behind it is one no stored record can fill.
    #[test]
    fn a_read_field_with_no_frontmatter_key_is_named() {
        let (wire, frontmatter, columns, mut read) = agreeing();
        read.insert("summary".to_owned());
        let found = check_against(
            &Shapes {
                wire: &wire,
                frontmatter: &frontmatter,
                columns: &columns,
                read: &read,
            },
            FIXTURE,
        );
        let message = only(&found);
        assert!(message.contains("returns `summary`"), "{message}");
        assert!(message.contains("frontmatter does not carry"), "{message}");
    }

    /// No entry in the table can excuse the read side, whichever way it diverges.
    #[test]
    fn no_exemption_excuses_the_read_projection() {
        let (wire, frontmatter, columns, mut read) = agreeing();
        read.remove("action");
        read.insert("summary".to_owned());
        let excusing_everything: Vec<Exemption> = ["action", "summary"]
            .into_iter()
            .flat_map(|name| {
                [
                    Side::WireOnly,
                    Side::FrontmatterOnly,
                    Side::Column { from: None },
                ]
                .map(|side| Exemption {
                    name,
                    side,
                    reason: "an exemption that must not reach the read projection",
                })
            })
            .collect();
        let found = check_against(
            &Shapes {
                wire: &wire,
                frontmatter: &frontmatter,
                columns: &columns,
                read: &read,
            },
            &excusing_everything,
        );
        assert!(
            found
                .iter()
                .any(|d| matches!(d, Divergence::KeyMissingFromRead(key) if key == "action")),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|d| matches!(d, Divergence::ReadFieldWithoutKey(f) if f == "summary")),
            "{found:?}"
        );
    }

    #[test]
    fn an_exemption_pointing_at_a_renamed_field_is_reported() {
        let (mut wire, mut frontmatter, columns, mut read) = agreeing();
        wire.remove("at");
        wire.insert("at_utc".to_owned());
        frontmatter.retain(|k| *k != "at");
        frontmatter.push("at_utc");
        read.remove("at");
        read.insert("at_utc".to_owned());
        let found = check_against(
            &Shapes {
                wire: &wire,
                frontmatter: &frontmatter,
                columns: &columns,
                read: &read,
            },
            FIXTURE,
        );
        let message = only(&found);
        assert!(message.contains("`at_ms` is exempt"), "{message}");
        assert!(message.contains("projection of `at`"), "{message}");
    }

    #[test]
    fn an_exemption_nobody_needs_is_reported() {
        let (wire, mut frontmatter, columns, mut read) = agreeing();
        // `summary` became a frontmatter key, so its exemption has nothing left to excuse.
        frontmatter.push("summary");
        read.insert("summary".to_owned());
        let found = check_against(
            &Shapes {
                wire: &wire,
                frontmatter: &frontmatter,
                columns: &columns,
                read: &read,
            },
            FIXTURE,
        );
        let message = only(&found);
        assert!(message.contains("still excuses `summary`"), "{message}");
        assert!(message.contains("delete the entry"), "{message}");
    }

    #[test]
    fn a_frontmatter_only_exemption_is_honoured_and_reclaimed() {
        let (wire, frontmatter, columns, read) = agreeing();
        let exemptions = &[Exemption {
            name: "action",
            side: Side::FrontmatterOnly,
            reason: "not a real divergence; here to drive the arm",
        }];
        // `action` is on both sides, so this exemption excuses nothing.
        let found = check_against(
            &Shapes {
                wire: &wire,
                frontmatter: &frontmatter,
                columns: &columns,
                read: &read,
            },
            exemptions,
        );
        assert!(
            found
                .iter()
                .any(|d| matches!(d, Divergence::UnusedExemption { name, side }
                    if name == "action" && *side == Side::FrontmatterOnly)),
            "{found:?}"
        );

        // Removed from the wire, it is exactly what the exemption describes.
        let mut narrowed = wire.clone();
        narrowed.remove("action");
        let found = check_against(
            &Shapes {
                wire: &narrowed,
                frontmatter: &frontmatter,
                columns: &columns,
                read: &read,
            },
            exemptions,
        );
        let unexcused: Vec<&Divergence> = found
            .iter()
            .filter(|d| matches!(d, Divergence::KeyWithoutField(_)))
            .collect();
        assert!(unexcused.is_empty(), "{unexcused:?}");
    }

    /// One table, reached one way: a second list would be the drift this module exists to catch.
    #[test]
    fn the_public_check_reads_the_declared_exemptions() {
        let (wire, frontmatter, columns, read) = agreeing();
        let shapes = Shapes {
            wire: &wire,
            frontmatter: &frontmatter,
            columns: &columns,
            read: &read,
        };
        assert_eq!(check(&shapes), check_against(&shapes, EXEMPTIONS));
    }

    #[test]
    fn a_side_matches_only_its_own_comparison() {
        assert!(matches_side(Side::WireOnly, Side::WireOnly));
        assert!(!matches_side(Side::WireOnly, Side::FrontmatterOnly));
        // What a column projects is not part of the comparison it excuses.
        assert!(matches_side(
            Side::Column { from: Some("at") },
            Side::Column { from: None }
        ));
    }

    #[test]
    fn every_side_says_which_comparison_it_excuses() {
        assert!(Side::WireOnly.to_string().contains("frontmatter key"));
        assert!(Side::FrontmatterOnly.to_string().contains("wire field"));
        assert_eq!(
            Side::Column { from: Some("at") }.to_string(),
            "a column projected from `at`"
        );
        assert_eq!(
            Side::Column { from: None }.to_string(),
            "a column projected from the whole record"
        );
    }

    #[test]
    fn a_projection_that_matches_reports_nothing() {
        let wire = serde_json::json!({ "action": "deploy", "summary": "prose" });
        let frontmatter = serde_json::json!({ "action": "deploy" });
        assert!(check_projection(&wire, &frontmatter).is_empty());
    }

    /// The `redaction` failure in its original form: one name, two shapes.
    #[test]
    fn a_field_that_changed_shape_under_the_same_name_is_named() {
        let wire = serde_json::json!({ "redaction": { "policy": "default-v1", "fields": [] } });
        let frontmatter = serde_json::json!({ "redaction": "default-v1" });
        let message = only(&check_projection(&wire, &frontmatter));
        assert!(message.contains("`redaction` is an object"), "{message}");
        assert!(message.contains("a string"), "{message}");
    }

    #[test]
    fn a_long_value_is_clipped_so_the_field_name_stays_readable() {
        let wire = serde_json::json!({ "tags": vec!["a-fairly-long-tag"; 20] });
        let frontmatter = serde_json::json!({ "tags": [] });
        let message = only(&check_projection(&wire, &frontmatter));
        assert!(message.contains('…'), "{message}");
        assert!(message.len() < 400, "{message}");
    }

    #[test]
    fn a_projection_that_is_not_a_mapping_is_reported_as_one_divergence() {
        let message = only(&check_projection(
            &serde_json::json!({}),
            &serde_json::json!([]),
        ));
        assert!(message.contains("<document>"), "{message}");
        assert!(message.contains("an array"), "{message}");
    }

    /// Every value kind has a name, so no message can read "`x` is  on the wire".
    #[test]
    fn every_value_kind_is_named() {
        for value in [
            Json::Null,
            serde_json::json!(true),
            serde_json::json!(1),
            serde_json::json!("s"),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            assert!(!kind(&value).is_empty(), "{value}");
        }
    }

    /// Every entry has to earn its place: a reason nobody wrote is a reason nobody weighed.
    #[test]
    fn every_declared_exemption_gives_a_reason() {
        for exemption in EXEMPTIONS {
            assert!(
                exemption.reason.len() > 40,
                "`{}` needs a reason, not a label: {:?}",
                exemption.name,
                exemption.reason
            );
        }
    }
}
