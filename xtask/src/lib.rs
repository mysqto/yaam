//! Generating `spec/schemas/`, and checking the shapes it is generated from.
//!
//! The wire record, the Markdown frontmatter and the store's columns are three projections of one
//! shape. Each is owned by a different crate, and none of them can see the other two — which is why
//! the rule went unenforced long enough to be broken twice. This crate is the one place all three
//! are visible: it hands them to [`yaam_contract::lockstep`], which owns the rule, and fails the
//! build when they disagree.
//!
//! It also emits the schemas, and checks the committed copies against what the generator produces
//! now. A generated artefact nobody verifies drifts exactly as fast as a hand-written one.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use yaam_contract::lockstep::{Divergence, Shapes};
use yaam_contract::schema::Document;

pub mod openapi;
pub mod sample;

/// The store table the lockstep rule covers.
///
/// One table, because it is the only one whose columns are a projection of the record. The others
/// hold rows *derived* from a record's lists — one per entity reference, one per subject — and their
/// columns answer to those element types rather than to the record.
const RECORD_TABLE: &str = "records";

/// Every schema this repository publishes, in bundle order.
///
/// Assembled from each crate's own list rather than named here: a file this function forgot would
/// be a shape with no published description and nothing to notice.
#[must_use]
pub fn bundle() -> Vec<Document> {
    let mut documents = yaam_contract::schema::documents();
    documents.extend(yaam_server::schema::documents());
    documents
}

/// The directory the bundle is committed in.
///
/// # Panics
/// If this crate's manifest is not inside the repository, which cannot happen in a checkout.
#[must_use]
pub fn schema_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the manifest directory sits inside the repository")
        .join("spec")
        .join("schemas")
}

/// The published `OpenAPI` document, which describes the same wire by hand.
///
/// # Panics
/// As [`schema_dir`].
#[must_use]
pub fn openapi_path() -> PathBuf {
    schema_dir()
        .parent()
        .expect("spec/schemas sits inside spec")
        .join("memory.v1.yaml")
}

/// Writes the bundle into `dir`, returning the files whose contents changed.
///
/// Unchanged files are left alone so that regenerating never touches a timestamp for nothing.
pub fn emit(dir: &Path) -> std::io::Result<Vec<String>> {
    std::fs::create_dir_all(dir)?;
    let mut written = Vec::new();
    for document in bundle() {
        let path = dir.join(document.file);
        let rendered = document.render();
        if std::fs::read_to_string(&path).is_ok_and(|found| found == rendered) {
            continue;
        }
        std::fs::write(&path, rendered)?;
        written.push(document.file.to_owned());
    }
    Ok(written)
}

/// How the committed bundle differs from what the generator produces now.
///
/// An empty result is the committed copies being current. Reported as prose rather than a diff: the
/// fix is always to regenerate, so what the reader needs is which file and why.
#[must_use]
pub fn drift(dir: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut expected = BTreeSet::new();
    for document in bundle() {
        expected.insert(document.file.to_owned());
        let path = dir.join(document.file);
        match std::fs::read_to_string(&path) {
            Err(_) => found.push(format!(
                "{}: not committed — run `cargo xtask emit`",
                document.file
            )),
            Ok(committed) if committed != document.render() => found.push(format!(
                "{}: committed copy is not what the types produce — run `cargo xtask emit`",
                document.file
            )),
            Ok(_) => {}
        }
    }
    // A file left behind after a shape was renamed goes on being vendored under its old name.
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_schema = Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
            if is_schema && !expected.contains(&name) {
                found.push(format!(
                    "{name}: no shape produces this any more — delete it"
                ));
            }
        }
    }
    found
}

/// The three shapes as the crates that own them spell them.
///
/// Held together because [`Shapes`] borrows all three, and because reading them in one place is what
/// makes it obvious that none of them is a copy kept for the check.
#[derive(Debug)]
pub struct Enumerated {
    /// Field names of the wire record, read out of its generated schema.
    pub wire: BTreeSet<String>,
    /// Frontmatter keys, as the renderer emits and the parser accepts them.
    pub frontmatter: Vec<&'static str>,
    /// Columns of the store's record table, generated ones included.
    pub columns: Vec<String>,
}

impl Enumerated {
    /// Reads all three from the crates that own them.
    ///
    /// # Panics
    /// If an in-memory database cannot be created or migrated, which would mean the store's own
    /// schema no longer applies.
    #[must_use]
    pub fn read() -> Self {
        Self {
            wire: yaam_contract::schema::wire_fields(),
            frontmatter: yaam_md::frontmatter::KEYS.to_vec(),
            columns: record_columns(),
        }
    }

    /// The borrowed view the check takes.
    #[must_use]
    pub fn shapes(&self) -> Shapes<'_> {
        Shapes {
            wire: &self.wire,
            frontmatter: &self.frontmatter,
            columns: &self.columns,
        }
    }
}

/// Column names of the store's record table.
///
/// Asked of a migrated database, not parsed out of the migration text. `pragma_table_xinfo` answers
/// with the columns that exist — generated ones included, which `table_info` hides and which are
/// most of what this check is about.
///
/// # Panics
/// If the store's own schema will not apply to an empty database.
#[must_use]
pub fn record_columns() -> Vec<String> {
    let mut conn =
        rusqlite::Connection::open_in_memory().expect("an in-memory database needs no filesystem");
    yaam_store::schema::migrate(&mut conn)
        .expect("the store's schema applies to an empty database");
    let mut statement = conn
        .prepare("SELECT name FROM pragma_table_xinfo(?1) ORDER BY cid")
        .expect("pragma_table_xinfo is a table-valued function in every supported SQLite");
    let columns = statement
        .query_map([RECORD_TABLE], |row| row.get::<_, String>(0))
        .expect("the pragma answers one text column")
        .collect::<Result<Vec<String>, _>>()
        .expect("every row is one column name");
    assert!(
        !columns.is_empty(),
        "`{RECORD_TABLE}` has no columns, so the migration no longer creates it"
    );
    columns
}

/// Every way the three shapes currently disagree.
///
/// Two comparisons, because one field can diverge in two ways. The name sets catch a field that
/// exists on one side only — the `backfilled` failure. The projection of a maximal record catches a
/// field that kept its name and changed its shape — the `redaction` failure, which no comparison of
/// names can see.
///
/// # Panics
/// If the sample record cannot be rendered, which would mean the frontmatter projection had stopped
/// accepting a valid record.
#[must_use]
pub fn divergences() -> Vec<Divergence> {
    let shapes = Enumerated::read();
    let mut found = yaam_contract::lockstep::check(&shapes.shapes());

    let record = sample::maximal();
    let wire = serde_json::to_value(&record).expect("a record serialises");
    let projected: serde_json::Value =
        serde_json::from_str(&yaam_md::frontmatter::to_canonical_json(&record).expect("projects"))
            .expect("the canonical projection is JSON");
    found.extend(yaam_contract::lockstep::check_projection(&wire, &projected));
    found
}

/// What a chore did, and whether the repository is in the state it asked for.
///
/// Separated from printing so a chore can be driven against a temporary directory: the branches
/// worth testing are the ones a clean tree never takes, and a chore that only ever ran against the
/// repository could not be made to take them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// What to say. A chore always says something, even when there was nothing to do.
    pub lines: Vec<String>,
    /// Whether the repository is in the state the chore asked for.
    pub ok: bool,
}

/// Performs one chore against a schema directory, without printing.
///
/// The two chores are the same knowledge read two ways: `check` is what CI asks, and `emit` is what
/// a person runs to satisfy it.
#[must_use]
pub fn chore(name: Option<&str>, dir: &Path) -> Outcome {
    match name {
        Some("emit") => match emit(dir) {
            Ok(written) if written.is_empty() => Outcome {
                lines: vec!["spec/schemas: already current".to_owned()],
                ok: true,
            },
            Ok(written) => Outcome {
                lines: vec![format!("spec/schemas: wrote {}", written.join(", "))],
                ok: true,
            },
            Err(error) => Outcome {
                lines: vec![format!("spec/schemas: {error}")],
                ok: false,
            },
        },
        Some("check") => {
            let mut lines = drift(dir);
            lines.extend(openapi::drift());
            lines.extend(divergences().iter().map(ToString::to_string));
            if lines.is_empty() {
                return Outcome {
                    lines: vec!["spec/schemas: current, and the shapes agree".to_owned()],
                    ok: true,
                };
            }
            Outcome { lines, ok: false }
        }
        _ => Outcome {
            lines: vec!["usage: cargo xtask <emit|check>".to_owned()],
            ok: false,
        },
    }
}

/// Runs one chore against the committed tree and prints what it found.
///
/// `false` means the repository is not in the state the chore asks for, which is what the exit
/// status carries: `ci/check.sh` and the CI workflow both act on it.
pub fn run(args: &[String]) -> bool {
    let outcome = chore(args.first().map(String::as_str), &schema_dir());
    for line in &outcome.lines {
        if outcome.ok {
            println!("{line}");
        } else {
            eprintln!("{line}");
        }
    }
    outcome.ok
}

/// Property names and required names of one schema object.
///
/// Shared by the checks that compare the generated bundle against the `OpenAPI` document, so both read
/// a schema the same way whichever dialect it arrived in.
#[must_use]
pub fn object_fields(schema: &serde_json::Value) -> (BTreeSet<String>, BTreeSet<String>) {
    let properties = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .map(|fields| fields.keys().cloned().collect())
        .unwrap_or_default();
    let required = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    (properties, required)
}

/// One generated schema from the bundle, by file name.
///
/// # Panics
/// If no document in the bundle has that name.
#[must_use]
pub fn generated(file: &str) -> serde_json::Value {
    bundle()
        .into_iter()
        .find(|document| document.file == file)
        .unwrap_or_else(|| panic!("{file} is not in the bundle"))
        .schema
}

/// Every named shape the bundle defines: each document's root, under its title, plus its `$defs`.
///
/// Flattened by name because that is how the `OpenAPI` document names the same shapes, and comparing
/// them is the only thing keeping the hand-written document and the generated bundle from describing
/// two different services.
#[must_use]
pub fn generated_objects() -> BTreeMap<String, serde_json::Value> {
    let mut objects = BTreeMap::new();
    for document in bundle() {
        if let Some(title) = document.schema.get("title").and_then(|t| t.as_str()) {
            objects.insert(title.to_owned(), document.schema.clone());
        }
        let defs = document
            .schema
            .get("$defs")
            .and_then(serde_json::Value::as_object);
        for (name, schema) in defs.into_iter().flatten() {
            objects.insert(name.clone(), schema.clone());
        }
    }
    objects
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deliverable: the wire record, the frontmatter keys and the store's columns, compared.
    ///
    /// It has bitten twice in review and once in anger. What it costs when it does not run is two
    /// releases of a contract that described a record nobody was storing.
    #[test]
    fn the_three_shapes_are_in_lockstep() {
        let found: Vec<String> = divergences().iter().map(ToString::to_string).collect();
        assert!(
            found.is_empty(),
            "the three shapes have diverged: {found:#?}"
        );
    }

    /// A schema regenerated on demand and never verified drifts as easily as a hand-written one.
    #[test]
    fn the_committed_schemas_are_what_the_types_produce() {
        let found = drift(&schema_dir());
        assert!(found.is_empty(), "{}", found.join("\n"));
    }

    #[test]
    fn the_bundle_is_the_four_files_the_design_advertises() {
        let files: BTreeSet<&str> = bundle().iter().map(|d| d.file).collect();
        assert_eq!(
            files,
            BTreeSet::from([
                "action-record.v1.json",
                "bundle.v1.json",
                "envelope.v1.json",
                "result.v1.json",
            ])
        );
    }

    /// The generated columns are the whole reason this reads a database rather than the SQL: a
    /// `table_info` pragma would not list one of them.
    #[test]
    fn the_columns_include_the_generated_ones() {
        let columns = record_columns();
        for expected in [
            "id",
            "record_id",
            "frontmatter",
            "at_ms",
            "action",
            "sealed",
        ] {
            assert!(
                columns.iter().any(|c| c == expected),
                "`{expected}` missing from {columns:?}"
            );
        }
    }

    #[test]
    fn emitting_into_an_empty_directory_then_checking_it_is_quiet() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("schemas");
        let written = emit(&path).expect("writes");
        assert_eq!(written.len(), bundle().len(), "{written:?}");
        assert!(drift(&path).is_empty());
        // Second run changes nothing, so regenerating never churns a file for its own sake.
        assert!(emit(&path).expect("writes").is_empty());
    }

    #[test]
    fn drift_names_the_file_and_what_is_wrong_with_it() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("schemas");
        emit(&path).expect("writes");

        std::fs::write(path.join("action-record.v1.json"), "{}\n").expect("writes");
        let found = drift(&path);
        assert!(
            found
                .iter()
                .any(|m| m.contains("action-record.v1.json") && m.contains("not what the types")),
            "{found:?}"
        );

        std::fs::remove_file(path.join("envelope.v1.json")).expect("removes");
        let found = drift(&path);
        assert!(
            found
                .iter()
                .any(|m| m.contains("envelope.v1.json") && m.contains("not committed")),
            "{found:?}"
        );

        std::fs::write(path.join("retired.v1.json"), "{}\n").expect("writes");
        let found = drift(&path);
        assert!(
            found
                .iter()
                .any(|m| m.contains("retired.v1.json") && m.contains("delete it")),
            "{found:?}"
        );
    }

    #[test]
    fn a_missing_directory_is_drift_rather_than_a_crash() {
        let found = drift(Path::new("/nonexistent/spec/schemas"));
        assert_eq!(found.len(), bundle().len(), "{found:?}");
        assert!(
            found.iter().all(|m| m.contains("not committed")),
            "{found:?}"
        );
    }

    #[test]
    fn check_and_emit_both_succeed_on_the_committed_tree() {
        assert!(run(&["check".to_owned()]));
        assert!(run(&["emit".to_owned()]));
    }

    #[test]
    fn an_unknown_chore_fails_rather_than_doing_something() {
        for args in [vec![], vec!["polish".to_owned()]] {
            assert!(!run(&args), "{args:?}");
        }
        let outcome = chore(None, &schema_dir());
        assert!(
            !outcome.ok && outcome.lines[0].contains("emit|check"),
            "{outcome:?}"
        );
    }

    /// Every branch a chore has, including the ones the committed tree never takes.
    #[test]
    fn a_chore_says_what_it_did_in_each_case() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("schemas");

        let outcome = chore(Some("emit"), &path);
        assert!(
            outcome.ok && outcome.lines[0].contains("wrote"),
            "{outcome:?}"
        );
        let outcome = chore(Some("emit"), &path);
        assert!(
            outcome.ok && outcome.lines[0].contains("already current"),
            "{outcome:?}"
        );
        let outcome = chore(Some("check"), &path);
        assert!(
            outcome.ok && outcome.lines[0].contains("shapes agree"),
            "{outcome:?}"
        );

        // A directory that has nothing in it is drift, and drift is a failure with a reason.
        let outcome = chore(Some("check"), &dir.path().join("elsewhere"));
        assert!(!outcome.ok, "{outcome:?}");
        assert_eq!(outcome.lines.len(), bundle().len(), "{outcome:?}");

        // A path that cannot become a directory, because a file already occupies it.
        let blocked = dir.path().join("file");
        std::fs::write(&blocked, "").expect("writes");
        let outcome = chore(Some("emit"), &blocked.join("schemas"));
        assert!(
            !outcome.ok && outcome.lines[0].starts_with("spec/schemas:"),
            "{outcome:?}"
        );
    }

    #[test]
    fn object_fields_reads_properties_and_required() {
        let (properties, required) = object_fields(&serde_json::json!({
            "properties": { "a": {}, "b": {} },
            "required": ["a"],
        }));
        assert_eq!(properties, BTreeSet::from(["a".to_owned(), "b".to_owned()]));
        assert_eq!(required, BTreeSet::from(["a".to_owned()]));
        // A schema with neither is an empty pair, not a panic: a scalar is a schema too.
        let (properties, required) = object_fields(&serde_json::json!({ "type": "string" }));
        assert!(properties.is_empty() && required.is_empty());
    }

    #[test]
    fn the_generated_objects_include_the_record_and_its_definitions() {
        let objects = generated_objects();
        assert!(objects.contains_key("ActionRecord"), "{:?}", objects.keys());
        assert!(objects.contains_key("EntityRef"), "{:?}", objects.keys());
    }

    #[test]
    #[should_panic(expected = "is not in the bundle")]
    fn asking_for_a_schema_the_bundle_does_not_have_says_so() {
        let _ = generated("invented.v1.json");
    }
}
