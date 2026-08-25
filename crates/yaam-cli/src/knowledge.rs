//! Deriving knowledge from the record tree, and reading what was derived.
//!
//! Its own module rather than four more reports in [`crate::ops`], because these four are the only
//! commands that name a store and open nothing. Every one of them reads the Markdown records and
//! the cold manifests: no index row, no key, no fan-out queue. Sitting beside `reindex` they would
//! have inherited the pipeline open that `reindex` needs and a knowledge build does not — and the
//! store where a build is most worth having is the one whose index is the broken thing.
//!
//! Thin for the reason [`crate::ops`] is thin. What may contribute to a note, what a fact is, what a
//! read may hand back: all of it is `yaam_knowledge`'s judgement, because a second opinion held only
//! in a command-line tool is an opinion no test of the library can contradict.

use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

use yaam_contract::{RecordId, RecordStructure, timestamp};
use yaam_knowledge::note::KNOWLEDGE_DIR;
use yaam_knowledge::{BuildReport, EntityKey, Note, SyncState};

use crate::cli::KnowledgeCommand;
use crate::error::{Result, config, failed};
use crate::exit::Exit;
use crate::ops::{emit, line};

/// What the tree is, said wherever one of these commands ends.
///
/// Repeated at the point of use rather than left to the documentation, because it is the sentence
/// that tells an operator which of these files may be deleted when something looks wrong — and a
/// derived tree nobody dares delete is a derived tree in name only.
const DISPOSABLE: &str = "nothing here is authoritative: delete knowledge/ and build it again.\n";

/// Runs whichever knowledge command was asked for.
///
/// Takes the root rather than an open store, which is the whole point of the module: see above.
pub fn run(root: &Path, command: &KnowledgeCommand, out: &mut dyn Write) -> Result<Exit> {
    match command {
        KnowledgeCommand::Build => build(root, out),
        KnowledgeCommand::Status => status(root, out),
        KnowledgeCommand::Note { entity } => note(root, entity, out),
        KnowledgeCommand::Search { query, limit } => search(root, query, *limit, out),
        KnowledgeCommand::Evidence { records } => evidence(root, records, out),
    }
}

/// Rebuilds every note from the record tree.
///
/// [`Exit::Degraded`] for a source that would not parse and for a stamp that would not, and for
/// nothing else. The three other exclusion counts are what the gate is *for*: a record whose body
/// is erasable, or which is not readable org-wide, is excluded on purpose, and a store full of
/// subject-derived records reporting zero excluded would be the alarming report. Spending the exit
/// code on those would have a monitor paging somebody over a working boundary.
pub fn build(root: &Path, out: &mut dyn Write) -> Result<Exit> {
    let report = yaam_knowledge::rebuild(root)
        .map_err(|error| failed("rebuilding the knowledge tree", &error))?;
    emit(out, &describe_build(root, &report))?;
    if report.skipped_untimed > 0 || report.skipped_unreadable > 0 {
        Ok(Exit::Degraded)
    } else {
        Ok(Exit::Ok)
    }
}

/// Reports what the last build read, and when.
///
/// [`Exit::Degraded`] when there is nothing to report, because no state file is a definite answer
/// and not a missing one: a build removes it before swapping its tree in and writes it after, so its
/// absence says the tree is mid-build or has never been built. A store answering reads out of a
/// knowledge tree nobody has built since the records arrived wants an operator, and this is the
/// command a monitor asks.
pub fn status(root: &Path, out: &mut dyn Write) -> Result<Exit> {
    let state = yaam_knowledge::state(root)
        .map_err(|error| failed("reading what the last knowledge build recorded", &error))?;
    if let Some(state) = state {
        emit(out, &describe_state(root, &state))?;
        return Ok(Exit::Ok);
    }
    let mut text = format!("no build of {} has completed\n", tree(root).display());
    text.push_str(
        "which is a state and not a missing answer: the state file is removed before a build swaps \
         its tree into place and written after, so its absence means this tree is mid-build or has \
         never been built. Run `yaam knowledge build`.\n",
    );
    emit(out, &text)?;
    Ok(Exit::Degraded)
}

/// Prints one entity's note.
///
/// Through the library's own parse and render rather than as the file's bytes. That costs a round
/// trip and buys the thing the round trip is there for: a note this build cannot read back is a
/// failure here, rather than text an operator is left to notice is wrong. A note whose fields have
/// shifted reports the wrong provenance for a fact, and provenance is the only thing making a fact
/// checkable.
///
/// An entity nothing is held about is an answer, so it exits `0`. Folding it into a failure would
/// make an entity nobody has written about indistinguishable from a store that cannot be read.
pub fn note(root: &Path, entity: &str, out: &mut dyn Write) -> Result<Exit> {
    let key = key(entity)?;
    let found =
        yaam_knowledge::lookup(root, &key).map_err(|error| failed("reading the note", &error))?;
    let text = match found {
        Some(note) => note
            .render()
            .map_err(|error| failed("rendering the note", &error))?,
        None => nothing_held(&key),
    };
    emit(out, &text)?;
    Ok(Exit::Ok)
}

/// Lists the notes whose scalars carry a term.
///
/// Says which kind of search it is, because the two answer differently and both answer emptily. This
/// is a substring match over each note's own scalars; the full-text index over record bodies is
/// `yaam-read search`, and a caller expecting stemming and ranking would read this empty answer as
/// "nothing known".
pub fn search(root: &Path, term: &str, limit: usize, out: &mut dyn Write) -> Result<Exit> {
    let found = yaam_knowledge::search(root, term, limit)
        .map_err(|error| failed("searching the knowledge tree", &error))?;
    let mut text = match found.len() {
        1 => format!("1 note carries `{term}`\n"),
        count => format!("{count} notes carry `{term}`\n"),
    };
    for note in &found {
        listed(&mut text, note);
    }
    if found.len() == limit {
        let _ = writeln!(
            text,
            "the --limit stopped this listing, not the tree: there may be more."
        );
    }
    text.push_str(
        "a substring match over the scalars a note carries — identifiers, attribute keys and \
         values, agent names. Not full text, and no prose is reachable this way because the \
         derivation never read a body: `yaam-read search` is the one that reaches record bodies. \
         `yaam knowledge note --entity kind:id` prints one of these in full.\n",
    );
    emit(out, &text)?;
    Ok(Exit::Ok)
}

/// Prints the structure of the records behind a fact.
///
/// As JSON, which is the one place in this module that is not prose. The claim being made is that a
/// fact can be checked without reading anybody's data, and the whole structure printed verbatim is
/// what lets an operator see for themselves that no field of it holds prose. A prose summary of the
/// structure would be this command asserting the property instead of showing it.
///
/// An identifier that comes back unanswered is reported rather than passed over: the read applies
/// the same gate the derivation does, so naming a scoped or erasable record is not a way to read its
/// structure, and an operator who is not told that would read the gap as a lost record.
pub fn evidence(root: &Path, wanted: &[String], out: &mut dyn Write) -> Result<Exit> {
    let asked = wanted
        .iter()
        .map(|id| {
            RecordId::parse(id).map_err(|error| {
                config(format!(
                    "--record {id} is not a record identifier: {error}. A note lists the ones \
                     behind each of its facts"
                ))
            })
        })
        .collect::<Result<Vec<RecordId>>>()?;
    let found = yaam_knowledge::evidence(root, &asked)
        .map_err(|error| failed("reading the records behind a fact", &error))?;
    emit(out, &describe_evidence(&asked, &found)?)?;
    Ok(Exit::Ok)
}

/// A finished build, as an operator reads it.
fn describe_build(root: &Path, report: &BuildReport) -> String {
    let mut text = format!("rebuilt {}\n", tree(root).display());
    line(&mut text, "records read", report.records_read);
    line(&mut text, "records used", report.records_used);
    line(&mut text, "excluded, erasable", report.skipped_erasable);
    line(&mut text, "excluded, scoped", report.skipped_scoped);
    line(&mut text, "excluded, untimed", report.skipped_untimed);
    line(&mut text, "unreadable sources", report.skipped_unreadable);
    line(&mut text, "entities", report.entities);
    line(&mut text, "facts", report.facts);

    if report.skipped_erasable > 0 {
        text.push_str(
            "an erasable body is excluded on purpose. A note is an aggregate, and an aggregate \
             cannot be un-aggregated from a backup: subtracting one record's contribution reaches \
             the live copy and not last night's, so a record a key protects contributes nothing \
             rather than contributing something an erasure would have to chase.\n",
        );
    }
    if report.skipped_scoped > 0 {
        text.push_str(
            "a record that is not readable org-wide is excluded because a note is a shared file \
             with no scope of its own, and deriving from one would move restricted structure \
             somewhere the restriction does not apply.\n",
        );
    }
    if report.skipped_untimed > 0 || report.skipped_unreadable > 0 {
        text.push_str(
            "a source that would not parse, or a stamp that would not, is drift between the tree \
             and what can be derived from it. Nothing is lost — the record is still in the tree, \
             and a build after the cause is fixed picks it up.\n",
        );
    }
    text.push_str(DISPOSABLE);
    text
}

/// What the last build recorded, as an operator reads it.
fn describe_state(root: &Path, state: &SyncState) -> String {
    let mut text = format!("{}\n", tree(root).display());
    let _ = writeln!(
        text,
        "  {:<20}{}",
        "built",
        timestamp::format_ms(state.rebuilt_ms)
    );
    line(&mut text, "records read", state.records_read);
    line(&mut text, "records used", state.records_used);
    line(&mut text, "entities", state.entities);
    line(&mut text, "facts", state.facts);
    text.push_str(
        "these are the figures of the build that wrote this tree, not of the record tree as it now \
         stands. A store that has taken writes since is a store whose knowledge is behind them.\n",
    );
    text.push_str(DISPOSABLE);
    text
}

/// The records behind a fact, and what an unanswered identifier means.
fn describe_evidence(asked: &[RecordId], found: &[RecordStructure]) -> Result<String> {
    let mut text = format!("{} of {} records answered\n", found.len(), asked.len());
    for structure in found {
        let json = serde_json::to_string(structure)
            .map_err(|error| failed("rendering a record's structure", &error))?;
        let _ = writeln!(text, "{json}");
    }
    if found.len() < asked.len() {
        text.push_str(
            "an identifier that is not answered names a record this derivation would not have used \
             — one whose body is erasable, one not readable org-wide, one whose stamp will not \
             parse — or a record no longer in the tree. The read applies the same gate the \
             derivation does, so naming such a record is not a way to read its structure.\n",
        );
    }
    text.push_str(
        "structure, never a body: there is no field for prose in what is printed above, which is \
         what makes checking a fact against its evidence free of reading anybody's data.\n",
    );
    Ok(text)
}

/// One line of a listing: which entity, and how much is held about it.
fn listed(text: &mut String, note: &Note) {
    let _ = writeln!(
        text,
        "  {}:{}  {} facts",
        note.entity.kind,
        note.entity.id,
        note.facts.len()
    );
}

/// What to say about an entity knowledge holds nothing about.
///
/// Both reasons, because they call for opposite next acts and the answer looks identical: either
/// nothing the derivation may use names this entity, or it is spelled differently in the tree.
fn nothing_held(key: &EntityKey) -> String {
    format!(
        "knowledge holds nothing about {}:{}\nEither no record the derivation may use names it — a \
         record whose body is erasable contributes nothing — or the tree spells the identifier \
         differently: it was canonicalised on the way in and nothing here canonicalises again. \
         `yaam knowledge search --query {}` finds the spelling.\n",
        key.kind, key.id, key.id
    )
}

/// One `kind:id` pair, or a refusal.
///
/// Split at the first colon, matching the reads: a kind carries none and several configured
/// identifiers do, so splitting at the last would take an identifier's own colon for the separator.
fn key(spec: &str) -> Result<EntityKey> {
    let (kind, id) = spec.split_once(':').ok_or_else(|| {
        config(format!(
            "--entity {spec} names no kind: it is `kind:id`, as `ticket:PROJ-42`"
        ))
    })?;
    if kind.is_empty() || id.is_empty() {
        return Err(config(format!(
            "--entity {spec} leaves one half empty: it is `kind:id`, and neither half is optional"
        )));
    }
    Ok(EntityKey::new(kind, id))
}

/// Where the knowledge tree is, for a report to name.
fn tree(root: &Path) -> std::path::PathBuf {
    root.join(KNOWLEDGE_DIR)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use yaam_contract::Visibility;
    use yaam_core::{Paths, Pipeline};

    use super::{KNOWLEDGE_DIR, build, evidence, note, search, status};
    use crate::cli::KnowledgeCommand;
    use crate::exit::Exit;
    use crate::fixtures::{self, BODY};

    /// A tree with this repository's spec, and a pipeline to write records through it.
    ///
    /// Records go in through the real write path rather than as hand-written files, because
    /// "knowledge is a function of the record tree" is a claim about the tree a deployment actually
    /// produces. A fixture tree written by hand would let a layout change pass here and fail in a
    /// deployment.
    struct Tree {
        dir: tempfile::TempDir,
        pipeline: Pipeline,
    }

    impl Tree {
        fn new() -> Self {
            let dir = fixtures::tree();
            let pipeline =
                Pipeline::with_paths(Paths::under(dir.path())).expect("a pipeline over the tree");
            Self { dir, pipeline }
        }

        fn root(&self) -> &Path {
            self.dir.path()
        }
    }

    /// The text a command printed.
    fn run(command: impl FnOnce(&mut Vec<u8>) -> crate::error::Result<Exit>) -> (Exit, String) {
        let mut out = Vec::new();
        let exit = command(&mut out).expect("the command ran");
        (exit, String::from_utf8(out).expect("utf-8"))
    }

    /// What one command exited with, and what it printed, dispatched the way a binary dispatches it.
    fn run_reported(root: &Path, command: &KnowledgeCommand) -> (Exit, String) {
        let mut out = Vec::new();
        let exit = super::run(root, command, &mut out).expect("the command ran");
        (exit, String::from_utf8(out).expect("utf-8"))
    }

    /// The same, where the exit code is not what is being asserted.
    fn run_text(root: &Path, command: &KnowledgeCommand) -> String {
        run_reported(root, command).1
    }

    /// A tree holding one derivable record and one the gate excludes.
    fn populated() -> Tree {
        let mut tree = Tree::new();
        tree.pipeline
            .accept(fixtures::record("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        tree.pipeline
            .accept(
                fixtures::subject_record("2026-08-21T10:00:00Z", &fixtures::subject('a')),
                BODY,
            )
            .expect("accepted");
        tree
    }

    /// The counts are the whole report, and the erasable one is the load-bearing figure: an operator
    /// reading zero there on a store holding subject-derived records is reading a broken gate.
    #[test]
    fn a_build_counts_what_contributed_and_what_the_gate_excluded() {
        let tree = populated();
        let (exit, printed) = run(|out| build(tree.root(), out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("records read        2"), "{printed}");
        assert!(printed.contains("records used        1"), "{printed}");
        assert!(printed.contains("excluded, erasable  1"), "{printed}");
        assert!(printed.contains("excluded, scoped    0"), "{printed}");
        assert!(printed.contains("entities            1"), "{printed}");
        assert!(printed.contains("cannot be un-aggregated"), "{printed}");
        assert!(printed.contains("delete knowledge/"), "{printed}");
    }

    /// A build over a store nobody has written to is an empty tree, not a failure: the same command
    /// runs on a fresh deployment and on a busy one.
    #[test]
    fn a_build_over_a_store_with_no_records_is_empty_rather_than_a_failure() {
        let tree = Tree::new();
        let (exit, printed) = run(|out| build(tree.root(), out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("records read        0"), "{printed}");
        // Nothing was excluded, so nothing explains an exclusion. A report that argued about the
        // erasure gate over an empty store would teach an operator to skip the prose.
        assert!(!printed.contains("un-aggregated"), "{printed}");
    }

    /// A record readable by one owner is excluded, and the report says why rather than leaving an
    /// operator to read the count as a fault. A note is a shared file with no scope of its own.
    #[test]
    fn a_build_excludes_a_record_no_reader_outside_its_owner_may_see() {
        let mut tree = Tree::new();
        let mut owned = fixtures::record("2026-08-20T09:00:00Z");
        owned.visibility = Visibility::Owner;
        tree.pipeline.accept(owned, BODY).expect("accepted");

        let (exit, printed) = run_reported(tree.root(), &KnowledgeCommand::Build);
        assert_eq!(
            exit,
            Exit::Ok,
            "a working boundary is not a degraded store: {printed}"
        );
        assert!(printed.contains("excluded, scoped    1"), "{printed}");
        assert!(printed.contains("no scope of its own"), "{printed}");
        assert!(printed.contains("entities            0"), "{printed}");
    }

    /// A record file this build cannot read is drift, and the one exclusion worth an exit code: the
    /// others are the gate working, and this one is a record in the tree contributing nothing.
    #[test]
    fn a_build_reports_a_source_it_could_not_read_as_degraded() {
        let mut tree = Tree::new();
        tree.pipeline
            .accept(fixtures::record("2026-08-20T09:00:00Z"), BODY)
            .expect("accepted");
        fs::write(
            tree.root().join("records/2026/08/20/unreadable.md"),
            "---\naction: [unclosed\n---\nbody\n",
        )
        .expect("write");

        let (exit, printed) = run_reported(tree.root(), &KnowledgeCommand::Build);
        assert_eq!(exit, Exit::Degraded, "{printed}");
        assert!(printed.contains("unreadable sources  1"), "{printed}");
        assert!(printed.contains("still in the tree"), "{printed}");
    }

    /// Every command reaches the operation it names.
    ///
    /// The dispatch is the one place a knowledge command could be wired to the wrong library call,
    /// and a build wired where a read belongs would rewrite the tree somebody meant to read.
    #[test]
    fn each_command_reaches_the_operation_it_names() {
        let tree = populated();
        assert!(run_text(tree.root(), &KnowledgeCommand::Build).contains("rebuilt"));
        assert!(run_text(tree.root(), &KnowledgeCommand::Status).contains("records used"));
        assert!(
            run_text(
                tree.root(),
                &KnowledgeCommand::Note {
                    entity: "ticket:PROJ-42".to_owned()
                }
            )
            .contains("ticket:PROJ-42")
        );
        assert!(
            run_text(
                tree.root(),
                &KnowledgeCommand::Search {
                    query: "staging".to_owned(),
                    limit: 5
                }
            )
            .contains("note carries")
        );
        assert!(
            run_text(
                tree.root(),
                &KnowledgeCommand::Evidence {
                    records: vec!["01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned()]
                }
            )
            .contains("0 of 1 records answered")
        );
    }

    /// No state file means mid-build or never built, which is a state worth an exit code: a store
    /// answering out of a knowledge tree nobody has built wants an operator.
    #[test]
    fn a_status_before_any_build_is_degraded_and_says_why() {
        let tree = Tree::new();
        let (exit, printed) = run(|out| status(tree.root(), out));
        assert_eq!(exit, Exit::Degraded, "{printed}");
        assert!(printed.contains("no build of"), "{printed}");
        assert!(
            printed.contains("mid-build or has never been built"),
            "{printed}"
        );
    }

    /// What status reports is the build's figures and not the tree's, and it says so — a store that
    /// has taken writes since is a store whose knowledge is behind them.
    ///
    /// The time is asserted through the parser rather than against a literal, because the figure is
    /// read from the clock. What matters about it is that it is a stamp a person and a parser can
    /// both read: the millisecond count the state file holds is neither.
    #[test]
    fn a_status_after_a_build_reports_that_builds_figures() {
        let tree = populated();
        run(|out| build(tree.root(), out));

        let (exit, printed) = run(|out| status(tree.root(), out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("records read        2"), "{printed}");
        assert!(printed.contains("records used        1"), "{printed}");
        assert!(
            printed.contains("not of the record tree as it now stands"),
            "{printed}"
        );

        let built = printed
            .lines()
            .find_map(|line| line.trim().strip_prefix("built"))
            .map(str::trim)
            .expect("a build time");
        assert!(
            yaam_contract::timestamp::parse_ms(built).is_some(),
            "{built}"
        );
    }

    /// The property the whole crate rests on, checked where an operator would see it break: a note
    /// printed at a terminal carries facts and provenance, and no line of the body behind them.
    #[test]
    fn a_note_prints_its_facts_and_never_the_body_behind_them() {
        let tree = populated();
        run(|out| build(tree.root(), out));

        let (exit, printed) = run(|out| note(tree.root(), "ticket:PROJ-42", out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("ticket:PROJ-42"), "{printed}");
        assert!(printed.contains("staging"), "{printed}");
        assert!(printed.contains("agent_a"), "{printed}");
        assert!(!printed.contains(BODY), "a body reached a note: {printed}");
    }

    /// An entity nothing is held about is an answer. It exits `0` and names both reasons, because
    /// they look identical and call for opposite next acts.
    #[test]
    fn a_note_for_an_unknown_entity_is_an_answer_rather_than_a_failure() {
        let tree = populated();
        run(|out| build(tree.root(), out));

        let (exit, printed) = run(|out| note(tree.root(), "ticket:PROJ-999", out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(
            printed.contains("holds nothing about ticket:PROJ-999"),
            "{printed}"
        );
        assert!(
            printed.contains("spells the identifier differently"),
            "{printed}"
        );
    }

    /// The erasure gate reaches the reads too: the subject-derived record's entity contributed
    /// nothing, so nothing is held about it and nothing about it can be read back.
    #[test]
    fn a_note_holds_nothing_about_an_entity_only_an_erasable_record_named() {
        let tree = populated();
        run(|out| build(tree.root(), out));

        let (_, printed) = run(|out| note(tree.root(), "order_ref:ord10014721", out));
        assert!(printed.contains("holds nothing about"), "{printed}");
    }

    /// An entity that names no kind is refused before the tree is touched, because `PROJ-42` alone
    /// would otherwise be looked up under a kind nothing configures and answered as an empty tree.
    #[test]
    fn an_entity_missing_either_half_is_refused_before_anything_is_read() {
        let tree = Tree::new();
        let mut out = Vec::new();
        for spec in ["PROJ-42", "ticket:", ":PROJ-42"] {
            let error = note(tree.root(), spec, &mut out).expect_err("refused");
            assert_eq!(error.exit(), Exit::Config, "{error}");
        }
        assert!(out.is_empty(), "nothing was read, so nothing is reported");
    }

    /// A search lists what it found and says which kind of search it was, so an empty answer is not
    /// read as "nothing known" by a caller who expected the full-text index.
    #[test]
    fn a_search_lists_the_notes_a_term_reaches_and_names_what_it_matched() {
        let tree = populated();
        run(|out| build(tree.root(), out));

        let (exit, printed) = run(|out| search(tree.root(), "STAGING", 10, out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("1 note carries `STAGING`"), "{printed}");
        assert!(printed.contains("ticket:PROJ-42"), "{printed}");
        assert!(printed.contains("Not full text"), "{printed}");

        // The body was never read, so it is not reachable from here however it is spelled.
        let (_, printed) = run(|out| search(tree.root(), "Rolled out", 10, out));
        assert!(printed.contains("0 notes carry"), "{printed}");
    }

    /// The cap has to name itself, or a listing the cap truncated reads as the whole tree.
    #[test]
    fn a_search_says_when_its_own_limit_stopped_the_listing() {
        let tree = populated();
        run(|out| build(tree.root(), out));

        let (_, printed) = run(|out| search(tree.root(), "PROJ-42", 1, out));
        assert!(
            printed.contains("--limit stopped this listing"),
            "{printed}"
        );
    }

    /// Evidence hands back the frontmatter behind a fact and nothing else, which is what makes a
    /// fact checkable without reading anybody's data.
    #[test]
    fn evidence_answers_with_structure_and_no_prose() {
        let mut tree = Tree::new();
        let record = fixtures::record("2026-08-20T09:00:00Z");
        let id = record.record_id.clone();
        tree.pipeline.accept(record, BODY).expect("accepted");
        run(|out| build(tree.root(), out));

        let (exit, printed) = run(|out| evidence(tree.root(), &[id.as_str().to_owned()], out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("1 of 1 records answered"), "{printed}");
        assert!(printed.contains(id.as_str()), "{printed}");
        assert!(
            !printed.contains(BODY),
            "a body reached evidence: {printed}"
        );
        assert!(!printed.contains("summary"), "{printed}");
    }

    /// Naming a record the derivation would not have used is not a way to read it. The gap is
    /// reported, because an operator not told about it would read it as a lost record.
    #[test]
    fn evidence_refuses_a_record_the_derivation_would_not_have_used_and_says_so() {
        let mut tree = Tree::new();
        let excluded = fixtures::subject_record("2026-08-21T10:00:00Z", &fixtures::subject('a'));
        let id = excluded.record_id.clone();
        tree.pipeline.accept(excluded, BODY).expect("accepted");
        run(|out| build(tree.root(), out));

        let (exit, printed) = run(|out| evidence(tree.root(), &[id.as_str().to_owned()], out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(printed.contains("0 of 1 records answered"), "{printed}");
        assert!(
            printed.contains("not a way to read its structure"),
            "{printed}"
        );
    }

    /// A store that has built its knowledge is not a store with a stray directory beside it.
    ///
    /// The interaction this module could not be added without: `backup`, `check` and the commit
    /// guard all report an entry under the root that the manifest does not classify, so the first
    /// build would otherwise have degraded three commands at once. Two crates spell the directory
    /// and this is the only one that sees both, which is why the drift is caught here.
    #[test]
    fn a_built_knowledge_tree_is_left_behind_deliberately_rather_than_unclassified() {
        let tree = populated();
        run(|out| build(tree.root(), out));

        let elsewhere = tempfile::TempDir::new().expect("tempdir");
        let (exit, printed) =
            run(|out| crate::ops::backup(&tree.pipeline, &elsewhere.path().join("copy"), out));
        assert_eq!(exit, Exit::Ok, "{printed}");
        assert!(!printed.contains("in no manifest"), "{printed}");
        assert!(
            printed.lines().any(|listed| {
                listed.trim_start().starts_with(KNOWLEDGE_DIR) && listed.contains("present")
            }),
            "the built tree is not named among what a backup leaves behind: {printed}"
        );
    }

    /// A record identifier that is not one is refused before the tree is walked, and names itself:
    /// evidence takes what a note printed, and a mistyped one would otherwise look like a record
    /// the gate excluded.
    #[test]
    fn a_record_identifier_that_is_not_one_is_refused_by_name() {
        let tree = Tree::new();
        let mut out = Vec::new();
        let error =
            evidence(tree.root(), &["not-a-ulid".to_owned()], &mut out).expect_err("refused");
        assert_eq!(error.exit(), Exit::Config, "{error}");
        assert!(error.to_string().contains("not-a-ulid"), "{error}");
        assert!(out.is_empty(), "nothing was read, so nothing is reported");
    }
}
