//! The queries the system exists to answer.
//!
//! Three rules hold everywhere here. Ordering, windowing and joins use the server-stamped time, so
//! a skewed or replayed source clock cannot reorder history. No query calls a `SQLite` time
//! function: "now" arrives as a bound parameter, which keeps a query reproducible under test and
//! keeps its plan free of a non-deterministic term. And every read carries a [`Scope`] — what a
//! caller may see is a predicate, not a convention, and the one it defaults to is *nothing*.
//!
//! Two projections, one query each. A read returns either the matching identifiers or their stored
//! frontmatter, and the second is the *same* statement with a wider select list — not a second query
//! over the ids the first returned. That is deliberate: a follow-up read is a place the scope
//! predicate can be forgotten, and the `body` column is never in either select list, so no read here
//! can return prose whether it was sealed or not.

use rusqlite::{Row, params_from_iter, types::Value as SqlValue};
use yaam_contract::{RecordId, RecordStructure, Visibility};

/// Rows a read of identifiers returns when the caller names no page size.
///
/// A cap rather than everything. "Page size" with no default and no cursor is a trap: the first
/// caller to omit it reads the whole index into memory, and it works until the index is large. A
/// caller that wants a different number says so, and one that wants more than this pages by
/// narrowing the window — there is deliberately no offset to walk.
pub const DEFAULT_LIMIT: u32 = 1_000;

/// Rows a read of *structure* returns when the caller names no page size.
///
/// Lower than [`DEFAULT_LIMIT`], because the row got thirty times bigger. An identifier is 26 bytes;
/// a record's stored frontmatter is 600 to 1,500 depending on how many attributes, entities and tags
/// it carries. A thousand of those is most of a megabyte in one answer, which is not a page — so the
/// default page size follows the projection rather than being one number for both.
pub const DEFAULT_STRUCTURE_LIMIT: u32 = 200;

/// A structure page must not default to the identifier page size. Checked at compile time, because
/// the two numbers are only meaningful relative to each other.
const _: () = assert!(DEFAULT_STRUCTURE_LIMIT < DEFAULT_LIMIT);

/// How many full-text matches [`search`] may examine per row it returns.
///
/// The scope test runs after the match, so the candidate set has to be wider than the page or a
/// scoped caller would never fill one. Twenty covers a caller entitled to a twentieth of what
/// matched; beyond that the page comes back short, which is the stated cost of bounding this read at
/// all.
pub const SCOPE_HEADROOM: u32 = 20;

/// Most full-text matches [`search`] will examine, whatever the page size.
///
/// Without this, a page size of a million would buy back the unbounded read the headroom exists to
/// prevent.
pub const MAX_CANDIDATES: u32 = 5_000;

/// How the full-text extension names itself in the messages it writes.
///
/// Dropped from what [`refused_needle`] reports, because the caller is being told what is wrong with
/// its needle and the name of the index extension is not part of that.
const FTS_PREFIX: &str = "fts5:";

/// The predicate for a read that may return nothing.
///
/// A predicate rather than an early return, so a scope that admits no record takes the same path as
/// one that admits some — there is no branch that could forget to apply it.
const MATCHES_NOTHING: &str = "1 = 0";

/// A time window, in server-stamped milliseconds.
#[derive(Debug, Clone, Copy)]
pub struct Window {
    /// Inclusive start.
    pub from_ms: i64,
    /// Exclusive end.
    pub to_ms: i64,
}

/// Which records a read may return.
///
/// The default is [`Scope::Nothing`] on purpose: a read whose entitlements could not be established
/// must come back empty rather than complete. Widening is then something a caller had to write.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Scope {
    /// No record at all.
    #[default]
    Nothing,
    /// Every record, whatever its visibility.
    ///
    /// What a sweep, a rebuild or an erasure reads with: those walk the index on the tree's behalf
    /// and are not answering a caller. A request-driven read must never use it.
    Unrestricted,
    /// One caller's entitlements.
    Caller {
        /// Visibility levels this caller may read at all.
        visibility: Vec<Visibility>,
        /// The caller's own identity. An owner-visible record matches only its own agent.
        agent: String,
        /// Teams whose team-visible records this caller may read. Empty matches no team-visible
        /// record, which is what a caller in no team should see.
        teams: Vec<String>,
    },
}

/// Filters for a record query.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Restrict to one action.
    pub action: Option<String>,
    /// Restrict to one outcome, spelled as the contract serialises it: `success`, `failure`,
    /// `partial` or `declined`.
    pub outcome: Option<String>,
    /// Restrict to one agent.
    pub agent: Option<String>,
    /// Require a structural attribute to equal a value.
    ///
    /// Compared as text: a whole number matches its decimal form, a truth value `true` or `false`.
    pub attr: Option<(String, String)>,
    /// Restrict to a time window.
    pub window: Option<Window>,
    /// Page size. `None` means the default for what the read returns — [`DEFAULT_LIMIT`] for
    /// identifiers, [`DEFAULT_STRUCTURE_LIMIT`] for structure — never unbounded.
    pub limit: Option<u32>,
    /// What the reader is entitled to see.
    pub scope: Scope,
}

/// One entity's history, newest first, one page of it.
///
/// `min_confidence` is the caller's tolerance for inferred references: `1.0` keeps only the ones
/// read out of a structured field. `limit` is the page size; `None` means [`DEFAULT_LIMIT`], never
/// unbounded — an entity's history is as long as the entity is busy, and the busiest identifier in
/// a store decides the cost of what the API calls a point lookup. Measured over a synthetic 200,000
/// record store: 0.039 ms for a tail identifier against 1.514 ms for the busiest one, and a real
/// store's hot entity is bigger than a synthetic store's.
///
/// A caller that has to see *every* reference — a rebuild verifying its own output, a sweep — reads
/// [`by_entity_unbounded`] and says so at the call site.
pub fn by_entity(
    store: &crate::Store,
    kind: &str,
    id: &str,
    min_confidence: f32,
    limit: Option<u32>,
    scope: &Scope,
) -> crate::Result<Vec<RecordId>> {
    let (sql, binds) = by_entity_sql(
        kind,
        id,
        min_confidence,
        Extent::Page(limit),
        scope,
        Select::Id,
    );
    run_ids(store, &sql, binds)
}

/// One entity's history as structure, newest first, one page of it.
///
/// [`by_entity`] with the wider select list: the same predicate, the same scope test, the same page
/// — and every matched row's stored frontmatter instead of its bare identifier. What a caller asking
/// an entity's history actually wanted, since an identifier is only answerable by another read this
/// service does not offer to a caller.
pub fn by_entity_structures(
    store: &crate::Store,
    kind: &str,
    id: &str,
    min_confidence: f32,
    limit: Option<u32>,
    scope: &Scope,
) -> crate::Result<Vec<RecordStructure>> {
    let (sql, binds) = by_entity_sql(
        kind,
        id,
        min_confidence,
        Extent::Page(limit),
        scope,
        Select::Structure,
    );
    run_structures(store, &sql, binds)
}

/// Every record touching one entity, with no row cap and no scope.
///
/// The read a rebuild's own verification needs. Capping *that* would let a hot entity fail
/// verification silently, which is why the page size went on the endpoint rather than on the query.
///
/// It takes no [`Scope`], and that is the guard rather than an omission: unbounded and unrestricted
/// are the same decision, so a request-driven path cannot reach for this one without also handing
/// back rows nobody checked entitlements against. Cost is linear in the entity's history and
/// bounded by nothing — do not answer a request from it.
pub fn by_entity_unbounded(
    store: &crate::Store,
    kind: &str,
    id: &str,
    min_confidence: f32,
) -> crate::Result<Vec<RecordId>> {
    let (sql, binds) = by_entity_sql(
        kind,
        id,
        min_confidence,
        Extent::Everything,
        &Scope::Unrestricted,
        Select::Id,
    );
    run_ids(store, &sql, binds)
}

/// How much of an entity's history one read may take.
///
/// Spelled out rather than left as an optional page size, because the two cases are not "a number or
/// the default" but "a page or all of it", and the second is not something a caller should be able to
/// ask for by leaving a field out.
#[derive(Clone, Copy)]
enum Extent {
    /// One page: `Some(n)` rows, or [`DEFAULT_LIMIT`] when the caller named none.
    Page(Option<u32>),
    /// Every reference there is. The rebuild's verification read, and nothing request-driven.
    Everything,
}

/// What a read pulls out of every row it matched.
///
/// A parameter on the query builders rather than a second set of them, so the two projections cannot
/// come from two different predicates. `body` is in neither: the column exists for the full-text
/// index, and a read that selected it would hand a caller prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Select {
    /// The record's identifier alone. What a sweep, a rebuild and a correlation want.
    Id,
    /// The record's identifier and its stored frontmatter — the whole plaintext structure.
    ///
    /// Costs a table lookup per returned row, because the covering indexes carry `record_id` and not
    /// the frontmatter. Bounded by the page size, which is why the page sizes came down when this
    /// projection arrived.
    Structure,
}

impl Select {
    /// The select list this projection reads.
    fn columns(self) -> &'static str {
        match self {
            Self::Id => "rec.record_id",
            Self::Structure => "rec.record_id, rec.frontmatter",
        }
    }

    /// The page size a caller that named none gets, which is a property of what the row costs.
    fn default_limit(self) -> u32 {
        match self {
            Self::Id => DEFAULT_LIMIT,
            Self::Structure => DEFAULT_STRUCTURE_LIMIT,
        }
    }
}

/// Runs a statement whose one column is a record id.
fn run_ids(store: &crate::Store, sql: &str, binds: Vec<SqlValue>) -> crate::Result<Vec<RecordId>> {
    let lease = store.lease()?;
    let mut stmt = lease.prepare(sql)?;
    ids_of(&mut stmt, binds)
}

/// Steps a prepared statement whose one column is a record id.
///
/// Split from preparing it for the full-text reads' sake: which of the two steps failed is what
/// says whether a failure was the caller's, so those two prepare for themselves and step through
/// here. See [`refused_needle`].
fn ids_of(
    stmt: &mut rusqlite::Statement<'_>,
    binds: Vec<SqlValue>,
) -> crate::Result<Vec<RecordId>> {
    collect(stmt.query_map(params_from_iter(binds), one_id)?)
}

/// Runs a statement whose columns are a record id and its stored frontmatter.
fn run_structures(
    store: &crate::Store,
    sql: &str,
    binds: Vec<SqlValue>,
) -> crate::Result<Vec<RecordStructure>> {
    let lease = store.lease()?;
    let mut stmt = lease.prepare(sql)?;
    structures_of(&mut stmt, binds)
}

/// Steps a prepared statement whose columns are a record id and its frontmatter, as [`ids_of`] does.
fn structures_of(
    stmt: &mut rusqlite::Statement<'_>,
    binds: Vec<SqlValue>,
) -> crate::Result<Vec<RecordStructure>> {
    let rows = stmt.query_map(params_from_iter(binds), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (id, frontmatter) = row?;
        out.push(crate::stored_structure(id, &frontmatter)?);
    }
    Ok(out)
}

/// Builds the entity query and its bindings.
///
/// Separate from running it for the reason [`filter_sql`] is: the plan is the only thing that says
/// whether the entity index was used, and it can only be asked of the statement text.
///
fn by_entity_sql(
    kind: &str,
    id: &str,
    min_confidence: f32,
    extent: Extent,
    scope: &Scope,
    select: Select,
) -> (String, Vec<SqlValue>) {
    let mut binds: Vec<SqlValue> = vec![
        kind.to_owned().into(),
        id.to_owned().into(),
        f64::from(min_confidence).into(),
    ];
    let mut sql = format!(
        "SELECT {}
         FROM entity_refs AS er
         JOIN records AS rec ON rec.id = er.record_pk
         WHERE er.kind = ? AND er.entity_id = ? AND er.confidence >= ?",
        select.columns()
    );
    if let Some(predicate) = scope_predicate(scope, "rec", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    // Ordered on the reference's own copy of the time, not on the record's: the two are the same
    // value, and only this one is in the index the seek uses — which is what lets the page size stop
    // the walk instead of capping a set that was sorted in full first.
    sql.push_str(" ORDER BY er.received_ms DESC, er.record_pk DESC");
    if let Extent::Page(page) = extent {
        push_limit(&mut sql, &mut binds, page, select);
    }
    (sql, binds)
}

/// Whether one record is in the index, as a point lookup.
///
/// Here because the alternative is reading every indexed identifier to answer one question about
/// one of them, which costs the whole table on every sweep. `id` is text rather than a parsed
/// identifier: the callers hold a filename, and a stem the contract would reject is by definition
/// not a row.
pub fn exists(store: &crate::Store, id: &str, scope: &Scope) -> crate::Result<bool> {
    let mut binds: Vec<SqlValue> = vec![id.to_owned().into()];
    let mut sql = "SELECT 1 FROM records AS rec WHERE rec.record_id = ?".to_owned();
    if let Some(predicate) = scope_predicate(scope, "rec", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    let lease = store.lease()?;
    let mut stmt = lease.prepare(&sql)?;
    Ok(stmt.exists(params_from_iter(binds))?)
}

/// Filtered record query.
///
/// Every predicate lands on an indexed column. `action`, `outcome` and `agent` are generated
/// columns rather than inline `json_extract`, and an attribute filter drives the query from the
/// attribute index instead of testing JSON per row.
pub fn by_filter(store: &crate::Store, filter: &Filter) -> crate::Result<Vec<RecordId>> {
    let (sql, binds) = filter_sql(filter, Select::Id);
    run_ids(store, &sql, binds)
}

/// The filtered query, returning each match's structure rather than its identifier.
///
/// The same statement as [`by_filter`] with a wider select list, so the scope predicate and the page
/// size are the ones that filtered the rows and not a second read's.
pub fn by_filter_structures(
    store: &crate::Store,
    filter: &Filter,
) -> crate::Result<Vec<RecordStructure>> {
    let (sql, binds) = filter_sql(filter, Select::Structure);
    run_structures(store, &sql, binds)
}

/// Builds the filtered query and its bindings.
///
/// Separate from running it so the plan can be asserted on: "indexed" is a property of the plan,
/// not of the source text, and nothing else would notice an index quietly going unused.
fn filter_sql(filter: &Filter, select: Select) -> (String, Vec<SqlValue>) {
    let mut binds: Vec<SqlValue> = Vec::new();
    let columns = select.columns();
    // Driving from record_attrs when an attribute is required: it is the most selective start
    // available, and it keeps the seek on an index either way.
    let mut sql = if let Some((key, value)) = &filter.attr {
        binds.push(key.clone().into());
        binds.push(value.clone().into());
        format!(
            "SELECT {columns} FROM record_attrs AS ra
         JOIN records AS rec ON rec.id = ra.record_pk
         WHERE ra.key = ? AND ra.value = ?"
        )
    } else {
        format!("SELECT {columns} FROM records AS rec WHERE 1 = 1")
    };
    for predicate in record_predicates(filter, "rec", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    sql.push_str(" ORDER BY rec.received_ms DESC, rec.id DESC");
    push_limit(&mut sql, &mut binds, filter.limit, select);
    (sql, binds)
}

/// Appends the row cap, which is emitted whether or not the caller named one.
///
/// The default comes from the projection: a page of structure costs far more than a page of
/// identifiers, and one number for both would make the cheaper read pay or the expensive one huge.
fn push_limit(sql: &mut String, binds: &mut Vec<SqlValue>, limit: Option<u32>, select: Select) {
    sql.push_str(" LIMIT ?");
    binds.push(i64::from(limit.unwrap_or_else(|| select.default_limit())).into());
}

/// Correlates two actions falling within `within_ms` of each other.
///
/// The shape most cross-agent questions reduce to: something failed, and something else happened
/// nearby. A non-equi range join, so it needs the covering index to stay cheap.
///
/// Directional: a pair is returned when the right record was stamped at or after the left one and
/// no later than `within_ms` after it. Bound the search with `left.window` — there is deliberately
/// no implicit "recent", because a query whose meaning depends on when it ran cannot be tested.
/// `left.limit` caps the number of pairs, defaulting to [`DEFAULT_LIMIT`]; a page size on the right
/// side has no meaning for a join.
pub fn correlate(
    store: &crate::Store,
    left: &Filter,
    right: &Filter,
    within_ms: i64,
) -> crate::Result<Vec<(RecordId, RecordId)>> {
    let (sql, binds) = correlate_sql(left, right, within_ms);
    let lease = store.lease()?;
    let mut stmt = lease.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(binds), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut pairs = Vec::new();
    for row in rows {
        let (left_id, right_id) = row?;
        pairs.push((
            crate::stored_record_id(left_id)?,
            crate::stored_record_id(right_id)?,
        ));
    }
    Ok(pairs)
}

/// Builds the correlation query and its bindings.
fn correlate_sql(left: &Filter, right: &Filter, within_ms: i64) -> (String, Vec<SqlValue>) {
    let mut binds: Vec<SqlValue> = vec![within_ms.into()];
    let mut sql = "SELECT l.record_id, r.record_id
         FROM records AS l
         JOIN records AS r
           ON r.received_ms >= l.received_ms
          AND r.received_ms <= l.received_ms + ?
         WHERE l.id <> r.id"
        .to_owned();
    for predicate in correlate_predicates(left, "l", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    for predicate in correlate_predicates(right, "r", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    sql.push_str(" ORDER BY l.received_ms DESC, r.received_ms ASC, l.id DESC, r.id ASC");
    // A correlation returns pairs of identifiers, so it pages at the cheaper default.
    push_limit(&mut sql, &mut binds, left.limit, Select::Id);
    (sql, binds)
}

/// Full-text search over plaintext bodies only, best match first.
///
/// `needle` is an FTS5 query expression, so prefix and phrase syntax reach the caller; a malformed
/// one is reported rather than silently matching nothing. Sealed records hold an empty body and so
/// index no text; the explicit predicate says so at the query too, because "it cannot happen" is
/// not the same as "it is refused".
///
/// # What this costs, and what it buys
///
/// A `LIMIT` cannot be pushed into an FTS match, and every hit needs its `records` row for the scope
/// and sealed tests, so the obvious spelling of this query costs whatever the *corpus* matches
/// rather than whatever the caller asked for: 0.24 ms for a needle matching nothing, 6.9 ms for
/// 3,908 matching bodies, 583 ms for one common word matching 138,485 of them. So the candidates are
/// capped before the join, by [`candidate_ceiling`], and taken from the most recently indexed end of
/// the match. Descending row id is the only order the full-text index walks without visiting every
/// hit: measured over 137,995 matches, 200 candidates in row-id order cost 0.2 ms and the same 200
/// by rank cost 195 ms, because a global ranking has to score every hit to find the best few. Ranked
/// candidates would keep the better matches and give back the bound.
///
/// Row id is insertion order, which is arrival order: a live write takes the next id, and a rebuild
/// walks the tree in arrival order for this reason rather than by chance — `yaam_core`'s rebuild
/// sorts by it and has a test that says so. A backfilled record is the exception, arriving late with
/// an older stamp, so "newest" here means newest to the store rather than newest by claimed time. The
/// page itself is then ordered properly, by relevance and then server-stamped time, over whatever the
/// ceiling admitted.
///
/// The price is paid by a narrowly scoped caller. The ceiling is applied *before* the scope test,
/// because a scope predicate cannot be pushed into the match either, so a caller who may read only
/// a small share of the store can get a short page — up to and including an empty one — while
/// records it is entitled to sit just past the ceiling. It is a real loss of recall, deliberately
/// preferred to an unbounded read: the alternative is a page size that says nothing about the work
/// behind it. The ceiling leaves [`SCOPE_HEADROOM`]× the page for the scope test to discard, which
/// covers a caller who can read a twentieth of what matched, and no more than that.
pub fn search(
    store: &crate::Store,
    needle: &str,
    limit: u32,
    scope: &Scope,
) -> crate::Result<Vec<RecordId>> {
    let (sql, binds) = search_sql(needle, limit, scope, Select::Id);
    let lease = store.lease()?;
    let mut stmt = lease.prepare(&sql)?;
    ids_of(&mut stmt, binds).map_err(|error| refused_needle(needle, error))
}

/// Full-text search returning each match's structure rather than its identifier.
///
/// [`search`] with the wider select list: the same match, the same ceiling, the same scope test, and
/// each hit's stored frontmatter. What a caller asking a full-text question wanted — the prose the
/// needle matched is the one thing no read hands back, so an identifier would leave the caller
/// holding a name it cannot resolve.
///
/// `limit` is the page size, `None` meaning [`DEFAULT_STRUCTURE_LIMIT`] and never unbounded. Every
/// caveat on [`search`] holds unchanged, the recall one included: the ceiling is a multiple of
/// whatever page was asked for, so the smaller default page here also examines fewer candidates.
pub fn search_structures(
    store: &crate::Store,
    needle: &str,
    limit: Option<u32>,
    scope: &Scope,
) -> crate::Result<Vec<RecordStructure>> {
    let select = Select::Structure;
    let limit = limit.unwrap_or_else(|| select.default_limit());
    let (sql, binds) = search_sql(needle, limit, scope, select);
    let lease = store.lease()?;
    let mut stmt = lease.prepare(&sql)?;
    structures_of(&mut stmt, binds).map_err(|error| refused_needle(needle, error))
}

/// Reports a failure the needle caused as the caller's, and everything else as it arrived.
///
/// Only failures from *stepping* a full-text statement reach this, which is what makes the
/// attribution sound rather than a guess at a message: the needle is a bound parameter, so the match
/// expression is not read until the statement runs, while a statement this module spelled wrongly
/// and an index missing its full-text table are both refused at prepare. What is left is the
/// caller's own expression, whether or not the extension named itself in the message it wrote.
fn refused_needle(needle: &str, error: crate::Error) -> crate::Error {
    match &error {
        crate::Error::Sqlite(rusqlite::Error::SqliteFailure(code, Some(detail)))
            if code.code == rusqlite::ErrorCode::Unknown =>
        {
            crate::Error::BadNeedle {
                needle: needle.to_owned(),
                detail: detail
                    .strip_prefix(FTS_PREFIX)
                    .unwrap_or(detail)
                    .trim()
                    .to_owned(),
            }
        }
        _ => error,
    }
}

/// Matches the full-text index is allowed to hand to the scope test, for a page of `limit`.
///
/// Headroom for the scope predicate, capped so that a corpus-wide needle cannot buy an unbounded
/// read, and never below the page itself — a ceiling under the page size would cap the answer twice.
fn candidate_ceiling(limit: u32) -> u32 {
    limit
        .saturating_mul(SCOPE_HEADROOM)
        .min(MAX_CANDIDATES)
        .max(limit)
}

/// Builds the full-text query and its bindings.
fn search_sql(needle: &str, limit: u32, scope: &Scope, select: Select) -> (String, Vec<SqlValue>) {
    let mut binds: Vec<SqlValue> = vec![
        needle.to_owned().into(),
        i64::from(candidate_ceiling(limit)).into(),
    ];
    // The candidate set is its own statement so the ceiling applies to the match itself. Ordering
    // it by rowid descending is what lets the full-text index stop early: rowid is its own scan
    // order, so nothing is sorted and nothing past the ceiling is visited. `rank` comes out with
    // each candidate — best-match order among the candidates is still worth having, and it costs
    // only the rows already read.
    let mut sql = format!(
        "WITH candidates AS (
             SELECT rowid AS record_pk, rank AS relevance
             FROM records_fts
             WHERE records_fts MATCH ?
             ORDER BY rowid DESC
             LIMIT ?
         )
         SELECT {}
         FROM candidates
         JOIN records AS rec ON rec.id = candidates.record_pk
         WHERE rec.sealed = 0",
        select.columns()
    );
    if let Some(predicate) = scope_predicate(scope, "rec", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    // `rec.id` last, as every other read here does: relevance and `received_ms` both tie
    // readily -- two records carrying the same text score the same, and a batch written in one
    // millisecond shares a timestamp -- and an order that is not total makes a page arbitrary.
    sql.push_str(" ORDER BY candidates.relevance, rec.received_ms DESC, rec.id DESC LIMIT ?");
    binds.push(i64::from(limit).into());
    (sql, binds)
}

/// Predicates over a record alias, appending their bindings in the same order.
fn record_predicates(filter: &Filter, alias: &str, binds: &mut Vec<SqlValue>) -> Vec<String> {
    let mut predicates = Vec::new();
    if let Some(action) = &filter.action {
        predicates.push(format!("{alias}.action = ?"));
        binds.push(action.clone().into());
    }
    if let Some(outcome) = &filter.outcome {
        predicates.push(format!("{alias}.outcome = ?"));
        binds.push(outcome.clone().into());
    }
    if let Some(agent) = &filter.agent {
        predicates.push(format!("{alias}.agent = ?"));
        binds.push(agent.clone().into());
    }
    if let Some(window) = filter.window {
        predicates.push(format!(
            "{alias}.received_ms >= ? AND {alias}.received_ms < ?"
        ));
        binds.push(window.from_ms.into());
        binds.push(window.to_ms.into());
    }
    // Last, so that the columns a query is *selected* by still lead the predicate list, and so
    // every path that builds record predicates gets the scope test whether or not it remembers to.
    predicates.extend(scope_predicate(&filter.scope, alias, binds));
    predicates
}

/// The scope test over a record alias, as one predicate, or `None` when nothing is excluded.
///
/// The rules, in one place because they are the whole of "who may read what": org-visible records
/// are readable by any caller the service authenticated; a team-visible record only by a caller in
/// that team; an owner-visible record only by the agent it is attributed to; an operator-visible
/// record only by a caller whose entitlements name that level. A level the caller cannot satisfy
/// contributes no clause at all, so an entitlement without the identity to use it widens nothing.
fn scope_predicate(scope: &Scope, alias: &str, binds: &mut Vec<SqlValue>) -> Option<String> {
    let (visibility, agent, teams) = match scope {
        Scope::Unrestricted => return None,
        Scope::Nothing => return Some(MATCHES_NOTHING.to_owned()),
        Scope::Caller {
            visibility,
            agent,
            teams,
        } => (visibility, agent, teams),
    };

    let mut allowed: Vec<String> = Vec::new();
    for level in visibility {
        match level {
            Visibility::Owner => {
                allowed.push(format!("({alias}.visibility = ? AND {alias}.agent = ?)"));
                binds.push(level.as_str().to_owned().into());
                binds.push(agent.clone().into());
            }
            Visibility::Team if !teams.is_empty() => {
                let holes = vec!["?"; teams.len()].join(", ");
                allowed.push(format!(
                    "({alias}.visibility = ? AND {alias}.team IN ({holes}))"
                ));
                binds.push(level.as_str().to_owned().into());
                binds.extend(teams.iter().map(|team| SqlValue::from(team.clone())));
            }
            Visibility::Team => {}
            Visibility::Org | Visibility::Operator => {
                allowed.push(format!("{alias}.visibility = ?"));
                binds.push(level.as_str().to_owned().into());
            }
        }
    }

    Some(if allowed.is_empty() {
        MATCHES_NOTHING.to_owned()
    } else {
        format!("({})", allowed.join(" OR "))
    })
}

/// As [`record_predicates`], plus the attribute test as a semi-join.
///
/// A join has no single driving table to start from an attribute index, so the attribute becomes a
/// lookup on the already narrowed rows — still an index seek, still no JSON extraction.
fn correlate_predicates(filter: &Filter, alias: &str, binds: &mut Vec<SqlValue>) -> Vec<String> {
    let mut predicates = record_predicates(filter, alias, binds);
    if let Some((key, value)) = &filter.attr {
        predicates.push(format!(
            "EXISTS (SELECT 1 FROM record_attrs AS ra
                     WHERE ra.record_pk = {alias}.id AND ra.key = ? AND ra.value = ?)"
        ));
        binds.push(key.clone().into());
        binds.push(value.clone().into());
    }
    predicates
}

/// Reads the single record-id column of a row.
fn one_id(row: &Row<'_>) -> rusqlite::Result<String> {
    row.get(0)
}

/// Collects a row iterator of record ids.
fn collect(rows: impl Iterator<Item = rusqlite::Result<String>>) -> crate::Result<Vec<RecordId>> {
    let mut ids = Vec::new();
    for row in rows {
        ids.push(crate::stored_record_id(row?)?);
    }
    Ok(ids)
}

/// What the planner says it will do, for the reads above.
///
/// Behind a non-default feature because it is diagnostic surface, not caller surface: benchmarks and
/// operators need it, and a default build should not carry it. It lives here rather than in a
/// benchmark because the plan has to come from the *same* statement text the query runs — a plan
/// explained from a second, hand-copied spelling of the SQL is a plan for a query nobody executes.
#[cfg(feature = "explain")]
pub mod explain {
    use super::{
        Extent, Filter, Scope, Select, by_entity_sql, correlate_sql, filter_sql, search_sql,
    };

    /// How [`super::by_entity`] would run.
    pub fn by_entity(
        store: &crate::Store,
        kind: &str,
        id: &str,
        min_confidence: f32,
        limit: Option<u32>,
        scope: &Scope,
    ) -> crate::Result<String> {
        let (sql, binds) = by_entity_sql(
            kind,
            id,
            min_confidence,
            Extent::Page(limit),
            scope,
            Select::Id,
        );
        plan(store, &sql, binds)
    }

    /// How [`super::by_entity_structures`] would run.
    ///
    /// Its own helper rather than a note beside the one above: the wider select list is the whole
    /// difference between the read a sweep makes and the read a request makes, and whether it costs
    /// a table lookup per row is a property of the plan.
    pub fn by_entity_structures(
        store: &crate::Store,
        kind: &str,
        id: &str,
        min_confidence: f32,
        limit: Option<u32>,
        scope: &Scope,
    ) -> crate::Result<String> {
        let (sql, binds) = by_entity_sql(
            kind,
            id,
            min_confidence,
            Extent::Page(limit),
            scope,
            Select::Structure,
        );
        plan(store, &sql, binds)
    }

    /// How [`super::by_filter`] would run.
    pub fn by_filter(store: &crate::Store, filter: &Filter) -> crate::Result<String> {
        let (sql, binds) = filter_sql(filter, Select::Id);
        plan(store, &sql, binds)
    }

    /// How [`super::by_filter_structures`] would run.
    pub fn by_filter_structures(store: &crate::Store, filter: &Filter) -> crate::Result<String> {
        let (sql, binds) = filter_sql(filter, Select::Structure);
        plan(store, &sql, binds)
    }

    /// How [`super::correlate`] would run.
    pub fn correlate(
        store: &crate::Store,
        left: &Filter,
        right: &Filter,
        within_ms: i64,
    ) -> crate::Result<String> {
        let (sql, binds) = correlate_sql(left, right, within_ms);
        plan(store, &sql, binds)
    }

    /// How [`super::search`] would run.
    pub fn search(
        store: &crate::Store,
        needle: &str,
        limit: u32,
        scope: &Scope,
    ) -> crate::Result<String> {
        let (sql, binds) = search_sql(needle, limit, scope, Select::Id);
        plan(store, &sql, binds)
    }

    /// How [`super::search_structures`] would run.
    ///
    /// Its own helper for the reason [`by_entity_structures`] has one: the wider select list is the
    /// difference between the read a rebuild makes and the read a request makes, and what the extra
    /// column costs is a property of the plan rather than of the source text.
    pub fn search_structures(
        store: &crate::Store,
        needle: &str,
        limit: Option<u32>,
        scope: &Scope,
    ) -> crate::Result<String> {
        let select = Select::Structure;
        let limit = limit.unwrap_or_else(|| select.default_limit());
        let (sql, binds) = search_sql(needle, limit, scope, select);
        plan(store, &sql, binds)
    }

    /// Runs `EXPLAIN QUERY PLAN`, indenting each step under its parent.
    ///
    /// The parameters are bound rather than omitted: the planner is free to use a bound value, so a
    /// plan explained without them is not necessarily the plan the query gets.
    fn plan(
        store: &crate::Store,
        sql: &str,
        binds: Vec<rusqlite::types::Value>,
    ) -> crate::Result<String> {
        let lease = store.lease()?;
        let mut stmt = lease.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
        let rows = stmt.query_map(rusqlite::params_from_iter(binds), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        // Depth by walking parents rather than by nesting level in the result set: the rows arrive
        // flat, and a child can appear before another subtree's parent.
        let mut depth = std::collections::HashMap::from([(0i64, 0usize)]);
        let mut lines = Vec::new();
        for row in rows {
            let (id, parent, detail) = row?;
            let level = depth.get(&parent).copied().unwrap_or(0) + 1;
            depth.insert(id, level);
            lines.push(format!("{}{detail}", "  ".repeat(level - 1)));
        }
        Ok(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use yaam_contract::Visibility;

    use super::{
        DEFAULT_LIMIT, DEFAULT_STRUCTURE_LIMIT, Extent, Filter, MAX_CANDIDATES, SCOPE_HEADROOM,
        Scope, Select, SqlValue, Window, by_entity_sql, candidate_ceiling, correlate_sql,
        filter_sql, scope_predicate, search_sql,
    };

    /// What a reader on one team is entitled to.
    fn reader() -> Scope {
        Scope::Caller {
            visibility: vec![Visibility::Org, Visibility::Team, Visibility::Owner],
            agent: "agent_a".to_owned(),
            teams: vec!["platform".to_owned()],
        }
    }

    /// A migrated but empty database: the planner picks its indexes from the schema, so an empty
    /// table is enough to see whether a predicate can be served by a seek.
    fn migrated() -> rusqlite::Connection {
        let mut conn = rusqlite::Connection::open_in_memory().expect("open");
        crate::schema::migrate(&mut conn).expect("migrate");
        conn
    }

    /// The planner's own account of how it would run the query. Binding the real parameters also
    /// proves the builder emitted as many placeholders as it pushed values.
    fn plan(sql: &str, binds: Vec<SqlValue>) -> String {
        let conn = migrated();
        let mut stmt = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .expect("prepare");
        let rows = stmt
            .query_map(rusqlite::params_from_iter(binds), |row| {
                row.get::<_, String>(3)
            })
            .expect("explain");
        rows.map(|row| row.expect("row"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn filter_on_promoted_columns_seeks_an_index() {
        let filter = Filter {
            action: Some("deploy".to_owned()),
            outcome: Some("failure".to_owned()),
            window: Some(Window {
                from_ms: 1_000,
                to_ms: 9_000,
            }),
            limit: Some(10),
            // Scoped as a real read is: the scope narrows the rows a seek returned, so it must not
            // be what the query is driven from.
            scope: reader(),
            ..Filter::default()
        };
        let (sql, binds) = filter_sql(&filter, Select::Id);
        let ids = plan(&sql, binds);
        assert!(
            ids.contains("SEARCH") && ids.contains("USING INDEX records_action_outcome_time"),
            "expected an index seek, got:\n{ids}"
        );
        assert!(!ids.contains("SCAN records"), "unexpected scan:\n{ids}");

        // The structure projection is the same seek. It pays a table lookup per row it returns,
        // which the page size bounds; what it must not do is stop using the index.
        let (sql, binds) = filter_sql(&filter, Select::Structure);
        let structured = plan(&sql, binds);
        assert!(
            structured.contains("USING INDEX records_action_outcome_time"),
            "the wider select list must not cost the seek:\n{structured}"
        );
        assert!(
            !structured.contains("SCAN records"),
            "unexpected scan:\n{structured}"
        );
    }

    #[test]
    fn attribute_filter_seeks_the_attribute_index() {
        let filter = Filter {
            attr: Some(("order_ref".to_owned(), "ORD-1001".to_owned())),
            scope: reader(),
            ..Filter::default()
        };
        let (sql, binds) = filter_sql(&filter, Select::Id);
        let plan = plan(&sql, binds);
        assert!(
            plan.contains("SEARCH ra") && plan.contains("record_attrs_lookup"),
            "expected an attribute index seek, got:\n{plan}"
        );
    }

    #[test]
    fn correlation_seeks_both_sides() {
        let left = Filter {
            action: Some("deploy".to_owned()),
            outcome: Some("failure".to_owned()),
            scope: reader(),
            ..Filter::default()
        };
        let right = Filter {
            action: Some("ticket".to_owned()),
            attr: Some(("severity".to_owned(), "high".to_owned())),
            scope: reader(),
            ..Filter::default()
        };
        let (sql, binds) = correlate_sql(&left, &right, 60_000);
        let plan = plan(&sql, binds);
        assert!(
            !plan.contains("SCAN"),
            "range join fell back to a scan:\n{plan}"
        );
        // Each side wants the index that matches what it pins. The left pins action and outcome;
        // the right pins action alone, and asking it to use the outcome-leading index leaves a gap
        // mid-key that turns the range into a per-row filter. Measured, that was 25x.
        assert!(
            plan.contains("USING INDEX records_action_outcome_time"),
            "the side pinning action and outcome should use the index covering both:\n{plan}"
        );
        assert!(
            plan.contains("USING INDEX records_action_time"),
            "the side pinning action alone should use the action-leading index, not the one with \
             outcome mid-key:\n{plan}"
        );
    }

    #[test]
    fn a_page_of_entity_history_is_taken_in_index_order() {
        // The row cap on its own would be cosmetic. Under an index that could not supply the order,
        // every reference was sorted before the page was taken, so `LIMIT 10` over an entity with
        // 20,000 references cost 28 ms — the same as no limit at all — and 0.07 ms once the order
        // came out of the index. Only the plan tells those two apart.
        let (sql, binds) = by_entity_sql(
            "ticket",
            "PROJ-42",
            0.0,
            Extent::Page(Some(10)),
            &reader(),
            Select::Id,
        );
        let ids = plan(&sql, binds);
        assert!(
            ids.contains("entity_refs_recent"),
            "the entity index must supply the order:\n{ids}"
        );
        assert!(
            !ids.contains("USE TEMP B-TREE FOR ORDER BY"),
            "sorting the whole history before taking the page is what the index avoids:\n{ids}"
        );

        // Structure comes out of the same walk, in the same order, still without a sort.
        let (sql, binds) = by_entity_sql(
            "ticket",
            "PROJ-42",
            0.0,
            Extent::Page(Some(10)),
            &reader(),
            Select::Structure,
        );
        let structured = plan(&sql, binds);
        assert!(structured.contains("entity_refs_recent"), "{structured}");
        assert!(
            !structured.contains("USE TEMP B-TREE FOR ORDER BY"),
            "{structured}"
        );
    }

    #[test]
    fn the_unbounded_entity_read_is_the_only_one_without_a_cap() {
        let (bounded, _) = by_entity_sql(
            "ticket",
            "PROJ-42",
            0.0,
            Extent::Page(None),
            &reader(),
            Select::Id,
        );
        assert!(bounded.contains("LIMIT ?"), "{bounded}");
        let (unbounded, binds) = by_entity_sql(
            "ticket",
            "PROJ-42",
            0.0,
            Extent::Everything,
            &Scope::Unrestricted,
            Select::Id,
        );
        assert!(!unbounded.contains("LIMIT"), "{unbounded}");
        assert_eq!(binds.len(), 3, "no scope and no cap to bind: {binds:?}");
    }

    #[test]
    fn a_full_text_read_caps_its_candidates_before_the_join() {
        let (sql, binds) = search_sql("shards", 10, &reader(), Select::Id);
        let plan = plan(&sql, binds.clone());
        assert!(
            plan.contains("records_fts"),
            "the match must still be served by the full-text index:\n{plan}"
        );
        // The candidate set is materialised on its own, ahead of the join, which is the whole of the
        // bound: the join and the sort then see the ceiling and never the corpus.
        assert!(
            plan.contains("CO-ROUTINE") || plan.contains("SUBQUERY"),
            "the candidate cap must be its own step:\n{plan}"
        );
        assert!(
            binds.contains(&SqlValue::from(i64::from(candidate_ceiling(10)))),
            "the ceiling has to be bound, not implied: {binds:?}"
        );
    }

    #[test]
    fn the_candidate_ceiling_leaves_headroom_for_the_scope_and_stops() {
        assert_eq!(candidate_ceiling(10), 10 * SCOPE_HEADROOM);
        assert_eq!(candidate_ceiling(0), 0);
        // A page size large enough to reach the ceiling stops there, and one larger than the ceiling
        // is still served in full — a candidate set under the page would cap the answer twice.
        assert_eq!(candidate_ceiling(MAX_CANDIDATES), MAX_CANDIDATES);
        assert_eq!(candidate_ceiling(u32::MAX), u32::MAX);
    }

    #[test]
    fn a_full_text_page_is_ordered_totally() {
        // Relevance and `received_ms` both tie readily: two records carrying the same text score the
        // same, and a batch written inside one millisecond shares a timestamp. Without the primary
        // key last the page order is arbitrary, which is how a scope test passed eight runs in nine.
        for select in [Select::Id, Select::Structure] {
            let (sql, _) = search_sql("shards", 10, &reader(), select);
            let order = sql
                .rsplit_once("ORDER BY")
                .map(|(_, tail)| tail.to_owned())
                .expect("an ordered page");
            assert!(
                order.contains("rec.id"),
                "the page order must end at the primary key: {order}"
            );
        }
    }

    #[test]
    fn the_default_scope_matches_nothing() {
        // A filter nobody scoped is a read whose entitlements are unknown, and the only safe answer
        // to that is no rows.
        for select in [Select::Id, Select::Structure] {
            let (sql, _) = filter_sql(&Filter::default(), select);
            assert!(sql.contains("1 = 0"), "{select:?}: {sql}");
            // The full-text read the same way. Its scope test cannot be pushed into the match, so
            // it lands on the join instead — but it does land in the statement, so a record outside
            // the scope is never selected rather than selected and then dropped. A needle is the one
            // input a caller writes, and this is the read where that distinction is easiest to lose.
            let (sql, _) = search_sql("shards", 10, &Scope::default(), select);
            assert!(sql.contains("1 = 0"), "{select:?}: {sql}");
            let (scoped, _) = search_sql("shards", 10, &reader(), select);
            assert!(
                scoped.contains("rec.visibility = ?"),
                "{select:?}: {scoped}"
            );
            assert!(scoped.contains("rec.team IN"), "{select:?}: {scoped}");
        }
    }

    #[test]
    fn an_unrestricted_scope_adds_no_predicate() {
        let (sql, binds) = filter_sql(
            &Filter {
                scope: Scope::Unrestricted,
                ..Filter::default()
            },
            Select::Id,
        );
        assert!(!sql.contains("visibility"), "{sql}");
        assert_eq!(
            binds,
            vec![SqlValue::from(i64::from(DEFAULT_LIMIT))],
            "the row cap is the only thing an unscoped filter binds"
        );
    }

    #[test]
    fn a_read_that_names_no_page_size_is_still_bounded() {
        // An absent `limit` used to emit no `LIMIT` clause at all, so the first caller to omit it
        // read the whole index into memory — which works until the index is large.
        for (sql, binds) in [
            filter_sql(&Filter::default(), Select::Id),
            correlate_sql(&Filter::default(), &Filter::default(), 1),
        ] {
            assert!(sql.contains("LIMIT ?"), "{sql}");
            assert!(
                binds.contains(&SqlValue::from(i64::from(DEFAULT_LIMIT))),
                "{binds:?}"
            );
        }

        // A page of structure defaults lower, because the row is thirty times the size.
        let (sql, binds) = filter_sql(&Filter::default(), Select::Structure);
        assert!(sql.contains("LIMIT ?"), "{sql}");
        assert!(
            binds.contains(&SqlValue::from(i64::from(DEFAULT_STRUCTURE_LIMIT))),
            "{binds:?}"
        );

        // A caller that names one still gets exactly that.
        let (_, binds) = filter_sql(
            &Filter {
                limit: Some(7),
                ..Filter::default()
            },
            Select::Id,
        );
        assert!(binds.contains(&SqlValue::from(7i64)), "{binds:?}");
    }

    #[test]
    fn a_caller_scope_binds_every_level_it_claims() {
        let mut binds: Vec<SqlValue> = Vec::new();
        let predicate = scope_predicate(&reader(), "rec", &mut binds).expect("a predicate");

        assert!(predicate.contains("rec.agent = ?"), "{predicate}");
        assert!(predicate.contains("rec.team IN (?)"), "{predicate}");
        assert_eq!(
            binds,
            vec![
                SqlValue::from("org".to_owned()),
                SqlValue::from("team".to_owned()),
                SqlValue::from("platform".to_owned()),
                SqlValue::from("owner".to_owned()),
                SqlValue::from("agent_a".to_owned()),
            ],
            "a placeholder without its value in the same order is a silently wrong query"
        );
    }

    #[test]
    fn an_entitlement_without_the_identity_to_use_it_widens_nothing() {
        // Team-visible records and no team: the entitlement is real and satisfies no record.
        let mut binds: Vec<SqlValue> = Vec::new();
        let scope = Scope::Caller {
            visibility: vec![Visibility::Team],
            agent: "agent_a".to_owned(),
            teams: Vec::new(),
        };
        assert_eq!(
            scope_predicate(&scope, "rec", &mut binds).as_deref(),
            Some("1 = 0")
        );
        assert!(binds.is_empty());
    }

    /// The plan helpers explain the *same* statement text the queries run.
    ///
    /// Compiled only with the `explain` feature, which is what the benchmark turns on. Worth a test
    /// rather than trusting the benchmark to notice: a helper that quietly explained a different
    /// query would print a plan for something nobody executes, which is worse than printing none.
    #[cfg(feature = "explain")]
    #[test]
    fn the_plan_helpers_explain_the_queries_they_name() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("index.sqlite");
        drop(crate::Writer::open(&path).expect("migrate"));
        let store = crate::Store::open_read(&path).expect("open");

        let filter = Filter {
            action: Some("deploy".to_owned()),
            outcome: Some("failure".to_owned()),
            scope: reader(),
            ..Filter::default()
        };
        let plan = super::explain::by_filter(&store, &filter).expect("a plan");
        assert!(plan.contains("records_action_outcome_time"), "{plan}");
        // The projection a request runs has its own helper, and it explains the same seek.
        assert!(
            super::explain::by_filter_structures(&store, &filter)
                .expect("a plan")
                .contains("records_action_outcome_time")
        );
        assert!(
            super::explain::by_entity_structures(&store, "ticket", "PROJ-42", 1.0, None, &reader())
                .expect("a plan")
                .contains("entity_refs_recent")
        );

        // Every helper answers, and the join names both sides.
        assert!(
            super::explain::by_entity(&store, "ticket", "PROJ-42", 1.0, None, &reader())
                .expect("a plan")
                .contains("entity_refs_recent")
        );
        assert!(
            super::explain::search(&store, "shards", 10, &reader())
                .expect("a plan")
                .contains("records_fts")
        );
        assert!(
            super::explain::search_structures(&store, "shards", None, &reader())
                .expect("a plan")
                .contains("records_fts")
        );
        let join = super::explain::correlate(&store, &filter, &filter, 1_000).expect("a plan");
        assert_eq!(
            join.matches("records_action_outcome_time").count(),
            2,
            "{join}"
        );
    }

    #[test]
    fn no_query_reads_the_clock() {
        // A time function in the plan would make the result depend on when it ran.
        let (correlation, _) = correlate_sql(&Filter::default(), &Filter::default(), 1);
        let (filtered, _) = filter_sql(&Filter::default(), Select::Id);
        for sql in [correlation, filtered] {
            assert!(!sql.contains("unixepoch"), "clock read in: {sql}");
            assert!(!sql.contains("'now'"), "clock read in: {sql}");
        }
    }
}
