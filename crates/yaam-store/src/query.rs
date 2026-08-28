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

/// Pairs a correlation of *structure* returns when the caller names no page size.
///
/// Half [`DEFAULT_STRUCTURE_LIMIT`], because a pair row is two structures. The page size here is a
/// byte budget rather than a row count — a page of pairs at the structure default would be twice the
/// answer every other read is allowed to give, and the caller asking a two-sided question is the
/// last one who should be charged double for it without saying so.
///
/// It bounds the answer and not the duplication inside it: a left record paired with several right
/// ones is returned once per pair, frontmatter and all, because a pair is what was asked for. A
/// caller that wants fewer copies narrows `within_ms`.
pub const DEFAULT_PAIR_LIMIT: u32 = 100;

/// A pair page must not default to the single-structure page size. Checked at compile time, for the
/// reason above: the two numbers only mean anything relative to each other.
const _: () = assert!(DEFAULT_PAIR_LIMIT < DEFAULT_STRUCTURE_LIMIT);

/// Edges a traversal returns when the caller names no page size.
///
/// An edge row is one record's structure plus the two entity keys it links, so it costs a little
/// more than a single-structure row and far less than a pair. It is under [`MAX_FRONTIER`] on
/// purpose: the frontier is the ceiling on what the recursion will find, and a default page above it
/// would promise rows the traversal never materialises.
pub const DEFAULT_LINK_LIMIT: u32 = 100;

/// Most edges one traversal will materialise, whatever page size it was asked for.
///
/// A bound on the recursion rather than on the answer, which is what makes it a bound at all: the
/// work of a hop is the fan-out of the frontier, so capping the returned rows alone would let a wide
/// third hop cost the whole window and then throw most of it away. Measured over a 200,000-record
/// store, from its busiest identifier at depth 3: 347 edges over a 30-day window, and **35,845 edges
/// in 504 ms** over the whole two years. The corridor rule is what keeps that a five-figure number
/// rather than a six-figure one; this is what keeps it a page.
///
/// Two hundred, because it is also the largest page this read will serve — so the recursion does as
/// much work as the answer can carry and no more.
///
/// It is a ceiling on recall, and the cost is worse than [`search`]'s candidate ceiling rather than
/// merely analogous to it. SQLite fills a recursive queue breadth-first, so the cap is spent on near
/// hops before far ones: the 30-day depth-3 traversal above returns 115 hop-1 edges, 85 hop-2 edges
/// and **no hop-3 edges at all** — a request for three hops answered entirely out of the first two.
/// A per-hop budget would be the better shape and is not expressible as a `LIMIT` on the compound
/// select, so it is not what this does. Until it is, a deep question over a busy seed should narrow
/// its window rather than raise its page; a deep question over a quiet one is unaffected, because
/// its whole neighbourhood fits.
pub const MAX_FRONTIER: u32 = 200;

/// A traversal must not promise a page its own frontier cannot fill. Checked at compile time.
const _: () = assert!(DEFAULT_LINK_LIMIT <= MAX_FRONTIER);

/// Most references an entity may carry inside a traversal's window and still be a corridor.
///
/// The one number in this module that is a judgement rather than a measurement, so here is the
/// judgement. Below it sits a busy work item — a ticket touched a few dozen times over the day of an
/// incident — which is exactly the node a traversal has to be able to walk through, because "what
/// else was going on around this" is a question about that ticket's neighbourhood. Above it sits a
/// shared context object — a channel, a service, a deployment target — where the neighbourhood is
/// the corpus and the answer to any two-hop question through it is "everything".
///
/// It is not a percentile of the corpus, and that was a real choice. A percentile adapts, which
/// sounds better and is worse in three ways: it is a global aggregate over `entities`, so it is
/// either computed per query or materialised as derived state with a rebuild invariant — the remedy
/// the plan's §7.6 already rejected once for the correlation join; it moves, so the same traversal
/// answers differently tomorrow because an unrelated entity got busy, and a rule that cannot be
/// reproduced cannot be tested; and it always excludes its top percent, so a store where nothing is
/// a hub still loses its busiest entity as a corridor.
///
/// A caller may lower it and may not raise it. Lowering is how an operator tightens a traversal that
/// came back noisy; raising would be a way to buy back the incident this rule exists to prevent,
/// which is not a thing a request should be able to ask for.
pub const CORRIDOR_DEGREE: u32 = 32;

/// Deepest traversal this index will run.
///
/// Three, not because the fourth hop is expensive — the frontier bounds it — but because past the
/// third it is [`MAX_FRONTIER`] rather than the graph that decides the answer, and an answer decided
/// by its own bound is not a fact about the store. Refused at the endpoint rather than clamped: a
/// depth silently reduced is a caller believing it saw four hops.
pub const MAX_DEPTH: u32 = 3;

/// What each further hop is worth, relative to the one before it.
///
/// A hop-2 edge is a claim about a record the seed never named, so it is weaker evidence than a
/// hop-1 edge by construction, and a caller ranking these against anything else needs the exchange
/// rate stated rather than invented. Half per hop is the same attenuation the traversal this rule
/// was copied from uses; nothing here has measured a better one, and saying so is more useful than a
/// number with a false provenance.
pub const HOP_ATTENUATION: f32 = 0.5;

/// The confidence a reference read out of a structured field carries.
///
/// Spelled once, because three separate rules test against it: what a bundle will admit, what a
/// traversal defaults its floor to, and what a traversal requires of a reference before it will walk
/// *through* it.
pub const FULL_CONFIDENCE: f32 = 1.0;

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
    window: Option<Window>,
    limit: Option<u32>,
    scope: &Scope,
) -> crate::Result<Vec<RecordId>> {
    let (sql, binds) = by_entity_sql(
        kind,
        id,
        min_confidence,
        window,
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
    window: Option<Window>,
    limit: Option<u32>,
    scope: &Scope,
) -> crate::Result<Vec<RecordStructure>> {
    let (sql, binds) = by_entity_sql(
        kind,
        id,
        min_confidence,
        window,
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
        // No window, for the same reason there is no scope: this is the read that has to see
        // everything, and a sweep that skipped a reference outside some window would report a
        // rebuild complete having rebuilt part of it.
        None,
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

    /// The select list a join reads: this projection over each side, left first.
    ///
    /// Spelled out rather than composed from [`Select::columns`] with the alias substituted, because
    /// the column *order* is what the row reader unpacks by position — and a projection whose two
    /// halves could be assembled in either order is one a refactor can silently transpose, handing
    /// every caller the pair backwards.
    fn pair_columns(self) -> &'static str {
        match self {
            Self::Id => "l.record_id, r.record_id",
            Self::Structure => "l.record_id, l.frontmatter, r.record_id, r.frontmatter",
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
    window: Option<Window>,
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
    // Windowed on the reference's own copy of the time, for the same reason the ordering is: it is
    // the column the index carries, so a window narrows the seek rather than filtering rows the seek
    // already walked. Half-open, matching every other window in this module — the end is exclusive,
    // so consecutive windows tile without double-counting the instant they share.
    if let Some(window) = window {
        sql.push_str(" AND er.received_ms >= ? AND er.received_ms < ?");
        binds.push(window.from_ms.into());
        binds.push(window.to_ms.into());
    }
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
    let (sql, binds) = correlate_sql(left, right, within_ms, Select::Id);
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

/// The correlation as pairs of *structure* rather than pairs of identifiers.
///
/// [`correlate`] with the wider select list: the same join, the same direction, the same window, the
/// same scope test on both sides — and each side's stored frontmatter instead of its bare identifier.
/// What a caller asking a correlation wanted, because an identifier is answerable only by a read this
/// service does not offer a caller, and a pair of them is two names it cannot resolve rather than
/// one.
///
/// One statement, not this join for the ids and a second read for their structure. The second read
/// is where a scope predicate gets forgotten, and here it would be forgotten twice — a pair joins two
/// records whose visibility was decided separately, so a hydration step that dropped the predicate
/// would hand back the record on the other side of the join to a caller no read admits it to.
///
/// `left.limit` caps the number of *pairs*, defaulting to [`DEFAULT_PAIR_LIMIT`]: a pair row carries
/// two structures, so it is half what a single-structure page costs. A left record matching several
/// right ones is returned once per pair, its frontmatter repeated — the duplication is the shape of
/// the answer rather than a defect in it, and `within_ms` is what a caller narrows to reduce it.
pub fn correlate_structures(
    store: &crate::Store,
    left: &Filter,
    right: &Filter,
    within_ms: i64,
) -> crate::Result<Vec<(RecordStructure, RecordStructure)>> {
    let (sql, binds) = correlate_sql(left, right, within_ms, Select::Structure);
    let lease = store.lease()?;
    let mut stmt = lease.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(binds), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut pairs = Vec::new();
    for row in rows {
        let (left_id, left_front, right_id, right_front) = row?;
        pairs.push((
            crate::stored_structure(left_id, &left_front)?,
            crate::stored_structure(right_id, &right_front)?,
        ));
    }
    Ok(pairs)
}

/// Builds the correlation query and its bindings.
fn correlate_sql(
    left: &Filter,
    right: &Filter,
    within_ms: i64,
    select: Select,
) -> (String, Vec<SqlValue>) {
    let mut binds: Vec<SqlValue> = vec![within_ms.into()];
    let mut sql = format!(
        "SELECT {}
         FROM records AS l
         JOIN records AS r
           ON r.received_ms >= l.received_ms
          AND r.received_ms <= l.received_ms + ?
         WHERE l.id <> r.id",
        select.pair_columns()
    );
    for predicate in correlate_predicates(left, "l", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    for predicate in correlate_predicates(right, "r", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    sql.push_str(" ORDER BY l.received_ms DESC, r.received_ms ASC, l.id DESC, r.id ASC");
    // The page a correlation defaults to is the pair's, not the projection's: a pair of identifiers
    // is cheap and a pair of structures is two rows of frontmatter, so [`push_limit`]'s per-projection
    // default is the wrong one on this read and the page is resolved here instead.
    let page = match select {
        Select::Id => left.limit,
        Select::Structure => Some(left.limit.unwrap_or(DEFAULT_PAIR_LIMIT)),
    };
    push_limit(&mut sql, &mut binds, page, select);
    (sql, binds)
}

/// One entity, as a traversal names it. Kind and identifier, and nothing else.
///
/// Not an [`EntityRef`]: a reference carries a role and a confidence because it is a *record's*
/// claim about an entity, and the endpoints of a link are not claims — the claim is the [`Link`]
/// itself, and it carries the confidence of the weaker of the two references behind it. Reusing the
/// reference type here would have put a `role` on each end that belongs to whichever record was read
/// last.
///
/// [`EntityRef`]: yaam_contract::entity::EntityRef
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityKey {
    /// Kind the deployment configures.
    pub kind: String,
    /// Canonical identifier within the kind.
    pub id: String,
}

/// One edge of the graph `entity_refs` implies: two entities, and the record that names both.
///
/// The record is the whole point. A traversal that answered with entity identifiers would say *that*
/// two things are connected and never *why*, and the caller's only recourse would be a second read
/// per edge — which is the read where the scope predicate gets forgotten, times the number of edges.
/// So the evidence travels with the claim, and `R` is either the record's identifier or its whole
/// stored structure depending on which projection was asked for.
#[derive(Debug, Clone, PartialEq)]
pub struct Link<R> {
    /// The entity this edge was reached *from*: the seed at hop 1, a hop-1 neighbour at hop 2.
    pub from: EntityKey,
    /// The entity this edge reaches.
    pub to: EntityKey,
    /// How many records deep this edge sits: `1` for one the seed's own records made.
    pub hop: u32,
    /// The weaker of the two references the record makes, so an edge is never stronger than the
    /// worse half of its own evidence.
    pub confidence: f32,
    /// How many records inside the window reference [`Link::to`], counted no further than
    /// `max_degree + 1` — see [`Traversal::max_degree`]. Above the cap, this entity was reached and
    /// not traversed through.
    pub degree: u32,
    /// The record naming both ends.
    pub via: R,
}

impl<R> Link<R> {
    /// What this edge is worth relative to a hop-1 one, at [`HOP_ATTENUATION`] per hop.
    ///
    /// A method rather than a stored column because it is a pure function of [`Link::hop`], and a
    /// second copy of a derived number is a second thing to keep in step. It is contract all the
    /// same: a caller merging these edges with another signal needs to know how much a further hop
    /// costs, and one that had to guess would invent its own attenuation.
    #[must_use]
    pub fn score(&self) -> f32 {
        HOP_ATTENUATION.powi(i32::try_from(self.hop).unwrap_or(i32::MAX))
    }

    /// Whether the corridor rule stopped the traversal here rather than the requested depth.
    ///
    /// The distinction a caller cannot make from an edge list alone, and the same distinction a
    /// bundle's `omitted` exists for: an answer that stops because this entity is a hub and one that
    /// stops because nothing else is connected look identical, and they call for opposite next
    /// moves.
    #[must_use]
    pub fn hub(&self, traversal: &Traversal) -> bool {
        self.degree > traversal.max_degree && self.hop < traversal.depth
    }
}

/// What a traversal asks: a seed, how far, over which window, and what it will believe.
///
/// No [`Default`], deliberately, and `window` is a [`Window`] rather than an `Option<Window>`. The
/// two fields a traversal cannot be asked without are the two a defaulted request would silently
/// invent: a depth, because the work is exponential in it, and a window, because the seed's history
/// is as long as the seed is busy. `correlate` learned the second one the expensive way — measured
/// at 4.2 s unwindowed — and a traversal is that read at every hop.
#[derive(Debug, Clone)]
pub struct Traversal {
    /// Kind of the entity to start from.
    pub kind: String,
    /// Canonical identifier of the entity to start from.
    pub id: String,
    /// How many records deep to go: `1` is co-mention, `2` is co-mention of a co-mention.
    ///
    /// Held to [`MAX_DEPTH`] by whoever answers a request, not here. This module runs the traversal
    /// it is handed — a sweep or a test may reasonably go deeper than an endpoint will — and the
    /// refusal belongs where the caller is, so it can be reported as the caller's rather than
    /// silently reduced.
    pub depth: u32,
    /// Half-open span of server-stamped time every hop is taken inside.
    pub window: Window,
    /// Floor every reference on every hop must meet to be an edge at all.
    ///
    /// Below [`FULL_CONFIDENCE`] this admits references inferred from prose. It does not make them
    /// corridors: see [`linked`].
    pub min_confidence: f32,
    /// Most references an entity may have inside the window and still be traversed *through*.
    ///
    /// The corridor rule. See [`CORRIDOR_DEGREE`] for what the number is and why, and note that the
    /// direction it may be moved in is enforced where the request is — a caller of this module can
    /// name any cap, and an endpoint refuses one above the constant.
    pub max_degree: u32,
    /// Most edges to return. `None` means [`DEFAULT_LINK_LIMIT`], never unbounded.
    pub limit: Option<u32>,
    /// What the reader is entitled to see, tested on the mediating record of *every* hop.
    pub scope: Scope,
}

/// What else is connected to one entity, and by which records.
///
/// The read that turns `entity_refs` from a bipartite index into a graph. Two entities are linked
/// because one record references both; a second hop is the same join taken again from a hop-1
/// neighbour, and the record that made each edge comes back with it.
///
/// # The corridor rule
///
/// An entity may be *reached* however busy it is. What it may not do, above `max_degree` references
/// inside the window, is carry the traversal onward. Without that rule the second hop of any
/// question that passes near a shared identifier answers "everything that identifier ever touched",
/// and the answer is technically correct and useless. The rule is here from the first commit rather
/// than after the incident that teaches it, because the incident is documented in somebody else's
/// system and is not worth reproducing: a verified degree-94 node that made their traversal
/// unusable.
///
/// Degree is counted *inside the traversal's own window*, unscoped, and no further than
/// `max_degree + 1` rows. Each of those three is load-bearing. In-window, because the traversal is
/// windowed: an entity that was a hub last year and quiet during the hour under investigation is a
/// perfectly good corridor for that hour, and the lifetime count in `entities.ref_count` — which is
/// free to read — would refuse it. Unscoped, because a scoped count cannot be bounded: stopping at
/// `max_degree + 1` *visible* rows means walking the whole history of a hub to find them, which is
/// the work the cap exists to avoid, and because a corridor decision that differed per credential
/// would give an operator asking "why did this stop here" one answer per caller. Bounded, because
/// the count is the only unbounded thing in the query otherwise. The stated cost of the second one
/// is a leak of exactly one bit — that an entity the caller already reached through a record it may
/// read is busy — and the degree is returned, so the refusal is legible rather than silent.
///
/// The *seed* is not degree-capped, and that is deliberate rather than an omission. The caller named
/// it, so asking about a busy identifier directly is a legitimate question — it is what
/// [`by_entity`] answers — and refusing it would make the read unusable for exactly the entity an
/// incident is usually about. What the rule governs is passing *through* a node nobody asked for.
/// The cost is that hop 1 from a hub is as wide as the hub, which the window and [`MAX_FRONTIER`]
/// bound and nothing else does.
///
/// # Confidence, in two tiers
///
/// `min_confidence` is the floor every reference on every hop must meet to be an edge. It defaults —
/// at the endpoint above, since this struct has no default — to [`FULL_CONFIDENCE`], which is
/// `bundle`'s bar rather than `by_entity`'s `0.0`. The difference is who named the far end:
/// `by_entity` answers about an entity the caller wrote down, so an inferred reference there is one
/// row the caller can see the confidence of, while a traversal *invents* the far end. An inferred
/// link presented at hop 2 is indistinguishable from a fact for the same reason a guess in a bundle
/// is.
///
/// A caller may still lower it, and then the second tier holds: **an inferred reference may end a
/// path and may not extend one.** Expanding from a node requires the reference that discovered it
/// and the reference that leaves it to be at full confidence, whatever the floor says. So lowering
/// the floor widens what is *reported* and never what is *routed through* — the same shape as the
/// corridor rule, applied to the other way a hop can be wrong. Without it, hop 2 would quietly
/// launder what hop 1 was only willing to show with a confidence beside it.
///
/// # Scope
///
/// The predicate is on the mediating record of every hop, inside the recursive query. A traversal is
/// `correlate`'s problem raised to a power: each hop joins records whose visibility was decided
/// separately, and a scope test applied once — at the seed, or to the finished edge list — would let
/// a caller learn that A and C are connected through a record no read admits them to. There is no
/// second read here for the same reason there is none in `correlate_structures`: the structure comes
/// out of the statement that filtered the rows.
///
/// # What bounds it
///
/// The window bounds every hop. `max_degree` bounds the fan-out of each node. [`MAX_FRONTIER`]
/// bounds the recursion itself, in edges, and it is the ceiling on the answer whatever `limit` says.
/// Read [`MAX_FRONTIER`] before promising a caller a deep traversal: the queue is filled
/// breadth-first, so a frontier spent on hop 1 leaves nothing for hop 3, and a wide depth-3 request
/// can come back with no hop-3 edges in it at all. Narrow the window rather than raising the page.
///
/// Measured over the same 200,000-record store the other reads in this module are measured against,
/// as a scoped caller: one hop from the busiest identifier over 7 days is 24 edges at 0.78 ms p50,
/// two hops 59 edges at 1.10 ms, the same two hops as structure 2.10 ms, and three hops over 30 days
/// 3.09 ms — at which point the frontier and not the graph is deciding the answer. Two hops from a
/// long-tail identifier across the whole two years is 17 edges at 0.68 ms.
pub fn linked(store: &crate::Store, traversal: &Traversal) -> crate::Result<Vec<Link<RecordId>>> {
    let (sql, binds) = linked_sql(traversal, Select::Id);
    let lease = store.lease()?;
    let mut stmt = lease.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(binds), |row| {
        Ok((edge_of(row)?, row.get::<_, String>(7)?))
    })?;
    let mut links = Vec::new();
    for row in rows {
        let (edge, id) = row?;
        links.push(edge.with(crate::stored_record_id(id)?));
    }
    Ok(links)
}

/// The traversal, with each edge's record as *structure* rather than its identifier.
///
/// [`linked`] with the wider select list, and the projection a request actually wants: an identifier
/// beside two entity keys is a third name the caller cannot resolve, and the whole point of carrying
/// the record is that "why are these two connected" is answered without a second read. Every rule on
/// [`linked`] holds unchanged.
pub fn linked_structures(
    store: &crate::Store,
    traversal: &Traversal,
) -> crate::Result<Vec<Link<RecordStructure>>> {
    let (sql, binds) = linked_sql(traversal, Select::Structure);
    let lease = store.lease()?;
    let mut stmt = lease.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(binds), |row| {
        Ok((
            edge_of(row)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
        ))
    })?;
    let mut links = Vec::new();
    for row in rows {
        let (edge, id, frontmatter) = row?;
        links.push(edge.with(crate::stored_structure(id, &frontmatter)?));
    }
    Ok(links)
}

/// An edge's columns, read by position, with the record still to come.
///
/// Split out because both projections read the same seven leading columns and only differ in what
/// follows them: two readers spelling those seven twice is two places for a transposition to enter,
/// and a transposed `from` and `to` is an answer that reads perfectly and points backwards.
struct Edge {
    from: EntityKey,
    to: EntityKey,
    hop: u32,
    confidence: f32,
    degree: u32,
}

impl Edge {
    /// The link this edge becomes once its evidence is attached.
    fn with<R>(self, via: R) -> Link<R> {
        Link {
            from: self.from,
            to: self.to,
            hop: self.hop,
            confidence: self.confidence,
            degree: self.degree,
            via,
        }
    }
}

/// Reads the seven columns every traversal row leads with.
fn edge_of(row: &Row<'_>) -> rusqlite::Result<Edge> {
    Ok(Edge {
        hop: row.get::<_, i64>(0)?.try_into().unwrap_or(u32::MAX),
        from: EntityKey {
            kind: row.get(1)?,
            id: row.get(2)?,
        },
        to: EntityKey {
            kind: row.get(3)?,
            id: row.get(4)?,
        },
        confidence: row.get(5)?,
        degree: row.get::<_, i64>(6)?.try_into().unwrap_or(u32::MAX),
    })
}

/// Builds the traversal and its bindings.
///
/// Separate from running it for the reason every builder here is: whether each hop is an index seek
/// is a property of the plan, and the plan can only be asked of the statement text. This is the one
/// query in the module where that matters most — a hop that fell back to a scan would scan
/// `entity_refs` once per node on the frontier.
fn linked_sql(traversal: &Traversal, select: Select) -> (String, Vec<SqlValue>) {
    let mut binds: Vec<SqlValue> = Vec::new();
    let mut sql = String::from(
        "WITH RECURSIVE reached(
             hop, from_kind, from_id, to_kind, to_id, confidence, degree, record_pk
         ) AS (
             SELECT 1, ?, ?, b.kind, b.entity_id, min(a.confidence, b.confidence), ",
    );
    // The seed's own kind and id, as the `from` of every hop-1 edge. Bound rather than read back out
    // of `a`, so the answer names the entity the caller asked about even when the reference row
    // spells it identically.
    binds.push(traversal.kind.clone().into());
    binds.push(traversal.id.clone().into());
    push_degree(&mut sql, &mut binds, traversal);
    sql.push_str(
        ", a.record_pk
             FROM entity_refs AS a
             JOIN entity_refs AS b ON b.record_pk = a.record_pk
             JOIN records AS rec ON rec.id = a.record_pk
             WHERE a.kind = ? AND a.entity_id = ?",
    );
    binds.push(traversal.kind.clone().into());
    binds.push(traversal.id.clone().into());
    push_hop_window(&mut sql, &mut binds, traversal);
    // The floor on both references at hop 1. The seed is a thing the caller named, so the reference
    // *to* it is held to the floor rather than to full confidence; what that buys is an edge that
    // reports a confidence below 1.0 and, by the rule in the recursive term, goes no further.
    sql.push_str(" AND a.confidence >= ? AND b.confidence >= ?");
    binds.push(f64::from(traversal.min_confidence).into());
    binds.push(f64::from(traversal.min_confidence).into());
    sql.push_str(" AND (b.kind <> a.kind OR b.entity_id <> a.entity_id)");
    push_scope(&mut sql, &mut binds, &traversal.scope);

    sql.push_str(
        " UNION
             SELECT h.hop + 1, h.to_kind, h.to_id, b.kind, b.entity_id,
                    min(a.confidence, b.confidence), ",
    );
    push_degree(&mut sql, &mut binds, traversal);
    sql.push_str(
        ", a.record_pk
             FROM reached AS h
             JOIN entity_refs AS a ON a.kind = h.to_kind AND a.entity_id = h.to_id
             JOIN entity_refs AS b ON b.record_pk = a.record_pk
             JOIN records AS rec ON rec.id = a.record_pk
             WHERE h.hop < ?",
    );
    binds.push(i64::from(traversal.depth).into());
    // The corridor rule, as one comparison against a number this row already carries. Counting the
    // degree when the node was discovered rather than when it is expanded is what keeps it out of a
    // subquery correlated to the recursive table — and it is what lets the answer report the degree
    // that stopped it.
    sql.push_str(" AND h.degree <= ?");
    binds.push(i64::from(traversal.max_degree).into());
    // The second confidence tier: a path that arrived on anything short of a stated reference ends
    // here, whatever floor the caller set.
    sql.push_str(" AND h.confidence >= ?");
    binds.push(f64::from(FULL_CONFIDENCE).into());
    push_hop_window(&mut sql, &mut binds, traversal);
    // `a` is the reference that carries the traversal onward and is held to full confidence for the
    // reason above; `b` only has to clear the floor, because it ends a path rather than extending
    // one.
    sql.push_str(" AND a.confidence >= ? AND b.confidence >= ?");
    binds.push(f64::from(FULL_CONFIDENCE).into());
    binds.push(f64::from(traversal.min_confidence).into());
    sql.push_str(" AND (b.kind <> h.to_kind OR b.entity_id <> h.to_id)");
    // Back to the seed is not news. Excluded rather than returned and ignored, because an edge whose
    // far end is the entity the caller named reads as a discovery and is not one.
    sql.push_str(" AND (b.kind <> ? OR b.entity_id <> ?)");
    binds.push(traversal.kind.clone().into());
    binds.push(traversal.id.clone().into());
    push_scope(&mut sql, &mut binds, &traversal.scope);
    // On the recursion itself, which is what makes it terminate on work rather than only on depth.
    sql.push_str(" LIMIT ?");
    binds.push(i64::from(MAX_FRONTIER).into());

    sql.push_str(
        " )
         SELECT reached.hop, reached.from_kind, reached.from_id,
                reached.to_kind, reached.to_id, reached.confidence, reached.degree, ",
    );
    sql.push_str(select.columns());
    sql.push_str(
        " FROM reached
          JOIN records AS rec ON rec.id = reached.record_pk",
    );
    // Nearest hops first, then the newest evidence, then the primary key — every term of an order
    // this module ends at the primary key for the same reason: hop and timestamp both tie readily,
    // and a page taken from a partial order is arbitrary. The endpoints break the last tie, because
    // one record can make several edges and they are otherwise indistinguishable.
    sql.push_str(
        " ORDER BY reached.hop ASC, rec.received_ms DESC, rec.id DESC,
                   reached.to_kind ASC, reached.to_id ASC,
                   reached.from_kind ASC, reached.from_id ASC
          LIMIT ?",
    );
    binds.push(i64::from(traversal.limit.unwrap_or(DEFAULT_LINK_LIMIT)).into());
    (sql, binds)
}

/// Appends the bounded degree count for the entity `b` names, and its bindings.
///
/// A counted subquery with its own `LIMIT`, so a hub costs `max_degree + 1` index entries rather
/// than its whole history. An unbounded `count(*)` here would make the corridor rule cost exactly
/// what the corridor rule exists to avoid paying.
///
/// References and not distinct records, and not filtered by the caller's confidence floor. One
/// record naming an entity under two roles therefore counts twice, and a reference the floor would
/// have excluded still counts — both err toward refusing a corridor, which is the direction to err
/// in, and both keep the count a property of the entity rather than of the request that asked.
fn push_degree(sql: &mut String, binds: &mut Vec<SqlValue>, traversal: &Traversal) {
    sql.push_str(
        "(SELECT count(*) FROM (
              SELECT 1 FROM entity_refs AS d
              WHERE d.kind = b.kind AND d.entity_id = b.entity_id
                AND d.received_ms >= ? AND d.received_ms < ?
              LIMIT ?))",
    );
    binds.push(traversal.window.from_ms.into());
    binds.push(traversal.window.to_ms.into());
    binds.push(i64::from(traversal.max_degree.saturating_add(1)).into());
}

/// Appends one hop's window over the reference's own copy of the time, and its bindings.
///
/// On `a.received_ms` rather than on the record's, for the reason every window in this module is:
/// it is the column `entity_refs_recent` carries, so the window narrows the seek instead of
/// filtering rows the seek already walked — which at two hops is the difference between reading a
/// window and reading a history per node on the frontier.
fn push_hop_window(sql: &mut String, binds: &mut Vec<SqlValue>, traversal: &Traversal) {
    sql.push_str(" AND a.received_ms >= ? AND a.received_ms < ?");
    binds.push(traversal.window.from_ms.into());
    binds.push(traversal.window.to_ms.into());
}

/// Appends the scope test over the mediating record of one hop, and its bindings.
///
/// Called once per term of the recursion and nowhere else, so "the predicate holds on every hop" is
/// a property of there being no other way to write a hop rather than of somebody having remembered.
fn push_scope(sql: &mut String, binds: &mut Vec<SqlValue>, scope: &Scope) {
    if let Some(predicate) = scope_predicate(scope, "rec", binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
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
        Extent, Filter, Scope, Select, Traversal, Window, by_entity_sql, correlate_sql, filter_sql,
        linked_sql, search_sql,
    };

    /// How [`super::by_entity`] would run.
    pub fn by_entity(
        store: &crate::Store,
        kind: &str,
        id: &str,
        min_confidence: f32,
        window: Option<Window>,
        limit: Option<u32>,
        scope: &Scope,
    ) -> crate::Result<String> {
        let (sql, binds) = by_entity_sql(
            kind,
            id,
            min_confidence,
            window,
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
        window: Option<Window>,
        limit: Option<u32>,
        scope: &Scope,
    ) -> crate::Result<String> {
        let (sql, binds) = by_entity_sql(
            kind,
            id,
            min_confidence,
            window,
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
        let (sql, binds) = correlate_sql(left, right, within_ms, Select::Id);
        plan(store, &sql, binds)
    }

    /// How [`super::correlate_structures`] would run.
    ///
    /// Its own helper for the reason [`by_entity_structures`] has one, doubled: the wider select list
    /// costs a table lookup per row on *both* sides of the join, and whether the join still seeks
    /// rather than scans once the frontmatter is in the select list is a property of the plan.
    pub fn correlate_structures(
        store: &crate::Store,
        left: &Filter,
        right: &Filter,
        within_ms: i64,
    ) -> crate::Result<String> {
        let (sql, binds) = correlate_sql(left, right, within_ms, Select::Structure);
        plan(store, &sql, binds)
    }

    /// How [`super::linked`] would run.
    pub fn linked(store: &crate::Store, traversal: &Traversal) -> crate::Result<String> {
        let (sql, binds) = linked_sql(traversal, Select::Id);
        plan(store, &sql, binds)
    }

    /// How [`super::linked_structures`] would run.
    ///
    /// Its own helper for the reason [`by_entity_structures`] has one, and with more at stake: the
    /// traversal is the only read here whose join runs once per node on the frontier, so a hop that
    /// stopped seeking would scan `entity_refs` a frontier's worth of times, and nothing but the plan
    /// says whether it still seeks with the frontmatter in the select list.
    pub fn linked_structures(store: &crate::Store, traversal: &Traversal) -> crate::Result<String> {
        let (sql, binds) = linked_sql(traversal, Select::Structure);
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
        CORRIDOR_DEGREE, DEFAULT_LIMIT, DEFAULT_LINK_LIMIT, DEFAULT_PAIR_LIMIT,
        DEFAULT_STRUCTURE_LIMIT, Extent, FULL_CONFIDENCE, Filter, HOP_ATTENUATION, Link,
        MAX_CANDIDATES, MAX_FRONTIER, SCOPE_HEADROOM, Scope, Select, SqlValue, Traversal, Window,
        by_entity_sql, candidate_ceiling, correlate_sql, filter_sql, linked_sql, scope_predicate,
        search_sql,
    };

    /// The traversal the plan tests explain: two hops over a day, at the shipped corridor cap.
    fn traversal() -> Traversal {
        Traversal {
            kind: "ticket".to_owned(),
            id: "PROJ-42".to_owned(),
            depth: 2,
            window: Window {
                from_ms: 1_000,
                to_ms: 90_000,
            },
            min_confidence: FULL_CONFIDENCE,
            max_degree: CORRIDOR_DEGREE,
            limit: None,
            scope: reader(),
        }
    }

    #[test]
    fn every_hop_of_a_traversal_seeks_the_reference_index() {
        // The read whose cost is a product rather than a sum: the second hop's join runs once per
        // node the first hop found, so a hop that fell back to a scan would scan `entity_refs` a
        // frontier's worth of times. Only the plan tells a seek from a scan.
        for select in [Select::Id, Select::Structure] {
            let (sql, binds) = linked_sql(&traversal(), select);
            let plan = plan(&sql, binds);
            assert_eq!(
                plan.matches("entity_refs_recent").count(),
                4,
                "each of the two hops seeks the reference index for its own side and for the \
                 degree it counts:\n{plan}"
            );
            assert!(
                !plan.contains("SCAN entity_refs") && !plan.contains("SCAN records"),
                "a traversal that scans a base table scans it once per node on the frontier:\n\
                 {plan}"
            );
            assert!(
                plan.contains("RECURSIVE STEP"),
                "the second hop must be the recursion rather than a second copy of the first:\n\
                 {plan}"
            );
        }
    }

    #[test]
    fn the_scope_predicate_is_on_the_mediating_record_of_every_hop() {
        // The failure this prevents is precise: scoped once, a caller learns that A and C are
        // connected through a record no read admits it to. Counted rather than merely found,
        // because one occurrence is what a traversal scoped at the seed alone would also show.
        let (sql, _) = linked_sql(&traversal(), Select::Structure);
        assert_eq!(
            sql.matches("rec.visibility = ?").count(),
            6,
            "three visibility levels on each of two hops: {sql}"
        );
        assert_eq!(sql.matches("rec.team IN").count(), 2, "{sql}");
        assert_eq!(sql.matches("rec.agent = ?").count(), 2, "{sql}");

        // And the default scope reaches both hops too, so a traversal nobody scoped returns nothing
        // rather than everything past hop one.
        let (unscoped, _) = linked_sql(
            &Traversal {
                scope: Scope::default(),
                ..traversal()
            },
            Select::Structure,
        );
        assert_eq!(unscoped.matches("1 = 0").count(), 2, "{unscoped}");
    }

    #[test]
    fn a_traversal_binds_its_window_its_corridor_cap_and_its_frontier() {
        let (sql, binds) = linked_sql(&traversal(), Select::Id);
        // The window is bound six times: once per hop for the reference the hop is taken on, and
        // once per hop for the bounded degree count. A degree counted outside the window would
        // refuse a corridor that was quiet during the hour under investigation.
        assert_eq!(
            binds
                .iter()
                .filter(|bind| **bind == SqlValue::from(90_000i64))
                .count(),
            4,
            "{binds:?}"
        );
        // The count stops one row past the cap, so a hub costs the cap and not its history.
        assert!(
            binds.contains(&SqlValue::from(i64::from(CORRIDOR_DEGREE) + 1)),
            "{binds:?}"
        );
        assert!(
            sql.contains("LIMIT ?))"),
            "the degree count carries its own cap: {sql}"
        );
        // The frontier bounds the recursion, and the page bounds the answer. Both, and they are not
        // the same number.
        assert!(
            binds.contains(&SqlValue::from(i64::from(MAX_FRONTIER))),
            "{binds:?}"
        );
        assert!(
            binds.contains(&SqlValue::from(i64::from(DEFAULT_LINK_LIMIT))),
            "a traversal that named no page size is still bounded: {binds:?}"
        );
    }

    #[test]
    fn an_inferred_reference_may_end_a_path_and_may_not_extend_one() {
        // The second confidence tier, as the query text. Lowering the floor widens what is reported
        // and never what is routed through: hop two would otherwise present, as a discovery, a
        // neighbourhood reached by walking through a guess.
        let (sql, binds) = linked_sql(
            &Traversal {
                min_confidence: 0.7,
                ..traversal()
            },
            Select::Id,
        );
        assert!(
            sql.contains("h.confidence >= ?"),
            "a path that arrived on a guess ends there: {sql}"
        );
        let floor = SqlValue::from(f64::from(0.7f32));
        let full = SqlValue::from(f64::from(FULL_CONFIDENCE));
        assert_eq!(
            binds.iter().filter(|bind| **bind == floor).count(),
            3,
            "both references at hop one, and the discovering reference at hop two: {binds:?}"
        );
        assert_eq!(
            binds.iter().filter(|bind| **bind == full).count(),
            2,
            "the arriving path and the reference that carries it onward: {binds:?}"
        );
    }

    #[test]
    fn a_further_hop_is_worth_less_and_says_by_how_much() {
        let edge = |hop| Link {
            from: super::EntityKey {
                kind: "ticket".to_owned(),
                id: "PROJ-42".to_owned(),
            },
            to: super::EntityKey {
                kind: "deploy".to_owned(),
                id: "api/staging#1041".to_owned(),
            },
            hop,
            confidence: FULL_CONFIDENCE,
            degree: 3,
            via: (),
        };
        assert!((edge(1).score() - HOP_ATTENUATION).abs() < f32::EPSILON);
        assert!((edge(2).score() - HOP_ATTENUATION * HOP_ATTENUATION).abs() < f32::EPSILON);
        // Reached and not traversed through is a property of the edge and the request together: at
        // the requested depth nothing was going to be expanded, so nothing there is a hub.
        let asked = traversal();
        assert!(!edge(1).hub(&asked), "under the cap");
        assert!(
            Link {
                degree: CORRIDOR_DEGREE + 1,
                ..edge(1)
            }
            .hub(&asked)
        );
        assert!(
            !Link {
                degree: CORRIDOR_DEGREE + 1,
                ..edge(2)
            }
            .hub(&asked),
            "the last hop stopped because the depth ran out, not because of the corridor rule"
        );
    }

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
        // Both projections, because the wider select list is what a request-driven correlation runs
        // and the frontmatter column is in neither covering index: if selecting it cost the join its
        // seeks, the read exposed on the wire would be the slow one and this test would still pass.
        for select in [Select::Id, Select::Structure] {
            let (sql, binds) = correlate_sql(&left, &right, 60_000, select);
            let plan = plan(&sql, binds);
            assert!(
                !plan.contains("SCAN"),
                "range join fell back to a scan for {select:?}:\n{plan}"
            );
            // Each side wants the index that matches what it pins. The left pins action and outcome;
            // the right pins action alone, and asking it to use the outcome-leading index leaves a
            // gap mid-key that turns the range into a per-row filter. Measured, that was 25x.
            assert!(
                plan.contains("USING INDEX records_action_outcome_time"),
                "the side pinning action and outcome should use the index covering both:\n{plan}"
            );
            assert!(
                plan.contains("USING INDEX records_action_time"),
                "the side pinning action alone should use the action-leading index, not the one \
                 with outcome mid-key:\n{plan}"
            );
        }
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
            None,
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
            None,
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
            None,
            Extent::Page(None),
            &reader(),
            Select::Id,
        );
        assert!(bounded.contains("LIMIT ?"), "{bounded}");
        let (unbounded, binds) = by_entity_sql(
            "ticket",
            "PROJ-42",
            0.0,
            None,
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
            correlate_sql(&Filter::default(), &Filter::default(), 1, Select::Id),
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

        // And a page of *pairs* of structure lower again, because the row is two of them. A pair
        // page that defaulted to the structure page would be the one read allowed to answer with
        // twice what every other read may.
        let (sql, binds) =
            correlate_sql(&Filter::default(), &Filter::default(), 1, Select::Structure);
        assert!(sql.contains("LIMIT ?"), "{sql}");
        assert!(
            binds.contains(&SqlValue::from(i64::from(DEFAULT_PAIR_LIMIT))),
            "{binds:?}"
        );
        assert!(
            !binds.contains(&SqlValue::from(i64::from(DEFAULT_STRUCTURE_LIMIT))),
            "a pair page must not fall back to the single-structure page: {binds:?}"
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
            super::explain::by_entity_structures(
                &store,
                "ticket",
                "PROJ-42",
                1.0,
                None,
                None,
                &reader()
            )
            .expect("a plan")
            .contains("entity_refs_recent")
        );

        // Every helper answers, and the join names both sides.
        assert!(
            super::explain::by_entity(&store, "ticket", "PROJ-42", 1.0, None, None, &reader())
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
        for traversed in [
            super::explain::linked(&store, &traversal()).expect("a plan"),
            super::explain::linked_structures(&store, &traversal()).expect("a plan"),
        ] {
            assert!(traversed.contains("RECURSIVE STEP"), "{traversed}");
            assert!(traversed.contains("entity_refs_recent"), "{traversed}");
        }
        for join in [
            super::explain::correlate(&store, &filter, &filter, 1_000).expect("a plan"),
            super::explain::correlate_structures(&store, &filter, &filter, 1_000).expect("a plan"),
        ] {
            assert_eq!(
                join.matches("records_action_outcome_time").count(),
                2,
                "{join}"
            );
        }
    }

    #[test]
    fn no_query_reads_the_clock() {
        // A time function in the plan would make the result depend on when it ran.
        let (correlation, _) = correlate_sql(&Filter::default(), &Filter::default(), 1, Select::Id);
        let (pairs, _) =
            correlate_sql(&Filter::default(), &Filter::default(), 1, Select::Structure);
        let (filtered, _) = filter_sql(&Filter::default(), Select::Id);
        let (traversed, _) = linked_sql(&traversal(), Select::Structure);
        for sql in [correlation, pairs, filtered, traversed] {
            assert!(!sql.contains("unixepoch"), "clock read in: {sql}");
            assert!(!sql.contains("'now'"), "clock read in: {sql}");
        }
    }
}
