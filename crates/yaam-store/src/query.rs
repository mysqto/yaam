//! The queries the system exists to answer.
//!
//! Three rules hold everywhere here. Ordering, windowing and joins use the server-stamped time, so
//! a skewed or replayed source clock cannot reorder history. No query calls a `SQLite` time
//! function: "now" arrives as a bound parameter, which keeps a query reproducible under test and
//! keeps its plan free of a non-deterministic term. And every read carries a [`Scope`] — what a
//! caller may see is a predicate, not a convention, and the one it defaults to is *nothing*.

use rusqlite::{Row, params_from_iter, types::Value as SqlValue};
use yaam_contract::{RecordId, Visibility};

/// Rows a filtered read returns when the caller names no page size.
///
/// A cap rather than everything. "Page size" with no default and no cursor is a trap: the first
/// caller to omit it reads the whole index into memory, and it works until the index is large. A
/// caller that wants a different number says so, and one that wants more than this pages by
/// narrowing the window — there is deliberately no offset to walk.
pub const DEFAULT_LIMIT: u32 = 1_000;

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
    /// Page size. `None` means [`DEFAULT_LIMIT`], never unbounded.
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
    let (sql, binds) = by_entity_sql(kind, id, min_confidence, Extent::Page(limit), scope);
    run_ids(store, &sql, binds)
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

/// Runs a statement whose one column is a record id.
fn run_ids(store: &crate::Store, sql: &str, binds: Vec<SqlValue>) -> crate::Result<Vec<RecordId>> {
    let lease = store.lease()?;
    let mut stmt = lease.prepare(sql)?;
    let rows = stmt.query_map(params_from_iter(binds), one_id)?;
    collect(rows)
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
) -> (String, Vec<SqlValue>) {
    let mut binds: Vec<SqlValue> = vec![
        kind.to_owned().into(),
        id.to_owned().into(),
        f64::from(min_confidence).into(),
    ];
    let mut sql = "SELECT rec.record_id
         FROM entity_refs AS er
         JOIN records AS rec ON rec.id = er.record_pk
         WHERE er.kind = ? AND er.entity_id = ? AND er.confidence >= ?"
        .to_owned();
    if let Some(predicate) = scope_predicate(scope, "rec", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    // Ordered on the reference's own copy of the time, not on the record's: the two are the same
    // value, and only this one is in the index the seek uses — which is what lets the page size stop
    // the walk instead of capping a set that was sorted in full first.
    sql.push_str(" ORDER BY er.received_ms DESC, er.record_pk DESC");
    if let Extent::Page(page) = extent {
        push_limit(&mut sql, &mut binds, page);
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
    let (sql, binds) = filter_sql(filter);
    run_ids(store, &sql, binds)
}

/// Builds the filtered query and its bindings.
///
/// Separate from running it so the plan can be asserted on: "indexed" is a property of the plan,
/// not of the source text, and nothing else would notice an index quietly going unused.
fn filter_sql(filter: &Filter) -> (String, Vec<SqlValue>) {
    let mut binds: Vec<SqlValue> = Vec::new();
    // Driving from record_attrs when an attribute is required: it is the most selective start
    // available, and it keeps the seek on an index either way.
    let mut sql = if let Some((key, value)) = &filter.attr {
        binds.push(key.clone().into());
        binds.push(value.clone().into());
        "SELECT rec.record_id FROM record_attrs AS ra
         JOIN records AS rec ON rec.id = ra.record_pk
         WHERE ra.key = ? AND ra.value = ?"
            .to_owned()
    } else {
        "SELECT rec.record_id FROM records AS rec WHERE 1 = 1".to_owned()
    };
    for predicate in record_predicates(filter, "rec", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    sql.push_str(" ORDER BY rec.received_ms DESC, rec.id DESC");
    push_limit(&mut sql, &mut binds, filter.limit);
    (sql, binds)
}

/// Appends the row cap, which is emitted whether or not the caller named one.
fn push_limit(sql: &mut String, binds: &mut Vec<SqlValue>, limit: Option<u32>) {
    sql.push_str(" LIMIT ?");
    binds.push(i64::from(limit.unwrap_or(DEFAULT_LIMIT)).into());
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
    push_limit(&mut sql, &mut binds, left.limit);
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
    let (sql, binds) = search_sql(needle, limit, scope);
    run_ids(store, &sql, binds)
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
fn search_sql(needle: &str, limit: u32, scope: &Scope) -> (String, Vec<SqlValue>) {
    let mut binds: Vec<SqlValue> = vec![
        needle.to_owned().into(),
        i64::from(candidate_ceiling(limit)).into(),
    ];
    // The candidate set is its own statement so the ceiling applies to the match itself. Ordering
    // it by rowid descending is what lets the full-text index stop early: rowid is its own scan
    // order, so nothing is sorted and nothing past the ceiling is visited. `rank` comes out with
    // each candidate — best-match order among the candidates is still worth having, and it costs
    // only the rows already read.
    let mut sql = "WITH candidates AS (
             SELECT rowid AS record_pk, rank AS relevance
             FROM records_fts
             WHERE records_fts MATCH ?
             ORDER BY rowid DESC
             LIMIT ?
         )
         SELECT rec.record_id
         FROM candidates
         JOIN records AS rec ON rec.id = candidates.record_pk
         WHERE rec.sealed = 0"
        .to_owned();
    if let Some(predicate) = scope_predicate(scope, "rec", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    sql.push_str(" ORDER BY candidates.relevance, rec.received_ms DESC LIMIT ?");
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
    use super::{Extent, Filter, Scope, by_entity_sql, correlate_sql, filter_sql, search_sql};

    /// How [`super::by_entity`] would run.
    pub fn by_entity(
        store: &crate::Store,
        kind: &str,
        id: &str,
        min_confidence: f32,
        limit: Option<u32>,
        scope: &Scope,
    ) -> crate::Result<String> {
        let (sql, binds) = by_entity_sql(kind, id, min_confidence, Extent::Page(limit), scope);
        plan(store, &sql, binds)
    }

    /// How [`super::by_filter`] would run.
    pub fn by_filter(store: &crate::Store, filter: &Filter) -> crate::Result<String> {
        let (sql, binds) = filter_sql(filter);
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
        let (sql, binds) = search_sql(needle, limit, scope);
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
        DEFAULT_LIMIT, Extent, Filter, MAX_CANDIDATES, SCOPE_HEADROOM, Scope, SqlValue, Window,
        by_entity_sql, candidate_ceiling, correlate_sql, filter_sql, scope_predicate, search_sql,
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
        let (sql, binds) = filter_sql(&filter);
        let plan = plan(&sql, binds);
        assert!(
            plan.contains("SEARCH") && plan.contains("USING INDEX records_action_outcome_time"),
            "expected an index seek, got:\n{plan}"
        );
        assert!(!plan.contains("SCAN records"), "unexpected scan:\n{plan}");
    }

    #[test]
    fn attribute_filter_seeks_the_attribute_index() {
        let filter = Filter {
            attr: Some(("order_ref".to_owned(), "ORD-1001".to_owned())),
            scope: reader(),
            ..Filter::default()
        };
        let (sql, binds) = filter_sql(&filter);
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
        let (sql, binds) =
            by_entity_sql("ticket", "PROJ-42", 0.0, Extent::Page(Some(10)), &reader());
        let plan = plan(&sql, binds);
        assert!(
            plan.contains("entity_refs_recent"),
            "the entity index must supply the order:\n{plan}"
        );
        assert!(
            !plan.contains("USE TEMP B-TREE FOR ORDER BY"),
            "sorting the whole history before taking the page is what the index avoids:\n{plan}"
        );
    }

    #[test]
    fn the_unbounded_entity_read_is_the_only_one_without_a_cap() {
        let (bounded, _) = by_entity_sql("ticket", "PROJ-42", 0.0, Extent::Page(None), &reader());
        assert!(bounded.contains("LIMIT ?"), "{bounded}");
        let (unbounded, binds) = by_entity_sql(
            "ticket",
            "PROJ-42",
            0.0,
            Extent::Everything,
            &Scope::Unrestricted,
        );
        assert!(!unbounded.contains("LIMIT"), "{unbounded}");
        assert_eq!(binds.len(), 3, "no scope and no cap to bind: {binds:?}");
    }

    #[test]
    fn a_full_text_read_caps_its_candidates_before_the_join() {
        let (sql, binds) = search_sql("shards", 10, &reader());
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
    fn the_default_scope_matches_nothing() {
        // A filter nobody scoped is a read whose entitlements are unknown, and the only safe answer
        // to that is no rows.
        let (sql, _) = filter_sql(&Filter::default());
        assert!(sql.contains("1 = 0"), "{sql}");
    }

    #[test]
    fn an_unrestricted_scope_adds_no_predicate() {
        let (sql, binds) = filter_sql(&Filter {
            scope: Scope::Unrestricted,
            ..Filter::default()
        });
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
            filter_sql(&Filter::default()),
            correlate_sql(&Filter::default(), &Filter::default(), 1),
        ] {
            assert!(sql.contains("LIMIT ?"), "{sql}");
            assert!(
                binds.contains(&SqlValue::from(i64::from(DEFAULT_LIMIT))),
                "{binds:?}"
            );
        }

        // A caller that names one still gets exactly that.
        let (_, binds) = filter_sql(&Filter {
            limit: Some(7),
            ..Filter::default()
        });
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
        let (filtered, _) = filter_sql(&Filter::default());
        for sql in [correlation, filtered] {
            assert!(!sql.contains("unixepoch"), "clock read in: {sql}");
            assert!(!sql.contains("'now'"), "clock read in: {sql}");
        }
    }
}
