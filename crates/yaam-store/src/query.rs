//! The queries the system exists to answer.
//!
//! Three rules hold everywhere here. Ordering, windowing and joins use the server-stamped time, so
//! a skewed or replayed source clock cannot reorder history. No query calls a `SQLite` time
//! function: "now" arrives as a bound parameter, which keeps a query reproducible under test and
//! keeps its plan free of a non-deterministic term. And every read carries a [`Scope`] — what a
//! caller may see is a predicate, not a convention, and the one it defaults to is *nothing*.

use rusqlite::{Row, params_from_iter, types::Value as SqlValue};
use yaam_contract::{RecordId, Visibility};

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
    /// Page size.
    pub limit: Option<u32>,
    /// What the reader is entitled to see.
    pub scope: Scope,
}

/// Everything touching one entity, newest first.
///
/// `min_confidence` is the caller's tolerance for inferred references: `1.0` keeps only the ones
/// read out of a structured field.
pub fn by_entity(
    store: &crate::Store,
    kind: &str,
    id: &str,
    min_confidence: f32,
    scope: &Scope,
) -> crate::Result<Vec<RecordId>> {
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
    sql.push_str(" ORDER BY rec.received_ms DESC, rec.id DESC");

    let lease = store.lease()?;
    let mut stmt = lease.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(binds), one_id)?;
    collect(rows)
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
    let lease = store.lease()?;
    let mut stmt = lease.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(binds), one_id)?;
    collect(rows)
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
    if let Some(limit) = filter.limit {
        sql.push_str(" LIMIT ?");
        binds.push(i64::from(limit).into());
    }
    (sql, binds)
}

/// Correlates two actions falling within `within_ms` of each other.
///
/// The shape most cross-agent questions reduce to: something failed, and something else happened
/// nearby. A non-equi range join, so it needs the covering index to stay cheap.
///
/// Directional: a pair is returned when the right record was stamped at or after the left one and
/// no later than `within_ms` after it. Bound the search with `left.window` — there is deliberately
/// no implicit "recent", because a query whose meaning depends on when it ran cannot be tested.
/// `left.limit` caps the number of pairs; a page size on the right side has no meaning for a join.
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
    if let Some(limit) = left.limit {
        sql.push_str(" LIMIT ?");
        binds.push(i64::from(limit).into());
    }
    (sql, binds)
}

/// Full-text search over plaintext bodies only.
///
/// `needle` is an FTS5 query expression, so prefix and phrase syntax reach the caller; a malformed
/// one is reported rather than silently matching nothing. Sealed records hold an empty body and so
/// index no text; the explicit predicate says so at the query too, because "it cannot happen" is
/// not the same as "it is refused".
pub fn search(
    store: &crate::Store,
    needle: &str,
    limit: u32,
    scope: &Scope,
) -> crate::Result<Vec<RecordId>> {
    let mut binds: Vec<SqlValue> = vec![needle.to_owned().into()];
    let mut sql = "SELECT rec.record_id
         FROM records_fts
         JOIN records AS rec ON rec.id = records_fts.rowid
         WHERE records_fts MATCH ? AND rec.sealed = 0"
        .to_owned();
    if let Some(predicate) = scope_predicate(scope, "rec", &mut binds) {
        sql.push_str(" AND ");
        sql.push_str(&predicate);
    }
    sql.push_str(" ORDER BY records_fts.rank, rec.received_ms DESC LIMIT ?");
    binds.push(i64::from(limit).into());

    let lease = store.lease()?;
    let mut stmt = lease.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(binds), one_id)?;
    collect(rows)
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

#[cfg(test)]
mod tests {
    use yaam_contract::Visibility;

    use super::{Filter, Scope, SqlValue, Window, correlate_sql, filter_sql, scope_predicate};

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
        assert_eq!(
            plan.matches("USING INDEX records_action_outcome_time")
                .count(),
            2,
            "both sides should use the covering index:\n{plan}"
        );
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
        assert!(binds.is_empty(), "{binds:?}");
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
