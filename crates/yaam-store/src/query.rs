//! The queries the system exists to answer.
//!
//! Two rules hold everywhere here. Ordering, windowing and joins use the server-stamped time, so
//! a skewed or replayed source clock cannot reorder history. And no query calls a `SQLite` time
//! function: "now" arrives as a bound parameter, which keeps a query reproducible under test and
//! keeps its plan free of a non-deterministic term.

use rusqlite::{Row, params, params_from_iter, types::Value as SqlValue};
use yaam_contract::RecordId;

/// A time window, in server-stamped milliseconds.
#[derive(Debug, Clone, Copy)]
pub struct Window {
    /// Inclusive start.
    pub from_ms: i64,
    /// Exclusive end.
    pub to_ms: i64,
}

/// Filters for a record query.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Restrict to one action.
    pub action: Option<String>,
    /// Restrict to one outcome.
    pub outcome: Option<String>,
    /// Restrict to one agent.
    pub agent: Option<String>,
    /// Require a structural attribute to equal a value.
    pub attr: Option<(String, String)>,
    /// Restrict to a time window.
    pub window: Option<Window>,
    /// Page size.
    pub limit: Option<u32>,
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
) -> crate::Result<Vec<RecordId>> {
    let mut stmt = store.conn.prepare(
        "SELECT rec.record_id
         FROM entity_refs AS er
         JOIN records AS rec ON rec.id = er.record_pk
         WHERE er.kind = ?1 AND er.entity_id = ?2 AND er.confidence >= ?3
         ORDER BY rec.received_ms DESC, rec.id DESC",
    )?;
    let rows = stmt.query_map(params![kind, id, f64::from(min_confidence)], one_id)?;
    collect(rows)
}

/// Filtered record query.
///
/// Every predicate lands on an indexed column. `action`, `outcome` and `agent` are generated
/// columns rather than inline `json_extract`, and an attribute filter drives the query from the
/// attribute index instead of testing JSON per row.
pub fn by_filter(store: &crate::Store, filter: &Filter) -> crate::Result<Vec<RecordId>> {
    let (sql, binds) = filter_sql(filter);
    let mut stmt = store.conn.prepare(&sql)?;
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
    let mut stmt = store.conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(binds), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut pairs = Vec::new();
    for row in rows {
        let (left_id, right_id) = row?;
        pairs.push((parse_id(left_id)?, parse_id(right_id)?));
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
pub fn search(store: &crate::Store, needle: &str, limit: u32) -> crate::Result<Vec<RecordId>> {
    let mut stmt = store.conn.prepare(
        "SELECT rec.record_id
         FROM records_fts
         JOIN records AS rec ON rec.id = records_fts.rowid
         WHERE records_fts MATCH ?1 AND rec.sealed = 0
         ORDER BY records_fts.rank, rec.received_ms DESC
         LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![needle, i64::from(limit)], one_id)?;
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
    predicates
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
        ids.push(parse_id(row?)?);
    }
    Ok(ids)
}

/// Rebuilds a record id from its stored text.
///
/// Goes through the contract's own deserialisation rather than a local constructor, so the index
/// cannot mint an id shape the contract would reject. A value that fails is drift by definition:
/// the row no longer matches the tree it was derived from.
fn parse_id(text: String) -> crate::Result<RecordId> {
    serde_json::from_value(serde_json::Value::String(text.clone()))
        .map_err(|_| crate::Error::Drift(text))
}

#[cfg(test)]
mod tests {
    use super::{Filter, SqlValue, Window, correlate_sql, filter_sql};

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
            ..Filter::default()
        };
        let right = Filter {
            action: Some("ticket".to_owned()),
            attr: Some(("severity".to_owned(), "high".to_owned())),
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
