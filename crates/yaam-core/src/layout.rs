//! Where things live under the memory root, and how a record's path is derived.
//!
//! One module, because a path spelled in two places is a path that drifts apart. A record's location
//! is a function of the record — its server-stamped time and its identifier — so the same record
//! always lands in the same place, whoever writes it and whenever they replay it.

use std::path::PathBuf;

use yaam_contract::{ActionRecord, Visibility, entity::Registry};

/// Configuration this deployment reads: entity kinds, attribute schema, redaction policy.
pub(crate) const SPEC_DIR: &str = "spec";
/// The authoritative record tree.
pub(crate) const RECORDS_DIR: &str = "records";
/// Owner-visible records, one subtree per owner, inside [`RECORDS_DIR`].
///
/// A name no dated directory can take, so the two cannot be confused for one another.
pub(crate) const OWNER_DIR: &str = "owner";
/// Materialised entity timelines.
pub(crate) const ENTITIES_DIR: &str = "entities";
/// Audit records fan-out writes.
pub(crate) const AUDIT_DIR: &str = "audit";
/// Manifests of archived records, still indexable.
pub(crate) const COLD_DIR: &str = "cold";
/// Root of the key store.
pub(crate) const KEYSTORE_DIR: &str = "keystore";
/// Write-ahead copies, before publish.
pub(crate) const STAGING_DIR: &str = ".staging";
/// Sealed copies of records whose subjects will not resolve.
pub(crate) const QUARANTINE_DIR: &str = ".quarantine";
/// Fan-out work set aside after repeated failure.
pub(crate) const DEAD_LETTER_DIR: &str = ".dead-letter";
/// The derived index.
pub(crate) const INDEX_FILE: &str = "index.sqlite";
/// The append-only erasure log.
pub(crate) const TOMBSTONE_LOG: &str = "tombstones.jsonl";
/// Extension of every record file.
pub(crate) const RECORD_EXT: &str = "md";

/// A parsed server timestamp: the instant, and the UTC date it falls on.
///
/// Both are needed and neither derives from the other cheaply: the instant selects the key epoch,
/// and the date selects the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stamp {
    /// Milliseconds since the Unix epoch.
    pub(crate) ms: i64,
    /// UTC year.
    pub(crate) year: i64,
    /// UTC month, 1-12.
    pub(crate) month: i64,
    /// UTC day of month, 1-31.
    pub(crate) day: i64,
}

impl Stamp {
    /// The date as `YYYY-MM-DD`, the form the quarantine key is labelled by.
    pub(crate) fn date(&self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// Parses an `RFC3339` timestamp into an instant and its UTC date.
///
/// The reading is the contract's, not a local one: the same grammar decides whether a record is
/// accepted at all, and a second parser here would eventually place a record on a day the contract
/// read differently.
pub(crate) fn stamp(text: &str) -> Option<Stamp> {
    let ms = yaam_contract::timestamp::parse_ms(text)?;
    let (year, month, day) = yaam_contract::timestamp::civil_from_ms(ms);
    Some(Stamp {
        ms,
        year,
        month,
        day,
    })
}

/// The server stamp of a record, or the permanent fault of not having one.
pub(crate) fn stamp_of(record: &ActionRecord) -> crate::Result<Stamp> {
    stamp(&record.received_at).ok_or_else(|| {
        crate::pipeline::invalid(format!(
            "record `{}` has an unreadable received_at `{}`",
            record.record_id.as_str(),
            record.received_at
        ))
    })
}

/// A record's path relative to the memory root.
///
/// Dated directories rather than one flat one: a day's worth of records is a browsable size, and a
/// cold archive moves whole directories.
///
/// An owner-visible record is filed under [`OWNER_DIR`] and its owner's own segment first, because
/// [`Visibility::Owner`] promises the record is stored apart: one directory per identity is what
/// makes the promise a boundary the filesystem can hold, rather than a field a reader has to honour.
/// Still under [`RECORDS_DIR`], so every walk that rebuilds the index finds it without being told.
pub(crate) fn record_relative(record: &ActionRecord, stamp: &Stamp) -> crate::Result<PathBuf> {
    let mut path = PathBuf::from(RECORDS_DIR);
    if record.visibility == Visibility::Owner {
        path = path.join(OWNER_DIR).join(owner_segment(&record.agent)?);
    }
    Ok(path
        .join(format!("{:04}", stamp.year))
        .join(format!("{:02}", stamp.month))
        .join(format!("{:02}", stamp.day))
        .join(format!("{}.{RECORD_EXT}", record.record_id.as_str())))
}

/// The subtree holding one owner's records, relative to the memory root.
///
/// `None` for every other visibility: those records share the dated tree, and there is no identity
/// boundary to restrict.
pub(crate) fn owner_relative(record: &ActionRecord) -> crate::Result<Option<PathBuf>> {
    if record.visibility != Visibility::Owner {
        return Ok(None);
    }
    Ok(Some(
        PathBuf::from(RECORDS_DIR)
            .join(OWNER_DIR)
            .join(owner_segment(&record.agent)?),
    ))
}

/// File mode a record's own copy is written with, where the platform has modes.
///
/// Owner-visible records are owner-read-only; the rest keep the process umask, because they are
/// meant to be readable by whoever may read the tree.
pub(crate) fn record_mode(record: &ActionRecord) -> Option<u32> {
    (record.visibility == Visibility::Owner).then_some(0o600)
}

/// Filename-safe, injective encoding of an owner's identity.
///
/// The contract's own entity encoding, so a `/` in an agent name becomes one segment rather than a
/// directory level, and two agents cannot land in one directory. Then the guard that encoding does
/// not give: `.` and `..` pass through it unchanged, and either would aim a record back at the
/// shared tree.
fn owner_segment(agent: &str) -> crate::Result<String> {
    let segment = Registry::to_path_segment(agent);
    if segment.is_empty() || segment == "." || segment == ".." || segment.contains(['\\', '\0']) {
        return Err(crate::pipeline::invalid(format!(
            "agent `{agent}` cannot name an owner directory"
        )));
    }
    Ok(segment)
}

#[cfg(test)]
mod tests {
    use super::{owner_relative, record_mode, record_relative, stamp};
    use crate::testkit;
    use yaam_contract::Visibility;

    #[test]
    fn a_stamp_carries_the_instant_and_the_utc_day_it_falls_on() {
        // The reading itself is the contract's; what this owns is the pair the tree needs from it.
        let parsed = stamp("2026-08-20T09:14:02.117Z").expect("valid");
        assert_eq!(parsed.ms, 1_787_217_242_117);
        assert_eq!((parsed.year, parsed.month, parsed.day), (2026, 8, 20));
        assert_eq!(parsed.date(), "2026-08-20");
        assert!(stamp("not a timestamp").is_none());
    }

    #[test]
    fn a_records_path_is_dated_and_named_by_its_id() {
        let record = testkit::internal("2026-01-05T00:00:00Z");
        let parsed = stamp(&record.received_at).expect("valid");
        assert_eq!(
            record_relative(&record, &parsed).expect("a path"),
            std::path::PathBuf::from(format!(
                "records/2026/01/05/{}.md",
                record.record_id.as_str()
            ))
        );
        assert_eq!(owner_relative(&record).expect("no owner subtree"), None);
        assert_eq!(record_mode(&record), None);
    }

    #[test]
    fn an_owner_visible_record_is_filed_under_its_owner() {
        let mut record = testkit::internal("2026-01-05T00:00:00Z");
        record.visibility = Visibility::Owner;
        record.agent = "agent/a".to_owned();
        let parsed = stamp(&record.received_at).expect("valid");

        // The `/` is encoded rather than becoming a directory level, and the day still decides the
        // directory below the owner's own.
        assert_eq!(
            record_relative(&record, &parsed).expect("a path"),
            std::path::PathBuf::from(format!(
                "records/owner/agent~sa/2026/01/05/{}.md",
                record.record_id.as_str()
            ))
        );
        assert_eq!(
            owner_relative(&record).expect("an owner subtree"),
            Some(std::path::PathBuf::from("records/owner/agent~sa"))
        );
        assert_eq!(record_mode(&record), Some(0o600));
    }

    #[test]
    fn an_agent_that_cannot_name_a_directory_is_refused() {
        // `..` survives the encoding untouched, and would aim an owner's record at the shared tree.
        for agent in ["", ".", ".."] {
            let mut record = testkit::internal("2026-01-05T00:00:00Z");
            record.visibility = Visibility::Owner;
            record.agent = agent.to_owned();
            let parsed = stamp(&record.received_at).expect("valid");
            assert!(record_relative(&record, &parsed).is_err(), "{agent:?}");
            assert!(owner_relative(&record).is_err(), "{agent:?}");
        }
    }
}
