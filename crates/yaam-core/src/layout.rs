//! Where things live under the memory root, and how a record's path is derived.
//!
//! One module, because a path spelled in two places is a path that drifts apart. A record's location
//! is a function of the record — its server-stamped time and its identifier — so the same record
//! always lands in the same place, whoever writes it and whenever they replay it.

use std::path::PathBuf;

use yaam_contract::{ActionRecord, RecordId};

/// Configuration this deployment reads: entity kinds, attribute schema, redaction policy.
pub(crate) const SPEC_DIR: &str = "spec";
/// The authoritative record tree.
pub(crate) const RECORDS_DIR: &str = "records";
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

/// Milliseconds in a day.
const MS_PER_DAY: i64 = 86_400_000;

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
/// Hand-parsed rather than delegated, because the index converts the same string with `SQLite`'s
/// `unixepoch()` and the two must agree about which day a record belongs to. Returns `None` rather
/// than repairing: a timestamp this cannot read would place a record on an arbitrary day, and a
/// record filed under the wrong day is one a windowed query silently misses.
pub(crate) fn stamp(text: &str) -> Option<Stamp> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if !matches!(bytes[10], b'T' | b't' | b' ') || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let year = digits(text, 0, 4)?;
    let month = digits(text, 5, 7)?;
    let day = digits(text, 8, 10)?;
    let hour = digits(text, 11, 13)?;
    let minute = digits(text, 14, 16)?;
    let second = digits(text, 17, 19)?;
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        // A leap second is stamped :60 by some sources; it belongs to the same minute.
        || second > 60
    {
        return None;
    }

    let (fraction_ms, rest) = fraction(&text[19..])?;
    let offset_minutes = offset(rest)?;

    let ms = days_from_civil(year, month, day) * MS_PER_DAY
        + hour * 3_600_000
        + minute * 60_000
        + second.min(59) * 1_000
        + fraction_ms
        - offset_minutes * 60_000;
    let (year, month, day) = civil_from_days(ms.div_euclid(MS_PER_DAY));
    Some(Stamp {
        ms,
        year,
        month,
        day,
    })
}

/// Reads a fixed-width run of ASCII digits as a number.
///
/// Deliberately not `str::parse`, which accepts a leading sign: `+123` in a year field would parse
/// and then place the record four thousand years away.
fn digits(text: &str, from: usize, to: usize) -> Option<i64> {
    let slice = text.get(from..to)?;
    if !slice.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    slice.parse().ok()
}

/// Splits an optional `.fff` fraction off the head of `rest`, in milliseconds.
///
/// Sub-millisecond digits are truncated rather than rounded, matching what the index stores.
fn fraction(rest: &str) -> Option<(i64, &str)> {
    let Some(after_dot) = rest.strip_prefix('.') else {
        return Some((0, rest));
    };
    let end = after_dot
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(after_dot.len());
    if end == 0 {
        return None;
    }
    let mut millis = 0i64;
    for (index, byte) in after_dot[..end].bytes().take(3).enumerate() {
        millis += i64::from(byte - b'0') * [100, 10, 1][index];
    }
    Some((millis, &after_dot[end..]))
}

/// Reads the zone suffix as an offset in minutes east of UTC.
fn offset(rest: &str) -> Option<i64> {
    if matches!(rest, "Z" | "z") {
        return Some(0);
    }
    let sign = match rest.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    if rest.len() != 6 || rest.as_bytes()[3] != b':' {
        return None;
    }
    let hours = digits(rest, 1, 3)?;
    let minutes = digits(rest, 4, 6)?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 60 + minutes))
}

/// Days since 1970-01-01 for a civil date. Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Inverse of [`days_from_civil`]. Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Length of a month, so an impossible date is rejected rather than rolled forward.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.rem_euclid(4) == 0
            && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0) =>
        {
            29
        }
        2 => 28,
        _ => 0,
    }
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
pub(crate) fn record_relative(id: &RecordId, stamp: &Stamp) -> PathBuf {
    PathBuf::from(RECORDS_DIR)
        .join(format!("{:04}", stamp.year))
        .join(format!("{:02}", stamp.month))
        .join(format!("{:02}", stamp.day))
        .join(format!("{}.{RECORD_EXT}", id.as_str()))
}

#[cfg(test)]
mod tests {
    use super::{civil_from_days, days_from_civil, record_relative, stamp};
    use yaam_contract::RecordId;

    #[test]
    fn a_utc_timestamp_parses_to_its_own_date() {
        let parsed = stamp("2026-08-20T09:14:02Z").expect("valid");
        assert_eq!((parsed.year, parsed.month, parsed.day), (2026, 8, 20));
        assert_eq!(parsed.date(), "2026-08-20");
        assert_eq!(parsed.ms, 1_787_217_242_000);
    }

    #[test]
    fn fractions_reach_milliseconds_and_no_further() {
        assert_eq!(
            stamp("2026-08-20T09:14:02.117Z").expect("valid").ms % 1_000,
            117
        );
        assert_eq!(
            stamp("2026-08-20T09:14:02.1Z").expect("valid").ms % 1_000,
            100
        );
        // Sub-millisecond digits are truncated, which is what the index does with them too.
        assert_eq!(
            stamp("2026-08-20T09:14:02.117999Z").expect("valid").ms % 1_000,
            117
        );
    }

    #[test]
    fn an_offset_moves_the_instant_and_can_move_the_day() {
        let utc = stamp("2026-08-20T00:30:00Z").expect("valid");
        let ahead = stamp("2026-08-20T09:30:00+09:00").expect("valid");
        assert_eq!(utc.ms, ahead.ms);
        // The directory follows the UTC date, not the source's local one.
        let crossing = stamp("2026-08-20T00:30:00+09:00").expect("valid");
        assert_eq!((crossing.year, crossing.month, crossing.day), (2026, 8, 19));
    }

    #[test]
    fn a_timestamp_this_cannot_read_is_refused_rather_than_repaired() {
        for text in [
            "",
            "2026-08-20",
            "2026-08-20T09:14",
            "2026-08-20 09:14:02",  // no zone
            "2026-13-01T00:00:00Z", // month 13
            "2026-02-30T00:00:00Z", // February has no 30th
            "2026-08-20T24:00:00Z", // hour 24
            "2026-08-20T09:61:00Z", // minute 61
            "+026-08-20T09:14:02Z", // a signed year is not a year
            "2026-08-20T09:14:02.Z",
            "2026-08-20T09:14:02+9:00",
            "2026-08-20T09:14:02+24:00",
            "2026-08-20T09:14:02*",
            "2026/08/20T09:14:02Z",
        ] {
            assert!(stamp(text).is_none(), "{text:?} must be refused");
        }
        // A space separator is accepted; the zone still is not optional.
        assert!(stamp("2026-08-20 09:14:02Z").is_some());
    }

    #[test]
    fn a_leap_second_stays_in_its_own_minute() {
        let leap = stamp("2016-12-31T23:59:60Z").expect("valid");
        let before = stamp("2016-12-31T23:59:59Z").expect("valid");
        assert_eq!(leap.ms, before.ms);
    }

    #[test]
    fn the_calendar_round_trips_across_era_boundaries() {
        for (year, month, day) in [
            (1970, 1, 1),
            (1969, 12, 31),
            (2000, 2, 29),
            (1900, 3, 1),
            (2026, 8, 20),
            (2400, 12, 31),
        ] {
            let days = days_from_civil(year, month, day);
            assert_eq!(
                civil_from_days(days),
                (year, month, day),
                "{year}-{month}-{day}"
            );
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn a_pre_epoch_timestamp_keeps_its_own_day() {
        let parsed = stamp("1969-07-20T20:17:00Z").expect("valid");
        assert!(parsed.ms < 0);
        assert_eq!((parsed.year, parsed.month, parsed.day), (1969, 7, 20));
    }

    #[test]
    fn a_records_path_is_dated_and_named_by_its_id() {
        let id = RecordId::parse("01ARZ3NDEKTSV4RRFFQ69G5FAV").expect("valid");
        let parsed = stamp("2026-01-05T00:00:00Z").expect("valid");
        assert_eq!(
            record_relative(&id, &parsed),
            std::path::PathBuf::from("records/2026/01/05/01ARZ3NDEKTSV4RRFFQ69G5FAV.md")
        );
    }
}
