//! The one reading of a record's timestamps.
//!
//! Here rather than in the layers above because two of them disagree cheaply and silently: the
//! index converts the same string with `SQLite`'s `unixepoch()`, and the tree derives a record's
//! directory from the date. A record filed under a day a windowed query does not look at is not a
//! failure anybody sees.
//!
//! Hand-parsed rather than delegated to a date library, for the same reason: the accepted grammar
//! *is* the contract, and it has to be the same grammar `unixepoch()` accepts.

/// Milliseconds in a day.
const MS_PER_DAY: i64 = 86_400_000;

/// Reads an `RFC3339` timestamp as milliseconds since the Unix epoch.
///
/// `None` rather than a repaired value: a timestamp this cannot read would place a record at an
/// arbitrary instant, and every ordering, window and directory downstream is derived from it.
///
/// # Examples
/// ```
/// use yaam_contract::timestamp;
///
/// assert_eq!(timestamp::parse_ms("1970-01-01T00:00:01Z"), Some(1_000));
/// assert_eq!(timestamp::parse_ms("not a timestamp"), None);
/// ```
#[must_use]
pub fn parse_ms(text: &str) -> Option<i64> {
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

    Some(
        days_from_civil(year, month, day) * MS_PER_DAY
            + hour * 3_600_000
            + minute * 60_000
            + second.min(59) * 1_000
            + fraction_ms
            - offset_minutes * 60_000,
    )
}

/// The UTC calendar date — year, month, day — an instant falls on.
///
/// Paired with [`parse_ms`] rather than read out of the text: an offset can move an instant onto the
/// day before or after the one its own digits name, and it is the UTC day that has to be agreed on.
///
/// # Examples
/// ```
/// use yaam_contract::timestamp;
///
/// let ms = timestamp::parse_ms("2026-08-20T00:30:00+09:00").expect("valid");
/// assert_eq!(timestamp::civil_from_ms(ms), (2026, 8, 19));
/// ```
#[must_use]
pub fn civil_from_ms(ms: i64) -> (i64, i64, i64) {
    civil_from_days(ms.div_euclid(MS_PER_DAY))
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

#[cfg(test)]
mod tests {
    use super::{civil_from_days, civil_from_ms, days_from_civil, parse_ms};

    #[test]
    fn a_utc_timestamp_parses_to_its_own_date() {
        let ms = parse_ms("2026-08-20T09:14:02Z").expect("valid");
        assert_eq!(ms, 1_787_217_242_000);
        assert_eq!(civil_from_ms(ms), (2026, 8, 20));
    }

    #[test]
    fn fractions_reach_milliseconds_and_no_further() {
        assert_eq!(
            parse_ms("2026-08-20T09:14:02.117Z").expect("valid") % 1_000,
            117
        );
        assert_eq!(
            parse_ms("2026-08-20T09:14:02.1Z").expect("valid") % 1_000,
            100
        );
        // Sub-millisecond digits are truncated, which is what the index does with them too.
        assert_eq!(
            parse_ms("2026-08-20T09:14:02.117999Z").expect("valid") % 1_000,
            117
        );
    }

    #[test]
    fn an_offset_moves_the_instant_and_can_move_the_day() {
        let utc = parse_ms("2026-08-20T00:30:00Z").expect("valid");
        let ahead = parse_ms("2026-08-20T09:30:00+09:00").expect("valid");
        assert_eq!(utc, ahead);
        // The date follows UTC, not the source's local one.
        let crossing = parse_ms("2026-08-20T00:30:00+09:00").expect("valid");
        assert_eq!(civil_from_ms(crossing), (2026, 8, 19));
    }

    #[test]
    fn a_timestamp_this_cannot_read_is_refused_rather_than_repaired() {
        for text in [
            "",
            "2026-08-20",
            "2026-08-20T09:14",
            "2026-08-20 09:14:02",  // no zone
            "2026-13-01T00:00:00Z", // month 13
            "2026-00-01T00:00:00Z", // month 0
            "2026-02-30T00:00:00Z", // February has no 30th
            "2100-02-29T00:00:00Z", // nor a 29th in a century that is not a leap year
            "2026-04-31T00:00:00Z", // April has no 31st
            "2026-08-20X09:14:02Z", // X does not separate a date from a time
            "2026-08-20T24:00:00Z", // hour 24
            "2026-08-20T09:61:00Z", // minute 61
            "+026-08-20T09:14:02Z", // a signed year is not a year
            "2026-08-20T09:14:02.Z",
            "2026-08-20T09:14:02+9:00",
            "2026-08-20T09:14:02+24:00",
            "2026-08-20T09:14:02*",
            "2026/08/20T09:14:02Z",
        ] {
            assert!(parse_ms(text).is_none(), "{text:?} must be refused");
        }
        // A space separator is accepted; the zone still is not optional.
        assert!(parse_ms("2026-08-20 09:14:02Z").is_some());
    }

    #[test]
    fn an_offset_behind_utc_moves_the_instant_forward() {
        // Behind as well as ahead: a sign read the wrong way round is two hours of history filed
        // under the wrong stamp, and nothing downstream could tell.
        assert_eq!(
            parse_ms("2026-08-20T09:00:00-02:00").expect("valid"),
            parse_ms("2026-08-20T11:00:00Z").expect("valid")
        );
    }

    #[test]
    fn every_month_keeps_its_own_length() {
        for (date, valid) in [
            ("2026-01-31", true),
            ("2026-04-30", true),
            ("2026-04-31", false),
            ("2024-02-29", true),
            ("2026-02-29", false),
            ("2000-02-29", true),
        ] {
            let text = format!("{date}T00:00:00Z");
            assert_eq!(parse_ms(&text).is_some(), valid, "{text}");
        }
    }

    #[test]
    fn a_leap_second_stays_in_its_own_minute() {
        let leap = parse_ms("2016-12-31T23:59:60Z").expect("valid");
        let before = parse_ms("2016-12-31T23:59:59Z").expect("valid");
        assert_eq!(leap, before);
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
        let ms = parse_ms("1969-07-20T20:17:00Z").expect("valid");
        assert!(ms < 0);
        assert_eq!(civil_from_ms(ms), (1969, 7, 20));
    }
}
