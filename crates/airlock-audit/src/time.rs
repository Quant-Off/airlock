use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m as u32, d as u32)
}

pub fn format_rfc3339_nanos(unix_nanos: u64) -> String {
    let secs = (unix_nanos / 1_000_000_000) as i64;
    let nanos = unix_nanos % 1_000_000_000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let h = tod / 3600;
    let mi = (tod % 3600) / 60;
    let s = tod % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{nanos:09}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch() {
        assert_eq!(format_rfc3339_nanos(0), "1970-01-01T00:00:00.000000000Z");
    }

    #[test]
    fn known_instants() {
        assert_eq!(
            format_rfc3339_nanos(1_000_000_000_000_000_000),
            "2001-09-09T01:46:40.000000000Z"
        );
        assert_eq!(
            format_rfc3339_nanos(1_700_000_000_123_456_789),
            "2023-11-14T22:13:20.123456789Z"
        );
    }

    #[test]
    fn leap_day_2024() {
        let secs: u64 = 1_709_164_800;
        assert_eq!(
            format_rfc3339_nanos(secs * 1_000_000_000),
            "2024-02-29T00:00:00.000000000Z"
        );
    }

    #[test]
    fn end_of_century_non_leap_1900_rule() {
        let secs: u64 = 4_107_542_400;
        assert_eq!(
            format_rfc3339_nanos(secs * 1_000_000_000),
            "2100-03-01T00:00:00.000000000Z"
        );
    }

    #[test]
    fn nanos_are_zero_padded_to_nine_digits() {
        assert_eq!(format_rfc3339_nanos(1), "1970-01-01T00:00:00.000000001Z");
    }

    #[test]
    fn now_is_after_2020() {
        assert!(now_unix_nanos() > 1_577_836_800_000_000_000);
    }

    #[test]
    fn day_boundary() {
        let secs: u64 = 86_399;
        assert_eq!(
            format_rfc3339_nanos(secs * 1_000_000_000),
            "1970-01-01T23:59:59.000000000Z"
        );
        assert_eq!(
            format_rfc3339_nanos(86_400 * 1_000_000_000),
            "1970-01-02T00:00:00.000000000Z"
        );
    }
}
