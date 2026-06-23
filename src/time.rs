//! Wall-clock helpers. The whole app reasons about "today" in
//! America/Los_Angeles regardless of the server's own timezone (PRD §2.5).

use chrono::{DateTime, NaiveDate, NaiveTime, TimeZone, Utc};
use chrono_tz::America::Los_Angeles;
use chrono_tz::Tz;

pub const APP_TZ: Tz = Los_Angeles;

/// Current instant.
pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// The current local (LA) calendar date — the app's `game_date` for "today".
pub fn today() -> NaiveDate {
    now().with_timezone(&APP_TZ).date_naive()
}

/// Current local wall-clock time (LA).
pub fn local_time_now() -> NaiveTime {
    now().with_timezone(&APP_TZ).time()
}

/// Convert an LA local date+time to a UTC instant, handling DST gaps/folds by
/// taking the earliest valid mapping.
pub fn la_datetime_to_utc(date: NaiveDate, time: NaiveTime) -> DateTime<Utc> {
    let naive = date.and_time(time);
    match APP_TZ.from_local_datetime(&naive) {
        chrono::LocalResult::Single(dt) => dt.with_timezone(&Utc),
        chrono::LocalResult::Ambiguous(dt, _) => dt.with_timezone(&Utc),
        chrono::LocalResult::None => {
            // Spring-forward gap: nudge forward an hour to the next valid time.
            let bumped = naive + chrono::Duration::hours(1);
            APP_TZ
                .from_local_datetime(&bumped)
                .single()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|| Utc.from_utc_datetime(&naive))
        }
    }
}

/// Parse "HH:MM" (24h) into a NaiveTime.
pub fn parse_hhmm(s: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(s.trim(), "%H:%M").ok()
}
