//! PHP date/time extension.
//!
//! Implements time(), date(), strtotime(), mktime(), DateTime classes.
//! Reference: php-src/ext/date/

use std::time::{SystemTime, UNIX_EPOCH};

/// time() — Return current Unix timestamp.
pub fn php_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// microtime() — Return current Unix timestamp with microseconds.
pub fn php_microtime_float() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// date() — Format a local time/date.
///
/// Supports common format characters: Y, m, d, H, i, s, G, g, A, a, N, w, j, n, U, etc.
pub fn php_date(format: &str, timestamp: i64) -> String {
    let dt = DateTime::from_timestamp(timestamp);
    let mut result = String::new();
    let mut chars = format.chars();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(next) = chars.next() {
                    result.push(next);
                }
            }
            'Y' => result.push_str(&format!("{:04}", dt.year)),
            'y' => result.push_str(&format!("{:02}", dt.year % 100)),
            'm' => result.push_str(&format!("{:02}", dt.month)),
            'n' => result.push_str(&format!("{}", dt.month)),
            'd' => result.push_str(&format!("{:02}", dt.day)),
            'j' => result.push_str(&format!("{}", dt.day)),
            'H' => result.push_str(&format!("{:02}", dt.hour)),
            'G' => result.push_str(&format!("{}", dt.hour)),
            'g' => {
                let h = if dt.hour == 0 {
                    12
                } else if dt.hour > 12 {
                    dt.hour - 12
                } else {
                    dt.hour
                };
                result.push_str(&format!("{}", h));
            }
            'i' => result.push_str(&format!("{:02}", dt.minute)),
            's' => result.push_str(&format!("{:02}", dt.second)),
            'A' => result.push_str(if dt.hour < 12 { "AM" } else { "PM" }),
            'a' => result.push_str(if dt.hour < 12 { "am" } else { "pm" }),
            'U' => result.push_str(&format!("{}", timestamp)),
            'w' => result.push_str(&format!("{}", dt.day_of_week())),
            'N' => {
                let dow = dt.day_of_week();
                result.push_str(&format!("{}", if dow == 0 { 7 } else { dow }));
            }
            'l' => result.push_str(dt.day_name()),
            'D' => result.push_str(&dt.day_name()[..3]),
            'F' => result.push_str(dt.month_name()),
            'M' => result.push_str(&dt.month_name()[..3]),
            't' => result.push_str(&format!("{}", dt.days_in_month())),
            'L' => result.push_str(if dt.is_leap_year() { "1" } else { "0" }),
            _ => result.push(ch),
        }
    }

    result
}

/// mktime() — Get Unix timestamp for a date.
pub fn php_mktime(hour: i32, minute: i32, second: i32, month: i32, day: i32, year: i32) -> i64 {
    let dt = DateTime {
        year: year as i64,
        month: month as u8,
        day: day as u8,
        hour: hour as u8,
        minute: minute as u8,
        second: second as u8,
    };
    dt.to_timestamp()
}

// ── strtotime() ─────────────────────────────────────────────────────────────

/// strtotime() — Parse about any English textual datetime description into a Unix timestamp.
///
/// Supported formats:
/// - ISO dates: "2024-01-15", "2024/01/15", "15-01-2024", "01/15/2024"
/// - Date+time: "2024-01-15 12:30:45", "2024-01-15T12:30:45"
/// - Relative: "now", "yesterday", "tomorrow", "today"
/// - Relative modifiers: "+1 day", "-2 weeks", "+3 months", "+1 year", "next Monday", "last Friday"
/// - Named: "first day of January 2024", "last day of December"
/// - Timestamps: "@1705321845"
/// - Simple: "January 15, 2024", "15 January 2024"
pub fn php_strtotime(input: &str, base_time: Option<i64>) -> Option<i64> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }

    let base = base_time.unwrap_or_else(php_time);

    // Timestamp literal: "@1705321845"
    if let Some(rest) = input.strip_prefix('@') {
        return rest.trim().parse::<i64>().ok();
    }

    // "now"
    if input.eq_ignore_ascii_case("now") {
        return Some(base);
    }

    // "today"
    if input.eq_ignore_ascii_case("today") {
        let dt = DateTime::from_timestamp(base);
        let today = DateTime {
            year: dt.year,
            month: dt.month,
            day: dt.day,
            hour: 0,
            minute: 0,
            second: 0,
        };
        return Some(today.to_timestamp());
    }

    // "yesterday"
    if input.eq_ignore_ascii_case("yesterday") {
        let dt = DateTime::from_timestamp(base - 86400);
        let yesterday = DateTime {
            year: dt.year,
            month: dt.month,
            day: dt.day,
            hour: 0,
            minute: 0,
            second: 0,
        };
        return Some(yesterday.to_timestamp());
    }

    // "tomorrow"
    if input.eq_ignore_ascii_case("tomorrow") {
        let dt = DateTime::from_timestamp(base + 86400);
        let tomorrow = DateTime {
            year: dt.year,
            month: dt.month,
            day: dt.day,
            hour: 0,
            minute: 0,
            second: 0,
        };
        return Some(tomorrow.to_timestamp());
    }

    // Relative modifier: "+1 day", "-2 weeks", "+3 months", "+1 year"
    if let Some(ts) = parse_relative_modifier(input, base) {
        return Some(ts);
    }

    // "next Monday", "last Friday"
    if let Some(ts) = parse_next_last_day(input, base) {
        return Some(ts);
    }

    // "first day of January 2024", "last day of December 2024"
    if let Some(ts) = parse_first_last_day_of(input) {
        return Some(ts);
    }

    // Named month formats: "January 15, 2024", "15 January 2024"
    if let Some(ts) = parse_named_month_date(input) {
        return Some(ts);
    }

    // ISO-like date (with optional time): "2024-01-15", "2024-01-15 12:30:45", "2024-01-15T12:30:45"
    if let Some(ts) = parse_iso_date(input) {
        return Some(ts);
    }

    // Slash date: "2024/01/15" or "01/15/2024"
    if let Some(ts) = parse_slash_date(input) {
        return Some(ts);
    }

    // DD-MM-YYYY format: "15-01-2024"
    if let Some(ts) = parse_dmy_dash_date(input) {
        return Some(ts);
    }

    None
}

/// Parse relative modifiers: "+1 day", "-2 weeks", "+3 months", "+1 year", "1 day", etc.
fn parse_relative_modifier(input: &str, base: i64) -> Option<i64> {
    let input_lower = input.to_ascii_lowercase();
    let input_lower = input_lower.trim();

    // Parse sign and number
    let (sign, rest): (i64, &str) = if let Some(r) = input_lower.strip_prefix('+') {
        (1, r.trim())
    } else if let Some(r) = input_lower.strip_prefix('-') {
        (-1, r.trim())
    } else {
        // Try without explicit sign
        (1, input_lower.as_ref())
    };

    // Try to parse "N unit"
    let parts: Vec<&str> = rest.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return None;
    }

    let n: i64 = parts[0].parse().ok()?;
    let unit = parts[1].trim();

    let dt = DateTime::from_timestamp(base);

    match unit {
        "second" | "seconds" | "sec" | "secs" => Some(base + sign * n),
        "minute" | "minutes" | "min" | "mins" => Some(base + sign * n * 60),
        "hour" | "hours" => Some(base + sign * n * 3600),
        "day" | "days" => Some(base + sign * n * 86400),
        "week" | "weeks" => Some(base + sign * n * 7 * 86400),
        "month" | "months" => {
            let total_months = dt.year * 12 + dt.month as i64 - 1 + sign * n;
            let new_year = total_months.div_euclid(12);
            let new_month = (total_months.rem_euclid(12) + 1) as u8;
            let max_day = days_in_month_for(new_year, new_month);
            let new_day = if dt.day > max_day { max_day } else { dt.day };
            let new_dt = DateTime {
                year: new_year,
                month: new_month,
                day: new_day,
                hour: dt.hour,
                minute: dt.minute,
                second: dt.second,
            };
            Some(new_dt.to_timestamp())
        }
        "year" | "years" => {
            let new_year = dt.year + sign * n;
            let max_day = days_in_month_for(new_year, dt.month);
            let new_day = if dt.day > max_day { max_day } else { dt.day };
            let new_dt = DateTime {
                year: new_year,
                month: dt.month,
                day: new_day,
                hour: dt.hour,
                minute: dt.minute,
                second: dt.second,
            };
            Some(new_dt.to_timestamp())
        }
        _ => None,
    }
}

/// Parse "next Monday", "last Friday", etc.
fn parse_next_last_day(input: &str, base: i64) -> Option<i64> {
    let input_lower = input.to_ascii_lowercase();
    let parts: Vec<&str> = input_lower.split_whitespace().collect();
    if parts.len() != 2 {
        return None;
    }

    let direction = parts[0];
    let target_dow = day_name_to_dow(parts[1])?;

    let dt = DateTime::from_timestamp(base);
    let current_dow = dt.day_of_week() as i64;
    let target = target_dow as i64;

    let offset_days = match direction {
        "next" => {
            let diff = target - current_dow;
            if diff <= 0 {
                diff + 7
            } else {
                diff
            }
        }
        "last" => {
            let diff = current_dow - target;
            if diff <= 0 {
                -(diff + 7)
            } else {
                -diff
            }
        }
        _ => return None,
    };

    let target_ts = base + offset_days * 86400;
    let target_dt = DateTime::from_timestamp(target_ts);
    let result = DateTime {
        year: target_dt.year,
        month: target_dt.month,
        day: target_dt.day,
        hour: 0,
        minute: 0,
        second: 0,
    };
    Some(result.to_timestamp())
}

/// Parse "first day of January 2024", "last day of December 2024"
fn parse_first_last_day_of(input: &str) -> Option<i64> {
    let input_lower = input.to_ascii_lowercase();

    if let Some(rest) = input_lower.strip_prefix("first day of ") {
        let (month, year) = parse_month_and_year(rest)?;
        let dt = DateTime {
            year,
            month,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        };
        return Some(dt.to_timestamp());
    }

    if let Some(rest) = input_lower.strip_prefix("last day of ") {
        let (month, year) = parse_month_and_year(rest)?;
        let last_day = days_in_month_for(year, month);
        let dt = DateTime {
            year,
            month,
            day: last_day,
            hour: 0,
            minute: 0,
            second: 0,
        };
        return Some(dt.to_timestamp());
    }

    None
}

/// Parse month name (+ optional year) from string like "January 2024" or "December"
fn parse_month_and_year(input: &str) -> Option<(u8, i64)> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let month = month_name_to_num(parts[0])?;
    let year = if parts.len() >= 2 {
        parts[1].parse::<i64>().ok()?
    } else {
        // Use current year
        let now = php_time();
        DateTime::from_timestamp(now).year
    };

    Some((month, year))
}

/// Parse named month date: "January 15, 2024" or "15 January 2024"
fn parse_named_month_date(input: &str) -> Option<i64> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    // "January 15, 2024"
    if let Some(month) = month_name_to_num(&parts[0].to_ascii_lowercase()) {
        let day_str = parts[1].trim_end_matches(',');
        let day: u8 = day_str.parse().ok()?;
        let year: i64 = parts[2].parse().ok()?;
        let dt = DateTime {
            year,
            month,
            day,
            hour: 0,
            minute: 0,
            second: 0,
        };
        return Some(dt.to_timestamp());
    }

    // "15 January 2024"
    if let Ok(day) = parts[0].parse::<u8>() {
        if let Some(month) = month_name_to_num(&parts[1].to_ascii_lowercase()) {
            let year: i64 = parts[2].parse().ok()?;
            let dt = DateTime {
                year,
                month,
                day,
                hour: 0,
                minute: 0,
                second: 0,
            };
            return Some(dt.to_timestamp());
        }
    }

    None
}

/// Parse ISO-like dates: "2024-01-15", "2024-01-15 12:30:45", "2024-01-15T12:30:45"
fn parse_iso_date(input: &str) -> Option<i64> {
    // Split date and optional time
    let (date_part, time_part) = if input.contains('T') {
        let mut parts = input.splitn(2, 'T');
        (parts.next()?, parts.next())
    } else if input.contains(' ') {
        let mut parts = input.splitn(2, ' ');
        (parts.next()?, parts.next())
    } else {
        (input, None)
    };

    let date_parts: Vec<&str> = date_part.split('-').collect();
    if date_parts.len() != 3 {
        return None;
    }

    let year: i64 = date_parts[0].parse().ok()?;
    let month: u8 = date_parts[1].parse().ok()?;
    let day: u8 = date_parts[2].parse().ok()?;

    // Validate that this looks like YYYY-MM-DD (year must be > 31 to distinguish from DD-MM-YYYY)
    if year < 100 && date_parts[0].len() < 4 {
        return None; // Not ISO format
    }

    let (hour, minute, second) = if let Some(time) = time_part {
        parse_time_string(time)?
    } else {
        (0, 0, 0)
    };

    if month < 1 || month > 12 || day < 1 || day > 31 {
        return None;
    }

    let dt = DateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
    };
    Some(dt.to_timestamp())
}

/// Parse slash dates: "2024/01/15" or "01/15/2024"
fn parse_slash_date(input: &str) -> Option<i64> {
    let parts: Vec<&str> = input.split('/').collect();
    if parts.len() != 3 {
        return None;
    }

    let a: i64 = parts[0].parse().ok()?;
    let b: u8 = parts[1].parse().ok()?;
    let c: i64 = parts[2].parse().ok()?;

    // If first part is > 31, it's YYYY/MM/DD
    if a > 31 {
        let year = a;
        let month = b;
        let day = c as u8;
        if month < 1 || month > 12 || day < 1 || day > 31 {
            return None;
        }
        let dt = DateTime {
            year,
            month,
            day,
            hour: 0,
            minute: 0,
            second: 0,
        };
        Some(dt.to_timestamp())
    } else {
        // MM/DD/YYYY
        let month = a as u8;
        let day = b;
        let year = c;
        if month < 1 || month > 12 || day < 1 || day > 31 {
            return None;
        }
        let dt = DateTime {
            year,
            month,
            day,
            hour: 0,
            minute: 0,
            second: 0,
        };
        Some(dt.to_timestamp())
    }
}

/// Parse DD-MM-YYYY dashed date (non-ISO order).
fn parse_dmy_dash_date(input: &str) -> Option<i64> {
    let parts: Vec<&str> = input.split('-').collect();
    if parts.len() != 3 {
        return None;
    }

    let day: u8 = parts[0].parse().ok()?;
    let month: u8 = parts[1].parse().ok()?;
    let year: i64 = parts[2].parse().ok()?;

    // Day should be <= 31, month <= 12, year > 31 to distinguish from ISO
    if day < 1 || day > 31 || month < 1 || month > 12 || year <= 31 {
        return None;
    }

    let dt = DateTime {
        year,
        month,
        day,
        hour: 0,
        minute: 0,
        second: 0,
    };
    Some(dt.to_timestamp())
}

/// Parse a time string like "12:30:45" or "12:30"
fn parse_time_string(input: &str) -> Option<(u8, u8, u8)> {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.len() < 2 {
        return None;
    }
    let hour: u8 = parts[0].parse().ok()?;
    let minute: u8 = parts[1].parse().ok()?;
    let second: u8 = if parts.len() >= 3 {
        parts[2].parse().ok()?
    } else {
        0
    };

    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    Some((hour, minute, second))
}

/// Convert day name to day of week number (0=Sunday).
fn day_name_to_dow(name: &str) -> Option<u8> {
    match name {
        "sunday" | "sun" => Some(0),
        "monday" | "mon" => Some(1),
        "tuesday" | "tue" => Some(2),
        "wednesday" | "wed" => Some(3),
        "thursday" | "thu" => Some(4),
        "friday" | "fri" => Some(5),
        "saturday" | "sat" => Some(6),
        _ => None,
    }
}

/// Convert month name to number (1-12).
fn month_name_to_num(name: &str) -> Option<u8> {
    match name {
        "january" | "jan" => Some(1),
        "february" | "feb" => Some(2),
        "march" | "mar" => Some(3),
        "april" | "apr" => Some(4),
        "may" => Some(5),
        "june" | "jun" => Some(6),
        "july" | "jul" => Some(7),
        "august" | "aug" => Some(8),
        "september" | "sep" => Some(9),
        "october" | "oct" => Some(10),
        "november" | "nov" => Some(11),
        "december" | "dec" => Some(12),
        _ => None,
    }
}

/// Helper: days in a month for a given year.
fn days_in_month_for(year: i64, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

/// Simple date/time struct (UTC, no timezone support yet).
#[derive(Debug, Clone, PartialEq)]
pub struct DateTime {
    pub year: i64,
    pub month: u8,  // 1-12
    pub day: u8,    // 1-31
    pub hour: u8,   // 0-23
    pub minute: u8, // 0-59
    pub second: u8, // 0-59
}

impl DateTime {
    /// Create DateTime from a Unix timestamp (UTC).
    pub fn from_timestamp(ts: i64) -> Self {
        // Algorithm from Howard Hinnant's date algorithms
        let z = ts / 86400 + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = (z - era * 146097) as u32;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };

        let day_seconds = ts.rem_euclid(86400);
        let hour = (day_seconds / 3600) as u8;
        let minute = ((day_seconds % 3600) / 60) as u8;
        let second = (day_seconds % 60) as u8;

        Self {
            year: y,
            month: m as u8,
            day: d as u8,
            hour,
            minute,
            second,
        }
    }

    /// Convert to Unix timestamp.
    pub fn to_timestamp(&self) -> i64 {
        let y = if self.month <= 2 {
            self.year - 1
        } else {
            self.year
        };
        let m = if self.month <= 2 {
            self.month as i64 + 9
        } else {
            self.month as i64 - 3
        };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = (y - era * 400) as u32;
        let doy = (153 * m as u32 + 2) / 5 + self.day as u32 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe as i64 - 719468;
        days * 86400 + self.hour as i64 * 3600 + self.minute as i64 * 60 + self.second as i64
    }

    /// Get day of week (0=Sunday, 6=Saturday).
    pub fn day_of_week(&self) -> u8 {
        let ts = self.to_timestamp();
        let days = ts / 86400;
        (((days % 7) + 4 + 7) % 7) as u8 // Unix epoch was Thursday (4)
    }

    /// Get day name.
    pub fn day_name(&self) -> &'static str {
        match self.day_of_week() {
            0 => "Sunday",
            1 => "Monday",
            2 => "Tuesday",
            3 => "Wednesday",
            4 => "Thursday",
            5 => "Friday",
            6 => "Saturday",
            _ => "Unknown",
        }
    }

    /// Get month name.
    pub fn month_name(&self) -> &'static str {
        match self.month {
            1 => "January",
            2 => "February",
            3 => "March",
            4 => "April",
            5 => "May",
            6 => "June",
            7 => "July",
            8 => "August",
            9 => "September",
            10 => "October",
            11 => "November",
            12 => "December",
            _ => "Unknown",
        }
    }

    /// Days in the current month.
    pub fn days_in_month(&self) -> u8 {
        days_in_month_for(self.year, self.month)
    }

    /// Is this a leap year?
    pub fn is_leap_year(&self) -> bool {
        (self.year % 4 == 0 && self.year % 100 != 0) || self.year % 400 == 0
    }
}

// ── DateTime classes ────────────────────────────────────────────────────────

/// PHP DateTime class equivalent.
#[derive(Debug, Clone)]
pub struct PhpDateTime {
    pub timestamp: i64,
    pub timezone: String,
}

impl PhpDateTime {
    /// Create a new PhpDateTime, parsing an optional datetime string.
    /// If no string is provided, uses current time.
    pub fn new(datetime_str: Option<&str>, timezone: Option<&str>) -> Result<Self, String> {
        let tz = timezone.unwrap_or("UTC").to_string();
        let tz_offset = PhpDateTimeZone::offset_for_name(&tz).unwrap_or(0);

        let timestamp = match datetime_str {
            Some(s) => {
                let ts = php_strtotime(s, None)
                    .ok_or_else(|| format!("Failed to parse datetime string: {}", s))?;
                // Adjust for timezone: strtotime returns UTC, we store as UTC but adjusted
                ts - tz_offset as i64
            }
            None => php_time(),
        };

        Ok(Self {
            timestamp,
            timezone: tz,
        })
    }

    /// Format the datetime using php_date() format characters.
    pub fn format(&self, format: &str) -> String {
        let tz_offset = PhpDateTimeZone::offset_for_name(&self.timezone).unwrap_or(0);
        php_date(format, self.timestamp + tz_offset as i64)
    }

    /// Get the Unix timestamp.
    pub fn get_timestamp(&self) -> i64 {
        self.timestamp
    }

    /// Modify the datetime with a relative modifier like "+1 day", "-2 months".
    pub fn modify(&mut self, modifier: &str) -> Result<(), String> {
        let new_ts = php_strtotime(modifier, Some(self.timestamp))
            .ok_or_else(|| format!("Failed to parse modifier: {}", modifier))?;
        self.timestamp = new_ts;
        Ok(())
    }

    /// Compute the difference between this and another PhpDateTime.
    pub fn diff(&self, other: &PhpDateTime) -> PhpDateInterval {
        let dt1 = DateTime::from_timestamp(self.timestamp);
        let dt2 = DateTime::from_timestamp(other.timestamp);

        let invert = self.timestamp > other.timestamp;
        let (earlier, later) = if invert { (&dt2, &dt1) } else { (&dt1, &dt2) };

        // Calculate year/month/day differences
        let mut years = later.year - earlier.year;
        let mut months = later.month as i32 - earlier.month as i32;
        let mut days = later.day as i32 - earlier.day as i32;

        if days < 0 {
            months -= 1;
            let prev_month_days = days_in_month_for(
                later.year,
                if later.month == 1 {
                    12
                } else {
                    later.month - 1
                },
            );
            days += prev_month_days as i32;
        }

        if months < 0 {
            years -= 1;
            months += 12;
        }

        let hours = later.hour as i32 - earlier.hour as i32;
        let minutes = later.minute as i32 - earlier.minute as i32;
        let seconds = later.second as i32 - earlier.second as i32;

        // Normalize time components
        let total_seconds = hours * 3600 + minutes * 60 + seconds;
        let (h, m, s) = if total_seconds < 0 {
            days -= 1;
            let adj = total_seconds + 86400;
            (adj / 3600, (adj % 3600) / 60, adj % 60)
        } else {
            (
                total_seconds / 3600,
                (total_seconds % 3600) / 60,
                total_seconds % 60,
            )
        };

        PhpDateInterval {
            years: years as i32,
            months: months,
            days,
            hours: h,
            minutes: m,
            seconds: s,
            invert,
        }
    }

    /// Set the date components.
    pub fn set_date(&mut self, year: i32, month: i32, day: i32) {
        let dt = DateTime::from_timestamp(self.timestamp);
        let new_dt = DateTime {
            year: year as i64,
            month: month as u8,
            day: day as u8,
            hour: dt.hour,
            minute: dt.minute,
            second: dt.second,
        };
        self.timestamp = new_dt.to_timestamp();
    }

    /// Set the time components.
    pub fn set_time(&mut self, hour: i32, minute: i32, second: i32) {
        let dt = DateTime::from_timestamp(self.timestamp);
        let new_dt = DateTime {
            year: dt.year,
            month: dt.month,
            day: dt.day,
            hour: hour as u8,
            minute: minute as u8,
            second: second as u8,
        };
        self.timestamp = new_dt.to_timestamp();
    }

    /// Create from a format string (basic implementation).
    ///
    /// Supports: Y (4-digit year), m (2-digit month), d (2-digit day),
    /// H (2-digit hour), i (2-digit minute), s (2-digit second),
    /// literal characters.
    pub fn create_from_format(format: &str, datetime: &str) -> Result<Self, String> {
        let mut year: i64 = 1970;
        let mut month: u8 = 1;
        let mut day: u8 = 1;
        let mut hour: u8 = 0;
        let mut minute: u8 = 0;
        let mut second: u8 = 0;

        let fmt_chars: Vec<char> = format.chars().collect();
        let dt_chars: Vec<char> = datetime.chars().collect();
        let mut di = 0;

        for &fc in &fmt_chars {
            match fc {
                'Y' => {
                    if di + 4 > dt_chars.len() {
                        return Err("Not enough characters for year".to_string());
                    }
                    let s: String = dt_chars[di..di + 4].iter().collect();
                    year = s.parse().map_err(|_| format!("Invalid year: {}", s))?;
                    di += 4;
                }
                'm' => {
                    if di + 2 > dt_chars.len() {
                        return Err("Not enough characters for month".to_string());
                    }
                    let s: String = dt_chars[di..di + 2].iter().collect();
                    month = s.parse().map_err(|_| format!("Invalid month: {}", s))?;
                    di += 2;
                }
                'd' => {
                    if di + 2 > dt_chars.len() {
                        return Err("Not enough characters for day".to_string());
                    }
                    let s: String = dt_chars[di..di + 2].iter().collect();
                    day = s.parse().map_err(|_| format!("Invalid day: {}", s))?;
                    di += 2;
                }
                'H' => {
                    if di + 2 > dt_chars.len() {
                        return Err("Not enough characters for hour".to_string());
                    }
                    let s: String = dt_chars[di..di + 2].iter().collect();
                    hour = s.parse().map_err(|_| format!("Invalid hour: {}", s))?;
                    di += 2;
                }
                'i' => {
                    if di + 2 > dt_chars.len() {
                        return Err("Not enough characters for minute".to_string());
                    }
                    let s: String = dt_chars[di..di + 2].iter().collect();
                    minute = s.parse().map_err(|_| format!("Invalid minute: {}", s))?;
                    di += 2;
                }
                's' => {
                    if di + 2 > dt_chars.len() {
                        return Err("Not enough characters for second".to_string());
                    }
                    let s: String = dt_chars[di..di + 2].iter().collect();
                    second = s.parse().map_err(|_| format!("Invalid second: {}", s))?;
                    di += 2;
                }
                _ => {
                    // Literal character — skip it in the input
                    if di < dt_chars.len() {
                        di += 1;
                    }
                }
            }
        }

        let dt = DateTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        };
        Ok(Self {
            timestamp: dt.to_timestamp(),
            timezone: "UTC".to_string(),
        })
    }
}

/// PHP DateTimeImmutable - same as DateTime but returns new instances.
#[derive(Debug, Clone)]
pub struct PhpDateTimeImmutable {
    inner: PhpDateTime,
}

impl PhpDateTimeImmutable {
    /// Create a new PhpDateTimeImmutable.
    pub fn new(datetime_str: Option<&str>, timezone: Option<&str>) -> Result<Self, String> {
        Ok(Self {
            inner: PhpDateTime::new(datetime_str, timezone)?,
        })
    }

    /// Format the datetime.
    pub fn format(&self, format: &str) -> String {
        self.inner.format(format)
    }

    /// Get the Unix timestamp.
    pub fn get_timestamp(&self) -> i64 {
        self.inner.get_timestamp()
    }

    /// Modify and return a new instance.
    pub fn modify(&self, modifier: &str) -> Result<Self, String> {
        let mut new_inner = self.inner.clone();
        new_inner.modify(modifier)?;
        Ok(Self { inner: new_inner })
    }

    /// Compute the difference.
    pub fn diff(&self, other: &PhpDateTimeImmutable) -> PhpDateInterval {
        self.inner.diff(&other.inner)
    }

    /// Set date and return a new instance.
    pub fn set_date(&self, year: i32, month: i32, day: i32) -> Self {
        let mut new_inner = self.inner.clone();
        new_inner.set_date(year, month, day);
        Self { inner: new_inner }
    }

    /// Set time and return a new instance.
    pub fn set_time(&self, hour: i32, minute: i32, second: i32) -> Self {
        let mut new_inner = self.inner.clone();
        new_inner.set_time(hour, minute, second);
        Self { inner: new_inner }
    }

    /// Create from a format string.
    pub fn create_from_format(format: &str, datetime: &str) -> Result<Self, String> {
        Ok(Self {
            inner: PhpDateTime::create_from_format(format, datetime)?,
        })
    }
}

// ── DateTimeZone ────────────────────────────────────────────────────────────

/// PHP DateTimeZone.
#[derive(Debug, Clone)]
pub struct PhpDateTimeZone {
    pub name: String,
    pub offset: i32, // seconds from UTC
}

/// Timezone entry: name and UTC offset in seconds.
struct TzEntry {
    name: &'static str,
    offset: i32,
}

/// Built-in timezone database with major timezones and their UTC offsets.
const TIMEZONE_DB: &[TzEntry] = &[
    TzEntry {
        name: "UTC",
        offset: 0,
    },
    TzEntry {
        name: "GMT",
        offset: 0,
    },
    TzEntry {
        name: "US/Eastern",
        offset: -5 * 3600,
    },
    TzEntry {
        name: "US/Central",
        offset: -6 * 3600,
    },
    TzEntry {
        name: "US/Mountain",
        offset: -7 * 3600,
    },
    TzEntry {
        name: "US/Pacific",
        offset: -8 * 3600,
    },
    TzEntry {
        name: "Europe/London",
        offset: 0,
    },
    TzEntry {
        name: "Europe/Paris",
        offset: 1 * 3600,
    },
    TzEntry {
        name: "Europe/Berlin",
        offset: 1 * 3600,
    },
    TzEntry {
        name: "Europe/Moscow",
        offset: 3 * 3600,
    },
    TzEntry {
        name: "Asia/Tokyo",
        offset: 9 * 3600,
    },
    TzEntry {
        name: "Asia/Shanghai",
        offset: 8 * 3600,
    },
    TzEntry {
        name: "Asia/Kolkata",
        offset: 19800,
    }, // 5.5 hours
    TzEntry {
        name: "Australia/Sydney",
        offset: 10 * 3600,
    },
    TzEntry {
        name: "Pacific/Auckland",
        offset: 12 * 3600,
    },
    TzEntry {
        name: "America/New_York",
        offset: -5 * 3600,
    },
    TzEntry {
        name: "America/Chicago",
        offset: -6 * 3600,
    },
    TzEntry {
        name: "America/Denver",
        offset: -7 * 3600,
    },
    TzEntry {
        name: "America/Los_Angeles",
        offset: -8 * 3600,
    },
    TzEntry {
        name: "America/Anchorage",
        offset: -9 * 3600,
    },
    TzEntry {
        name: "America/Sao_Paulo",
        offset: -3 * 3600,
    },
    TzEntry {
        name: "Africa/Cairo",
        offset: 2 * 3600,
    },
    TzEntry {
        name: "Asia/Dubai",
        offset: 4 * 3600,
    },
    TzEntry {
        name: "Asia/Singapore",
        offset: 8 * 3600,
    },
    TzEntry {
        name: "Asia/Hong_Kong",
        offset: 8 * 3600,
    },
];

impl PhpDateTimeZone {
    /// Create a new timezone by name.
    pub fn new(timezone: &str) -> Result<Self, String> {
        let offset = Self::offset_for_name(timezone)
            .ok_or_else(|| format!("Unknown timezone: {}", timezone))?;
        Ok(Self {
            name: timezone.to_string(),
            offset,
        })
    }

    /// Get the UTC offset in seconds.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    /// List all known timezone identifiers.
    pub fn list_identifiers() -> Vec<String> {
        TIMEZONE_DB.iter().map(|tz| tz.name.to_string()).collect()
    }

    /// Lookup offset for a timezone name (case-insensitive).
    pub fn offset_for_name(name: &str) -> Option<i32> {
        let name_lower = name.to_ascii_lowercase();
        TIMEZONE_DB
            .iter()
            .find(|tz| tz.name.to_ascii_lowercase() == name_lower)
            .map(|tz| tz.offset)
    }
}

// ── DateInterval ────────────────────────────────────────────────────────────

/// PHP DateInterval.
#[derive(Debug, Clone, PartialEq)]
pub struct PhpDateInterval {
    pub years: i32,
    pub months: i32,
    pub days: i32,
    pub hours: i32,
    pub minutes: i32,
    pub seconds: i32,
    pub invert: bool,
}

impl PhpDateInterval {
    /// Create from an ISO 8601 duration string: "P1Y2M3DT4H5M6S".
    pub fn create_from_date_string(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        if !spec.starts_with('P') && !spec.starts_with('p') {
            return Err(format!(
                "Invalid interval spec: must start with 'P': {}",
                spec
            ));
        }

        let mut years = 0i32;
        let mut months = 0i32;
        let mut days = 0i32;
        let mut hours = 0i32;
        let mut minutes = 0i32;
        let mut seconds = 0i32;

        let spec = &spec[1..]; // strip 'P'

        // Split on 'T' to separate date and time parts
        let (date_part, time_part) = if let Some(t_pos) = spec.find(|c: char| c == 'T' || c == 't')
        {
            (&spec[..t_pos], Some(&spec[t_pos + 1..]))
        } else {
            (spec, None)
        };

        // Parse date part
        let mut num_buf = String::new();
        for ch in date_part.chars() {
            if ch.is_ascii_digit() {
                num_buf.push(ch);
            } else {
                let n: i32 = if num_buf.is_empty() {
                    0
                } else {
                    num_buf
                        .parse()
                        .map_err(|_| format!("Invalid number in interval: {}", num_buf))?
                };
                num_buf.clear();
                match ch {
                    'Y' | 'y' => years = n,
                    'M' | 'm' => months = n,
                    'D' | 'd' => days = n,
                    'W' | 'w' => days = n * 7,
                    _ => return Err(format!("Unknown date interval character: {}", ch)),
                }
            }
        }

        // Parse time part
        if let Some(time) = time_part {
            num_buf.clear();
            for ch in time.chars() {
                if ch.is_ascii_digit() {
                    num_buf.push(ch);
                } else {
                    let n: i32 = if num_buf.is_empty() {
                        0
                    } else {
                        num_buf
                            .parse()
                            .map_err(|_| format!("Invalid number in interval: {}", num_buf))?
                    };
                    num_buf.clear();
                    match ch {
                        'H' | 'h' => hours = n,
                        'M' | 'm' => minutes = n,
                        'S' | 's' => seconds = n,
                        _ => return Err(format!("Unknown time interval character: {}", ch)),
                    }
                }
            }
        }

        Ok(Self {
            years,
            months,
            days,
            hours,
            minutes,
            seconds,
            invert: false,
        })
    }

    /// Format the interval using format specifiers.
    ///
    /// %Y — years, zero-padded
    /// %y — years
    /// %M — months, zero-padded
    /// %m — months
    /// %D — days, zero-padded
    /// %d — days
    /// %H — hours, zero-padded
    /// %h — hours
    /// %I — minutes, zero-padded
    /// %i — minutes
    /// %S — seconds, zero-padded
    /// %s — seconds
    /// %R — sign (+/-)
    /// %r — sign (- when negative, empty when positive)
    pub fn format(&self, format: &str) -> String {
        let mut result = String::new();
        let mut chars = format.chars();

        while let Some(ch) = chars.next() {
            if ch == '%' {
                if let Some(spec) = chars.next() {
                    match spec {
                        'Y' => result.push_str(&format!("{:02}", self.years)),
                        'y' => result.push_str(&format!("{}", self.years)),
                        'M' => result.push_str(&format!("{:02}", self.months)),
                        'm' => result.push_str(&format!("{}", self.months)),
                        'D' => result.push_str(&format!("{:02}", self.days)),
                        'd' => result.push_str(&format!("{}", self.days)),
                        'H' => result.push_str(&format!("{:02}", self.hours)),
                        'h' => result.push_str(&format!("{}", self.hours)),
                        'I' => result.push_str(&format!("{:02}", self.minutes)),
                        'i' => result.push_str(&format!("{}", self.minutes)),
                        'S' => result.push_str(&format!("{:02}", self.seconds)),
                        's' => result.push_str(&format!("{}", self.seconds)),
                        'R' => result.push(if self.invert { '-' } else { '+' }),
                        'r' => {
                            if self.invert {
                                result.push('-');
                            }
                        }
                        '%' => result.push('%'),
                        _ => {
                            result.push('%');
                            result.push(spec);
                        }
                    }
                }
            } else {
                result.push(ch);
            }
        }

        result
    }
}

// ── DatePeriod ──────────────────────────────────────────────────────────────

/// PHP DatePeriod — iterates over a set of dates/times at a regular interval.
#[derive(Debug, Clone)]
pub struct PhpDatePeriod {
    pub start: PhpDateTime,
    pub interval: PhpDateInterval,
    pub end: Option<PhpDateTime>,
    pub recurrences: Option<u32>,
}

impl PhpDatePeriod {
    /// Create a new DatePeriod.
    pub fn new(
        start: PhpDateTime,
        interval: PhpDateInterval,
        end: Option<PhpDateTime>,
        recurrences: Option<u32>,
    ) -> Self {
        Self {
            start,
            interval,
            end,
            recurrences,
        }
    }

    /// Generate all timestamps in the period.
    pub fn timestamps(&self) -> Vec<i64> {
        let mut results = Vec::new();
        let mut current = self.start.timestamp;
        let mut count = 0u32;
        let max_count = self.recurrences.unwrap_or(u32::MAX);

        loop {
            if count >= max_count {
                break;
            }
            if let Some(ref end) = self.end {
                if current >= end.timestamp {
                    break;
                }
            }

            results.push(current);
            count += 1;

            // Advance by the interval
            let dt = DateTime::from_timestamp(current);
            let new_dt = if self.interval.years != 0 || self.interval.months != 0 {
                let total_months = dt.year * 12 + dt.month as i64 - 1
                    + self.interval.years as i64 * 12
                    + self.interval.months as i64;
                let new_year = total_months.div_euclid(12);
                let new_month = (total_months.rem_euclid(12) + 1) as u8;
                let max_day = days_in_month_for(new_year, new_month);
                let new_day = if dt.day > max_day { max_day } else { dt.day };
                DateTime {
                    year: new_year,
                    month: new_month,
                    day: new_day,
                    hour: dt.hour,
                    minute: dt.minute,
                    second: dt.second,
                }
            } else {
                dt
            };

            current = new_dt.to_timestamp()
                + self.interval.days as i64 * 86400
                + self.interval.hours as i64 * 3600
                + self.interval.minutes as i64 * 60
                + self.interval.seconds as i64;

            // Safety: avoid infinite loops
            if current <= self.start.timestamp && self.end.is_none() && max_count == u32::MAX {
                break;
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time() {
        let t = php_time();
        assert!(t > 1700000000); // After Nov 2023
    }

    #[test]
    fn test_datetime_from_timestamp_epoch() {
        let dt = DateTime::from_timestamp(0);
        assert_eq!(dt.year, 1970);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 1);
        assert_eq!(dt.hour, 0);
        assert_eq!(dt.minute, 0);
        assert_eq!(dt.second, 0);
    }

    #[test]
    fn test_datetime_from_timestamp_known() {
        // 2024-01-15 12:30:45 UTC
        let dt = DateTime::from_timestamp(1705321845);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 15);
        assert_eq!(dt.hour, 12);
        assert_eq!(dt.minute, 30);
        assert_eq!(dt.second, 45);
    }

    #[test]
    fn test_datetime_roundtrip() {
        let ts = 1705321845i64;
        let dt = DateTime::from_timestamp(ts);
        assert_eq!(dt.to_timestamp(), ts);
    }

    #[test]
    fn test_datetime_epoch_roundtrip() {
        assert_eq!(DateTime::from_timestamp(0).to_timestamp(), 0);
    }

    #[test]
    fn test_mktime() {
        let ts = php_mktime(12, 30, 45, 1, 15, 2024);
        let dt = DateTime::from_timestamp(ts);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 15);
        assert_eq!(dt.hour, 12);
    }

    #[test]
    fn test_date_format() {
        let ts = 1705321845; // 2024-01-15 12:30:45
        assert_eq!(php_date("Y-m-d", ts), "2024-01-15");
        assert_eq!(php_date("H:i:s", ts), "12:30:45");
        assert_eq!(php_date("Y", ts), "2024");
        assert_eq!(php_date("A", ts), "PM");
        assert_eq!(php_date("g", ts), "12");
    }

    #[test]
    fn test_date_day_of_week() {
        // 2024-01-15 is a Monday
        let dt = DateTime::from_timestamp(1705321845);
        assert_eq!(dt.day_of_week(), 1);
        assert_eq!(dt.day_name(), "Monday");
    }

    #[test]
    fn test_date_month_name() {
        let dt = DateTime::from_timestamp(1705321845);
        assert_eq!(dt.month_name(), "January");
    }

    #[test]
    fn test_leap_year() {
        assert!(DateTime {
            year: 2024,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0
        }
        .is_leap_year());
        assert!(!DateTime {
            year: 2023,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0
        }
        .is_leap_year());
        assert!(DateTime {
            year: 2000,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0
        }
        .is_leap_year());
        assert!(!DateTime {
            year: 1900,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0
        }
        .is_leap_year());
    }

    #[test]
    fn test_days_in_month() {
        let feb_leap = DateTime {
            year: 2024,
            month: 2,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        };
        assert_eq!(feb_leap.days_in_month(), 29);
        let feb_normal = DateTime {
            year: 2023,
            month: 2,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        };
        assert_eq!(feb_normal.days_in_month(), 28);
        let jan = DateTime {
            year: 2024,
            month: 1,
            day: 1,
            hour: 0,
            minute: 0,
            second: 0,
        };
        assert_eq!(jan.days_in_month(), 31);
    }

    #[test]
    fn test_date_escape() {
        let ts = 1705321845;
        assert_eq!(php_date("Y\\-m\\-d", ts), "2024-01-15");
    }

    #[test]
    fn test_microtime() {
        let mt = php_microtime_float();
        assert!(mt > 1700000000.0);
    }

    // ── strtotime tests ─────────────────────────────────────────────────────

    #[test]
    fn test_strtotime_timestamp_literal() {
        assert_eq!(php_strtotime("@1705321845", None), Some(1705321845));
        assert_eq!(php_strtotime("@0", None), Some(0));
    }

    #[test]
    fn test_strtotime_now() {
        let base = 1705321845i64;
        assert_eq!(php_strtotime("now", Some(base)), Some(base));
    }

    #[test]
    fn test_strtotime_today() {
        let base = 1705321845i64; // 2024-01-15 12:30:45
        let result = php_strtotime("today", Some(base)).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 15);
        assert_eq!(dt.hour, 0);
        assert_eq!(dt.minute, 0);
        assert_eq!(dt.second, 0);
    }

    #[test]
    fn test_strtotime_yesterday() {
        let base = 1705321845i64; // 2024-01-15 12:30:45
        let result = php_strtotime("yesterday", Some(base)).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 14);
        assert_eq!(dt.hour, 0);
    }

    #[test]
    fn test_strtotime_tomorrow() {
        let base = 1705321845i64; // 2024-01-15 12:30:45
        let result = php_strtotime("tomorrow", Some(base)).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 16);
        assert_eq!(dt.hour, 0);
    }

    #[test]
    fn test_strtotime_iso_date() {
        let result = php_strtotime("2024-01-15", None).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 15);
    }

    #[test]
    fn test_strtotime_iso_datetime() {
        let result = php_strtotime("2024-01-15 12:30:45", None).unwrap();
        assert_eq!(result, 1705321845);
    }

    #[test]
    fn test_strtotime_iso_datetime_t() {
        let result = php_strtotime("2024-01-15T12:30:45", None).unwrap();
        assert_eq!(result, 1705321845);
    }

    #[test]
    fn test_strtotime_slash_date_ymd() {
        let result = php_strtotime("2024/01/15", None).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 15);
    }

    #[test]
    fn test_strtotime_slash_date_mdy() {
        let result = php_strtotime("01/15/2024", None).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 15);
    }

    #[test]
    fn test_strtotime_dmy_dash() {
        let result = php_strtotime("15-01-2024", None).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 15);
    }

    #[test]
    fn test_strtotime_relative_plus_day() {
        let base = 1705321845i64; // 2024-01-15 12:30:45
        let result = php_strtotime("+1 day", Some(base)).unwrap();
        assert_eq!(result, base + 86400);
    }

    #[test]
    fn test_strtotime_relative_minus_weeks() {
        let base = 1705321845i64;
        let result = php_strtotime("-2 weeks", Some(base)).unwrap();
        assert_eq!(result, base - 2 * 7 * 86400);
    }

    #[test]
    fn test_strtotime_relative_plus_months() {
        let base = 1705321845i64; // 2024-01-15 12:30:45
        let result = php_strtotime("+3 months", Some(base)).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 4);
        assert_eq!(dt.day, 15);
    }

    #[test]
    fn test_strtotime_relative_plus_year() {
        let base = 1705321845i64; // 2024-01-15 12:30:45
        let result = php_strtotime("+1 year", Some(base)).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2025);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 15);
    }

    #[test]
    fn test_strtotime_next_monday() {
        // Base: 2024-01-15 (Monday) => next Monday is 2024-01-22
        let base = 1705321845i64;
        let result = php_strtotime("next Monday", Some(base)).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 22);
        assert_eq!(dt.day_of_week(), 1); // Monday
    }

    #[test]
    fn test_strtotime_last_friday() {
        // Base: 2024-01-15 (Monday) => last Friday is 2024-01-12
        let base = 1705321845i64;
        let result = php_strtotime("last Friday", Some(base)).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 12);
        assert_eq!(dt.day_of_week(), 5); // Friday
    }

    #[test]
    fn test_strtotime_first_day_of_january() {
        let result = php_strtotime("first day of January 2024", None).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 1);
    }

    #[test]
    fn test_strtotime_last_day_of_december() {
        let result = php_strtotime("last day of December 2024", None).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 12);
        assert_eq!(dt.day, 31);
    }

    #[test]
    fn test_strtotime_named_date_mdy() {
        let result = php_strtotime("January 15, 2024", None).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 15);
    }

    #[test]
    fn test_strtotime_named_date_dmy() {
        let result = php_strtotime("15 January 2024", None).unwrap();
        let dt = DateTime::from_timestamp(result);
        assert_eq!(dt.year, 2024);
        assert_eq!(dt.month, 1);
        assert_eq!(dt.day, 15);
    }

    #[test]
    fn test_strtotime_empty() {
        assert_eq!(php_strtotime("", None), None);
    }

    #[test]
    fn test_strtotime_invalid() {
        assert_eq!(php_strtotime("not a date", None), None);
    }

    // ── PhpDateTime tests ───────────────────────────────────────────────────

    #[test]
    fn test_php_datetime_new_with_string() {
        let dt = PhpDateTime::new(Some("2024-01-15 12:30:45"), None).unwrap();
        assert_eq!(dt.timestamp, 1705321845);
    }

    #[test]
    fn test_php_datetime_format() {
        let dt = PhpDateTime {
            timestamp: 1705321845,
            timezone: "UTC".to_string(),
        };
        assert_eq!(dt.format("Y-m-d H:i:s"), "2024-01-15 12:30:45");
    }

    #[test]
    fn test_php_datetime_get_timestamp() {
        let dt = PhpDateTime {
            timestamp: 1705321845,
            timezone: "UTC".to_string(),
        };
        assert_eq!(dt.get_timestamp(), 1705321845);
    }

    #[test]
    fn test_php_datetime_modify() {
        let mut dt = PhpDateTime {
            timestamp: 1705321845,
            timezone: "UTC".to_string(),
        };
        dt.modify("+1 day").unwrap();
        assert_eq!(dt.timestamp, 1705321845 + 86400);
    }

    #[test]
    fn test_php_datetime_set_date() {
        let mut dt = PhpDateTime {
            timestamp: 1705321845, // 2024-01-15 12:30:45
            timezone: "UTC".to_string(),
        };
        dt.set_date(2025, 6, 20);
        let formatted = dt.format("Y-m-d H:i:s");
        assert_eq!(formatted, "2025-06-20 12:30:45");
    }

    #[test]
    fn test_php_datetime_set_time() {
        let mut dt = PhpDateTime {
            timestamp: 1705321845, // 2024-01-15 12:30:45
            timezone: "UTC".to_string(),
        };
        dt.set_time(8, 0, 0);
        let formatted = dt.format("Y-m-d H:i:s");
        assert_eq!(formatted, "2024-01-15 08:00:00");
    }

    #[test]
    fn test_php_datetime_diff() {
        let dt1 = PhpDateTime {
            timestamp: php_mktime(0, 0, 0, 1, 1, 2024),
            timezone: "UTC".to_string(),
        };
        let dt2 = PhpDateTime {
            timestamp: php_mktime(0, 0, 0, 3, 15, 2024),
            timezone: "UTC".to_string(),
        };
        let diff = dt1.diff(&dt2);
        assert_eq!(diff.months, 2);
        assert_eq!(diff.days, 14);
        assert!(!diff.invert);
    }

    #[test]
    fn test_php_datetime_diff_inverted() {
        let dt1 = PhpDateTime {
            timestamp: php_mktime(0, 0, 0, 3, 15, 2024),
            timezone: "UTC".to_string(),
        };
        let dt2 = PhpDateTime {
            timestamp: php_mktime(0, 0, 0, 1, 1, 2024),
            timezone: "UTC".to_string(),
        };
        let diff = dt1.diff(&dt2);
        assert!(diff.invert);
        assert_eq!(diff.months, 2);
        assert_eq!(diff.days, 14);
    }

    #[test]
    fn test_php_datetime_create_from_format() {
        let dt = PhpDateTime::create_from_format("Y-m-d H:i:s", "2024-01-15 12:30:45").unwrap();
        assert_eq!(dt.timestamp, 1705321845);
    }

    #[test]
    fn test_php_datetime_create_from_format_date_only() {
        let dt = PhpDateTime::create_from_format("Y/m/d", "2024/01/15").unwrap();
        let parsed = DateTime::from_timestamp(dt.timestamp);
        assert_eq!(parsed.year, 2024);
        assert_eq!(parsed.month, 1);
        assert_eq!(parsed.day, 15);
    }

    // ── PhpDateTimeImmutable tests ──────────────────────────────────────────

    #[test]
    fn test_php_datetime_immutable_modify() {
        let dt = PhpDateTimeImmutable {
            inner: PhpDateTime {
                timestamp: 1705321845,
                timezone: "UTC".to_string(),
            },
        };
        let dt2 = dt.modify("+1 day").unwrap();
        // Original unchanged
        assert_eq!(dt.get_timestamp(), 1705321845);
        // New instance updated
        assert_eq!(dt2.get_timestamp(), 1705321845 + 86400);
    }

    #[test]
    fn test_php_datetime_immutable_set_date() {
        let dt = PhpDateTimeImmutable {
            inner: PhpDateTime {
                timestamp: 1705321845,
                timezone: "UTC".to_string(),
            },
        };
        let dt2 = dt.set_date(2025, 6, 20);
        // Original unchanged
        assert_eq!(dt.format("Y"), "2024");
        assert_eq!(dt2.format("Y-m-d"), "2025-06-20");
    }

    // ── PhpDateTimeZone tests ───────────────────────────────────────────────

    #[test]
    fn test_timezone_utc() {
        let tz = PhpDateTimeZone::new("UTC").unwrap();
        assert_eq!(tz.get_offset(), 0);
    }

    #[test]
    fn test_timezone_us_eastern() {
        let tz = PhpDateTimeZone::new("US/Eastern").unwrap();
        assert_eq!(tz.get_offset(), -5 * 3600);
    }

    #[test]
    fn test_timezone_asia_kolkata() {
        let tz = PhpDateTimeZone::new("Asia/Kolkata").unwrap();
        assert_eq!(tz.get_offset(), 19800); // 5.5 hours
    }

    #[test]
    fn test_timezone_asia_tokyo() {
        let tz = PhpDateTimeZone::new("Asia/Tokyo").unwrap();
        assert_eq!(tz.get_offset(), 9 * 3600);
    }

    #[test]
    fn test_timezone_unknown() {
        assert!(PhpDateTimeZone::new("Mars/Olympus").is_err());
    }

    #[test]
    fn test_timezone_list_identifiers() {
        let list = PhpDateTimeZone::list_identifiers();
        assert!(list.contains(&"UTC".to_string()));
        assert!(list.contains(&"America/New_York".to_string()));
        assert!(list.contains(&"Asia/Tokyo".to_string()));
        assert!(list.len() >= 20);
    }

    #[test]
    fn test_timezone_case_insensitive() {
        assert!(PhpDateTimeZone::offset_for_name("utc").is_some());
        assert!(PhpDateTimeZone::offset_for_name("UTC").is_some());
    }

    // ── PhpDateInterval tests ───────────────────────────────────────────────

    #[test]
    fn test_date_interval_parse_full() {
        let di = PhpDateInterval::create_from_date_string("P1Y2M3DT4H5M6S").unwrap();
        assert_eq!(di.years, 1);
        assert_eq!(di.months, 2);
        assert_eq!(di.days, 3);
        assert_eq!(di.hours, 4);
        assert_eq!(di.minutes, 5);
        assert_eq!(di.seconds, 6);
    }

    #[test]
    fn test_date_interval_parse_date_only() {
        let di = PhpDateInterval::create_from_date_string("P1Y6M").unwrap();
        assert_eq!(di.years, 1);
        assert_eq!(di.months, 6);
        assert_eq!(di.days, 0);
        assert_eq!(di.hours, 0);
    }

    #[test]
    fn test_date_interval_parse_time_only() {
        let di = PhpDateInterval::create_from_date_string("PT12H30M").unwrap();
        assert_eq!(di.years, 0);
        assert_eq!(di.hours, 12);
        assert_eq!(di.minutes, 30);
    }

    #[test]
    fn test_date_interval_parse_weeks() {
        let di = PhpDateInterval::create_from_date_string("P2W").unwrap();
        assert_eq!(di.days, 14);
    }

    #[test]
    fn test_date_interval_invalid_no_p() {
        assert!(PhpDateInterval::create_from_date_string("1Y2M").is_err());
    }

    #[test]
    fn test_date_interval_format() {
        let di = PhpDateInterval {
            years: 1,
            months: 2,
            days: 3,
            hours: 4,
            minutes: 5,
            seconds: 6,
            invert: false,
        };
        assert_eq!(
            di.format("%Y years %M months %D days"),
            "01 years 02 months 03 days"
        );
        assert_eq!(di.format("%R%y years"), "+1 years");
    }

    #[test]
    fn test_date_interval_format_inverted() {
        let di = PhpDateInterval {
            years: 1,
            months: 0,
            days: 0,
            hours: 0,
            minutes: 0,
            seconds: 0,
            invert: true,
        };
        assert_eq!(di.format("%R%y years"), "-1 years");
        assert_eq!(di.format("%r%y years"), "-1 years");
    }

    #[test]
    fn test_date_interval_format_positive_r() {
        let di = PhpDateInterval {
            years: 1,
            months: 0,
            days: 0,
            hours: 0,
            minutes: 0,
            seconds: 0,
            invert: false,
        };
        // %r is empty when positive
        assert_eq!(di.format("%r%y years"), "1 years");
    }

    // ── PhpDatePeriod tests ─────────────────────────────────────────────────

    #[test]
    fn test_date_period_with_recurrences() {
        let start = PhpDateTime {
            timestamp: php_mktime(0, 0, 0, 1, 1, 2024),
            timezone: "UTC".to_string(),
        };
        let interval = PhpDateInterval {
            years: 0,
            months: 1,
            days: 0,
            hours: 0,
            minutes: 0,
            seconds: 0,
            invert: false,
        };
        let period = PhpDatePeriod::new(start, interval, None, Some(3));
        let timestamps = period.timestamps();
        assert_eq!(timestamps.len(), 3);

        let dt0 = DateTime::from_timestamp(timestamps[0]);
        assert_eq!(dt0.month, 1);
        let dt1 = DateTime::from_timestamp(timestamps[1]);
        assert_eq!(dt1.month, 2);
        let dt2 = DateTime::from_timestamp(timestamps[2]);
        assert_eq!(dt2.month, 3);
    }

    #[test]
    fn test_date_period_with_end() {
        let start = PhpDateTime {
            timestamp: php_mktime(0, 0, 0, 1, 1, 2024),
            timezone: "UTC".to_string(),
        };
        let end = PhpDateTime {
            timestamp: php_mktime(0, 0, 0, 4, 1, 2024),
            timezone: "UTC".to_string(),
        };
        let interval = PhpDateInterval {
            years: 0,
            months: 1,
            days: 0,
            hours: 0,
            minutes: 0,
            seconds: 0,
            invert: false,
        };
        let period = PhpDatePeriod::new(start, interval, Some(end), None);
        let timestamps = period.timestamps();
        // Jan, Feb, Mar (Apr is >= end, so excluded)
        assert_eq!(timestamps.len(), 3);
    }

    #[test]
    fn test_date_period_daily() {
        let start = PhpDateTime {
            timestamp: php_mktime(0, 0, 0, 1, 1, 2024),
            timezone: "UTC".to_string(),
        };
        let interval = PhpDateInterval {
            years: 0,
            months: 0,
            days: 1,
            hours: 0,
            minutes: 0,
            seconds: 0,
            invert: false,
        };
        let period = PhpDatePeriod::new(start, interval, None, Some(5));
        let timestamps = period.timestamps();
        assert_eq!(timestamps.len(), 5);
        // Each should be 86400 apart
        for i in 1..timestamps.len() {
            assert_eq!(timestamps[i] - timestamps[i - 1], 86400);
        }
    }
}
