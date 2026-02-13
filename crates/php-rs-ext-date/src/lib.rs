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
        match self.month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => {
                if self.is_leap_year() {
                    29
                } else {
                    28
                }
            }
            _ => 30,
        }
    }

    /// Is this a leap year?
    pub fn is_leap_year(&self) -> bool {
        (self.year % 4 == 0 && self.year % 100 != 0) || self.year % 400 == 0
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
}
