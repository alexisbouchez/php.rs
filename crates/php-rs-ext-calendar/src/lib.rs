//! PHP calendar extension.
//!
//! Implements calendar conversion functions between different calendar systems.
//! Reference: php-src/ext/calendar/

use std::fmt;

/// Calendar type constants.
pub const CAL_GREGORIAN: i32 = 0;
pub const CAL_JULIAN: i32 = 1;
pub const CAL_JEWISH: i32 = 2;
pub const CAL_FRENCH: i32 = 3;

/// Day-of-week mode constants for jddayofweek().
pub const CAL_DOW_DAYNO: i32 = 0;
pub const CAL_DOW_SHORT: i32 = 1;
pub const CAL_DOW_LONG: i32 = 2;

/// Month name mode constants for jdmonthname().
pub const CAL_MONTH_GREGORIAN_SHORT: i32 = 0;
pub const CAL_MONTH_GREGORIAN_LONG: i32 = 1;
pub const CAL_MONTH_JULIAN_SHORT: i32 = 2;
pub const CAL_MONTH_JULIAN_LONG: i32 = 3;
pub const CAL_MONTH_JEWISH: i32 = 4;
pub const CAL_MONTH_FRENCH: i32 = 5;

/// Easter calculation method constants.
pub const CAL_EASTER_DEFAULT: i32 = 0;
pub const CAL_EASTER_ROMAN: i32 = 1;
pub const CAL_EASTER_ALWAYS_GREGORIAN: i32 = 2;
pub const CAL_EASTER_ALWAYS_JULIAN: i32 = 3;

/// Error type for calendar operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarError {
    /// Invalid calendar type.
    InvalidCalendar(i32),
    /// Invalid date.
    InvalidDate,
    /// Invalid Julian day.
    InvalidJulianDay,
}

impl fmt::Display for CalendarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CalendarError::InvalidCalendar(c) => write!(f, "Invalid calendar: {}", c),
            CalendarError::InvalidDate => write!(f, "Invalid date"),
            CalendarError::InvalidJulianDay => write!(f, "Invalid Julian day"),
        }
    }
}

/// Information about a calendar date, returned by cal_from_jd().
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarInfo {
    /// Day of the month.
    pub day: i32,
    /// Month number (1-12).
    pub month: i32,
    /// Year.
    pub year: i32,
    /// Day of the week (0=Sunday, 6=Saturday).
    pub dow: i32,
    /// Abbreviated month name.
    pub abbrevmonth: String,
    /// Full month name.
    pub monthname: String,
    /// Abbreviated day name.
    pub abbrevdayname: String,
    /// Full day name.
    pub dayname: String,
}

/// Details about a calendar system, returned by cal_info().
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarDetails {
    /// Calendar name.
    pub calname: String,
    /// Calendar symbol.
    pub calsymbol: String,
    /// Number of months.
    pub months: i32,
    /// Maximum days in a month.
    pub maxdaysinmonth: i32,
    /// Short month names.
    pub short_months: Vec<String>,
    /// Long month names.
    pub long_months: Vec<String>,
}

/// Short names for Gregorian/Julian months.
const GREGORIAN_MONTHS_SHORT: [&str; 13] = [
    "", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Long names for Gregorian/Julian months.
const GREGORIAN_MONTHS_LONG: [&str; 13] = [
    "",
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// Day of week names.
const DAY_NAMES_SHORT: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const DAY_NAMES_LONG: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

/// French Republican month names.
const FRENCH_MONTHS: [&str; 14] = [
    "",
    "Vendemiaire",
    "Brumaire",
    "Frimaire",
    "Nivose",
    "Pluviose",
    "Ventose",
    "Germinal",
    "Floreal",
    "Prairial",
    "Messidor",
    "Thermidor",
    "Fructidor",
    "Extra",
];

/// Jewish month names.
const JEWISH_MONTHS: [&str; 14] = [
    "", "Tishri", "Heshvan", "Kislev", "Tevet", "Shevat", "Adar I", "Adar II", "Nisan", "Iyyar",
    "Sivan", "Tammuz", "Av", "Elul",
];

/// cal_days_in_month -- Return the number of days in a month for a given year and calendar.
pub fn cal_days_in_month(calendar: i32, month: i32, year: i32) -> Result<i32, CalendarError> {
    match calendar {
        CAL_GREGORIAN => {
            if !(1..=12).contains(&month) || year == 0 {
                return Err(CalendarError::InvalidDate);
            }
            Ok(gregorian_days_in_month(month, year))
        }
        CAL_JULIAN => {
            if !(1..=12).contains(&month) || year == 0 {
                return Err(CalendarError::InvalidDate);
            }
            Ok(julian_days_in_month(month, year))
        }
        _ => Err(CalendarError::InvalidCalendar(calendar)),
    }
}

/// Return days in a Gregorian month.
fn gregorian_days_in_month(month: i32, year: i32) -> i32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_gregorian_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Return days in a Julian month.
fn julian_days_in_month(month: i32, year: i32) -> i32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_julian_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Check if a year is a Gregorian leap year.
fn is_gregorian_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Check if a year is a Julian leap year.
fn is_julian_leap_year(year: i32) -> bool {
    year % 4 == 0
}

/// gregoriantojd -- Converts a Gregorian date to Julian Day Count.
///
/// The algorithm is from the US Naval Observatory.
pub fn gregoriantojd(month: i32, day: i32, year: i32) -> i64 {
    if year == 0 {
        return 0;
    }

    // Algorithm from Meeus, "Astronomical Algorithms"
    let (y, m) = if month <= 2 {
        (year as i64 - 1, month as i64 + 12)
    } else {
        (year as i64, month as i64)
    };

    let a = y / 100;
    let b = 2 - a + a / 4;

    (365.25 * (y + 4716) as f64) as i64 + (30.6001 * (m + 1) as f64) as i64 + day as i64 + b - 1524
}

/// jdtogregorian -- Converts Julian Day Count to Gregorian date.
///
/// Returns (month, day, year).
pub fn jdtogregorian(jd: i64) -> (i32, i32, i32) {
    if jd <= 0 {
        return (0, 0, 0);
    }

    let a = jd + 32044;
    let b = (4 * a + 3) / 146097;
    let c = a - (146097 * b) / 4;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;

    let day = (e - (153 * m + 2) / 5 + 1) as i32;
    let month = (m + 3 - 12 * (m / 10)) as i32;
    let year = (100 * b + d - 4800 + m / 10) as i32;

    (month, day, year)
}

/// juliantojd -- Converts a Julian date to Julian Day Count.
pub fn juliantojd(month: i32, day: i32, year: i32) -> i64 {
    if year == 0 {
        return 0;
    }

    let (y, m) = if month <= 2 {
        (year as i64 - 1, month as i64 + 12)
    } else {
        (year as i64, month as i64)
    };

    (365.25 * (y + 4716) as f64) as i64 + (30.6001 * (m + 1) as f64) as i64 + day as i64 - 1524
}

/// jdtojulian -- Converts Julian Day Count to Julian date.
///
/// Returns (month, day, year).
pub fn jdtojulian(jd: i64) -> (i32, i32, i32) {
    if jd <= 0 {
        return (0, 0, 0);
    }

    let b = 0i64;
    let c = jd + 32082;
    let d = (4 * c + 3) / 1461;
    let e = c - (1461 * d) / 4;
    let m = (5 * e + 2) / 153;

    let day = (e - (153 * m + 2) / 5 + 1) as i32;
    let month = (m + 3 - 12 * (m / 10)) as i32;
    let year = (d + b / 100 - b / 400 - 4800 + m / 10) as i32;

    (month, day, year)
}

/// cal_to_jd -- Converts from a supported calendar to Julian Day Count.
pub fn cal_to_jd(calendar: i32, month: i32, day: i32, year: i32) -> Result<i64, CalendarError> {
    match calendar {
        CAL_GREGORIAN => Ok(gregoriantojd(month, day, year)),
        CAL_JULIAN => Ok(juliantojd(month, day, year)),
        _ => Err(CalendarError::InvalidCalendar(calendar)),
    }
}

/// cal_from_jd -- Converts from Julian Day Count to a supported calendar.
pub fn cal_from_jd(jd: i64, calendar: i32) -> Result<CalendarInfo, CalendarError> {
    let (month, day, year) = match calendar {
        CAL_GREGORIAN => jdtogregorian(jd),
        CAL_JULIAN => jdtojulian(jd),
        _ => return Err(CalendarError::InvalidCalendar(calendar)),
    };

    let dow = ((jd + 1) % 7) as i32;
    let dow = if dow < 0 { dow + 7 } else { dow };

    let monthname = if (1..=12).contains(&month) {
        GREGORIAN_MONTHS_LONG[month as usize].to_string()
    } else {
        String::new()
    };
    let abbrevmonth = if (1..=12).contains(&month) {
        GREGORIAN_MONTHS_SHORT[month as usize].to_string()
    } else {
        String::new()
    };

    let dayname = DAY_NAMES_LONG[dow as usize].to_string();
    let abbrevdayname = DAY_NAMES_SHORT[dow as usize].to_string();

    Ok(CalendarInfo {
        day,
        month,
        year,
        dow,
        abbrevmonth,
        monthname,
        abbrevdayname,
        dayname,
    })
}

/// cal_info -- Returns information about a particular calendar.
pub fn cal_info(calendar: i32) -> Result<CalendarDetails, CalendarError> {
    match calendar {
        CAL_GREGORIAN => Ok(CalendarDetails {
            calname: "Gregorian".to_string(),
            calsymbol: "CAL_GREGORIAN".to_string(),
            months: 12,
            maxdaysinmonth: 31,
            short_months: GREGORIAN_MONTHS_SHORT
                .iter()
                .map(|s| s.to_string())
                .collect(),
            long_months: GREGORIAN_MONTHS_LONG
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }),
        CAL_JULIAN => Ok(CalendarDetails {
            calname: "Julian".to_string(),
            calsymbol: "CAL_JULIAN".to_string(),
            months: 12,
            maxdaysinmonth: 31,
            short_months: GREGORIAN_MONTHS_SHORT
                .iter()
                .map(|s| s.to_string())
                .collect(),
            long_months: GREGORIAN_MONTHS_LONG
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }),
        CAL_JEWISH => Ok(CalendarDetails {
            calname: "Jewish".to_string(),
            calsymbol: "CAL_JEWISH".to_string(),
            months: 13,
            maxdaysinmonth: 30,
            short_months: JEWISH_MONTHS.iter().map(|s| s.to_string()).collect(),
            long_months: JEWISH_MONTHS.iter().map(|s| s.to_string()).collect(),
        }),
        CAL_FRENCH => Ok(CalendarDetails {
            calname: "French".to_string(),
            calsymbol: "CAL_FRENCH".to_string(),
            months: 13,
            maxdaysinmonth: 30,
            short_months: FRENCH_MONTHS.iter().map(|s| s.to_string()).collect(),
            long_months: FRENCH_MONTHS.iter().map(|s| s.to_string()).collect(),
        }),
        _ => Err(CalendarError::InvalidCalendar(calendar)),
    }
}

/// easter_days -- Get the number of days after March 21 on which Easter falls for a given year.
///
/// Uses the Anonymous Gregorian algorithm by default.
pub fn easter_days(year: i32, method: i32) -> i32 {
    if method == CAL_EASTER_ALWAYS_JULIAN {
        return easter_days_julian(year);
    }

    // Anonymous Gregorian algorithm (Meeus/Jones/Butcher)
    let a = year % 19;
    let b = year / 100;
    let c = year % 100;
    let d = b / 4;
    let e = b % 4;
    let f = (b + 8) / 25;
    let g = (b - f + 1) / 3;
    let h = (19 * a + b - d - g + 15) % 30;
    let i = c / 4;
    let k = c % 4;
    let l = (32 + 2 * e + 2 * i - h - k) % 7;
    let m = (a + 11 * h + 22 * l) / 451;
    let month = (h + l - 7 * m + 114) / 31;
    let day = (h + l - 7 * m + 114) % 31 + 1;

    // Days after March 21
    if month == 3 {
        day - 21
    } else {
        // April
        day + 10
    }
}

/// Easter days for Julian calendar.
fn easter_days_julian(year: i32) -> i32 {
    let a = year % 4;
    let b = year % 7;
    let c = year % 19;
    let d = (19 * c + 15) % 30;
    let e = (2 * a + 4 * b - d + 34) % 7;
    let month = (d + e + 114) / 31;
    let day = (d + e + 114) % 31 + 1;

    if month == 3 {
        day - 21
    } else {
        day + 10
    }
}

/// easter_date -- Get Unix timestamp for midnight on Easter of a given year.
///
/// Returns the Unix timestamp for Easter Sunday at midnight UTC.
pub fn easter_date(year: i32) -> i64 {
    let days = easter_days(year, CAL_EASTER_DEFAULT);
    // March 21 of the given year as Julian Day
    let march21_jd = gregoriantojd(3, 21, year);
    let easter_jd = march21_jd + days as i64;
    jdtounix(easter_jd)
}

/// jdtounix -- Convert Julian Day to Unix timestamp.
///
/// Returns the Unix timestamp corresponding to midnight UTC on the given Julian Day.
pub fn jdtounix(jd: i64) -> i64 {
    // Unix epoch (1970-01-01) = JD 2440588
    (jd - 2440588) * 86400
}

/// unixtojd -- Convert Unix timestamp to Julian Day.
///
/// Returns the Julian Day for the given Unix timestamp.
pub fn unixtojd(timestamp: i64) -> i64 {
    // Unix epoch (1970-01-01) = JD 2440588
    timestamp / 86400 + 2440588
}

/// jddayofweek -- Returns the day of the week.
///
/// In mode 0, returns the day number (0=Sunday ... 6=Saturday).
/// In mode 1, returns the abbreviated day name as a string.
/// In mode 2, returns the full day name as a string.
pub fn jddayofweek(jd: i64, mode: i32) -> DayOfWeekResult {
    let dow = ((jd + 1) % 7) as usize;
    let dow = if dow > 6 { 0 } else { dow };

    match mode {
        CAL_DOW_DAYNO => DayOfWeekResult::Number(dow as i32),
        CAL_DOW_SHORT => DayOfWeekResult::Name(DAY_NAMES_SHORT[dow].to_string()),
        CAL_DOW_LONG => DayOfWeekResult::Name(DAY_NAMES_LONG[dow].to_string()),
        _ => DayOfWeekResult::Number(dow as i32),
    }
}

/// Result type for jddayofweek which can return either a number or a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DayOfWeekResult {
    /// Day number (0=Sunday, 6=Saturday).
    Number(i32),
    /// Day name.
    Name(String),
}

/// jdmonthname -- Returns the name of a month.
///
/// The mode determines which calendar's month names to use.
pub fn jdmonthname(jd: i64, mode: i32) -> String {
    let month = match mode {
        CAL_MONTH_GREGORIAN_SHORT | CAL_MONTH_GREGORIAN_LONG => {
            let (m, _, _) = jdtogregorian(jd);
            m
        }
        CAL_MONTH_JULIAN_SHORT | CAL_MONTH_JULIAN_LONG => {
            let (m, _, _) = jdtojulian(jd);
            m
        }
        _ => {
            let (m, _, _) = jdtogregorian(jd);
            m
        }
    };

    if !(1..=12).contains(&month) {
        return String::new();
    }

    match mode {
        CAL_MONTH_GREGORIAN_SHORT | CAL_MONTH_JULIAN_SHORT => {
            GREGORIAN_MONTHS_SHORT[month as usize].to_string()
        }
        CAL_MONTH_GREGORIAN_LONG | CAL_MONTH_JULIAN_LONG => {
            GREGORIAN_MONTHS_LONG[month as usize].to_string()
        }
        CAL_MONTH_FRENCH => {
            if (1..=13).contains(&month) {
                FRENCH_MONTHS[month as usize].to_string()
            } else {
                String::new()
            }
        }
        CAL_MONTH_JEWISH => {
            if (1..=13).contains(&month) {
                JEWISH_MONTHS[month as usize].to_string()
            } else {
                String::new()
            }
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gregoriantojd() {
        // Known conversion: January 1, 2000 = JD 2451545
        assert_eq!(gregoriantojd(1, 1, 2000), 2451545);
        // Unix epoch: January 1, 1970 = JD 2440588
        assert_eq!(gregoriantojd(1, 1, 1970), 2440588);
    }

    #[test]
    fn test_jdtogregorian() {
        let (m, d, y) = jdtogregorian(2451545);
        assert_eq!((m, d, y), (1, 1, 2000));

        let (m, d, y) = jdtogregorian(2440588);
        assert_eq!((m, d, y), (1, 1, 1970));
    }

    #[test]
    fn test_gregorian_roundtrip() {
        // Test roundtrip for various dates
        for &(month, day, year) in &[
            (1, 1, 2000),
            (12, 31, 1999),
            (2, 29, 2000), // leap year
            (7, 4, 1776),
            (6, 15, 2023),
        ] {
            let jd = gregoriantojd(month, day, year);
            let (m, d, y) = jdtogregorian(jd);
            assert_eq!(
                (m, d, y),
                (month, day, year),
                "Roundtrip failed for {}/{}/{}",
                month,
                day,
                year
            );
        }
    }

    #[test]
    fn test_juliantojd_and_back() {
        let jd = juliantojd(1, 1, 2000);
        let (m, d, y) = jdtojulian(jd);
        assert_eq!((m, d, y), (1, 1, 2000));
    }

    #[test]
    fn test_cal_days_in_month() {
        assert_eq!(cal_days_in_month(CAL_GREGORIAN, 1, 2000).unwrap(), 31);
        assert_eq!(cal_days_in_month(CAL_GREGORIAN, 2, 2000).unwrap(), 29); // leap year
        assert_eq!(cal_days_in_month(CAL_GREGORIAN, 2, 2001).unwrap(), 28);
        assert_eq!(cal_days_in_month(CAL_GREGORIAN, 4, 2000).unwrap(), 30);
        assert_eq!(cal_days_in_month(CAL_GREGORIAN, 2, 1900).unwrap(), 28); // not leap (divisible by 100)
        assert_eq!(cal_days_in_month(CAL_GREGORIAN, 2, 2400).unwrap(), 29); // leap (divisible by 400)
    }

    #[test]
    fn test_cal_days_in_month_julian() {
        // Julian calendar: every 4th year is leap, no 100/400 exception
        assert_eq!(cal_days_in_month(CAL_JULIAN, 2, 1900).unwrap(), 29); // leap in Julian
        assert_eq!(cal_days_in_month(CAL_JULIAN, 2, 2001).unwrap(), 28);
    }

    #[test]
    fn test_cal_days_invalid() {
        assert!(cal_days_in_month(CAL_GREGORIAN, 13, 2000).is_err());
        assert!(cal_days_in_month(CAL_GREGORIAN, 0, 2000).is_err());
        assert!(cal_days_in_month(5, 1, 2000).is_err()); // Invalid calendar
    }

    #[test]
    fn test_jdtounix_unixtojd() {
        // Unix epoch
        assert_eq!(jdtounix(2440588), 0);
        assert_eq!(unixtojd(0), 2440588);

        // Roundtrip
        let ts = 1000000;
        let jd = unixtojd(ts);
        // jdtounix returns midnight, so we check the day matches
        let back = jdtounix(jd);
        assert!(back <= ts);
        assert!(ts - back < 86400);
    }

    #[test]
    fn test_easter_days() {
        // Easter 2000: April 23 = 33 days after March 21
        assert_eq!(easter_days(2000, CAL_EASTER_DEFAULT), 33);
        // Easter 2023: April 9 = 19 days after March 21
        assert_eq!(easter_days(2023, CAL_EASTER_DEFAULT), 19);
        // Easter 2024: March 31 = 10 days after March 21
        assert_eq!(easter_days(2024, CAL_EASTER_DEFAULT), 10);
    }

    #[test]
    fn test_cal_from_jd() {
        let info = cal_from_jd(2451545, CAL_GREGORIAN).unwrap();
        assert_eq!(info.month, 1);
        assert_eq!(info.day, 1);
        assert_eq!(info.year, 2000);
        assert_eq!(info.monthname, "January");
        assert_eq!(info.dayname, "Saturday");
    }

    #[test]
    fn test_cal_to_jd() {
        let jd = cal_to_jd(CAL_GREGORIAN, 1, 1, 2000).unwrap();
        assert_eq!(jd, 2451545);
    }

    #[test]
    fn test_cal_info() {
        let info = cal_info(CAL_GREGORIAN).unwrap();
        assert_eq!(info.calname, "Gregorian");
        assert_eq!(info.months, 12);
        assert_eq!(info.maxdaysinmonth, 31);

        let info = cal_info(CAL_JULIAN).unwrap();
        assert_eq!(info.calname, "Julian");
    }

    #[test]
    fn test_jddayofweek() {
        // Jan 1, 2000 (JD 2451545) was a Saturday
        assert_eq!(
            jddayofweek(2451545, CAL_DOW_DAYNO),
            DayOfWeekResult::Number(6)
        );
        assert_eq!(
            jddayofweek(2451545, CAL_DOW_LONG),
            DayOfWeekResult::Name("Saturday".to_string())
        );
        assert_eq!(
            jddayofweek(2451545, CAL_DOW_SHORT),
            DayOfWeekResult::Name("Sat".to_string())
        );
    }

    #[test]
    fn test_jdmonthname() {
        // Jan 1, 2000
        assert_eq!(jdmonthname(2451545, CAL_MONTH_GREGORIAN_LONG), "January");
        assert_eq!(jdmonthname(2451545, CAL_MONTH_GREGORIAN_SHORT), "Jan");
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_gregorian_leap_year(2000));
        assert!(!is_gregorian_leap_year(1900));
        assert!(is_gregorian_leap_year(2004));
        assert!(!is_gregorian_leap_year(2001));
        assert!(is_gregorian_leap_year(2400));

        // Julian: every 4th year
        assert!(is_julian_leap_year(1900));
        assert!(is_julian_leap_year(2000));
        assert!(!is_julian_leap_year(2001));
    }
}
