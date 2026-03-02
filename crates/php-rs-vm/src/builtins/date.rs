//! Date/time built-in functions.

use crate::value::{PhpArray, PhpObject, Value};
use crate::vm::{Vm, VmResult};
use php_rs_compiler::op::OperandType;

use super::BuiltinRegistry;

pub(crate) fn register(r: &mut BuiltinRegistry) {
    r.insert("date", php_date);
    r.insert("gmdate", php_gmdate);
    r.insert("mktime", php_mktime);
    r.insert("gmmktime", php_gmmktime);
    r.insert("strtotime", php_strtotime);
    r.insert("checkdate", php_checkdate);
    r.insert("getdate", php_getdate);
    r.insert("localtime", php_localtime);
    r.insert("idate", php_idate);
    r.insert("date_create", php_date_create);
    r.insert("date_create_immutable", php_date_create_immutable);
    r.insert("date_format", php_date_format_fn);
    r.insert("date_modify", php_date_modify);
    r.insert("date_diff", php_date_diff);
    r.insert("date_date_set", php_date_date_set);
    r.insert("date_time_set", php_date_time_set);
    r.insert("date_timestamp_get", php_date_timestamp_get);
    r.insert("date_timestamp_set", php_date_timestamp_set);
    r.insert("date_timezone_get", php_date_timezone_get);
    r.insert("date_timezone_set", php_date_timezone_set);
    r.insert(
        "date_interval_create_from_date_string",
        php_date_interval_create_from_date_string,
    );
    r.insert("timezone_identifiers_list", php_timezone_identifiers_list);
    r.insert("timezone_open", php_timezone_open);
    r.insert("timezone_name_get", php_timezone_name_get);
    r.insert("timezone_offset_get", php_timezone_offset_get);
    r.insert("strftime", php_strftime);
    r.insert("date_default_timezone_set", php_date_default_timezone_set);
    r.insert("date_default_timezone_get", php_date_default_timezone_get);
}

// ── Helpers ────────────────────────────────────────────────────────────

/// Compute day-of-year (0-based) for a DateTime.
fn day_of_year(year: i64, month: u8, day: u8) -> u32 {
    let days_before_month: [u32; 13] = [0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut yday = days_before_month[month as usize] + day as u32 - 1;
    if month > 2 && is_leap(year) {
        yday += 1;
    }
    yday
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Days in a given month (1-12) for a given year.
fn days_in_month(year: i64, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
        _ => 30,
    }
}

fn arg_to_i64(args: &[Value], idx: usize) -> Option<i64> {
    args.get(idx).map(|v| match v {
        Value::Long(n) => *n,
        Value::Double(f) => *f as i64,
        Value::String(s) => s.parse::<i64>().unwrap_or(0),
        Value::Bool(b) => {
            if *b {
                1
            } else {
                0
            }
        }
        Value::Null => 0,
        _ => 0,
    })
}

fn arg_to_string(args: &[Value], idx: usize) -> Option<String> {
    args.get(idx).map(|v| match v {
        Value::String(s) => s.clone(),
        Value::Long(n) => n.to_string(),
        Value::Double(f) => f.to_string(),
        Value::Bool(b) => {
            if *b {
                "1".to_string()
            } else {
                String::new()
            }
        }
        Value::Null => String::new(),
        _ => String::new(),
    })
}

// ── Built-in function implementations ──────────────────────────────────

/// date(string $format, ?int $timestamp = null): string
pub(crate) fn php_date(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let format = arg_to_string(args, 0).unwrap_or_default();
    let timestamp = arg_to_i64(args, 1).unwrap_or_else(php_rs_ext_date::php_time);
    Ok(Value::String(php_rs_ext_date::php_date(&format, timestamp)))
}

/// gmdate(string $format, ?int $timestamp = null): string
/// For simplicity, delegates to php_date (DateTime is already UTC-based in ext-date).
pub(crate) fn php_gmdate(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let format = arg_to_string(args, 0).unwrap_or_default();
    let timestamp = arg_to_i64(args, 1).unwrap_or_else(php_rs_ext_date::php_time);
    Ok(Value::String(php_rs_ext_date::php_date(&format, timestamp)))
}

/// mktime(int $hour, ?int $minute, ?int $second, ?int $month, ?int $day, ?int $year): int|false
pub(crate) fn php_mktime(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let hour = arg_to_i64(args, 0).unwrap_or(0) as i32;
    let minute = arg_to_i64(args, 1).unwrap_or(0) as i32;
    let second = arg_to_i64(args, 2).unwrap_or(0) as i32;
    let month = arg_to_i64(args, 3).unwrap_or(1) as i32;
    let day = arg_to_i64(args, 4).unwrap_or(1) as i32;
    let year = arg_to_i64(args, 5).unwrap_or(1970) as i32;
    Ok(Value::Long(php_rs_ext_date::php_mktime(
        hour, minute, second, month, day, year,
    )))
}

/// gmmktime — same as mktime for UTC (our ext-date is UTC-based).
pub(crate) fn php_gmmktime(
    vm: &mut Vm,
    args: &[Value],
    ref_args: &[(usize, OperandType, u32)],
    ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    php_mktime(vm, args, ref_args, ref_prop_args)
}

/// strtotime(string $datetime, ?int $baseTimestamp = null): int|false
pub(crate) fn php_strtotime(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let input = arg_to_string(args, 0).unwrap_or_default();
    let base = arg_to_i64(args, 1);
    match php_rs_ext_date::php_strtotime(&input, base) {
        Some(ts) => Ok(Value::Long(ts)),
        None => Ok(Value::Bool(false)),
    }
}

/// checkdate(int $month, int $day, int $year): bool
pub(crate) fn php_checkdate(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let month = arg_to_i64(args, 0).unwrap_or(0);
    let day = arg_to_i64(args, 1).unwrap_or(0);
    let year = arg_to_i64(args, 2).unwrap_or(0);

    if year < 1 || year > 32767 || month < 1 || month > 12 {
        return Ok(Value::Bool(false));
    }

    let max_day = days_in_month(year, month as u8) as i64;
    Ok(Value::Bool(day >= 1 && day <= max_day))
}

/// getdate(?int $timestamp = null): array
pub(crate) fn php_getdate(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let timestamp = arg_to_i64(args, 0).unwrap_or_else(php_rs_ext_date::php_time);
    let dt = php_rs_ext_date::DateTime::from_timestamp(timestamp);

    let mut arr = PhpArray::new();
    arr.set_string("seconds".to_string(), Value::Long(dt.second as i64));
    arr.set_string("minutes".to_string(), Value::Long(dt.minute as i64));
    arr.set_string("hours".to_string(), Value::Long(dt.hour as i64));
    arr.set_string("mday".to_string(), Value::Long(dt.day as i64));
    arr.set_string("wday".to_string(), Value::Long(dt.day_of_week() as i64));
    arr.set_string("mon".to_string(), Value::Long(dt.month as i64));
    arr.set_string("year".to_string(), Value::Long(dt.year));
    arr.set_string(
        "yday".to_string(),
        Value::Long(day_of_year(dt.year, dt.month, dt.day) as i64),
    );
    arr.set_string(
        "weekday".to_string(),
        Value::String(dt.day_name().to_string()),
    );
    arr.set_string(
        "month".to_string(),
        Value::String(dt.month_name().to_string()),
    );
    arr.set_int(0, Value::Long(timestamp));

    Ok(Value::Array(arr))
}

/// localtime(?int $timestamp = null, bool $associative = false): array
pub(crate) fn php_localtime(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let timestamp = arg_to_i64(args, 0).unwrap_or_else(php_rs_ext_date::php_time);
    let associative = match args.get(1) {
        Some(Value::Bool(b)) => *b,
        Some(Value::Long(n)) => *n != 0,
        _ => false,
    };

    let dt = php_rs_ext_date::DateTime::from_timestamp(timestamp);
    let yday = day_of_year(dt.year, dt.month, dt.day) as i64;
    // tm_year is years since 1900, tm_mon is 0-11
    let tm_year = dt.year - 1900;
    let tm_mon = dt.month as i64 - 1;
    let tm_isdst = 0_i64; // No DST support in our UTC-based implementation

    let values: [(&str, i64); 9] = [
        ("tm_sec", dt.second as i64),
        ("tm_min", dt.minute as i64),
        ("tm_hour", dt.hour as i64),
        ("tm_mday", dt.day as i64),
        ("tm_mon", tm_mon),
        ("tm_year", tm_year),
        ("tm_wday", dt.day_of_week() as i64),
        ("tm_yday", yday),
        ("tm_isdst", tm_isdst),
    ];

    let mut arr = PhpArray::new();
    if associative {
        for (key, val) in &values {
            arr.set_string(key.to_string(), Value::Long(*val));
        }
    } else {
        for (_, val) in &values {
            arr.push(Value::Long(*val));
        }
    }

    Ok(Value::Array(arr))
}

/// idate(string $format, ?int $timestamp = null): int
pub(crate) fn php_idate(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let format = arg_to_string(args, 0).unwrap_or_default();
    let timestamp = arg_to_i64(args, 1).unwrap_or_else(php_rs_ext_date::php_time);
    let dt = php_rs_ext_date::DateTime::from_timestamp(timestamp);

    // idate accepts a single format character
    let ch = format.chars().next().unwrap_or('U');
    let result: i64 = match ch {
        'B' => {
            // Swatch Internet Time
            let swatch =
                ((dt.hour as i64 * 3600 + dt.minute as i64 * 60 + dt.second as i64 + 3600) % 86400)
                    * 1000
                    / 86400;
            swatch
        }
        'd' => dt.day as i64,
        'h' => {
            let h = dt.hour % 12;
            if h == 0 {
                12
            } else {
                h as i64
            }
        }
        'H' => dt.hour as i64,
        'i' => dt.minute as i64,
        'I' => 0, // DST flag, always 0 in UTC
        'L' => {
            if is_leap(dt.year) {
                1
            } else {
                0
            }
        }
        'm' => dt.month as i64,
        's' => dt.second as i64,
        't' => dt.days_in_month() as i64,
        'U' => timestamp,
        'w' => dt.day_of_week() as i64,
        'W' => {
            // ISO 8601 week number (approximation)
            let yday = day_of_year(dt.year, dt.month, dt.day) as i64;
            (yday / 7 + 1).min(53)
        }
        'y' => dt.year % 100,
        'Y' => dt.year,
        'z' => day_of_year(dt.year, dt.month, dt.day) as i64,
        'Z' => 0, // Timezone offset in seconds, 0 for UTC
        _ => 0,
    };

    Ok(Value::Long(result))
}

/// date_create(?string $datetime = "now", ?DateTimeZone $timezone = null): DateTime|false
pub(crate) fn php_date_create(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let datetime_str = match args.first() {
        Some(Value::String(s)) if !s.is_empty() => Some(s.as_str()),
        _ => None,
    };

    let tz_string: Option<String> = match args.get(1) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(obj)) => obj.get_property("timezone").and_then(|v| {
            if let Value::String(s) = v {
                Some(s)
            } else {
                None
            }
        }),
        _ => None,
    };
    let tz_ref = tz_string.as_deref();

    match php_rs_ext_date::PhpDateTime::new(datetime_str, tz_ref) {
        Ok(php_dt) => {
            let obj = PhpObject::new("DateTime".to_string());
            obj.set_object_id(vm.next_object_id);
            vm.next_object_id += 1;
            obj.set_property(
                "__timestamp".to_string(),
                Value::Long(php_dt.get_timestamp()),
            );
            obj.set_property(
                "__timezone".to_string(),
                Value::String(php_dt.timezone.clone()),
            );
            Ok(Value::Object(obj))
        }
        Err(_) => Ok(Value::Bool(false)),
    }
}

/// strftime(string $format, ?int $timestamp = null): string|false
/// Converts common strftime specifiers to PHP date() format chars.
pub(crate) fn php_strftime(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let format = arg_to_string(args, 0).unwrap_or_default();
    let timestamp = arg_to_i64(args, 1).unwrap_or_else(php_rs_ext_date::php_time);

    // Convert strftime format specifiers to PHP date() format chars
    let mut date_format = String::with_capacity(format.len());
    let mut chars = format.chars();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            match chars.next() {
                Some('Y') => date_format.push('Y'),
                Some('m') => date_format.push('m'),
                Some('d') => date_format.push('d'),
                Some('H') => date_format.push('H'),
                Some('M') => date_format.push('i'),
                Some('S') => date_format.push('s'),
                Some('A') => date_format.push('l'), // Full weekday name
                Some('B') => date_format.push('F'), // Full month name
                Some('a') => date_format.push('D'), // Abbreviated weekday name
                Some('b') | Some('h') => date_format.push('M'), // Abbreviated month name
                Some('e') => date_format.push('j'), // Day of month without leading zero
                Some('p') => date_format.push('A'), // AM/PM
                Some('P') => date_format.push('a'), // am/pm
                Some('Z') => date_format.push('T'), // Timezone abbreviation
                Some('y') => date_format.push('y'), // 2-digit year
                Some('j') => {
                    // Day of year (001-366) — format with leading zeros
                    let dt = php_rs_ext_date::DateTime::from_timestamp(timestamp);
                    let yday = day_of_year(dt.year, dt.month, dt.day);
                    date_format.push_str(&format!("{:03}", yday + 1));
                    continue;
                }
                Some('n') => date_format.push('\n'),
                Some('t') => date_format.push('\t'),
                Some('%') => date_format.push('%'),
                Some('I') => date_format.push('H'), // Hour 00-12 with leading zero (approx)
                Some('l') | Some('k') => date_format.push('G'), // Hour 0-23 without leading zero
                Some('u') => date_format.push('w'), // Day of week (1=Monday in strftime, approx)
                Some('w') => date_format.push('w'), // Day of week (0=Sunday)
                Some('s') => {
                    // Seconds since epoch
                    date_format.push('U');
                }
                Some('c') | Some('x') => {
                    // Locale date representation — use ISO-like Y-m-d
                    date_format.push_str("Y-m-d");
                }
                Some('X') | Some('T') => {
                    // Locale time representation — use H:i:s
                    date_format.push_str("H:i:s");
                }
                Some('R') => {
                    // 24-hour time HH:MM
                    date_format.push_str("H:i");
                }
                Some('r') => {
                    // Locale 12-hour time
                    date_format.push_str("h:i:s A");
                }
                Some('D') | Some('F') => {
                    // Full date: equivalent to %m/%d/%y or Y-m-d
                    date_format.push_str("m/d/y");
                }
                Some(other) => {
                    // Unknown specifier — pass through
                    date_format.push('%');
                    date_format.push(other);
                }
                None => {
                    date_format.push('%');
                }
            }
        } else {
            // For literal chars in strftime, we need to escape them so php_date
            // doesn't interpret them as format chars.
            if "dDjlNSwzWFmMntLoYyaABgGhHisuveIOPpTZcrU".contains(ch) {
                date_format.push('\\');
            }
            date_format.push(ch);
        }
    }

    Ok(Value::String(php_rs_ext_date::php_date(
        &date_format,
        timestamp,
    )))
}

/// date_create_immutable(?string $datetime = "now", ?DateTimeZone $timezone = null): DateTimeImmutable|false
pub(crate) fn php_date_create_immutable(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let datetime_str = match args.first() {
        Some(Value::String(s)) if !s.is_empty() => Some(s.as_str()),
        _ => None,
    };
    let tz_string: Option<String> = match args.get(1) {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Object(obj)) => obj.get_property("__tz_name").map(|v| v.to_php_string()),
        _ => None,
    };

    match php_rs_ext_date::PhpDateTime::new(datetime_str, tz_string.as_deref()) {
        Ok(php_dt) => {
            let obj = PhpObject::new("DateTimeImmutable".to_string());
            obj.set_object_id(vm.next_object_id);
            vm.next_object_id += 1;
            obj.set_property(
                "__timestamp".to_string(),
                Value::Long(php_dt.get_timestamp()),
            );
            obj.set_property(
                "__timezone".to_string(),
                Value::String(php_dt.timezone.clone()),
            );
            Ok(Value::Object(obj))
        }
        Err(_) => Ok(Value::Bool(false)),
    }
}

/// date_format(DateTimeInterface $object, string $format): string
pub(crate) fn php_date_format_fn(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let ts = match args.first() {
        Some(Value::Object(ref obj)) => obj
            .get_property("__timestamp")
            .map(|v| v.to_long())
            .unwrap_or_else(php_rs_ext_date::php_time),
        _ => php_rs_ext_date::php_time(),
    };
    let format = arg_to_string(args, 1).unwrap_or_else(|| "Y-m-d H:i:s".to_string());
    Ok(Value::String(php_rs_ext_date::php_date(&format, ts)))
}

/// date_modify(DateTime $object, string $modifier): DateTime|false
pub(crate) fn php_date_modify(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if let Some(Value::Object(ref obj)) = args.first() {
        let ts = obj
            .get_property("__timestamp")
            .map(|v| v.to_long())
            .unwrap_or_else(php_rs_ext_date::php_time);
        let modifier = arg_to_string(args, 1).unwrap_or_default();
        match php_rs_ext_date::php_strtotime(&modifier, Some(ts)) {
            Some(new_ts) => {
                obj.set_property("__timestamp".to_string(), Value::Long(new_ts));
                Ok(args.first().cloned().unwrap_or(Value::Bool(false)))
            }
            None => Ok(Value::Bool(false)),
        }
    } else {
        Ok(Value::Bool(false))
    }
}

/// date_diff(DateTimeInterface $baseObject, DateTimeInterface $targetObject, bool $absolute = false): DateInterval
pub(crate) fn php_date_diff(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let ts1 = match args.first() {
        Some(Value::Object(ref obj)) => obj
            .get_property("__timestamp")
            .map(|v| v.to_long())
            .unwrap_or(0),
        _ => 0,
    };
    let ts2 = match args.get(1) {
        Some(Value::Object(ref obj)) => obj
            .get_property("__timestamp")
            .map(|v| v.to_long())
            .unwrap_or(0),
        _ => 0,
    };
    let dt1 = php_rs_ext_date::PhpDateTime {
        timestamp: ts1,
        timezone: "UTC".to_string(),
    };
    let dt2 = php_rs_ext_date::PhpDateTime {
        timestamp: ts2,
        timezone: "UTC".to_string(),
    };
    let di = dt1.diff(&dt2);

    let interval = PhpObject::new("DateInterval".to_string());
    interval.set_object_id(vm.next_object_id);
    vm.next_object_id += 1;
    interval.set_property("y".to_string(), Value::Long(di.years as i64));
    interval.set_property("m".to_string(), Value::Long(di.months as i64));
    interval.set_property("d".to_string(), Value::Long(di.days as i64));
    interval.set_property("h".to_string(), Value::Long(di.hours as i64));
    interval.set_property("i".to_string(), Value::Long(di.minutes as i64));
    interval.set_property("s".to_string(), Value::Long(di.seconds as i64));
    interval.set_property(
        "invert".to_string(),
        Value::Long(if di.invert { 1 } else { 0 }),
    );
    let total_days = ((ts1 - ts2).abs()) / 86400;
    interval.set_property("days".to_string(), Value::Long(total_days));
    Ok(Value::Object(interval))
}

/// date_date_set(DateTime $object, int $year, int $month, int $day): DateTime
pub(crate) fn php_date_date_set(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if let Some(Value::Object(ref obj)) = args.first() {
        let ts = obj
            .get_property("__timestamp")
            .map(|v| v.to_long())
            .unwrap_or(0);
        let year = arg_to_i64(args, 1).unwrap_or(1970) as i32;
        let month = arg_to_i64(args, 2).unwrap_or(1) as i32;
        let day = arg_to_i64(args, 3).unwrap_or(1) as i32;
        let mut php_dt = php_rs_ext_date::PhpDateTime {
            timestamp: ts,
            timezone: "UTC".to_string(),
        };
        php_dt.set_date(year, month, day);
        obj.set_property("__timestamp".to_string(), Value::Long(php_dt.timestamp));
        Ok(args.first().cloned().unwrap_or(Value::Bool(false)))
    } else {
        Ok(Value::Bool(false))
    }
}

/// date_time_set(DateTime $object, int $hour, int $minute, int $second = 0): DateTime
pub(crate) fn php_date_time_set(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if let Some(Value::Object(ref obj)) = args.first() {
        let ts = obj
            .get_property("__timestamp")
            .map(|v| v.to_long())
            .unwrap_or(0);
        let hour = arg_to_i64(args, 1).unwrap_or(0) as i32;
        let minute = arg_to_i64(args, 2).unwrap_or(0) as i32;
        let second = arg_to_i64(args, 3).unwrap_or(0) as i32;
        let mut php_dt = php_rs_ext_date::PhpDateTime {
            timestamp: ts,
            timezone: "UTC".to_string(),
        };
        php_dt.set_time(hour, minute, second);
        obj.set_property("__timestamp".to_string(), Value::Long(php_dt.timestamp));
        Ok(args.first().cloned().unwrap_or(Value::Bool(false)))
    } else {
        Ok(Value::Bool(false))
    }
}

/// date_timestamp_get(DateTimeInterface $object): int
pub(crate) fn php_date_timestamp_get(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    match args.first() {
        Some(Value::Object(ref obj)) => {
            let ts = obj
                .get_property("__timestamp")
                .map(|v| v.to_long())
                .unwrap_or_else(php_rs_ext_date::php_time);
            Ok(Value::Long(ts))
        }
        _ => Ok(Value::Bool(false)),
    }
}

/// date_timestamp_set(DateTime $object, int $timestamp): DateTime
pub(crate) fn php_date_timestamp_set(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if let Some(Value::Object(ref obj)) = args.first() {
        let ts = arg_to_i64(args, 1).unwrap_or(0);
        obj.set_property("__timestamp".to_string(), Value::Long(ts));
        Ok(args.first().cloned().unwrap_or(Value::Bool(false)))
    } else {
        Ok(Value::Bool(false))
    }
}

/// date_timezone_get(DateTimeInterface $object): DateTimeZone|false
pub(crate) fn php_date_timezone_get(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    match args.first() {
        Some(Value::Object(ref obj)) => {
            let tz_name = obj
                .get_property("__timezone")
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "UTC".to_string());
            let tz_obj = PhpObject::new("DateTimeZone".to_string());
            tz_obj.set_object_id(vm.next_object_id);
            vm.next_object_id += 1;
            let offset = php_rs_ext_date::PhpDateTimeZone::offset_for_name(&tz_name).unwrap_or(0);
            tz_obj.set_property("__tz_name".to_string(), Value::String(tz_name));
            tz_obj.set_property("__tz_offset".to_string(), Value::Long(offset as i64));
            Ok(Value::Object(tz_obj))
        }
        _ => Ok(Value::Bool(false)),
    }
}

/// date_timezone_set(DateTime $object, DateTimeZone $timezone): DateTime
pub(crate) fn php_date_timezone_set(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    if let Some(Value::Object(ref obj)) = args.first() {
        let tz_name = match args.get(1) {
            Some(Value::Object(ref tz_obj)) => tz_obj
                .get_property("__tz_name")
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "UTC".to_string()),
            _ => "UTC".to_string(),
        };
        obj.set_property("__timezone".to_string(), Value::String(tz_name));
        Ok(args.first().cloned().unwrap_or(Value::Bool(false)))
    } else {
        Ok(Value::Bool(false))
    }
}

/// date_interval_create_from_date_string(string $datetime): DateInterval|false
pub(crate) fn php_date_interval_create_from_date_string(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let spec = arg_to_string(args, 0).unwrap_or_default();
    // Try relative string first ("1 day", "2 months"), then ISO 8601
    let di_result = if spec.starts_with('P') || spec.starts_with('p') {
        php_rs_ext_date::PhpDateInterval::create_from_date_string(&spec)
    } else {
        parse_relative_interval(&spec)
    };
    match di_result {
        Ok(di) => {
            let interval = PhpObject::new("DateInterval".to_string());
            interval.set_object_id(vm.next_object_id);
            vm.next_object_id += 1;
            interval.set_property("y".to_string(), Value::Long(di.years as i64));
            interval.set_property("m".to_string(), Value::Long(di.months as i64));
            interval.set_property("d".to_string(), Value::Long(di.days as i64));
            interval.set_property("h".to_string(), Value::Long(di.hours as i64));
            interval.set_property("i".to_string(), Value::Long(di.minutes as i64));
            interval.set_property("s".to_string(), Value::Long(di.seconds as i64));
            interval.set_property(
                "invert".to_string(),
                Value::Long(if di.invert { 1 } else { 0 }),
            );
            interval.set_property(
                "days".to_string(),
                Value::Long((di.years as i64 * 365) + (di.months as i64 * 30) + di.days as i64),
            );
            Ok(Value::Object(interval))
        }
        Err(_) => Ok(Value::Bool(false)),
    }
}

fn parse_relative_interval(spec: &str) -> Result<php_rs_ext_date::PhpDateInterval, String> {
    let spec = spec.trim().to_ascii_lowercase();
    let parts: Vec<&str> = spec.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid interval: {}", spec));
    }
    let n: i32 = parts[0]
        .parse()
        .map_err(|_| format!("Invalid number: {}", parts[0]))?;
    let mut di = php_rs_ext_date::PhpDateInterval {
        years: 0,
        months: 0,
        days: 0,
        hours: 0,
        minutes: 0,
        seconds: 0,
        invert: false,
    };
    match parts[1].trim() {
        "year" | "years" => di.years = n,
        "month" | "months" => di.months = n,
        "week" | "weeks" => di.days = n * 7,
        "day" | "days" => di.days = n,
        "hour" | "hours" => di.hours = n,
        "minute" | "minutes" | "min" | "mins" => di.minutes = n,
        "second" | "seconds" | "sec" | "secs" => di.seconds = n,
        _ => return Err(format!("Unknown unit: {}", parts[1])),
    }
    Ok(di)
}

/// timezone_identifiers_list(): array
pub(crate) fn php_timezone_identifiers_list(
    _vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let ids = php_rs_ext_date::PhpDateTimeZone::list_identifiers();
    let mut arr = PhpArray::new();
    for id in ids {
        arr.push(Value::String(id));
    }
    Ok(Value::Array(arr))
}

/// timezone_open(string $timezone): DateTimeZone|false
pub(crate) fn php_timezone_open(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let tz_name = arg_to_string(args, 0).unwrap_or_else(|| "UTC".to_string());
    match php_rs_ext_date::PhpDateTimeZone::offset_for_name(&tz_name) {
        Some(offset) => {
            let obj = PhpObject::new("DateTimeZone".to_string());
            obj.set_object_id(vm.next_object_id);
            vm.next_object_id += 1;
            obj.set_property("__tz_name".to_string(), Value::String(tz_name));
            obj.set_property("__tz_offset".to_string(), Value::Long(offset as i64));
            Ok(Value::Object(obj))
        }
        None => Ok(Value::Bool(false)),
    }
}

/// timezone_name_get(DateTimeZone $object): string
pub(crate) fn php_timezone_name_get(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    match args.first() {
        Some(Value::Object(ref obj)) => {
            let name = obj
                .get_property("__tz_name")
                .map(|v| v.to_php_string())
                .unwrap_or_else(|| "UTC".to_string());
            Ok(Value::String(name))
        }
        _ => Ok(Value::String("UTC".to_string())),
    }
}

/// timezone_offset_get(DateTimeZone $object, DateTimeInterface $datetime): int
pub(crate) fn php_timezone_offset_get(
    _vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    match args.first() {
        Some(Value::Object(ref obj)) => {
            let offset = obj
                .get_property("__tz_offset")
                .map(|v| v.to_long())
                .unwrap_or(0);
            Ok(Value::Long(offset))
        }
        _ => Ok(Value::Long(0)),
    }
}

fn php_date_default_timezone_set(
    vm: &mut Vm,
    args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let tz = args.first().map(|v| v.to_php_string()).unwrap_or_default();
    vm.ini.force_set("date.timezone", &tz);
    Ok(Value::Bool(true))
}

fn php_date_default_timezone_get(
    vm: &mut Vm,
    _args: &[Value],
    _ref_args: &[(usize, OperandType, u32)],
    _ref_prop_args: &[(usize, Value, String)],
) -> VmResult<Value> {
    let tz = vm.ini.get("date.timezone");
    let tz = if tz.is_empty() { "UTC" } else { tz };
    Ok(Value::String(tz.to_string().into()))
}
