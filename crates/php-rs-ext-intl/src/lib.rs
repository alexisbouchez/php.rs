//! PHP intl extension — Internationalization functions.
//!
//! Basic implementation without ICU dependency. Provides NumberFormatter,
//! DateFormatter, Collator, Normalizer, Transliterator, IntlCalendar, IntlTimeZone.
//! Reference: php-src/ext/intl/

use std::cmp::Ordering;

// ── NumberFormatter ──────────────────────────────────────────────────────────

/// Number format styles matching PHP's NumberFormatter constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberFormatStyle {
    /// Standard decimal formatting with thousands separator.
    Decimal,
    /// Currency formatting (prefix with currency symbol).
    Currency,
    /// Percentage formatting (multiply by 100, append %).
    Percent,
    /// Scientific notation (e.g., 1.23E4).
    Scientific,
    /// Spell out numbers in words (basic English only).
    SpellOut,
}

/// Attributes that can be set on a NumberFormatter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberFormatAttr {
    /// Number of decimal digits to show.
    MinFractionDigits,
    /// Maximum number of decimal digits.
    MaxFractionDigits,
    /// Grouping size (usually 3 for thousands).
    GroupingSize,
}

/// NumberFormatter — format and parse numbers according to locale conventions.
///
/// Reference: php-src/ext/intl/formatter/formatter_main.c
pub struct NumberFormatter {
    locale: String,
    style: NumberFormatStyle,
    min_fraction_digits: i64,
    max_fraction_digits: i64,
    grouping_size: i64,
    currency_code: String,
}

impl NumberFormatter {
    /// Create a new NumberFormatter for the given locale and style.
    pub fn new(locale: &str, style: NumberFormatStyle) -> Self {
        let max_frac = match style {
            NumberFormatStyle::Decimal => 3,
            NumberFormatStyle::Currency => 2,
            NumberFormatStyle::Percent => 0,
            NumberFormatStyle::Scientific => 6,
            NumberFormatStyle::SpellOut => 0,
        };
        let currency_code = if locale.starts_with("en") {
            "USD".to_string()
        } else if locale.starts_with("de") || locale.starts_with("fr") {
            "EUR".to_string()
        } else if locale.starts_with("ja") {
            "JPY".to_string()
        } else {
            "USD".to_string()
        };

        NumberFormatter {
            locale: locale.to_string(),
            style,
            min_fraction_digits: 0,
            max_fraction_digits: max_frac,
            grouping_size: 3,
            currency_code,
        }
    }

    /// Format an integer value according to the configured style and locale.
    pub fn format_int(&self, value: i64) -> String {
        match self.style {
            NumberFormatStyle::Decimal => self.format_decimal(value as f64, true),
            NumberFormatStyle::Currency => {
                let symbol = self.currency_symbol();
                let formatted = self.format_decimal(value as f64, true);
                format!("{}{}", symbol, formatted)
            }
            NumberFormatStyle::Percent => {
                format!("{}%", self.format_decimal(value as f64 * 100.0, true))
            }
            NumberFormatStyle::Scientific => {
                format!("{:E}", value)
            }
            NumberFormatStyle::SpellOut => spell_out(value),
        }
    }

    /// Format a floating-point value according to the configured style and locale.
    pub fn format_float(&self, value: f64) -> String {
        match self.style {
            NumberFormatStyle::Decimal => self.format_decimal(value, false),
            NumberFormatStyle::Currency => {
                let symbol = self.currency_symbol();
                let formatted = self.format_decimal(value, false);
                format!("{}{}", symbol, formatted)
            }
            NumberFormatStyle::Percent => {
                format!("{}%", self.format_decimal(value * 100.0, false))
            }
            NumberFormatStyle::Scientific => {
                format!("{:.*E}", self.max_fraction_digits as usize, value)
            }
            NumberFormatStyle::SpellOut => spell_out(value as i64),
        }
    }

    /// Parse a formatted number string back to a float.
    pub fn parse(&self, string: &str) -> Option<f64> {
        let cleaned: String = string
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-' || *c == '+')
            .collect();
        cleaned.parse::<f64>().ok()
    }

    /// Set a formatting attribute.
    pub fn set_attribute(&mut self, attr: NumberFormatAttr, value: i64) {
        match attr {
            NumberFormatAttr::MinFractionDigits => self.min_fraction_digits = value,
            NumberFormatAttr::MaxFractionDigits => self.max_fraction_digits = value,
            NumberFormatAttr::GroupingSize => self.grouping_size = value,
        }
    }

    fn currency_symbol(&self) -> &str {
        match self.currency_code.as_str() {
            "USD" => "$",
            "EUR" => "\u{20ac}",
            "GBP" => "\u{a3}",
            "JPY" => "\u{a5}",
            _ => "$",
        }
    }

    fn decimal_separator(&self) -> char {
        if self.locale.starts_with("de") || self.locale.starts_with("fr") {
            ','
        } else {
            '.'
        }
    }

    fn thousands_separator(&self) -> char {
        if self.locale.starts_with("de") {
            '.'
        } else if self.locale.starts_with("fr") {
            '\u{a0}' // non-breaking space
        } else {
            ','
        }
    }

    fn format_decimal(&self, value: f64, is_int: bool) -> String {
        let negative = value < 0.0;
        let abs_value = value.abs();

        // Determine fraction digits
        let frac_digits = if is_int && self.min_fraction_digits == 0 {
            0
        } else {
            self.max_fraction_digits.max(self.min_fraction_digits) as usize
        };

        let rounded = if frac_digits == 0 {
            abs_value.round() as u64
        } else {
            let factor = 10f64.powi(frac_digits as i32);
            (abs_value * factor).round() as u64 / (factor as u64).max(1)
        };

        // Format the integer part with grouping
        let int_part = if frac_digits == 0 {
            abs_value.round() as u64
        } else {
            abs_value.trunc() as u64
        };

        let int_str = int_part.to_string();
        let grouped = if self.grouping_size > 0 {
            self.add_thousands_separator(&int_str)
        } else {
            int_str
        };

        let result = if frac_digits > 0 && !is_int {
            let frac_part = abs_value.fract();
            let factor = 10f64.powi(frac_digits as i32);
            let frac_rounded = (frac_part * factor).round() as u64;
            let frac_str = format!("{:0>width$}", frac_rounded, width = frac_digits);
            format!("{}{}{}", grouped, self.decimal_separator(), frac_str)
        } else if frac_digits > 0 && is_int && self.min_fraction_digits > 0 {
            let frac_str = "0".repeat(self.min_fraction_digits as usize);
            format!("{}{}{}", grouped, self.decimal_separator(), frac_str)
        } else {
            let _ = rounded; // suppress unused warning
            grouped
        };

        if negative {
            format!("-{}", result)
        } else {
            result
        }
    }

    fn add_thousands_separator(&self, s: &str) -> String {
        let sep = self.thousands_separator();
        let gs = self.grouping_size as usize;
        if gs == 0 || s.len() <= gs {
            return s.to_string();
        }

        let mut result = String::new();
        let chars: Vec<char> = s.chars().collect();
        let len = chars.len();

        for (i, &ch) in chars.iter().enumerate() {
            if i > 0 && (len - i) % gs == 0 {
                result.push(sep);
            }
            result.push(ch);
        }
        result
    }
}

/// Spell out an integer in English words (basic implementation).
fn spell_out(value: i64) -> String {
    if value < 0 {
        return format!("minus {}", spell_out(-value));
    }
    match value {
        0 => "zero".to_string(),
        1 => "one".to_string(),
        2 => "two".to_string(),
        3 => "three".to_string(),
        4 => "four".to_string(),
        5 => "five".to_string(),
        6 => "six".to_string(),
        7 => "seven".to_string(),
        8 => "eight".to_string(),
        9 => "nine".to_string(),
        10 => "ten".to_string(),
        11 => "eleven".to_string(),
        12 => "twelve".to_string(),
        13 => "thirteen".to_string(),
        14 => "fourteen".to_string(),
        15 => "fifteen".to_string(),
        16 => "sixteen".to_string(),
        17 => "seventeen".to_string(),
        18 => "eighteen".to_string(),
        19 => "nineteen".to_string(),
        20..=99 => {
            let tens = [
                "", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty",
                "ninety",
            ];
            let t = tens[(value / 10) as usize].to_string();
            let remainder = value % 10;
            if remainder == 0 {
                t
            } else {
                format!("{}-{}", t, spell_out(remainder))
            }
        }
        100..=999 => {
            let remainder = value % 100;
            if remainder == 0 {
                format!("{} hundred", spell_out(value / 100))
            } else {
                format!(
                    "{} hundred {}",
                    spell_out(value / 100),
                    spell_out(remainder)
                )
            }
        }
        1000..=999_999 => {
            let remainder = value % 1000;
            if remainder == 0 {
                format!("{} thousand", spell_out(value / 1000))
            } else {
                format!(
                    "{} thousand {}",
                    spell_out(value / 1000),
                    spell_out(remainder)
                )
            }
        }
        1_000_000..=999_999_999 => {
            let remainder = value % 1_000_000;
            if remainder == 0 {
                format!("{} million", spell_out(value / 1_000_000))
            } else {
                format!(
                    "{} million {}",
                    spell_out(value / 1_000_000),
                    spell_out(remainder)
                )
            }
        }
        _ => {
            let remainder = value % 1_000_000_000;
            if remainder == 0 {
                format!("{} billion", spell_out(value / 1_000_000_000))
            } else {
                format!(
                    "{} billion {}",
                    spell_out(value / 1_000_000_000),
                    spell_out(remainder)
                )
            }
        }
    }
}

// ── DateFormatter ────────────────────────────────────────────────────────────

/// Format type for date/time components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatType {
    /// Do not include this component.
    None,
    /// Short format (e.g., "1/2/24" or "3:04 PM").
    Short,
    /// Medium format (e.g., "Jan 2, 2024" or "3:04:05 PM").
    Medium,
    /// Long format (e.g., "January 2, 2024" or "3:04:05 PM UTC").
    Long,
    /// Full format (e.g., "Tuesday, January 2, 2024").
    Full,
}

/// DateFormatter — format timestamps according to locale conventions.
///
/// Reference: php-src/ext/intl/dateformat/dateformat.c
pub struct DateFormatter {
    locale: String,
    date_type: FormatType,
    time_type: FormatType,
}

impl DateFormatter {
    /// Create a new DateFormatter.
    pub fn new(locale: &str, date_type: FormatType, time_type: FormatType) -> Self {
        DateFormatter {
            locale: locale.to_string(),
            date_type,
            time_type,
        }
    }

    /// Format a Unix timestamp into a string.
    pub fn format(&self, timestamp: i64) -> String {
        // Basic date/time formatting from Unix timestamp.
        // We compute year, month, day, hour, minute, second from the timestamp.
        let (year, month, day, hour, minute, second) = unix_to_components(timestamp);

        let date_part = match self.date_type {
            FormatType::None => String::new(),
            FormatType::Short => format!("{}/{}/{}", month, day, year % 100),
            FormatType::Medium => {
                let mon = month_abbrev(month);
                format!("{} {}, {}", mon, day, year)
            }
            FormatType::Long => {
                let mon = month_name(month);
                format!("{} {}, {}", mon, day, year)
            }
            FormatType::Full => {
                let dow = day_of_week_name(timestamp);
                let mon = month_name(month);
                format!("{}, {} {}, {}", dow, mon, day, year)
            }
        };

        let time_part = match self.time_type {
            FormatType::None => String::new(),
            FormatType::Short => {
                let (h12, ampm) = to_12h(hour);
                format!("{}:{:02} {}", h12, minute, ampm)
            }
            FormatType::Medium => {
                let (h12, ampm) = to_12h(hour);
                format!("{}:{:02}:{:02} {}", h12, minute, second, ampm)
            }
            FormatType::Long => {
                let (h12, ampm) = to_12h(hour);
                format!("{}:{:02}:{:02} {} UTC", h12, minute, second, ampm)
            }
            FormatType::Full => {
                let (h12, ampm) = to_12h(hour);
                format!(
                    "{}:{:02}:{:02} {} Coordinated Universal Time",
                    h12, minute, second, ampm
                )
            }
        };

        let _ = &self.locale; // locale affects output in full impl

        match (date_part.is_empty(), time_part.is_empty()) {
            (true, true) => String::new(),
            (false, true) => date_part,
            (true, false) => time_part,
            (false, false) => format!("{} {}", date_part, time_part),
        }
    }
}

fn to_12h(hour: u32) -> (u32, &'static str) {
    match hour {
        0 => (12, "AM"),
        1..=11 => (hour, "AM"),
        12 => (12, "PM"),
        _ => (hour - 12, "PM"),
    }
}

fn month_abbrev(month: u32) -> &'static str {
    match month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "???",
    }
}

fn month_name(month: u32) -> &'static str {
    match month {
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

fn day_of_week_name(timestamp: i64) -> &'static str {
    // Jan 1, 1970 was a Thursday (day 4).
    let days = if timestamp >= 0 {
        timestamp / 86400
    } else {
        (timestamp - 86399) / 86400
    };
    let dow = ((days % 7) + 4 + 7) % 7; // 0=Sunday
    match dow {
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

/// Convert a Unix timestamp to (year, month, day, hour, minute, second) in UTC.
fn unix_to_components(timestamp: i64) -> (i64, u32, u32, u32, u32, u32) {
    let seconds_in_day: i64 = 86400;
    let mut remaining = timestamp;

    let second = ((remaining % 60) + 60) % 60;
    remaining /= 60;
    let minute = ((remaining % 60) + 60) % 60;
    remaining /= 60;
    let hour = ((remaining % 24) + 24) % 24;

    // Days since epoch
    let mut days = if timestamp >= 0 {
        timestamp / seconds_in_day
    } else {
        (timestamp - (seconds_in_day - 1)) / seconds_in_day
    };

    // Compute year, month, day from days since epoch using the civil calendar algorithm.
    // Based on Howard Hinnant's algorithm.
    days += 719468; // shift to March 1, 0000
    let era = if days >= 0 {
        days / 146097
    } else {
        (days - 146096) / 146097
    };
    let doe = (days - era * 146097) as u32; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month (March=0) [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    (y, m, d, hour as u32, minute as u32, second as u32)
}

// ── Collator ─────────────────────────────────────────────────────────────────

/// Collator — locale-aware string comparison and sorting.
///
/// Reference: php-src/ext/intl/collator/collator.c
pub struct Collator {
    locale: String,
}

impl Collator {
    /// Create a new Collator for the given locale.
    pub fn new(locale: &str) -> Self {
        Collator {
            locale: locale.to_string(),
        }
    }

    /// Compare two strings according to locale collation rules.
    ///
    /// Basic implementation: case-insensitive comparison for most locales.
    pub fn compare(&self, a: &str, b: &str) -> Ordering {
        let _ = &self.locale; // full impl uses locale-specific rules
        let a_lower = a.to_lowercase();
        let b_lower = b.to_lowercase();
        a_lower.cmp(&b_lower).then_with(|| a.cmp(b))
    }

    /// Sort a slice of strings in-place according to locale collation rules.
    pub fn sort(&self, strings: &mut [String]) {
        strings.sort_by(|a, b| self.compare(a, b));
    }
}

// ── Normalizer ───────────────────────────────────────────────────────────────

/// Unicode normalization forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalizationForm {
    /// Canonical Decomposition, followed by Canonical Composition.
    NFC,
    /// Canonical Decomposition.
    NFD,
    /// Compatibility Decomposition, followed by Canonical Composition.
    NFKC,
    /// Compatibility Decomposition.
    NFKD,
}

/// Normalizer — Unicode text normalization.
///
/// Basic implementation: handles ASCII passthrough. Full Unicode normalization
/// requires a complete decomposition/composition database.
/// Reference: php-src/ext/intl/normalizer/normalizer.c
pub struct Normalizer;

impl Normalizer {
    /// Normalize a string to the specified form.
    ///
    /// For ASCII input, all forms produce identical output.
    /// For non-ASCII input, this basic implementation passes through unchanged.
    pub fn normalize(input: &str, form: NormalizationForm) -> String {
        let _ = form;
        // Basic normalization: ASCII is already normalized in all forms.
        // For non-ASCII, a full implementation would decompose/compose
        // using the Unicode Character Database.
        if input.is_ascii() {
            return input.to_string();
        }

        // Basic handling for common cases:
        // - Replace common composed characters with their NFC form
        // For now, pass through non-ASCII unchanged (correct for most NFC text).
        input.to_string()
    }

    /// Check if a string is already in the specified normalization form.
    pub fn is_normalized(input: &str, form: NormalizationForm) -> bool {
        let _ = form;
        // ASCII strings are always normalized in all forms.
        if input.is_ascii() {
            return true;
        }
        // For non-ASCII, conservatively return true (most UTF-8 text is NFC).
        true
    }
}

// ── Transliterator ───────────────────────────────────────────────────────────

/// Transliterator — text transliteration between scripts.
///
/// Reference: php-src/ext/intl/transliterator/transliterator.c
pub struct Transliterator;

impl Transliterator {
    /// Transliterate a string using the given transliterator ID.
    ///
    /// Supports basic Latin-ASCII transliteration: removes accents from common
    /// Latin characters.
    pub fn transliterate(input: &str, id: &str) -> String {
        match id {
            "Latin-ASCII" | "Any-Latin; Latin-ASCII" | "NFD; [:Nonspacing Mark:] Remove; NFC" => {
                Self::latin_to_ascii(input)
            }
            _ => input.to_string(),
        }
    }

    fn latin_to_ascii(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        for ch in input.chars() {
            match ch {
                '\u{00C0}'..='\u{00C5}' => result.push('A'), // A with accents
                '\u{00C6}' => result.push_str("AE"),         // AE ligature
                '\u{00C7}' => result.push('C'),              // C cedilla
                '\u{00C8}'..='\u{00CB}' => result.push('E'), // E with accents
                '\u{00CC}'..='\u{00CF}' => result.push('I'), // I with accents
                '\u{00D0}' => result.push('D'),              // Eth
                '\u{00D1}' => result.push('N'),              // N tilde
                '\u{00D2}'..='\u{00D6}' => result.push('O'), // O with accents
                '\u{00D8}' => result.push('O'),              // O stroke
                '\u{00D9}'..='\u{00DC}' => result.push('U'), // U with accents
                '\u{00DD}' => result.push('Y'),              // Y acute
                '\u{00DE}' => result.push_str("TH"),         // Thorn
                '\u{00DF}' => result.push_str("ss"),         // sharp s
                '\u{00E0}'..='\u{00E5}' => result.push('a'), // a with accents
                '\u{00E6}' => result.push_str("ae"),         // ae ligature
                '\u{00E7}' => result.push('c'),              // c cedilla
                '\u{00E8}'..='\u{00EB}' => result.push('e'), // e with accents
                '\u{00EC}'..='\u{00EF}' => result.push('i'), // i with accents
                '\u{00F0}' => result.push('d'),              // eth
                '\u{00F1}' => result.push('n'),              // n tilde
                '\u{00F2}'..='\u{00F6}' => result.push('o'), // o with accents
                '\u{00F8}' => result.push('o'),              // o stroke
                '\u{00F9}'..='\u{00FC}' => result.push('u'), // u with accents
                '\u{00FD}' | '\u{00FF}' => result.push('y'), // y with accents
                '\u{00FE}' => result.push_str("th"),         // thorn
                c if c.is_ascii() => result.push(c),
                _ => result.push(ch), // Pass through other Unicode
            }
        }
        result
    }
}

// ── IntlTimeZone ─────────────────────────────────────────────────────────────

/// IntlTimeZone — timezone representation with UTC offset.
///
/// Reference: php-src/ext/intl/timezone/timezone.c
#[derive(Debug, Clone)]
pub struct IntlTimeZone {
    /// IANA timezone identifier (e.g., "America/New_York").
    pub id: String,
    /// UTC offset in seconds.
    pub raw_offset: i32,
    /// Whether this timezone uses daylight saving time.
    pub uses_dst: bool,
}

impl IntlTimeZone {
    /// Create a new timezone with the given ID and offset.
    pub fn new(id: &str, raw_offset: i32, uses_dst: bool) -> Self {
        IntlTimeZone {
            id: id.to_string(),
            raw_offset,
            uses_dst,
        }
    }

    /// Get the UTC timezone.
    pub fn utc() -> Self {
        IntlTimeZone {
            id: "UTC".to_string(),
            raw_offset: 0,
            uses_dst: false,
        }
    }

    /// Create a timezone from a well-known ID.
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "UTC" | "Etc/UTC" => Some(Self::new("UTC", 0, false)),
            "America/New_York" | "US/Eastern" => Some(Self::new("America/New_York", -18000, true)),
            "America/Chicago" | "US/Central" => Some(Self::new("America/Chicago", -21600, true)),
            "America/Denver" | "US/Mountain" => Some(Self::new("America/Denver", -25200, true)),
            "America/Los_Angeles" | "US/Pacific" => {
                Some(Self::new("America/Los_Angeles", -28800, true))
            }
            "Europe/London" => Some(Self::new("Europe/London", 0, true)),
            "Europe/Paris" | "Europe/Berlin" => Some(Self::new(id, 3600, true)),
            "Asia/Tokyo" | "Japan" => Some(Self::new("Asia/Tokyo", 32400, false)),
            "Asia/Shanghai" | "Asia/Hong_Kong" => Some(Self::new(id, 28800, false)),
            "Australia/Sydney" => Some(Self::new("Australia/Sydney", 36000, true)),
            _ => None,
        }
    }

    /// Get the offset from UTC in milliseconds (PHP convention).
    pub fn get_raw_offset(&self) -> i32 {
        self.raw_offset * 1000
    }
}

// ── IntlCalendar ─────────────────────────────────────────────────────────────

/// IntlCalendar — calendar operations with timezone support.
///
/// Reference: php-src/ext/intl/calendar/calendar.c
#[derive(Debug, Clone)]
pub struct IntlCalendar {
    /// The timezone for this calendar.
    pub timezone: IntlTimeZone,
    /// Current timestamp in seconds since epoch.
    pub timestamp: i64,
}

impl IntlCalendar {
    /// Create a new IntlCalendar with the given timezone and current time.
    pub fn new(timezone: IntlTimeZone, timestamp: i64) -> Self {
        IntlCalendar {
            timezone,
            timestamp,
        }
    }

    /// Get the year.
    pub fn get_year(&self) -> i64 {
        let local_ts = self.timestamp + self.timezone.raw_offset as i64;
        let (year, _, _, _, _, _) = unix_to_components(local_ts);
        year
    }

    /// Get the month (1-12).
    pub fn get_month(&self) -> u32 {
        let local_ts = self.timestamp + self.timezone.raw_offset as i64;
        let (_, month, _, _, _, _) = unix_to_components(local_ts);
        month
    }

    /// Get the day of the month (1-31).
    pub fn get_day(&self) -> u32 {
        let local_ts = self.timestamp + self.timezone.raw_offset as i64;
        let (_, _, day, _, _, _) = unix_to_components(local_ts);
        day
    }

    /// Get the hour (0-23).
    pub fn get_hour(&self) -> u32 {
        let local_ts = self.timestamp + self.timezone.raw_offset as i64;
        let (_, _, _, hour, _, _) = unix_to_components(local_ts);
        hour
    }

    /// Get the minute (0-59).
    pub fn get_minute(&self) -> u32 {
        let local_ts = self.timestamp + self.timezone.raw_offset as i64;
        let (_, _, _, _, minute, _) = unix_to_components(local_ts);
        minute
    }

    /// Get the second (0-59).
    pub fn get_second(&self) -> u32 {
        let local_ts = self.timestamp + self.timezone.raw_offset as i64;
        let (_, _, _, _, _, second) = unix_to_components(local_ts);
        second
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // NumberFormatter tests

    #[test]
    fn test_number_formatter_decimal_int() {
        let fmt = NumberFormatter::new("en_US", NumberFormatStyle::Decimal);
        assert_eq!(fmt.format_int(0), "0");
        assert_eq!(fmt.format_int(1234), "1,234");
        assert_eq!(fmt.format_int(1000000), "1,000,000");
        assert_eq!(fmt.format_int(-42), "-42");
    }

    #[test]
    fn test_number_formatter_decimal_float() {
        let fmt = NumberFormatter::new("en_US", NumberFormatStyle::Decimal);
        assert_eq!(fmt.format_float(1234.56), "1,234.560");
        assert_eq!(fmt.format_float(0.5), "0.500");
    }

    #[test]
    fn test_number_formatter_currency() {
        let fmt = NumberFormatter::new("en_US", NumberFormatStyle::Currency);
        assert_eq!(fmt.format_int(1234), "$1,234");
        assert_eq!(fmt.format_float(99.99), "$99.99");
    }

    #[test]
    fn test_number_formatter_percent() {
        let fmt = NumberFormatter::new("en_US", NumberFormatStyle::Percent);
        assert_eq!(fmt.format_int(1), "100%");
    }

    #[test]
    fn test_number_formatter_scientific() {
        let fmt = NumberFormatter::new("en_US", NumberFormatStyle::Scientific);
        let result = fmt.format_float(12345.678);
        assert!(
            result.contains('E'),
            "Expected scientific notation: {}",
            result
        );
    }

    #[test]
    fn test_number_formatter_spellout() {
        let fmt = NumberFormatter::new("en_US", NumberFormatStyle::SpellOut);
        assert_eq!(fmt.format_int(0), "zero");
        assert_eq!(fmt.format_int(1), "one");
        assert_eq!(fmt.format_int(42), "forty-two");
        assert_eq!(fmt.format_int(100), "one hundred");
        assert_eq!(fmt.format_int(1000), "one thousand");
        assert_eq!(fmt.format_int(1234), "one thousand two hundred thirty-four");
    }

    #[test]
    fn test_number_formatter_de_locale() {
        let fmt = NumberFormatter::new("de_DE", NumberFormatStyle::Decimal);
        assert_eq!(fmt.format_int(1234), "1.234");
        assert_eq!(fmt.format_float(1234.56), "1.234,560");
    }

    #[test]
    fn test_number_formatter_parse() {
        let fmt = NumberFormatter::new("en_US", NumberFormatStyle::Decimal);
        assert_eq!(fmt.parse("1,234.56"), Some(1234.56));
        assert_eq!(fmt.parse("42"), Some(42.0));
        assert!(fmt.parse("abc").is_none());
    }

    #[test]
    fn test_number_formatter_set_attribute() {
        let mut fmt = NumberFormatter::new("en_US", NumberFormatStyle::Decimal);
        fmt.set_attribute(NumberFormatAttr::MaxFractionDigits, 2);
        let result = fmt.format_float(1.5);
        assert!(result.contains('.'), "Should have decimal: {}", result);
    }

    // DateFormatter tests

    #[test]
    fn test_date_formatter_short() {
        let fmt = DateFormatter::new("en_US", FormatType::Short, FormatType::None);
        // Unix epoch: Jan 1, 1970
        let result = fmt.format(0);
        assert_eq!(result, "1/1/70");
    }

    #[test]
    fn test_date_formatter_medium() {
        let fmt = DateFormatter::new("en_US", FormatType::Medium, FormatType::None);
        let result = fmt.format(0);
        assert_eq!(result, "Jan 1, 1970");
    }

    #[test]
    fn test_date_formatter_long() {
        let fmt = DateFormatter::new("en_US", FormatType::Long, FormatType::None);
        let result = fmt.format(0);
        assert_eq!(result, "January 1, 1970");
    }

    #[test]
    fn test_date_formatter_full() {
        let fmt = DateFormatter::new("en_US", FormatType::Full, FormatType::None);
        let result = fmt.format(0);
        assert_eq!(result, "Thursday, January 1, 1970");
    }

    #[test]
    fn test_date_formatter_time_short() {
        let fmt = DateFormatter::new("en_US", FormatType::None, FormatType::Short);
        let result = fmt.format(0);
        assert_eq!(result, "12:00 AM");
    }

    #[test]
    fn test_date_formatter_time_medium() {
        let fmt = DateFormatter::new("en_US", FormatType::None, FormatType::Medium);
        let result = fmt.format(0);
        assert_eq!(result, "12:00:00 AM");
    }

    #[test]
    fn test_date_formatter_date_and_time() {
        let fmt = DateFormatter::new("en_US", FormatType::Short, FormatType::Short);
        let result = fmt.format(0);
        assert_eq!(result, "1/1/70 12:00 AM");
    }

    #[test]
    fn test_date_formatter_specific_timestamp() {
        // 2024-01-15 14:30:00 UTC = 1705329000
        let fmt = DateFormatter::new("en_US", FormatType::Medium, FormatType::Short);
        let result = fmt.format(1705329000);
        assert_eq!(result, "Jan 15, 2024 2:30 PM");
    }

    // Collator tests

    #[test]
    fn test_collator_compare_equal() {
        let col = Collator::new("en_US");
        assert_eq!(col.compare("hello", "hello"), Ordering::Equal);
    }

    #[test]
    fn test_collator_compare_case_insensitive() {
        let col = Collator::new("en_US");
        // Case-insensitive: "Apple" and "apple" should be equal (primary level).
        // But at secondary level, uppercase comes after lowercase.
        let ord = col.compare("Apple", "apple");
        assert_eq!(ord, Ordering::Less); // 'A' < 'a' in tiebreaker
    }

    #[test]
    fn test_collator_compare_ordering() {
        let col = Collator::new("en_US");
        assert_eq!(col.compare("apple", "banana"), Ordering::Less);
        assert_eq!(col.compare("banana", "apple"), Ordering::Greater);
    }

    #[test]
    fn test_collator_sort() {
        let col = Collator::new("en_US");
        let mut strings = vec![
            "banana".to_string(),
            "Apple".to_string(),
            "cherry".to_string(),
            "apple".to_string(),
        ];
        col.sort(&mut strings);
        assert_eq!(strings, vec!["Apple", "apple", "banana", "cherry"]);
    }

    // Normalizer tests

    #[test]
    fn test_normalizer_ascii() {
        let result = Normalizer::normalize("hello", NormalizationForm::NFC);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_normalizer_is_normalized_ascii() {
        assert!(Normalizer::is_normalized("hello", NormalizationForm::NFC));
        assert!(Normalizer::is_normalized("hello", NormalizationForm::NFD));
        assert!(Normalizer::is_normalized("hello", NormalizationForm::NFKC));
        assert!(Normalizer::is_normalized("hello", NormalizationForm::NFKD));
    }

    #[test]
    fn test_normalizer_unicode_passthrough() {
        let input = "\u{00E9}"; // e-acute (NFC form)
        let result = Normalizer::normalize(input, NormalizationForm::NFC);
        assert_eq!(result, input);
    }

    // Transliterator tests

    #[test]
    fn test_transliterator_latin_ascii() {
        let result = Transliterator::transliterate("caf\u{00e9}", "Latin-ASCII");
        assert_eq!(result, "cafe");
    }

    #[test]
    fn test_transliterator_accented_chars() {
        let result = Transliterator::transliterate(
            "\u{00C0}\u{00C8}\u{00D1}\u{00DC}\u{00DF}",
            "Latin-ASCII",
        );
        assert_eq!(result, "AENUss");
    }

    #[test]
    fn test_transliterator_ascii_passthrough() {
        let result = Transliterator::transliterate("Hello World", "Latin-ASCII");
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn test_transliterator_unknown_id() {
        let result = Transliterator::transliterate("hello", "Unknown-ID");
        assert_eq!(result, "hello");
    }

    // IntlTimeZone tests

    #[test]
    fn test_timezone_utc() {
        let tz = IntlTimeZone::utc();
        assert_eq!(tz.id, "UTC");
        assert_eq!(tz.raw_offset, 0);
        assert!(!tz.uses_dst);
    }

    #[test]
    fn test_timezone_from_id() {
        let tz = IntlTimeZone::from_id("America/New_York").unwrap();
        assert_eq!(tz.raw_offset, -18000); // UTC-5
        assert!(tz.uses_dst);

        let tz = IntlTimeZone::from_id("Asia/Tokyo").unwrap();
        assert_eq!(tz.raw_offset, 32400); // UTC+9
        assert!(!tz.uses_dst);
    }

    #[test]
    fn test_timezone_unknown_id() {
        assert!(IntlTimeZone::from_id("Invalid/Zone").is_none());
    }

    #[test]
    fn test_timezone_get_raw_offset() {
        let tz = IntlTimeZone::new("Test", 3600, false);
        assert_eq!(tz.get_raw_offset(), 3600000); // milliseconds
    }

    // IntlCalendar tests

    #[test]
    fn test_calendar_utc_epoch() {
        let cal = IntlCalendar::new(IntlTimeZone::utc(), 0);
        assert_eq!(cal.get_year(), 1970);
        assert_eq!(cal.get_month(), 1);
        assert_eq!(cal.get_day(), 1);
        assert_eq!(cal.get_hour(), 0);
        assert_eq!(cal.get_minute(), 0);
        assert_eq!(cal.get_second(), 0);
    }

    #[test]
    fn test_calendar_with_timezone() {
        let tz = IntlTimeZone::from_id("Asia/Tokyo").unwrap(); // UTC+9
        let cal = IntlCalendar::new(tz, 0);
        assert_eq!(cal.get_hour(), 9); // midnight UTC = 9am Tokyo
    }

    #[test]
    fn test_calendar_specific_date() {
        // 2024-06-15 12:30:45 UTC = 1718454645
        let cal = IntlCalendar::new(IntlTimeZone::utc(), 1718454645);
        assert_eq!(cal.get_year(), 2024);
        assert_eq!(cal.get_month(), 6);
        assert_eq!(cal.get_day(), 15);
        assert_eq!(cal.get_hour(), 12);
        assert_eq!(cal.get_minute(), 30);
        assert_eq!(cal.get_second(), 45);
    }

    // unix_to_components tests

    #[test]
    fn test_unix_to_components_epoch() {
        let (y, m, d, h, min, s) = unix_to_components(0);
        assert_eq!((y, m, d, h, min, s), (1970, 1, 1, 0, 0, 0));
    }

    #[test]
    fn test_unix_to_components_known_date() {
        // 2000-01-01 00:00:00 UTC = 946684800
        let (y, m, d, h, min, s) = unix_to_components(946684800);
        assert_eq!((y, m, d, h, min, s), (2000, 1, 1, 0, 0, 0));
    }
}
