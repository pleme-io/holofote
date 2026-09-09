//! Typed SPL — a search is a value, and exactly one renderer turns it into
//! text.
//!
//! There is no raw-SPL entry point anywhere in this crate. A caller builds a
//! [`Search`] from typed parts — an [`IndexName`] and [`FieldName`]s that
//! admit one strict grammar, [`Term`]s whose values are always quoted by the
//! renderer, a [`TimeWindow`] whose bounds are parsed [`TimeSpec`]s, and a
//! [`ResultCap`] bounded by the deployment's configured maximum — and the
//! [`Display`](fmt::Display) impl on `Search` is the only place SPL text is
//! ever assembled. `| delete` inside a value is therefore a quoted literal,
//! not a pipeline stage; a `count` of `0` (which Splunk reads as *all*) has
//! no representation; and a search with no time bound cannot be built,
//! because the REST API defaults an unbounded search to **all time**.
//!
//! Every dimension of a request is bounded by the deployment
//! ([`SearchBounds`]): the result limit, how many terms, how many bytes one
//! term value may carry, how many field names one list may name. A request
//! over a bound is refused with the bound's YAML key, never sent.

use std::cmp::Ordering;
use std::fmt::{self, Write as _};
use std::str::FromStr;

/// The grammar every index and field name must satisfy.
pub const IDENT_GRAMMAR: &str = "[A-Za-z_][A-Za-z0-9_.:-]*";

/// The longest identifier accepted — a bound, so a name is never a payload.
const IDENT_MAX_LEN: usize = 256;

fn is_ident(candidate: &str) -> bool {
    let mut bytes = candidate.bytes();
    let head_ok = matches!(bytes.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_');
    head_ok
        && candidate.len() <= IDENT_MAX_LEN
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

/// Why a typed search could not be built. Every arm names what WOULD have
/// been accepted through [`SplError::legal`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SplError {
    /// An index name outside [`IDENT_GRAMMAR`].
    #[error("index name {got:?} is not {IDENT_GRAMMAR}")]
    IllegalIndex {
        /// The rejected name.
        got: String,
    },
    /// A field name outside [`IDENT_GRAMMAR`].
    #[error("field name {got:?} is not {IDENT_GRAMMAR}")]
    IllegalField {
        /// The rejected name.
        got: String,
    },
    /// An operator spelling outside [`Op::LEGAL`].
    #[error("operator {got:?} is not one of eq ne gt lt ge le")]
    IllegalOp {
        /// The rejected spelling.
        got: String,
    },
    /// A time bound that did not parse.
    #[error(transparent)]
    Time(#[from] TimeSpecError),
    /// A result limit outside `1..=cap`.
    #[error(transparent)]
    Limit(#[from] CapError),
    /// The window provably runs backwards without consulting a clock —
    /// see [`TimeSpec::ordered_without_a_clock`].
    #[error("time window runs backwards: earliest {earliest} is after latest {latest}")]
    InvertedWindow {
        /// The rendered earliest bound.
        earliest: String,
        /// The rendered latest bound.
        latest: String,
    },
    /// A count or a length over one of the deployment's [`SearchBounds`].
    #[error("{got} {bound} exceeds the configured maximum of {max}; legal: at most {max}")]
    OverBound {
        /// Which bound.
        bound: SearchBound,
        /// What was asked for.
        got: usize,
        /// The configured maximum.
        max: u32,
    },
}

impl SplError {
    /// What would have been accepted — the `legal` set of a refusal.
    #[must_use]
    pub fn legal(&self) -> Vec<String> {
        match self {
            Self::IllegalIndex { .. } | Self::IllegalField { .. } => {
                vec![IDENT_GRAMMAR.to_owned()]
            }
            Self::IllegalOp { .. } => Op::LEGAL.iter().map(|s| (*s).to_owned()).collect(),
            Self::Time(_) | Self::InvertedWindow { .. } => TimeSpec::LEGAL_FORMS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            Self::Limit(e) => vec![e.legal()],
            Self::OverBound { bound, max, .. } => {
                let mut s = String::new();
                // Writing into a String cannot fail.
                let _ = write!(s, "at most {max} {bound}");
                vec![s]
            }
        }
    }
}

/// The dimensions of a request the deployment bounds, besides the result
/// limit. Each names the `HolofoteConfig` key that sets it, so a refusal
/// tells the operator what to raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchBound {
    /// How many terms one search may carry (`maxTerms`).
    Terms,
    /// How many bytes one term value may carry (`maxTermBytes`).
    TermBytes,
    /// How many names one `fields` / `stats_count_by` list may carry
    /// (`maxFields`).
    Fields,
}

impl SearchBound {
    /// The camelCase `HolofoteConfig` key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Terms => "maxTerms",
            Self::TermBytes => "maxTermBytes",
            Self::Fields => "maxFields",
        }
    }

    const fn noun(self) -> &'static str {
        match self {
            Self::Terms => "terms in one search",
            Self::TermBytes => "bytes in one term value",
            Self::Fields => "field names in one list",
        }
    }
}

impl fmt::Display for SearchBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.noun(), self.key())
    }
}

/// Every bound a deployment places on one search, read off
/// `HolofoteConfig` once (`HolofoteConfig::search_bounds`). Plain `Copy`
/// data so the SPL module never depends on the config module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SearchBounds {
    /// The cap on `limit` — `ResultCap` is `1..=max_results`.
    pub max_results: u32,
    /// The cap on the number of terms.
    pub max_terms: u32,
    /// The cap on one term value's length in bytes.
    pub max_term_bytes: u32,
    /// The cap on the length of each of `fields` and `stats_count_by`.
    pub max_fields: u32,
}

impl SearchBounds {
    fn check(bound: SearchBound, got: usize, max: u32) -> Result<(), SplError> {
        if got > usize::try_from(max).unwrap_or(usize::MAX) {
            Err(SplError::OverBound { bound, got, max })
        } else {
            Ok(())
        }
    }
}

/// The one newtype shape for a grammar-checked identifier, stamped twice.
macro_rules! ident_newtype {
    ($(#[$doc:meta])* $name:ident, $variant:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// The validated name.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = SplError;

            fn try_from(candidate: &str) -> Result<Self, Self::Error> {
                if is_ident(candidate) {
                    Ok(Self(candidate.to_owned()))
                } else {
                    Err(SplError::$variant {
                        got: candidate.to_owned(),
                    })
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

ident_newtype! {
    /// A Splunk index name — constructible only through `TryFrom<&str>`
    /// against [`IDENT_GRAMMAR`], so it can never carry a quote or a pipe.
    IndexName, IllegalIndex
}

ident_newtype! {
    /// A Splunk field name — same grammar, same guarantee.
    FieldName, IllegalField
}

/// A comparison operator on a fielded term.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Op {
    /// `field="value"` — the default.
    #[default]
    Eq,
    /// `field!="value"`.
    Ne,
    /// `field>value`.
    Gt,
    /// `field<value`.
    Lt,
    /// `field>=value`.
    Ge,
    /// `field<=value`.
    Le,
}

impl Op {
    /// The six spellings a request may use.
    pub const LEGAL: [&'static str; 6] = ["eq", "ne", "gt", "lt", "ge", "le"];

    const fn symbol(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "!=",
            Self::Gt => ">",
            Self::Lt => "<",
            Self::Ge => ">=",
            Self::Le => "<=",
        }
    }

    /// Whether the operator compares magnitudes, where a numeric literal
    /// may be rendered bare.
    const fn is_ordering(self) -> bool {
        matches!(self, Self::Gt | Self::Lt | Self::Ge | Self::Le)
    }
}

impl FromStr for Op {
    type Err = SplError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "eq" => Ok(Self::Eq),
            "ne" => Ok(Self::Ne),
            "gt" => Ok(Self::Gt),
            "lt" => Ok(Self::Lt),
            "ge" => Ok(Self::Ge),
            "le" => Ok(Self::Le),
            other => Err(SplError::IllegalOp {
                got: other.to_owned(),
            }),
        }
    }
}

/// A search term: a fielded comparison, or a free-text phrase when `field`
/// is absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Term {
    field: Option<FieldName>,
    op: Op,
    value: String,
}

impl Term {
    /// A free-text phrase, rendered as one quoted literal.
    #[must_use]
    pub fn phrase(value: impl Into<String>) -> Self {
        Self {
            field: None,
            op: Op::Eq,
            value: value.into(),
        }
    }

    /// `field <op> value`.
    #[must_use]
    pub fn fielded(field: FieldName, op: Op, value: impl Into<String>) -> Self {
        Self {
            field: Some(field),
            op,
            value: value.into(),
        }
    }
}

/// A string as SPL sees it: double-quoted, with `\` and `"` escaped.
///
/// This is the only escaping rule in the crate, and every user-supplied
/// value passes through it. Splunk recognises exactly these two escapes
/// inside a quoted string; a newline inside the quotes is a literal
/// newline, which is harmless — it stays inside the quotes.
struct Quoted<'a>(&'a str);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        for ch in self.0.chars() {
            match ch {
                '\\' => f.write_str("\\\\")?,
                '"' => f.write_str("\\\"")?,
                other => write!(f, "{other}")?,
            }
        }
        f.write_str("\"")
    }
}

/// `-?\d+(\.\d+)?` — the only shape rendered without quotes, and only
/// under an ordering operator.
fn is_numeric_literal(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    match digits.split_once('.') {
        Some((int, frac)) => {
            !int.is_empty()
                && !frac.is_empty()
                && int.bytes().all(|b| b.is_ascii_digit())
                && frac.bytes().all(|b| b.is_ascii_digit())
        }
        None => !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.field {
            None => write!(f, "{}", Quoted(&self.value)),
            Some(field) => {
                write!(f, "{field}{}", self.op.symbol())?;
                if self.op.is_ordering() && is_numeric_literal(&self.value) {
                    f.write_str(&self.value)
                } else {
                    write!(f, "{}", Quoted(&self.value))
                }
            }
        }
    }
}

// ── time ───────────────────────────────────────────────────────────────

/// A Splunk relative-time unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unit {
    /// `s`
    Second,
    /// `m`
    Minute,
    /// `h`
    Hour,
    /// `d`
    Day,
    /// `w`
    Week,
    /// `mon`
    Month,
    /// `q`
    Quarter,
    /// `y`
    Year,
}

impl Unit {
    /// Seconds in one unit, for the units whose length never varies.
    /// Splunk does relative-time arithmetic in local time, so a day or
    /// anything larger can be 23 or 25 hours across a DST edge; those
    /// units are ordered only against themselves.
    const fn fixed_seconds(self) -> Option<i64> {
        match self {
            Self::Second => Some(1),
            Self::Minute => Some(60),
            Self::Hour => Some(3_600),
            Self::Day | Self::Week | Self::Month | Self::Quarter | Self::Year => None,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "s" | "sec" | "secs" | "second" | "seconds" => Self::Second,
            "m" | "min" | "mins" | "minute" | "minutes" => Self::Minute,
            "h" | "hr" | "hrs" | "hour" | "hours" => Self::Hour,
            "d" | "day" | "days" => Self::Day,
            "w" | "week" | "weeks" => Self::Week,
            "mon" | "month" | "months" => Self::Month,
            "q" | "qtr" | "qtrs" | "quarter" | "quarters" => Self::Quarter,
            "y" | "yr" | "yrs" | "year" | "years" => Self::Year,
            _ => return None,
        })
    }
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Second => "s",
            Self::Minute => "m",
            Self::Hour => "h",
            Self::Day => "d",
            Self::Week => "w",
            Self::Month => "mon",
            Self::Quarter => "q",
            Self::Year => "y",
        })
    }
}

/// The `@` snap of a relative time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Snap {
    /// Snap to the start of a unit: `@d`, `@h`, `@mon`.
    Unit(Unit),
    /// Snap to a weekday, `@w0` (Sunday) through `@w6`.
    Weekday(u8),
}

impl fmt::Display for Snap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unit(u) => write!(f, "@{u}"),
            Self::Weekday(d) => write!(f, "@w{d}"),
        }
    }
}

/// The signed offset of a relative time: `-15m`, `+1h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Offset {
    negative: bool,
    amount: u32,
    unit: Unit,
}

impl Offset {
    /// `now` as an offset: zero seconds.
    const ZERO: Self = Self {
        negative: false,
        amount: 0,
        unit: Unit::Second,
    };

    const fn signed_amount(self) -> i64 {
        let amount = self.amount as i64;
        if self.negative { -amount } else { amount }
    }

    /// Order two offsets from `now` without a clock, when that is
    /// possible: a zero offset orders against any other by sign alone; two
    /// offsets in the same unit by amount; two offsets in fixed units
    /// (`s`, `m`, `h`) by seconds. A day against an hour is `None` — a DST
    /// day may be 23 hours.
    fn ordered_against(self, other: Self) -> Option<Ordering> {
        let (a, b) = (self.signed_amount(), other.signed_amount());
        if a == 0 || b == 0 || self.unit == other.unit {
            return Some(a.cmp(&b));
        }
        match (self.unit.fixed_seconds(), other.unit.fixed_seconds()) {
            (Some(x), Some(y)) => Some((a * x).cmp(&(b * y))),
            _ => None,
        }
    }
}

impl fmt::Display for Offset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.negative { '-' } else { '+' },
            self.amount,
            self.unit
        )
    }
}

/// A relative time: an optional offset and an optional snap, at least one
/// of them present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Relative {
    offset: Option<Offset>,
    snap: Option<Snap>,
}

impl fmt::Display for Relative {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(o) = &self.offset {
            write!(f, "{o}")?;
        }
        if let Some(s) = &self.snap {
            write!(f, "{s}")?;
        }
        Ok(())
    }
}

/// A point in time as Splunk's `earliest_time` / `latest_time` take it.
///
/// Absolute times are always sent as an epoch, whatever form they arrived
/// in: an RFC 3339 string is converted here, so the wire never depends on
/// Splunk's `time_format` guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeSpec {
    /// `now`.
    Now,
    /// `-15m`, `-24h@h`, `@d`, …
    Relative(Relative),
    /// Seconds since the Unix epoch.
    Absolute(u64),
}

/// Why a time string was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TimeSpecError {
    /// Nothing was given.
    #[error("time spec is empty")]
    Empty,
    /// None of the legal shapes.
    #[error("time {got:?} is not a legal time spec")]
    Unrecognized {
        /// The rejected string.
        got: String,
    },
    /// All digits, but not ten of them.
    #[error("epoch {got:?} must be exactly 10 digits")]
    EpochLength {
        /// The rejected string.
        got: String,
    },
    /// A relative offset with no digits, or too many.
    #[error("relative time {got:?} needs an amount of 1 to 9 digits after the sign")]
    Amount {
        /// The rejected string.
        got: String,
    },
    /// An unknown offset unit.
    #[error("relative time {got:?}: unit {unit:?} is not one of s m h d w mon q y")]
    Unit {
        /// The rejected string.
        got: String,
        /// The unit text that was not recognised.
        unit: String,
    },
    /// An unknown snap.
    #[error("relative time {got:?}: snap {snap:?} is not a unit (s m h d w mon q y) or w0..w6")]
    Snap {
        /// The rejected string.
        got: String,
        /// The snap text that was not recognised.
        snap: String,
    },
    /// Text left over after a complete relative time.
    #[error("relative time {got:?} has trailing text {rest:?}")]
    Trailing {
        /// The rejected string.
        got: String,
        /// What was left.
        rest: String,
    },
    /// Looked like RFC 3339 and was not.
    #[error("time {got:?} is not RFC 3339 ({why})")]
    Rfc3339 {
        /// The rejected string.
        got: String,
        /// Which part failed.
        why: &'static str,
    },
    /// An absolute time before 1970 or past the representable range.
    #[error("time {got:?} is outside the representable epoch range")]
    OutOfRange {
        /// The rejected string.
        got: String,
    },
}

impl TimeSpec {
    /// This spec as a signed offset from `now`, when it is one: `now` is
    /// zero, a snapless relative time is its offset. A snap lands on a
    /// boundary an unknown distance away and an absolute time is on a
    /// different clock, so both are `None`.
    const fn as_offset(&self) -> Option<Offset> {
        match self {
            Self::Now => Some(Offset::ZERO),
            Self::Relative(Relative {
                offset: Some(o),
                snap: None,
            }) => Some(*o),
            Self::Relative(_) | Self::Absolute(_) => None,
        }
    }

    /// `Some(ordering)` when the two can be ordered WITHOUT a clock: two
    /// absolute times; `now` against any snapless relative time; two
    /// snapless relative times in the same unit, or both in fixed units.
    /// Everything else — a snap, a mixed absolute/relative pair, a day
    /// against an hour — is `None` and passes through to Splunk.
    #[must_use]
    pub fn ordered_without_a_clock(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Absolute(a), Self::Absolute(b)) => Some(a.cmp(b)),
            _ => match (self.as_offset(), other.as_offset()) {
                (Some(a), Some(b)) => a.ordered_against(b),
                _ => None,
            },
        }
    }

    /// The legal shapes, quoted in every refusal.
    pub const LEGAL_FORMS: [&'static str; 5] = [
        "now",
        "a relative offset: [+-]<amount><unit>, unit in s m h d w mon q y — e.g. -15m, +1h, -3mon",
        "a relative offset with a snap, or a bare snap: -24h@h, -1d@d, -7d@w0, @d — snap is a unit or w0..w6",
        "a 10-digit Unix epoch — e.g. 1757400000",
        "an RFC 3339 timestamp — e.g. 2026-09-09T12:00:00Z or 2026-09-09T14:00:00+02:00",
    ];

    fn parse(raw: &str) -> Result<Self, TimeSpecError> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(TimeSpecError::Empty);
        }
        if s == "now" {
            return Ok(Self::Now);
        }
        if s.bytes().all(|b| b.is_ascii_digit()) {
            return if s.len() == 10 {
                s.parse::<u64>()
                    .map(Self::Absolute)
                    .map_err(|_| TimeSpecError::EpochLength {
                        got: raw.to_owned(),
                    })
            } else {
                Err(TimeSpecError::EpochLength {
                    got: raw.to_owned(),
                })
            };
        }
        if s.starts_with(['+', '-', '@']) {
            return parse_relative(raw, s).map(Self::Relative);
        }
        if s.len() >= 19 && s.as_bytes()[4] == b'-' && matches!(s.as_bytes()[10], b'T' | b't') {
            return parse_rfc3339(raw, s).map(Self::Absolute);
        }
        Err(TimeSpecError::Unrecognized {
            got: raw.to_owned(),
        })
    }
}

impl TryFrom<&str> for TimeSpec {
    type Error = TimeSpecError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        Self::parse(raw)
    }
}

impl fmt::Display for TimeSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Now => f.write_str("now"),
            Self::Relative(r) => write!(f, "{r}"),
            Self::Absolute(epoch) => write!(f, "{epoch}"),
        }
    }
}

fn parse_relative(raw: &str, s: &str) -> Result<Relative, TimeSpecError> {
    let got = || raw.to_owned();
    let mut rest = s;
    let mut offset = None;
    if let Some(sign) = rest.chars().next().filter(|c| matches!(c, '+' | '-')) {
        rest = &rest[1..];
        let digits_len = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits_len == 0 || digits_len > 9 {
            return Err(TimeSpecError::Amount { got: got() });
        }
        let amount: u32 = rest[..digits_len]
            .parse()
            .map_err(|_| TimeSpecError::Amount { got: got() })?;
        rest = &rest[digits_len..];
        let unit_len = rest.bytes().take_while(u8::is_ascii_alphabetic).count();
        let unit = Unit::parse(&rest[..unit_len]).ok_or_else(|| TimeSpecError::Unit {
            got: got(),
            unit: rest[..unit_len].to_owned(),
        })?;
        rest = &rest[unit_len..];
        offset = Some(Offset {
            negative: sign == '-',
            amount,
            unit,
        });
    }
    let mut snap = None;
    if let Some(after_at) = rest.strip_prefix('@') {
        let snap_len = after_at
            .bytes()
            .take_while(u8::is_ascii_alphanumeric)
            .count();
        let text = &after_at[..snap_len];
        let parsed = match text.strip_prefix('w') {
            Some(day) if day.len() == 1 && day.as_bytes()[0].is_ascii_digit() => {
                let d = day.as_bytes()[0] - b'0';
                (d <= 6).then_some(Snap::Weekday(d))
            }
            _ => Unit::parse(text).map(Snap::Unit),
        };
        snap = Some(parsed.ok_or_else(|| TimeSpecError::Snap {
            got: got(),
            snap: text.to_owned(),
        })?);
        rest = &after_at[snap_len..];
    }
    if !rest.is_empty() {
        return Err(TimeSpecError::Trailing {
            got: got(),
            rest: rest.to_owned(),
        });
    }
    Ok(Relative { offset, snap })
}

fn two_digits(s: &str, at: usize, why: &'static str, raw: &str) -> Result<u32, TimeSpecError> {
    s.get(at..at + 2)
        .filter(|d| d.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|d| d.parse().ok())
        .ok_or(TimeSpecError::Rfc3339 {
            got: raw.to_owned(),
            why,
        })
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
            if leap { 29 } else { 28 }
        }
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DDThh:mm:ss[.frac](Z|±hh:mm)` → epoch seconds. Fractions are
/// truncated; Splunk's bounds are whole seconds on this path.
fn parse_rfc3339(raw: &str, s: &str) -> Result<u64, TimeSpecError> {
    let bad = |why| TimeSpecError::Rfc3339 {
        got: raw.to_owned(),
        why,
    };
    let b = s.as_bytes();
    let year: i64 = s
        .get(0..4)
        .filter(|y| y.bytes().all(|c| c.is_ascii_digit()))
        .and_then(|y| y.parse().ok())
        .ok_or_else(|| bad("year"))?;
    if b.get(7) != Some(&b'-') {
        return Err(bad("date separators"));
    }
    let month = two_digits(s, 5, "month", raw)?;
    let day = two_digits(s, 8, "day", raw)?;
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return Err(bad("calendar date"));
    }
    if b.get(13) != Some(&b':') || b.get(16) != Some(&b':') {
        return Err(bad("time separators"));
    }
    let hour = two_digits(s, 11, "hour", raw)?;
    let minute = two_digits(s, 14, "minute", raw)?;
    let second = two_digits(s, 17, "second", raw)?;
    if hour > 23 || minute > 59 || second > 60 {
        return Err(bad("clock"));
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return Err(bad("fraction"));
        }
        rest = &frac[n..];
    }
    let offset_secs: i64 = match rest {
        "Z" | "z" => 0,
        tz if tz.len() == 6
            && matches!(tz.as_bytes()[0], b'+' | b'-')
            && tz.as_bytes()[3] == b':' =>
        {
            let oh = two_digits(tz, 1, "offset hour", raw)?;
            let om = two_digits(tz, 4, "offset minute", raw)?;
            if oh > 23 || om > 59 {
                return Err(bad("offset"));
            }
            let magnitude = i64::from(oh) * 3600 + i64::from(om) * 60;
            if tz.starts_with('-') {
                -magnitude
            } else {
                magnitude
            }
        }
        _ => return Err(bad("zone")),
    };
    let local = days_from_civil(year, month, day) * 86_400
        + i64::from(hour) * 3600
        + i64::from(minute) * 60
        + i64::from(second);
    u64::try_from(local - offset_secs).map_err(|_| TimeSpecError::OutOfRange {
        got: raw.to_owned(),
    })
}

/// The two bounds of a search. Both are required: an unbounded REST search
/// is an all-time search, and that default has no representation here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimeWindow {
    earliest: TimeSpec,
    latest: TimeSpec,
}

impl TimeWindow {
    /// Build a window, refusing one that provably runs backwards without a
    /// clock — both bounds absolute, `now` against `-1h`, `-1h` against
    /// `-2h`, `-90m` against `-1h` (see [`TimeSpec::ordered_without_a_clock`]).
    /// A window that cannot be ordered here — a snap, a mixed
    /// absolute/relative pair, a day against an hour — passes through:
    /// Splunk answers it, and a backwards one comes back as `empty`.
    pub fn new(earliest: TimeSpec, latest: TimeSpec) -> Result<Self, SplError> {
        if earliest.ordered_without_a_clock(&latest) == Some(Ordering::Greater) {
            return Err(SplError::InvertedWindow {
                earliest: earliest.to_string(),
                latest: latest.to_string(),
            });
        }
        Ok(Self { earliest, latest })
    }

    /// The lower bound, as `earliest_time`.
    #[must_use]
    pub const fn earliest(&self) -> TimeSpec {
        self.earliest
    }

    /// The upper bound, as `latest_time`.
    #[must_use]
    pub const fn latest(&self) -> TimeSpec {
        self.latest
    }
}

impl fmt::Display for TimeWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}]", self.earliest, self.latest)
    }
}

// ── the result cap ─────────────────────────────────────────────────────

/// A result limit in `1..=cap`, where `cap` is the deployment's configured
/// maximum. `0` — which Splunk's `count` reads as *everything* — has no
/// value here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResultCap {
    value: u32,
    cap: u32,
}

/// Why a limit was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapError {
    /// `0` asked for; Splunk would read it as *all*.
    #[error("limit 0 is not allowed (Splunk reads count=0 as ALL results); legal: 1..={cap}")]
    Zero {
        /// The configured maximum.
        cap: u32,
    },
    /// More than the deployment allows.
    #[error("limit {got} exceeds the configured maximum {cap}; legal: 1..={cap}")]
    OverCap {
        /// What was asked for.
        got: u32,
        /// The configured maximum.
        cap: u32,
    },
    /// The deployment itself allows nothing — a configuration error.
    #[error("the configured maximum is 0, so no limit can be legal — raise maxResults")]
    NoRoom,
}

impl CapError {
    fn legal(&self) -> String {
        let cap = match self {
            Self::Zero { cap } | Self::OverCap { cap, .. } => *cap,
            Self::NoRoom => 0,
        };
        let mut s = String::new();
        // Writing into a String cannot fail.
        let _ = write!(s, "1..={cap}");
        s
    }
}

impl ResultCap {
    /// `value` in `1..=cap`.
    pub const fn new(value: u32, cap: u32) -> Result<Self, CapError> {
        if cap == 0 {
            Err(CapError::NoRoom)
        } else if value == 0 {
            Err(CapError::Zero { cap })
        } else if value > cap {
            Err(CapError::OverCap { got: value, cap })
        } else {
            Ok(Self { value, cap })
        }
    }

    /// The limit.
    #[must_use]
    pub const fn get(&self) -> u32 {
        self.value
    }

    /// The maximum it was checked against.
    #[must_use]
    pub const fn cap(&self) -> u32 {
        self.cap
    }

    /// One row beyond the limit: the row the client asks Splunk for that
    /// the caller did not, so `truncated` is a fact the wire carries (a
    /// probe row came back) rather than a comparison two post-`head`
    /// counters can never make true. Rendered as `head`/`sort`'s count and
    /// sent as `max_count` / results `count`; the client drops the row
    /// before answering. `u64` so `u32::MAX` needs no special case.
    #[must_use]
    pub const fn probe(&self) -> u64 {
        self.value as u64 + 1
    }
}

impl fmt::Display for ResultCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

// ── the search ─────────────────────────────────────────────────────────

/// A sort stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sort {
    field: FieldName,
    descending: bool,
}

impl Sort {
    /// Sort by `field`, descending when asked.
    #[must_use]
    pub const fn new(field: FieldName, descending: bool) -> Self {
        Self { field, descending }
    }
}

/// A complete, renderable search. Built only through [`Search::new`] and
/// the builder methods, or from a [`SearchRequest`] via [`Search::build`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Search {
    index: IndexName,
    terms: Vec<Term>,
    window: TimeWindow,
    limit: ResultCap,
    stats_count_by: Vec<FieldName>,
    fields: Vec<FieldName>,
    sort: Option<Sort>,
}

impl Search {
    /// The three things a search cannot be without.
    #[must_use]
    pub const fn new(index: IndexName, window: TimeWindow, limit: ResultCap) -> Self {
        Self {
            index,
            terms: Vec::new(),
            window,
            limit,
            stats_count_by: Vec::new(),
            fields: Vec::new(),
            sort: None,
        }
    }

    /// Add a term.
    #[must_use]
    pub fn term(mut self, term: Term) -> Self {
        self.terms.push(term);
        self
    }

    /// `| stats count by …`.
    #[must_use]
    pub fn stats_count_by(mut self, fields: Vec<FieldName>) -> Self {
        self.stats_count_by = fields;
        self
    }

    /// `| fields …`.
    #[must_use]
    pub fn fields(mut self, fields: Vec<FieldName>) -> Self {
        self.fields = fields;
        self
    }

    /// `| sort …`.
    #[must_use]
    pub fn sort(mut self, sort: Sort) -> Self {
        self.sort = Some(sort);
        self
    }

    /// The time bounds, for `earliest_time` / `latest_time`.
    #[must_use]
    pub const fn window(&self) -> &TimeWindow {
        &self.window
    }

    /// The result cap, for `max_count` and `count`.
    #[must_use]
    pub const fn limit(&self) -> ResultCap {
        self.limit
    }

    /// Validate a raw request into a search, against the deployment's
    /// [`SearchBounds`]. Every failure is one [`SplError`] carrying its
    /// legal set. Counts and lengths are checked before anything is
    /// parsed, so an oversized request is refused at its cheapest.
    pub fn build(req: SearchRequest, bounds: SearchBounds) -> Result<Self, SplError> {
        SearchBounds::check(SearchBound::Terms, req.terms.len(), bounds.max_terms)?;
        for t in &req.terms {
            SearchBounds::check(SearchBound::TermBytes, t.value.len(), bounds.max_term_bytes)?;
        }
        SearchBounds::check(SearchBound::Fields, req.fields.len(), bounds.max_fields)?;
        SearchBounds::check(
            SearchBound::Fields,
            req.stats_count_by.len(),
            bounds.max_fields,
        )?;
        let index = IndexName::try_from(req.index.as_str())?;
        let earliest = TimeSpec::try_from(req.earliest.as_str())?;
        let latest = match req.latest.as_deref() {
            None => TimeSpec::Now,
            Some(l) => TimeSpec::try_from(l)?,
        };
        let window = TimeWindow::new(earliest, latest)?;
        let limit = ResultCap::new(req.limit, bounds.max_results)?;
        let mut search = Self::new(index, window, limit);
        for t in req.terms {
            let op = match t.op.as_deref() {
                None => Op::Eq,
                Some(o) => o.parse()?,
            };
            search = search.term(match t.field.as_deref() {
                None => Term::phrase(t.value),
                Some(f) => Term::fielded(FieldName::try_from(f)?, op, t.value),
            });
        }
        let names = |xs: Vec<String>| -> Result<Vec<FieldName>, SplError> {
            xs.iter().map(|x| FieldName::try_from(x.as_str())).collect()
        };
        search = search
            .stats_count_by(names(req.stats_count_by)?)
            .fields(names(req.fields)?);
        if let Some(s) = req.sort {
            search = search.sort(Sort::new(
                FieldName::try_from(s.field.as_str())?,
                s.descending,
            ));
        }
        Ok(search)
    }
}

/// **The renderer.** The only place SPL text is assembled.
///
/// `sort` and `head` carry [`ResultCap::probe`] — one more than the
/// caller's limit — so the client can tell "exactly `limit` matched" from
/// "more than `limit` matched" by whether the extra row came back.
impl fmt::Display for Search {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "search index={}", Quoted(self.index.as_str()))?;
        for term in &self.terms {
            write!(f, " {term}")?;
        }
        if !self.stats_count_by.is_empty() {
            f.write_str(" | stats count by")?;
            for field in &self.stats_count_by {
                write!(f, " {field}")?;
            }
        }
        if !self.fields.is_empty() {
            f.write_str(" | fields")?;
            for field in &self.fields {
                write!(f, " {field}")?;
            }
        }
        if let Some(sort) = &self.sort {
            write!(
                f,
                " | sort {} {}{}",
                self.limit.probe(),
                if sort.descending { '-' } else { '+' },
                sort.field
            )?;
        }
        write!(f, " | head {}", self.limit.probe())
    }
}

/// A search as a caller states it, before validation — plain strings, so
/// an MCP input or a CLI can map onto it without knowing the typed grammar.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SearchRequest {
    /// The index to search.
    pub index: String,
    /// Terms, fielded or free-text.
    pub terms: Vec<TermRequest>,
    /// Lower time bound. Required.
    pub earliest: String,
    /// Upper time bound. `None` ⇒ `now`.
    pub latest: Option<String>,
    /// Result limit. Required; checked against the configured maximum.
    pub limit: u32,
    /// `| fields …`.
    pub fields: Vec<String>,
    /// `| stats count by …`.
    pub stats_count_by: Vec<String>,
    /// `| sort …`.
    pub sort: Option<SortRequest>,
}

/// One term as stated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TermRequest {
    /// Field name; `None` ⇒ free-text phrase.
    pub field: Option<String>,
    /// One of [`Op::LEGAL`]; `None` ⇒ `eq`.
    pub op: Option<String>,
    /// The value, always quoted by the renderer.
    pub value: String,
}

/// A sort as stated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SortRequest {
    /// Field to sort on.
    pub field: String,
    /// Descending when true.
    pub descending: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx(s: &str) -> IndexName {
        IndexName::try_from(s).expect("legal index")
    }

    fn fld(s: &str) -> FieldName {
        FieldName::try_from(s).expect("legal field")
    }

    fn window(e: &str, l: &str) -> TimeWindow {
        TimeWindow::new(
            TimeSpec::try_from(e).expect("e"),
            TimeSpec::try_from(l).expect("l"),
        )
        .expect("window")
    }

    fn cap(n: u32) -> ResultCap {
        ResultCap::new(n, 1000).expect("in bounds")
    }

    /// Bounds wide enough that only the row under test can trip them.
    fn bounds(max_results: u32) -> SearchBounds {
        SearchBounds {
            max_results,
            max_terms: 32,
            max_term_bytes: 4_096,
            max_fields: 32,
        }
    }

    fn spec(s: &str) -> TimeSpec {
        TimeSpec::try_from(s).expect("legal time spec")
    }

    /// Count pipeline stages the way Splunk's lexer would: a `|` inside a
    /// double-quoted string (with `\"` and `\\` escapes) is not a stage break.
    fn stage_count(spl: &str) -> usize {
        let mut stages = 1;
        let mut in_quotes = false;
        let mut escaped = false;
        for ch in spl.chars() {
            match (in_quotes, escaped, ch) {
                (true, true, _) => escaped = false,
                (true, false, '\\') => escaped = true,
                (true, false, '"') => in_quotes = false,
                (false, _, '"') => in_quotes = true,
                (false, _, '|') => stages += 1,
                _ => {}
            }
        }
        assert!(!in_quotes, "unbalanced quotes in {spl:?}");
        stages
    }

    #[test]
    fn identifiers_follow_one_grammar() {
        for ok in ["main", "_internal", "a.b:c-d", "F1", "_"] {
            assert!(IndexName::try_from(ok).is_ok(), "{ok}");
            assert!(FieldName::try_from(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "1abc",
            "main\" | delete",
            "a b",
            "-x",
            "a/b",
            "ünïcode",
            "x*",
        ] {
            assert_eq!(
                IndexName::try_from(bad),
                Err(SplError::IllegalIndex { got: bad.into() })
            );
            assert_eq!(
                FieldName::try_from(bad),
                Err(SplError::IllegalField { got: bad.into() })
            );
        }
        let too_long = "a".repeat(IDENT_MAX_LEN + 1);
        assert!(IndexName::try_from(too_long.as_str()).is_err());
    }

    #[test]
    fn time_specs_that_are_accepted_render_canonically() {
        let table = [
            ("now", "now"),
            ("-15m", "-15m"),
            ("+1h", "+1h"),
            ("-24h@h", "-24h@h"),
            ("-1d@d", "-1d@d"),
            ("-7d@w0", "-7d@w0"),
            ("@d", "@d"),
            ("@w6", "@w6"),
            ("-3mon", "-3mon"),
            ("-1q@q", "-1q@q"),
            ("-2y", "-2y"),
            ("-30minutes", "-30m"),
            ("-1week@w", "-1w@w"),
            ("1757400000", "1757400000"),
            ("2026-09-09T12:00:00Z", "1788955200"),
            ("2026-09-09t12:00:00.250z", "1788955200"),
            ("2026-09-09T14:00:00+02:00", "1788955200"),
            ("2026-09-09T10:00:00-02:00", "1788955200"),
            ("1970-01-01T00:00:00Z", "0"),
            ("2000-03-01T00:00:00Z", "951868800"),
            ("  -15m  ", "-15m"),
        ];
        for (input, canonical) in table {
            let spec =
                TimeSpec::try_from(input).unwrap_or_else(|e| panic!("{input:?} must parse: {e}"));
            assert_eq!(spec.to_string(), canonical, "{input:?}");
        }
    }

    #[test]
    fn time_specs_that_are_refused_name_the_failure() {
        type Expect = fn(&TimeSpecError) -> bool;
        let table: [(&str, Expect); 14] = [
            ("", |e| matches!(e, TimeSpecError::Empty)),
            ("yesterday", |e| {
                matches!(e, TimeSpecError::Unrecognized { .. })
            }),
            ("15m", |e| matches!(e, TimeSpecError::Unrecognized { .. })),
            ("-15", |e| matches!(e, TimeSpecError::Unit { .. })),
            ("-15x", |e| matches!(e, TimeSpecError::Unit { .. })),
            ("-m", |e| matches!(e, TimeSpecError::Amount { .. })),
            ("-1234567890d", |e| {
                matches!(e, TimeSpecError::Amount { .. })
            }),
            ("-1d@", |e| matches!(e, TimeSpecError::Snap { .. })),
            ("-1d@w7", |e| matches!(e, TimeSpecError::Snap { .. })),
            ("-1d@d!", |e| matches!(e, TimeSpecError::Trailing { .. })),
            ("123", |e| matches!(e, TimeSpecError::EpochLength { .. })),
            ("12345678901", |e| {
                matches!(e, TimeSpecError::EpochLength { .. })
            }),
            ("2026-13-01T00:00:00Z", |e| {
                matches!(e, TimeSpecError::Rfc3339 { .. })
            }),
            ("2026-02-29T00:00:00Z", |e| {
                matches!(e, TimeSpecError::Rfc3339 { .. })
            }),
        ];
        for (input, expected) in table {
            let err = TimeSpec::try_from(input).expect_err(input);
            assert!(expected(&err), "{input:?} gave {err:?}");
        }
        // No zone, a bad zone, and a pre-epoch instant.
        assert!(matches!(
            TimeSpec::try_from("2026-09-09T12:00:00"),
            Err(TimeSpecError::Rfc3339 { why: "zone", .. })
        ));
        assert!(matches!(
            TimeSpec::try_from("2026-09-09T12:00:00+0200"),
            Err(TimeSpecError::Rfc3339 { why: "zone", .. })
        ));
        assert!(matches!(
            TimeSpec::try_from("1969-12-31T23:59:59Z"),
            Err(TimeSpecError::OutOfRange { .. })
        ));
        // Leap day on a leap year IS accepted.
        assert!(TimeSpec::try_from("2028-02-29T00:00:00Z").is_ok());
    }

    #[test]
    fn every_time_error_carries_the_legal_forms_through_spl_error() {
        let err: SplError = TimeSpec::try_from("soon").expect_err("refused").into();
        assert_eq!(err.legal().len(), TimeSpec::LEGAL_FORMS.len());
        assert_eq!(err.legal()[0], "now");
    }

    #[test]
    fn the_result_cap_admits_exactly_one_to_cap() {
        assert_eq!(ResultCap::new(0, 1000), Err(CapError::Zero { cap: 1000 }));
        assert_eq!(
            ResultCap::new(1001, 1000),
            Err(CapError::OverCap {
                got: 1001,
                cap: 1000
            })
        );
        assert_eq!(ResultCap::new(5, 0), Err(CapError::NoRoom));
        assert_eq!(ResultCap::new(1, 1000).map(|c| c.get()), Ok(1));
        assert_eq!(ResultCap::new(1000, 1000).map(|c| c.get()), Ok(1000));
        let legal = SplError::from(CapError::OverCap { got: 9, cap: 5 }).legal();
        assert_eq!(legal, vec!["1..=5".to_owned()]);
    }

    #[test]
    fn a_backwards_absolute_window_is_refused_and_mixed_windows_pass() {
        let err =
            TimeWindow::new(TimeSpec::Absolute(20), TimeSpec::Absolute(10)).expect_err("inverted");
        assert!(matches!(err, SplError::InvertedWindow { .. }));
        assert!(TimeWindow::new(TimeSpec::Absolute(10), TimeSpec::Absolute(10)).is_ok());
        assert!(TimeWindow::new(spec("-1h"), TimeSpec::Absolute(10)).is_ok());
        assert_eq!(window("-15m", "now").to_string(), "[-15m, now]");
    }

    /// A window that is backwards WITHOUT a clock is refused, so the caller
    /// reads `refused` (a malformed question) and never `empty` (a finding
    /// about a window that was never searched).
    #[test]
    fn a_window_that_is_provably_backwards_without_a_clock_is_refused() {
        for (earliest, latest) in [
            ("now", "-1h"),
            ("-0m", "-1h"),
            ("+1h", "now"),
            ("-1h", "-2h"),
            ("-1h", "-90m"),
            ("-30m", "-1h"),
            ("now", "-1d"),
            ("+1d", "now"),
        ] {
            let err = TimeWindow::new(spec(earliest), spec(latest))
                .err()
                .unwrap_or_else(|| panic!("[{earliest}, {latest}] must be refused"));
            assert!(
                matches!(err, SplError::InvertedWindow { .. }),
                "[{earliest}, {latest}] gave {err:?}"
            );
            assert_eq!(err.legal().len(), TimeSpec::LEGAL_FORMS.len());
        }
        // Ordered the right way, equal, or not orderable without a clock:
        // a snap, an absolute against a relative, a day against an hour.
        for (earliest, latest) in [
            ("-1h", "now"),
            ("-2h", "-1h"),
            ("-90m", "-1h"),
            ("-1h", "-1h"),
            ("-1h", "-60m"),
            ("now", "+1h"),
            ("-1d@d", "now"),
            ("now", "-1h@h"),
            ("-1d", "-25h"),
            ("-2d", "-1h"),
            ("1757400000", "-1h"),
        ] {
            assert!(
                TimeWindow::new(spec(earliest), spec(latest)).is_ok(),
                "[{earliest}, {latest}] must pass"
            );
        }
    }

    /// The probe: `sort`/`head` ask for one row past the limit, and the
    /// value is `u64` so the top of `u32` is still one more.
    #[test]
    fn the_probe_is_one_past_the_limit_even_at_the_top_of_u32() {
        assert_eq!(cap(1).probe(), 2);
        assert_eq!(cap(1000).probe(), 1001);
        let top = ResultCap::new(u32::MAX, u32::MAX).expect("in bounds");
        assert_eq!(top.probe(), u64::from(u32::MAX) + 1);
    }

    /// Every bound refuses by its YAML key, and the legal set names the
    /// maximum — so the operator knows what to raise and the agent what to
    /// shrink. Nothing is parsed before the counts are checked.
    #[test]
    fn every_search_bound_refuses_naming_its_key_and_maximum() {
        let ok = SearchRequest {
            index: "main".into(),
            earliest: "-1h".into(),
            limit: 1,
            ..SearchRequest::default()
        };
        let tight = SearchBounds {
            max_results: 10,
            max_terms: 2,
            max_term_bytes: 8,
            max_fields: 1,
        };
        assert!(Search::build(ok.clone(), tight).is_ok());

        let term = |v: &str| TermRequest {
            field: None,
            op: None,
            value: v.into(),
        };
        let cases: [(SearchRequest, SearchBound, usize, u32); 5] = [
            (
                SearchRequest {
                    terms: vec![term("a"), term("b"), term("c")],
                    ..ok.clone()
                },
                SearchBound::Terms,
                3,
                2,
            ),
            (
                SearchRequest {
                    terms: vec![term("123456789")],
                    ..ok.clone()
                },
                SearchBound::TermBytes,
                9,
                8,
            ),
            (
                SearchRequest {
                    fields: vec!["a".into(), "b".into()],
                    ..ok.clone()
                },
                SearchBound::Fields,
                2,
                1,
            ),
            (
                SearchRequest {
                    stats_count_by: vec!["a".into(), "b".into()],
                    ..ok.clone()
                },
                SearchBound::Fields,
                2,
                1,
            ),
            // Over the bound AND malformed: the bound refuses first, so a
            // megabyte of garbage is never parsed.
            (
                SearchRequest {
                    index: "ma in".into(),
                    terms: vec![term("123456789")],
                    ..ok.clone()
                },
                SearchBound::TermBytes,
                9,
                8,
            ),
        ];
        for (req, bound, got, max) in cases {
            let err = Search::build(req, tight).expect_err("over a bound");
            assert_eq!(
                err,
                SplError::OverBound { bound, got, max },
                "{bound}: {err}"
            );
            let msg = err.to_string();
            assert!(msg.contains(bound.key()), "{msg}");
            assert_eq!(err.legal().len(), 1);
            assert!(err.legal()[0].contains(bound.key()), "{:?}", err.legal());
            assert!(err.legal()[0].starts_with("at most "), "{:?}", err.legal());
        }
    }

    #[test]
    fn the_full_shape_renders_in_the_documented_order() {
        let s = Search::new(idx("main"), window("-15m", "now"), cap(100))
            .term(Term::fielded(fld("status"), Op::Eq, "500"))
            .term(Term::phrase("timeout"))
            .stats_count_by(vec![fld("host"), fld("source")])
            .fields(vec![fld("host"), fld("count")])
            .sort(Sort::new(fld("count"), true));
        assert_eq!(
            s.to_string(),
            "search index=\"main\" status=\"500\" \"timeout\" | stats count by host source | fields host count | sort 101 -count | head 101"
        );
        assert_eq!(stage_count(&s.to_string()), 5);
    }

    #[test]
    fn a_minimal_search_is_index_and_head_only() {
        let s = Search::new(idx("main"), window("-1h", "now"), cap(10));
        assert_eq!(s.to_string(), "search index=\"main\" | head 11");
        assert_eq!(stage_count(&s.to_string()), 2);
    }

    #[test]
    fn every_operator_renders_and_ascending_sort_uses_plus() {
        let s = Search::new(idx("i"), window("-1h", "now"), cap(7))
            .term(Term::fielded(fld("a"), Op::Ne, "x"))
            .term(Term::fielded(fld("b"), Op::Gt, "5"))
            .term(Term::fielded(fld("c"), Op::Lt, "-1.5"))
            .term(Term::fielded(fld("d"), Op::Ge, "abc"))
            .term(Term::fielded(fld("e"), Op::Le, "10"))
            .sort(Sort::new(fld("b"), false));
        assert_eq!(
            s.to_string(),
            "search index=\"i\" a!=\"x\" b>5 c<-1.5 d>=\"abc\" e<=10 | sort 8 +b | head 8"
        );
    }

    /// **The injection test.** A value carrying a pipeline stage, a quote, a
    /// backslash and a newline renders as ONE quoted literal: the stage
    /// count of the rendered SPL is exactly what the typed search declared.
    #[test]
    fn hostile_values_render_as_harmless_quoted_literals() {
        let hostile = "foo\" | delete\n| collect index=main \\ bar";
        let s = Search::new(idx("main"), window("-1h", "now"), cap(5))
            .term(Term::fielded(fld("msg"), Op::Eq, hostile))
            .term(Term::phrase("x\" | delete"))
            .term(Term::fielded(fld("n"), Op::Gt, "5 | delete"));
        let spl = s.to_string();
        assert_eq!(stage_count(&spl), 2, "only `search` and `head`: {spl}");
        assert!(
            spl.contains("msg=\"foo\\\" | delete\n| collect index=main \\\\ bar\""),
            "{spl}"
        );
        assert!(spl.contains(" \"x\\\" | delete\" "), "{spl}");
        // A non-numeric value under an ordering operator is quoted, not bare.
        assert!(spl.contains("n>\"5 | delete\""), "{spl}");
        assert!(spl.ends_with(" | head 6"));
    }

    #[test]
    fn only_strict_numeric_literals_render_bare_under_ordering() {
        for bare in ["5", "-5", "3.25", "-0.5", "0"] {
            assert!(is_numeric_literal(bare), "{bare}");
        }
        for quoted in ["", "-", ".5", "5.", "1e3", "0x10", "5 ", "+5", "1_000"] {
            assert!(!is_numeric_literal(quoted), "{quoted:?}");
        }
        // And equality NEVER renders bare, numeric or not.
        let s = Search::new(idx("i"), window("-1h", "now"), cap(1)).term(Term::fielded(
            fld("a"),
            Op::Eq,
            "5",
        ));
        assert!(s.to_string().contains("a=\"5\""));
    }

    #[test]
    fn build_validates_every_part_of_a_raw_request() {
        let req = SearchRequest {
            index: "main".into(),
            terms: vec![
                TermRequest {
                    field: Some("status".into()),
                    op: None,
                    value: "500".into(),
                },
                TermRequest {
                    field: None,
                    op: None,
                    value: "boom".into(),
                },
                TermRequest {
                    field: Some("n".into()),
                    op: Some("ge".into()),
                    value: "3".into(),
                },
            ],
            earliest: "-24h@h".into(),
            latest: None,
            limit: 50,
            fields: vec!["host".into()],
            stats_count_by: vec![],
            sort: Some(SortRequest {
                field: "host".into(),
                descending: true,
            }),
        };
        let s = Search::build(req.clone(), bounds(1000)).expect("builds");
        assert_eq!(
            s.to_string(),
            "search index=\"main\" status=\"500\" \"boom\" n>=3 | fields host | sort 51 -host | head 51"
        );
        assert_eq!(s.window().latest(), TimeSpec::Now, "latest defaults to now");
        assert_eq!(s.limit().get(), 50);

        let bad_index = SearchRequest {
            index: "ma in".into(),
            ..req.clone()
        };
        assert!(matches!(
            Search::build(bad_index, bounds(1000)),
            Err(SplError::IllegalIndex { .. })
        ));
        let bad_time = SearchRequest {
            earliest: "soon".into(),
            ..req.clone()
        };
        assert!(matches!(
            Search::build(bad_time, bounds(1000)),
            Err(SplError::Time(_))
        ));
        let bad_limit = SearchRequest {
            limit: 0,
            ..req.clone()
        };
        assert!(matches!(
            Search::build(bad_limit, bounds(1000)),
            Err(SplError::Limit(CapError::Zero { .. }))
        ));
        let over = SearchRequest {
            limit: 51,
            ..req.clone()
        };
        assert!(matches!(
            Search::build(over, bounds(50)),
            Err(SplError::Limit(CapError::OverCap { .. }))
        ));
        let bad_op = SearchRequest {
            terms: vec![TermRequest {
                field: Some("a".into()),
                op: Some("like".into()),
                value: "x".into(),
            }],
            ..req.clone()
        };
        assert!(matches!(
            Search::build(bad_op, bounds(1000)),
            Err(SplError::IllegalOp { .. })
        ));
        let bad_sort = SearchRequest {
            sort: Some(SortRequest {
                field: "a b".into(),
                descending: false,
            }),
            ..req
        };
        assert!(matches!(
            Search::build(bad_sort, bounds(1000)),
            Err(SplError::IllegalField { .. })
        ));
    }
}
