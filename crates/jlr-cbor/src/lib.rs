//! JLR-DCBOR/1: the deterministic CBOR profile used for every JLR signed record.
//!
//! The profile is the RFC 8949 section 4.2.1 "core deterministic encoding"
//! restricted further so that exactly one byte string represents each value:
//!
//! * integers, byte strings, text strings, arrays, maps, tags, `true`,
//!   `false` and `null` only; floating point, `undefined` and other simple
//!   values are rejected;
//! * every head uses the shortest possible argument;
//! * indefinite-length items are rejected;
//! * map keys are sorted by the bytewise lexicographic order of their
//!   encodings, and duplicate keys are rejected;
//! * text strings must be valid UTF-8;
//! * trailing bytes after the top-level item are rejected;
//! * nesting depth is bounded.
//!
//! The decoder checks every rule while parsing, so `decode(bytes)` succeeds
//! only if `encode(decode(bytes)) == bytes`. This crate has no dependencies
//! so that it can be audited on its own.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Maximum nesting depth accepted by [`decode`].
pub const MAX_DEPTH: usize = 32;

/// A decoded or constructed CBOR value in the JLR-DCBOR/1 data model.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Value {
    /// Unsigned integer (major type 0).
    Uint(u64),
    /// Negative integer (major type 1) holding `n` for the value `-1 - n`.
    Nint(u64),
    /// Byte string (major type 2).
    Bytes(Vec<u8>),
    /// UTF-8 text string (major type 3).
    Text(String),
    /// Array (major type 4).
    Array(Vec<Value>),
    /// Map (major type 5) kept in canonical key order.
    Map(Map),
    /// Tagged item (major type 6).
    Tag(u64, Box<Value>),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
}

/// A CBOR map whose entries are always held in canonical order.
///
/// Keys are ordered by the bytewise order of their deterministic encodings,
/// which is exactly the order RFC 8949 section 4.2.1 requires on the wire.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Map {
    entries: BTreeMap<Vec<u8>, (Value, Value)>,
}

impl fmt::Debug for Map {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

impl Map {
    /// Creates an empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an entry, rejecting a key that is already present.
    pub fn insert(&mut self, key: impl Into<Value>, value: impl Into<Value>) -> Result<(), Error> {
        let key = key.into();
        let encoded = encode(&key);
        if self.entries.contains_key(&encoded) {
            return Err(Error::DuplicateKey);
        }
        self.entries.insert(encoded, (key, value.into()));
        Ok(())
    }

    /// Builder form of [`Map::insert`] for keys known to be distinct.
    ///
    /// # Panics
    /// Panics when the key is already present, which is a programming error
    /// in the record encoder that calls it.
    #[must_use]
    pub fn with(mut self, key: impl Into<Value>, value: impl Into<Value>) -> Self {
        #[allow(clippy::expect_used)]
        self.insert(key, value).expect("duplicate key in map builder");
        self
    }

    /// Looks up the value stored under `key`.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.entries.get(&encode(key)).map(|(_, v)| v)
    }

    /// Looks up the value stored under an unsigned integer key.
    pub fn get_uint(&self, key: u64) -> Option<&Value> {
        self.get(&Value::Uint(key))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates over entries in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&Value, &Value)> {
        self.entries.values().map(|(k, v)| (k, v))
    }
}

/// Errors produced by the strict decoder or by map construction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// Input ended before the item was complete.
    Truncated,
    /// Bytes remain after the top-level item.
    TrailingBytes,
    /// An argument was not encoded in its shortest form.
    NonShortestArgument,
    /// Indefinite-length encoding was used.
    IndefiniteLength,
    /// Reserved additional-information value 28, 29 or 30.
    ReservedAdditionalInfo,
    /// Floating point, `undefined`, or an unassigned simple value.
    UnsupportedSimpleOrFloat,
    /// Text string was not valid UTF-8.
    InvalidUtf8,
    /// Map keys were not in canonical order.
    UnsortedMapKeys,
    /// A map contained the same key twice.
    DuplicateKey,
    /// Nesting exceeded [`MAX_DEPTH`].
    TooDeep,
    /// A declared length cannot fit in the remaining input.
    LengthExceedsInput,
    /// Schema-level error: the value had the wrong type.
    Type {
        /// What the schema expected.
        expected: &'static str,
    },
    /// Schema-level error: a required map field was absent.
    MissingField(u64),
    /// Schema-level error: a map contained a field the schema does not know.
    UnknownField(String),
    /// Schema-level error: an integer was outside the permitted range.
    OutOfRange,
    /// Schema-level error: a value was syntactically valid but not allowed.
    Invalid(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated => write!(f, "truncated CBOR input"),
            Error::TrailingBytes => write!(f, "trailing bytes after CBOR item"),
            Error::NonShortestArgument => write!(f, "non-shortest CBOR argument"),
            Error::IndefiniteLength => write!(f, "indefinite-length CBOR item"),
            Error::ReservedAdditionalInfo => write!(f, "reserved CBOR additional information"),
            Error::UnsupportedSimpleOrFloat => write!(f, "float or unsupported simple value"),
            Error::InvalidUtf8 => write!(f, "text string is not valid UTF-8"),
            Error::UnsortedMapKeys => write!(f, "map keys are not in canonical order"),
            Error::DuplicateKey => write!(f, "duplicate map key"),
            Error::TooDeep => write!(f, "CBOR nesting too deep"),
            Error::LengthExceedsInput => write!(f, "declared length exceeds input"),
            Error::Type { expected } => write!(f, "wrong type: expected {expected}"),
            Error::MissingField(k) => write!(f, "missing required field {k}"),
            Error::UnknownField(k) => write!(f, "unknown field {k}"),
            Error::OutOfRange => write!(f, "integer out of range"),
            Error::Invalid(what) => write!(f, "invalid value: {what}"),
        }
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg < 24 {
        out.push(mt | arg as u8);
    } else if arg <= u64::from(u8::MAX) {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= u64::from(u16::MAX) {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= u64::from(u32::MAX) {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

fn encode_into(out: &mut Vec<u8>, v: &Value) {
    match v {
        Value::Uint(n) => write_head(out, 0, *n),
        Value::Nint(n) => write_head(out, 1, *n),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            write_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            write_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(out, item);
            }
        }
        Value::Map(m) => {
            write_head(out, 5, m.len() as u64);
            for (encoded_key, (_, value)) in &m.entries {
                out.extend_from_slice(encoded_key);
                encode_into(out, value);
            }
        }
        Value::Tag(tag, inner) => {
            write_head(out, 6, *tag);
            encode_into(out, inner);
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

/// Encodes a value in JLR-DCBOR/1 deterministic form.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(&mut out, v);
    out
}

// ---------------------------------------------------------------------------
// Strict decoding
// ---------------------------------------------------------------------------

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.remaining() {
            return Err(Error::Truncated);
        }
        let s = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    /// Reads a head and returns `(major, additional_info, argument)`.
    fn head(&mut self) -> Result<(u8, u8, u64), Error> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let ai = initial & 0x1f;
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 && major != 7 {
                    return Err(Error::NonShortestArgument);
                }
                v
            }
            25 => {
                let b = self.take(2)?;
                let v = u64::from(u16::from_be_bytes([b[0], b[1]]));
                if v <= u64::from(u8::MAX) && major != 7 {
                    return Err(Error::NonShortestArgument);
                }
                v
            }
            26 => {
                let b = self.take(4)?;
                let v = u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                if v <= u64::from(u16::MAX) && major != 7 {
                    return Err(Error::NonShortestArgument);
                }
                v
            }
            27 => {
                let b = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                let v = u64::from_be_bytes(a);
                if v <= u64::from(u32::MAX) && major != 7 {
                    return Err(Error::NonShortestArgument);
                }
                v
            }
            28..=30 => return Err(Error::ReservedAdditionalInfo),
            _ => return Err(Error::IndefiniteLength),
        };
        Ok((major, ai, arg))
    }

    fn length(&self, arg: u64) -> Result<usize, Error> {
        let len = usize::try_from(arg).map_err(|_| Error::LengthExceedsInput)?;
        if len > self.remaining() {
            return Err(Error::LengthExceedsInput);
        }
        Ok(len)
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        let (major, ai, arg) = self.head()?;
        match major {
            0 => Ok(Value::Uint(arg)),
            1 => Ok(Value::Nint(arg)),
            2 => {
                let len = self.length(arg)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.length(arg)?;
                let raw = self.take(len)?;
                let s = std::str::from_utf8(raw).map_err(|_| Error::InvalidUtf8)?;
                Ok(Value::Text(s.to_owned()))
            }
            4 => {
                // Every item occupies at least one byte, so the count is
                // bounded by the remaining input before allocating.
                let count = self.length(arg)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let count = self.length(arg)?;
                let mut map = Map::new();
                let mut previous: Option<&'a [u8]> = None;
                for _ in 0..count {
                    let start = self.pos;
                    let key = self.value(depth + 1)?;
                    let key_bytes = &self.input[start..self.pos];
                    if let Some(prev) = previous {
                        match prev.cmp(key_bytes) {
                            std::cmp::Ordering::Less => {}
                            std::cmp::Ordering::Equal => return Err(Error::DuplicateKey),
                            std::cmp::Ordering::Greater => return Err(Error::UnsortedMapKeys),
                        }
                    }
                    previous = Some(key_bytes);
                    let value = self.value(depth + 1)?;
                    map.entries.insert(key_bytes.to_vec(), (key, value));
                }
                Ok(Value::Map(map))
            }
            6 => {
                let inner = self.value(depth + 1)?;
                Ok(Value::Tag(arg, Box::new(inner)))
            }
            _ => match ai {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(Error::UnsupportedSimpleOrFloat),
            },
        }
    }
}

/// Decodes exactly one JLR-DCBOR/1 item, rejecting any non-canonical form.
pub fn decode(input: &[u8]) -> Result<Value, Error> {
    let mut d = Decoder { input, pos: 0 };
    let v = d.value(0)?;
    if d.pos != input.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// Conversions and accessors
// ---------------------------------------------------------------------------

impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::Uint(n)
    }
}
impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Value::Uint(u64::from(n))
    }
}
impl From<u16> for Value {
    fn from(n: u16) -> Self {
        Value::Uint(u64::from(n))
    }
}
impl From<u8> for Value {
    fn from(n: u8) -> Self {
        Value::Uint(u64::from(n))
    }
}
impl From<i64> for Value {
    fn from(n: i64) -> Self {
        if n >= 0 {
            Value::Uint(n as u64)
        } else {
            // -1 - m = n  =>  m = -1 - n = !n for two's complement.
            Value::Nint(!(n as u64))
        }
    }
}
impl From<i32> for Value {
    fn from(n: i32) -> Self {
        Value::from(i64::from(n))
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Text(s.to_owned())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Text(s)
    }
}
impl From<&String> for Value {
    fn from(s: &String) -> Self {
        Value::Text(s.clone())
    }
}
impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self {
        Value::Bytes(b)
    }
}
impl From<&[u8]> for Value {
    fn from(b: &[u8]) -> Self {
        Value::Bytes(b.to_vec())
    }
}
impl<const N: usize> From<[u8; N]> for Value {
    fn from(b: [u8; N]) -> Self {
        Value::Bytes(b.to_vec())
    }
}
impl<const N: usize> From<&[u8; N]> for Value {
    fn from(b: &[u8; N]) -> Self {
        Value::Bytes(b.to_vec())
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<Map> for Value {
    fn from(m: Map) -> Self {
        Value::Map(m)
    }
}
impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Self {
        Value::Array(a)
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(o: Option<T>) -> Self {
        match o {
            Some(v) => v.into(),
            None => Value::Null,
        }
    }
}

impl Value {
    /// Returns the unsigned integer or a type error.
    pub fn as_u64(&self) -> Result<u64, Error> {
        match self {
            Value::Uint(n) => Ok(*n),
            _ => Err(Error::Type { expected: "unsigned integer" }),
        }
    }

    /// Returns the integer as `i64` when it fits.
    pub fn as_i64(&self) -> Result<i64, Error> {
        match self {
            Value::Uint(n) => i64::try_from(*n).map_err(|_| Error::OutOfRange),
            Value::Nint(n) => {
                let m = i64::try_from(*n).map_err(|_| Error::OutOfRange)?;
                Ok(-1 - m)
            }
            _ => Err(Error::Type { expected: "integer" }),
        }
    }

    /// Returns a `u32`, rejecting larger values.
    pub fn as_u32(&self) -> Result<u32, Error> {
        u32::try_from(self.as_u64()?).map_err(|_| Error::OutOfRange)
    }

    /// Returns a `u16`, rejecting larger values.
    pub fn as_u16(&self) -> Result<u16, Error> {
        u16::try_from(self.as_u64()?).map_err(|_| Error::OutOfRange)
    }

    /// Returns a `u8`, rejecting larger values.
    pub fn as_u8(&self) -> Result<u8, Error> {
        u8::try_from(self.as_u64()?).map_err(|_| Error::OutOfRange)
    }

    /// Returns the byte string contents.
    pub fn as_bytes(&self) -> Result<&[u8], Error> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(Error::Type { expected: "byte string" }),
        }
    }

    /// Returns a fixed-size byte string.
    pub fn as_byte_array<const N: usize>(&self) -> Result<[u8; N], Error> {
        let b = self.as_bytes()?;
        <[u8; N]>::try_from(b).map_err(|_| Error::Invalid("byte string has wrong length"))
    }

    /// Returns the text string contents.
    pub fn as_text(&self) -> Result<&str, Error> {
        match self {
            Value::Text(s) => Ok(s),
            _ => Err(Error::Type { expected: "text string" }),
        }
    }

    /// Returns the array items.
    pub fn as_array(&self) -> Result<&[Value], Error> {
        match self {
            Value::Array(a) => Ok(a),
            _ => Err(Error::Type { expected: "array" }),
        }
    }

    /// Returns the map.
    pub fn as_map(&self) -> Result<&Map, Error> {
        match self {
            Value::Map(m) => Ok(m),
            _ => Err(Error::Type { expected: "map" }),
        }
    }

    /// Returns the boolean.
    pub fn as_bool(&self) -> Result<bool, Error> {
        match self {
            Value::Bool(b) => Ok(*b),
            _ => Err(Error::Type { expected: "bool" }),
        }
    }

    /// Returns the tagged content when the tag number matches.
    pub fn as_tag(&self, expected: u64) -> Result<&Value, Error> {
        match self {
            Value::Tag(t, inner) if *t == expected => Ok(inner),
            _ => Err(Error::Type { expected: "tagged item" }),
        }
    }

    /// Whether the value is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Renders RFC 8949 section 8 diagnostic notation for humans.
    ///
    /// The rendering is informative only and is never signed or parsed.
    pub fn diag(&self) -> String {
        let mut s = String::new();
        diag_into(&mut s, self);
        s
    }
}

fn diag_into(s: &mut String, v: &Value) {
    use std::fmt::Write as _;
    match v {
        Value::Uint(n) => {
            let _ = write!(s, "{n}");
        }
        Value::Nint(n) => {
            let _ = write!(s, "-{}", u128::from(*n) + 1);
        }
        Value::Bytes(b) => {
            s.push_str("h'");
            for byte in b {
                let _ = write!(s, "{byte:02x}");
            }
            s.push('\'');
        }
        Value::Text(t) => {
            s.push('"');
            for c in t.chars() {
                match c {
                    '"' => s.push_str("\\\""),
                    '\\' => s.push_str("\\\\"),
                    c if c.is_control() => {
                        let _ = write!(s, "\\u{:04x}", c as u32);
                    }
                    c => s.push(c),
                }
            }
            s.push('"');
        }
        Value::Array(items) => {
            s.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                diag_into(s, item);
            }
            s.push(']');
        }
        Value::Map(m) => {
            s.push('{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                diag_into(s, k);
                s.push_str(": ");
                diag_into(s, v);
            }
            s.push('}');
        }
        Value::Tag(t, inner) => {
            let _ = write!(s, "{t}(");
            diag_into(s, inner);
            s.push(')');
        }
        Value::Bool(b) => {
            let _ = write!(s, "{b}");
        }
        Value::Null => s.push_str("null"),
    }
}

// ---------------------------------------------------------------------------
// Schema helpers
// ---------------------------------------------------------------------------

/// Reads a record map with integer keys and rejects fields it was not asked
/// about, so that unknown or misspelled fields can never be silently ignored.
#[derive(Debug)]
pub struct Fields<'a> {
    map: &'a Map,
    used: BTreeSet<u64>,
}

impl<'a> Fields<'a> {
    /// Starts reading a map-typed value.
    pub fn new(v: &'a Value) -> Result<Self, Error> {
        Ok(Self { map: v.as_map()?, used: BTreeSet::new() })
    }

    /// Returns a required field.
    pub fn req(&mut self, key: u64) -> Result<&'a Value, Error> {
        self.used.insert(key);
        self.map.get_uint(key).ok_or(Error::MissingField(key))
    }

    /// Returns an optional field; an explicit `null` counts as absent.
    pub fn opt(&mut self, key: u64) -> Option<&'a Value> {
        self.used.insert(key);
        self.map.get_uint(key).filter(|v| !v.is_null())
    }

    /// Fails if the map holds any key that was not read.
    pub fn finish(self) -> Result<(), Error> {
        for (k, _) in self.map.iter() {
            match k {
                Value::Uint(n) if self.used.contains(n) => {}
                other => return Err(Error::UnknownField(other.diag())),
            }
        }
        Ok(())
    }
}

/// Types with a canonical JLR-DCBOR/1 representation.
pub trait Cbor: Sized {
    /// Converts to the data model.
    fn to_value(&self) -> Value;
    /// Parses from the data model, rejecting unknown fields.
    fn from_value(v: &Value) -> Result<Self, Error>;

    /// Encodes to canonical bytes.
    fn to_cbor(&self) -> Vec<u8> {
        encode(&self.to_value())
    }

    /// Strictly decodes canonical bytes.
    ///
    /// After parsing, the value is encoded again and must reproduce the input
    /// exactly, so a record has exactly one accepted byte representation even
    /// when its schema has optional fields.
    fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let parsed = Self::from_value(&decode(bytes)?)?;
        if parsed.to_cbor() != bytes {
            return Err(Error::Invalid("record is not in canonical form"));
        }
        Ok(parsed)
    }
}

macro_rules! cbor_uint {
    ($($t:ty => $get:ident),*) => {$(
        impl Cbor for $t {
            fn to_value(&self) -> Value { Value::Uint(u64::from(*self)) }
            fn from_value(v: &Value) -> Result<Self, Error> { v.$get() }
        }
    )*};
}
cbor_uint!(u16 => as_u16, u32 => as_u32, u64 => as_u64);

impl Cbor for i64 {
    fn to_value(&self) -> Value {
        Value::from(*self)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        v.as_i64()
    }
}
impl Cbor for bool {
    fn to_value(&self) -> Value {
        Value::Bool(*self)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        v.as_bool()
    }
}
impl Cbor for String {
    fn to_value(&self) -> Value {
        Value::Text(self.clone())
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        v.as_text().map(str::to_owned)
    }
}
/// Byte strings.
impl Cbor for Vec<u8> {
    fn to_value(&self) -> Value {
        Value::Bytes(self.clone())
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        v.as_bytes().map(<[u8]>::to_vec)
    }
}
impl<const N: usize> Cbor for [u8; N] {
    fn to_value(&self) -> Value {
        Value::Bytes(self.to_vec())
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        v.as_byte_array::<N>()
    }
}
/// Arrays of any encodable item other than `u8` (which is a byte string).
impl<T: Cbor> Cbor for Vec<T> {
    fn to_value(&self) -> Value {
        Value::Array(self.iter().map(Cbor::to_value).collect())
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        v.as_array()?.iter().map(T::from_value).collect()
    }
}

/// A schema field: required as-is, or optional when wrapped in [`Option`].
///
/// `None` is omitted from the encoding rather than written as `null`.
pub trait Field: Sized {
    /// Writes the field into a map under `key`.
    fn put(&self, map: &mut Map, key: u64);
    /// Reads the field from a record being parsed.
    fn get(fields: &mut Fields<'_>, key: u64) -> Result<Self, Error>;
}

impl<T: Cbor> Field for T {
    fn put(&self, map: &mut Map, key: u64) {
        // Keys inside a record schema are distinct by construction.
        let _ = map.insert(key, self.to_value());
    }
    fn get(fields: &mut Fields<'_>, key: u64) -> Result<Self, Error> {
        T::from_value(fields.req(key)?)
    }
}

impl<T: Cbor> Field for Option<T> {
    fn put(&self, map: &mut Map, key: u64) {
        if let Some(v) = self {
            let _ = map.insert(key, v.to_value());
        }
    }
    fn get(fields: &mut Fields<'_>, key: u64) -> Result<Self, Error> {
        fields.opt(key).map(T::from_value).transpose()
    }
}

/// Declares a record struct with integer-keyed CBOR map encoding.
///
/// ```ignore
/// jlr_cbor::record! {
///     /// Doc comment.
///     #[derive(Clone, Debug, PartialEq, Eq)]
///     pub struct Example { 1 => name: String, 2 => size: u64, 3 => note: Option<String> }
/// }
/// ```
#[macro_export]
macro_rules! record {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $( $(#[$fmeta:meta])* $key:literal => $field:ident : $ty:ty ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $( $(#[$fmeta])* pub $field: $ty ),*
        }

        impl $crate::Cbor for $name {
            fn to_value(&self) -> $crate::Value {
                let mut map = $crate::Map::new();
                $( $crate::Field::put(&self.$field, &mut map, $key); )*
                $crate::Value::Map(map)
            }

            fn from_value(v: &$crate::Value) -> ::core::result::Result<Self, $crate::Error> {
                let mut fields = $crate::Fields::new(v)?;
                $( let $field = <$ty as $crate::Field>::get(&mut fields, $key)?; )*
                fields.finish()?;
                Ok(Self { $( $field ),* })
            }
        }
    };
}

/// Encodes a slice of items as a CBOR array.
pub fn array_of<T: Cbor>(items: &[T]) -> Value {
    Value::Array(items.iter().map(Cbor::to_value).collect())
}

/// Decodes a CBOR array into items.
pub fn vec_of<T: Cbor>(v: &Value) -> Result<Vec<T>, Error> {
    v.as_array()?.iter().map(T::from_value).collect()
}

/// Decodes a CBOR array of text strings.
pub fn text_vec(v: &Value) -> Result<Vec<String>, Error> {
    v.as_array()?.iter().map(|x| x.as_text().map(str::to_owned)).collect()
}

/// Encodes a slice of strings as a CBOR array of text strings.
pub fn text_array<S: AsRef<str>>(items: &[S]) -> Value {
    Value::Array(items.iter().map(|s| Value::Text(s.as_ref().to_owned())).collect())
}

#[cfg(test)]
mod tests;
