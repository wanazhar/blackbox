//! Canonical JSON serialization for Blackbox protocol objects.
//!
//! Rules (normative for hashing and commitments):
//!
//! 1. **UTF-8** only. Invalid UTF-8 is rejected before canonicalization.
//! 2. **Object keys** are sorted lexicographically by Unicode code point order.
//! 3. **No insignificant whitespace** — compact form, no spaces after `:` / `,`.
//! 4. **Numbers** must be finite JSON numbers (no `NaN` / `Infinity`). Integers
//!    that fit in `i64`/`u64` are emitted without a fractional part; otherwise
//!    the shortest decimal that round-trips via `serde_json::Number`.
//! 5. **Strings** use JSON escaping for control chars; Unicode is not escaped
//!    beyond JSON requirements (non-ASCII left as UTF-8).
//! 6. **Arrays** preserve order (authoritative order is the logical array).
//! 7. **Null / bool** use JSON literals `null`, `true`, `false`.
//! 8. **Unknown fields** that are present are included in the canonical form
//!    (they participate in hashes). Dropping unknown fields is a consumer policy
//!    decision, not part of canonicalization.
//! 9. **Transport metadata** (socket peer, connection id, spool batch path)
//!    must never appear on protocol objects that are hashed.
//! 10. **Timestamps** that are hashed must be RFC 3339 UTC with `Z` suffix and
//!     fractional seconds only when non-zero; prefer millisecond precision when
//!     produced by Blackbox reference encoders (`chrono` default `to_rfc3339`).
//!
//! Two independently written encoders given the same logical object MUST produce
//! the same canonical byte sequence and therefore the same SHA-256 hash.

use std::collections::HashSet;
use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};

/// Algorithm identifier embedded in commitment docs.
pub const CANONICAL_HASH_ALG: &str = "sha256";

/// Errors raised while producing canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// Non-finite number (NaN / Infinity) is forbidden.
    NonFiniteNumber,
    /// Value is not valid JSON (parse failure).
    InvalidJson(String),
    /// Serialization failure.
    Serialize(String),
}

impl std::fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonFiniteNumber => {
                write!(f, "non-finite number is not allowed in canonical JSON")
            }
            Self::InvalidJson(m) => write!(f, "invalid JSON: {m}"),
            Self::Serialize(m) => write!(f, "serialize error: {m}"),
        }
    }
}

impl std::error::Error for CanonicalError {}

/// Canonical UTF-8 bytes of a `serde_json::Value`.
pub fn canonical_bytes(value: &serde_json::Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::with_capacity(256);
    write_canonical(value, &mut out)?;
    Ok(out)
}

/// Canonical UTF-8 string of a `serde_json::Value`.
pub fn canonical_string(value: &serde_json::Value) -> Result<String, CanonicalError> {
    let bytes = canonical_bytes(value)?;
    // Canonical form is always valid UTF-8 by construction.
    String::from_utf8(bytes).map_err(|e| CanonicalError::Serialize(e.to_string()))
}

/// SHA-256 hex digest of the canonical bytes of `value`.
pub fn canonical_hash(value: &serde_json::Value) -> Result<String, CanonicalError> {
    let bytes = canonical_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Canonicalize any `Serialize` value via `serde_json::Value`.
pub fn canonical_hash_of<T: serde::Serialize>(value: &T) -> Result<String, CanonicalError> {
    let v = serde_json::to_value(value).map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    canonical_hash(&v)
}

/// Canonical string of any `Serialize` value.
pub fn canonical_string_of<T: serde::Serialize>(value: &T) -> Result<String, CanonicalError> {
    let v = serde_json::to_value(value).map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    canonical_string(&v)
}

/// Parse raw JSON text, reject non-finite numbers, return canonical form.
pub fn canonicalize_raw_json(raw: &str) -> Result<String, CanonicalError> {
    let value = parse_json_strict(raw)?;
    canonical_string(&value)
}

/// Parse JSON without silently applying last-key-wins semantics.
///
/// Duplicate object keys are ambiguous hash inputs and therefore fail at any
/// nesting depth. `serde_json` also rejects invalid escapes, non-finite
/// numbers, trailing data, and invalid UTF-8 before values reach this API.
pub fn parse_json_strict(raw: &str) -> Result<serde_json::Value, CanonicalError> {
    serde_json::from_str::<UniqueValue>(raw)
        .map(|value| value.0)
        .map_err(|e| CanonicalError::InvalidJson(e.to_string()))
}

struct UniqueValue(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(serde_json::Value::Null))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_unit()
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(|number| UniqueValue(serde_json::Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite number is not valid JSON"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(serde_json::Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(serde_json::Value::String(value)))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate object key {key:?}"
                )));
            }
            let value = map.next_value::<UniqueValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueValue(serde_json::Value::Object(values)))
    }
}

fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => out.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => out.extend_from_slice(b"false"),
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(CanonicalError::NonFiniteNumber);
                }
            }
            // Prefer integer form when exact.
            if let Some(i) = n.as_i64() {
                out.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                out.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(f) = n.as_f64() {
                if f == 0.0 {
                    out.push(b'0');
                    return Ok(());
                }
                if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
                    out.extend_from_slice((f as i64).to_string().as_bytes());
                    return Ok(());
                }
                // Use serde_json's shortest round-trip representation.
                let s = serde_json::Number::from_f64(f)
                    .ok_or(CanonicalError::NonFiniteNumber)?
                    .to_string();
                out.extend_from_slice(s.as_bytes());
            } else {
                out.extend_from_slice(n.to_string().as_bytes());
            }
        }
        serde_json::Value::String(s) => write_string(s, out),
        serde_json::Value::Array(arr) => {
            out.push(b'[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        serde_json::Value::Object(map) => {
            // Sort keys by Unicode code point (byte-wise for UTF-8).
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                // Safe: key came from map.keys().
                write_canonical(&map[*key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br#"\\"#),
            '\u{08}' => out.extend_from_slice(br#"\b"#),
            '\u{0C}' => out.extend_from_slice(br#"\f"#),
            '\n' => out.extend_from_slice(br#"\n"#),
            '\r' => out.extend_from_slice(br#"\r"#),
            '\t' => out.extend_from_slice(br#"\t"#),
            c if (c as u32) < 0x20 => {
                let esc = format!("\\u{:04x}", c as u32);
                out.extend_from_slice(esc.as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                let encoded = c.encode_utf8(&mut buf);
                out.extend_from_slice(encoded.as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_independent() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(canonical_string(&a).unwrap(), canonical_string(&b).unwrap());
        assert_eq!(canonical_hash(&a).unwrap(), canonical_hash(&b).unwrap());
        assert_eq!(canonical_string(&a).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn nested_objects_sorted() {
        let v = json!({"z": {"y": 1, "x": 2}, "a": [3, 1]});
        assert_eq!(
            canonical_string(&v).unwrap(),
            r#"{"a":[3,1],"z":{"x":2,"y":1}}"#
        );
    }

    #[test]
    fn dual_encoder_identity() {
        // Simulate two encoders: map insertion order differs.
        let mut m1 = serde_json::Map::new();
        m1.insert("schema".into(), json!("blackbox.run/v1"));
        m1.insert("id".into(), json!("run-1"));
        m1.insert("status".into(), json!("succeeded"));

        let mut m2 = serde_json::Map::new();
        m2.insert("status".into(), json!("succeeded"));
        m2.insert("schema".into(), json!("blackbox.run/v1"));
        m2.insert("id".into(), json!("run-1"));

        let v1 = serde_json::Value::Object(m1);
        let v2 = serde_json::Value::Object(m2);
        assert_eq!(canonical_bytes(&v1).unwrap(), canonical_bytes(&v2).unwrap());
        assert_eq!(canonical_hash(&v1).unwrap().len(), 64);
    }

    #[test]
    fn raw_json_whitespace_normalized() {
        let raw = r#"{ "b" : 1, "a" : 2 }"#;
        assert_eq!(canonicalize_raw_json(raw).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn duplicate_keys_fail_at_every_depth() {
        for raw in [
            r#"{"a":1,"a":2}"#,
            r#"{"outer":{"a":1,"a":2}}"#,
            r#"[{"a":1,"a":2}]"#,
        ] {
            let error = canonicalize_raw_json(raw).unwrap_err().to_string();
            assert!(error.contains("duplicate object key"), "{error}");
        }
    }

    #[test]
    fn string_escaping() {
        let v = json!({"s": "a\"b\nc"});
        let c = canonical_string(&v).unwrap();
        assert_eq!(c, r#"{"s":"a\"b\nc"}"#);
    }

    #[test]
    fn integral_floats_and_negative_zero_normalize() {
        assert_eq!(canonicalize_raw_json("1.0").unwrap(), "1");
        assert_eq!(canonicalize_raw_json("1e3").unwrap(), "1000");
        assert_eq!(canonicalize_raw_json("-0.0").unwrap(), "0");
    }
}
