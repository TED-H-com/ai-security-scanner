//! Bounded product sidecars and native values; duplicate keys are never erased.
use crate::error::{AppError, AppResult};
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::cell::Cell;
use std::fmt;

struct Seed<'a> {
    depth: usize,
    remaining: &'a Cell<usize>,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > 64 || self.remaining.get() == 0 {
            return Err(D::Error::custom("JSON bounds exceeded"));
        }
        self.remaining.set(self.remaining.get() - 1);
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("bounded JSON")
    }
    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        if self.depth >= 64 {
            return Err(A::Error::custom("depth limit"));
        }
        let mut values = Vec::new();
        while let Some(value) = access.next_element_seed(Seed {
            depth: self.depth + 1,
            remaining: self.remaining,
        })? {
            if values.len() >= 10_000 {
                return Err(A::Error::custom("array limit"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
        if self.depth >= 64 {
            return Err(A::Error::custom("depth limit"));
        }
        let mut values = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if values.len() >= 1000 || values.contains_key(&key) {
                return Err(A::Error::custom("duplicate key or object limit"));
            }
            let value = access.next_value_seed(Seed {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
pub(super) fn parse(bytes: &[u8]) -> AppResult<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let remaining = Cell::new(500_000);
    let value = Seed {
        depth: 0,
        remaining: &remaining,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| {
        AppError::InvalidRequest(
            "Cloudflare bundle JSON is invalid, ambiguous or exceeds structural limits".into(),
        )
    })?;
    deserializer.end().map_err(|_| {
        AppError::InvalidRequest("Cloudflare bundle JSON contains trailing data".into())
    })?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_duplicate_keys_depth_and_invalid_unicode_are_rejected() {
        for input in [
            br#"{"a":{"x":1,"\u0078":2}}"#.as_slice(),
            br#"{"a":"\ud800"}"#,
            b"[] false",
            b"\xff",
        ] {
            assert!(parse(input).is_err());
        }
        assert!(parse(format!("{}0{}", "[".repeat(66), "]".repeat(66)).as_bytes()).is_err());
        assert_eq!(
            parse(br#"{"payload":"{\"x\":1,\"x\":2}"}"#).unwrap()["payload"],
            "{\"x\":1,\"x\":2}"
        );
    }
}
