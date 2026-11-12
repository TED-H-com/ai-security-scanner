//! Focused structural validation of the additive framework source-audit schema.
use serde_json::Value;

pub(super) fn validate(root: &Value, schema: &Value, value: &Value) -> Result<(), String> {
    if let Some(reference) = schema["$ref"].as_str() {
        return validate(
            root,
            root.pointer(reference.strip_prefix('#').unwrap()).unwrap(),
            value,
        );
    }
    if let Some(allowed) = schema["enum"].as_array()
        && !allowed.contains(value)
    {
        return Err(format!("enum: {value}"));
    }
    if let Some(expected) = schema.get("const")
        && value != expected
    {
        return Err(format!("const: {value}"));
    }
    if let Some(kind) = schema.get("type") {
        let kinds = kind
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![kind.clone()]);
        if !kinds.iter().any(|kind| match kind.as_str().unwrap() {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            other => panic!("unhandled type {other}"),
        }) {
            return Err(format!("type: {value}"));
        }
    }
    if let Some(min) = schema["minimum"].as_i64()
        && value.as_i64().is_some_and(|n| n < min)
    {
        return Err("minimum".into());
    }
    if let Some(fields) = value.as_object() {
        for required in schema["required"].as_array().into_iter().flatten() {
            if !fields.contains_key(required.as_str().unwrap()) {
                return Err(format!("missing {required}"));
            }
        }
        for (key, child) in fields {
            if let Some(property) = schema["properties"].get(key) {
                validate(root, property, child).map_err(|e| format!("{key}: {e}"))?;
            } else if schema["additionalProperties"] == false {
                return Err(format!("unexpected {key}"));
            } else if schema["additionalProperties"].is_object() {
                validate(root, &schema["additionalProperties"], child)?;
            }
        }
    }
    if let Some(items) = value.as_array() {
        if schema["minItems"]
            .as_u64()
            .is_some_and(|n| items.len() < n as usize)
        {
            return Err("minItems".into());
        }
        if schema["items"].is_object() {
            for item in items {
                validate(root, &schema["items"], item)?;
            }
        }
    }
    Ok(())
}
