//! A small JSON Schema checker for command arguments.
//!
//! The registry's argument schemas (draft 2020-12, produced by `schemars`) only use a small
//! vocabulary, and the command handlers re-validate everything server side. This checker exists so
//! a script gets a precise error (`/limit: expected integer, got string`) before any round trip,
//! and so `Project.call` rejects typos in argument names. Supported keywords: `$ref` (local
//! `#/$defs/..`), `type` (string or list), `properties`, `required`, `additionalProperties`
//! (`false` or a schema), `items`, `enum`, `const`, `oneOf`, `anyOf`, `allOf`, `minimum`,
//! `maximum`, `format` for the integer widths, `pattern`, `minLength`, `maxLength`. Anything else
//! is ignored, never rejected.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use regex::Regex;
use serde_json::Value;

/// Why arguments do not satisfy a schema: a JSON pointer to the offending value and a reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {message}")]
pub struct SchemaError {
    /// JSON pointer of the value (`/` is the whole argument object).
    pub path: String,
    /// What is wrong with it.
    pub message: String,
}

/// Checks `value` against `schema`; the first problem found is returned.
pub fn validate(schema: &Value, value: &Value) -> Result<(), SchemaError> {
    let mut path = Vec::new();
    check(schema, schema, value, &mut path, 0)
}

const MAX_DEPTH: usize = 64;

fn pointer(path: &[String]) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        path.iter().fold(String::new(), |mut s, p| {
            s.push('/');
            s.push_str(p);
            s
        })
    }
}

fn err(path: &[String], message: impl Into<String>) -> SchemaError {
    SchemaError {
        path: pointer(path),
        message: message.into(),
    }
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn type_matches(ty: &str, v: &Value) -> bool {
    match ty {
        "null" => v.is_null(),
        "boolean" => v.is_boolean(),
        "integer" => match v {
            Value::Number(n) => {
                n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0)
            }
            _ => false,
        },
        "number" => v.is_number(),
        "string" => v.is_string(),
        "array" => v.is_array(),
        "object" => v.is_object(),
        _ => true,
    }
}

fn resolve<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let pointer = reference.strip_prefix('#')?;
    if pointer.is_empty() {
        return Some(root);
    }
    root.pointer(pointer)
}

fn cached_regex(pattern: &str) -> Option<Regex> {
    static CACHE: Mutex<Option<HashMap<String, Option<Regex>>>> = Mutex::new(None);
    let mut guard = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    guard
        .get_or_insert_with(HashMap::new)
        .entry(pattern.to_string())
        .or_insert_with(|| Regex::new(pattern).ok())
        .clone()
}

fn check(
    root: &Value,
    schema: &Value,
    value: &Value,
    path: &mut Vec<String>,
    depth: usize,
) -> Result<(), SchemaError> {
    if depth > MAX_DEPTH {
        return Err(err(path, "nested too deeply"));
    }
    let Some(obj) = schema.as_object() else {
        // `true` / `false` schemas and anything unexpected accept everything.
        return Ok(());
    };
    if let Some(r) = obj.get("$ref").and_then(Value::as_str) {
        match resolve(root, r) {
            Some(target) => check(root, target, value, path, depth + 1)?,
            None => return Err(err(path, format!("unresolvable schema reference {r}"))),
        }
    }
    if let Some(c) = obj.get("const")
        && c != value
    {
        return Err(err(path, format!("must be {c}")));
    }
    if let Some(Value::Array(options)) = obj.get("enum")
        && !options.contains(value)
    {
        return Err(err(path, format!("must be one of {}", list(options))));
    }
    match obj.get("type") {
        Some(Value::String(t)) if !type_matches(t, value) => {
            return Err(err(path, format!("expected {t}, got {}", type_name(value))));
        }
        Some(Value::Array(ts)) => {
            let names: Vec<&str> = ts.iter().filter_map(Value::as_str).collect();
            if !names.iter().any(|t| type_matches(t, value)) {
                return Err(err(
                    path,
                    format!("expected {}, got {}", names.join(" or "), type_name(value)),
                ));
            }
        }
        _ => {}
    }
    check_number(obj, value, path)?;
    check_string(obj, value, path)?;
    if let Some(items) = obj.get("items")
        && let Value::Array(values) = value
    {
        for (i, v) in values.iter().enumerate() {
            path.push(i.to_string());
            check(root, items, v, path, depth + 1)?;
            path.pop();
        }
    }
    if let Value::Object(map) = value {
        check_object(root, obj, map, path, depth)?;
    }
    check_combinators(root, obj, value, path, depth)
}

fn list(options: &[Value]) -> String {
    options
        .iter()
        .map(|o| match o {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn check_number(
    obj: &serde_json::Map<String, Value>,
    value: &Value,
    path: &[String],
) -> Result<(), SchemaError> {
    let Value::Number(n) = value else {
        return Ok(());
    };
    let as_f = n.as_f64().unwrap_or(0.0);
    if let Some(min) = obj.get("minimum").and_then(Value::as_f64)
        && as_f < min
    {
        return Err(err(path, format!("must be at least {min}")));
    }
    if let Some(max) = obj.get("maximum").and_then(Value::as_f64)
        && as_f > max
    {
        return Err(err(path, format!("must be at most {max}")));
    }
    let max_for_format = match obj.get("format").and_then(Value::as_str) {
        Some("uint8") => Some(f64::from(u8::MAX)),
        Some("uint16") => Some(f64::from(u16::MAX)),
        Some("uint32") => Some(f64::from(u32::MAX)),
        Some("uint64") => Some(u64::MAX as f64),
        _ => None,
    };
    if let Some(max) = max_for_format
        && as_f > max
    {
        return Err(err(path, "out of range for its integer width"));
    }
    if matches!(obj.get("format").and_then(Value::as_str), Some(f) if f.starts_with("uint"))
        && as_f < 0.0
    {
        return Err(err(path, "must not be negative"));
    }
    Ok(())
}

fn check_string(
    obj: &serde_json::Map<String, Value>,
    value: &Value,
    path: &[String],
) -> Result<(), SchemaError> {
    let Value::String(s) = value else {
        return Ok(());
    };
    let chars = s.chars().count() as u64;
    if let Some(min) = obj.get("minLength").and_then(Value::as_u64)
        && chars < min
    {
        return Err(err(path, format!("must have at least {min} characters")));
    }
    if let Some(max) = obj.get("maxLength").and_then(Value::as_u64)
        && chars > max
    {
        return Err(err(path, format!("must have at most {max} characters")));
    }
    if let Some(p) = obj.get("pattern").and_then(Value::as_str)
        && let Some(re) = cached_regex(p)
        && !re.is_match(s)
    {
        let hint = if p.starts_with("^0[xX]") {
            "must be an address such as 0x401000"
        } else {
            "has the wrong format"
        };
        return Err(err(path, hint));
    }
    Ok(())
}

fn check_object(
    root: &Value,
    obj: &serde_json::Map<String, Value>,
    map: &serde_json::Map<String, Value>,
    path: &mut Vec<String>,
    depth: usize,
) -> Result<(), SchemaError> {
    if let Some(Value::Array(required)) = obj.get("required") {
        for r in required.iter().filter_map(Value::as_str) {
            if !map.contains_key(r) {
                return Err(err(path, format!("missing required argument `{r}`")));
            }
        }
    }
    let props = obj.get("properties").and_then(Value::as_object);
    for (k, v) in map {
        path.push(k.clone());
        let result = match props.and_then(|p| p.get(k)) {
            Some(s) => check(root, s, v, path, depth + 1),
            None => match obj.get("additionalProperties") {
                Some(Value::Bool(false)) => {
                    let known: Vec<&str> = props
                        .map(|p| p.keys().map(String::as_str).collect())
                        .unwrap_or_default();
                    Err(err(
                        path,
                        if known.is_empty() {
                            "unknown argument (this command takes none)".to_string()
                        } else {
                            format!("unknown argument; expected one of {}", known.join(", "))
                        },
                    ))
                }
                Some(s @ Value::Object(_)) => check(root, s, v, path, depth + 1),
                _ => Ok(()),
            },
        };
        path.pop();
        result?;
    }
    Ok(())
}

fn check_combinators(
    root: &Value,
    obj: &serde_json::Map<String, Value>,
    value: &Value,
    path: &mut Vec<String>,
    depth: usize,
) -> Result<(), SchemaError> {
    if let Some(Value::Array(all)) = obj.get("allOf") {
        for s in all {
            check(root, s, value, path, depth + 1)?;
        }
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(Value::Array(options)) = obj.get(key) {
            let mut first_failure = None;
            let mut ok = false;
            for s in options {
                match check(root, s, value, path, depth + 1) {
                    Ok(()) => {
                        ok = true;
                        break;
                    }
                    Err(e) => {
                        first_failure.get_or_insert(e);
                    }
                }
            }
            if !ok {
                let consts: Vec<Value> = options
                    .iter()
                    .filter_map(|o| o.get("const").cloned())
                    .collect();
                if consts.len() == options.len() && !consts.is_empty() {
                    return Err(err(path, format!("must be one of {}", list(&consts))));
                }
                return Err(first_failure.unwrap_or_else(|| err(path, "matches no variant")));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema() -> Value {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["address", "kind"],
            "properties": {
                "address": {"$ref": "#/$defs/Hex64"},
                "kind": {"$ref": "#/$defs/Kind"},
                "limit": {"type": ["integer", "null"], "format": "uint32", "minimum": 0},
                "filter": {"type": ["string", "null"]},
                "versions": {"type": ["object", "null"], "additionalProperties": {"type": "integer", "minimum": 0}}
            },
            "$defs": {
                "Hex64": {"type": "string", "pattern": "^0[xX][0-9a-fA-F]{1,16}$"},
                "Kind": {"oneOf": [
                    {"type": "string", "const": "plate"},
                    {"type": "string", "const": "eol"}
                ]}
            }
        })
    }

    #[test]
    fn accepts_a_valid_object() {
        let v = json!({"address": "0x401000", "kind": "eol", "limit": 5, "filter": null});
        assert_eq!(validate(&schema(), &v), Ok(()));
    }

    #[test]
    fn reports_missing_and_unknown_arguments() {
        let e = validate(&schema(), &json!({"kind": "eol"})).unwrap_err();
        assert_eq!(e.path, "/");
        assert!(e.message.contains("`address`"), "{e}");
        let e = validate(
            &schema(),
            &json!({"address": "0x1", "kind": "eol", "limt": 3}),
        )
        .unwrap_err();
        assert_eq!(e.path, "/limt");
        assert!(e.message.contains("limit"), "{e}");
    }

    #[test]
    fn reports_types_with_a_pointer() {
        let e = validate(
            &schema(),
            &json!({"address": "0x1", "kind": "eol", "limit": "ten"}),
        )
        .unwrap_err();
        assert_eq!(e.path, "/limit");
        assert!(e.message.contains("integer or null"), "{e}");
        assert!(e.message.contains("string"), "{e}");
    }

    #[test]
    fn checks_patterns_ranges_and_enums() {
        let bad_addr = validate(&schema(), &json!({"address": "401000", "kind": "eol"}));
        assert!(bad_addr.unwrap_err().message.contains("0x401000"));
        let neg = validate(
            &schema(),
            &json!({"address": "0x1", "kind": "eol", "limit": -1}),
        );
        assert_eq!(neg.unwrap_err().path, "/limit");
        let huge = validate(
            &schema(),
            &json!({"address": "0x1", "kind": "eol", "limit": 5_000_000_000u64}),
        );
        assert!(huge.is_err());
        let kind = validate(&schema(), &json!({"address": "0x1", "kind": "nope"})).unwrap_err();
        assert!(kind.message.contains("plate, eol"), "{kind}");
    }

    #[test]
    fn checks_nested_additional_properties() {
        let e = validate(
            &schema(),
            &json!({"address": "0x1", "kind": "eol", "versions": {"a": -2}}),
        )
        .unwrap_err();
        assert_eq!(e.path, "/versions/a");
    }

    #[test]
    fn unknown_keywords_and_bad_refs_do_not_panic() {
        assert_eq!(validate(&json!({"x-weird": 1}), &json!(3)), Ok(()));
        assert!(validate(&json!({"$ref": "#/$defs/Missing"}), &json!(3)).is_err());
        assert_eq!(validate(&json!(true), &json!(3)), Ok(()));
    }

    #[test]
    fn every_registry_schema_accepts_an_empty_object_or_names_what_is_missing() {
        let registry = kraken_registry::Registry::standard();
        for entry in registry.iter() {
            match validate(entry.args_schema(), &json!({})) {
                Ok(()) => {}
                Err(e) => assert!(
                    e.message.contains("missing required"),
                    "{}: {e}",
                    entry.spec().name
                ),
            }
        }
    }
}
