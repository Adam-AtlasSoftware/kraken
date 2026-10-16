//! CLI flags derived from a command's args JSON Schema.

use kraken_proto::{ErrorCode, ProtoError};
use serde_json::{Map, Number, Value};

/// Flag names the CLI reserves for itself.
pub const RESERVED: &[&str] = &[
    "help",
    "version",
    "json",
    "project",
    "yes",
    "args-json",
    "no-wait",
];

/// How a flag's text is turned into a JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagKind {
    /// A JSON string.
    Str,
    /// A JSON integer.
    Int,
    /// A JSON number.
    Num,
    /// A JSON boolean (`--flag`, `--flag true`, `--flag false`).
    Bool,
    /// A JSON string restricted to these values.
    Enum(Vec<String>),
    /// Any other JSON value, written as JSON text.
    Json,
}

impl FlagKind {
    /// Short name for help text and `kraken commands`.
    pub fn label(&self) -> &'static str {
        match self {
            FlagKind::Str => "string",
            FlagKind::Int => "integer",
            FlagKind::Num => "number",
            FlagKind::Bool => "boolean",
            FlagKind::Enum(_) => "enum",
            FlagKind::Json => "json",
        }
    }
}

/// One flag of a subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagSpec {
    /// Property name in the args object (snake_case).
    pub prop: String,
    /// Flag name without dashes (kebab-case).
    pub flag: String,
    /// Value kind.
    pub kind: FlagKind,
    /// Description from the schema.
    pub help: String,
    /// Whether the schema lists the property as required.
    pub required: bool,
}

/// `snake_case` to `kebab-case`.
pub fn kebab(name: &str) -> String {
    name.replace('_', "-")
}

fn defs(root: &Value) -> Option<&Map<String, Value>> {
    root.get("$defs")
        .or_else(|| root.get("definitions"))
        .and_then(Value::as_object)
}

/// Follows `$ref`s into `$defs` (a few levels); the description of the referencing node wins.
fn resolve(root: &Value, node: &Value) -> Value {
    let mut cur = node.clone();
    for _ in 0..8 {
        let Some(target) = cur.get("$ref").and_then(Value::as_str) else {
            break;
        };
        let name = target.rsplit('/').next().unwrap_or(target);
        let Some(def) = defs(root).and_then(|d| d.get(name)) else {
            break;
        };
        let mut merged = def.clone();
        if let (Some(m), Some(o)) = (merged.as_object_mut(), cur.as_object()) {
            for (k, v) in o {
                if k != "$ref" {
                    m.insert(k.clone(), v.clone());
                }
            }
        }
        cur = merged;
    }
    cur
}

fn classify(root: &Value, node: &Value) -> FlagKind {
    let n = resolve(root, node);
    if let Some(vals) = n.get("enum").and_then(Value::as_array) {
        let names: Vec<String> = vals
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        if names.len() == vals.len() && !names.is_empty() {
            return FlagKind::Enum(names);
        }
    }
    if let Some(vs) = n.get("oneOf").and_then(Value::as_array) {
        let names: Vec<String> = vs
            .iter()
            .filter_map(|v| v.get("const").and_then(Value::as_str).map(str::to_string))
            .collect();
        if !names.is_empty() && names.len() == vs.len() {
            return FlagKind::Enum(names);
        }
    }
    match n.get("type") {
        Some(Value::String(t)) => return by_type(t),
        Some(Value::Array(ts)) => {
            let non_null: Vec<&str> = ts
                .iter()
                .filter_map(Value::as_str)
                .filter(|t| *t != "null")
                .collect();
            if let [only] = non_null.as_slice() {
                return by_type(only);
            }
            return FlagKind::Json;
        }
        _ => {}
    }
    for key in ["anyOf", "oneOf"] {
        if let Some(vs) = n.get(key).and_then(Value::as_array) {
            let non_null: Vec<&Value> = vs
                .iter()
                .filter(|v| v.get("type").and_then(Value::as_str) != Some("null"))
                .collect();
            if let [only] = non_null.as_slice() {
                return classify(root, only);
            }
        }
    }
    FlagKind::Json
}

fn by_type(t: &str) -> FlagKind {
    match t {
        "string" => FlagKind::Str,
        "integer" => FlagKind::Int,
        "number" => FlagKind::Num,
        "boolean" => FlagKind::Bool,
        _ => FlagKind::Json,
    }
}

fn describe(root: &Value, node: &Value) -> String {
    let n = resolve(root, node);
    n.get("description")
        .and_then(Value::as_str)
        .map(|d| d.split_whitespace().collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

/// The flags of a command, in schema property order. Properties whose flag name is reserved are
/// left out (reachable through `--args-json`).
pub fn flags_from_schema(schema: &Value) -> Vec<FlagSpec> {
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    props
        .iter()
        .filter_map(|(prop, node)| {
            let flag = kebab(prop);
            if RESERVED.contains(&flag.as_str()) {
                return None;
            }
            Some(FlagSpec {
                prop: prop.clone(),
                flag,
                kind: classify(schema, node),
                help: describe(schema, node),
                required: required.contains(&prop.as_str()),
            })
        })
        .collect()
}

fn bad(msg: String) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

/// Converts flag text to a JSON value of the flag's kind.
pub fn parse_flag_value(flag: &FlagSpec, text: &str) -> Result<Value, ProtoError> {
    let name = &flag.flag;
    match &flag.kind {
        FlagKind::Str => Ok(Value::String(text.to_string())),
        FlagKind::Int => {
            let t = text.trim();
            if let Ok(n) = t.parse::<u64>() {
                Ok(Value::Number(n.into()))
            } else if let Ok(n) = t.parse::<i64>() {
                Ok(Value::Number(n.into()))
            } else {
                Err(bad(format!("--{name}: `{text}` is not an integer")))
            }
        }
        FlagKind::Num => text
            .trim()
            .parse::<f64>()
            .ok()
            .and_then(Number::from_f64)
            .map(Value::Number)
            .ok_or_else(|| bad(format!("--{name}: `{text}` is not a number"))),
        FlagKind::Bool => match text.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" | "on" => Ok(Value::Bool(true)),
            "false" | "no" | "0" | "off" => Ok(Value::Bool(false)),
            _ => Err(bad(format!("--{name}: `{text}` is not true or false"))),
        },
        FlagKind::Enum(allowed) => {
            if allowed.iter().any(|a| a == text) {
                Ok(Value::String(text.to_string()))
            } else {
                Err(bad(format!(
                    "--{name}: `{text}` is not one of {}",
                    allowed.join(", ")
                )))
            }
        }
        FlagKind::Json => serde_json::from_str(text)
            .map_err(|e| bad(format!("--{name}: invalid JSON ({e}); pass a JSON value"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn flag(kind: FlagKind) -> FlagSpec {
        FlagSpec {
            prop: "x_y".into(),
            flag: "x-y".into(),
            kind,
            help: String::new(),
            required: false,
        }
    }

    #[test]
    fn kinds_are_derived_from_the_schema() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "A\n name."},
                "limit": {"type": ["integer", "null"], "format": "uint32"},
                "dry_run": {"type": "boolean"},
                "address": {"$ref": "#/$defs/Hex64", "description": "Where."},
                "mode": {"enum": ["a", "b"]},
                "status": {"oneOf": [{"const": "open"}, {"const": "all"}]},
                "maybe": {"anyOf": [{"$ref": "#/$defs/Hex64"}, {"type": "null"}]},
                "map": {"type": "object", "additionalProperties": {"type": "integer"}}
            },
            "required": ["name"],
            "$defs": {"Hex64": {"type": "string"}}
        });
        let f = flags_from_schema(&schema);
        let kind = |p: &str| f.iter().find(|x| x.prop == p).map(|x| x.kind.clone());
        assert_eq!(kind("name"), Some(FlagKind::Str));
        assert_eq!(kind("limit"), Some(FlagKind::Int));
        assert_eq!(kind("dry_run"), Some(FlagKind::Bool));
        assert_eq!(kind("address"), Some(FlagKind::Str));
        assert_eq!(
            kind("mode"),
            Some(FlagKind::Enum(vec!["a".into(), "b".into()]))
        );
        assert_eq!(
            kind("status"),
            Some(FlagKind::Enum(vec!["open".into(), "all".into()]))
        );
        assert_eq!(kind("maybe"), Some(FlagKind::Str));
        assert_eq!(kind("map"), Some(FlagKind::Json));
        let by = |p: &str| f.iter().find(|x| x.prop == p).expect("flag");
        assert!(by("name").required);
        assert!(!by("limit").required);
        assert_eq!(by("name").help, "A name.");
        assert_eq!(by("address").help, "Where.");
        assert_eq!(by("dry_run").flag, "dry-run");
    }

    #[test]
    fn values_are_converted_by_kind() {
        assert_eq!(
            parse_flag_value(&flag(FlagKind::Int), "42").unwrap(),
            json!(42)
        );
        assert_eq!(
            parse_flag_value(&flag(FlagKind::Int), "-3").unwrap(),
            json!(-3)
        );
        assert!(parse_flag_value(&flag(FlagKind::Int), "x").is_err());
        assert_eq!(
            parse_flag_value(&flag(FlagKind::Bool), "false").unwrap(),
            json!(false)
        );
        assert_eq!(
            parse_flag_value(&flag(FlagKind::Str), "0x401000").unwrap(),
            json!("0x401000")
        );
        assert_eq!(
            parse_flag_value(&flag(FlagKind::Json), "{\"a\":1}").unwrap(),
            json!({"a": 1})
        );
        assert!(parse_flag_value(&flag(FlagKind::Json), "{").is_err());
        let e = flag(FlagKind::Enum(vec!["a".into()]));
        assert!(parse_flag_value(&e, "b").is_err());
    }

    #[test]
    fn reserved_names_are_skipped() {
        let schema = json!({"type": "object", "properties": {"json": {"type": "string"}, "ok": {"type": "string"}}});
        let f = flags_from_schema(&schema);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].flag, "ok");
    }
}
