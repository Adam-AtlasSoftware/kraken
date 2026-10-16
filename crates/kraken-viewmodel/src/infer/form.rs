//! A settings form generated from an engine's JSON-Schema (`InferenceBackend::settings_schema`),
//! so a new engine from a manifest needs no GUI code.
//!
//! Supported property shapes: `integer` and `number` (with `minimum`/`maximum`), `boolean`,
//! `string` with `enum`, `string` with `x-kraken-widget = "file-path"`, and plain `string`.
//! Anything else is shown as a text field holding JSON. `default`, `title`, `description` and
//! `required` are honoured; a field left empty is simply not sent.

use std::collections::BTreeMap;

use serde_json::{Map, Number, Value};

/// How a field is edited.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldKind {
    /// A whole number.
    Integer {
        /// Smallest allowed value.
        min: Option<i64>,
        /// Largest allowed value.
        max: Option<i64>,
    },
    /// Any number.
    Number {
        /// Smallest allowed value.
        min: Option<f64>,
        /// Largest allowed value.
        max: Option<f64>,
    },
    /// On or off.
    Bool,
    /// One of a fixed list.
    Enum(Vec<String>),
    /// A file on this computer.
    Path,
    /// Free text.
    Text,
    /// Something else, edited as JSON text.
    Json,
}

/// One setting.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// The setting's name in the settings object.
    pub key: String,
    /// Label for people.
    pub title: String,
    /// Explanation, when the schema has one.
    pub description: Option<String>,
    /// The engine cannot start without it.
    pub required: bool,
    /// How it is edited.
    pub kind: FieldKind,
    /// The value the engine uses when the field is left empty.
    pub default: Option<Value>,
    /// The text being edited (numbers, paths, text, JSON, the chosen enum value).
    pub text: String,
    /// The state of a checkbox.
    pub flag: bool,
    /// For a [`FieldKind::Bool`]: the person touched it, so it is sent even if it equals the
    /// default.
    pub touched: bool,
}

impl Field {
    fn default_text(&self) -> String {
        match &self.default {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) | None => String::new(),
            Some(v) => v.to_string(),
        }
    }

    /// The problem with the current text, if any (empty optional fields are fine).
    pub fn error(&self) -> Option<String> {
        self.parse().err()
    }

    /// `Ok(None)` when the field is empty and optional or left at its default.
    fn parse(&self) -> Result<Option<Value>, String> {
        let name = &self.title;
        if self.kind == FieldKind::Bool {
            return Ok(self.touched.then_some(Value::Bool(self.flag)));
        }
        let text = self.text.trim();
        if text.is_empty() {
            return if self.required && self.default.is_none() {
                Err(format!("{name} is required"))
            } else {
                Ok(None)
            };
        }
        match &self.kind {
            FieldKind::Integer { min, max } => {
                let n: i64 = text
                    .parse()
                    .map_err(|_| format!("{name} needs a whole number"))?;
                if min.is_some_and(|m| n < m) {
                    return Err(format!("{name} must be at least {}", min.unwrap_or(0)));
                }
                if max.is_some_and(|m| n > m) {
                    return Err(format!("{name} must be at most {}", max.unwrap_or(0)));
                }
                Ok(Some(Value::from(n)))
            }
            FieldKind::Number { min, max } => {
                let n: f64 = text.parse().map_err(|_| format!("{name} needs a number"))?;
                if min.is_some_and(|m| n < m) {
                    return Err(format!("{name} must be at least {}", min.unwrap_or(0.0)));
                }
                if max.is_some_and(|m| n > m) {
                    return Err(format!("{name} must be at most {}", max.unwrap_or(0.0)));
                }
                Number::from_f64(n)
                    .map(|n| Some(Value::Number(n)))
                    .ok_or_else(|| format!("{name} needs a finite number"))
            }
            FieldKind::Enum(options) => {
                if options.iter().any(|o| o == text) {
                    Ok(Some(Value::String(text.to_string())))
                } else {
                    Err(format!("{name} must be one of: {}", options.join(", ")))
                }
            }
            FieldKind::Path | FieldKind::Text => Ok(Some(Value::String(text.to_string()))),
            FieldKind::Json => serde_json::from_str(text)
                .map(Some)
                .map_err(|e| format!("{name} needs JSON ({e})")),
            FieldKind::Bool => Ok(None),
        }
    }
}

/// The whole form.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SettingsForm {
    /// Title of the engine's schema, when it has one.
    pub title: Option<String>,
    /// The fields, in display order: required ones and file paths first.
    pub fields: Vec<Field>,
}

fn as_i64(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

fn humanize(key: &str) -> String {
    let mut s = key.replace('_', " ");
    if let Some(c) = s.get_mut(..1) {
        c.make_ascii_uppercase();
    }
    s
}

impl SettingsForm {
    /// Builds the form for `schema`. A schema without properties gives an empty form.
    pub fn from_schema(schema: &Value) -> Self {
        let required: Vec<&str> = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|r| r.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut fields = Vec::new();
        if let Some(props) = schema.get("properties").and_then(Value::as_object) {
            for (key, p) in props {
                let ty = p.get("type").and_then(Value::as_str);
                let widget = p.get("x-kraken-widget").and_then(Value::as_str);
                let kind = if let Some(options) = p.get("enum").and_then(Value::as_array) {
                    FieldKind::Enum(
                        options
                            .iter()
                            .map(|o| o.as_str().map_or_else(|| o.to_string(), str::to_string))
                            .collect(),
                    )
                } else {
                    match (ty, widget) {
                        (Some("boolean"), _) => FieldKind::Bool,
                        (Some("integer"), _) => FieldKind::Integer {
                            min: p.get("minimum").and_then(as_i64),
                            max: p.get("maximum").and_then(as_i64),
                        },
                        (Some("number"), _) => FieldKind::Number {
                            min: p.get("minimum").and_then(Value::as_f64),
                            max: p.get("maximum").and_then(Value::as_f64),
                        },
                        (_, Some("file-path")) => FieldKind::Path,
                        (Some("string") | None, _) => FieldKind::Text,
                        _ => FieldKind::Json,
                    }
                };
                let default = p.get("default").cloned();
                let mut f = Field {
                    key: key.clone(),
                    title: p
                        .get("title")
                        .and_then(Value::as_str)
                        .map_or_else(|| humanize(key), str::to_string),
                    description: p
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    required: required.contains(&key.as_str()),
                    kind,
                    default,
                    text: String::new(),
                    flag: false,
                    touched: false,
                };
                f.text = f.default_text();
                f.flag = f.default.as_ref().and_then(Value::as_bool).unwrap_or(false);
                fields.push(f);
            }
        }
        // Required first, then file paths, then the rest by title.
        fields.sort_by(|a, b| {
            let rank = |f: &Field| (!f.required, f.kind != FieldKind::Path);
            rank(a)
                .cmp(&rank(b))
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        SettingsForm {
            title: schema
                .get("title")
                .and_then(Value::as_str)
                .map(str::to_string),
            fields,
        }
    }

    /// The field called `key`.
    pub fn field(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.key == key)
    }

    /// The field called `key`, to edit.
    pub fn field_mut(&mut self, key: &str) -> Option<&mut Field> {
        self.fields.iter_mut().find(|f| f.key == key)
    }

    /// Sets a text field (numbers, paths, enum choice).
    pub fn set_text(&mut self, key: &str, text: impl Into<String>) {
        if let Some(f) = self.field_mut(key) {
            f.text = text.into();
        }
    }

    /// Sets a checkbox.
    pub fn set_flag(&mut self, key: &str, on: bool) {
        if let Some(f) = self.field_mut(key) {
            f.flag = on;
            f.touched = true;
        }
    }

    /// The first path field that looks like the model file (`model_path`, `model`, else the
    /// first path field).
    pub fn model_key(&self) -> Option<&str> {
        ["model_path", "model"]
            .into_iter()
            .find(|k| self.field(k).is_some_and(|f| f.kind == FieldKind::Path))
            .or_else(|| {
                self.fields
                    .iter()
                    .find(|f| f.kind == FieldKind::Path)
                    .map(|f| f.key.as_str())
            })
    }

    /// The numeric value of field `key`, when it parses.
    pub fn number(&self, key: &str) -> Option<f64> {
        let f = self.field(key)?;
        match f.parse() {
            Ok(Some(v)) => v.as_f64(),
            _ => None,
        }
    }

    /// Every problem, keyed by field.
    pub fn errors(&self) -> BTreeMap<String, String> {
        self.fields
            .iter()
            .filter_map(|f| f.error().map(|e| (f.key.clone(), e)))
            .collect()
    }

    /// The settings object to send: only fields with a value (a field left empty falls back to
    /// the engine's default). Fails with the problems when something is wrong.
    pub fn to_settings(&self) -> Result<Value, Vec<String>> {
        let mut out = Map::new();
        let mut problems = Vec::new();
        for f in &self.fields {
            match f.parse() {
                Ok(Some(v)) => {
                    out.insert(f.key.clone(), v);
                }
                Ok(None) => {}
                Err(e) => problems.push(e),
            }
        }
        if problems.is_empty() {
            Ok(Value::Object(out))
        } else {
            Err(problems)
        }
    }
}
