//! Forms generated from a command's argument schema, so the palette can run every registry
//! command, and the window that shows what a command returned.

use std::sync::OnceLock;

use kraken_registry::Registry;
use serde_json::{Map, Value, json};

use crate::backend::{CommandInfo, Permission};
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex};

/// Characters of a result shown before it is cut.
pub const MAX_RESULT_CHARS: usize = 200_000;

/// What kind of input a field takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    /// Free text.
    Text,
    /// An address, `0x...`.
    Address,
    /// A whole number.
    Integer,
    /// Yes or no.
    Bool,
    /// One of a fixed set: (value, description).
    Enum(Vec<(String, String)>),
    /// Anything else, typed as JSON.
    Json,
}

/// One input of a generated form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormField {
    /// Argument name.
    pub name: String,
    /// Its description from the schema.
    pub doc: String,
    /// Input kind.
    pub kind: FieldKind,
    /// Must be filled in.
    pub required: bool,
    /// The text typed (or the chosen enum value); empty means "leave out" for optional fields.
    pub value: String,
    /// The checkbox of a [`FieldKind::Bool`].
    pub flag: bool,
}

impl FormField {
    /// The JSON for this field, `None` to leave it out.
    fn json(&self) -> Result<Option<Value>, String> {
        let v = self.value.trim();
        if self.kind == FieldKind::Bool {
            return Ok((self.required || self.flag).then_some(json!(self.flag)));
        }
        if v.is_empty() {
            return if self.required {
                Err(format!("Fill in {}.", self.name))
            } else {
                Ok(None)
            };
        }
        Ok(Some(match &self.kind {
            FieldKind::Text => json!(self.value),
            FieldKind::Address => match super::parse_address(v)
                .or_else(|| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            {
                Some(a) => json!(hex(a)),
                None => {
                    return Err(format!(
                        "{} must be an address such as 0x401000.",
                        self.name
                    ));
                }
            },
            FieldKind::Integer => {
                let n = match v.strip_prefix("0x") {
                    Some(h) => i64::from_str_radix(h, 16).ok(),
                    None => v.parse::<i64>().ok(),
                };
                match n {
                    Some(n) => json!(n),
                    None => return Err(format!("{} must be a whole number.", self.name)),
                }
            }
            FieldKind::Enum(opts) => {
                if !opts.iter().any(|(o, _)| o == v) {
                    return Err(format!("Pick a value for {}.", self.name));
                }
                json!(v)
            }
            FieldKind::Json => serde_json::from_str(v)
                .map_err(|e| format!("{} is not valid JSON: {e}", self.name))?,
            FieldKind::Bool => unreachable!("handled above"),
        }))
    }
}

fn registry() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(Registry::standard)
}

fn resolve<'a>(v: &'a Value, defs: &'a Value) -> &'a Value {
    if let Some(name) = v
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|r| r.strip_prefix("#/$defs/"))
        && let Some(d) = defs.get(name)
    {
        return d;
    }
    v
}

fn is_hex64(v: &Value) -> bool {
    v.get("pattern")
        .and_then(Value::as_str)
        .is_some_and(|p| p.starts_with("^0[xX]"))
}

fn kind_of(prop: &Value, defs: &Value) -> (FieldKind, bool) {
    // `Option<T>` is `anyOf: [T, null]` or `type: [t, "null"]`.
    let mut nullable = false;
    let mut v = resolve(prop, defs);
    if let Some(any) = prop.get("anyOf").and_then(Value::as_array) {
        let non_null: Vec<&Value> = any
            .iter()
            .filter(|a| a.get("type").and_then(Value::as_str) != Some("null"))
            .collect();
        nullable = non_null.len() < any.len();
        if let [one] = non_null.as_slice() {
            v = resolve(one, defs);
        } else {
            return (FieldKind::Json, nullable);
        }
    }
    if is_hex64(v) {
        return (FieldKind::Address, nullable);
    }
    if let Some(one_of) = v.get("oneOf").and_then(Value::as_array) {
        let opts: Option<Vec<(String, String)>> = one_of
            .iter()
            .map(|o| {
                let c = o.get("const")?.as_str()?.to_string();
                let d = o
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                Some((c, d))
            })
            .collect();
        return match opts {
            Some(o) => (FieldKind::Enum(o), nullable),
            None => (FieldKind::Json, nullable),
        };
    }
    if let Some(e) = v.get("enum").and_then(Value::as_array) {
        let opts: Vec<(String, String)> = e
            .iter()
            .filter_map(|x| x.as_str().map(|s| (s.to_string(), String::new())))
            .collect();
        return (FieldKind::Enum(opts), nullable);
    }
    let types: Vec<&str> = match v.get("type") {
        Some(Value::String(t)) => vec![t.as_str()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    nullable |= types.contains(&"null");
    let main: Vec<&str> = types.into_iter().filter(|t| *t != "null").collect();
    let kind = match main.as_slice() {
        ["string"] => FieldKind::Text,
        ["integer"] | ["number"] => FieldKind::Integer,
        ["boolean"] => FieldKind::Bool,
        _ => FieldKind::Json,
    };
    (kind, nullable)
}

/// Arguments a form leaves out: the GUI sends versions itself where it matters.
const HIDDEN: &[&str] = &["expect_versions"];

/// The fields of a form for an argument schema, required ones first.
pub fn fields_for_schema(schema: &Value) -> Vec<FormField> {
    let defs = schema.get("$defs").cloned().unwrap_or(Value::Null);
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out: Vec<FormField> = props
        .iter()
        .filter(|(k, _)| !HIDDEN.contains(&k.as_str()))
        .map(|(name, prop)| {
            let (kind, nullable) = kind_of(prop, &defs);
            let flag = prop
                .get("default")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            FormField {
                name: name.clone(),
                doc: prop
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .replace('\n', " "),
                required: required.contains(&name.as_str()) && !nullable,
                kind,
                value: String::new(),
                flag,
            }
        })
        .collect();
    out.sort_by_key(|f| !f.required);
    out
}

/// A generated form for one registry command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandForm {
    /// Command name.
    pub command: String,
    /// Its one-line summary.
    pub summary: String,
    /// Its documentation (when to use it, an example).
    pub doc: String,
    /// The inputs.
    pub fields: Vec<FormField>,
    /// Who may run it without asking.
    pub permission: Permission,
    /// Why the last attempt was refused.
    pub error: Option<String>,
    /// The call is running.
    pub running: bool,
}

impl CommandForm {
    /// The arguments as JSON, or the first problem.
    pub fn args(&self) -> Result<Value, String> {
        let mut m = Map::new();
        for f in &self.fields {
            if let Some(v) = f.json()? {
                m.insert(f.name.clone(), v);
            }
        }
        Ok(Value::Object(m))
    }
}

/// A piece of a result line: plain text or an address to go to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultSegment {
    /// Plain text.
    Text(String),
    /// A `0x...` address.
    Address(String, u64),
}

/// Splits pretty JSON into lines of text and clickable addresses.
pub fn result_lines(text: &str) -> Vec<Vec<ResultSegment>> {
    text.lines()
        .map(|line| {
            let mut out = Vec::new();
            let mut rest = line;
            while let Some(i) = rest.find("0x") {
                let digits = rest[i + 2..]
                    .chars()
                    .take_while(char::is_ascii_hexdigit)
                    .count();
                let boundary_ok = i == 0
                    || !rest[..i]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_ascii_alphanumeric());
                if digits == 0 || digits > 16 || !boundary_ok {
                    out.push(ResultSegment::Text(rest[..i + 2].to_string()));
                    rest = &rest[i + 2..];
                    continue;
                }
                if i > 0 {
                    out.push(ResultSegment::Text(rest[..i].to_string()));
                }
                let tok = &rest[i..i + 2 + digits];
                if let Ok(a) = u64::from_str_radix(&tok[2..], 16) {
                    out.push(ResultSegment::Address(tok.to_string(), a));
                } else {
                    out.push(ResultSegment::Text(tok.to_string()));
                }
                rest = &rest[i + 2 + digits..];
            }
            if !rest.is_empty() {
                out.push(ResultSegment::Text(rest.to_string()));
            }
            out
        })
        .collect()
}

/// What a command run from a form returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    /// Command name.
    pub command: String,
    /// The arguments it ran with.
    pub args: String,
    /// Pretty JSON of the result, or the error in plain words.
    pub text: String,
    /// True when the command failed.
    pub failed: bool,
    /// The text was cut at [`MAX_RESULT_CHARS`].
    pub truncated: bool,
}

impl ViewModel {
    /// Opens the generated form for `command`. A command without arguments runs at once.
    pub fn open_command_form(&mut self, command: &str) {
        let info: Option<CommandInfo> = self.commands().into_iter().find(|c| c.name == command);
        let entry = registry().get(command);
        let (fields, doc) = match entry {
            Some(e) => (fields_for_schema(e.args_schema()), e.spec().doc.clone()),
            // A command this build's registry does not know: arguments as raw JSON.
            None => (
                vec![FormField {
                    name: "arguments".into(),
                    doc: "All arguments as one JSON object.".into(),
                    kind: FieldKind::Json,
                    required: false,
                    value: "{}".into(),
                    flag: false,
                }],
                String::new(),
            ),
        };
        let mut form = CommandForm {
            command: command.to_string(),
            summary: info.as_ref().map(|i| i.summary.clone()).unwrap_or_default(),
            doc,
            fields,
            permission: info.map_or(Permission::Safe, |i| i.permission),
            error: None,
            running: false,
        };
        let here = self.cursor_address();
        let module = self.module.clone();
        for f in &mut form.fields {
            if f.kind == FieldKind::Address
                && let Some(a) = here
            {
                f.value = hex(a);
            }
            if f.name == "module"
                && let Some(m) = &module
            {
                f.value = m.clone();
            }
        }
        let no_inputs = form.fields.is_empty();
        self.tools.form = Some(form);
        if no_inputs {
            self.submit_command_form();
        }
    }

    /// Changes the text of field `i`.
    pub fn set_form_value(&mut self, i: usize, value: impl Into<String>) {
        if let Some(f) = self.tools.form.as_mut().and_then(|f| f.fields.get_mut(i)) {
            f.value = value.into();
        }
        if let Some(f) = self.tools.form.as_mut() {
            f.error = None;
        }
    }

    /// Sets the checkbox of field `i`.
    pub fn set_form_flag(&mut self, i: usize, flag: bool) {
        if let Some(f) = self.tools.form.as_mut().and_then(|f| f.fields.get_mut(i)) {
            f.flag = flag;
        }
    }

    /// Closes the form.
    pub fn cancel_command_form(&mut self) {
        self.tools.form = None;
    }

    /// Closes the result window.
    pub fn close_command_result(&mut self) {
        self.tools.result = None;
    }

    /// Runs the form's command. A dangerous one still asks for approval first (the backend
    /// does that, as for every call).
    pub fn submit_command_form(&mut self) {
        let Some(form) = self.tools.form.as_mut().filter(|f| !f.running) else {
            return;
        };
        let mut args = match form.args() {
            Ok(a) => a,
            Err(e) => {
                form.error = Some(e);
                return;
            }
        };
        if registry().get(&form.command).is_none()
            && let Some(inner) = args.get("arguments").cloned()
        {
            args = inner;
        }
        form.running = true;
        form.error = None;
        let command = form.command.clone();
        let changes = form.permission != Permission::Safe;
        let shown_args = serde_json::to_string(&args).unwrap_or_default();
        self.call(command.clone(), args, move |vm, res| {
            if let Some(f) = vm.tools.form.as_mut() {
                f.running = false;
            }
            let (text, failed) = match &res {
                Ok(v) => (serde_json::to_string_pretty(v).unwrap_or_default(), false),
                Err(e) => (plain_error(e), true),
            };
            let truncated = text.chars().count() > MAX_RESULT_CHARS;
            let text = if truncated {
                text.chars().take(MAX_RESULT_CHARS).collect()
            } else {
                text
            };
            if failed {
                if let Some(f) = vm.tools.form.as_mut() {
                    f.error = Some(text.clone());
                } else {
                    vm.toast(ToastLevel::Error, format!("{command} failed: {text}"));
                }
            } else {
                vm.tools.form = None;
                if changes {
                    vm.refresh_after_edit();
                    vm.refresh_bookmarks();
                }
            }
            vm.tools.result = Some(CommandResult {
                command,
                args: shown_args,
                text,
                failed,
                truncated,
            });
        });
    }
}
