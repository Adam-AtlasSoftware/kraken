//! Calling one function in the emulator: the "Call this function..." dialog (`emulate_call`),
//! pre-filled from the function's signature, and the result the Emulation tab shows.

use kraken_registry::commands::EmulateCallOut;
use serde_json::{Value, json};

use super::NavTab;
use super::emulate::EmulationResult;
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, parse};

/// How an argument is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamKind {
    /// A whole number (decimal or `0x...`).
    Int,
    /// Text placed in emulated memory; the function gets its address.
    Text,
    /// Bytes as hexadecimal digits placed in emulated memory.
    Bytes,
    /// A zero-filled buffer of this many bytes for the function to write into.
    Buffer,
    /// A raw address or pointer-sized number.
    Pointer,
    /// A `float`.
    Float,
    /// A `double`.
    Double,
}

impl ParamKind {
    /// All kinds, in the order the dialog offers them.
    pub const ALL: [ParamKind; 7] = [
        ParamKind::Int,
        ParamKind::Text,
        ParamKind::Bytes,
        ParamKind::Buffer,
        ParamKind::Pointer,
        ParamKind::Float,
        ParamKind::Double,
    ];

    /// The name shown in the kind picker.
    pub fn label(self) -> &'static str {
        match self {
            ParamKind::Int => "number",
            ParamKind::Text => "text",
            ParamKind::Bytes => "hex bytes",
            ParamKind::Buffer => "empty buffer",
            ParamKind::Pointer => "address",
            ParamKind::Float => "float",
            ParamKind::Double => "double",
        }
    }

    /// What the picker entry means.
    pub fn hint(self) -> &'static str {
        match self {
            ParamKind::Int => "A whole number, for example 5 or 0x10",
            ParamKind::Text => "Text copied into emulated memory, passed as a pointer",
            ParamKind::Bytes => {
                "Hexadecimal digits copied into emulated memory, passed as a pointer"
            }
            ParamKind::Buffer => {
                "A zero-filled buffer for the function to write into; type its size in bytes"
            }
            ParamKind::Pointer => "A raw address in the program, for example 0x404040",
            ParamKind::Float => "A floating-point number (float)",
            ParamKind::Double => "A floating-point number (double)",
        }
    }

    fn default_value(self) -> &'static str {
        match self {
            ParamKind::Int | ParamKind::Pointer => "0",
            ParamKind::Buffer => "64",
            ParamKind::Float | ParamKind::Double => "0.0",
            ParamKind::Text | ParamKind::Bytes => "",
        }
    }
}

/// One argument row of the dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallParam {
    /// The parameter as the signature spells it (`const char *s`).
    pub label: String,
    /// How it is given.
    pub kind: ParamKind,
    /// What was typed.
    pub value: String,
}

/// The dialog that sets up a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallDialog {
    /// The function's entry.
    pub address: u64,
    /// Its name.
    pub name: String,
    /// Its signature, when known.
    pub signature: String,
    /// One row per parameter.
    pub params: Vec<CallParam>,
    /// The return kind sent as `returns`.
    pub returns: String,
    /// Start the program up to `main` first so libc works.
    pub libc: bool,
    /// Where that startup stops when the program has no `main` symbol; empty for `main`.
    pub startup: String,
    /// Instruction budget as typed; empty for the default.
    pub max_steps: String,
    /// Why the last attempt failed.
    pub error: Option<String>,
    /// The call is in progress.
    pub running: bool,
}

/// The return kinds the dialog offers.
pub const RETURN_KINDS: [&str; 12] = [
    "int", "void", "long", "ptr", "i8", "i16", "u8", "u16", "u32", "u64", "f32", "f64",
];

impl CallDialog {
    /// A dialog for the function at `address` named `name`, filled from `signature`.
    pub fn new(address: u64, name: &str, signature: Option<&str>) -> CallDialog {
        let (returns, params) = signature.map(parse_signature).unwrap_or_default();
        CallDialog {
            address,
            name: name.to_string(),
            signature: signature.unwrap_or("").to_string(),
            params: params
                .into_iter()
                .map(|(label, kind)| CallParam {
                    label,
                    kind,
                    value: kind.default_value().to_string(),
                })
                .collect(),
            returns: if returns.is_empty() {
                "int".into()
            } else {
                returns
            },
            libc: false,
            startup: String::new(),
            max_steps: String::new(),
            error: None,
            running: false,
        }
    }

    /// The arguments of `emulate_call`, or what is wrong with the dialog.
    pub fn args(&self) -> Result<Value, String> {
        let mut args = Vec::new();
        for (i, p) in self.params.iter().enumerate() {
            let v = p.value.trim();
            let n = i + 1;
            args.push(match p.kind {
                ParamKind::Int => {
                    if v.is_empty() {
                        return Err(format!("Argument {n} needs a number."));
                    }
                    json!({"int": v})
                }
                ParamKind::Pointer => {
                    if v.is_empty() {
                        return Err(format!("Argument {n} needs an address."));
                    }
                    json!({"ptr": if v.starts_with("0x") { v.to_string() } else { format!("0x{v}") }})
                }
                ParamKind::Text => json!({"string": p.value}),
                ParamKind::Bytes => json!({"hex": v}),
                ParamKind::Buffer => {
                    let size: usize = v
                        .parse()
                        .map_err(|_| format!("Argument {n} needs a size in bytes."))?;
                    json!({"buffer": size})
                }
                ParamKind::Float => json!({"f32": v.parse::<f32>().map_err(|_| {
                    format!("Argument {n} needs a decimal number.")
                })?}),
                ParamKind::Double => json!({"f64": v.parse::<f64>().map_err(|_| {
                    format!("Argument {n} needs a decimal number.")
                })?}),
            });
        }
        let mut m = serde_json::Map::new();
        m.insert("address".into(), json!(format!("{:#x}", self.address)));
        m.insert("args".into(), json!(args));
        m.insert("returns".into(), json!(self.returns));
        if self.libc {
            m.insert("libc".into(), json!(true));
            let s = self.startup.trim();
            if !s.is_empty() {
                m.insert("startup_address".into(), json!(s));
            }
        }
        if !self.max_steps.trim().is_empty() {
            let steps: u64 = self
                .max_steps
                .trim()
                .replace('_', "")
                .parse()
                .map_err(|_| "The step limit must be a whole number.".to_string())?;
            m.insert("max_steps".into(), json!(steps));
        }
        Ok(Value::Object(m))
    }
}

/// The return kind and the parameters (label and likely kind) of a C signature such as
/// `int vm_run(struct vm *vm, const uint8_t *code, unsigned len)`.
pub fn parse_signature(sig: &str) -> (String, Vec<(String, ParamKind)>) {
    let Some(open) = sig.find('(') else {
        return (String::new(), Vec::new());
    };
    let head = sig[..open].trim_end();
    let name_start = head
        .rfind(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$' || c == '@' || c == ':'))
        .map_or(0, |i| i + 1);
    let ret = head[..name_start].trim();
    let close = sig.rfind(')').unwrap_or(sig.len());
    let inner = sig[open + 1..close].trim();
    let mut params = Vec::new();
    let (mut depth, mut start) = (0i32, 0usize);
    let mut pieces = Vec::new();
    for (i, c) in inner.char_indices() {
        match c {
            '(' | '<' | '[' => depth += 1,
            ')' | '>' | ']' => depth -= 1,
            ',' if depth == 0 => {
                pieces.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    pieces.push(&inner[start..]);
    for p in pieces {
        let p = p.trim();
        if p.is_empty() || p == "void" || p == "..." {
            continue;
        }
        params.push((p.to_string(), kind_of(p)));
    }
    (return_kind(ret), params)
}

fn kind_of(param: &str) -> ParamKind {
    let t = param.to_ascii_lowercase();
    let ptr = t.contains('*') || t.contains('[');
    if ptr {
        if t.contains("char")
            && !t.contains("**")
            && !t.contains("uchar")
            && !t.contains("unsigned char")
        {
            ParamKind::Text
        } else if t.contains("(*") {
            ParamKind::Pointer
        } else {
            ParamKind::Buffer
        }
    } else if t.starts_with("float") {
        ParamKind::Float
    } else if t.starts_with("double") {
        ParamKind::Double
    } else {
        ParamKind::Int
    }
}

fn return_kind(ret: &str) -> String {
    let t = ret.to_ascii_lowercase();
    let t = t.trim();
    if t.is_empty() {
        return String::new();
    }
    if t.contains('*') {
        return "ptr".into();
    }
    let words: Vec<&str> = t
        .split_whitespace()
        .filter(|w| !matches!(*w, "const" | "static" | "extern" | "inline" | "volatile"))
        .collect();
    let joined = words.join(" ");
    match joined.as_str() {
        "void" => "void",
        "float" => "f32",
        "double" => "f64",
        "char" | "signed char" | "int8_t" => "i8",
        "unsigned char" | "uchar" | "uint8_t" | "bool" | "_bool" | "byte" | "undefined1" => "u8",
        "short" | "int16_t" => "i16",
        "unsigned short" | "ushort" | "uint16_t" | "undefined2" => "u16",
        "uint" | "unsigned" | "unsigned int" | "uint32_t" | "undefined4" => "u32",
        "long" | "long long" | "longlong" | "int64_t" | "ssize_t" | "intptr_t" | "ptrdiff_t" => {
            "long"
        }
        "unsigned long" | "ulong" | "unsigned long long" | "ulonglong" | "uint64_t" | "size_t"
        | "uintptr_t" | "undefined8" | "undefined" => "u64",
        _ => "int",
    }
    .to_string()
}

/// One buffer after a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallBufferDetail {
    /// The parameter it was given as, `argument N`.
    pub label: String,
    /// Its size in bytes.
    pub size: usize,
    /// The text up to the first zero byte.
    pub text: String,
    /// The first bytes as hexadecimal digits.
    pub hex: String,
    /// The function changed it.
    pub changed: bool,
}

/// What a call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallDetail {
    /// The function's name.
    pub name: String,
    /// Its entry.
    pub address: u64,
    /// How the call ended, in words.
    pub ended: String,
    /// True when it returned.
    pub clean: bool,
    /// The returned value, when it returned one.
    pub value: Option<String>,
    /// The buffers after the call.
    pub buffers: Vec<CallBufferDetail>,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
    /// Instructions executed.
    pub steps: u64,
    /// The emulator's notes.
    pub notes: Vec<String>,
    /// What was passed, in one line.
    pub given: String,
}

fn detail_of(o: EmulateCallOut, given: String) -> CallDetail {
    let ended = match o.ended.as_str() {
        "returned" => "returned".to_string(),
        "import" => format!(
            "reached the library function {}",
            o.detail.as_ref().map_or("", |d| d.0.as_str())
        ),
        "fault" => format!(
            "faulted: {}",
            o.detail.as_ref().map_or("", |d| d.0.as_str())
        ),
        "step_limit" => "ran out of instructions".to_string(),
        "exited" => format!(
            "the program ended: {}",
            o.detail.as_ref().map_or("", |d| d.0.as_str())
        ),
        other => other.to_string(),
    };
    let value = o.value.map(|v| match (v.signed, v.unsigned, v.float) {
        (Some(s), Some(u), _) if s as u64 == u => format!("{s} ({})", v.hex),
        (Some(s), Some(u), _) => format!("{s} / {u} ({})", v.hex),
        (_, _, Some(f)) => format!("{f} ({})", v.hex),
        _ => v.hex,
    });
    CallDetail {
        name: o.name.map(|n| n.0).unwrap_or_default(),
        address: o.address.0,
        clean: o.ended == "returned",
        ended,
        value,
        buffers: o
            .buffers
            .into_iter()
            .map(|b| CallBufferDetail {
                label: format!("argument {}", b.arg + 1),
                size: b.size,
                text: b.text.0,
                hex: b.hex.0,
                changed: b.changed,
            })
            .collect(),
        stdout: o.stdout.0,
        stderr: o.stderr.0,
        steps: o.steps,
        notes: o.notes,
        given,
    }
}

impl ViewModel {
    /// Opens the call dialog for the function at `address`, filled from its signature.
    pub fn begin_call(&mut self, address: u64) {
        let (name, sig) = match self.functions.find(address) {
            Some(f) => (f.name.clone(), f.signature.clone()),
            None => (format!("{address:#x}"), None),
        };
        self.tools.call_dialog = Some(CallDialog::new(address, &name, sig.as_deref()));
    }

    /// Opens the call dialog for the function being looked at.
    pub fn begin_call_current(&mut self) {
        match self.current.as_ref().map(|c| c.address) {
            Some(a) => self.begin_call(a),
            None => self.toast(ToastLevel::Info, "Pick a function first."),
        }
    }

    /// Closes the call dialog.
    pub fn cancel_call(&mut self) {
        if self.tools.call_dialog.as_ref().is_some_and(|d| d.running) {
            return;
        }
        self.tools.call_dialog = None;
    }

    /// Calls the function the dialog describes.
    pub fn submit_call(&mut self) {
        let Some(d) = self.tools.call_dialog.as_mut().filter(|d| !d.running) else {
            return;
        };
        let args = match d.args() {
            Ok(a) => a,
            Err(e) => {
                d.error = Some(e);
                return;
            }
        };
        d.error = None;
        d.running = true;
        let given = if d.params.is_empty() {
            "no arguments".to_string()
        } else {
            d.params
                .iter()
                .map(|p| {
                    if p.kind == ParamKind::Text {
                        format!("{:?}", p.value)
                    } else {
                        p.value.trim().to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        self.tools.emulation.running = true;
        self.tools.emulation.doing = format!("Calling {}", d.name);
        self.call("emulate_call", args, move |vm, res| {
            vm.tools.emulation.running = false;
            let outcome = res
                .and_then(parse::<EmulateCallOut>)
                .map(|o| EmulationResult::Call(Box::new(detail_of(o, given))))
                .map_err(|e| plain_error(&e));
            match outcome {
                Ok(result) => {
                    vm.tools.call_dialog = None;
                    vm.tools.emulation.error = None;
                    vm.tools.emulation.result = Some(result);
                    vm.tools.request_tab(NavTab::Emulation);
                }
                Err(e) => match vm.tools.call_dialog.as_mut() {
                    Some(d) => {
                        d.running = false;
                        d.error = Some(e);
                    }
                    None => vm.tools.emulation.error = Some(e),
                },
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_fills_the_rows_and_the_return_kind() {
        let (ret, p) =
            parse_signature("int vm_run(struct vm *vm, const uint8_t *code, unsigned len)");
        assert_eq!(ret, "int");
        assert_eq!(
            p.iter().map(|(_, k)| *k).collect::<Vec<_>>(),
            [ParamKind::Buffer, ParamKind::Buffer, ParamKind::Int]
        );
        let (ret, p) = parse_signature("char * strdup2(const char *s, double scale, float f)");
        assert_eq!(ret, "ptr");
        assert_eq!(
            p.iter().map(|(_, k)| *k).collect::<Vec<_>>(),
            [ParamKind::Text, ParamKind::Double, ParamKind::Float]
        );
        let (ret, p) = parse_signature("void cleanup(void)");
        assert_eq!((ret.as_str(), p.len()), ("void", 0));
        let (ret, p) = parse_signature("undefined8 FUN_00101020(long a, void (*cb)(int, int))");
        assert_eq!(ret, "u64");
        assert_eq!(p[1].1, ParamKind::Pointer);
        assert_eq!(parse_signature("garbage").0, "");
    }

    #[test]
    fn the_dialog_builds_the_call_and_names_what_is_wrong() {
        let mut d = CallDialog::new(
            0x1255,
            "vm_run",
            Some("int vm_run(char *s, int n, void *buf)"),
        );
        d.params[0].value = "hello".into();
        d.params[1].value = "0x10".into();
        d.params[2].value = "32".into();
        d.libc = true;
        d.max_steps = "1_000".into();
        let a = d.args().expect("valid");
        assert_eq!(a["address"], "0x1255");
        assert_eq!(a["args"][0], json!({"string": "hello"}));
        assert_eq!(a["args"][1], json!({"int": "0x10"}));
        assert_eq!(a["args"][2], json!({"buffer": 32}));
        assert_eq!(
            (a["libc"].clone(), a["max_steps"].clone()),
            (json!(true), json!(1000))
        );
        d.params[1].value.clear();
        assert!(d.args().expect_err("empty number").contains("Argument 2"));
        d.params[1].value = "7".into();
        d.params[2].value = "many".into();
        assert!(d.args().expect_err("bad size").contains("Argument 3"));
    }
}
