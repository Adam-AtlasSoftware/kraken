//! Manifest-driven backend for any engine that serves an OpenAI-compatible HTTP API.
//!
//! A manifest (TOML) names the command as an argv array with `{placeholder}`s, the health path,
//! a JSON-Schema settings description and capabilities. `{port}` and `{host}` are supplied by
//! KRAKEN (host is always 127.0.0.1); every other placeholder must be a property of
//! `settings_schema` and is filled from the user's settings or the property's `default`.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::backend::{BackendCapabilities, GpuApi, InferenceBackend, RunningBackend};
use crate::budget::{GIB, MemoryBudget, Reservation};
use crate::error::{InferError, Result};
use crate::logring::LogStream;
use crate::port::{LOOPBACK, pick_free_port};
use crate::supervisor::{ManagedProcess, ProcessSpec};

const RESERVED: &[&str] = &["port", "host"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestCapabilities {
    #[serde(default = "default_os")]
    pub os: Vec<String>,
    #[serde(default = "default_arch")]
    pub arch: Vec<String>,
    #[serde(default = "default_gpu")]
    pub gpu_apis: Vec<GpuApi>,
    #[serde(default)]
    pub min_ram_mb: u64,
    #[serde(default)]
    pub supports_moe_offload: bool,
    #[serde(default)]
    pub supports_tool_calls: bool,
}

fn default_os() -> Vec<String> {
    vec!["linux".into()]
}
fn default_arch() -> Vec<String> {
    vec!["x86_64".into()]
}
fn default_gpu() -> Vec<GpuApi> {
    vec![GpuApi::Cpu]
}
fn default_health() -> String {
    "/v1/models".into()
}
fn default_ready_secs() -> u64 {
    600
}
fn default_grace_secs() -> u64 {
    5
}
fn empty_schema() -> Value {
    serde_json::json!({"type": "object", "properties": {}})
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub license: String,
    /// argv template; element 0 is the program (absolute path, or looked up on PATH).
    pub command: Vec<String>,
    #[serde(default = "default_health")]
    pub health_path: String,
    #[serde(default = "default_ready_secs")]
    pub ready_timeout_secs: u64,
    #[serde(default = "default_grace_secs")]
    pub grace_secs: u64,
    /// Extra environment for the engine (the parent environment is otherwise filtered).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub capabilities: ManifestCapabilities,
    #[serde(default = "empty_schema")]
    pub settings_schema: Value,
}

#[derive(Debug, PartialEq, Eq)]
enum Piece<'a> {
    Lit(String),
    Var(&'a str),
}

/// Splits a template into literals and `{name}` variables; `{{` and `}}` are literal braces.
fn parse_template(t: &str) -> Result<Vec<Piece<'_>>> {
    let mut out = Vec::new();
    let mut lit = String::new();
    let mut i = 0;
    let b = t.as_bytes();
    while i < b.len() {
        match b[i] {
            b'{' if b.get(i + 1) == Some(&b'{') => {
                lit.push('{');
                i += 2;
            }
            b'}' if b.get(i + 1) == Some(&b'}') => {
                lit.push('}');
                i += 2;
            }
            b'{' => {
                let end = t[i..]
                    .find('}')
                    .ok_or_else(|| InferError::Manifest(format!("unclosed '{{' in {t:?}")))?
                    + i;
                let name = &t[i + 1..end];
                if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    return Err(InferError::Manifest(format!(
                        "bad placeholder {{{name}}} in {t:?}"
                    )));
                }
                if !lit.is_empty() {
                    out.push(Piece::Lit(std::mem::take(&mut lit)));
                }
                out.push(Piece::Var(name));
                i = end + 1;
            }
            b'}' => {
                return Err(InferError::Manifest(format!("stray '}}' in {t:?}")));
            }
            _ => {
                // Copy one UTF-8 char.
                let ch = t[i..].chars().next().unwrap_or(' ');
                lit.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    if !lit.is_empty() {
        out.push(Piece::Lit(lit));
    }
    Ok(out)
}

fn render(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

impl Manifest {
    pub fn parse(text: &str) -> Result<Self> {
        let m: Manifest = toml::from_str(text).map_err(|e| InferError::Manifest(e.to_string()))?;
        m.validate()?;
        Ok(m)
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    fn properties(&self) -> Option<&Map<String, Value>> {
        self.settings_schema.get("properties")?.as_object()
    }

    fn validate(&self) -> Result<()> {
        let id_ok = !self.id.is_empty()
            && self
                .id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
        if !id_ok {
            return Err(InferError::Manifest(format!(
                "id {:?} must be lowercase [a-z0-9_-]",
                self.id
            )));
        }
        if self.command.is_empty() || self.command[0].is_empty() {
            return Err(InferError::Manifest("command is empty".into()));
        }
        if !self.health_path.starts_with('/') {
            return Err(InferError::Manifest(
                "health_path must start with '/'".into(),
            ));
        }
        if !self.settings_schema.is_object() {
            return Err(InferError::Manifest(
                "settings_schema must be a table".into(),
            ));
        }
        for tpl in &self.command {
            for piece in parse_template(tpl)? {
                if let Piece::Var(n) = piece
                    && !RESERVED.contains(&n)
                    && !self.properties().is_some_and(|p| p.contains_key(n))
                {
                    return Err(InferError::Manifest(format!(
                        "placeholder {{{n}}} is neither port/host nor in settings_schema.properties"
                    )));
                }
            }
        }
        if parse_template(&self.command[0])?
            .iter()
            .any(|p| matches!(p, Piece::Var(_)))
        {
            return Err(InferError::Manifest(
                "the program (command[0]) cannot contain placeholders".into(),
            ));
        }
        Ok(())
    }

    /// Merges property defaults under the user's settings and checks `required`.
    pub fn resolve_settings(&self, settings: &Value) -> Result<Map<String, Value>> {
        let given = match settings {
            Value::Object(m) => m.clone(),
            Value::Null => Map::new(),
            _ => return Err(InferError::Settings("settings must be an object".into())),
        };
        let mut out = Map::new();
        if let Some(props) = self.properties() {
            for (k, p) in props {
                if let Some(d) = p.get("default") {
                    out.insert(k.clone(), d.clone());
                }
            }
            for k in given.keys() {
                if !props.contains_key(k) {
                    return Err(InferError::Settings(format!("unknown setting {k:?}")));
                }
            }
        }
        out.extend(given);
        if let Some(req) = self
            .settings_schema
            .get("required")
            .and_then(Value::as_array)
        {
            for r in req.iter().filter_map(Value::as_str) {
                if !out.contains_key(r) {
                    return Err(InferError::Settings(format!(
                        "missing required setting {r:?}"
                    )));
                }
            }
        }
        Ok(out)
    }

    /// Expands the command template into `[program, args...]`.
    pub fn expand(&self, settings: &Value, port: u16) -> Result<Vec<String>> {
        let values = self.resolve_settings(settings)?;
        self.command
            .iter()
            .map(|tpl| {
                let mut s = String::new();
                for piece in parse_template(tpl)? {
                    match piece {
                        Piece::Lit(l) => s.push_str(&l),
                        Piece::Var("port") => s.push_str(&port.to_string()),
                        Piece::Var("host") => s.push_str(LOOPBACK),
                        Piece::Var(n) => {
                            let v = values.get(n).ok_or_else(|| {
                                InferError::Settings(format!("missing setting {n:?}"))
                            })?;
                            s.push_str(&render(v).ok_or_else(|| {
                                InferError::Settings(format!("setting {n:?} must be a scalar"))
                            })?);
                        }
                    }
                }
                Ok(s)
            })
            .collect()
    }
}

pub struct GenericOpenAiServerBackend {
    manifest: Manifest,
}

impl GenericOpenAiServerBackend {
    pub fn new(manifest: Manifest) -> Self {
        Self { manifest }
    }

    pub fn from_manifest_str(text: &str) -> Result<Self> {
        Ok(Self::new(Manifest::parse(text)?))
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
}

#[async_trait]
impl InferenceBackend for GenericOpenAiServerBackend {
    fn id(&self) -> &str {
        &self.manifest.id
    }

    fn display_name(&self) -> &str {
        self.manifest.name.as_deref().unwrap_or(&self.manifest.id)
    }

    fn capabilities(&self) -> BackendCapabilities {
        let c = &self.manifest.capabilities;
        BackendCapabilities {
            os: c.os.clone(),
            arch: c.arch.clone(),
            gpu_apis: c.gpu_apis.clone(),
            min_ram: c.min_ram_mb * 1024 * 1024,
            supports_moe_offload: c.supports_moe_offload,
            supports_tool_calls: c.supports_tool_calls,
            license: self.manifest.license.clone(),
            detected_version: None,
        }
    }

    fn settings_schema(&self) -> Value {
        self.manifest.settings_schema.clone()
    }

    async fn start(&self, settings: Value, budget: &MemoryBudget) -> Result<RunningBackend> {
        let m = &self.manifest;
        let values = m.resolve_settings(&settings)?;
        // Generic engines have no known memory model; charge the model file to RAM when a
        // `model` setting names an existing file, plus the manifest's minimum.
        let model_bytes = values
            .get("model")
            .and_then(Value::as_str)
            .and_then(|p| std::fs::metadata(p).ok())
            .map_or(0, |md| md.len());
        let ram = model_bytes + model_bytes / 10 + m.capabilities.min_ram_mb * 1024 * 1024;
        let warnings = budget.enforce(&Reservation::new(
            format!("{} model", m.id),
            ram.max(GIB / 4),
            0,
        ))?;

        let port = match values.get("port").and_then(Value::as_u64) {
            Some(p) if p != 0 => {
                u16::try_from(p).map_err(|_| InferError::Settings("port out of range".into()))?
            }
            _ => pick_free_port()?,
        };
        let mut argv = m.expand(&settings, port)?.into_iter();
        let program = argv.next().unwrap_or_default();

        let mut spec = ProcessSpec::new(program, port, m.health_path.clone());
        spec.args = argv.collect();
        spec.env = m.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        spec.health.ready_timeout = Duration::from_secs(m.ready_timeout_secs);
        spec.grace = Duration::from_secs(m.grace_secs);
        let process = ManagedProcess::start(spec)?;
        for w in warnings {
            process
                .ring()
                .push(LogStream::System, format!("budget warning: {w}"));
        }
        let model = values.get("model").and_then(Value::as_str).map(|p| {
            Path::new(p)
                .file_name()
                .map_or_else(|| p.to_string(), |n| n.to_string_lossy().into_owned())
        });
        Ok(RunningBackend::new(m.id.clone(), model, process))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MANIFEST: &str = r#"
id = "demo-engine"
name = "Demo"
license = "Apache-2.0"
command = ["/opt/demo/serve", "--model", "{model}", "--listen", "{host}:{port}", "--ctx", "{ctx}", "{{literal}}"]
health_path = "/health"

[capabilities]
os = ["linux"]
arch = ["x86_64"]
gpu_apis = ["cpu", "vulkan"]
min_ram_mb = 2048
supports_moe_offload = true

[settings_schema]
type = "object"
required = ["model"]

[settings_schema.properties.model]
type = "string"

[settings_schema.properties.ctx]
type = "integer"
default = 4096
"#;

    #[test]
    fn parses_and_expands() {
        let m = Manifest::parse(MANIFEST).unwrap();
        let argv = m.expand(&json!({"model": "/m/a b.gguf"}), 5555).unwrap();
        assert_eq!(
            argv,
            [
                "/opt/demo/serve",
                "--model",
                "/m/a b.gguf",
                "--listen",
                "127.0.0.1:5555",
                "--ctx",
                "4096",
                "{literal}"
            ]
        );
        let argv = m.expand(&json!({"model": "x", "ctx": 128}), 1).unwrap();
        assert_eq!(argv[6], "128");
    }

    #[test]
    fn capabilities_from_manifest() {
        let b = GenericOpenAiServerBackend::from_manifest_str(MANIFEST).unwrap();
        let c = b.capabilities();
        assert_eq!(c.min_ram, 2048 * 1024 * 1024);
        assert_eq!(c.gpu_apis, vec![GpuApi::Cpu, GpuApi::Vulkan]);
        assert!(c.supports_moe_offload && !c.supports_tool_calls);
        assert_eq!(b.id(), "demo-engine");
        assert_eq!(b.settings_schema()["required"][0], "model");
    }

    #[test]
    fn rejects_bad_manifests() {
        let bad_placeholder = MANIFEST.replace("{ctx}", "{nope}");
        assert!(Manifest::parse(&bad_placeholder).is_err());
        let bad_id = MANIFEST.replace("demo-engine", "Demo Engine");
        assert!(Manifest::parse(&bad_id).is_err());
        let unknown_key = format!("bogus = 1\n{MANIFEST}");
        assert!(Manifest::parse(&unknown_key).is_err());
        let var_program = MANIFEST.replace("/opt/demo/serve", "{model}");
        assert!(Manifest::parse(&var_program).is_err());
    }

    #[test]
    fn settings_errors() {
        let m = Manifest::parse(MANIFEST).unwrap();
        assert!(m.expand(&json!({}), 1).is_err());
        assert!(m.expand(&json!({"model": "x", "extra": 1}), 1).is_err());
        assert!(m.expand(&json!({"model": ["x"]}), 1).is_err());
    }

    #[test]
    fn template_scanner() {
        assert_eq!(
            parse_template("a{b}c").unwrap(),
            vec![
                Piece::Lit("a".into()),
                Piece::Var("b"),
                Piece::Lit("c".into())
            ]
        );
        assert!(parse_template("{a").is_err());
        assert!(parse_template("a}").is_err());
        assert!(parse_template("{a b}").is_err());
        assert_eq!(
            parse_template("héllo").unwrap(),
            vec![Piece::Lit("héllo".into())]
        );
    }

    #[test]
    fn shipped_example_manifest_parses() {
        let text = include_str!("../manifests/example-engine.toml");
        let m = Manifest::parse(text).unwrap();
        m.expand(&json!({"model": "/m/x.gguf"}), 1234).unwrap();
    }
}
