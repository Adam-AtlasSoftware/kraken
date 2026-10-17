//! `llama-server` (llama.cpp) backend. Launches an upstream binary; KRAKEN never bundles it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::backend::{BackendCapabilities, GpuApi, InferenceBackend, RunningBackend};
use crate::budget::{GIB, MemoryBudget, Reservation};
use crate::error::{InferError, Result};
use crate::logring::LogStream;
use crate::port::{LOOPBACK, generate_api_key, pick_free_port};
use crate::supervisor::{ManagedProcess, ProcessSpec};

pub const LLAMA_BINARY_NAME: &str = if cfg!(windows) {
    "llama-server.exe"
} else {
    "llama-server"
};

fn default_ctx() -> u32 {
    8192
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlamaSettings {
    /// Explicit llama-server path; otherwise discovered on PATH or in KRAKEN's data dir.
    #[serde(default)]
    pub binary_path: Option<PathBuf>,
    pub model_path: PathBuf,
    #[serde(default = "default_ctx")]
    pub context_size: u32,
    /// `-ngl`: layers offloaded to the GPU (large value = all).
    #[serde(default)]
    pub gpu_layers: Option<u32>,
    /// `--n-cpu-moe`: keep the expert tensors of the first N layers in system RAM.
    #[serde(default)]
    pub n_cpu_moe: Option<u32>,
    #[serde(default)]
    pub threads: Option<u32>,
    /// Fixed port; a free one is chosen when absent.
    #[serde(default)]
    pub port: Option<u16>,
    /// `--jinja`: needed for tool calls via the model's chat template.
    #[serde(default = "default_true")]
    pub jinja: bool,
}

impl LlamaSettings {
    pub fn from_value(v: Value) -> Result<Self> {
        let s: Self = serde_json::from_value(v).map_err(|e| InferError::Settings(e.to_string()))?;
        if s.model_path.as_os_str().is_empty() {
            return Err(InferError::Settings("model_path is empty".into()));
        }
        if s.context_size == 0 {
            return Err(InferError::Settings("context_size must be > 0".into()));
        }
        if s.threads == Some(0) {
            return Err(InferError::Settings("threads must be > 0".into()));
        }
        Ok(s)
    }
}

/// Maps settings to the `llama-server` command line (without the program name).
pub fn build_argv(s: &LlamaSettings, port: u16) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-m".into(),
        s.model_path.display().to_string(),
        "-c".into(),
        s.context_size.to_string(),
        "--host".into(),
        LOOPBACK.into(),
        "--port".into(),
        port.to_string(),
        // `/slots` can expose in-flight prompts (decompiled code) to any API-key holder.
        "--no-slots".into(),
    ];
    if let Some(n) = s.gpu_layers {
        a.push("-ngl".into());
        a.push(n.to_string());
    }
    if let Some(n) = s.n_cpu_moe {
        a.push("--n-cpu-moe".into());
        a.push(n.to_string());
    }
    if let Some(t) = s.threads {
        a.push("-t".into());
        a.push(t.to_string());
    }
    if s.jinja {
        a.push("--jinja".into());
    }
    a
}

/// Name of the environment variable `llama-server` reads its API key from. The key travels in the
/// environment, not argv, because `/proc/<pid>/cmdline` is world-readable.
pub const API_KEY_ENV: &str = "LLAMA_API_KEY";

/// The supervised process description for one run, with its per-run API key.
pub fn build_spec(binary: PathBuf, s: &LlamaSettings, port: u16, api_key: &str) -> ProcessSpec {
    let mut spec = ProcessSpec::new(binary, port, "/health");
    spec.args = build_argv(s, port);
    spec.env.push((API_KEY_ENV.into(), api_key.to_string()));
    spec.progress_parser = Some(parse_progress);
    spec
}

/// Finds `llama-server`: explicit path, then each `PATH` entry, then `data_dir/bin`.
pub fn discover_binary(
    explicit: Option<&Path>,
    path_var: Option<&std::ffi::OsStr>,
    data_dir: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return p.is_file().then(|| p.to_path_buf());
    }
    if let Some(pv) = path_var {
        for dir in std::env::split_paths(pv) {
            let c = dir.join(LLAMA_BINARY_NAME);
            if c.is_file() {
                return Some(c);
            }
        }
    }
    let c = data_dir?.join("bin").join(LLAMA_BINARY_NAME);
    c.is_file().then_some(c)
}

/// KRAKEN's per-user data dir (`$XDG_DATA_HOME/kraken` or `~/.local/share/kraken`).
pub fn default_data_dir() -> Option<PathBuf> {
    if let Some(x) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(x).join("kraken"));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".local/share/kraken"))
}

/// Extracts the engine version line from `--version` output (llama.cpp prints it on stderr).
pub fn parse_version(output: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.trim_start().starts_with("version:"))
        .map(|l| l.trim().to_string())
}

/// Heuristic GPU API detection from `--version` output (backend init lines name the API).
pub fn detect_gpu_apis(output: &str) -> Vec<GpuApi> {
    let lower = output.to_ascii_lowercase();
    let mut apis = vec![GpuApi::Cpu];
    for (needle, api) in [
        ("cuda", GpuApi::Cuda),
        ("rocm", GpuApi::Rocm),
        ("hip", GpuApi::Rocm),
        ("vulkan", GpuApi::Vulkan),
        ("metal", GpuApi::Metal),
    ] {
        if lower.contains(needle) && !apis.contains(&api) {
            apis.push(api);
        }
    }
    apis
}

/// Runs `<binary> --version` with a timeout and returns combined stdout+stderr.
pub fn run_version(binary: &Path, timeout: Duration) -> Option<String> {
    let mut child = Command::new(binary)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().ok()? {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    let out = child.wait_with_output().ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Some(text)
}

/// Loading fraction from llama.cpp's "offloaded 12/33 layers to GPU" log line.
pub fn parse_progress(line: &str) -> Option<f32> {
    let rest = line.split("offloaded ").nth(1)?;
    let frac = rest.split_whitespace().next()?;
    let (a, b) = frac.split_once('/')?;
    let (a, b): (f32, f32) = (a.parse().ok()?, b.parse().ok()?);
    (b > 0.0).then(|| a / b)
}

pub struct LlamaServerBackend {
    binary: Option<PathBuf>,
    version_output: Option<String>,
    data_dir: Option<PathBuf>,
}

impl Default for LlamaServerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LlamaServerBackend {
    /// No detection; the binary is resolved per `start` call.
    pub fn new() -> Self {
        Self {
            binary: None,
            version_output: None,
            data_dir: default_data_dir(),
        }
    }

    /// Looks for `llama-server` on PATH / the data dir and runs `--version` to detect its
    /// version and GPU APIs. Runs a subprocess; call from a blocking context at startup.
    pub fn discover() -> Self {
        let mut b = Self::new();
        b.binary = discover_binary(
            None,
            std::env::var_os("PATH").as_deref(),
            b.data_dir.as_deref(),
        );
        b.version_output = b
            .binary
            .as_deref()
            .and_then(|p| run_version(p, Duration::from_secs(10)));
        b
    }

    pub fn with_data_dir(mut self, dir: PathBuf) -> Self {
        self.data_dir = Some(dir);
        self
    }

    pub fn binary(&self) -> Option<&Path> {
        self.binary.as_deref()
    }

    fn resolve_binary(&self, s: &LlamaSettings) -> Result<PathBuf> {
        if let Some(p) = &s.binary_path {
            return discover_binary(Some(p), None, None)
                .ok_or_else(|| InferError::BinaryNotFound(p.display().to_string()));
        }
        if let Some(p) = &self.binary {
            return Ok(p.clone());
        }
        discover_binary(
            None,
            std::env::var_os("PATH").as_deref(),
            self.data_dir.as_deref(),
        )
        .ok_or_else(|| {
            InferError::BinaryNotFound(format!(
                "{LLAMA_BINARY_NAME} (not on PATH or in the KRAKEN data dir)"
            ))
        })
    }
}

/// Crude memory estimate from the model file size (+10% for KV cache and buffers). With
/// `gpu_layers` set the weights are charged to VRAM; with `n_cpu_moe` the experts live in RAM,
/// so RAM is charged conservatively for the whole file. Callers can reserve more explicitly.
fn estimate(s: &LlamaSettings) -> Reservation {
    let size = std::fs::metadata(&s.model_path).map_or(0, |m| m.len());
    let size = size + size / 10;
    let name = "llama-server model";
    match (s.gpu_layers.unwrap_or(0), s.n_cpu_moe) {
        (0, _) | (_, Some(_)) => Reservation::new(name, size, 0),
        _ => Reservation::new(name, GIB / 2, size),
    }
}

#[async_trait]
impl InferenceBackend for LlamaServerBackend {
    fn id(&self) -> &str {
        "llama-server"
    }

    fn display_name(&self) -> &str {
        "llama.cpp (llama-server)"
    }

    fn capabilities(&self) -> BackendCapabilities {
        let gpu_apis = self
            .version_output
            .as_deref()
            .map_or_else(|| vec![GpuApi::Cpu], detect_gpu_apis);
        BackendCapabilities {
            os: vec!["linux".into(), "windows".into(), "macos".into()],
            arch: vec!["x86_64".into(), "aarch64".into()],
            gpu_apis,
            min_ram: GIB / 2,
            supports_moe_offload: true,
            supports_tool_calls: true,
            license: "MIT".into(),
            detected_version: self.version_output.as_deref().and_then(parse_version),
        }
    }

    fn settings_schema(&self) -> Value {
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "llama.cpp server",
            "type": "object",
            "additionalProperties": false,
            "required": ["model_path"],
            "properties": {
                "model_path": {
                    "type": "string", "title": "Model file (GGUF)",
                    "x-kraken-widget": "file-path"
                },
                "binary_path": {
                    "type": "string", "title": "llama-server binary",
                    "description": "Leave empty to use PATH or the KRAKEN data directory.",
                    "x-kraken-widget": "file-path"
                },
                "context_size": {
                    "type": "integer", "title": "Context size (-c)",
                    "minimum": 1, "default": 8192
                },
                "gpu_layers": {
                    "type": "integer", "title": "GPU layers (-ngl)",
                    "minimum": 0, "description": "Layers offloaded to the GPU; 0 or empty = CPU only."
                },
                "n_cpu_moe": {
                    "type": "integer", "title": "Expert layers kept on CPU (--n-cpu-moe)",
                    "minimum": 0,
                    "description": "For MoE models on low-VRAM machines: keep the expert tensors of the first N layers in system RAM."
                },
                "threads": {
                    "type": "integer", "title": "CPU threads (-t)", "minimum": 1
                },
                "port": {
                    "type": "integer", "title": "Port",
                    "minimum": 1, "maximum": 65535,
                    "description": "Bound to 127.0.0.1 only. Empty = pick a free port."
                },
                "jinja": {
                    "type": "boolean", "title": "Jinja chat template (tool calls)", "default": true
                }
            }
        })
    }

    async fn start(&self, settings: Value, budget: &MemoryBudget) -> Result<RunningBackend> {
        let s = LlamaSettings::from_value(settings)?;
        if !s.model_path.is_file() {
            return Err(InferError::Settings(format!(
                "model_path {} is not a file",
                s.model_path.display()
            )));
        }
        let binary = self.resolve_binary(&s)?;
        let warnings = budget.enforce(&estimate(&s))?;
        let port = match s.port {
            Some(p) if p != 0 => p,
            _ => pick_free_port()?,
        };

        let api_key = generate_api_key()?;
        let spec = build_spec(binary, &s, port, &api_key);
        let process = ManagedProcess::start(spec)?;
        for w in warnings {
            process
                .ring()
                .push(LogStream::System, format!("budget warning: {w}"));
        }
        let model = s
            .model_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        Ok(RunningBackend::new(self.id(), model, process).with_api_key(api_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(v: Value) -> LlamaSettings {
        LlamaSettings::from_value(v).unwrap()
    }

    #[test]
    fn argv_minimal() {
        let s = settings(json!({"model_path": "/m/x.gguf"}));
        assert_eq!(
            build_argv(&s, 8080),
            [
                "-m",
                "/m/x.gguf",
                "-c",
                "8192",
                "--host",
                "127.0.0.1",
                "--port",
                "8080",
                "--no-slots",
                "--jinja"
            ]
        );
    }

    #[test]
    fn argv_full_moe() {
        let s = settings(json!({
            "model_path": "/m/x.gguf", "context_size": 32768, "gpu_layers": 99,
            "n_cpu_moe": 30, "threads": 12, "jinja": false
        }));
        assert_eq!(
            build_argv(&s, 9000),
            [
                "-m",
                "/m/x.gguf",
                "-c",
                "32768",
                "--host",
                "127.0.0.1",
                "--port",
                "9000",
                "--no-slots",
                "-ngl",
                "99",
                "--n-cpu-moe",
                "30",
                "-t",
                "12"
            ]
        );
    }

    #[test]
    fn spec_carries_the_key_in_env_not_argv_and_disables_slots() {
        let s = settings(json!({"model_path": "/m/x.gguf"}));
        let spec = build_spec("llama-server".into(), &s, 8080, "secretkey");
        assert!(spec.args.iter().any(|a| a == "--no-slots"));
        assert!(spec.args.iter().all(|a| !a.contains("secretkey")));
        assert!(
            spec.env
                .iter()
                .any(|(k, v)| k == API_KEY_ENV && v == "secretkey")
        );
    }

    #[test]
    fn host_is_always_loopback() {
        let s = settings(json!({"model_path": "/m/x.gguf"}));
        let a = build_argv(&s, 1);
        let i = a.iter().position(|x| x == "--host").unwrap();
        assert_eq!(a[i + 1], "127.0.0.1");
    }

    #[test]
    fn rejects_bad_settings() {
        assert!(LlamaSettings::from_value(json!({})).is_err());
        assert!(LlamaSettings::from_value(json!({"model_path": "x", "bogus": 1})).is_err());
        assert!(LlamaSettings::from_value(json!({"model_path": "x", "threads": 0})).is_err());
        assert!(LlamaSettings::from_value(json!({"model_path": "x", "context_size": 0})).is_err());
    }

    #[test]
    fn schema_covers_every_setting() {
        let b = LlamaServerBackend::new();
        let schema = b.settings_schema();
        let props = schema["properties"].as_object().unwrap();
        let full = serde_json::to_value(LlamaSettings {
            binary_path: Some("b".into()),
            model_path: "m".into(),
            context_size: 1,
            gpu_layers: Some(1),
            n_cpu_moe: Some(1),
            threads: Some(1),
            port: Some(1),
            jinja: true,
        })
        .unwrap();
        for k in full.as_object().unwrap().keys() {
            assert!(props.contains_key(k), "schema lacks {k}");
        }
        assert_eq!(props.len(), full.as_object().unwrap().len());
    }

    #[test]
    fn version_and_gpu_detection() {
        let out =
            "ggml_cuda_init: found 1 CUDA devices:\nversion: 6123 (abc1234)\nbuilt with gcc\n";
        assert_eq!(
            parse_version(out).as_deref(),
            Some("version: 6123 (abc1234)")
        );
        assert_eq!(detect_gpu_apis(out), vec![GpuApi::Cpu, GpuApi::Cuda]);
        assert_eq!(detect_gpu_apis("nothing"), vec![GpuApi::Cpu]);
    }

    #[test]
    fn progress_parse() {
        assert_eq!(
            parse_progress("load_tensors: offloaded 33/66 layers to GPU"),
            Some(0.5)
        );
        assert_eq!(parse_progress("something else"), None);
    }

    #[test]
    fn binary_discovery_order() {
        let dir = std::env::temp_dir().join(format!("kraken-infer-disc-{}", std::process::id()));
        let path_dir = dir.join("pathdir");
        let data = dir.join("data");
        std::fs::create_dir_all(&path_dir).unwrap();
        std::fs::create_dir_all(data.join("bin")).unwrap();
        let in_path = path_dir.join(LLAMA_BINARY_NAME);
        let in_data = data.join("bin").join(LLAMA_BINARY_NAME);
        std::fs::write(&in_data, "").unwrap();

        let pv = std::env::join_paths([&path_dir]).unwrap();
        assert_eq!(
            discover_binary(None, Some(&pv), Some(&data)),
            Some(in_data.clone())
        );
        std::fs::write(&in_path, "").unwrap();
        assert_eq!(discover_binary(None, Some(&pv), Some(&data)), Some(in_path));
        assert_eq!(
            discover_binary(Some(&in_data), Some(&pv), Some(&data)),
            Some(in_data)
        );
        assert_eq!(discover_binary(Some(&dir.join("nope")), None, None), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn capabilities_basics() {
        let c = LlamaServerBackend::new().capabilities();
        assert!(c.supports_moe_offload && c.supports_tool_calls);
        assert_eq!(c.license, "MIT");
    }
}
