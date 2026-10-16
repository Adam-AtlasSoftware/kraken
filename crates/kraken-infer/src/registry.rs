use std::path::Path;
use std::sync::Arc;

use crate::backend::{GpuApi, InferenceBackend};
use crate::error::Result;
use crate::generic::GenericOpenAiServerBackend;
use crate::llama::LlamaServerBackend;

/// Constraints for [`BackendRegistry::filter`]; `None`/`false` means "don't care".
#[derive(Debug, Clone, Default)]
pub struct CapabilityFilter {
    pub os: Option<String>,
    pub arch: Option<String>,
    pub gpu_api: Option<GpuApi>,
    pub needs_moe_offload: bool,
    pub needs_tool_calls: bool,
    /// Machine RAM in bytes; backends whose `min_ram` exceeds it are dropped.
    pub total_ram: Option<u64>,
}

impl CapabilityFilter {
    /// Filter for the platform KRAKEN is running on.
    pub fn current_platform() -> Self {
        Self {
            os: Some(std::env::consts::OS.into()),
            arch: Some(std::env::consts::ARCH.into()),
            ..Self::default()
        }
    }
}

#[derive(Default)]
pub struct BackendRegistry {
    backends: Vec<Arc<dyn InferenceBackend>>,
}

impl BackendRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registry with the built-in backends (llama-server).
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        r.register(Arc::new(LlamaServerBackend::new()));
        r
    }

    /// Adds a backend, replacing any earlier one with the same id.
    pub fn register(&mut self, backend: Arc<dyn InferenceBackend>) {
        self.backends.retain(|b| b.id() != backend.id());
        self.backends.push(backend);
    }

    /// Registers every `*.toml` manifest in `dir`; returns the ids registered. A broken manifest
    /// fails the whole load so mistakes are not silently ignored.
    pub fn load_manifest_dir(&mut self, dir: &Path) -> Result<Vec<String>> {
        let mut paths: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        paths.sort();
        let mut ids = Vec::new();
        for p in paths {
            let b = GenericOpenAiServerBackend::new(crate::generic::Manifest::load(&p)?);
            ids.push(b.id().to_string());
            self.register(Arc::new(b));
        }
        Ok(ids)
    }

    pub fn list(&self) -> &[Arc<dyn InferenceBackend>] {
        &self.backends
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn InferenceBackend>> {
        self.backends.iter().find(|b| b.id() == id).cloned()
    }

    pub fn filter(&self, f: &CapabilityFilter) -> Vec<Arc<dyn InferenceBackend>> {
        self.backends
            .iter()
            .filter(|b| {
                let c = b.capabilities();
                f.os.as_ref().is_none_or(|o| c.os.contains(o))
                    && f.arch.as_ref().is_none_or(|a| c.arch.contains(a))
                    && f.gpu_api.is_none_or(|g| c.gpu_apis.contains(&g))
                    && (!f.needs_moe_offload || c.supports_moe_offload)
                    && (!f.needs_tool_calls || c.supports_tool_calls)
                    && f.total_ram.is_none_or(|r| c.min_ram <= r)
            })
            .cloned()
            .collect()
    }

    /// Backends usable on this machine's OS and architecture.
    pub fn available(&self) -> Vec<Arc<dyn InferenceBackend>> {
        self.filter(&CapabilityFilter::current_platform())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(id: &str, os: &str, moe: bool, gpu: &str) -> String {
        format!(
            r#"
id = "{id}"
license = "MIT"
command = ["/bin/true"]
[capabilities]
os = ["{os}"]
arch = ["x86_64", "aarch64"]
gpu_apis = ["{gpu}"]
min_ram_mb = 4096
supports_moe_offload = {moe}
"#
        )
    }

    fn registry() -> BackendRegistry {
        let mut r = BackendRegistry::with_defaults();
        for (id, os, moe, gpu) in [
            ("a-linux", "linux", true, "cpu"),
            ("b-win", "windows", false, "vulkan"),
        ] {
            r.register(Arc::new(
                GenericOpenAiServerBackend::from_manifest_str(&manifest(id, os, moe, gpu)).unwrap(),
            ));
        }
        r
    }

    fn ids(v: Vec<Arc<dyn InferenceBackend>>) -> Vec<String> {
        v.iter().map(|b| b.id().to_string()).collect()
    }

    #[test]
    fn filters_by_capability() {
        let r = registry();
        assert_eq!(r.list().len(), 3);
        let f = CapabilityFilter {
            os: Some("windows".into()),
            ..CapabilityFilter::default()
        };
        assert_eq!(ids(r.filter(&f)), ["llama-server", "b-win"]);
        let f = CapabilityFilter {
            os: Some("linux".into()),
            needs_moe_offload: true,
            ..CapabilityFilter::default()
        };
        assert_eq!(ids(r.filter(&f)), ["llama-server", "a-linux"]);
        let f = CapabilityFilter {
            gpu_api: Some(GpuApi::Vulkan),
            ..CapabilityFilter::default()
        };
        assert_eq!(ids(r.filter(&f)), ["b-win"]);
        let f = CapabilityFilter {
            total_ram: Some(1 << 30),
            needs_tool_calls: false,
            ..CapabilityFilter::default()
        };
        assert_eq!(ids(r.filter(&f)), ["llama-server"]);
    }

    #[test]
    fn register_replaces_same_id_and_get_works() {
        let mut r = registry();
        r.register(Arc::new(LlamaServerBackend::new()));
        assert_eq!(r.list().len(), 3);
        assert!(r.get("a-linux").is_some());
        assert!(r.get("zzz").is_none());
    }

    #[test]
    fn loads_manifest_dir() {
        let dir = std::env::temp_dir().join(format!("kraken-infer-reg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("x.toml"),
            manifest("from-dir", "linux", false, "cpu"),
        )
        .unwrap();
        std::fs::write(dir.join("ignored.txt"), "nope").unwrap();
        let mut r = BackendRegistry::new();
        assert_eq!(r.load_manifest_dir(&dir).unwrap(), ["from-dir"]);
        std::fs::write(dir.join("bad.toml"), "id = 1").unwrap();
        assert!(BackendRegistry::new().load_manifest_dir(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
