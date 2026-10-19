//! Reading and writing `[[local_models]]` for the model cards, keeping the rest of the file.

use std::path::PathBuf;

use kraken_host::KrakenConfig;
use kraken_proto::infer::LocalModel;
use serde_json::Value;

/// The `config.toml` the cards edit; `None` means nothing can be saved.
#[derive(Debug, Clone, Default)]
pub struct LocalModelStore {
    path: Option<PathBuf>,
}

fn points_at(table: &Option<Value>, id: &str) -> bool {
    table
        .as_ref()
        .is_some_and(|v| v["kind"] == "local" && v["model"] == id)
}

impl LocalModelStore {
    /// A store over `path`.
    pub fn new(path: Option<PathBuf>) -> Self {
        LocalModelStore { path }
    }

    /// The models set up, in the file's order.
    pub fn load(&self) -> Result<Vec<LocalModel>, String> {
        let Some(path) = &self.path else {
            return Ok(Vec::new());
        };
        KrakenConfig::from_file(path)
            .map(|c| c.local_models)
            .map_err(|e| e.to_string())
    }

    fn edit(&self, f: impl FnOnce(&mut KrakenConfig)) -> Result<(), String> {
        let path = self
            .path
            .as_deref()
            .ok_or("There is no settings folder to save to (HOME is not set).")?;
        let mut cfg = KrakenConfig::from_file(path).map_err(|e| e.to_string())?;
        f(&mut cfg);
        cfg.save(path).map_err(|e| e.to_string())
    }

    /// Replaces the record with the same id.
    pub fn update(&self, model: &LocalModel) -> Result<(), String> {
        self.edit(|cfg| {
            if let Some(m) = cfg.local_models.iter_mut().find(|m| m.id == model.id) {
                *m = model.clone();
            }
        })
    }

    /// Forgets the model. The assistant and rewriting stop using it too, when they did. The
    /// downloaded files stay where they are.
    pub fn remove(&self, id: &str) -> Result<(), String> {
        self.edit(|cfg| {
            cfg.local_models.retain(|m| m.id != id);
            if points_at(&cfg.provider, id) {
                cfg.provider = None;
            }
            if points_at(&cfg.rewrite, id) {
                cfg.rewrite = None;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kraken_proto::infer::{LocalEngine, MultiGpuMode};

    use super::*;

    fn model(id: &str) -> LocalModel {
        LocalModel {
            id: id.into(),
            name: id.into(),
            engine: LocalEngine::Llama,
            model_path: PathBuf::from("/m.gguf"),
            devices: Vec::new(),
            cpu_only: false,
            multi_gpu: MultiGpuMode::Split,
            shares: None,
            main_device: None,
            context_size: None,
            autostart: true,
            extra: None,
        }
    }

    #[test]
    fn editing_keeps_the_other_tables_and_removing_clears_the_roles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kraken/config.toml");
        let cfg = KrakenConfig {
            local_models: vec![model("a"), model("b")],
            provider: Some(serde_json::json!({"kind": "local", "model": "a"})),
            rewrite: Some(serde_json::json!({"kind": "local", "model": "b"})),
            ..KrakenConfig::default()
        };
        cfg.save(&path).unwrap();

        let store = LocalModelStore::new(Some(path.clone()));
        let mut a = model("a");
        a.autostart = false;
        store.update(&a).unwrap();
        let back = store.load().unwrap();
        assert!(!back[0].autostart && back[1].autostart);
        let file = KrakenConfig::from_file(&path).unwrap();
        assert!(file.provider.is_some() && file.rewrite.is_some());

        store.remove("a").unwrap();
        let file = KrakenConfig::from_file(&path).unwrap();
        assert_eq!(file.local_models.len(), 1);
        assert!(
            file.provider.is_none(),
            "the assistant used the removed model"
        );
        assert!(file.rewrite.is_some(), "rewriting used another one");
    }

    #[test]
    fn without_a_file_there_is_nothing_and_nothing_to_save() {
        let store = LocalModelStore::new(None);
        assert!(store.load().unwrap().is_empty());
        assert!(store.update(&model("a")).is_err());
    }
}
