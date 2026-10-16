//! The configured model, kept by the app so it survives opening and closing projects.

use std::path::PathBuf;
use std::sync::Arc;

use kraken_agent::ChatProvider;
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::assist::{
    ProviderBadge, ProviderDraft, ProviderKind, ProviderStore, badge_of,
};

/// The provider in use plus where it is saved.
pub struct AssistSetup {
    /// Reads and writes `[provider]` in `config.toml` and the secrets file beside it.
    pub store: ProviderStore,
    active: Option<(Arc<dyn ChatProvider>, ProviderBadge)>,
    problem: Option<String>,
}

impl AssistSetup {
    /// Loads the saved provider, if any. A saved provider that cannot be built (a missing key
    /// variable, a damaged file) is kept as a message for the chat panel.
    pub fn load(config_path: Option<PathBuf>) -> Self {
        let store = ProviderStore::new(config_path);
        let mut setup = AssistSetup {
            store,
            active: None,
            problem: None,
        };
        match setup.store.load() {
            Ok(Some(cfg)) => match setup.store.build(&cfg) {
                Ok(p) => setup.active = Some((p, badge_of(&cfg))),
                Err(e) => setup.problem = Some(e),
            },
            Ok(None) => {}
            Err(e) => {
                setup.problem = Some(format!("The AI settings in config.toml are not valid: {e}"))
            }
        }
        setup
    }

    /// Uses `provider` (not saved).
    pub fn set(&mut self, provider: Arc<dyn ChatProvider>, badge: ProviderBadge) {
        self.active = Some((provider, badge));
        self.problem = None;
    }

    /// Forgets the provider.
    pub fn clear(&mut self) {
        self.active = None;
        self.problem = None;
    }

    /// Notes a problem with the saved provider.
    pub fn set_problem(&mut self, problem: String) {
        self.active = None;
        self.problem = Some(problem);
    }

    /// True when a model is ready to use.
    #[cfg(test)]
    pub fn is_ready(&self) -> bool {
        self.active.is_some()
    }

    /// Gives the view-model the current provider (or tells it there is none).
    pub fn apply(&self, vm: &mut ViewModel) {
        match &self.active {
            Some((p, b)) => vm.assist.set_provider(p.clone(), b.clone()),
            None => vm.assist.clear_provider(),
        }
        vm.assist.provider_problem = self.problem.clone();
    }

    /// One click: saves the standard settings of `kind` and starts using them.
    pub fn use_preset(&mut self, kind: ProviderKind) -> Result<(), String> {
        let out = self.store.save(&ProviderDraft::preset(kind))?;
        let provider = self.store.build(&out.config)?;
        self.set(provider, badge_of(&out.config));
        Ok(())
    }
}
