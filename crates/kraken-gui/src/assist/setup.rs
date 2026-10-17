//! The configured assistant, kept by the app so it survives opening and closing projects.

use std::path::PathBuf;
use std::sync::Arc;

use kraken_agent::ChatProvider;
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::agents::AgentEnv;
use kraken_viewmodel::assist::{
    BackendChoice, ProviderBadge, ProviderDraft, ProviderKind, ProviderStore,
};

/// The backend in use (a model API or a terminal agent) plus where it is saved.
pub struct AssistSetup {
    /// Reads and writes `[provider]` in `config.toml` and the secrets file beside it.
    pub store: ProviderStore,
    active: Option<(BackendChoice, ProviderBadge)>,
    problem: Option<String>,
}

impl AssistSetup {
    /// Loads the saved assistant, if any. A saved provider that cannot be built (a missing key
    /// variable, a damaged file) is kept as a message for the chat panel.
    pub fn load(config_path: Option<PathBuf>) -> Self {
        let store = ProviderStore::new(config_path);
        let mut setup = AssistSetup {
            store,
            active: None,
            problem: None,
        };
        match setup.store.load() {
            Ok(Some(cfg)) => match setup.store.choice(&cfg) {
                Ok(choice) => setup.active = Some((choice, setup.store.badge(&cfg))),
                Err(e) => setup.problem = Some(e),
            },
            Ok(None) => {}
            Err(e) => {
                setup.problem = Some(format!("The AI settings in config.toml are not valid: {e}"))
            }
        }
        setup
    }

    /// Uses the model API `provider` (not saved).
    pub fn set(&mut self, provider: Arc<dyn ChatProvider>, badge: ProviderBadge) {
        self.set_choice(BackendChoice::Api(provider), badge);
    }

    /// Uses `choice` (not saved).
    pub fn set_choice(&mut self, choice: BackendChoice, badge: ProviderBadge) {
        self.active = Some((choice, badge));
        self.problem = None;
    }

    /// Forgets the backend.
    pub fn clear(&mut self) {
        self.active = None;
        self.problem = None;
    }

    /// Notes a problem with the saved provider.
    pub fn set_problem(&mut self, problem: String) {
        self.active = None;
        self.problem = Some(problem);
    }

    /// True when a model or agent is ready to use.
    #[cfg(test)]
    pub fn is_ready(&self) -> bool {
        self.active.is_some()
    }

    /// Whether the active backend is a terminal agent.
    #[cfg(all(test, unix))]
    pub fn is_agent(&self) -> bool {
        matches!(self.active, Some((BackendChoice::Agent(_), _)))
    }

    /// Gives the view-model the current backend (or tells it there is none) and where agents
    /// are found.
    pub fn apply(&self, vm: &mut ViewModel, agents: Option<AgentEnv>) {
        match &self.active {
            Some((c, b)) => vm.assist.set_backend(c.clone(), b.clone()),
            None => vm.assist.clear_provider(),
        }
        vm.assist.agent_env = agents;
        vm.assist.provider_problem = self.problem.clone();
    }

    /// Tells the view-model where agents are found and whether the notice was read, without
    /// touching the running conversation.
    pub fn sync_agents(vm: &mut ViewModel, agents: Option<AgentEnv>) {
        vm.assist.agent_env = agents;
    }

    /// One click: saves the standard settings of `kind` and starts using them.
    pub fn use_preset(&mut self, kind: ProviderKind) -> Result<(), String> {
        let out = self.store.save(&ProviderDraft::preset(kind))?;
        let choice = self.store.choice(&out.config)?;
        let badge = self.store.badge(&out.config);
        self.set_choice(choice, badge);
        Ok(())
    }
}
