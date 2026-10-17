//! [`AgentsHub`]: the list of agents, their setup, the notice and the connection test, for the
//! AI settings. It lives in the application, not in a project's view-model.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use kraken_acp::NoticeStore;
use tokio::runtime::Handle;

use super::catalogue::{Built, build};
use super::setup::SetupState;
use super::test_agent::AgentTestState;
use super::{AgentRow, AgentsConfig};

/// Whether the one-time notice has been acknowledged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoticeState {
    /// The notice was acknowledged (now or earlier).
    pub acknowledged: bool,
    /// The acknowledgement could not be saved (it still counts for this run; the notice is
    /// advice, not a lock).
    pub save_error: Option<String>,
}

/// What a project's view-model needs to start the chosen agent.
#[derive(Clone)]
pub struct AgentEnv {
    /// How agents are found and started.
    pub config: AgentsConfig,
    /// The one-time notice was acknowledged.
    pub acknowledged: bool,
}

pub(super) enum Msg {
    Rows(u64, Box<Built>),
    Setup(SetupState),
    SetupDone { id: String, name: String },
    Test(u64, AgentTestState),
}

/// The agents the settings list, and what can be done with them.
pub struct AgentsHub {
    /// The known agents, built-in ones first.
    pub rows: Vec<AgentRow>,
    /// The list has been built at least once.
    pub loaded: bool,
    /// The list is being rebuilt.
    pub loading: bool,
    /// Why `agents.toml` could not be read (the built-in agents still work).
    pub catalogue_error: Option<String>,
    /// The first line of what this computer can or cannot do, when it cannot run agents.
    pub platform_note: Option<String>,
    /// The one-time notice.
    pub notice: NoticeState,
    /// Downloading and installing an agent.
    pub setup: SetupState,
    /// The connection test.
    pub test: AgentTestState,
    /// Why something was refused (plain language).
    pub error: Option<String>,
    pub(super) config: Option<AgentsConfig>,
    pub(super) store: Option<NoticeStore>,
    pub(super) rt: Handle,
    pub(super) tx: Sender<Msg>,
    rx: Receiver<Msg>,
    pub(super) repaint: Option<Arc<dyn Fn() + Send + Sync>>,
    pub(super) refresh_seq: u64,
    pub(super) test_seq: u64,
}

impl AgentsHub {
    /// A hub that runs its background work on `rt`. `config` is where agents are found (`None`:
    /// the user's directories, read from the environment on first use).
    pub fn new(rt: Handle, config: Option<AgentsConfig>) -> Self {
        let (tx, rx) = channel();
        let mut hub = AgentsHub {
            rows: Vec::new(),
            loaded: false,
            loading: false,
            catalogue_error: None,
            platform_note: None,
            notice: NoticeState::default(),
            setup: SetupState::Idle,
            test: AgentTestState::Idle,
            error: None,
            config: None,
            store: None,
            rt,
            tx,
            rx,
            repaint: None,
            refresh_seq: 0,
            test_seq: 0,
        };
        if let Some(c) = config {
            hub.configure(c);
        }
        hub
    }

    /// Called when background work has news, so the window redraws.
    pub fn set_repaint(&mut self, f: Arc<dyn Fn() + Send + Sync>) {
        self.repaint = Some(f);
    }

    /// Uses `config`. Rereads the saved acknowledgement and clears the list.
    pub fn configure(&mut self, config: AgentsConfig) {
        let store = config.config_dir.as_deref().map(NoticeStore::in_config_dir);
        self.notice = NoticeState {
            acknowledged: store.as_ref().is_some_and(NoticeStore::is_acknowledged),
            save_error: None,
        };
        self.store = store;
        self.config = Some(config);
        self.loaded = false;
        self.loading = false;
        self.rows.clear();
        self.refresh_seq += 1;
    }

    /// The configuration, made from the environment on first use. `None` when neither `HOME`
    /// nor `XDG_DATA_HOME` is set.
    pub fn config(&mut self) -> Option<AgentsConfig> {
        if self.config.is_none() {
            match AgentsConfig::from_env(true) {
                Some(c) => self.configure(c),
                None => {
                    self.loaded = true;
                    self.error = Some(
                        "KRAKEN cannot tell where to keep agent files: neither XDG_DATA_HOME nor HOME is set."
                            .into(),
                    );
                    return None;
                }
            }
        }
        self.config.clone()
    }

    /// Whether agents get the daemon-backed MCP server (their edits then reach the window live).
    pub fn set_daemon(&mut self, use_daemon: bool) {
        if let Some(c) = self.config.as_mut() {
            c.use_daemon = use_daemon;
        } else if let Some(mut c) = AgentsConfig::from_env(use_daemon) {
            c.use_daemon = use_daemon;
            self.configure(c);
        }
    }

    /// What a project's view-model needs to start an agent.
    pub fn env(&mut self) -> Option<AgentEnv> {
        let config = self.config()?;
        Some(AgentEnv {
            config,
            acknowledged: self.notice.acknowledged,
        })
    }

    /// The agent with `id`.
    pub fn row(&self, id: &str) -> Option<&AgentRow> {
        self.rows.iter().find(|r| r.id == id)
    }

    /// Takes in what the background tasks have reported. Call once per frame.
    pub fn poll(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Rows(seq, built) => {
                    if seq != self.refresh_seq {
                        continue;
                    }
                    self.rows = built.rows;
                    self.catalogue_error = built.catalogue_error;
                    self.platform_note = built.platform_note;
                    self.loading = false;
                    self.loaded = true;
                }
                Msg::Setup(state) => {
                    if self.setup.running() {
                        self.setup = state;
                    }
                }
                Msg::SetupDone { id, name } => {
                    self.setup = SetupState::Done {
                        agent_id: id,
                        agent_name: name,
                    };
                    self.refresh();
                }
                Msg::Test(seq, state) => {
                    if seq == self.test_seq {
                        self.test = state;
                    }
                }
            }
        }
    }

    /// Builds the list the first time it is needed.
    pub fn ensure_loaded(&mut self) {
        if !self.loaded && !self.loading {
            self.refresh();
        }
    }

    /// Looks again at what each agent needs (off the UI thread: it runs `node --version`).
    pub fn refresh(&mut self) {
        let Some(cfg) = self.config() else {
            return;
        };
        self.loading = true;
        self.refresh_seq += 1;
        let seq = self.refresh_seq;
        let tx = self.tx.clone();
        let repaint = self.repaint.clone();
        self.rt.spawn_blocking(move || {
            let built = build(&cfg);
            let _ = tx.send(Msg::Rows(seq, Box::new(built)));
            if let Some(f) = repaint {
                f();
            }
        });
    }

    /// The person read the notice. Remembers it in the config directory; if that fails the
    /// notice still counts for this run.
    pub fn acknowledge(&mut self) {
        self.notice.acknowledged = true;
        self.notice.save_error = match &self.store {
            Some(s) => s.acknowledge().err().map(|e| {
                format!("KRAKEN could not remember that you read this ({e}); it will ask again next time.")
            }),
            None => Some(
                "KRAKEN has no place to remember this; it will ask again next time.".to_string(),
            ),
        };
    }
}
