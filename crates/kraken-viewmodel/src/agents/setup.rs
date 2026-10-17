//! "Set up": download Node.js if needed and install an agent's adapter, after an explicit yes.

use std::sync::Arc;

use kraken_acp::{AgentSetup, NODE_VERSION, NodeRuntime, install_adapter, node_download_for};
use kraken_host::provision::{Fetcher, HttpsFetcher, Progress};

use super::hub::Msg;
use super::{AgentsHub, Availability};

/// What setting an agent up would download, shown before anything is fetched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupPlan {
    /// Agent id.
    pub agent_id: String,
    /// Agent name.
    pub agent_name: String,
    /// One line per download.
    pub downloads: Vec<String>,
    /// Where the files go.
    pub into_dir: String,
}

/// How far setup has got.
#[derive(Debug, Clone, PartialEq)]
pub struct SetupProgress {
    /// Agent id.
    pub agent_id: String,
    /// Agent name.
    pub agent_name: String,
    /// What is happening ("Downloading Node.js").
    pub step: String,
    /// 0 to 1 when the size is known.
    pub fraction: Option<f32>,
}

/// State of the setup flow.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum SetupState {
    /// Nothing going on.
    #[default]
    Idle,
    /// Waiting for the person to agree to the downloads.
    Confirm(SetupPlan),
    /// Downloading and installing.
    Running(SetupProgress),
    /// It failed (plain-language reason).
    Failed {
        /// Agent id.
        agent_id: String,
        /// What went wrong.
        message: String,
    },
    /// It worked.
    Done {
        /// Agent id.
        agent_id: String,
        /// Agent name.
        agent_name: String,
    },
}

impl SetupState {
    /// Downloading or installing right now.
    pub fn running(&self) -> bool {
        matches!(self, SetupState::Running(_))
    }
}

impl AgentsHub {
    /// Shows what setting `id` up would download and waits for a yes
    /// ([`confirm_setup`](Self::confirm_setup)). Nothing is fetched yet.
    pub fn request_setup(&mut self, id: &str) {
        if self.setup.running() {
            return;
        }
        let Some(cfg) = self.config.clone() else {
            return;
        };
        let Some(row) = self.row(id) else {
            return;
        };
        let Availability::NeedsSetup { downloads_node, .. } = &row.availability else {
            return;
        };
        let AgentSetup::NodeAdapter(spec) = row.profile.setup else {
            return;
        };
        let mut downloads = Vec::new();
        if *downloads_node {
            let size = node_download_for(&cfg.resolver.platform)
                .map(|d| format!(" (about {} MB)", d.approx_mib))
                .unwrap_or_default();
            downloads.push(format!(
                "Node.js {NODE_VERSION}{size} from nodejs.org, checked against a built-in SHA-256 before it is unpacked"
            ));
        }
        downloads.push(format!(
            "{}@{} and its dependencies from the npm registry (a pinned list with integrity hashes; install scripts are switched off)",
            spec.package, spec.version
        ));
        self.setup = SetupState::Confirm(SetupPlan {
            agent_id: row.id.clone(),
            agent_name: row.name.clone(),
            downloads,
            into_dir: cfg.resolver.paths.root().display().to_string(),
        });
    }

    /// The person agreed: download and install.
    pub fn confirm_setup(&mut self) {
        let SetupState::Confirm(plan) = self.setup.clone() else {
            return;
        };
        let (Some(cfg), Some(row)) = (self.config.clone(), self.row(&plan.agent_id).cloned())
        else {
            self.setup = SetupState::Idle;
            return;
        };
        let AgentSetup::NodeAdapter(spec) = row.profile.setup else {
            self.setup = SetupState::Idle;
            return;
        };
        self.setup = SetupState::Running(SetupProgress {
            agent_id: plan.agent_id.clone(),
            agent_name: plan.agent_name.clone(),
            step: "Starting...".to_string(),
            fraction: None,
        });

        let tx = self.tx.clone();
        let repaint = self.repaint.clone();
        let (id, name) = (plan.agent_id, plan.agent_name);
        self.rt.spawn(async move {
            let send = move |msg: Msg| {
                let _ = tx.send(msg);
                if let Some(f) = &repaint {
                    f();
                }
            };
            let set = |state: SetupState| send(Msg::Setup(state));
            let running = |step: &str, fraction: Option<f32>| {
                SetupState::Running(SetupProgress {
                    agent_id: id.clone(),
                    agent_name: name.clone(),
                    step: step.to_string(),
                    fraction,
                })
            };
            let failed = |message: String| SetupState::Failed {
                agent_id: id.clone(),
                message,
            };

            let resolver = cfg.resolver.clone();
            let min = spec.min_node_major;
            let found = {
                let r = resolver.clone();
                tokio::task::spawn_blocking(move || r.node(min)).await
            };
            let node = match found {
                Ok(Some(n)) => n,
                Ok(None) => {
                    let fetcher: Arc<dyn Fetcher> = match cfg.fetcher.clone() {
                        Some(f) => f,
                        None => match HttpsFetcher::new() {
                            Ok(f) => Arc::new(f),
                            Err(e) => return set(failed(e.to_string())),
                        },
                    };
                    let data_dir = resolver
                        .paths
                        .root()
                        .parent()
                        .map(std::path::Path::to_path_buf)
                        .unwrap_or_default();
                    set(running("Downloading Node.js", Some(0.0)));
                    let mut last = None::<u32>;
                    let mut posting = |p: Progress| {
                        let state = match p {
                            Progress::Downloading { done, total, .. } => {
                                let pct = total
                                    .filter(|t| *t > 0)
                                    .map(|t| u32::try_from(done * 100 / t).unwrap_or(100));
                                if pct == last {
                                    return;
                                }
                                last = pct;
                                running(
                                    "Downloading Node.js",
                                    pct.map(|p| p.min(100) as f32 / 100.0),
                                )
                            }
                            Progress::Verifying { .. } => running("Checking the download", None),
                            Progress::Extracting { .. } => running("Unpacking Node.js", None),
                            _ => return,
                        };
                        set(state);
                    };
                    match NodeRuntime::provision(&data_dir, fetcher.as_ref(), &mut posting).await {
                        Ok(n) => n,
                        Err(e) => return set(failed(e.to_string())),
                    }
                }
                Err(e) => return set(failed(e.to_string())),
            };
            set(running(&format!("Installing {}", spec.package), None));
            match install_adapter(&row.profile, &resolver.paths, &node).await {
                Ok(_) => send(Msg::SetupDone {
                    id: id.clone(),
                    name: name.clone(),
                }),
                Err(e) => set(failed(e.to_string())),
            }
        });
    }

    /// Closes the consent step, or the result of the last setup, without doing anything.
    pub fn dismiss_setup(&mut self) {
        if !self.setup.running() {
            self.setup = SetupState::Idle;
        }
    }
}
