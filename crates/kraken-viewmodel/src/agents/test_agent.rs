//! "Test": start the agent without KRAKEN's tools, ask it one tiny question and report what
//! happened, so a missing sign-in or a broken install shows up in the settings and not in the
//! middle of a conversation.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kraken_acp::{AcpError, AcpEvent, AcpHost, DenyAll, HostConfig, PermissionPolicy};

use super::AgentsHub;
use super::hub::Msg;

/// How long the whole test may take (an agent can take a while to start).
const TEST_TIMEOUT: Duration = Duration::from_secs(90);

/// State of the connection test.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AgentTestState {
    /// Not running.
    #[default]
    Idle,
    /// Waiting for the agent.
    Running {
        /// Agent id.
        agent_id: String,
    },
    /// The agent answered.
    Passed {
        /// Agent id.
        agent_id: String,
        /// What it reported about itself and said (plain language).
        message: String,
    },
    /// It did not (plain-language reason).
    Failed {
        /// Agent id.
        agent_id: String,
        /// What went wrong.
        message: String,
    },
}

impl AgentTestState {
    /// A test is running.
    pub fn running(&self) -> bool {
        matches!(self, AgentTestState::Running { .. })
    }
}

fn plain(e: &AcpError) -> String {
    e.to_string()
}

impl AgentsHub {
    /// Starts the agent `agent` (with the chosen model and extra arguments) without KRAKEN's
    /// tools and asks it for one word. The result lands in [`AgentsHub::test`].
    pub fn test_agent(&mut self, agent: &str, model: Option<&str>, args: &[String]) {
        let agent_id = agent.to_string();
        if self.test.running() {
            return;
        }
        let fail = |hub: &mut AgentsHub, message: String| {
            hub.test = AgentTestState::Failed {
                agent_id: agent_id.clone(),
                message,
            };
        };
        if !self.notice.acknowledged {
            fail(
                self,
                "Read the note about terminal agents first, then test again.".into(),
            );
            return;
        }
        let Some(cfg) = self.config() else {
            fail(self, "KRAKEN cannot tell where to keep agent files.".into());
            return;
        };
        let Some(row) = self.row(agent) else {
            fail(self, format!("There is no agent called `{agent}`."));
            return;
        };
        let name = row.name.clone();
        let profile = row.profile.clone().with_choice(model, args);
        let launch = match cfg.resolver.status(&profile) {
            kraken_acp::AgentStatus::Detected(l) => l,
            kraken_acp::AgentStatus::Available { reason, .. } => {
                fail(
                    self,
                    format!("{name} is not set up yet ({reason}). Press Set up first."),
                );
                return;
            }
            kraken_acp::AgentStatus::Missing { reason }
            | kraken_acp::AgentStatus::Unsupported { reason } => {
                fail(self, format!("{name} cannot run here: {reason}"));
                return;
            }
        };
        self.test_seq += 1;
        let seq = self.test_seq;
        self.test = AgentTestState::Running {
            agent_id: agent_id.clone(),
        };
        let mut host_cfg = HostConfig::new(profile, launch, std::env::temp_dir(), None);
        host_cfg.permission = PermissionPolicy::Handler(Arc::new(DenyAll));
        host_cfg.parent_env = cfg.parent_env.clone();
        host_cfg.start_timeout = cfg.start_timeout;
        let tx = self.tx.clone();
        let repaint = self.repaint.clone();
        self.rt.spawn(async move {
            let started = Instant::now();
            let outcome = tokio::time::timeout(TEST_TIMEOUT, async {
                let (host, mut rx) = AcpHost::start(host_cfg).await?;
                let who = host.agent_info().clone();
                let prompted = host.prompt("Reply with the single word: ready").await;
                let mut said = String::new();
                while let Ok(ev) = rx.try_recv() {
                    if let AcpEvent::AgentText { text } = ev {
                        said.push_str(&text);
                    }
                }
                host.shutdown().await;
                prompted.map(|_| (who, said))
            })
            .await;
            let state = match outcome {
                Ok(Ok((who, said))) => {
                    let label = match (&who.name, &who.version) {
                        (Some(n), Some(v)) => format!("{n} {v}"),
                        (Some(n), None) => n.clone(),
                        _ => name.clone(),
                    };
                    let reply: String = kraken_proto::sanitize(said.trim())
                        .chars()
                        .take(60)
                        .collect();
                    let model = who.model.map(|m| format!(" using {m}")).unwrap_or_default();
                    AgentTestState::Passed {
                        agent_id: agent_id.clone(),
                        message: format!(
                            "Connected. {label}{model} answered \"{reply}\" in {} ms.",
                            started.elapsed().as_millis()
                        ),
                    }
                }
                Ok(Err(e)) => AgentTestState::Failed {
                    agent_id: agent_id.clone(),
                    message: plain(&e),
                },
                Err(_) => AgentTestState::Failed {
                    agent_id: agent_id.clone(),
                    message: format!(
                        "{name} did not answer within {} seconds.",
                        TEST_TIMEOUT.as_secs()
                    ),
                },
            };
            let _ = tx.send(Msg::Test(seq, state));
            if let Some(f) = repaint {
                f();
            }
        });
    }
}
