//! The list the Assistant and the Rewriting pickers share: models on this computer (the ones set
//! up, and "Set up a model on this computer..."), servers you run, cloud services and terminal
//! agents.

use kraken_proto::infer::LocalModel;

use super::provider::{ProviderDraft, ProviderKind};

/// One line of the picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickEntry {
    /// A model set up on this computer.
    LocalModel {
        /// Its id in `[[local_models]]`.
        id: String,
        /// Name for people.
        name: String,
    },
    /// "+ Set up a model on this computer...": opens the guided setup.
    SetUp,
    /// A server the person runs (Ollama, vLLM, anything OpenAI-compatible).
    Server(ProviderKind),
    /// A cloud service.
    Cloud(ProviderKind),
    /// A terminal agent.
    Agent {
        /// Its id.
        id: String,
        /// Name and availability, as shown.
        label: String,
    },
}

/// A titled group of entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickGroup {
    /// The group's heading.
    pub title: &'static str,
    /// Its lines.
    pub entries: Vec<PickEntry>,
}

/// The servers a person runs.
pub const SERVERS: [ProviderKind; 5] = [
    ProviderKind::Ollama,
    ProviderKind::LmStudio,
    ProviderKind::LlamaServer,
    ProviderKind::Vllm,
    ProviderKind::OpenAiCompatible,
];

/// The cloud services.
pub const CLOUD: [ProviderKind; 3] = [
    ProviderKind::Anthropic,
    ProviderKind::OpenAi,
    ProviderKind::Gemini,
];

/// The groups, in the order the picker shows them. `agents` are `(id, label)` pairs.
pub fn groups(models: &[LocalModel], agents: &[(String, String)]) -> Vec<PickGroup> {
    let mut local: Vec<PickEntry> = models
        .iter()
        .map(|m| PickEntry::LocalModel {
            id: m.id.clone(),
            name: m.name.clone(),
        })
        .collect();
    local.push(PickEntry::SetUp);
    vec![
        PickGroup {
            title: "On this computer",
            entries: local,
        },
        PickGroup {
            title: "Server you run",
            entries: SERVERS.iter().copied().map(PickEntry::Server).collect(),
        },
        PickGroup {
            title: "Cloud",
            entries: CLOUD.iter().copied().map(PickEntry::Cloud).collect(),
        },
        PickGroup {
            title: "Terminal agent",
            entries: agents
                .iter()
                .map(|(id, label)| PickEntry::Agent {
                    id: id.clone(),
                    label: label.clone(),
                })
                .collect(),
        },
    ]
}

impl PickEntry {
    /// The text on the line.
    pub fn label(&self) -> String {
        match self {
            PickEntry::LocalModel { name, .. } => name.clone(),
            PickEntry::SetUp => "+ Set up a model on this computer...".into(),
            PickEntry::Server(k) | PickEntry::Cloud(k) => k.label().into(),
            PickEntry::Agent { label, .. } => label.clone(),
        }
    }

    /// The hover text.
    pub fn help(&self) -> String {
        match self {
            PickEntry::LocalModel { .. } => {
                "A model KRAKEN runs on this computer. Nothing leaves your machine.".into()
            }
            PickEntry::SetUp => {
                "Check this computer, pick a model that fits and download it".into()
            }
            PickEntry::Server(k) | PickEntry::Cloud(k) => k.help().into(),
            PickEntry::Agent { label, .. } => format!("Use {label} as the assistant"),
        }
    }
}

impl ProviderDraft {
    /// True when `entry` is what the form has chosen.
    pub fn is_picked(&self, entry: &PickEntry) -> bool {
        match entry {
            PickEntry::LocalModel { id, .. } => {
                self.kind == ProviderKind::Local && self.model == *id
            }
            PickEntry::SetUp => false,
            PickEntry::Server(k) | PickEntry::Cloud(k) => self.kind == *k,
            PickEntry::Agent { id, .. } => self.kind.is_agent() && self.agent == *id,
        }
    }

    /// Chooses `entry`. Returns true for "Set up a model...", which changes nothing here.
    pub fn pick(&mut self, entry: &PickEntry) -> bool {
        match entry {
            PickEntry::SetUp => return true,
            PickEntry::LocalModel { id, .. } => {
                if !self.is_picked(entry) {
                    *self = ProviderDraft::for_local(id);
                }
            }
            PickEntry::Server(k) | PickEntry::Cloud(k) => self.switch_kind(*k),
            PickEntry::Agent { id, .. } => {
                if !self.is_picked(entry) {
                    *self = ProviderDraft::for_agent(id);
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agents() -> Vec<(String, String)> {
        vec![("claude".into(), "Claude Code".into())]
    }

    #[test]
    fn the_groups_come_in_the_decided_order() {
        let g = groups(&[], &agents());
        let titles: Vec<_> = g.iter().map(|g| g.title).collect();
        assert_eq!(
            titles,
            [
                "On this computer",
                "Server you run",
                "Cloud",
                "Terminal agent"
            ]
        );
        assert_eq!(g[0].entries, vec![PickEntry::SetUp], "no models yet");
        assert_eq!(g[1].entries.len(), 5);
        assert_eq!(g[3].entries[0].label(), "Claude Code");
    }

    #[test]
    fn picking_changes_the_form_and_set_up_asks_for_the_dialog() {
        let mut d = ProviderDraft::preset(ProviderKind::Ollama);
        let local = PickEntry::LocalModel {
            id: "qwen".into(),
            name: "Qwen".into(),
        };
        assert!(!d.pick(&local));
        assert!(d.is_picked(&local) && d.kind == ProviderKind::Local && d.model == "qwen");
        assert!(
            d.pick(&PickEntry::SetUp),
            "set up is a request, not a choice"
        );
        assert!(d.is_picked(&local), "and leaves the choice alone");
        d.pick(&PickEntry::Cloud(ProviderKind::Anthropic));
        assert_eq!(d.kind, ProviderKind::Anthropic);
        d.pick(&PickEntry::Agent {
            id: "codex".into(),
            label: "Codex".into(),
        });
        assert!(d.kind.is_agent() && d.agent == "codex");
    }
}
