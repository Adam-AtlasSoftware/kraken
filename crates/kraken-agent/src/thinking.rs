//! How hard a model thinks before it answers: one setting (off, low, medium, high), mapped to
//! each API's own parameter.
//!
//! ```toml
//! [thinking]
//! anthropic = "medium"          # extended thinking budget
//! gemini = "low"                # thinkingBudget
//! openai_compatible = "high"    # reasoning_effort
//! "agent:claude" = "low"        # terminal agents, where they support it
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::ProviderConfig;

/// The setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effort {
    Off,
    Low,
    Medium,
    High,
}

impl Effort {
    pub const ALL: [Effort; 4] = [Effort::Off, Effort::Low, Effort::Medium, Effort::High];

    pub fn as_str(self) -> &'static str {
        match self {
            Effort::Off => "off",
            Effort::Low => "low",
            Effort::Medium => "medium",
            Effort::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Effort> {
        Effort::ALL.into_iter().find(|e| e.as_str() == s.trim())
    }

    /// Anthropic extended-thinking budget in tokens (`None` for off).
    pub fn anthropic_budget(self) -> Option<u32> {
        match self {
            Effort::Off => None,
            Effort::Low => Some(1024),
            Effort::Medium => Some(4096),
            Effort::High => Some(16384),
        }
    }

    /// Gemini `thinkingBudget` (0 turns thinking off where the model allows it).
    pub fn gemini_budget(self) -> u32 {
        match self {
            Effort::Off => 0,
            Effort::Low => 1024,
            Effort::Medium => 8192,
            Effort::High => 24576,
        }
    }

    /// OpenAI `reasoning_effort` (`None` for off: the parameter is left out).
    pub fn openai_effort(self) -> Option<&'static str> {
        match self {
            Effort::Off => None,
            Effort::Low => Some("low"),
            Effort::Medium => Some("medium"),
            Effort::High => Some("high"),
        }
    }
}

/// Adds extended thinking to an Anthropic Messages request body. The API wants the thinking
/// blocks of earlier tool turns sent back, which KRAKEN does not keep, so a request that
/// continues a tool call is left as it is.
pub fn apply_anthropic(body: &mut Value, effort: Effort, continues_tool_turn: bool) {
    let Some(budget) = effort.anthropic_budget() else {
        return;
    };
    if continues_tool_turn {
        return;
    }
    body["thinking"] = json!({"type": "enabled", "budget_tokens": budget});
    // The budget counts against max_tokens, which must stay above it; thinking also
    // requires the default temperature.
    let max = body["max_tokens"].as_u64().unwrap_or(0);
    if max <= u64::from(budget) {
        body["max_tokens"] = json!(u64::from(budget) + 4096);
    }
    if let Value::Object(m) = body {
        m.remove("temperature");
    }
}

/// Adds `generationConfig.thinkingConfig` to a Gemini request body.
pub fn apply_gemini(body: &mut Value, effort: Effort) {
    if !body["generationConfig"].is_object() {
        body["generationConfig"] = json!({});
    }
    body["generationConfig"]["thinkingConfig"] = json!({"thinkingBudget": effort.gemini_budget()});
}

/// Adds `reasoning_effort` to an OpenAI-compatible chat request body.
pub fn apply_openai(body: &mut Value, effort: Effort) {
    if let Some(e) = effort.openai_effort() {
        body["reasoning_effort"] = json!(e);
    }
}

/// The `[thinking]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ThinkingConfig(pub BTreeMap<String, Effort>);

impl ThinkingConfig {
    /// The `[thinking]` table of a whole `config.toml`; empty when missing.
    pub fn from_config_text(text: &str) -> Result<Self, String> {
        let table: toml::Table = text.parse().map_err(|e| format!("{e}"))?;
        match table.get("thinking") {
            None => Ok(ThinkingConfig::default()),
            Some(v) => v
                .clone()
                .try_into::<ThinkingConfig>()
                .map_err(|e| format!("[thinking]: {e}")),
        }
    }

    /// The table of the config file at `path`; empty when the file or table is missing or bad.
    pub fn load(path: Option<&std::path::Path>) -> Self {
        path.and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| Self::from_config_text(&t).ok())
            .unwrap_or_default()
    }

    /// The key of `cfg`: the provider kind, or `agent:<id>` for a terminal agent.
    pub fn key_of(cfg: &ProviderConfig) -> String {
        match cfg {
            ProviderConfig::OpenaiCompatible { .. } => "openai_compatible".into(),
            ProviderConfig::Anthropic { .. } => "anthropic".into(),
            ProviderConfig::Gemini { .. } => "gemini".into(),
            ProviderConfig::Replay { .. } => "replay".into(),
            ProviderConfig::Local { .. } => "local".into(),
            ProviderConfig::TerminalAgent { agent, .. } => format!("agent:{agent}"),
        }
    }

    /// The effort set for the provider of `cfg`.
    pub fn for_config(&self, cfg: &ProviderConfig) -> Option<Effort> {
        self.0.get(&Self::key_of(cfg)).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_gets_a_budget_and_room_for_the_answer() {
        let mut b = json!({"max_tokens": 1000, "temperature": 0.2});
        apply_anthropic(&mut b, Effort::Medium, false);
        assert_eq!(b["thinking"]["budget_tokens"], 4096);
        assert_eq!(b["max_tokens"], 4096 + 4096);
        assert!(b.get("temperature").is_none());
    }

    #[test]
    fn anthropic_off_and_tool_continuations_are_left_alone() {
        let mut b = json!({"max_tokens": 1000});
        apply_anthropic(&mut b, Effort::Off, false);
        apply_anthropic(&mut b, Effort::High, true);
        assert_eq!(b, json!({"max_tokens": 1000}));
    }

    #[test]
    fn gemini_and_openai_map_each_level() {
        let mut g = json!({});
        apply_gemini(&mut g, Effort::High);
        assert_eq!(
            g["generationConfig"]["thinkingConfig"]["thinkingBudget"],
            24576
        );
        apply_gemini(&mut g, Effort::Off);
        assert_eq!(g["generationConfig"]["thinkingConfig"]["thinkingBudget"], 0);
        let mut o = json!({});
        apply_openai(&mut o, Effort::Low);
        assert_eq!(o["reasoning_effort"], "low");
        let mut off = json!({});
        apply_openai(&mut off, Effort::Off);
        assert!(off.get("reasoning_effort").is_none());
    }

    #[test]
    fn the_table_is_keyed_by_provider() {
        let t = ThinkingConfig::from_config_text(
            "[thinking]\nanthropic = \"high\"\n\"agent:claude\" = \"low\"\n",
        )
        .expect("parses");
        let a = ProviderConfig::Anthropic {
            model: None,
            api_key: crate::config::SecretRef::Env("K".into()),
            base_url: None,
            max_tokens: None,
            context_window: None,
        };
        assert_eq!(t.for_config(&a), Some(Effort::High));
        let c = ProviderConfig::TerminalAgent {
            agent: "claude".into(),
            model: None,
            args: vec![],
        };
        assert_eq!(t.for_config(&c), Some(Effort::Low));
        assert!(ThinkingConfig::from_config_text("[thinking]\nanthropic = \"max\"\n").is_err());
    }
}
