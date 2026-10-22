//! AI usage: what one model call cost, running totals, AI jobs and the estimate shown before
//! AI work starts.
//!
//! Money is always an estimate: KRAKEN computes it from token counts and a price table, never
//! from a provider's bill. Terminal agents report no tokens (they are billed by the agent's own
//! subscription) and local models cost nothing.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What the model call was for.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AiFeature {
    /// The assistant: chat, explain, overview.
    Assistant,
    /// Suggest names (the auto-name pass).
    AutoName,
    /// Automate: the agent that works through the whole flow.
    Automate,
    /// The Rust rewrite: translations, specs and repairs.
    Rewrite,
    /// Byte patches planned from edited decompiled code (`patch_from_source`).
    Patch,
    /// `kraken eval`.
    Eval,
    /// Anything else.
    Other,
}

impl AiFeature {
    /// The wire name (`auto_name`).
    pub fn as_str(self) -> &'static str {
        match self {
            AiFeature::Assistant => "assistant",
            AiFeature::AutoName => "auto_name",
            AiFeature::Automate => "automate",
            AiFeature::Rewrite => "rewrite",
            AiFeature::Patch => "patch",
            AiFeature::Eval => "eval",
            AiFeature::Other => "other",
        }
    }

    /// A short name for people ("Rust rewrite").
    pub fn label(self) -> &'static str {
        match self {
            AiFeature::Assistant => "Assistant",
            AiFeature::AutoName => "Suggest names",
            AiFeature::Automate => "Automate",
            AiFeature::Rewrite => "Rust rewrite",
            AiFeature::Patch => "Patch from source",
            AiFeature::Eval => "Evaluation",
            AiFeature::Other => "AI work",
        }
    }

    /// Parses [`as_str`](Self::as_str); unknown names are `Other`.
    pub fn parse(s: &str) -> AiFeature {
        match s {
            "assistant" => AiFeature::Assistant,
            "auto_name" => AiFeature::AutoName,
            "automate" => AiFeature::Automate,
            "rewrite" => AiFeature::Rewrite,
            "patch" => AiFeature::Patch,
            "eval" => AiFeature::Eval,
            _ => AiFeature::Other,
        }
    }
}

/// Where the model runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiProviderKind {
    /// A model API in the cloud, billed per token.
    Api,
    /// A model on this computer (Ollama, LM Studio, llama-server): free.
    Local,
    /// A terminal agent (Claude Code, Codex, Gemini CLI), billed by its own subscription.
    TerminalAgent,
}

impl AiProviderKind {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AiProviderKind::Api => "api",
            AiProviderKind::Local => "local",
            AiProviderKind::TerminalAgent => "terminal_agent",
        }
    }

    /// Parses [`as_str`](Self::as_str); unknown names are `Api`.
    pub fn parse(s: &str) -> AiProviderKind {
        match s {
            "local" => AiProviderKind::Local,
            "terminal_agent" => AiProviderKind::TerminalAgent,
            _ => AiProviderKind::Api,
        }
    }
}

/// How a call is paid for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiBilling {
    /// Per token; the cost is an estimate from the price table.
    Metered,
    /// By the terminal agent's own subscription; KRAKEN sees no tokens.
    Subscription,
    /// A local model: free.
    Free,
    /// Per token, but the price table has no entry for the model.
    Unpriced,
}

impl AiBilling {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AiBilling::Metered => "metered",
            AiBilling::Subscription => "subscription",
            AiBilling::Free => "free",
            AiBilling::Unpriced => "unpriced",
        }
    }

    /// Parses [`as_str`](Self::as_str); unknown names are `Unpriced`.
    pub fn parse(s: &str) -> AiBilling {
        match s {
            "metered" => AiBilling::Metered,
            "subscription" => AiBilling::Subscription,
            "free" => AiBilling::Free,
            _ => AiBilling::Unpriced,
        }
    }
}

/// Who started a piece of AI work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiOrigin {
    /// The person, in the window.
    Gui,
    /// The person, on the command line.
    Cli,
    /// An agent (an assistant run, a terminal agent, an MCP client).
    Agent,
    /// Tests and embedding code.
    Other,
}

impl AiOrigin {
    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AiOrigin::Gui => "gui",
            AiOrigin::Cli => "cli",
            AiOrigin::Agent => "agent",
            AiOrigin::Other => "other",
        }
    }

    /// Parses [`as_str`](Self::as_str).
    pub fn parse(s: &str) -> AiOrigin {
        match s {
            "gui" => AiOrigin::Gui,
            "cli" => AiOrigin::Cli,
            "agent" => AiOrigin::Agent,
            _ => AiOrigin::Other,
        }
    }

    /// "you", "you (command line)", "an agent".
    pub fn label(self) -> &'static str {
        match self {
            AiOrigin::Gui => "you",
            AiOrigin::Cli => "you (command line)",
            AiOrigin::Agent => "an agent",
            AiOrigin::Other => "KRAKEN",
        }
    }
}

/// One model call, as the usage ledger stores it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiCallRecord {
    /// When the call ended, milliseconds since the Unix epoch.
    pub ts_ms: i64,
    /// What it was for.
    pub feature: AiFeature,
    /// Where the model runs.
    pub provider_kind: AiProviderKind,
    /// Provider id (`anthropic`, `openai_compatible`) or agent id (`claude`).
    pub provider: String,
    /// The model, when known.
    pub model: String,
    /// The daemon job the call belongs to (`job-3`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// The AI run the call belongs to (an assistant run id, `ai-3`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Who started the work.
    pub origin: AiOrigin,
    /// Input tokens, when the provider reported them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    /// Output tokens, when the provider reported them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
    /// How long the call took, milliseconds.
    pub wall_ms: u64,
    /// Estimated cost in US dollars; `None` when it cannot be estimated (see `billing`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    /// How the call is paid for.
    pub billing: AiBilling,
}

/// Sums over model calls.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiUsageTotals {
    /// Model calls.
    pub calls: u64,
    /// Input tokens reported.
    pub input_tokens: u64,
    /// Output tokens reported.
    pub output_tokens: u64,
    /// Time spent waiting for models, milliseconds.
    pub wall_ms: u64,
    /// Estimated cost of the metered calls, US dollars (an estimate).
    pub cost_usd: f64,
    /// Calls billed by a terminal agent's subscription.
    #[serde(default)]
    pub subscription_calls: u64,
    /// Calls to local models (free).
    #[serde(default)]
    pub free_calls: u64,
    /// Metered calls whose model has no price in the table.
    #[serde(default)]
    pub unpriced_calls: u64,
}

impl AiUsageTotals {
    /// Adds one call.
    pub fn add(&mut self, r: &AiCallRecord) {
        self.calls += 1;
        self.input_tokens += r.input_tokens.unwrap_or(0);
        self.output_tokens += r.output_tokens.unwrap_or(0);
        self.wall_ms += r.wall_ms;
        self.cost_usd += r.cost_usd.unwrap_or(0.0);
        match r.billing {
            AiBilling::Metered => {}
            AiBilling::Subscription => self.subscription_calls += 1,
            AiBilling::Free => self.free_calls += 1,
            AiBilling::Unpriced => self.unpriced_calls += 1,
        }
    }

    /// Adds other totals.
    pub fn merge(&mut self, o: &AiUsageTotals) {
        self.calls += o.calls;
        self.input_tokens += o.input_tokens;
        self.output_tokens += o.output_tokens;
        self.wall_ms += o.wall_ms;
        self.cost_usd += o.cost_usd;
        self.subscription_calls += o.subscription_calls;
        self.free_calls += o.free_calls;
        self.unpriced_calls += o.unpriced_calls;
    }

    /// "12 calls, 48k tokens, about $0.31 (estimate)".
    pub fn line(&self) -> String {
        let mut parts = vec![format!(
            "{} call{}",
            self.calls,
            if self.calls == 1 { "" } else { "s" }
        )];
        let tokens = self.input_tokens + self.output_tokens;
        if tokens > 0 {
            parts.push(format!("{} tokens", short_count(tokens)));
        }
        parts.push(self.cost_text());
        parts.join(", ")
    }

    /// The money part of [`line`](Self::line): "about $0.31 (estimate)", "billed by the agent's
    /// subscription", "free (local model)".
    pub fn cost_text(&self) -> String {
        let metered = self
            .calls
            .saturating_sub(self.subscription_calls + self.free_calls + self.unpriced_calls);
        if metered > 0 || self.cost_usd > 0.0 {
            let mut s = format!("about {} (estimate)", money(self.cost_usd));
            if self.unpriced_calls > 0 {
                s.push_str(&format!(
                    ", {} call(s) with no known price",
                    self.unpriced_calls
                ));
            }
            return s;
        }
        if self.unpriced_calls > 0 {
            return "price unknown (add the model to [pricing])".into();
        }
        if self.subscription_calls > 0 {
            return "billed by the agent's subscription".into();
        }
        if self.free_calls > 0 {
            return "free (local model)".into();
        }
        "nothing spent".into()
    }
}

/// Where a piece of AI work stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiJobStatus {
    /// Still working.
    Running,
    /// Finished.
    Succeeded,
    /// Ended with an error.
    Failed,
    /// Stopped by a person.
    Cancelled,
    /// Stopped because it reached a limit (calls, cost or the daily budget).
    Limited,
}

impl AiJobStatus {
    /// True once the work has ended.
    pub fn is_terminal(self) -> bool {
        self != AiJobStatus::Running
    }

    /// A word for people.
    pub fn label(self) -> &'static str {
        match self {
            AiJobStatus::Running => "running",
            AiJobStatus::Succeeded => "finished",
            AiJobStatus::Failed => "failed",
            AiJobStatus::Cancelled => "stopped",
            AiJobStatus::Limited => "stopped at its limit",
        }
    }
}

/// A piece of AI work: a rewrite job, an assistant task, an Automate run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiJobView {
    /// Id of the AI work (`ai-3`).
    pub id: String,
    /// The daemon job behind it, when there is one: what `job_cancel` stops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// What it is for.
    pub feature: AiFeature,
    /// One line saying what it does ("Rewriting checksum").
    pub label: String,
    /// Where the model runs.
    pub provider_kind: AiProviderKind,
    /// Provider id or agent id.
    pub provider: String,
    /// The model, when known.
    pub model: String,
    /// Who started it.
    pub origin: AiOrigin,
    /// The agent or user id that started it.
    #[serde(default)]
    pub started_by: String,
    /// Where it stands.
    pub status: AiJobStatus,
    /// When it started, milliseconds since the Unix epoch.
    pub started_ms: i64,
    /// When it ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_ms: Option<i64>,
    /// Usage so far.
    pub usage: AiUsageTotals,
    /// Why it ended, for a failure or a limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl AiJobView {
    /// "claude-sonnet-5-5" or the provider when no model is known.
    pub fn model_label(&self) -> String {
        if self.model.is_empty() {
            self.provider.clone()
        } else {
            self.model.clone()
        }
    }
}

/// What AI work will cost at most, shown before it starts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiEstimate {
    /// What it is for.
    pub feature: AiFeature,
    /// Where the model runs.
    pub provider_kind: AiProviderKind,
    /// Provider id or agent id.
    pub provider: String,
    /// The model, when known.
    pub model: String,
    /// The most model calls the work can make.
    pub max_calls: u64,
    /// How it is paid for.
    pub billing: AiBilling,
    /// Low end of the cost, US dollars (an estimate); `None` when there is no price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_low_usd: Option<f64>,
    /// High end of the cost, US dollars (an estimate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_high_usd: Option<f64>,
}

impl AiEstimate {
    /// "about $0.20 to $1.10 (estimate)", "billed by your subscription", "free, local".
    pub fn cost_text(&self) -> String {
        match self.billing {
            AiBilling::Free => "free, local".into(),
            AiBilling::Subscription => "billed by your subscription".into(),
            AiBilling::Unpriced => {
                "price unknown: this model is not in the price table (add it under [pricing])"
                    .into()
            }
            AiBilling::Metered => match (self.cost_low_usd, self.cost_high_usd) {
                (Some(lo), Some(hi)) if money(lo) != money(hi) => {
                    format!("about {} to {} (estimate)", money(lo), money(hi))
                }
                (_, Some(hi)) => format!("up to about {} (estimate)", money(hi)),
                _ => "price unknown".into(),
            },
        }
    }

    /// The model, or the provider when no model is named.
    pub fn model_label(&self) -> String {
        if self.model.is_empty() {
            self.provider.clone()
        } else {
            format!("{} ({})", self.model, self.provider)
        }
    }

    /// Several lines for a confirmation question.
    pub fn text(&self) -> String {
        format!(
            "{}: up to {} model call{}.\nModel: {}.\nCost: {}.",
            self.feature.label(),
            self.max_calls,
            if self.max_calls == 1 { "" } else { "s" },
            self.model_label(),
            self.cost_text()
        )
    }

    /// The high end of the cost that counts against limits: 0 for free and subscription work.
    pub fn high_usd(&self) -> f64 {
        match self.billing {
            AiBilling::Metered => self.cost_high_usd.unwrap_or(0.0),
            _ => 0.0,
        }
    }
}

/// `$0.0042` below a cent, `$0.31` otherwise.
pub fn money(usd: f64) -> String {
    if usd <= 0.0 {
        "$0.00".into()
    } else if usd < 0.01 {
        format!("${usd:.4}")
    } else {
        format!("${usd:.2}")
    }
}

/// 950, 12k, 3.4M.
pub fn short_count(n: u64) -> String {
    match n {
        0..=999 => n.to_string(),
        1_000..=999_999 => format!("{}k", n / 1_000),
        _ => format!("{:.1}M", n as f64 / 1_000_000.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(billing: AiBilling, cost: Option<f64>) -> AiCallRecord {
        AiCallRecord {
            ts_ms: 0,
            feature: AiFeature::Rewrite,
            provider_kind: AiProviderKind::Api,
            provider: "anthropic".into(),
            model: "m".into(),
            job_id: None,
            run_id: None,
            origin: AiOrigin::Gui,
            input_tokens: Some(1000),
            output_tokens: Some(200),
            wall_ms: 5,
            cost_usd: cost,
            billing,
        }
    }

    #[test]
    fn totals_say_what_was_spent() {
        let mut t = AiUsageTotals::default();
        assert_eq!(t.cost_text(), "nothing spent");
        t.add(&rec(AiBilling::Subscription, None));
        assert_eq!(t.cost_text(), "billed by the agent's subscription");
        t.add(&rec(AiBilling::Metered, Some(0.25)));
        assert_eq!(t.calls, 2);
        assert_eq!(t.input_tokens, 2000);
        assert!(t.line().contains("about $0.25 (estimate)"), "{}", t.line());
        let mut free = AiUsageTotals::default();
        free.add(&rec(AiBilling::Free, Some(0.0)));
        assert_eq!(free.cost_text(), "free (local model)");
    }

    #[test]
    fn estimates_are_labelled() {
        let e = AiEstimate {
            feature: AiFeature::Rewrite,
            provider_kind: AiProviderKind::Api,
            provider: "anthropic".into(),
            model: "claude".into(),
            max_calls: 30,
            billing: AiBilling::Metered,
            cost_low_usd: Some(0.2),
            cost_high_usd: Some(1.1),
        };
        assert_eq!(e.cost_text(), "about $0.20 to $1.10 (estimate)");
        assert!(e.text().contains("up to 30 model calls"));
        assert_eq!(money(0.004), "$0.0040");
        assert_eq!(short_count(48_200), "48k");
        assert_eq!(AiFeature::parse("auto_name"), AiFeature::AutoName);
    }
}
