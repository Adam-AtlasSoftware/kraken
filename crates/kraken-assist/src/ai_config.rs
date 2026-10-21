//! What AI work may cost and which model does it: the `[ai_limits]` and `[pricing]` tables, the
//! model each feature uses (`[provider]` for the assistant, `[rewrite]` or else `[provider]` for
//! the rewrite) and the estimate shown before work starts.
//!
//! ```toml
//! [ai_limits]
//! max_calls_per_run = 200     # a run stops cleanly after this many model calls
//! max_cost_per_run = 5.0      # ... or once its estimated cost reaches this many US dollars
//! daily_budget = 10.0         # no new AI work once today's estimated total reaches this
//! skip_confirm_under = 0.10   # do not ask before runs estimated below this
//! low_context_mode = true     # send tools to the model by name; it asks for the details
//! ```

use std::path::Path;

use kraken_agent::ProviderConfig;
use kraken_host::KrakenConfig;
use kraken_proto::{AiBilling, AiEstimate, AiFeature, AiProviderKind};
use serde::{Deserialize, Serialize};

use crate::error::AssistError;
use crate::pricing::Pricing;
use crate::provider::{load_provider_config, load_rewrite_config};

/// The `[ai_limits]` table. Every limit is off when unset.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiLimits {
    /// Most model calls one run makes; it stops cleanly at the limit and keeps what it finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_calls_per_run: Option<u64>,
    /// Most estimated cost of one run, US dollars.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cost_per_run: Option<f64>,
    /// Most estimated cost of all AI work in a day (UTC), US dollars; new work is refused after.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daily_budget: Option<f64>,
    /// Runs whose estimate stays below this many US dollars start without asking. Free and
    /// subscription runs count as 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_confirm_under: Option<f64>,
    /// Low context mode: the assistant's model is told what tools exist by name and a short
    /// line, and asks for a tool's full description and parameters when it wants to use it
    /// (the `tool_help` tool). Saves thousands of tokens per request on a model with a small
    /// context window.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub low_context_mode: bool,
}

impl AiLimits {
    /// The `[ai_limits]` table of a whole `config.toml`; the defaults when it is missing.
    pub fn from_config_text(text: &str) -> Result<Self, String> {
        let table: toml::Table = text.parse().map_err(|e| format!("{e}"))?;
        match table.get("ai_limits") {
            None => Ok(AiLimits::default()),
            Some(v) => v
                .clone()
                .try_into::<AiLimits>()
                .map_err(|e| format!("[ai_limits]: {e}")),
        }
    }

    /// The limits of the config file at `path` (none when it or the table is missing or does
    /// not parse).
    pub fn load(path: Option<&Path>) -> Self {
        path.and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| Self::from_config_text(&t).ok())
            .unwrap_or_default()
    }

    /// Writes the table into the config file at `path`, keeping everything else.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let mut file = KrakenConfig::from_file(path).map_err(|e| e.to_string())?;
        let value = serde_json::to_value(self).map_err(|e| e.to_string())?;
        file.ai_limits = match &value {
            serde_json::Value::Object(m) if m.is_empty() => None,
            _ => Some(value),
        };
        file.save(path).map_err(|e| e.to_string())
    }
}

/// True for a server on this computer.
pub fn is_local_url(url: &str) -> bool {
    let rest = url
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = rest.split(['/', '?']).next().unwrap_or("");
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let name = if let Some(stripped) = host.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        host.split(':').next().unwrap_or("")
    };
    matches!(name, "localhost" | "127.0.0.1" | "::1" | "0.0.0.0") || name.starts_with("127.")
}

/// Where the model of `cfg` runs.
pub fn provider_kind_of(cfg: &ProviderConfig) -> AiProviderKind {
    match cfg {
        ProviderConfig::OpenaiCompatible { base_url, .. } if is_local_url(base_url) => {
            AiProviderKind::Local
        }
        ProviderConfig::TerminalAgent { .. } => AiProviderKind::TerminalAgent,
        // A recorded cassette answers from a file: nothing is sent anywhere.
        ProviderConfig::Replay { .. } => AiProviderKind::Local,
        // Served on this computer: free, but still in the usage ledger.
        ProviderConfig::Local { .. } => AiProviderKind::Local,
        _ => AiProviderKind::Api,
    }
}

/// The provider id and the model `cfg` asks for (the provider default when it names none).
pub fn model_of(cfg: &ProviderConfig) -> (String, String) {
    use kraken_agent::provider::{anthropic, gemini};
    match cfg {
        ProviderConfig::OpenaiCompatible { model, .. } => {
            ("openai-compatible".into(), model.clone())
        }
        ProviderConfig::Anthropic { model, .. } => (
            "anthropic".into(),
            model
                .clone()
                .unwrap_or_else(|| anthropic::DEFAULT_MODEL.into()),
        ),
        ProviderConfig::Gemini { model, .. } => (
            "gemini".into(),
            model
                .clone()
                .unwrap_or_else(|| gemini::DEFAULT_MODEL.into()),
        ),
        ProviderConfig::Replay { .. } => ("replay".into(), String::new()),
        ProviderConfig::Local { model } => ("local".into(), model.clone()),
        ProviderConfig::TerminalAgent { agent, model, .. } => {
            (agent.clone(), model.clone().unwrap_or_default())
        }
    }
}

/// `cfg` asking for `model` instead.
pub fn with_model(cfg: &ProviderConfig, model: &str) -> ProviderConfig {
    let m = model.trim().to_string();
    let mut out = cfg.clone();
    match &mut out {
        ProviderConfig::OpenaiCompatible { model, .. } | ProviderConfig::Local { model } => {
            *model = m
        }
        ProviderConfig::Anthropic { model, .. }
        | ProviderConfig::Gemini { model, .. }
        | ProviderConfig::TerminalAgent { model, .. } => *model = Some(m),
        ProviderConfig::Replay { .. } => {}
    }
    out
}

/// Which table a feature's model comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSource {
    /// `[provider]`, the assistant's model.
    Assistant,
    /// `[rewrite]`, the rewrite's own model.
    Rewrite,
}

/// The model a feature uses.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelChoice {
    /// The configuration.
    pub config: ProviderConfig,
    /// Where it runs.
    pub kind: AiProviderKind,
    /// Provider id or agent id.
    pub provider: String,
    /// The model (may be empty for a terminal agent that chooses itself).
    pub model: String,
    /// Which table it comes from.
    pub source: ModelSource,
}

impl ModelChoice {
    /// The choice for `cfg` read from `source`.
    pub fn new(config: ProviderConfig, source: ModelSource) -> Self {
        let (provider, model) = model_of(&config);
        ModelChoice {
            kind: provider_kind_of(&config),
            provider,
            model,
            config,
            source,
        }
    }

    /// "claude-sonnet-5-5 (anthropic)" or "claude (terminal agent)".
    pub fn label(&self) -> String {
        let place = match self.kind {
            AiProviderKind::Local => "on this computer",
            AiProviderKind::TerminalAgent => "terminal agent",
            AiProviderKind::Api => self.provider.as_str(),
        };
        if self.model.is_empty() {
            format!("{} ({place})", self.provider)
        } else {
            format!("{} ({place})", self.model)
        }
    }
}

/// Which model a rewrite run uses, as a command's `provider` argument names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RewriteModel {
    /// `[rewrite]` when there is one, else `[provider]` (the default).
    #[default]
    Configured,
    /// `[provider]`, the assistant's model, even when `[rewrite]` exists.
    Assistant,
}

impl RewriteModel {
    /// Parses `assistant` or `rewrite`; anything else is an error message.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim() {
            "" | "rewrite" | "configured" => Ok(RewriteModel::Configured),
            "assistant" => Ok(RewriteModel::Assistant),
            other => Err(format!(
                "`provider` must be `rewrite` (the [rewrite] table, else [provider]) or \
                 `assistant` (the [provider] table), not `{other}`"
            )),
        }
    }
}

/// The model the rewrite uses with the config file at `path`: `[rewrite]` when there is one
/// (unless `which` asks for the assistant's), else `[provider]`; with `model` in place of the
/// configured model when given.
pub fn rewrite_choice(
    path: Option<&Path>,
    which: RewriteModel,
    model: Option<&str>,
) -> Result<ModelChoice, AssistError> {
    let own = match which {
        RewriteModel::Configured => load_rewrite_config(path)?,
        RewriteModel::Assistant => None,
    };
    let (cfg, source) = match own {
        Some(c) => (c, ModelSource::Rewrite),
        None => (load_provider_config(path)?, ModelSource::Assistant),
    };
    let cfg = match model.map(str::trim).filter(|m| !m.is_empty()) {
        Some(m) => with_model(&cfg, m),
        None => cfg,
    };
    Ok(ModelChoice::new(cfg, source))
}

/// Writes (`Some`) or removes (`None`, "use the assistant's model") the `[rewrite]` table of
/// the config file at `path`, keeping everything else.
pub fn save_rewrite_config(path: &Path, cfg: Option<&ProviderConfig>) -> Result<(), String> {
    let mut file = KrakenConfig::from_file(path).map_err(|e| e.to_string())?;
    file.rewrite = match cfg {
        Some(c) => {
            let mut v = serde_json::to_value(c).map_err(|e| e.to_string())?;
            strip_nulls(&mut v);
            Some(v)
        }
        None => None,
    };
    file.save(path).map_err(|e| e.to_string())
}

/// Sets (or with `None` removes) the thinking effort of the provider `key` (see
/// `kraken_agent::ThinkingConfig::key_of`) in the `[thinking]` table of the config file.
pub fn save_thinking(
    path: &Path,
    key: &str,
    effort: Option<kraken_agent::Effort>,
) -> Result<(), String> {
    let mut file = KrakenConfig::from_file(path).map_err(|e| e.to_string())?;
    let mut table = kraken_agent::ThinkingConfig::load(Some(path));
    match effort {
        Some(e) => {
            table.0.insert(key.to_string(), e);
        }
        None => {
            table.0.remove(key);
        }
    }
    file.thinking = if table.0.is_empty() {
        None
    } else {
        Some(serde_json::to_value(&table).map_err(|e| e.to_string())?)
    };
    file.save(path).map_err(|e| e.to_string())
}

fn strip_nulls(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(m) => {
            m.retain(|_, x| !x.is_null());
            for x in m.values_mut() {
                strip_nulls(x);
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(strip_nulls),
        _ => {}
    }
}

/// Translation attempts per function when a call names none (`rewrite_function`'s default).
pub const REWRITE_ATTEMPTS: u32 = 3;
/// Functions re-translated per program-level repair round, at most.
pub const REPAIR_SUSPECTS: u64 = 3;
/// Attempts per re-translation in a repair round.
pub const REPAIR_ATTEMPTS: u64 = 2;

/// The most model calls a rewrite of `functions` functions can make: up to `attempts`
/// translations each (plus a spec each in spec mode) and the program-level repair rounds.
pub fn rewrite_max_calls(
    functions: u64,
    attempts: u32,
    spec_mode: bool,
    repair_rounds: u32,
) -> u64 {
    let per = u64::from(attempts.max(1)) + u64::from(spec_mode);
    functions
        .saturating_mul(per)
        .saturating_add(u64::from(repair_rounds) * REPAIR_SUSPECTS * REPAIR_ATTEMPTS)
}

/// Typical tokens of one call: (input, output) at the low and the high end.
fn typical_tokens(feature: AiFeature) -> ((u64, u64), (u64, u64)) {
    match feature {
        // One prompt with the decompile and callees, one reply with the code.
        AiFeature::Rewrite => ((2_500, 700), (9_000, 2_500)),
        // A tool loop: the context grows with every step.
        _ => ((3_000, 300), (14_000, 1_500)),
    }
}

/// What the person has set up for AI: the models, the prices and the limits.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AiPolicy {
    /// The assistant's model (`[provider]`).
    pub assistant: Option<ModelChoice>,
    /// The rewrite's model (`[rewrite]`, else `[provider]`).
    pub rewrite: Option<ModelChoice>,
    /// Prices for estimates.
    pub pricing: Pricing,
    /// Limits and the confirmation threshold.
    pub limits: AiLimits,
    /// Why the config could not be read, when it could not.
    pub problem: Option<String>,
}

impl AiPolicy {
    /// Reads the config file at `path`. A missing file gives no models and no limits.
    pub fn load(path: Option<&Path>) -> Self {
        let mut problem = None;
        let assistant = match load_provider_config(path) {
            Ok(c) => Some(ModelChoice::new(c, ModelSource::Assistant)),
            Err(AssistError::NoProvider(_)) => None,
            Err(e) => {
                problem = Some(e.to_string());
                None
            }
        };
        let rewrite = match load_rewrite_config(path) {
            Ok(Some(c)) => Some(ModelChoice::new(c, ModelSource::Rewrite)),
            Ok(None) => assistant.clone(),
            Err(e) => {
                problem = Some(e.to_string());
                assistant.clone()
            }
        };
        let text = path.and_then(|p| std::fs::read_to_string(p).ok());
        let limits = match text.as_deref().map(AiLimits::from_config_text) {
            Some(Ok(l)) => l,
            Some(Err(e)) => {
                problem = Some(e);
                AiLimits::default()
            }
            None => AiLimits::default(),
        };
        let pricing = text
            .as_deref()
            .map(|t| Pricing::from_config_text(t).0)
            .unwrap_or_default();
        AiPolicy {
            assistant,
            rewrite,
            pricing,
            limits,
            problem,
        }
    }

    /// The model `feature` uses.
    pub fn choice_for(&self, feature: AiFeature) -> Option<&ModelChoice> {
        match feature {
            AiFeature::Rewrite => self.rewrite.as_ref(),
            _ => self.assistant.as_ref(),
        }
    }

    /// The estimate for work of `feature` on `choice` making between `min_calls` and
    /// `max_calls` model calls.
    pub fn estimate_with(
        &self,
        feature: AiFeature,
        choice: &ModelChoice,
        min_calls: u64,
        max_calls: u64,
    ) -> AiEstimate {
        let (billing, price) = self.pricing.billing(choice.kind, &choice.model);
        let ((li, lo), (hi, ho)) = typical_tokens(feature);
        let (cost_low_usd, cost_high_usd) = match price {
            Some(p) => (
                Some(p.cost(li * min_calls, lo * min_calls)),
                Some(p.cost(hi * max_calls, ho * max_calls)),
            ),
            None if billing == AiBilling::Free => (Some(0.0), Some(0.0)),
            None => (None, None),
        };
        AiEstimate {
            feature,
            provider_kind: choice.kind,
            provider: choice.provider.clone(),
            model: choice.model.clone(),
            max_calls,
            billing,
            cost_low_usd,
            cost_high_usd,
        }
    }

    /// The estimate for `feature` on its configured model; `None` when no model is set up.
    pub fn estimate(
        &self,
        feature: AiFeature,
        min_calls: u64,
        max_calls: u64,
    ) -> Option<AiEstimate> {
        self.choice_for(feature)
            .map(|c| self.estimate_with(feature, c, min_calls.min(max_calls), max_calls))
    }

    /// Whether to ask before work with this estimate: never for a local model (it costs
    /// nothing), else always unless it stays under `skip_confirm_under` (a model with no known
    /// price always asks).
    pub fn needs_confirm(&self, e: &AiEstimate) -> bool {
        if e.billing == AiBilling::Free {
            return false;
        }
        match self.limits.skip_confirm_under {
            None => true,
            Some(_) if e.billing == AiBilling::Unpriced => true,
            Some(limit) => e.high_usd() >= limit,
        }
    }

    /// Why new AI work is refused today, given today's estimated total; `None` when it may
    /// start.
    pub fn daily_refusal(&self, today_usd: f64) -> Option<String> {
        let b = self.limits.daily_budget?;
        (today_usd >= b).then(|| crate::meter::daily_budget_message(b, today_usd))
    }

    /// One line per feature saying which model it uses (for the settings and `kraken ai`).
    pub fn models_line(&self) -> String {
        let a = self
            .assistant
            .as_ref()
            .map_or("none set up".to_string(), ModelChoice::label);
        let r = match &self.rewrite {
            Some(c) if c.source == ModelSource::Rewrite => c.label(),
            Some(c) => format!("{} (the assistant's)", c.label()),
            None => "none set up".to_string(),
        };
        format!("Assistant, Suggest names and Automate: {a}. Rust rewrite: {r}.")
    }
}

#[cfg(test)]
mod thinking_tests {
    use super::*;

    #[test]
    fn thinking_is_saved_per_provider_and_removed() {
        let dir = std::env::temp_dir().join(format!("kraken-think-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("config.toml");
        std::fs::write(&path, "per_run_cap = 5\n").expect("write");
        save_thinking(&path, "anthropic", Some(kraken_agent::Effort::High)).expect("saved");
        save_thinking(&path, "agent:claude", Some(kraken_agent::Effort::Low)).expect("saved");
        let t = kraken_agent::ThinkingConfig::load(Some(&path));
        assert_eq!(t.0.get("anthropic"), Some(&kraken_agent::Effort::High));
        save_thinking(&path, "anthropic", None).expect("removed");
        let t = kraken_agent::ThinkingConfig::load(Some(&path));
        assert!(!t.0.contains_key("anthropic"));
        assert_eq!(t.0.len(), 1);
        assert!(
            std::fs::read_to_string(&path)
                .expect("read")
                .contains("per_run_cap = 5")
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, text: &str) -> std::path::PathBuf {
        let p = dir.join("config.toml");
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn policy_reads_models_limits_and_prices() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "[provider]\nkind = \"openai_compatible\"\nbase_url = \"http://localhost:11434/v1\"\nmodel = \"qwen3\"\n\n\
             [rewrite]\nkind = \"anthropic\"\nmodel = \"claude-sonnet-5-5\"\n\n\
             [ai_limits]\nmax_calls_per_run = 50\ndaily_budget = 2.5\nskip_confirm_under = 0.05\n\n\
             [pricing]\n\"claude-sonnet\" = { input = 3.0, output = 15.0 }\n",
        );
        let pol = AiPolicy::load(Some(&p));
        assert!(pol.problem.is_none(), "{:?}", pol.problem);
        assert_eq!(pol.assistant.as_ref().unwrap().kind, AiProviderKind::Local);
        let rw = pol.rewrite.as_ref().unwrap();
        assert_eq!(rw.kind, AiProviderKind::Api);
        assert_eq!(rw.source, ModelSource::Rewrite);
        assert_eq!(pol.limits.max_calls_per_run, Some(50));
        let local = pol.estimate(AiFeature::Assistant, 1, 20).unwrap();
        assert_eq!(local.billing, AiBilling::Free);
        assert!(!pol.needs_confirm(&local), "free work under the threshold");
        let e = pol.estimate(AiFeature::Rewrite, 10, 30).unwrap();
        assert_eq!(e.billing, AiBilling::Metered);
        assert!(e.cost_high_usd.unwrap() > e.cost_low_usd.unwrap());
        assert!(pol.needs_confirm(&e));
        assert!(pol.daily_refusal(1.0).is_none());
        assert!(pol.daily_refusal(3.0).unwrap().contains("$2.50"));
        assert!(pol.models_line().contains("claude-sonnet-5-5"));

        let assistant = rewrite_choice(Some(&p), RewriteModel::Assistant, None).unwrap();
        assert_eq!(assistant.source, ModelSource::Assistant);
        let over =
            rewrite_choice(Some(&p), RewriteModel::Configured, Some("claude-haiku-4-5")).unwrap();
        assert_eq!(over.model, "claude-haiku-4-5");
    }

    #[test]
    fn rewrite_table_and_limits_are_written_back() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "[provider]\nkind = \"anthropic\"\napi_key = { env = \"K\" }\n",
        );
        let cfg = ProviderConfig::TerminalAgent {
            agent: "claude".into(),
            model: None,
            args: vec![],
        };
        save_rewrite_config(&p, Some(&cfg)).unwrap();
        let pol = AiPolicy::load(Some(&p));
        assert_eq!(
            pol.rewrite.as_ref().unwrap().kind,
            AiProviderKind::TerminalAgent
        );
        assert_eq!(pol.assistant.as_ref().unwrap().provider, "anthropic");
        save_rewrite_config(&p, None).unwrap();
        assert_eq!(
            AiPolicy::load(Some(&p)).rewrite.unwrap().source,
            ModelSource::Assistant
        );
        let limits = AiLimits {
            daily_budget: Some(4.0),
            ..AiLimits::default()
        };
        limits.save(&p).unwrap();
        assert_eq!(AiLimits::load(Some(&p)).daily_budget, Some(4.0));
        assert!(is_local_url("http://127.0.0.1:8080/v1"));
        assert!(!is_local_url("https://api.openai.com/v1"));
    }
}
