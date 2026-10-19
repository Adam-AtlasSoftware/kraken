//! Which models a provider offers: asked of its `/models` endpoint when reachable, else a
//! built-in list of well-known ids. A custom model name is always allowed, so neither list is
//! authoritative.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{ProviderConfig, SecretResolver};
use crate::provider::{anthropic, gemini, http_client, validate_base_url};

/// Known Claude model ids.
pub const CLAUDE_MODELS: &[&str] = &[
    "claude-sonnet-5-5",
    "claude-opus-4-1",
    "claude-sonnet-4-5",
    "claude-haiku-4-5",
];
/// Known Gemini model ids.
pub const GEMINI_MODELS: &[&str] = &[
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
];
/// Known OpenAI model ids.
pub const GPT_MODELS: &[&str] = &[
    "gpt-5",
    "gpt-5-mini",
    "gpt-5-nano",
    "gpt-4.1",
    "gpt-4.1-mini",
    "o4-mini",
];

/// How long the live listing may take before the built-in list is used.
const LIST_TIMEOUT: Duration = Duration::from_secs(4);

/// Where a list came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSource {
    /// The provider's own `/models` answer.
    Live,
    /// The built-in list of known ids.
    BuiltIn,
}

/// The ids to offer in a picker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelList {
    pub ids: Vec<String>,
    pub source: ModelSource,
    /// Why the built-in list is shown, when it is.
    pub note: Option<String>,
}

/// The built-in ids for `cfg`'s provider.
pub fn builtin_models(cfg: &ProviderConfig) -> Vec<String> {
    let list: &[&str] = match cfg {
        ProviderConfig::Anthropic { .. } => CLAUDE_MODELS,
        ProviderConfig::Gemini { .. } => GEMINI_MODELS,
        ProviderConfig::OpenaiCompatible { base_url, .. } if base_url.contains("openai.com") => {
            GPT_MODELS
        }
        ProviderConfig::TerminalAgent { agent, .. } => match agent.as_str() {
            "claude" => CLAUDE_MODELS,
            "gemini" => GEMINI_MODELS,
            "codex" => GPT_MODELS,
            _ => &[],
        },
        _ => &[],
    };
    list.iter().map(|s| s.to_string()).collect()
}

/// Ids out of a `/models` answer: `{"data":[{"id":..}]}` (Anthropic, OpenAI) or
/// `{"models":[{"name":"models/.."}]}` (Gemini; only models that can generate content).
pub fn parse_models(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(data) = v.get("data").and_then(Value::as_array) {
        out.extend(
            data.iter()
                .filter_map(|m| m["id"].as_str())
                .map(String::from),
        );
    }
    if let Some(models) = v.get("models").and_then(Value::as_array) {
        out.extend(
            models
                .iter()
                .filter(|m| {
                    m["supportedGenerationMethods"]
                        .as_array()
                        .is_none_or(|a| a.iter().any(|x| x == "generateContent"))
                })
                .filter_map(|m| m["name"].as_str())
                .map(|n| n.strip_prefix("models/").unwrap_or(n).to_string()),
        );
    }
    out.retain(|id| !id.is_empty() && id.len() <= 128);
    out.sort();
    out.dedup();
    out
}

async fn fetch(cfg: &ProviderConfig, secrets: &dyn SecretResolver) -> Result<Vec<String>, String> {
    let key = |r: &crate::config::SecretRef| -> Result<String, String> {
        secrets
            .resolve(r)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "no API key".to_string())
    };
    let client = http_client().map_err(|e| e.to_string())?;
    let rb = match cfg {
        ProviderConfig::Anthropic {
            api_key, base_url, ..
        } => {
            let base = base_url
                .clone()
                .unwrap_or(anthropic::DEFAULT_BASE_URL.into());
            validate_base_url(&base).map_err(|e| e.to_string())?;
            client
                .get(format!(
                    "{}/v1/models?limit=100",
                    base.trim_end_matches('/')
                ))
                .header("x-api-key", key(api_key)?)
                .header("anthropic-version", anthropic::ANTHROPIC_VERSION)
        }
        ProviderConfig::Gemini {
            api_key, base_url, ..
        } => {
            let base = base_url.clone().unwrap_or(gemini::DEFAULT_BASE_URL.into());
            validate_base_url(&base).map_err(|e| e.to_string())?;
            client
                .get(format!(
                    "{}/v1beta/models?pageSize=100",
                    base.trim_end_matches('/')
                ))
                .header("x-goog-api-key", key(api_key)?)
        }
        ProviderConfig::OpenaiCompatible {
            base_url, api_key, ..
        } => {
            validate_base_url(base_url).map_err(|e| e.to_string())?;
            let mut rb = client.get(format!("{}/models", base_url.trim_end_matches('/')));
            if let Some(r) = api_key
                && let Ok(k) = key(r)
            {
                rb = rb.bearer_auth(k);
            }
            rb
        }
        _ => return Err("this provider has no model listing".into()),
    };
    let resp = rb
        .timeout(LIST_TIMEOUT)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("the provider answered {}", resp.status()));
    }
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let ids = parse_models(&v);
    if ids.is_empty() {
        Err("the provider listed no models".into())
    } else {
        Ok(ids)
    }
}

/// The models to offer for `cfg`: the provider's own list when reachable, else the built-in one.
pub async fn model_choices(cfg: &ProviderConfig, secrets: &dyn SecretResolver) -> ModelList {
    match fetch(cfg, secrets).await {
        Ok(ids) => ModelList {
            ids,
            source: ModelSource::Live,
            note: None,
        },
        Err(why) => ModelList {
            ids: builtin_models(cfg),
            source: ModelSource::BuiltIn,
            note: Some(format!("Showing well-known models ({why}).")),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EnvSecrets, SecretRef};
    use serde_json::json;

    #[test]
    fn openai_style_and_gemini_style_answers_parse() {
        let o = parse_models(&json!({"data": [{"id": "b"}, {"id": "a"}, {"id": "a"}]}));
        assert_eq!(o, ["a", "b"]);
        let g = parse_models(&json!({"models": [
            {"name": "models/gemini-2.5-pro", "supportedGenerationMethods": ["generateContent"]},
            {"name": "models/embedding-001", "supportedGenerationMethods": ["embedContent"]},
        ]}));
        assert_eq!(g, ["gemini-2.5-pro"]);
        assert!(parse_models(&json!({"error": "x"})).is_empty());
    }

    #[test]
    fn builtin_lists_follow_the_provider() {
        let a = ProviderConfig::Anthropic {
            model: None,
            api_key: SecretRef::Env("K".into()),
            base_url: None,
            max_tokens: None,
            context_window: None,
        };
        assert!(builtin_models(&a).contains(&anthropic::DEFAULT_MODEL.to_string()));
        let gpt = ProviderConfig::OpenaiCompatible {
            base_url: "https://api.openai.com/v1".into(),
            model: "x".into(),
            api_key: None,
            supports_tools: true,
            context_window: None,
        };
        assert!(builtin_models(&gpt).iter().any(|m| m.starts_with("gpt-")));
        let local = ProviderConfig::OpenaiCompatible {
            base_url: "http://127.0.0.1:1/v1".into(),
            model: "x".into(),
            api_key: None,
            supports_tools: true,
            context_window: None,
        };
        assert!(builtin_models(&local).is_empty());
    }

    #[tokio::test]
    async fn an_unreachable_provider_falls_back_to_the_builtin_list() {
        let cfg = ProviderConfig::Anthropic {
            model: None,
            api_key: SecretRef::Env("KRAKEN_TEST_NO_SUCH_KEY".into()),
            base_url: Some("http://127.0.0.1:1".into()),
            max_tokens: None,
            context_window: None,
        };
        let l = model_choices(&cfg, &EnvSecrets).await;
        assert_eq!(l.source, ModelSource::BuiltIn);
        assert_eq!(l.ids, builtin_models(&cfg));
        assert!(l.note.is_some());
    }
}
