//! Provider configuration (TOML) and secret resolution.
//!
//! Config never contains key material, only a reference to where the key lives:
//!
//! ```toml
//! [provider]
//! kind = "anthropic"
//! model = "claude-sonnet-5-5"
//! api_key = { env = "ANTHROPIC_API_KEY" }
//! ```

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::AgentError;
use crate::provider::ChatProvider;
use crate::provider::anthropic::Anthropic;
use crate::provider::gemini::Gemini;
use crate::provider::openai::OpenAiCompatible;
use crate::provider::replay::ReplayProvider;

/// Where an API key is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRef {
    /// Name of an environment variable.
    Env(String),
    /// OS keyring entry (resolved through a [`Keyring`] implementation).
    Keyring { service: String, account: String },
}

/// OS keyring abstraction. No implementation ships yet; the GUI/daemon can provide one.
pub trait Keyring: Send + Sync {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, AgentError>;
}

/// Resolves a [`SecretRef`] to the secret value.
pub trait SecretResolver: Send + Sync {
    fn resolve(&self, r: &SecretRef) -> Result<Option<String>, AgentError>;
}

/// Resolves environment references only; keyring references are an error.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvSecrets;

impl SecretResolver for EnvSecrets {
    fn resolve(&self, r: &SecretRef) -> Result<Option<String>, AgentError> {
        match r {
            SecretRef::Env(var) => Ok(std::env::var(var).ok().filter(|v| !v.is_empty())),
            SecretRef::Keyring { .. } => Err(AgentError::Unsupported(
                "keyring secrets need a Keyring implementation".into(),
            )),
        }
    }
}

/// Environment first-class, with an optional keyring for `Keyring` references.
pub struct LayeredSecrets {
    pub keyring: Option<Arc<dyn Keyring>>,
}

impl SecretResolver for LayeredSecrets {
    fn resolve(&self, r: &SecretRef) -> Result<Option<String>, AgentError> {
        match (r, &self.keyring) {
            (SecretRef::Keyring { service, account }, Some(k)) => k.get(service, account),
            _ => EnvSecrets.resolve(r),
        }
    }
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderConfig {
    /// OpenAI, Ollama, LM Studio, llama-server, vLLM.
    OpenaiCompatible {
        base_url: String,
        model: String,
        #[serde(default)]
        api_key: Option<SecretRef>,
        #[serde(default = "yes")]
        supports_tools: bool,
        #[serde(default)]
        context_window: Option<u32>,
    },
    Anthropic {
        /// Defaults to [`crate::provider::anthropic::DEFAULT_MODEL`].
        #[serde(default)]
        model: Option<String>,
        #[serde(default = "default_anthropic_key")]
        api_key: SecretRef,
        #[serde(default)]
        base_url: Option<String>,
        #[serde(default)]
        max_tokens: Option<u32>,
        #[serde(default)]
        context_window: Option<u32>,
    },
    Gemini {
        #[serde(default)]
        model: Option<String>,
        #[serde(default = "default_gemini_key")]
        api_key: SecretRef,
        #[serde(default)]
        base_url: Option<String>,
        #[serde(default)]
        context_window: Option<u32>,
    },
    /// Deterministic replay of a recorded cassette file.
    Replay { cassette: PathBuf },
    /// A terminal agent (Claude Code, Codex, Gemini CLI) driven over ACP instead of a chat API.
    /// It is not a [`ChatProvider`]: `kraken-assist` runs it as its own backend, so
    /// [`ProviderConfig::build`] refuses it.
    TerminalAgent {
        /// Agent id: `claude`, `codex`, `gemini`, or an id from `agents.toml`.
        agent: String,
        /// The model to ask the agent for, when the adapter supports choosing one.
        #[serde(default)]
        model: Option<String>,
        /// Extra command-line arguments for the agent, appended after its own.
        #[serde(default)]
        args: Vec<String>,
    },
}

fn default_anthropic_key() -> SecretRef {
    SecretRef::Env("ANTHROPIC_API_KEY".into())
}

fn default_gemini_key() -> SecretRef {
    SecretRef::Env("GEMINI_API_KEY".into())
}

#[derive(Deserialize)]
struct File {
    provider: ProviderConfig,
}

impl ProviderConfig {
    /// Parses a TOML document with a `[provider]` table.
    pub fn from_toml(s: &str) -> Result<Self, AgentError> {
        toml::from_str::<File>(s)
            .map(|f| f.provider)
            .map_err(|e| AgentError::Config(e.to_string()))
    }

    /// Instantiates the provider, resolving secrets through `secrets`.
    pub fn build(&self, secrets: &dyn SecretResolver) -> Result<Arc<dyn ChatProvider>, AgentError> {
        fn required(r: &SecretRef, secrets: &dyn SecretResolver) -> Result<String, AgentError> {
            secrets.resolve(r)?.ok_or_else(|| {
                AgentError::MissingKey(match r {
                    SecretRef::Env(v) => format!("environment variable {v} is not set"),
                    SecretRef::Keyring { service, account } => {
                        format!("no keyring entry {service}/{account}")
                    }
                })
            })
        }
        Ok(match self {
            ProviderConfig::OpenaiCompatible {
                base_url,
                model,
                api_key,
                supports_tools,
                context_window,
            } => {
                let key = api_key
                    .as_ref()
                    .map(|r| secrets.resolve(r))
                    .transpose()?
                    .flatten();
                Arc::new(
                    OpenAiCompatible::new(base_url, model, key)?
                        .with_tools(*supports_tools)
                        .with_context_window(*context_window),
                )
            }
            ProviderConfig::Anthropic {
                model,
                api_key,
                base_url,
                max_tokens,
                context_window,
            } => {
                let mut p =
                    Anthropic::new(required(api_key, secrets)?, model.clone(), base_url.clone())?
                        .with_context_window(*context_window);
                if let Some(m) = max_tokens {
                    p = p.with_max_tokens(*m);
                }
                Arc::new(p)
            }
            ProviderConfig::Gemini {
                model,
                api_key,
                base_url,
                context_window,
            } => Arc::new(
                Gemini::new(required(api_key, secrets)?, model.clone(), base_url.clone())?
                    .with_context_window(*context_window),
            ),
            ProviderConfig::Replay { cassette } => Arc::new(ReplayProvider::from_path(cassette)?),
            ProviderConfig::TerminalAgent { agent, .. } => {
                return Err(AgentError::Unsupported(format!(
                    "`{agent}` is a terminal agent, not a chat model API; it runs through the assistant's agent backend"
                )));
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toml_variants() {
        let c = ProviderConfig::from_toml(
            r#"
[provider]
kind = "openai_compatible"
base_url = "http://localhost:11434/v1"
model = "qwen3"
"#,
        )
        .unwrap();
        assert_eq!(
            c,
            ProviderConfig::OpenaiCompatible {
                base_url: "http://localhost:11434/v1".into(),
                model: "qwen3".into(),
                api_key: None,
                supports_tools: true,
                context_window: None,
            }
        );
        let c = ProviderConfig::from_toml(
            r#"
[provider]
kind = "anthropic"
api_key = { env = "MY_KEY" }
"#,
        )
        .unwrap();
        assert!(matches!(
            c,
            ProviderConfig::Anthropic { model: None, api_key: SecretRef::Env(ref v), .. } if v == "MY_KEY"
        ));
        let c = ProviderConfig::from_toml(
            "[provider]\nkind = \"gemini\"\napi_key = { keyring = { service = \"kraken\", account = \"gem\" } }\n",
        )
        .unwrap();
        assert!(matches!(
            c,
            ProviderConfig::Gemini {
                api_key: SecretRef::Keyring { .. },
                ..
            }
        ));
        assert!(ProviderConfig::from_toml("[provider]\nkind = \"nope\"").is_err());
    }

    #[test]
    fn terminal_agent_parses_and_is_not_a_chat_provider() {
        let c = ProviderConfig::from_toml(
            "[provider]\nkind = \"terminal_agent\"\nagent = \"claude\"\nmodel = \"opus\"\nargs = [\"--x\"]\n",
        )
        .unwrap();
        assert_eq!(
            c,
            ProviderConfig::TerminalAgent {
                agent: "claude".into(),
                model: Some("opus".into()),
                args: vec!["--x".into()],
            }
        );
        let min =
            ProviderConfig::from_toml("[provider]\nkind = \"terminal_agent\"\nagent = \"codex\"\n")
                .unwrap();
        assert!(matches!(
            min,
            ProviderConfig::TerminalAgent { model: None, ref args, .. } if args.is_empty()
        ));
        assert!(matches!(
            c.build(&EnvSecrets),
            Err(AgentError::Unsupported(_))
        ));
        assert!(ProviderConfig::from_toml("[provider]\nkind = \"terminal_agent\"").is_err());
    }

    #[test]
    fn missing_env_key_is_reported_without_network() {
        let c = ProviderConfig::Anthropic {
            model: None,
            api_key: SecretRef::Env("KRAKEN_TEST_SURELY_UNSET_VAR".into()),
            base_url: None,
            max_tokens: None,
            context_window: None,
        };
        assert!(matches!(
            c.build(&EnvSecrets),
            Err(AgentError::MissingKey(_))
        ));
    }

    struct FakeKeyring;
    impl Keyring for FakeKeyring {
        fn get(&self, _: &str, _: &str) -> Result<Option<String>, AgentError> {
            Ok(Some("from-keyring".into()))
        }
    }

    #[test]
    fn keyring_layer() {
        let l = LayeredSecrets {
            keyring: Some(Arc::new(FakeKeyring)),
        };
        let r = SecretRef::Keyring {
            service: "s".into(),
            account: "a".into(),
        };
        assert_eq!(l.resolve(&r).unwrap().as_deref(), Some("from-keyring"));
        assert!(EnvSecrets.resolve(&r).is_err());
    }
}
