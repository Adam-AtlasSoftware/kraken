//! Choosing, saving and testing the assistant's chat model.
//!
//! The model is configured in the `[provider]` table of `config.toml` (the shape of
//! [`kraken_agent::ProviderConfig`]), so the CLI and the GUI use the same setting. The file never
//! holds a raw API key: it names an environment variable, or points at an entry of a separate
//! `secrets.toml` next to it that only the owner can read (mode 0600).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use kraken_agent::{
    AgentError, ChatProvider, ChatRequest, Keyring, LayeredSecrets, Message, ProviderConfig,
    SecretRef, StreamAssembler,
};
use kraken_assist::AssistError;
use kraken_host::KrakenConfig;
use kraken_proto::sanitize;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

/// The `service` name of a [`SecretRef::Keyring`] that points into the secrets file.
pub const SECRETS_SERVICE: &str = "kraken-secrets-file";

/// File name of the secrets file, next to `config.toml`.
pub const SECRETS_FILE: &str = "secrets.toml";

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The kinds of assistant the settings window offers: model APIs, and terminal agents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    /// A terminal agent (Claude Code, Codex, Gemini CLI): chosen by agent id, not listed in
    /// [`ProviderKind::ALL`].
    TerminalAgent,
    /// Ollama running on this computer.
    Ollama,
    /// LM Studio's local server.
    LmStudio,
    /// `llama-server` from llama.cpp.
    LlamaServer,
    /// A vLLM server.
    Vllm,
    /// Any other server that speaks the OpenAI chat API.
    OpenAiCompatible,
    /// OpenAI's cloud service.
    OpenAi,
    /// Anthropic's cloud service.
    Anthropic,
    /// Google's Gemini cloud service.
    Gemini,
}

impl ProviderKind {
    /// Every model API kind, in the order the settings list shows them. Terminal agents are
    /// listed after these, one entry per agent.
    pub const ALL: [ProviderKind; 8] = [
        ProviderKind::Ollama,
        ProviderKind::LmStudio,
        ProviderKind::LlamaServer,
        ProviderKind::Vllm,
        ProviderKind::OpenAiCompatible,
        ProviderKind::Anthropic,
        ProviderKind::OpenAi,
        ProviderKind::Gemini,
    ];

    /// Name shown to people.
    pub fn label(self) -> &'static str {
        match self {
            ProviderKind::Ollama => "Ollama",
            ProviderKind::LmStudio => "LM Studio",
            ProviderKind::LlamaServer => "llama-server (llama.cpp)",
            ProviderKind::Vllm => "vLLM",
            ProviderKind::OpenAiCompatible => "Other OpenAI-compatible server",
            ProviderKind::Anthropic => "Anthropic (Claude)",
            ProviderKind::OpenAi => "OpenAI",
            ProviderKind::Gemini => "Google Gemini",
            ProviderKind::TerminalAgent => "Terminal agent",
        }
    }

    /// One plain sentence about what choosing this means.
    pub fn help(self) -> &'static str {
        match self {
            ProviderKind::Ollama => {
                "Runs on your computer. Install Ollama, then run `ollama pull <model>`. Nothing leaves your machine."
            }
            ProviderKind::LmStudio => {
                "Runs on your computer. Load a model in LM Studio and start its local server (Developer tab)."
            }
            ProviderKind::LlamaServer => {
                "Runs on your computer. Start llama-server with --jinja so the model can use tools."
            }
            ProviderKind::Vllm => "A server you run yourself, often on a GPU machine.",
            ProviderKind::OpenAiCompatible => {
                "Any server that offers the OpenAI chat API at an address you give."
            }
            ProviderKind::Anthropic => {
                "Cloud service. The decompiled code the assistant reads is sent to Anthropic."
            }
            ProviderKind::OpenAi => {
                "Cloud service. The decompiled code the assistant reads is sent to OpenAI."
            }
            ProviderKind::Gemini => {
                "Cloud service. The decompiled code the assistant reads is sent to Google."
            }
            ProviderKind::TerminalAgent => {
                "A coding agent that runs on your computer and signs in by itself. It uses KRAKEN's tools, so what it changes shows up here and can be undone, but its own tools (shell, files) are outside KRAKEN's safety net. The code it reads is sent to the service behind the agent."
            }
        }
    }

    /// Server address for the kinds that have a standard one.
    pub fn default_base_url(self) -> Option<&'static str> {
        match self {
            ProviderKind::Ollama => Some("http://localhost:11434/v1"),
            ProviderKind::LmStudio => Some("http://localhost:1234/v1"),
            ProviderKind::LlamaServer => Some("http://localhost:8080/v1"),
            ProviderKind::Vllm => Some("http://localhost:8000/v1"),
            ProviderKind::OpenAi => Some("https://api.openai.com/v1"),
            ProviderKind::OpenAiCompatible
            | ProviderKind::Anthropic
            | ProviderKind::Gemini
            | ProviderKind::TerminalAgent => None,
        }
    }

    /// A model name to start from (empty when only the person knows it).
    pub fn default_model(self) -> &'static str {
        match self {
            ProviderKind::Ollama => "qwen3:14b",
            ProviderKind::LlamaServer => "local",
            ProviderKind::OpenAi => "gpt-4.1",
            ProviderKind::Anthropic => kraken_agent::provider::anthropic::DEFAULT_MODEL,
            ProviderKind::Gemini => kraken_agent::provider::gemini::DEFAULT_MODEL,
            ProviderKind::LmStudio
            | ProviderKind::Vllm
            | ProviderKind::OpenAiCompatible
            | ProviderKind::TerminalAgent => "",
        }
    }

    /// Environment variable that conventionally holds the key.
    pub fn default_key_env(self) -> Option<&'static str> {
        match self {
            ProviderKind::OpenAi => Some("OPENAI_API_KEY"),
            ProviderKind::Anthropic => Some("ANTHROPIC_API_KEY"),
            ProviderKind::Gemini => Some("GEMINI_API_KEY"),
            _ => None,
        }
    }

    /// True when the server address is the person's to type.
    pub fn needs_url(self) -> bool {
        matches!(
            self,
            ProviderKind::Ollama
                | ProviderKind::LmStudio
                | ProviderKind::LlamaServer
                | ProviderKind::Vllm
                | ProviderKind::OpenAiCompatible
        )
    }

    /// True when the service cannot be used without a key.
    pub fn needs_key(self) -> bool {
        matches!(
            self,
            ProviderKind::OpenAi | ProviderKind::Anthropic | ProviderKind::Gemini
        )
    }

    /// True for kinds that normally run on this computer.
    pub fn is_local_preset(self) -> bool {
        matches!(
            self,
            ProviderKind::Ollama | ProviderKind::LmStudio | ProviderKind::LlamaServer
        )
    }

    fn account(self) -> &'static str {
        match self {
            ProviderKind::Ollama => "ollama",
            ProviderKind::LmStudio => "lm-studio",
            ProviderKind::LlamaServer => "llama-server",
            ProviderKind::Vllm => "vllm",
            ProviderKind::OpenAiCompatible => "openai-compatible",
            ProviderKind::OpenAi => "openai",
            ProviderKind::Anthropic => "anthropic",
            ProviderKind::Gemini => "gemini",
            ProviderKind::TerminalAgent => "terminal-agent",
        }
    }

    /// The assistant is a terminal agent.
    pub fn is_agent(self) -> bool {
        self == ProviderKind::TerminalAgent
    }
}

/// What the chat panel shows about the model in use (decision 19: always visible).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderBadge {
    /// Service name such as `Ollama` or `Anthropic (Claude)`.
    pub service: String,
    /// Model name.
    pub model: String,
    /// True when requests stay on this computer.
    pub local: bool,
    /// A terminal agent rather than a model API.
    pub terminal_agent: bool,
}

impl ProviderBadge {
    /// `Ollama / qwen3:14b`.
    pub fn title(&self) -> String {
        if self.model.is_empty() {
            self.service.clone()
        } else {
            format!("{} / {}", self.service, self.model)
        }
    }

    /// Where requests go, in plain words.
    pub fn privacy(&self) -> &'static str {
        if self.terminal_agent {
            "A coding agent running on this computer. The code the assistant reads is sent to the service behind the agent, and its own tools (shell, files) are outside KRAKEN's safety net."
        } else if self.local {
            "Runs on this computer. Your code is not sent anywhere."
        } else {
            "Cloud service. The code the assistant reads is sent to this provider."
        }
    }
}

fn host_of(url: &str) -> &str {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(v6) = authority.strip_prefix('[') {
        return v6.split(']').next().unwrap_or(v6);
    }
    authority.split(':').next().unwrap_or(authority)
}

/// True when `url` points at this computer.
pub fn is_local_url(url: &str) -> bool {
    matches!(host_of(url), "localhost" | "127.0.0.1" | "::1" | "0.0.0.0")
}

/// The badge for a configured provider.
pub fn badge_of(cfg: &ProviderConfig) -> ProviderBadge {
    match cfg {
        ProviderConfig::OpenaiCompatible {
            base_url, model, ..
        } => ProviderBadge {
            service: ProviderDraft::guess_kind(base_url).label().to_string(),
            model: model.clone(),
            local: is_local_url(base_url),
            terminal_agent: false,
        },
        ProviderConfig::Anthropic { model, .. } => ProviderBadge {
            service: ProviderKind::Anthropic.label().to_string(),
            model: model
                .clone()
                .unwrap_or_else(|| ProviderKind::Anthropic.default_model().to_string()),
            local: false,
            terminal_agent: false,
        },
        ProviderConfig::Gemini { model, .. } => ProviderBadge {
            service: ProviderKind::Gemini.label().to_string(),
            model: model
                .clone()
                .unwrap_or_else(|| ProviderKind::Gemini.default_model().to_string()),
            local: false,
            terminal_agent: false,
        },
        ProviderConfig::Replay { .. } => ProviderBadge {
            service: "Recorded answers".to_string(),
            model: "replay".to_string(),
            local: true,
            terminal_agent: false,
        },
        ProviderConfig::TerminalAgent { agent, model, .. } => ProviderBadge {
            service: agent_name(agent),
            model: model.clone().unwrap_or_default(),
            local: false,
            terminal_agent: true,
        },
    }
}

/// The name people know a built-in agent by; other ids are shown as they are.
pub fn agent_name(id: &str) -> String {
    kraken_acp::builtin_profile(id).map_or_else(|| id.to_string(), |p| p.display_name)
}

/// The settings window's form for the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDraft {
    /// Which service.
    pub kind: ProviderKind,
    /// Server address (OpenAI-compatible kinds).
    pub base_url: String,
    /// Model name.
    pub model: String,
    /// Name of the environment variable that holds the key.
    pub key_env: String,
    /// The agent's id (terminal agents).
    pub agent: String,
    /// Extra command-line arguments for the agent, one line, split on spaces (terminal agents).
    pub agent_args: String,
    /// A key the person pasted. Cleared once saved; never written to `config.toml`.
    pub key_paste: String,
    /// The key reference already in the file, kept when nothing new is typed.
    existing_key: Option<SecretRef>,
}

impl ProviderDraft {
    /// The starting values of `kind`.
    pub fn preset(kind: ProviderKind) -> Self {
        ProviderDraft {
            kind,
            base_url: kind.default_base_url().unwrap_or_default().to_string(),
            model: kind.default_model().to_string(),
            key_env: kind.default_key_env().unwrap_or_default().to_string(),
            agent: if kind.is_agent() {
                "claude".to_string()
            } else {
                String::new()
            },
            agent_args: String::new(),
            key_paste: String::new(),
            existing_key: None,
        }
    }

    /// The starting values for the terminal agent `id`.
    pub fn for_agent(id: &str) -> Self {
        ProviderDraft {
            agent: id.to_string(),
            ..ProviderDraft::preset(ProviderKind::TerminalAgent)
        }
    }

    /// Switches to another kind and fills its defaults.
    pub fn switch_kind(&mut self, kind: ProviderKind) {
        if kind != self.kind {
            *self = ProviderDraft::preset(kind);
        }
    }

    fn guess_kind(url: &str) -> ProviderKind {
        let host = host_of(url);
        let port = url
            .split("://")
            .nth(1)
            .and_then(|r| r.split(['/', '?', '#']).next())
            .and_then(|a| a.rsplit(':').next())
            .and_then(|p| p.parse::<u16>().ok());
        if host == "api.openai.com" {
            ProviderKind::OpenAi
        } else if is_local_url(url) {
            match port {
                Some(11434) => ProviderKind::Ollama,
                Some(1234) => ProviderKind::LmStudio,
                Some(8080) => ProviderKind::LlamaServer,
                Some(8000) => ProviderKind::Vllm,
                _ => ProviderKind::OpenAiCompatible,
            }
        } else {
            ProviderKind::OpenAiCompatible
        }
    }

    /// The form for an existing configuration.
    pub fn from_config(cfg: &ProviderConfig) -> Self {
        let env_of = |r: &SecretRef| match r {
            SecretRef::Env(v) => v.clone(),
            SecretRef::Keyring { .. } => String::new(),
        };
        match cfg {
            ProviderConfig::OpenaiCompatible {
                base_url,
                model,
                api_key,
                ..
            } => ProviderDraft {
                kind: Self::guess_kind(base_url),
                base_url: base_url.clone(),
                model: model.clone(),
                key_env: api_key.as_ref().map(env_of).unwrap_or_default(),
                agent: String::new(),
                agent_args: String::new(),
                key_paste: String::new(),
                existing_key: api_key.clone(),
            },
            ProviderConfig::Anthropic { model, api_key, .. } => ProviderDraft {
                kind: ProviderKind::Anthropic,
                base_url: String::new(),
                model: model.clone().unwrap_or_default(),
                key_env: env_of(api_key),
                agent: String::new(),
                agent_args: String::new(),
                key_paste: String::new(),
                existing_key: Some(api_key.clone()),
            },
            ProviderConfig::Gemini { model, api_key, .. } => ProviderDraft {
                kind: ProviderKind::Gemini,
                base_url: String::new(),
                model: model.clone().unwrap_or_default(),
                key_env: env_of(api_key),
                agent: String::new(),
                agent_args: String::new(),
                key_paste: String::new(),
                existing_key: Some(api_key.clone()),
            },
            ProviderConfig::Replay { .. } => ProviderDraft::preset(ProviderKind::Ollama),
            ProviderConfig::TerminalAgent { agent, model, args } => ProviderDraft {
                model: model.clone().unwrap_or_default(),
                agent_args: args.join(" "),
                ..ProviderDraft::for_agent(agent)
            },
        }
    }

    /// True when the key is stored in the secrets file rather than named by a variable.
    pub fn uses_secrets_file(&self) -> bool {
        matches!(
            &self.existing_key,
            Some(SecretRef::Keyring { service, .. }) if service == SECRETS_SERVICE
        ) && self.key_env.trim().is_empty()
            && self.key_paste.is_empty()
    }
}

/// What saving a form produced.
#[derive(Debug, Clone, PartialEq)]
pub struct SaveOutcome {
    /// The configuration now in `config.toml`.
    pub config: ProviderConfig,
    /// Things the person should know (where a pasted key went, ...).
    pub notes: Vec<String>,
}

/// An environment variable name: letters, digits and underscores, not starting with a digit,
/// and not shaped like a well-known key prefix.
fn is_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && s.len() <= 40
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !s.starts_with("AIza")
        && !s.starts_with("sk_")
}

fn strip_nulls(v: &mut Value) {
    match v {
        Value::Object(m) => {
            m.retain(|_, x| !x.is_null());
            m.values_mut().for_each(strip_nulls);
        }
        Value::Array(a) => a.iter_mut().for_each(strip_nulls),
        _ => {}
    }
}

/// A file of secrets (`secrets.toml`) that only its owner can read.
#[derive(Debug, Clone)]
pub struct SecretsFile {
    path: PathBuf,
}

impl SecretsFile {
    /// The secrets file beside `config_path`.
    pub fn beside(config_path: &Path) -> Self {
        SecretsFile {
            path: config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(SECRETS_FILE),
        }
    }

    /// The file's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_table(&self) -> Result<toml::Table, String> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => text
                .parse::<toml::Table>()
                .map_err(|e| format!("{} is not valid TOML: {e}", self.path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(toml::Table::new()),
            Err(e) => Err(format!("cannot read {}: {e}", self.path.display())),
        }
    }

    /// The secret stored under `account`.
    pub fn get_secret(&self, account: &str) -> Result<Option<String>, String> {
        let table = self.read_table()?;
        tighten(&self.path);
        Ok(table
            .get("secrets")
            .and_then(toml::Value::as_table)
            .and_then(|t| t.get(account))
            .and_then(toml::Value::as_str)
            .map(str::to_string))
    }

    /// Stores `value` under `account`, creating the file with mode 0600 and replacing it in
    /// one step.
    pub fn set_secret(&self, account: &str, value: &str) -> Result<(), String> {
        let mut table = self.read_table()?;
        let secrets = table
            .entry("secrets".to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if let Some(t) = secrets.as_table_mut() {
            t.insert(account.to_string(), toml::Value::String(value.to_string()));
        }
        let text = format!(
            "# KRAKEN secrets. Keep this file private (mode 0600); do not share or commit it.\n{}",
            toml::to_string_pretty(&table).map_err(|e| e.to_string())?
        );
        write_private(&self.path, text.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", self.path.display()))
    }
}

impl Keyring for SecretsFile {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, AgentError> {
        if service != SECRETS_SERVICE {
            return Ok(None);
        }
        self.get_secret(account).map_err(AgentError::Config)
    }
}

#[cfg(unix)]
fn tighten(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path)
        && meta.permissions().mode() & 0o077 != 0
    {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

#[cfg(not(unix))]
fn tighten(_path: &Path) {}

/// Writes `bytes` to `path` through a temporary file created with mode 0600.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("toml.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// Where the provider is read from and written to.
#[derive(Debug, Clone, Default)]
pub struct ProviderStore {
    /// The `config.toml` to edit; `None` means nothing can be saved (tests, odd environments).
    pub config_path: Option<PathBuf>,
}

impl ProviderStore {
    /// A store over `config_path`.
    pub fn new(config_path: Option<PathBuf>) -> Self {
        ProviderStore { config_path }
    }

    /// The secrets file beside the config file.
    pub fn secrets(&self) -> Option<SecretsFile> {
        self.config_path.as_deref().map(SecretsFile::beside)
    }

    /// The saved provider; `Ok(None)` when none is configured.
    pub fn load(&self) -> Result<Option<ProviderConfig>, String> {
        match kraken_assist::load_provider_config(self.config_path.as_deref()) {
            Ok(c) => Ok(Some(c)),
            Err(AssistError::NoProvider(_)) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Turns the form into a configuration, storing a pasted key in the secrets file.
    pub fn configure(&self, d: &ProviderDraft) -> Result<SaveOutcome, String> {
        self.configure_with(d, true)
    }

    /// Builds a provider from the form without saving anything (for "Test connection"); a
    /// pasted key is used from memory only.
    pub fn build_unsaved(&self, d: &ProviderDraft) -> Result<Arc<dyn ChatProvider>, String> {
        let out = self.configure_with(d, false)?;
        let pasted = d.key_paste.trim();
        let overlay = Overlay {
            pasted: (!pasted.is_empty())
                .then(|| (d.kind.account().to_string(), pasted.to_string())),
            file: self.secrets(),
        };
        kraken_assist::build_provider(
            &out.config,
            &LayeredSecrets {
                keyring: Some(Arc::new(overlay)),
            },
        )
        .map_err(|e| plain_agent_error(&e))
    }

    fn configure_with(&self, d: &ProviderDraft, persist: bool) -> Result<SaveOutcome, String> {
        let model = d.model.trim().to_string();
        let mut notes = Vec::new();
        if d.kind.is_agent() {
            let agent = d.agent.trim();
            if agent.is_empty() {
                return Err("Choose which terminal agent to use.".to_string());
            }
            return Ok(SaveOutcome {
                config: ProviderConfig::TerminalAgent {
                    agent: agent.to_string(),
                    model: (!model.is_empty()).then_some(model),
                    args: d
                        .agent_args
                        .split_whitespace()
                        .map(str::to_string)
                        .collect(),
                },
                notes,
            });
        }
        let url = d.base_url.trim().trim_end_matches('/').to_string();
        if d.kind.needs_url() {
            if url.is_empty() {
                return Err(
                    "Enter the server address, for example http://localhost:11434/v1.".to_string(),
                );
            }
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err("The server address must start with http:// or https://.".to_string());
            }
            if model.is_empty() {
                return Err(
                    "Enter the model name the server should use. Your server lists it (for Ollama: `ollama list`)."
                        .to_string(),
                );
            }
        }

        let mut pasted = d.key_paste.trim().to_string();
        let mut env = d.key_env.trim().to_string();
        if !env.is_empty() && !is_env_name(&env) {
            // A key typed into the variable-name box: treat it as a pasted key, never as a name.
            if pasted.is_empty() {
                pasted = std::mem::take(&mut env);
                notes.push(
                    "That looked like an API key rather than a variable name, so KRAKEN stored it as a key."
                        .to_string(),
                );
            } else {
                return Err(
                    "The variable name may only use letters, digits and underscores. Paste keys in the API key box."
                        .to_string(),
                );
            }
        }

        let key: Option<SecretRef> = if !pasted.is_empty() {
            let secrets = self.secrets().ok_or_else(|| {
                "There is no settings folder to keep the key in. Use an environment variable instead."
                    .to_string()
            })?;
            let account = d.kind.account();
            if persist {
                secrets.set_secret(account, &pasted)?;
                notes.push(format!(
                    "The key is stored in {} (readable only by you); config.toml only points at it.",
                    secrets.path().display()
                ));
            }
            Some(SecretRef::Keyring {
                service: SECRETS_SERVICE.to_string(),
                account: account.to_string(),
            })
        } else if !env.is_empty() {
            Some(SecretRef::Env(env))
        } else {
            d.existing_key.clone()
        };

        let cfg = match d.kind {
            ProviderKind::Anthropic => {
                if key.is_none() {
                    return Err(
                        "Anthropic needs an API key: name the environment variable that holds it, or paste the key."
                            .to_string(),
                    );
                }
                ProviderConfig::Anthropic {
                    model: (!model.is_empty()).then_some(model),
                    api_key: key.unwrap_or_else(|| SecretRef::Env("ANTHROPIC_API_KEY".into())),
                    base_url: None,
                    max_tokens: None,
                    context_window: None,
                }
            }
            ProviderKind::Gemini => {
                if key.is_none() {
                    return Err(
                        "Gemini needs an API key: name the environment variable that holds it, or paste the key."
                            .to_string(),
                    );
                }
                ProviderConfig::Gemini {
                    model: (!model.is_empty()).then_some(model),
                    api_key: key.unwrap_or_else(|| SecretRef::Env("GEMINI_API_KEY".into())),
                    base_url: None,
                    context_window: None,
                }
            }
            kind => {
                if kind == ProviderKind::OpenAi && key.is_none() {
                    return Err(
                        "OpenAI needs an API key: name the environment variable that holds it, or paste the key."
                            .to_string(),
                    );
                }
                ProviderConfig::OpenaiCompatible {
                    base_url: url,
                    model,
                    api_key: key,
                    supports_tools: true,
                    context_window: None,
                }
            }
        };
        Ok(SaveOutcome { config: cfg, notes })
    }

    /// Validates the form and writes the `[provider]` table, keeping every other key of
    /// `config.toml`.
    pub fn save(&self, d: &ProviderDraft) -> Result<SaveOutcome, String> {
        let path = self.config_path.as_deref().ok_or_else(|| {
            "There is no settings folder to save to (HOME is not set).".to_string()
        })?;
        let out = self.configure(d)?;
        self.write_config(path, &out.config)?;
        Ok(out)
    }

    /// Writes `cfg` as the `[provider]` table.
    pub fn write_config(&self, path: &Path, cfg: &ProviderConfig) -> Result<(), String> {
        let mut file = KrakenConfig::from_file(path).map_err(|e| e.to_string())?;
        let mut value = serde_json::to_value(cfg).map_err(|e| e.to_string())?;
        strip_nulls(&mut value);
        file.provider = Some(value);
        file.save(path).map_err(|e| e.to_string())
    }

    /// Removes the `[provider]` table (the secrets file is left alone).
    pub fn clear(&self) -> Result<(), String> {
        let Some(path) = self.config_path.as_deref() else {
            return Ok(());
        };
        let mut file = KrakenConfig::from_file(path).map_err(|e| e.to_string())?;
        file.provider = None;
        file.save(path).map_err(|e| e.to_string())
    }

    /// The badge for `cfg`; a custom agent is named as `agents.toml` (beside `config.toml`)
    /// calls it.
    pub fn badge(&self, cfg: &ProviderConfig) -> ProviderBadge {
        let mut badge = badge_of(cfg);
        if let ProviderConfig::TerminalAgent { agent, .. } = cfg
            && let Some(dir) = self.config_path.as_deref().and_then(Path::parent)
            && let Ok(profiles) = kraken_acp::load_catalogue(Some(dir))
            && let Some(p) = profiles.iter().find(|p| p.id == *agent)
        {
            badge.service = p.display_name.clone();
        }
        badge
    }

    /// What `cfg` selects: the model API built from it, or the terminal agent it names. Keys
    /// are resolved from the environment and the secrets file.
    pub fn choice(&self, cfg: &ProviderConfig) -> Result<super::BackendChoice, String> {
        match kraken_assist::AgentChoice::from_config(cfg) {
            Some(agent) => Ok(super::BackendChoice::Agent(agent)),
            None => self.build(cfg).map(super::BackendChoice::Api),
        }
    }

    /// The configuration the form describes, without saving anything (a pasted key is not
    /// stored).
    pub fn config_of(&self, d: &ProviderDraft) -> Result<ProviderConfig, String> {
        self.configure_with(d, false).map(|o| o.config)
    }

    /// Which models to offer for `cfg`: the provider's own list when reachable, else the
    /// built-in one (see `kraken_agent::model_choices`).
    pub async fn model_choices(&self, cfg: &ProviderConfig) -> kraken_agent::ModelList {
        let keyring: Option<Arc<dyn Keyring>> =
            self.secrets().map(|s| Arc::new(s) as Arc<dyn Keyring>);
        kraken_agent::model_choices(cfg, &LayeredSecrets { keyring }).await
    }

    /// Builds the provider for `cfg`, resolving keys from the environment and the secrets
    /// file.
    pub fn build(&self, cfg: &ProviderConfig) -> Result<Arc<dyn ChatProvider>, String> {
        let keyring: Option<Arc<dyn Keyring>> =
            self.secrets().map(|s| Arc::new(s) as Arc<dyn Keyring>);
        kraken_assist::build_provider(cfg, &LayeredSecrets { keyring })
            .map_err(|e| plain_agent_error(&e))
    }
}

/// A pasted key that is not saved yet, falling back to the secrets file.
struct Overlay {
    pasted: Option<(String, String)>,
    file: Option<SecretsFile>,
}

impl Keyring for Overlay {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, AgentError> {
        if let Some((a, v)) = &self.pasted
            && service == SECRETS_SERVICE
            && a == account
        {
            return Ok(Some(v.clone()));
        }
        match &self.file {
            Some(f) => Keyring::get(f, service, account),
            None => Ok(None),
        }
    }
}

/// A model-provider failure in words a newcomer can act on.
pub fn plain_agent_error(e: &AgentError) -> String {
    let short = |s: &str| sanitize(s).chars().take(200).collect::<String>();
    match e {
        AgentError::MissingKey(m) => format!(
            "No API key was found ({m}). Set the variable before starting KRAKEN, or paste the key in Settings."
        ),
        AgentError::Transport(m) => format!(
            "Could not reach the model server ({}). Is it running, and is the address right?",
            short(m)
        ),
        AgentError::Http { status, body } => match status {
            401 | 403 => format!(
                "The provider refused the API key (HTTP {status}). Check that the key is correct and still valid."
            ),
            404 => format!(
                "The server does not know this address or model (HTTP 404). Check the model name and the address. {}",
                short(body)
            ),
            429 => "The provider says you are sending too much or are out of quota (HTTP 429). Wait a bit and try again."
                .to_string(),
            500..=599 => format!(
                "The provider had a problem on its side (HTTP {status}). Try again in a moment. {}",
                short(body)
            ),
            _ => format!("The provider answered HTTP {status}: {}", short(body)),
        },
        AgentError::Config(m) => format!("The provider settings are not valid: {}", short(m)),
        AgentError::Unsupported(m) => short(m),
        AgentError::Cancelled => "Stopped.".to_string(),
        other => format!("The model could not answer: {}", short(&other.to_string())),
    }
}

/// What a connection test found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReport {
    /// Model that answered.
    pub model: String,
    /// What it said (a few words).
    pub reply: String,
    /// Round trip in milliseconds.
    pub millis: u64,
}

/// Asks `provider` for a tiny completion. Errors come back as plain text.
pub async fn test_connection(provider: Arc<dyn ChatProvider>) -> Result<TestReport, String> {
    let started = Instant::now();
    let req = ChatRequest {
        system: "You are a connection test. Answer with one short word.".to_string(),
        messages: vec![Message::user("Reply with the single word: ready")],
        tools: Vec::new(),
        max_tokens: Some(16),
        temperature: Some(0.0),
    };
    let cancel = CancellationToken::new();
    let run = async {
        let mut stream = provider
            .complete(req, cancel.clone())
            .await
            .map_err(|e| plain_agent_error(&e))?;
        let mut asm = StreamAssembler::default();
        while let Some(ev) = stream.next().await {
            asm.push(&ev.map_err(|e| plain_agent_error(&e))?);
        }
        Ok::<_, String>(asm.finish())
    };
    let done = match tokio::time::timeout(TEST_TIMEOUT, run).await {
        Ok(r) => r?,
        Err(_) => {
            cancel.cancel();
            return Err(
                "The model did not answer within 30 seconds. A local model may still be loading; try again."
                    .to_string(),
            );
        }
    };
    let reply: String = sanitize(done.text.trim()).chars().take(60).collect();
    Ok(TestReport {
        model: provider.info().model,
        reply,
        millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}
