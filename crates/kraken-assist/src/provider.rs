//! Finding and loading the chat provider from `config.toml`.
//!
//! The file is the same one `kraken-host` reads (`$KRAKEN_CONFIG`, else
//! `$XDG_CONFIG_HOME/kraken/config.toml`, else `~/.config/kraken/config.toml`); the assistant
//! only looks at its `[provider]` table.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kraken_agent::{ProviderConfig, SecretResolver};
use kraken_host::KrakenConfig;

use crate::acp::{AcpBackend, AgentChoice, find_kraken_exe, plan_agent};
use crate::backend::{ApiBackend, AssistBackend};
use crate::error::AssistError;

/// Example `[provider]` tables: a heading and the TOML for each supported kind.
pub const SAMPLES: [(&str, &str); 6] = [
    (
        "Ollama (local; run `ollama serve` and `ollama pull <model>` first)",
        "[provider]\nkind = \"openai_compatible\"\nbase_url = \"http://localhost:11434/v1\"\nmodel = \"qwen3:14b\"\n",
    ),
    (
        "LM Studio (local; start its server from the Developer tab)",
        "[provider]\nkind = \"openai_compatible\"\nbase_url = \"http://localhost:1234/v1\"\nmodel = \"your-loaded-model\"\n",
    ),
    (
        "llama-server from llama.cpp (local; start it with --jinja so tool calls work)",
        "[provider]\nkind = \"openai_compatible\"\nbase_url = \"http://localhost:8080/v1\"\nmodel = \"local\"\n",
    ),
    (
        "Anthropic (cloud; the key stays in an environment variable, never in this file)",
        "[provider]\nkind = \"anthropic\"\napi_key = { env = \"ANTHROPIC_API_KEY\" }\n",
    ),
    (
        "OpenAI (cloud)",
        "[provider]\nkind = \"openai_compatible\"\nbase_url = \"https://api.openai.com/v1\"\nmodel = \"gpt-4.1\"\napi_key = { env = \"OPENAI_API_KEY\" }\n",
    ),
    (
        "Claude Code (a terminal agent; or agent = \"codex\" or \"gemini\". Set it up with `kraken agents setup claude`; it signs in by itself)",
        "[provider]\nkind = \"terminal_agent\"\nagent = \"claude\"\n",
    ),
];

/// [`SAMPLES`] as one commented sample file: the first provider is active, the rest are
/// commented out (keep exactly one `[provider]` table).
pub fn sample_config() -> String {
    let mut out = String::new();
    for (i, (heading, body)) in SAMPLES.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!("# {heading}\n"));
        for line in body.lines() {
            if i == 0 {
                out.push_str(line);
            } else {
                out.push_str("# ");
                out.push_str(line);
            }
            out.push('\n');
        }
    }
    out
}

/// Where the provider table is looked for, given an environment lookup.
pub fn provider_config_path(env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    KrakenConfig::default_path_with(env)
}

/// The "nothing configured" explanation, with a sample file. `path` is where the file was
/// looked for.
pub fn no_provider_message(path: Option<&Path>) -> String {
    let where_ = match path {
        Some(p) => p.display().to_string(),
        None => "~/.config/kraken/config.toml".to_string(),
    };
    format!(
        "no AI provider is configured.\n\n\
         The assistant needs a chat model. Add a [provider] table to {where_} \
         (KRAKEN_CONFIG overrides the location). Pick one (keep a single [provider] table):\n\n{}\n\
         Local models (Ollama, LM Studio, llama-server) keep everything on your machine; \
         cloud providers and terminal agents (Claude Code, Codex, Gemini CLI) send the decompiled \
         code the assistant reads to their service. \
         Models that cannot call tools can still explain text but cannot browse the program.",
        sample_config()
    )
}

/// Builds the chat provider for `cfg`, passing the `[thinking]` effort set for its kind.
pub fn build_provider(
    cfg: &ProviderConfig,
    secrets: &dyn SecretResolver,
) -> Result<Arc<dyn kraken_agent::ChatProvider>, kraken_agent::AgentError> {
    let path = provider_config_path(&|k| std::env::var_os(k));
    let effort = kraken_agent::ThinkingConfig::load(path.as_deref()).for_config(cfg);
    cfg.build_with_thinking(secrets, effort)
}

/// Reads the `[provider]` table from the file at `path`.
///
/// A missing file or a file without a `[provider]` table is [`AssistError::NoProvider`]; a table
/// that does not parse is [`AssistError::Config`].
pub fn load_provider_config(path: Option<&Path>) -> Result<ProviderConfig, AssistError> {
    let none = || AssistError::NoProvider(no_provider_message(path));
    let Some(p) = path else {
        return Err(none());
    };
    let text = match std::fs::read_to_string(p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(none()),
        Err(e) => {
            return Err(AssistError::Config(format!(
                "cannot read {}: {e}",
                p.display()
            )));
        }
    };
    let table: toml::Table = text
        .parse()
        .map_err(|e| AssistError::Config(format!("{}: {e}", p.display())))?;
    if !table.contains_key("provider") {
        return Err(none());
    }
    ProviderConfig::from_toml(&text)
        .map_err(|e| AssistError::Config(format!("{}: {e}", p.display())))
}

/// Reads the optional `[rewrite]` table from the file at `path`: a provider override for the
/// rewrite pipeline, with the same keys as `[provider]`. `None` when the file or the table is
/// missing (the rewrite pipeline then uses `[provider]`); [`AssistError::Config`] when the table
/// does not parse.
pub fn load_rewrite_config(path: Option<&Path>) -> Result<Option<ProviderConfig>, AssistError> {
    let Some(p) = path else {
        return Ok(None);
    };
    let text = match std::fs::read_to_string(p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(AssistError::Config(format!(
                "cannot read {}: {e}",
                p.display()
            )));
        }
    };
    let table: toml::Table = text
        .parse()
        .map_err(|e| AssistError::Config(format!("{}: {e}", p.display())))?;
    let Some(rewrite) = table.get("rewrite") else {
        return Ok(None);
    };
    rewrite
        .clone()
        .try_into::<ProviderConfig>()
        .map(Some)
        .map_err(|e| AssistError::Config(format!("{}: [rewrite]: {e}", p.display())))
}

/// The backend a text-only task (the rewrite pipeline) runs on: `[rewrite]` when the file has
/// one, else `[provider]`. Re-read on every call, so a changed file applies without a restart.
pub fn text_backend_from_config(
    env: &dyn Fn(&str) -> Option<OsString>,
    secrets: &dyn SecretResolver,
) -> Result<Arc<dyn AssistBackend>, AssistError> {
    let path = provider_config_path(env);
    let cfg = match load_rewrite_config(path.as_deref())? {
        Some(c) => c,
        None => load_provider_config(path.as_deref())?,
    };
    text_backend(&cfg, env, secrets)
}

/// The backend for `cfg`: a chat model API ([`ApiBackend`]), or the terminal agent a
/// `kind = "terminal_agent"` table names ([`AcpBackend`], used text-only: no KRAKEN tools, every
/// permission request denied; see [`AssistBackend::complete_text`]).
pub fn text_backend(
    cfg: &ProviderConfig,
    env: &dyn Fn(&str) -> Option<OsString>,
    secrets: &dyn SecretResolver,
) -> Result<Arc<dyn AssistBackend>, AssistError> {
    let Some(choice) = AgentChoice::from_config(cfg) else {
        return Ok(Arc::new(ApiBackend::new(build_provider(cfg, secrets)?)));
    };
    let profiles = kraken_acp::load_catalogue(kraken_acp::config_dir_with(env).as_deref())
        .map_err(|e| AssistError::Config(e.to_string()))?;
    let paths = kraken_acp::AgentPaths::from_env_with(env).ok_or_else(|| {
        AssistError::Config(
            "cannot place agent files: neither XDG_DATA_HOME nor HOME is set".to_string(),
        )
    })?;
    let resolver = kraken_acp::Resolver {
        paths,
        platform: kraken_acp::Platform::current(),
        path_env: env("PATH"),
    };
    // A text-only request never starts KRAKEN's MCP server; the entry only fills the slot.
    let exe = find_kraken_exe(env("PATH").as_deref()).unwrap_or_else(|| PathBuf::from("kraken"));
    let scratch = std::env::temp_dir();
    let mcp = kraken_acp::McpServerConfig::project(exe, &scratch);
    let settings = plan_agent(&resolver, &profiles, &choice, &scratch, mcp)
        .map_err(|e| AssistError::Config(e.to_string()))?;
    Ok(Arc::new(AcpBackend::new(
        settings,
        Arc::new(kraken_registry::Registry::standard()),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_sample_parses_and_the_active_one_loads() {
        for (_, body) in SAMPLES {
            ProviderConfig::from_toml(body).expect(body);
        }
        ProviderConfig::from_toml(&sample_config()).expect("the sample file");
        let msg = no_provider_message(None);
        for name in [
            "Ollama",
            "LM Studio",
            "llama-server",
            "Anthropic",
            "OpenAI",
            "Claude Code",
        ] {
            assert!(msg.contains(name), "{name}");
        }
    }

    #[test]
    fn missing_file_and_missing_table_are_no_provider() {
        let dir = std::env::temp_dir();
        let missing = dir.join("kraken-assist-no-such-config.toml");
        assert!(matches!(
            load_provider_config(Some(&missing)),
            Err(AssistError::NoProvider(_))
        ));
        assert!(matches!(
            load_provider_config(None),
            Err(AssistError::NoProvider(m)) if m.contains("ollama") || m.contains("Ollama")
        ));
    }
}
