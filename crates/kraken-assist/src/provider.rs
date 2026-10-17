//! Finding and loading the chat provider from `config.toml`.
//!
//! The file is the same one `kraken-host` reads (`$KRAKEN_CONFIG`, else
//! `$XDG_CONFIG_HOME/kraken/config.toml`, else `~/.config/kraken/config.toml`); the assistant
//! only looks at its `[provider]` table.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use kraken_agent::ProviderConfig;
use kraken_host::KrakenConfig;

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
