//! Agent profiles: how to start each terminal agent and which environment it may see.
//!
//! KRAKEN never forwards its own secrets to an agent. The environment an agent gets is built from
//! scratch: a short allowlist of harmless variables (`PATH`, `HOME`, locale, proxy settings,
//! the agent's own config-dir variable) plus whatever the person lists for that agent in
//! `agents.toml`. Variables starting with `KRAKEN_` are never forwarded. Signing in to the agent
//! (`claude login`, `codex login`, `gemini`) is the agent's own business and works through its own
//! files under `HOME`.

use std::ffi::{OsStr, OsString};

use serde::Serialize;

/// Variables every agent may see. No API keys.
pub const BASE_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "LANG",
    "LANGUAGE",
    "LC_*",
    "TMPDIR",
    "TEMP",
    "TMP",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
    "APPDATA",
    "LOCALAPPDATA",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
];

/// An agent that is installed from npm and run with Node.js.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AdapterSpec {
    /// npm package name.
    pub package: &'static str,
    /// Exact pinned version.
    pub version: &'static str,
    /// The script to run, relative to the adapter's `node_modules` directory.
    pub entry: &'static str,
    /// `package.json` that depends on exactly `package@version`.
    #[serde(skip)]
    pub package_json: &'static str,
    /// The `package-lock.json` generated for it: every transitive package with its integrity hash.
    #[serde(skip)]
    pub lockfile: &'static str,
    /// Oldest Node.js major version the package supports.
    pub min_node_major: u64,
    /// Whether the package needs npm install scripts. None of the built-in ones do, so installs
    /// always pass `--ignore-scripts`.
    pub needs_install_scripts: bool,
    /// A program on `PATH` that speaks ACP by itself, preferred over the npm copy when present
    /// (Gemini CLI: `gemini --acp`).
    pub native_binary: Option<&'static str>,
}

/// How an agent is made available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentSetup {
    /// `command` is run as is; it must be an absolute path or on `PATH` (custom agents).
    Command,
    /// Installed with npm into KRAKEN's data dir and run with Node.js.
    NodeAdapter(&'static AdapterSpec),
}

/// How to start one agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProfile {
    /// Short stable id (`claude`, `codex`, `gemini`, or the id of a custom agent).
    pub id: String,
    /// Name shown to people.
    pub display_name: String,
    /// One line of plain-language description.
    pub summary: String,
    /// The program to run. For npm adapters the program is the Node.js that was found, and this
    /// is only informational (`node`).
    pub command: String,
    /// Arguments after the program (after the adapter's script for npm adapters).
    pub args: Vec<String>,
    /// Extra environment variable names the agent may inherit, on top of
    /// [`BASE_ENV_ALLOWLIST`]. A trailing `*` matches a prefix.
    pub env_allowlist: Vec<String>,
    /// Fixed variables set for the agent.
    pub env: Vec<(String, String)>,
    /// How the agent is installed.
    pub setup: AgentSetup,
}

static CLAUDE: AdapterSpec = AdapterSpec {
    package: "@agentclientprotocol/claude-agent-acp",
    version: "0.89.1",
    entry: "@agentclientprotocol/claude-agent-acp/dist/index.js",
    package_json: include_str!("../adapters/claude/package.json"),
    lockfile: include_str!("../adapters/claude/package-lock.json"),
    min_node_major: 22,
    needs_install_scripts: false,
    native_binary: None,
};

static CODEX: AdapterSpec = AdapterSpec {
    package: "@agentclientprotocol/codex-acp",
    version: "2.2.2",
    entry: "@agentclientprotocol/codex-acp/dist/index.js",
    package_json: include_str!("../adapters/codex/package.json"),
    lockfile: include_str!("../adapters/codex/package-lock.json"),
    min_node_major: 20,
    needs_install_scripts: false,
    native_binary: None,
};

static GEMINI: AdapterSpec = AdapterSpec {
    package: "@google/gemini-cli",
    version: "0.62.0",
    entry: "@google/gemini-cli/bundle/gemini.js",
    package_json: include_str!("../adapters/gemini/package.json"),
    lockfile: include_str!("../adapters/gemini/package-lock.json"),
    min_node_major: 20,
    needs_install_scripts: false,
    native_binary: Some("gemini"),
};

/// The built-in profiles: Claude Code, Codex and Gemini CLI.
pub fn builtin_profiles() -> Vec<AgentProfile> {
    vec![
        AgentProfile {
            id: "claude".into(),
            display_name: "Claude Code".into(),
            summary: "Anthropic's coding agent, through the claude-agent-acp adapter".into(),
            command: "node".into(),
            args: vec![],
            env_allowlist: vec!["CLAUDE_CONFIG_DIR".into()],
            env: vec![],
            setup: AgentSetup::NodeAdapter(&CLAUDE),
        },
        AgentProfile {
            id: "codex".into(),
            display_name: "Codex".into(),
            summary: "OpenAI's coding agent, through the codex-acp adapter".into(),
            command: "node".into(),
            args: vec![],
            env_allowlist: vec!["CODEX_HOME".into()],
            env: vec![],
            setup: AgentSetup::NodeAdapter(&CODEX),
        },
        AgentProfile {
            id: "gemini".into(),
            display_name: "Gemini CLI".into(),
            summary: "Google's coding agent; it speaks ACP itself (`gemini --acp`)".into(),
            command: "gemini".into(),
            args: vec!["--acp".into()],
            env_allowlist: vec!["GEMINI_CLI_HOME".into()],
            env: vec![],
            setup: AgentSetup::NodeAdapter(&GEMINI),
        },
    ]
}

/// The built-in profile called `id`.
pub fn builtin_profile(id: &str) -> Option<AgentProfile> {
    builtin_profiles().into_iter().find(|p| p.id == id)
}

fn allowed(name: &str, pattern: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == pattern,
    }
}

/// True when KRAKEN refuses to pass `name` to an agent whatever the allowlists say.
pub fn is_kraken_private(name: &str) -> bool {
    name.to_ascii_uppercase().starts_with("KRAKEN_")
}

impl AgentProfile {
    /// A profile for an agent started by `command` (custom agents, tests).
    pub fn custom(
        id: impl Into<String>,
        display_name: impl Into<String>,
        command: impl Into<String>,
        args: Vec<String>,
    ) -> Self {
        let display_name = display_name.into();
        AgentProfile {
            id: id.into(),
            summary: format!("{display_name} (custom agent)"),
            display_name,
            command: command.into(),
            args,
            env_allowlist: vec![],
            env: vec![],
            setup: AgentSetup::Command,
        }
    }

    /// Builder: allows one more inherited variable.
    #[must_use]
    pub fn allow_env(mut self, name: impl Into<String>) -> Self {
        self.env_allowlist.push(name.into());
        self
    }

    /// Builder: sets a fixed variable.
    #[must_use]
    pub fn with_env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((name.into(), value.into()));
        self
    }

    /// The environment the agent process gets, built from `parent`: only allowlisted variables
    /// (never `KRAKEN_*`), then the fixed variables of the profile.
    pub fn child_env(
        &self,
        parent: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> Vec<(OsString, OsString)> {
        let mut out: Vec<(OsString, OsString)> = parent
            .into_iter()
            .filter(|(k, _)| {
                let name = k.to_string_lossy();
                !is_kraken_private(&name)
                    && (BASE_ENV_ALLOWLIST.iter().any(|p| allowed(&name, p))
                        || self.env_allowlist.iter().any(|p| allowed(&name, p)))
            })
            .collect();
        for (k, v) in &self.env {
            out.retain(|(name, _)| name != OsStr::new(k));
            out.push((OsString::from(k), OsString::from(v)));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect()
    }

    fn names(v: &[(OsString, OsString)]) -> Vec<String> {
        let mut n: Vec<_> = v
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        n.sort();
        n
    }

    #[test]
    fn secrets_and_kraken_variables_are_not_forwarded() {
        let p = builtin_profile("claude").expect("claude");
        let out = p.child_env(env(&[
            ("PATH", "/bin"),
            ("HOME", "/home/x"),
            ("LC_CTYPE", "C"),
            ("ANTHROPIC_API_KEY", "sk-secret"),
            ("OPENAI_API_KEY", "sk-other"),
            ("KRAKEN_PROVIDER_KEY", "k"),
            ("kraken_lowercase", "k"),
            ("CLAUDE_CONFIG_DIR", "/c"),
            ("AWS_SECRET_ACCESS_KEY", "s"),
        ]));
        assert_eq!(
            names(&out),
            ["CLAUDE_CONFIG_DIR", "HOME", "LC_CTYPE", "PATH"]
        );
    }

    #[test]
    fn explicit_opt_in_forwards_a_vendor_key_but_never_kraken_ones() {
        let p = builtin_profile("codex")
            .expect("codex")
            .allow_env("OPENAI_API_KEY")
            .allow_env("KRAKEN_*");
        let out = p.child_env(env(&[
            ("OPENAI_API_KEY", "sk"),
            ("KRAKEN_RUNTIME_DIR", "/r"),
            ("HOME", "/h"),
        ]));
        assert_eq!(names(&out), ["HOME", "OPENAI_API_KEY"]);
    }

    #[test]
    fn fixed_variables_override_inherited_ones() {
        let p = AgentProfile::custom("x", "X", "x", vec![]).with_env("HOME", "/fixed");
        let out = p.child_env(env(&[("HOME", "/real")]));
        assert_eq!(out, env(&[("HOME", "/fixed")]));
    }

    #[test]
    fn builtin_adapters_pin_versions_and_lockfiles() {
        for p in builtin_profiles() {
            let AgentSetup::NodeAdapter(a) = p.setup else {
                panic!("{} should be an npm adapter", p.id);
            };
            assert!(
                !a.version.contains(['^', '~', '*']),
                "{} is pinned exactly",
                p.id
            );
            assert!(a.package_json.contains(a.version));
            assert!(a.package_json.contains(a.package));
            assert!(a.lockfile.contains("\"lockfileVersion\""));
            assert!(a.lockfile.contains("\"integrity\": \"sha512-"));
            assert!(!a.needs_install_scripts);
            // Every download comes from the npm registry with an integrity hash.
            for line in a.lockfile.lines().filter(|l| l.contains("\"resolved\"")) {
                assert!(line.contains("https://registry.npmjs.org/"), "{line}");
            }
        }
    }
}
