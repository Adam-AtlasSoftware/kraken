//! The agent catalogue: built-in profiles plus the person's `agents.toml`, and whether each
//! agent can run on this machine ("detected", "available", "missing", "unsupported").

use crate::print_bridge::BridgeStyle;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::node::{NodeRuntime, find_in_path};
use crate::paths::AgentPaths;
use crate::platform::Platform;
use crate::profile::{AgentProfile, AgentSetup, builtin_profiles};

/// Failure to read `agents.toml`.
#[derive(Debug, thiserror::Error)]
pub enum AgentsFileError {
    /// The file cannot be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// File.
        path: PathBuf,
        /// OS error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid.
    #[error("invalid {path}: {message}")]
    Parse {
        /// File.
        path: PathBuf,
        /// Parser message.
        message: String,
    },
    /// An entry reuses the id of a built-in agent or another custom one.
    #[error("{path}: the agent id `{id}` is already taken")]
    DuplicateId {
        /// File.
        path: PathBuf,
        /// The id.
        id: String,
    },
    /// An `[env_allow]` entry names an agent that does not exist.
    #[error("{path}: [env_allow] names an unknown agent `{id}`")]
    UnknownAgent {
        /// File.
        path: PathBuf,
        /// The id.
        id: String,
    },
}

/// One `[[agent]]` entry of `agents.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomAgent {
    id: String,
    name: Option<String>,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    /// Extra environment variables the agent may inherit.
    #[serde(default)]
    env_allow: Vec<String>,
    /// `print` for a tool without ACP: it gets the message in place of `{prompt}` in `args`, or
    /// on its stdin, and what it prints is the answer. Leave it out for an ACP agent.
    #[serde(default)]
    mode: Option<String>,
}

/// `agents.toml`: custom ACP agents, and extra environment variables for any agent.
///
/// ```toml
/// [[agent]]
/// id = "goose"
/// name = "Goose"
/// command = "goose"
/// args = ["acp"]
///
/// [env_allow]
/// claude = ["ANTHROPIC_API_KEY"]   # opt in to passing a key through
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentsFile {
    #[serde(default, rename = "agent")]
    agents: Vec<CustomAgent>,
    #[serde(default)]
    env_allow: BTreeMap<String, Vec<String>>,
}

/// The file name inside the config directory.
pub const AGENTS_FILE: &str = "agents.toml";

/// An id for an agent called `name`: lower-case letters, digits and `-`.
pub fn agent_id(name: &str) -> String {
    name.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Adds an agent to `agents.toml`, keeping what is there, and returns its id. `print` marks a
/// tool without ACP. Nothing is written unless the file still reads afterwards.
pub fn add_agent(
    config_dir: &Path,
    name: &str,
    command: &str,
    args: &[String],
    print: bool,
) -> Result<String, String> {
    let (name, command) = (name.trim(), command.trim());
    let id = agent_id(name);
    if id.is_empty() {
        return Err("Give the agent a name.".to_string());
    }
    if command.is_empty() {
        return Err("Say which command starts the agent.".to_string());
    }
    let path = config_dir.join(AGENTS_FILE);
    let old = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("{} cannot be read: {e}", path.display())),
    };
    let mut entry = toml::Table::new();
    entry.insert("id".into(), id.clone().into());
    entry.insert("name".into(), name.into());
    entry.insert("command".into(), command.into());
    entry.insert("args".into(), args.to_vec().into());
    if print {
        entry.insert("mode".into(), "print".into());
    }
    let entry = toml::to_string(&entry).map_err(|e| e.to_string())?;
    let sep = if old.is_empty() || old.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let text = format!("{old}{sep}\n[[agent]]\n{entry}");
    parse_catalogue(&text, &path, builtin_profiles()).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(config_dir).map_err(|e| e.to_string())?;
    std::fs::write(&path, text)
        .map_err(|e| format!("{} cannot be written: {e}", path.display()))?;
    Ok(id)
}

/// Every known agent: the built-ins (with the person's `env_allow` additions applied) followed by
/// custom ones. A missing file means no additions.
pub fn load_catalogue(config_dir: Option<&Path>) -> Result<Vec<AgentProfile>, AgentsFileError> {
    let profiles = builtin_profiles();
    let Some(dir) = config_dir else {
        return Ok(profiles);
    };
    let path = dir.join(AGENTS_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(profiles),
        Err(source) => return Err(AgentsFileError::Io { path, source }),
    };
    parse_catalogue(&text, &path, profiles)
}

fn parse_catalogue(
    text: &str,
    path: &Path,
    mut profiles: Vec<AgentProfile>,
) -> Result<Vec<AgentProfile>, AgentsFileError> {
    let file: AgentsFile = toml::from_str(text).map_err(|e| AgentsFileError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    for c in file.agents {
        if profiles.iter().any(|p| p.id == c.id) {
            return Err(AgentsFileError::DuplicateId {
                path: path.to_path_buf(),
                id: c.id,
            });
        }
        let mut p = AgentProfile::custom(
            c.id.clone(),
            c.name.unwrap_or_else(|| c.id.clone()),
            c.command,
            c.args,
        );
        p.env_allowlist = c.env_allow;
        match c.mode.as_deref() {
            None | Some("acp") => {}
            Some("print") => p.setup = AgentSetup::Bridge(BridgeStyle::Text),
            Some(other) => {
                return Err(AgentsFileError::Parse {
                    path: path.to_path_buf(),
                    message: format!("agent `{}`: unknown mode `{other}`", p.id),
                });
            }
        }
        profiles.push(p);
    }
    for (id, names) in file.env_allow {
        let Some(p) = profiles.iter_mut().find(|p| p.id == id) else {
            return Err(AgentsFileError::UnknownAgent {
                path: path.to_path_buf(),
                id,
            });
        };
        p.env_allowlist.extend(names);
    }
    Ok(profiles)
}

/// How an agent will be started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    /// The program.
    pub program: PathBuf,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// A directory to put first on the agent's `PATH` (a downloaded Node.js).
    pub path_prepend: Option<PathBuf>,
    /// How it was found, for messages.
    pub via: String,
}

/// Whether an agent can run here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentStatus {
    /// Ready to start.
    Detected(LaunchSpec),
    /// Not installed yet, but `kraken agents setup <id>` can install it.
    Available {
        /// What is missing.
        reason: String,
        /// Whether setup would also download Node.js.
        needs_node_download: bool,
    },
    /// Cannot be started and setup cannot fix it by itself.
    Missing {
        /// Why, and what to do.
        reason: String,
    },
    /// This platform cannot run the agent.
    Unsupported {
        /// Why.
        reason: String,
    },
}

impl AgentStatus {
    /// `detected`, `available`, `missing` or `unsupported`.
    pub fn label(&self) -> &'static str {
        match self {
            AgentStatus::Detected(_) => "detected",
            AgentStatus::Available { .. } => "available",
            AgentStatus::Missing { .. } => "missing",
            AgentStatus::Unsupported { .. } => "unsupported",
        }
    }
}

/// Everything needed to decide.
#[derive(Debug, Clone)]
pub struct Resolver {
    /// KRAKEN's agent directories.
    pub paths: AgentPaths,
    /// The platform.
    pub platform: Platform,
    /// The `PATH` to search.
    pub path_env: Option<OsString>,
}

impl Resolver {
    /// The real machine and process environment.
    pub fn from_env(paths: AgentPaths) -> Self {
        Resolver {
            paths,
            platform: Platform::current(),
            path_env: std::env::var_os("PATH"),
        }
    }

    /// Finds a Node.js for `min_major`: on `PATH`, else KRAKEN's downloaded copy.
    pub fn node(&self, min_major: u64) -> Option<NodeRuntime> {
        NodeRuntime::resolve(
            &self.paths,
            &self.platform,
            self.path_env.as_deref(),
            min_major,
        )
    }

    /// Works out whether `profile` can run, and how.
    pub fn status(&self, profile: &AgentProfile) -> AgentStatus {
        match profile.setup {
            AgentSetup::Command => self.command_status(profile),
            AgentSetup::Bridge(style) => self.bridge_status(profile, style),
            AgentSetup::NodeAdapter(spec) => {
                if let Err(reason) = self.platform.supports_agents() {
                    return AgentStatus::Unsupported { reason };
                }
                if let Some(bin) = spec.native_binary
                    && let Some(found) = find_in_path(bin, self.path_env.as_deref())
                {
                    return AgentStatus::Detected(LaunchSpec {
                        program: found.clone(),
                        args: profile.args.iter().map(OsString::from).collect(),
                        path_prepend: None,
                        via: format!("{} found on PATH", found.display()),
                    });
                }
                let node = self.node(spec.min_node_major);
                let installed = spec.is_installed(&self.paths, &profile.id);
                match (node, installed) {
                    (Some(node), true) => {
                        let mut args =
                            vec![spec.entry_path(&self.paths, &profile.id).into_os_string()];
                        args.extend(profile.args.iter().map(OsString::from));
                        AgentStatus::Detected(LaunchSpec {
                            path_prepend: Some(node.bin_dir()),
                            via: format!(
                                "{}@{} with Node.js {}",
                                spec.package, spec.version, node.version
                            ),
                            program: node.node,
                            args,
                        })
                    }
                    (Some(node), false) => AgentStatus::Available {
                        reason: format!(
                            "{}@{} is not installed yet (Node.js {} is available)",
                            spec.package, spec.version, node.version
                        ),
                        needs_node_download: false,
                    },
                    (None, _) if self.platform.can_provision_node() => AgentStatus::Available {
                        reason: format!(
                            "needs Node.js {} or newer, which KRAKEN can download for you, and {}@{}",
                            spec.min_node_major, spec.package, spec.version
                        ),
                        needs_node_download: true,
                    },
                    (None, _) => AgentStatus::Missing {
                        reason: format!(
                            "needs Node.js {} or newer, which was not found on PATH and cannot be \
                             downloaded for {}; install it and run `kraken agents setup {}`",
                            spec.min_node_major,
                            self.platform.label(),
                            profile.id
                        ),
                    },
                }
            }
        }
    }

    /// A tool without ACP runs under `kraken agents bridge`.
    fn bridge_status(&self, profile: &AgentProfile, style: BridgeStyle) -> AgentStatus {
        let tool = match self.command_status(profile) {
            AgentStatus::Detected(l) => l,
            other => return other,
        };
        let name = if cfg!(windows) {
            "kraken.exe"
        } else {
            "kraken"
        };
        let kraken = std::env::var_os("KRAKEN_EXE")
            .map(PathBuf::from)
            .or_else(|| {
                let me = std::env::current_exe().ok()?;
                Some(me.parent()?.join(name)).filter(|p| p.is_file())
            })
            .or_else(|| find_in_path(name, self.path_env.as_deref().map(OsStr::new)));
        let Some(program) = kraken else {
            return AgentStatus::Missing {
                reason: "KRAKEN's own `kraken` command, which runs this agent, was not found"
                    .to_string(),
            };
        };
        let mut args: Vec<OsString> = ["agents", "bridge", "--style", style.as_str(), "--program"]
            .iter()
            .map(OsString::from)
            .collect();
        args.push(tool.program.clone().into_os_string());
        args.push("--".into());
        args.extend(tool.args);
        AgentStatus::Detected(LaunchSpec {
            via: format!("{} found", tool.program.display()),
            program,
            args,
            path_prepend: None,
        })
    }

    fn command_status(&self, profile: &AgentProfile) -> AgentStatus {
        let cmd = Path::new(&profile.command);
        let found = if cmd.is_absolute() || profile.command.contains(std::path::MAIN_SEPARATOR) {
            crate::node::is_executable_file(cmd).then(|| cmd.to_path_buf())
        } else {
            find_in_path(&profile.command, self.path_env.as_deref().map(OsStr::new))
        };
        match found {
            Some(program) => AgentStatus::Detected(LaunchSpec {
                via: format!("{} found", program.display()),
                program,
                args: profile.args.iter().map(OsString::from).collect(),
                path_prepend: None,
            }),
            None => AgentStatus::Missing {
                reason: format!(
                    "`{}` was not found on PATH; install it or fix `command` in agents.toml",
                    profile.command
                ),
            },
        }
    }
}

/// One row of `kraken agents list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentReport {
    /// Agent id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// What it is.
    pub summary: String,
    /// `detected`, `available`, `missing` or `unsupported`.
    pub status: String,
    /// Plain-language detail.
    pub detail: String,
    /// Whether the agent is a built-in.
    pub builtin: bool,
}

/// The availability report for `profiles`.
pub fn report(resolver: &Resolver, profiles: &[AgentProfile]) -> Vec<AgentReport> {
    profiles
        .iter()
        .map(|p| {
            let status = resolver.status(p);
            let detail = match &status {
                AgentStatus::Detected(l) => l.via.clone(),
                AgentStatus::Available { reason, .. }
                | AgentStatus::Missing { reason }
                | AgentStatus::Unsupported { reason } => reason.clone(),
            };
            AgentReport {
                id: p.id.clone(),
                name: p.display_name.clone(),
                summary: p.summary.clone(),
                status: status.label().to_string(),
                detail,
                builtin: crate::profile::builtin_profile(&p.id).is_some(),
            }
        })
        .collect()
}

#[cfg(test)]
mod add_tests {
    use super::*;

    #[test]
    fn an_added_agent_joins_the_catalogue_and_keeps_the_file() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(AGENTS_FILE), "[env_allow]\nclaude = [\"X\"]").unwrap();
        let args = vec!["-p".to_string(), "{prompt}".to_string()];
        let id = add_agent(d.path(), "My Tool 2", "mytool", &args, true).unwrap();
        assert_eq!(id, "my-tool-2");
        let all = load_catalogue(Some(d.path())).unwrap();
        let p = all.iter().find(|p| p.id == id).unwrap();
        assert_eq!(p.display_name, "My Tool 2");
        assert_eq!(p.args, args);
        assert_eq!(p.setup, AgentSetup::Bridge(BridgeStyle::Text));
        assert!(
            all.iter()
                .find(|p| p.id == "claude")
                .unwrap()
                .env_allowlist
                .contains(&"X".to_string())
        );
    }

    #[test]
    fn a_clash_or_an_empty_form_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        assert!(add_agent(d.path(), "Claude", "x", &[], false).is_err());
        assert!(add_agent(d.path(), "  ", "x", &[], false).is_err());
        assert!(add_agent(d.path(), "ok", " ", &[], false).is_err());
        assert!(!d.path().join(AGENTS_FILE).exists());
    }

    #[test]
    fn qwen_and_antigravity_are_built_in() {
        assert_eq!(
            crate::profile::builtin_profile("qwen").unwrap().args,
            ["--acp"]
        );
        assert_eq!(
            crate::profile::builtin_profile("antigravity")
                .unwrap()
                .command,
            "agy"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::builtin_profile;

    fn parse(text: &str) -> Result<Vec<AgentProfile>, AgentsFileError> {
        parse_catalogue(text, Path::new("agents.toml"), builtin_profiles())
    }

    #[test]
    fn custom_agents_and_env_opt_in() {
        let ps = parse(
            r#"
            [[agent]]
            id = "goose"
            name = "Goose"
            command = "goose"
            args = ["acp"]
            env_allow = ["GOOSE_*"]

            [env_allow]
            claude = ["ANTHROPIC_API_KEY"]
            "#,
        )
        .expect("parsed");
        assert_eq!(ps.len(), 6);
        let goose = ps.iter().find(|p| p.id == "goose").expect("goose");
        assert_eq!(goose.args, ["acp"]);
        assert_eq!(goose.env_allowlist, ["GOOSE_*"]);
        let claude = ps.iter().find(|p| p.id == "claude").expect("claude");
        assert!(
            claude
                .env_allowlist
                .contains(&"ANTHROPIC_API_KEY".to_string())
        );
    }

    #[test]
    fn bad_files_are_reported() {
        assert!(matches!(
            parse("[[agent]]\nid = \"claude\"\ncommand = \"x\""),
            Err(AgentsFileError::DuplicateId { .. })
        ));
        assert!(matches!(
            parse("[env_allow]\nnope = [\"X\"]"),
            Err(AgentsFileError::UnknownAgent { .. })
        ));
        assert!(matches!(
            parse("[[agent]]\nid = \"a\"\ncommand = \"x\"\nbogus = 1"),
            Err(AgentsFileError::Parse { .. })
        ));
    }

    #[test]
    fn a_missing_file_means_the_builtins() {
        let d = tempfile::tempdir().expect("tempdir");
        let ps = load_catalogue(Some(d.path())).expect("loaded");
        assert_eq!(
            ps.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
            ["claude", "codex", "gemini", "qwen", "antigravity"]
        );
        assert_eq!(load_catalogue(None).expect("none").len(), 5);
    }

    fn resolver(dir: &Path, platform: Platform, path: &Path) -> Resolver {
        Resolver {
            paths: AgentPaths::in_data_dir(dir),
            platform,
            path_env: Some(path.as_os_str().to_owned()),
        }
    }

    #[test]
    fn riscv64_is_unsupported_for_adapters() {
        let d = tempfile::tempdir().expect("tempdir");
        let r = resolver(d.path(), Platform::new("linux", "riscv64"), d.path());
        let p = builtin_profile("claude").expect("claude");
        assert!(matches!(r.status(&p), AgentStatus::Unsupported { .. }));
    }

    #[test]
    fn without_node_setup_can_download_it_on_linux_x64() {
        let d = tempfile::tempdir().expect("tempdir");
        let r = resolver(d.path(), Platform::new("linux", "x86_64"), d.path());
        let p = builtin_profile("claude").expect("claude");
        match r.status(&p) {
            AgentStatus::Available {
                needs_node_download,
                ..
            } => assert!(needs_node_download),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn without_node_on_an_undownloadable_platform_the_agent_is_missing() {
        let d = tempfile::tempdir().expect("tempdir");
        let r = resolver(d.path(), Platform::new("linux", "aarch64"), d.path());
        let p = builtin_profile("codex").expect("codex");
        assert!(matches!(r.status(&p), AgentStatus::Missing { .. }));
    }

    #[test]
    fn custom_command_is_found_on_path() {
        let d = tempfile::tempdir().expect("tempdir");
        let r = resolver(d.path(), Platform::current(), d.path());
        let p = AgentProfile::custom("x", "X", "definitely-not-installed-kraken", vec![]);
        assert!(matches!(r.status(&p), AgentStatus::Missing { .. }));
    }
}
