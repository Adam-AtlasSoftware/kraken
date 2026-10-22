//! [`ShellHost`]: a tool host that adds the `shell` tool to another host.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kraken_agent::{Decision, Permission, ToolCtx, ToolError, ToolHost, ToolSpec};
use kraken_host::ShellConfig;
use kraken_proto::Untrusted;
use serde_json::{Value, json};

use super::policy::{Policy, Verdict};
use super::sandbox::{self, DEFAULT_TIMEOUT_SECS, MAX_TIMEOUT_SECS, ShellSession};

/// The tool's name.
pub const SHELL_TOOL: &str = "shell";

/// Kept short on purpose: the assistant may have a small context window.
const DESCRIPTION: &str = "Run a shell command in a sandbox: no network, project files \
read-only, a scratch directory is writable and kept for the session. Use for math and quick \
helpers, e.g. `echo '2^64-1' | bc`, `python3 -c 'print(0x9e3779b9*3 % 2**32)'`. To run the \
analysed program use emulate_run.";

/// What the policy says about a command, for a card that asks the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellReview {
    /// Run, ask or refuse.
    pub verdict: Verdict,
    /// The program an "always allow in this project" button would add (`None`: nothing to add).
    pub program: Option<String>,
    /// Settings entries that were ignored.
    pub warnings: Vec<String>,
}

/// Classifies `command` under the built-in rules, `global` and the project's file.
pub fn review(global: &ShellConfig, project_dir: Option<&Path>, command: &str) -> ShellReview {
    let policy = Policy::load(global, project_dir);
    ShellReview {
        verdict: policy.classify(command),
        program: policy.program_to_allow(command),
        warnings: policy.warnings.clone(),
    }
}

/// Adds the `shell` tool to `inner`. The tool is left out when the host cannot confine.
pub struct ShellHost {
    inner: Arc<dyn ToolHost>,
    session: Arc<ShellSession>,
    global: ShellConfig,
    project_dir: Option<PathBuf>,
    binary: Option<PathBuf>,
}

impl ShellHost {
    /// `session` holds the scratch directory (keep one for the whole chat); `project_dir` is
    /// where `assistant-shell.toml` lives and `exports` is read from; `binary` is the analysed
    /// program, readable but not executable.
    pub fn new(
        inner: Arc<dyn ToolHost>,
        session: Arc<ShellSession>,
        global: ShellConfig,
        project_dir: Option<PathBuf>,
        binary: Option<PathBuf>,
    ) -> Self {
        ShellHost {
            inner,
            session,
            global,
            project_dir,
            binary,
        }
    }

    /// True when commands can be sandboxed on this computer.
    pub fn available() -> bool {
        kraken_confine::enforced()
    }

    fn spec() -> ToolSpec {
        ToolSpec {
            name: SHELL_TOOL.into(),
            description: DESCRIPTION.into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECS}
                },
                "required": ["command"]
            }),
            permission: Permission::Dangerous,
        }
    }

    fn policy(&self) -> Policy {
        Policy::load(&self.global, self.project_dir.as_deref())
    }

    fn read_only_paths(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = self.binary.iter().cloned().collect();
        if let Some(dir) = &self.project_dir {
            v.push(dir.join("exports"));
        }
        v
    }
}

#[async_trait]
impl ToolHost for ShellHost {
    fn tools(&self) -> Vec<ToolSpec> {
        let mut v = self.inner.tools();
        if Self::available() {
            v.push(Self::spec());
        }
        v
    }

    fn decide(&self, name: &str, args: &Value) -> Decision {
        if name != SHELL_TOOL {
            return self.inner.decide(name, args);
        }
        let Some(command) = args.get("command").and_then(Value::as_str) else {
            return Decision::Deny("`command` must be a string.".into());
        };
        match self.policy().classify(command) {
            Verdict::Allow => Decision::Allow,
            Verdict::Ask(_) => Decision::Ask,
            Verdict::Deny(why) => Decision::Deny(why),
        }
    }

    async fn call(&self, name: &str, args: Value, ctx: &ToolCtx) -> Result<Value, ToolError> {
        if name != SHELL_TOOL {
            return self.inner.call(name, args, ctx).await;
        }
        if !Self::available() {
            return Err(ToolError::NotFound(name.into()));
        }
        let command = args
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| ToolError::InvalidArgs("`command` must be a string".into()))?
            .to_string();
        let secs = match args.get("timeout_seconds") {
            None | Some(Value::Null) => DEFAULT_TIMEOUT_SECS,
            Some(v) => v
                .as_u64()
                .ok_or_else(|| {
                    ToolError::InvalidArgs("`timeout_seconds` must be an integer".into())
                })?
                .clamp(1, MAX_TIMEOUT_SECS),
        };
        // Whoever approved it, a refused command does not run.
        if let Verdict::Deny(why) = self.policy().classify(&command) {
            return Err(ToolError::Failed(why));
        }
        let scratch = self.session.scratch().map_err(ToolError::Failed)?;
        let read_only = self.read_only_paths();
        let work = tokio::task::spawn_blocking(move || {
            sandbox::run(&command, &scratch, &read_only, Duration::from_secs(secs))
        });
        let outcome = tokio::select! {
            () = ctx.cancel.cancelled() => return Err(ToolError::Cancelled),
            r = work => r
                .map_err(|e| ToolError::Failed(format!("the shell task failed: {e}")))?
                .map_err(ToolError::Failed)?,
        };
        let mut result = json!({
            "exit": outcome.exit,
            "output": Untrusted(outcome.output),
            "timed_out": outcome.timed_out,
        });
        if let (Some(sig), Some(obj)) = (outcome.signal, result.as_object_mut()) {
            obj.insert("signal".into(), json!(sig));
        }
        Ok(result)
    }
}
