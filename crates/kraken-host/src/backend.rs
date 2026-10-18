//! Where a surface (CLI, MCP) sends its commands: in-process or through `krakend`.
//!
//! Both backends take the same `(command, context, args)` and return exactly the registry's
//! output JSON, so a surface does not care which one it has. [`LocalBackend`] is the 0.1a direct
//! mode (a session in this process); [`DaemonBackend`] forwards to the daemon, which keeps the
//! sessions and the Ghidra sidecars alive between invocations.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::{
    ApprovalDecision, ApprovalRequest, CallContext, Permission, Registry, Session, Surface,
};
use serde_json::Value;

use kraken_ipc::Notification;
use kraken_proto::OpenProgress;
use tokio::sync::mpsc;

use crate::daemon::{
    CallParams, DaemonClient, GuiSelectionReply, METHOD_EVENT, absolute, canonical_prefix,
    event_kind,
};

/// A place commands run.
#[async_trait]
pub trait CommandBackend: Send + Sync {
    /// Runs the command `name` as `ctx`; the result is the registry's output JSON.
    async fn call(&self, name: &str, ctx: &CallContext, args: Value) -> Result<Value, ProtoError>;

    /// Takes the non-fatal notices collected so far (a stale engine cache, ...).
    fn take_warnings(&self) -> Vec<String>;

    /// What the person has selected in a GUI attached to the same daemon. Only a daemon can know
    /// this; an in-process backend has no GUI beside it and reports none.
    async fn gui_selection(&self) -> Result<GuiSelectionReply, ProtoError> {
        Ok(GuiSelectionReply {
            attached: false,
            stale: false,
            age_secs: 0,
            selection: None,
        })
    }
}

fn is_project_command(name: &str) -> bool {
    matches!(name, "project_create" | "project_open")
}

fn no_project() -> ProtoError {
    ProtoError::new(
        ErrorCode::NotFound,
        "no project is open; run project_create or project_open first",
    )
}

#[derive(Default)]
struct Warnings(Mutex<Vec<String>>);

impl Warnings {
    fn push(&self, w: String) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(w);
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Commands run in this process on one [`Session`].
pub struct LocalBackend {
    registry: Arc<Registry>,
    session: Arc<Session>,
    default_project: Option<PathBuf>,
    warnings: Warnings,
}

impl LocalBackend {
    /// A backend over `session`. When no project is open yet, the first command other than
    /// `project_create` / `project_open` opens `default_project` (if any).
    pub fn new(
        registry: Arc<Registry>,
        session: Arc<Session>,
        default_project: Option<PathBuf>,
    ) -> Self {
        LocalBackend {
            registry,
            session,
            default_project,
            warnings: Warnings::default(),
        }
    }

    /// The session commands run on.
    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }

    /// Opens the default project now if none is open.
    pub async fn ensure_project(&self) -> Result<(), ProtoError> {
        if self.session.project().is_err()
            && let Some(dir) = &self.default_project
        {
            let p = self.session.open_project(&absolute(dir)).await?;
            if !p.epoch_mismatch().is_empty() {
                self.warnings.push(format!(
                    "the engine cache is stale ({}); run `kraken rebuild`",
                    p.epoch_mismatch().join(", ")
                ));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl CommandBackend for LocalBackend {
    async fn call(&self, name: &str, ctx: &CallContext, args: Value) -> Result<Value, ProtoError> {
        if !is_project_command(name) {
            self.ensure_project().await?;
        }
        self.registry
            .call_json(name, &self.session, ctx, args)
            .await
    }

    fn take_warnings(&self) -> Vec<String> {
        self.warnings.take()
    }
}

/// Commands forwarded to `krakend`. The daemon keeps one session per project directory; this
/// backend remembers the current project of its connection (set by `project_create` /
/// `project_open`, or given as the default) the way a local session would.
pub struct DaemonBackend {
    client: Arc<DaemonClient>,
    registry: Arc<Registry>,
    current: Mutex<Option<PathBuf>>,
    warnings: Warnings,
    /// The daemon's events, taken on the first open that has a progress sink.
    events: tokio::sync::Mutex<Option<mpsc::UnboundedReceiver<Notification>>>,
}

impl DaemonBackend {
    /// A backend over `client`. `default_project` is the project commands use until a
    /// `project_create` / `project_open` changes it.
    pub fn new(
        client: Arc<DaemonClient>,
        registry: Arc<Registry>,
        default_project: Option<PathBuf>,
    ) -> Self {
        let warnings = Warnings::default();
        if let Some(w) = client.build_mismatch_warning() {
            warnings.push(w);
        }
        DaemonBackend {
            client,
            registry,
            current: Mutex::new(default_project.map(|p| absolute(&p))),
            warnings,
            events: tokio::sync::Mutex::new(None),
        }
    }

    /// The daemon connection.
    pub fn client(&self) -> &Arc<DaemonClient> {
        &self.client
    }

    /// The project commands currently run against.
    pub fn current_project(&self) -> Option<PathBuf> {
        self.current
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl DaemonBackend {
    /// Runs `project_create` / `project_open` while passing the daemon's `open_progress` events
    /// for that project to the context's sink. Cancelling the context cancels the open through
    /// its job (`job_cancel`), so the daemon stops it and keeps nothing of it.
    async fn open_watched(
        &self,
        params: &CallParams,
        ctx: &CallContext,
    ) -> Result<crate::daemon::CallResult, ProtoError> {
        let mut events = self.events.lock().await;
        if events.is_none() {
            *events = self.client.take_events();
        }
        let key = canonical_prefix(Path::new(&params.project_dir));
        let sink = ctx.open_progress.clone();
        let call = self.client.call(params);
        tokio::pin!(call);
        let mut job: Option<String> = None;
        let mut cancelling = false;
        loop {
            let next = async {
                match events.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                r = &mut call => return r,
                Some(n) = next => {
                    let Some(p) = open_progress_for(&n, &key) else {
                        continue;
                    };
                    if p.job_id.is_some() {
                        job.clone_from(&p.job_id);
                    }
                    if let Some(sink) = &sink {
                        sink(&p);
                    }
                }
                () = ctx.cancel.cancelled(), if !cancelling => {
                    cancelling = true;
                    let Some(id) = job.clone() else {
                        return Err(ProtoError::new(ErrorCode::Cancelled, "call cancelled"));
                    };
                    let cancel = CallParams {
                        command: "job_cancel".into(),
                        args: serde_json::json!({ "job_id": id }),
                        ..params.clone()
                    };
                    // the open itself then ends with `cancelled`
                    self.client.call(&cancel).await?;
                }
            }
        }
    }
}

/// The open progress in an `event` notification about the project `key`.
fn open_progress_for(n: &Notification, key: &Path) -> Option<OpenProgress> {
    if n.method != METHOD_EVENT {
        return None;
    }
    let v = &n.params;
    if v.get("kind").and_then(Value::as_str) != Some(event_kind::OPEN_PROGRESS)
        || v.get("project_dir").and_then(Value::as_str).map(Path::new) != Some(key)
    {
        return None;
    }
    serde_json::from_value(v.clone()).ok()
}

/// Paths in these arguments are resolved against the client's working directory, which the
/// daemon does not share.
fn absolutize_args(name: &str, args: &mut Value) {
    let Some(obj) = args.as_object_mut() else {
        return;
    };
    let keys: &[&str] = match name {
        "project_create" => &["binary", "project_dir"],
        "project_open" => &["project_dir"],
        _ => &[],
    };
    for k in keys {
        if let Some(Value::String(s)) = obj.get_mut(*k)
            && !s.is_empty()
        {
            *s = absolute(Path::new(s.as_str()))
                .to_string_lossy()
                .into_owned();
        }
    }
}

#[async_trait]
impl CommandBackend for DaemonBackend {
    async fn call(
        &self,
        name: &str,
        ctx: &CallContext,
        mut args: Value,
    ) -> Result<Value, ProtoError> {
        let entry = self.registry.get(name).ok_or_else(|| {
            ProtoError::new(ErrorCode::NotFound, format!("unknown command `{name}`"))
        })?;
        let mut approved = false;
        // On the MCP surface the daemon asks the person itself: this process runs under the
        // agent's control, so an approval it reports would prove nothing (the daemon ignores
        // the `approved` flag of an agent connection).
        if entry.spec().permission == Permission::Dangerous && ctx.surface != Surface::Mcp {
            let decision = ctx
                .approval
                .request(ApprovalRequest {
                    command: entry.spec().name.clone(),
                    summary: entry.spec().summary.clone(),
                    args: args.clone(),
                    author: ctx.author.clone(),
                    surface: ctx.surface,
                })
                .await;
            match decision {
                ApprovalDecision::Allow => approved = true,
                ApprovalDecision::Deny { reason } => {
                    return Err(ProtoError::new(
                        ErrorCode::Unsupported,
                        format!("approval denied: {reason}"),
                    )
                    .with_details(serde_json::json!({ "approval": "denied" })));
                }
            }
        }
        absolutize_args(name, &mut args);
        let creating = is_project_command(name);
        // An agent author on the CLI (a person typed `--yes` or answers the prompt) goes through
        // the same gate as in-process, and the daemon is told it was approved. On the MCP
        // surface the daemon asks the person itself.
        if creating && ctx.needs_user_approval() && ctx.surface != Surface::Mcp {
            kraken_registry::commands::project_gate(name, &args, ctx).await?;
            approved = true;
        }
        let project_dir = if creating {
            args.get("project_dir")
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .ok_or_else(|| ProtoError::new(ErrorCode::InvalidArgument, "missing project_dir"))?
        } else {
            self.current_project().ok_or_else(no_project)?
        };
        let params = CallParams {
            project_dir: project_dir.to_string_lossy().into_owned(),
            command: name.to_string(),
            args,
            author_kind: ctx.author.kind,
            author_id: Some(ctx.author.id.clone()),
            run_id: ctx.run_id.as_ref().map(|r| r.0.clone()),
            surface: Some(ctx.surface),
            approved,
        };
        let reply = if creating && ctx.open_progress.is_some() {
            self.open_watched(&params, ctx).await?
        } else {
            tokio::select! {
                biased;
                () = ctx.cancel.cancelled() => {
                    return Err(ProtoError::new(ErrorCode::Cancelled, "call cancelled"));
                }
                r = self.client.call(&params) => r?,
            }
        };
        for w in reply.warnings {
            self.warnings.push(w);
        }
        if creating {
            *self.current.lock().unwrap_or_else(PoisonError::into_inner) = Some(project_dir);
        }
        Ok(reply.result)
    }

    fn take_warnings(&self) -> Vec<String> {
        self.warnings.take()
    }

    async fn gui_selection(&self) -> Result<GuiSelectionReply, ProtoError> {
        let dir = self.current_project().ok_or_else(no_project)?;
        self.client.gui_selection(&dir).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn relative_paths_become_absolute_for_project_commands_only() {
        let mut a = json!({"binary": "prog.bin", "project_dir": "proj"});
        absolutize_args("project_create", &mut a);
        assert!(Path::new(a["binary"].as_str().unwrap()).is_absolute());
        assert!(Path::new(a["project_dir"].as_str().unwrap()).is_absolute());
        let mut b = json!({"address": "0x10"});
        absolutize_args("rename_symbol", &mut b);
        assert_eq!(b, json!({"address": "0x10"}));
    }
}
