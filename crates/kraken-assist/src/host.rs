//! [`RegistryToolHost`]: command-registry commands as agent tools.
//!
//! Which tools exist is decided here from the registry's command specs and the task's tool
//! subset, never from anything the model or the binary says. Calls run as the assistant agent
//! with the agent run's id, so the registry's own policy applies unchanged: additive edits
//! auto-apply up to the per-run cap, overwrites become proposals, dangerous commands are not
//! exposed at all.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_agent::{Decision, Permission, ToolCtx, ToolError, ToolHost, ToolSpec};
use kraken_host::backend::CommandBackend;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::{
    ApprovalRequester, AutoApprove, CallContext, CommandKind, CommandSpec, DenyApprover,
    Permission as RegPermission, Registry, Surface,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::Instant;

/// What the assistant may do with KRAKEN's dangerous commands (byte-patch export, delete, the
/// rewrite pipeline). Shell access is governed separately (see `crate::permissions`), because
/// running commands is far riskier than editing the project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DangerMode {
    /// Dangerous commands are not offered to the assistant at all; the person runs them by hand.
    /// Reversible edits (renames, comments, staging a byte patch) still work.
    #[default]
    Deny,
    /// The assistant may call a dangerous command, but each one asks the person first.
    Ask,
    /// The assistant runs dangerous commands without asking. Full hands-off control of KRAKEN.
    Yolo,
}

use crate::ASSISTANT_ID;

/// Commands never offered to the model by default: they open, create or rebuild projects (the
/// person's decision), are user-only decisions about the assistant's own work, start the
/// rewrite pipeline's model calls, sandboxed builds and exports (`rewrite_plan`,
/// `rewrite_status`, `rewrite_unit` and `rewrite_program_status` are read-only and stay
/// available), or start and stop local model servers (`local_model_list`, `local_model_status`
/// and `local_model_devices` stay available).
pub const DEFAULT_EXCLUDED: &[&str] = &[
    "project_create",
    "project_open",
    "rebuild",
    "undo",
    "undo_run",
    "undo_entry",
    "tainted_clear",
    "proposal_accept",
    "proposal_reject",
    "rewrite_function",
    "rewrite_program",
    "rewrite_spec",
    "rewrite_export",
    "rewrite_accept",
    "local_model_start",
    "local_model_hold",
    "local_model_release",
    "local_model_stop",
];

/// Commands no task can switch on: the person's decisions.
const PERSONS_OWN: &[&str] = &[
    "project_create",
    "project_open",
    "rebuild",
    "undo",
    "undo_run",
    "undo_entry",
    "tainted_clear",
    "proposal_accept",
    "proposal_reject",
    "rewrite_accept",
];

/// How a [`RegistryToolHost`] is set up.
#[derive(Debug, Clone)]
pub struct HostOptions {
    /// Author id the calls are logged under.
    pub agent_id: String,
    /// Surface reported to the registry.
    pub surface: Surface,
    /// Only these commands (when set), still subject to the exclusions.
    pub allow: Option<BTreeSet<String>>,
    /// Offer no mutating commands at all.
    pub read_only: bool,
    /// Most mutating calls per run; later ones fail without reaching the registry.
    pub max_writes: Option<usize>,
    /// How long a tool call waits for a job it started (for example `analyze`).
    pub job_timeout: Duration,
    /// Commands of [`DEFAULT_EXCLUDED`] this host offers anyway (a task switches them on). Only
    /// commands that stay inside the registry's policy belong here; never the person's own
    /// decisions (`rewrite_accept`, proposals, undo, opening projects).
    pub unlock: BTreeSet<String>,
    /// What the assistant may do with dangerous commands. `Ask` and `Yolo` also expose them;
    /// `Ask` needs an approver on the host (see [`RegistryToolHost::with_approver`]), else a
    /// dangerous call is denied.
    pub danger: DangerMode,
}

impl Default for HostOptions {
    fn default() -> Self {
        HostOptions {
            agent_id: ASSISTANT_ID.to_string(),
            surface: Surface::Cli,
            allow: None,
            read_only: false,
            max_writes: None,
            job_timeout: Duration::from_secs(600),
            unlock: BTreeSet::new(),
            danger: DangerMode::default(),
        }
    }
}

/// One tool call as the host saw it.
#[derive(Debug, Clone, PartialEq)]
pub struct CallRecord {
    /// Command name.
    pub tool: String,
    /// Arguments as the model sent them.
    pub args: Value,
    /// True when the registry returned a result.
    pub ok: bool,
    /// `status` of a mutation result (`applied`, `queued`, `proposed`).
    pub status: Option<String>,
    /// Error code of a failed call.
    pub error_code: Option<String>,
    /// True for commands of kind `Mutation`.
    pub is_write: bool,
}

/// Calls made through a host, in order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostStats {
    /// Every call that reached the registry or was refused by the write cap.
    pub calls: Vec<CallRecord>,
}

impl HostStats {
    /// Calls to `tool`.
    pub fn calls_to<'a>(&'a self, tool: &'a str) -> impl Iterator<Item = &'a CallRecord> {
        self.calls.iter().filter(move |c| c.tool == tool)
    }

    /// Mutation results with `status`.
    pub fn writes_with_status(&self, status: &str) -> usize {
        self.calls
            .iter()
            .filter(|c| c.is_write && c.status.as_deref() == Some(status))
            .count()
    }

    /// Mutation calls that failed.
    pub fn failed_writes(&self) -> usize {
        self.calls.iter().filter(|c| c.is_write && !c.ok).count()
    }
}

/// Registry commands as [`ToolHost`] tools.
pub struct RegistryToolHost {
    registry: Arc<Registry>,
    backend: Arc<dyn CommandBackend>,
    opts: HostOptions,
    /// Asked before a dangerous command runs in [`DangerMode::Ask`]. `DenyApprover` by default,
    /// so without an approver an `Ask`-mode dangerous call is refused rather than run unasked.
    approver: Arc<dyn ApprovalRequester>,
    stats: Mutex<HostStats>,
}

impl RegistryToolHost {
    /// A host over `backend`, offering the commands of `registry` that `opts` allows.
    pub fn new(
        registry: Arc<Registry>,
        backend: Arc<dyn CommandBackend>,
        opts: HostOptions,
    ) -> Self {
        RegistryToolHost {
            registry,
            backend,
            opts,
            approver: Arc::new(DenyApprover),
            stats: Mutex::new(HostStats::default()),
        }
    }

    /// Sets who approves dangerous commands in [`DangerMode::Ask`] (the GUI dialog, the CLI
    /// prompt). `Yolo` auto-approves and needs none; `Deny` never exposes them.
    pub fn with_approver(mut self, approver: Arc<dyn ApprovalRequester>) -> Self {
        self.approver = approver;
        self
    }

    /// The approver the backend call context should carry for `spec`, given the mode.
    fn approver_for(&self, spec: &CommandSpec) -> Arc<dyn ApprovalRequester> {
        if spec.permission != RegPermission::Dangerous {
            return Arc::new(DenyApprover);
        }
        match self.opts.danger {
            DangerMode::Yolo => Arc::new(AutoApprove),
            DangerMode::Ask => self.approver.clone(),
            DangerMode::Deny => Arc::new(DenyApprover),
        }
    }

    /// The calls made so far.
    pub fn stats(&self) -> HostStats {
        self.stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn exposed(&self, spec: &CommandSpec) -> bool {
        if !matches!(
            spec.kind,
            CommandKind::Query | CommandKind::Mutation | CommandKind::Job
        ) {
            return false;
        }
        // Dangerous commands are offered only when the mode allows them; `Ask`/`Yolo` expose
        // them, `Deny` hides them. Read-only tasks never expose a dangerous command.
        if spec.permission == RegPermission::Dangerous
            && (self.opts.danger == DangerMode::Deny || self.opts.read_only)
        {
            return false;
        }
        if DEFAULT_EXCLUDED.contains(&spec.name.as_str())
            && !(self.opts.unlock.contains(&spec.name)
                && !PERSONS_OWN.contains(&spec.name.as_str()))
        {
            return false;
        }
        if self.opts.read_only && spec.permission != RegPermission::Safe {
            return false;
        }
        if self.opts.read_only && spec.kind == CommandKind::Mutation {
            return false;
        }
        match &self.opts.allow {
            Some(set) => set.contains(&spec.name),
            None => true,
        }
    }

    fn record(&self, rec: CallRecord) {
        self.stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .calls
            .push(rec);
    }

    fn writes_so_far(&self) -> usize {
        self.stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .calls
            .iter()
            .filter(|c| c.is_write)
            .count()
    }

    /// Waits for the job a `Job` command started and returns its final view.
    async fn await_job(&self, started: &Value, ctx: &CallContext) -> Result<Value, ProtoError> {
        let Some(id) = started.get("job_id").and_then(Value::as_str) else {
            return Ok(started.clone());
        };
        let deadline = Instant::now() + self.opts.job_timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let slice = left.min(Duration::from_secs(5)).as_millis().max(1);
            let view = self
                .backend
                .call(
                    "job_await",
                    ctx,
                    json!({"job_id": id, "timeout_ms": u64::try_from(slice).unwrap_or(5000)}),
                )
                .await?;
            let running = view.get("status").and_then(Value::as_str) == Some("running");
            if !running || left.is_zero() {
                return Ok(view);
            }
        }
    }
}

fn tool_error(e: ProtoError) -> ToolError {
    match e.code {
        ErrorCode::Cancelled => ToolError::Cancelled,
        ErrorCode::InvalidArgument => ToolError::InvalidArgs(e.message),
        code => ToolError::Failed(format!("{}: {}", code.as_str(), e.message)),
    }
}

/// Gives a proposed write the top-level `"proposal"` field `kraken-agent` looks for, keeping the
/// registry's own fields.
pub(crate) fn shape_output(mut v: Value) -> Value {
    if v.get("status").and_then(Value::as_str) == Some("proposed")
        && let Some(obj) = v.as_object_mut()
    {
        let mut p = serde_json::Map::new();
        for k in ["proposal_id", "key", "reason"] {
            if let Some(x) = obj.get(k) {
                p.insert(k.to_string(), x.clone());
            }
        }
        p.insert("status".into(), json!("proposed"));
        obj.insert("proposal".into(), Value::Object(p));
    }
    v
}

fn description(spec: &CommandSpec) -> String {
    spec.tool_description()
}

fn input_schema(schema: &Value) -> Value {
    let mut s = schema.clone();
    if let Some(o) = s.as_object_mut() {
        o.remove("$schema");
        o.remove("title");
        o.entry("type").or_insert_with(|| json!("object"));
    } else {
        s = json!({"type": "object"});
    }
    s
}

#[async_trait]
impl ToolHost for RegistryToolHost {
    fn tools(&self) -> Vec<ToolSpec> {
        self.registry
            .iter()
            .filter(|e| self.exposed(e.spec()))
            .map(|e| ToolSpec {
                name: e.spec().name.clone(),
                description: description(e.spec()),
                input_schema: input_schema(e.args_schema()),
                permission: match e.spec().permission {
                    RegPermission::Safe => Permission::Safe,
                    RegPermission::Mutating => Permission::Mutating,
                    RegPermission::Dangerous => Permission::Dangerous,
                },
            })
            .collect()
    }

    /// Approval for a dangerous command is enforced by the registry when the call runs, through
    /// the approver this host puts on the call context (chosen by [`DangerMode`]). So the agent
    /// loop itself always proceeds: it must not raise a second prompt of its own, and it must not
    /// block on an approval channel the API path has no one to answer. A command the mode hides
    /// is refused here.
    fn decide(&self, name: &str, _args: &Value) -> Decision {
        match self.registry.get(name) {
            Some(e) if self.exposed(e.spec()) => Decision::Allow,
            _ => Decision::Deny(format!("`{name}` is not available to the assistant")),
        }
    }

    async fn call(&self, name: &str, args: Value, ctx: &ToolCtx) -> Result<Value, ToolError> {
        let entry = self
            .registry
            .get(name)
            .filter(|e| self.exposed(e.spec()))
            .ok_or_else(|| ToolError::NotFound(name.to_string()))?;
        let kind = entry.spec().kind;
        let is_write = kind == CommandKind::Mutation;
        let approver = self.approver_for(entry.spec());
        let mut rec = CallRecord {
            tool: name.to_string(),
            args: args.clone(),
            ok: false,
            status: None,
            error_code: None,
            is_write,
        };
        if is_write
            && let Some(max) = self.opts.max_writes
            && self.writes_so_far() >= max
        {
            rec.error_code = Some("write_limit".into());
            self.record(rec);
            return Err(ToolError::Failed(format!(
                "write limit reached: at most {max} edits per assistant run. \
                 Stop editing and summarise what is left for the user."
            )));
        }
        let call_ctx = CallContext::agent(
            self.opts.agent_id.clone(),
            ctx.run_id.clone(),
            self.opts.surface,
        )
        .with_cancel(ctx.cancel.clone())
        .with_approval(approver);
        let mut result = self.backend.call(name, &call_ctx, args).await;
        if kind == CommandKind::Job
            && let Ok(started) = &result
        {
            result = self.await_job(started, &call_ctx).await;
        }
        match result {
            Ok(v) => {
                rec.ok = true;
                rec.status = v.get("status").and_then(Value::as_str).map(str::to_string);
                self.record(rec);
                Ok(shape_output(v))
            }
            Err(e) => {
                rec.error_code = Some(e.code.as_str().to_string());
                self.record(rec);
                Err(tool_error(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposals_get_a_top_level_field() {
        let v = shape_output(json!({
            "status": "proposed", "proposal_id": 7, "key": "name@0x10",
            "versions": {}, "reason": "overwrites a user edit"
        }));
        assert_eq!(v["proposal"]["proposal_id"], 7);
        assert_eq!(v["status"], "proposed");
        let applied = shape_output(json!({"status": "applied", "entry_id": 1}));
        assert!(applied.get("proposal").is_none());
    }

    #[test]
    fn schema_is_trimmed_to_an_object_schema() {
        let s = input_schema(&json!({"$schema": "x", "title": "T", "properties": {}}));
        assert_eq!(s["type"], "object");
        assert!(s.get("$schema").is_none());
    }

    // ---- danger modes ----------------------------------------------------------------------

    use kraken_registry::{ApprovalDecision, ApprovalRequest};
    use std::sync::Mutex as StdMutex;
    use tokio_util::sync::CancellationToken;

    /// A backend that mimics the registry's dangerous-command gate: it asks `ctx.approval` and
    /// records whether the call was approved, so a test can see which approver the host attached.
    #[derive(Default)]
    struct GateBackend {
        approved: StdMutex<Vec<(String, bool)>>,
    }

    #[async_trait]
    impl CommandBackend for GateBackend {
        async fn call(
            &self,
            name: &str,
            ctx: &CallContext,
            args: Value,
        ) -> Result<Value, ProtoError> {
            let decision = ctx
                .approval
                .request(ApprovalRequest {
                    command: name.to_string(),
                    summary: String::new(),
                    args,
                    author: ctx.author.clone(),
                    surface: ctx.surface,
                })
                .await;
            let ok = matches!(decision, ApprovalDecision::Allow);
            self.approved.lock().unwrap().push((name.to_string(), ok));
            if ok {
                Ok(json!({"status": "applied"}))
            } else {
                Err(ProtoError::new(ErrorCode::Unsupported, "approval denied"))
            }
        }
        fn take_warnings(&self) -> Vec<String> {
            Vec::new()
        }
    }

    fn host(danger: DangerMode) -> (RegistryToolHost, Arc<GateBackend>) {
        let backend = Arc::new(GateBackend::default());
        let host = RegistryToolHost::new(
            Arc::new(Registry::standard()),
            backend.clone(),
            HostOptions {
                danger,
                ..Default::default()
            },
        );
        (host, backend)
    }

    fn has_tool(h: &RegistryToolHost, name: &str) -> bool {
        h.tools().iter().any(|t| t.name == name)
    }

    #[test]
    fn deny_hides_dangerous_but_keeps_reversible_patch_ops() {
        let (h, _) = host(DangerMode::Deny);
        // patch_export is dangerous -> hidden; patch_set/patch_remove are reversible -> offered.
        assert!(!has_tool(&h, "patch_export"));
        assert!(has_tool(&h, "patch_set"));
        assert!(has_tool(&h, "patch_remove"));
        assert_eq!(
            h.decide("patch_export", &json!({})),
            Decision::Deny("`patch_export` is not available to the assistant".into())
        );
        assert_eq!(h.decide("patch_set", &json!({})), Decision::Allow);
    }

    #[test]
    fn ask_and_yolo_expose_dangerous() {
        for mode in [DangerMode::Ask, DangerMode::Yolo] {
            let (h, _) = host(mode);
            assert!(has_tool(&h, "patch_export"), "{mode:?}");
            // The agent layer always proceeds; approval is enforced by the call context.
            assert_eq!(
                h.decide("patch_export", &json!({})),
                Decision::Allow,
                "{mode:?}"
            );
        }
    }

    fn ctx() -> ToolCtx {
        ToolCtx {
            run_id: "r".into(),
            call_id: "c".into(),
            cancel: CancellationToken::new(),
        }
    }

    #[tokio::test]
    async fn yolo_auto_approves_a_dangerous_call() {
        let (h, backend) = host(DangerMode::Yolo);
        let out = h
            .call("patch_export", json!({"output_path": "x"}), &ctx())
            .await
            .expect("yolo runs without a prompt");
        assert_eq!(out["status"], "applied");
        assert_eq!(
            backend.approved.lock().unwrap().as_slice(),
            &[("patch_export".to_string(), true)]
        );
    }

    #[tokio::test]
    async fn ask_without_an_approver_denies() {
        // Ask mode exposes the command, but with no approver attached the default DenyApprover
        // refuses it (ADR 0003 fallback) rather than running it unasked.
        let (h, backend) = host(DangerMode::Ask);
        let err = h
            .call("patch_export", json!({"output_path": "x"}), &ctx())
            .await
            .expect_err("no approval channel -> denied");
        assert!(matches!(err, ToolError::Failed(_)), "{err:?}");
        assert_eq!(
            backend.approved.lock().unwrap().as_slice(),
            &[("patch_export".to_string(), false)]
        );
    }

    #[tokio::test]
    async fn ask_with_an_approver_runs_after_approval() {
        let (h, backend) = host(DangerMode::Ask);
        let h = h.with_approver(Arc::new(kraken_registry::AutoApprove));
        let out = h
            .call("patch_export", json!({"output_path": "x"}), &ctx())
            .await
            .expect("approved");
        assert_eq!(out["status"], "applied");
        assert_eq!(
            backend.approved.lock().unwrap().as_slice(),
            &[("patch_export".to_string(), true)]
        );
    }

    #[test]
    fn read_only_hides_dangerous_even_in_yolo() {
        let backend = Arc::new(GateBackend::default());
        let h = RegistryToolHost::new(
            Arc::new(Registry::standard()),
            backend,
            HostOptions {
                danger: DangerMode::Yolo,
                read_only: true,
                ..Default::default()
            },
        );
        assert!(!has_tool(&h, "patch_export"));
    }
}
