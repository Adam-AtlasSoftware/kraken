//! The assistant as registry jobs: the [`AssistJobs`] backend behind `assist_explain`,
//! `assist_overview` and `assist_auto_name`.
//!
//! One job is one assistant task ([`Task`]) run by an [`Assistant`] whose tools are the registry's
//! own commands on the session that started the job, so edits land in that project's edit log
//! under the task's run id. The model backend is wrapped in a [`Meter`] (the project's usage
//! ledger, the daily file, the caps of `[ai_limits]`) and the work shows on the session's AI board.
//! Only model APIs run here; a terminal agent needs its own MCP server and is started by
//! `kraken explain` or the GUI.

use std::sync::Arc;

use async_trait::async_trait;
use kraken_agent::{AgentEvent, ChatProvider, EnvSecrets, StopReason};
use kraken_host::backend::LocalBackend;
use kraken_model::{DailyLedger, ProjectLedger};
use kraken_proto::{AiJobStatus, AiOrigin, AiProviderKind, ErrorCode, ProtoError};
use kraken_registry::commands::{AssistJobs, AssistRequest};
use kraken_registry::session::DB_FILE;
use kraken_registry::{
    AiBoard, AiWork, CallContext, JobProgress, JobReporter, Registry, Session, Surface,
};

use crate::acp::AgentChoice;
use crate::ai_config::AiPolicy;
use crate::assistant::Assistant;
use crate::backend::{ApiBackend, AssistBackend};
use crate::error::AssistError;
use crate::meter::{Meter, MeterSpec};
use crate::provider::{build_provider, load_provider_config, provider_config_path};
use crate::tasks::{AutoNameOptions, Task};

/// Where the model for assistant jobs comes from.
pub trait AssistSource: Send + Sync {
    /// Fails with what to fix when no model is set up.
    fn ready(&self) -> Result<(), ProtoError> {
        Ok(())
    }

    /// The model backend, made for one job.
    fn backend(&self) -> Result<Arc<dyn AssistBackend>, ProtoError>;

    /// Models, prices and limits, read fresh for every call.
    fn policy(&self) -> AiPolicy;

    /// The daily totals the budget is checked against and calls are added to.
    fn daily(&self) -> Option<DailyLedger> {
        None
    }
}

/// The `[provider]` table of `config.toml`, re-read on every call.
pub struct ConfigSource;

impl ConfigSource {
    fn path(&self) -> Option<std::path::PathBuf> {
        provider_config_path(&|k| std::env::var_os(k))
    }
}

fn config_error(e: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, e.to_string())
}

impl AssistSource for ConfigSource {
    fn ready(&self) -> Result<(), ProtoError> {
        let cfg = load_provider_config(self.path().as_deref()).map_err(|e| match e {
            AssistError::NoProvider(m) => config_error(m),
            e => config_error(e),
        })?;
        if AgentChoice::from_config(&cfg).is_some() {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                "the [provider] table names a terminal agent, which the assist_* commands do not \
                 run; use `kraken explain`, `kraken overview` or `kraken auto-name`, or the GUI",
            ));
        }
        Ok(())
    }

    fn backend(&self) -> Result<Arc<dyn AssistBackend>, ProtoError> {
        self.ready()?;
        let path = self.path();
        let cfg = load_provider_config(path.as_deref()).map_err(config_error)?;
        let provider = build_provider(&cfg, &EnvSecrets).map_err(config_error)?;
        let low = crate::ai_config::AiLimits::load(path.as_deref()).low_context_mode;
        Ok(Arc::new(
            ApiBackend::new(provider).with_low_context(move || low),
        ))
    }

    fn policy(&self) -> AiPolicy {
        AiPolicy::load(self.path().as_deref())
    }

    fn daily(&self) -> Option<DailyLedger> {
        DailyLedger::from_env(&|k| std::env::var_os(k))
    }
}

/// Always the same chat model API and policy (tests, embedding).
pub struct FixedSource {
    /// The model.
    pub provider: Arc<dyn ChatProvider>,
    /// What estimates and limits say about it.
    pub policy: AiPolicy,
}

impl AssistSource for FixedSource {
    fn backend(&self) -> Result<Arc<dyn AssistBackend>, ProtoError> {
        Ok(Arc::new(ApiBackend::new(self.provider.clone())))
    }

    fn policy(&self) -> AiPolicy {
        self.policy.clone()
    }
}

/// Runs the `assist_*` jobs.
pub struct AssistService {
    source: Arc<dyn AssistSource>,
}

impl AssistService {
    /// A service over `source`.
    pub fn new(source: Arc<dyn AssistSource>) -> Self {
        AssistService { source }
    }

    /// The service the CLI and `krakend` attach: the model from `config.toml`.
    pub fn standard() -> Self {
        Self::new(Arc::new(ConfigSource))
    }

    /// The service as the trait object sessions take.
    pub fn into_backend(self) -> Arc<dyn AssistJobs> {
        Arc::new(self)
    }

    fn task(registry: &Registry, request: &AssistRequest) -> Result<Task, ProtoError> {
        match request {
            AssistRequest::Explain { address } => Task::explain_function(registry, address)
                .map_err(|e| ProtoError::new(ErrorCode::InvalidArgument, e.to_string())),
            AssistRequest::Overview => Ok(Task::overview(registry)),
            AssistRequest::AutoName { limit, dry_run } => Ok(Task::auto_name(
                registry,
                AutoNameOptions {
                    limit: *limit,
                    dry_run: *dry_run,
                },
            )),
        }
    }
}

fn origin_of(ctx: &CallContext) -> AiOrigin {
    if ctx.needs_user_approval() {
        return AiOrigin::Agent;
    }
    match ctx.surface {
        Surface::Gui => AiOrigin::Gui,
        Surface::Cli => AiOrigin::Cli,
        Surface::Mcp => AiOrigin::Agent,
        Surface::Test => AiOrigin::Other,
    }
}

fn label_of(request: &AssistRequest) -> String {
    match request {
        AssistRequest::Explain { address } => format!("Explaining {address}"),
        AssistRequest::Overview => "Summarising the program".to_string(),
        AssistRequest::AutoName { limit, dry_run } => format!(
            "Naming up to {limit} functions{}",
            if *dry_run { " (dry run)" } else { "" }
        ),
    }
}

/// The job's entry on the session's AI board.
struct BoardEntry {
    board: AiBoard,
    id: String,
}

#[async_trait]
impl AssistJobs for AssistService {
    fn check_ready(&self) -> Result<(), ProtoError> {
        self.source.ready()?;
        let policy = self.source.policy();
        if let Some(d) = self.source.daily()
            && let Some(m) = policy.daily_refusal(d.today().cost_usd)
        {
            return Err(limit_error(m));
        }
        Ok(())
    }

    async fn approval(
        &self,
        _s: &Session,
        ctx: &CallContext,
        request: &AssistRequest,
    ) -> Option<String> {
        let registry = Registry::standard();
        let task = Self::task(&registry, request).ok()?;
        let policy = self.source.policy();
        let estimate = policy.estimate(task.kind.feature(), 1, task.max_model_calls());
        let must =
            ctx.needs_user_approval() || estimate.as_ref().is_some_and(|e| policy.needs_confirm(e));
        if !must {
            return None;
        }
        let what = match request {
            AssistRequest::Explain { address } => format!("explain the function at {address}"),
            AssistRequest::Overview => "summarise the whole program".to_string(),
            AssistRequest::AutoName { limit, dry_run } => format!(
                "name up to {limit} functions{}",
                if *dry_run {
                    " without writing"
                } else {
                    " and write the names as renames and comments (one undoable run)"
                }
            ),
        };
        Some(match estimate {
            Some(e) => format!(
                "ask the model to {what}; it sends decompiled code to the provider: {}",
                e.text().replace('\n', " ")
            ),
            None => format!(
                "ask the model to {what}; it sends decompiled code to the provider; see \
                 `ai_usage` for what it cost"
            ),
        })
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        request: AssistRequest,
        job: &JobReporter,
    ) -> Result<serde_json::Value, ProtoError> {
        let registry = Arc::new(Registry::standard());
        let task = Self::task(&registry, &request)?;
        let feature = task.kind.feature();
        let max_calls = task.max_model_calls();
        let policy = self.source.policy();
        let inner = self.source.backend()?;
        let info = inner.provider_info();
        let kind = match inner.info().kind {
            crate::backend::BackendKind::TerminalAgent => AiProviderKind::TerminalAgent,
            crate::backend::BackendKind::Api => policy
                .choice_for(feature)
                .map(|c| c.kind)
                .unwrap_or(AiProviderKind::Api),
        };

        let board = s.ai().clone();
        let origin = origin_of(ctx);
        let entry = BoardEntry {
            id: board.start(AiWork {
                feature,
                label: label_of(&request),
                job_id: Some(job.id().0),
                provider_kind: kind,
                provider: info.id.clone(),
                model: info.model.clone(),
                origin,
                started_by: ctx.author.id.clone(),
            }),
            board,
        };
        let mut builder = Meter::builder(MeterSpec::new(feature, origin).job(job.id().0))
            .pricing(policy.pricing.clone())
            .limits(policy.limits.clone())
            .daily(self.source.daily())
            .kind(kind);
        if let Ok(p) = s.project() {
            builder = builder.sink(Arc::new(ProjectLedger::new(p.dir().join(DB_FILE))));
        }
        let (board, id) = (entry.board.clone(), entry.id.clone());
        builder = builder.observer(Arc::new(move |rec, totals| {
            board.update(&id, *totals, Some(&rec.model));
        }));
        let meter = builder.build();
        let engine = meter.wrap(inner);

        let backend = Arc::new(LocalBackend::new(
            registry.clone(),
            Arc::new(s.clone()),
            None,
        ));
        let assistant =
            Assistant::with_engine(registry, backend, engine.clone()).with_surface(ctx.surface);
        let cancel = job.cancel_token();
        let mut calls = 0u64;
        let result = assistant
            .run(task, &cancel, &mut |ev| {
                if let AgentEvent::ToolCallStarted { name, .. } = ev {
                    calls += 1;
                    job.progress(JobProgress {
                        phase: "assistant".into(),
                        done: calls,
                        total: max_calls,
                        message: format!("running {name}"),
                        ..Default::default()
                    });
                }
            })
            .await;
        engine.close();

        let limit = meter.limit_message();
        entry.board.update(&entry.id, meter.totals(), None);
        let (status, message) = match result.stop {
            StopReason::Error if limit.is_some() => (AiJobStatus::Limited, limit.clone()),
            StopReason::Error => (AiJobStatus::Failed, result.error.clone()),
            StopReason::Cancelled => (AiJobStatus::Cancelled, None),
            _ => (AiJobStatus::Succeeded, None),
        };
        entry.board.finish(&entry.id, status, message);

        match result.stop {
            StopReason::Error => Err(match limit {
                Some(m) => limit_error(m),
                None => ProtoError::new(
                    ErrorCode::Internal,
                    result
                        .error
                        .clone()
                        .unwrap_or_else(|| "the model run failed".into()),
                ),
            }),
            StopReason::Cancelled => Err(ProtoError::new(ErrorCode::Cancelled, "cancelled")),
            _ => serde_json::to_value(&result).map_err(|e| {
                ProtoError::new(ErrorCode::Internal, format!("cannot serialize result: {e}"))
            }),
        }
    }
}

/// The error a job ends with when a limit stopped it: `cancelled`, with `ai_limit` in the
/// details so clients can tell it from a person's Stop (the rewrite jobs do the same).
pub fn limit_error(message: String) -> ProtoError {
    ProtoError::new(ErrorCode::Cancelled, message)
        .with_details(serde_json::json!({ "ai_limit": true }))
}
