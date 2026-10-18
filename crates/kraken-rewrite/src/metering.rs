//! The model calls of one rewrite job: the backend of the job's model wrapped in a meter, the
//! job's entry on the session's AI board, and how the job's end is reported there.
//!
//! The backend is made on the first model call, so a job that needs none (a stored spec) does
//! not show as AI work and does not need a configured provider.

use std::sync::{Arc, Mutex, PoisonError};

use kraken_assist::{AssistBackend, Meter, MeterSpec, RewriteModel};
use kraken_model::ProjectLedger;
use kraken_proto::{AiFeature, AiJobStatus, AiOrigin, AiProviderKind, ErrorCode, ProtoError};
use kraken_registry::session::DB_FILE;
use kraken_registry::{AiBoard, AiWork, CallContext, JobReporter, Session, Surface};

use crate::service::BackendSource;

/// Who started the work, as the AI board shows it.
pub fn origin_of(ctx: &CallContext) -> AiOrigin {
    if ctx.author.kind == kraken_model::AuthorKind::Agent || ctx.surface == Surface::Mcp {
        return AiOrigin::Agent;
    }
    match ctx.surface {
        Surface::Gui => AiOrigin::Gui,
        Surface::Cli => AiOrigin::Cli,
        Surface::Mcp => AiOrigin::Agent,
        Surface::Test => AiOrigin::Other,
    }
}

struct Started {
    backend: Arc<dyn AssistBackend>,
    meter: Meter,
    board_id: String,
}

/// The AI side of one rewrite job.
pub struct JobAi {
    source: Arc<dyn BackendSource>,
    board: AiBoard,
    which: RewriteModel,
    model: Option<String>,
    label: String,
    job_id: String,
    origin: AiOrigin,
    started_by: String,
    ledger: Option<std::path::PathBuf>,
    started: Mutex<Option<Started>>,
}

impl JobAi {
    /// The AI side of `job`, using the model `provider` and `model` name (the job's arguments).
    pub fn new(
        source: Arc<dyn BackendSource>,
        s: &Session,
        ctx: &CallContext,
        job: &JobReporter,
        label: String,
        provider: Option<&str>,
        model: Option<&str>,
    ) -> Result<JobAi, ProtoError> {
        let which = RewriteModel::parse(provider.unwrap_or(""))
            .map_err(|e| ProtoError::new(ErrorCode::InvalidArgument, e))?;
        Ok(JobAi {
            source,
            board: s.ai().clone(),
            which,
            model: model.map(str::to_string).filter(|m| !m.trim().is_empty()),
            label,
            job_id: job.id().0,
            origin: origin_of(ctx),
            started_by: ctx.author.id.clone(),
            ledger: s.project().ok().map(|p| p.dir().join(DB_FILE)),
            started: Mutex::new(None),
        })
    }

    /// The metered backend; made (and the work put on the AI board) on the first call.
    pub fn backend(&self) -> Result<Arc<dyn AssistBackend>, ProtoError> {
        let mut g = self.started.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(s) = g.as_ref() {
            return Ok(s.backend.clone());
        }
        let (inner, kind) = self.source.backend_for(self.which, self.model.as_deref())?;
        let info = inner.provider_info();
        let kind = kind.unwrap_or(match inner.info().kind {
            kraken_assist::BackendKind::TerminalAgent => AiProviderKind::TerminalAgent,
            kraken_assist::BackendKind::Api => AiProviderKind::Api,
        });
        let limits = self.source.limits();
        // Refuse before anything shows as started when today's budget is already used up.
        if let (Some(b), Some(d)) = (limits.daily_budget, self.source.daily()) {
            let today = d.today().cost_usd;
            if today >= b {
                return Err(limit_error(kraken_assist::daily_budget_message(b, today)));
            }
        }
        let board_id = self.board.start(AiWork {
            feature: AiFeature::Rewrite,
            label: self.label.clone(),
            job_id: Some(self.job_id.clone()),
            provider_kind: kind,
            provider: info.id.clone(),
            model: info.model.clone(),
            origin: self.origin,
            started_by: self.started_by.clone(),
        });
        let mut b =
            Meter::builder(MeterSpec::new(AiFeature::Rewrite, self.origin).job(&self.job_id))
                .pricing(self.source.pricing())
                .limits(limits)
                .daily(self.source.daily())
                .kind(kind);
        if let Some(p) = &self.ledger {
            b = b.sink(Arc::new(ProjectLedger::new(p)));
        }
        let board = self.board.clone();
        let id = board_id.clone();
        b = b.observer(Arc::new(move |rec, totals| {
            board.update(&id, *totals, Some(&rec.model));
        }));
        let meter = b.build();
        let backend = meter.wrap(inner);
        *g = Some(Started {
            backend: backend.clone(),
            meter,
            board_id,
        });
        Ok(backend)
    }

    /// Ends the work on the board with how the job ended. A job stopped by a limit says so.
    pub fn finish<T>(&self, outcome: &Result<T, ProtoError>) {
        let g = self.started.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(s) = g.as_ref() else {
            return;
        };
        let (status, message) = match outcome {
            Ok(_) => (AiJobStatus::Succeeded, None),
            Err(e) if s.meter.limit_message().is_some() || is_limit(e) => (
                AiJobStatus::Limited,
                s.meter.limit_message().or_else(|| Some(e.message.clone())),
            ),
            Err(e) if e.code == ErrorCode::Cancelled => (AiJobStatus::Cancelled, None),
            Err(e) => (AiJobStatus::Failed, Some(e.message.clone())),
        };
        self.board.update(&s.board_id, s.meter.totals(), None);
        self.board.finish(&s.board_id, status, message);
    }
}

/// The error a job ends with when a limit stopped it: `cancelled`, with `ai_limit` in the
/// details so clients can tell it from a person's Stop.
pub fn limit_error(message: String) -> ProtoError {
    ProtoError::new(ErrorCode::Cancelled, message)
        .with_details(serde_json::json!({ "ai_limit": true }))
}

/// True for an error made by [`limit_error`].
pub fn is_limit(e: &ProtoError) -> bool {
    e.details
        .as_ref()
        .and_then(|d| d.get("ai_limit"))
        .and_then(serde_json::Value::as_bool)
        == Some(true)
}
