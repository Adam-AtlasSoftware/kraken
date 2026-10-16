//! [`Backend`] over the command registry running inside the GUI process.

use std::any::Any;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_proto::ProtoError;
use kraken_registry::{
    ApprovalDecision, ApprovalRequest, ApprovalRequester, CallContext, CommandKind as RegKind,
    EngineFactory, JobId, JobSnapshot, JobStatus, Permission as RegPermission, Registry, Session,
    Surface,
};
use serde_json::Value;
use tokio::sync::broadcast;

use crate::backend::{
    ApprovalPrompt, Approver, Backend, BackendEvent, CallAs, CommandInfo, CommandKind, JobInfo,
    JobProgress, JobState, Permission,
};

/// Id the GUI's edits are logged under.
pub const GUI_USER: &str = "gui-user";

const JOB_POLL: Duration = Duration::from_millis(40);

/// Runs [`Registry::standard`] commands against a [`Session`] as the GUI user.
pub struct InProcessBackend {
    registry: Registry,
    session: Arc<Session>,
    events: broadcast::Sender<BackendEvent>,
    approver: Mutex<Option<Arc<dyn Approver>>>,
    _keepalive: Option<Box<dyn Any + Send + Sync>>,
}

impl InProcessBackend {
    /// A backend with a fresh, project-less session that builds engines with `factory`.
    pub fn new(factory: Arc<dyn EngineFactory>) -> Self {
        Self::with_session(Session::new(factory))
    }

    /// A backend over an existing session.
    pub fn with_session(session: Session) -> Self {
        let (events, _) = broadcast::channel(256);
        InProcessBackend {
            registry: Registry::standard(),
            session: Arc::new(session),
            events,
            approver: Mutex::new(None),
            _keepalive: None,
        }
    }

    /// Keeps `value` alive as long as the backend (a temp directory, for instance).
    pub fn with_keepalive(mut self, value: Box<dyn Any + Send + Sync>) -> Self {
        self._keepalive = Some(value);
        self
    }

    /// Sets who is asked before a dangerous command runs; without one such commands are refused.
    pub fn set_approver(&self, approver: Arc<dyn Approver>) {
        *self.approver.lock().unwrap_or_else(PoisonError::into_inner) = Some(approver);
    }

    /// The underlying session, for embedding code and tests.
    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }

    fn watch_job(&self, id: String) {
        let session = self.session.clone();
        let events = self.events.clone();
        tokio::spawn(async move {
            let mut last: Option<JobInfo> = None;
            while let Ok(snap) = session.jobs().snapshot(&JobId(id.clone())) {
                let terminal = snap.status.is_terminal();
                let info = job_info(snap);
                if last.as_ref() != Some(&info) {
                    let _ = events.send(BackendEvent::Job(info.clone()));
                    last = Some(info);
                }
                if terminal {
                    break;
                }
                tokio::time::sleep(JOB_POLL).await;
            }
        });
    }
}

struct Adapter(Arc<dyn Approver>);

#[async_trait]
impl ApprovalRequester for Adapter {
    async fn request(&self, req: ApprovalRequest) -> ApprovalDecision {
        let command = req.command.clone();
        let allowed = self
            .0
            .approve(ApprovalPrompt {
                command: req.command,
                summary: req.summary,
                args: req.args,
            })
            .await;
        if allowed {
            ApprovalDecision::Allow
        } else {
            ApprovalDecision::Deny {
                reason: format!("`{command}` was not approved"),
            }
        }
    }
}

fn job_info(s: JobSnapshot) -> JobInfo {
    JobInfo {
        job_id: s.id.0,
        command: s.command,
        status: match s.status {
            JobStatus::Running => JobState::Running,
            JobStatus::Succeeded => JobState::Succeeded,
            JobStatus::Failed => JobState::Failed,
            JobStatus::Cancelled => JobState::Cancelled,
        },
        progress: s.progress.map(|p| JobProgress {
            phase: p.phase,
            done: p.done,
            total: p.total,
            message: p.message,
        }),
        result: s.result,
        error: s.error,
    }
}

#[async_trait]
impl Backend for InProcessBackend {
    async fn call_as(&self, who: &CallAs, command: &str, args: Value) -> Result<Value, ProtoError> {
        let ctx = match (&who.run_id, who.agent) {
            (Some(run), true) => CallContext::agent(who.id.clone(), run.clone(), Surface::Gui),
            (None, true) => CallContext::agent(who.id.clone(), who.id.clone(), Surface::Gui),
            (_, false) => CallContext::user(who.id.clone(), Surface::Gui),
        };
        self.registry
            .call_json(command, &self.session, &ctx, args)
            .await
    }

    async fn call(&self, command: &str, args: Value) -> Result<Value, ProtoError> {
        let mut ctx = CallContext::user(GUI_USER, Surface::Gui);
        let approver = self
            .approver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(approver) = approver {
            ctx = ctx.with_approval(Arc::new(Adapter(approver)));
        }
        let out = self
            .registry
            .call_json(command, &self.session, &ctx, args)
            .await?;
        if command == "analyze"
            && let Some(id) = out.get("job_id").and_then(Value::as_str)
        {
            self.watch_job(id.to_string());
        }
        Ok(out)
    }

    fn commands(&self) -> Vec<CommandInfo> {
        self.registry
            .iter()
            .map(|e| {
                let s = e.spec();
                CommandInfo {
                    name: s.name.clone(),
                    summary: s.summary.clone(),
                    kind: match s.kind {
                        RegKind::Query => CommandKind::Query,
                        RegKind::Mutation => CommandKind::Mutation,
                        RegKind::Job => CommandKind::Job,
                        RegKind::Stream => CommandKind::Stream,
                    },
                    permission: match s.permission {
                        RegPermission::Safe => Permission::Safe,
                        RegPermission::Mutating => Permission::Mutating,
                        RegPermission::Dangerous => Permission::Dangerous,
                    },
                }
            })
            .collect()
    }

    fn events(&self) -> broadcast::Receiver<BackendEvent> {
        self.events.subscribe()
    }
}
