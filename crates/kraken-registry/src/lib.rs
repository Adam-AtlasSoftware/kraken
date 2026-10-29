//! KRAKEN command registry.
//!
//! Every operation is a type implementing [`Command`]; a [`Registry`] holds type-erased entries
//! exposing the command spec, JSON Schemas for arguments and output, and
//! [`Entry::call_json`]. CLI and MCP surfaces build themselves dynamically from the registry.
//!
//! A [`Session`] owns the engine, the project database (`kraken-model`, behind a mutex used via
//! `spawn_blocking`), the in-memory job table and the mutation pipeline (validate, append to the
//! log, push to the engine, mark pushed or engine-rejected).
//!
//! Binary-derived strings in outputs are sanitised and wrapped as
//! [`Untrusted<String>`](kraken_proto::Untrusted).

pub mod activity;
pub mod ai;
pub mod command;
pub mod commands;
pub mod context;
pub mod docs;
pub mod jobs;
mod mutate;
mod opening;
pub mod patchfile;
pub mod patchops;
pub mod project_lock;
pub mod session;
pub mod trust;
pub mod validate;
pub mod views;
pub mod views_data;

pub use ai::{AiBoard, AiWork};
pub use command::{Command, CommandKind, CommandSpec, Entry, Permission, Registry, Scope};
pub use context::{
    ApprovalDecision, ApprovalRequest, ApprovalRequester, AutoApprove, CallContext, DenyApprover,
    OpenProgressSink, Surface,
};
pub use jobs::{
    EngineActivity, JobId, JobProgress, JobReporter, JobSnapshot, JobStatus, JobStep, JobTable,
    TrackedJob,
};
pub use opening::OpenOptions;
pub use session::{
    AnalysisPhase, EngineChoice, EngineFactory, EngineKind, EngineSelection, EngineStatus, Epoch,
    Project, ProjectMeta, ReplayReport, ResyncReport, Session, SessionConfig,
};
