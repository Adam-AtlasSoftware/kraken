//! KRAKEN engine capability traits.
//!
//! An engine is a set of capability traits ([`Loader`], [`Analyzer`], [`Decompiler`],
//! [`TypeStore`], [`FunctionLister`], [`Mutator`]) bundled behind [`Engine`]. All traits are
//! dyn-compatible (via `async-trait`) so the registry can select engines at runtime as
//! `Arc<dyn Engine>`. Data is owned, every async method takes a
//! [`CancellationToken`], and errors are [`kraken_proto::ProtoError`].
//!
//! Long operations return a job: [`Analyzer::analyze`] yields an [`AnalysisJob`] with a progress
//! stream and a completion future, running the staged passes `load`, `core`, `expensive`.
//!
//! With the `testing` feature, `testing::run_contract_suite` checks any engine against a
//! fixture's expectations.

pub mod caps;
pub mod job;
pub mod traits;
pub mod types;

#[cfg(feature = "testing")]
pub mod testing;

pub use caps::{Cap, Engine, EngineCaps, SharedEngine};
pub use job::{AnalysisJob, ProgressSender};
pub use tokio_util::sync::CancellationToken;
pub use traits::{
    Analyzer, Decompiler, EngineResult, FunctionLister, Loader, Mutator, TypeStore, unsupported,
};
pub use types::{
    AnalysisSummary, AnalyzeRequest, EngineRejected, LoaderSpec, ProgramInfo, Progress, Stage,
    Watermark, type_def_name,
};
