//! The capability traits.

use std::path::Path;

use async_trait::async_trait;
use kraken_proto::{
    DecompileResult, ErrorCode, FunctionSummary, Locator, Page, PageRequest, ProtoError, TypeDef,
    VersionedLogOp,
};
use tokio_util::sync::CancellationToken;

use crate::job::AnalysisJob;
use crate::types::{AnalyzeRequest, EngineRejected, LoaderSpec, ProgramInfo, Watermark};

/// Result type of every engine call.
pub type EngineResult<T> = Result<T, ProtoError>;

/// An `unsupported` error naming the missing capability or feature.
pub fn unsupported(what: &str) -> ProtoError {
    ProtoError::new(ErrorCode::Unsupported, format!("{what} is not supported"))
}

/// Opens binaries.
#[async_trait]
pub trait Loader: Send + Sync {
    /// Opens `path` and returns facts about it. An unknown `spec.format` is `unsupported`.
    async fn open_binary(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
    ) -> EngineResult<ProgramInfo>;
}

/// Runs analysis as a job.
#[async_trait]
pub trait Analyzer: Send + Sync {
    /// Starts the staged passes `load`, `core`, `expensive` (skipping stages before
    /// `req.resume_from`). Cancelling `cancel` ends the job with a `cancelled` error.
    async fn analyze(
        &self,
        req: AnalyzeRequest,
        cancel: CancellationToken,
    ) -> EngineResult<AnalysisJob>;
}

/// Decompiles functions.
#[async_trait]
pub trait Decompiler: Send + Sync {
    /// Decompiles the function at `locator`; `not_found` if there is none. Token spans must pass
    /// [`DecompileResult::validate_tokens`].
    async fn decompile(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<DecompileResult>;
}

/// Reads and defines types in the neutral model.
#[async_trait]
pub trait TypeStore: Send + Sync {
    /// The type named `name`; `not_found` if undefined.
    async fn get_type(&self, name: &str, cancel: &CancellationToken) -> EngineResult<TypeDef>;
    /// Defines or replaces a named type; anonymous prototypes are `invalid_argument`.
    async fn define_type(&self, def: TypeDef, cancel: &CancellationToken) -> EngineResult<()>;
    /// Types ordered by name, paginated.
    async fn list_types(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<TypeDef>>;
}

/// Lists functions.
#[async_trait]
pub trait FunctionLister: Send + Sync {
    /// Functions ordered by (space, offset), paginated. Cursors are opaque; a malformed cursor is
    /// `invalid_argument`. Concatenating pages equals one full listing.
    async fn list_functions(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<FunctionSummary>>;
    /// The function whose entry is `locator`; `not_found` if there is none.
    async fn get_function(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<FunctionSummary>;
}

/// Applies edit-log operations.
#[async_trait]
pub trait Mutator: Send + Sync {
    /// Applies one op. Idempotent: re-applying an op already in effect is `Ok`. Reserved anchors
    /// and newer schema versions are rejected with code `unsupported`.
    async fn apply(
        &self,
        op: &VersionedLogOp,
        cancel: &CancellationToken,
    ) -> Result<(), EngineRejected>;
    /// Persists applied ops and returns the checkpoint that covers them.
    async fn save(&self, cancel: &CancellationToken) -> EngineResult<Watermark>;
}
