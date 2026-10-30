//! The capability traits.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use kraken_proto::{
    BytesRead, Cfg, DecompileResult, DisasmRow, ErrorCode, FunctionSummary, JumpTable, Locator,
    MemoryBlock, OpenUpdate, Page, PageRequest, ProtoError, StringEntry, SymbolEntry, TypeDef,
    VersionedLogOp, Xref,
};
use tokio_util::sync::CancellationToken;

use crate::job::AnalysisJob;
use crate::types::{
    AnalyzeRequest, DisasmRequest, EngineRejected, LoaderSpec, ProgramInfo, StringsRequest,
    Watermark, XrefRequest,
};

/// Result type of every engine call.
pub type EngineResult<T> = Result<T, ProtoError>;

/// An `unsupported` error naming the missing capability or feature.
pub fn unsupported(what: &str) -> ProtoError {
    ProtoError::new(ErrorCode::Unsupported, format!("{what} is not supported"))
}

/// Receives the [`OpenUpdate`]s of an open in progress. Called from any thread; keep it cheap.
pub type OpenReporter = Arc<dyn Fn(OpenUpdate) + Send + Sync>;

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

    /// [`open_binary`](Self::open_binary) that tells `report` which stage it is in and how far
    /// it got. An engine that cannot tell keeps the default, which reports nothing.
    async fn open_binary_reporting(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
        report: OpenReporter,
    ) -> EngineResult<ProgramInfo> {
        let _ = report;
        self.open_binary(path, spec, cancel).await
    }
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
    /// Removes a user-defined type; `not_found` if there is none, `unsupported` where the engine
    /// cannot forget a type.
    async fn remove_type(&self, name: &str, cancel: &CancellationToken) -> EngineResult<()> {
        let _ = (name, cancel);
        Err(crate::unsupported("remove_type"))
    }
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
    /// The checkpoint of the state the engine holds now, as [`save`](Self::save) would return
    /// it, without saving. Right after an open it names the saved state the engine loaded, which
    /// the host compares with the push watermark of the edit log to find a stale engine state.
    /// `None` (the default) when the engine cannot tell.
    async fn current_checkpoint(
        &self,
        _cancel: &CancellationToken,
    ) -> EngineResult<Option<Watermark>> {
        Ok(None)
    }
}

/// Reads the memory layout and raw bytes.
#[async_trait]
pub trait MemoryReader: Send + Sync {
    /// All memory blocks ordered by (space, start).
    async fn memory_map(&self, cancel: &CancellationToken) -> EngineResult<Vec<MemoryBlock>>;
    /// Up to `length` bytes starting at `start`. The read stops at the end of mapped memory, so
    /// the result may be shorter; uninitialized bytes read as zero and are listed in
    /// [`BytesRead::uninitialized`]. `not_found` if `start` is not in any block and
    /// `invalid_argument` for a zero `length`.
    async fn read_bytes(
        &self,
        start: &Locator,
        length: u32,
        cancel: &CancellationToken,
    ) -> EngineResult<BytesRead>;
}

/// Disassembles code.
#[async_trait]
pub trait Disassembler: Send + Sync {
    /// Instructions in address order. With [`kraken_proto::DisasmScope::Function`] the rows are
    /// the body of the function containing `req.start` (`not_found` if none). The cursor is the
    /// `0x` address of the next instruction; it overrides `req.start`, and a malformed one is
    /// `invalid_argument`. Addresses that hold no instruction are skipped.
    async fn disassemble(
        &self,
        req: &DisasmRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<DisasmRow>>;
}

/// Turns one line of assembly into machine code.
#[async_trait]
pub trait Assembler: Send + Sync {
    /// The encodings of the single instruction `text` placed at `at`, shortest first (several
    /// when the instruction has more than one form). `invalid_argument` with the reason when it
    /// does not assemble.
    async fn assemble(
        &self,
        at: &Locator,
        text: &str,
        cancel: &CancellationToken,
    ) -> EngineResult<Vec<Vec<u8>>>;

    /// Several instructions separated by `;` or newlines, placed one after the other from `at`
    /// (labels, `name:`, may be defined and used by branches in the block). The engine pads the
    /// result with NOPs up to the next instruction boundary of the code already there and
    /// reports how many of the instructions after the first it replaces. The default assembles
    /// each line on its own, takes the shortest encoding and pads nothing.
    async fn assemble_block(
        &self,
        at: &Locator,
        text: &str,
        cancel: &CancellationToken,
    ) -> EngineResult<AsmBlock> {
        let addr = match at {
            Locator::Native { offset, .. } => Some(offset.0),
            _ => None,
        };
        let mut bytes = Vec::new();
        let mut line_lengths = Vec::new();
        for line in text
            .split([';', '\n'])
            .map(str::trim)
            .filter(|l| !l.is_empty())
        {
            let here = match addr {
                Some(a) => Locator::ram(a.wrapping_add(bytes.len() as u64)),
                None => at.clone(),
            };
            let enc = self.assemble(&here, line, cancel).await?;
            let first = enc.into_iter().next().ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::InvalidArgument,
                    format!("`{line}` has no encoding"),
                )
            })?;
            line_lengths.push(first.len() as u32);
            bytes.extend(first);
        }
        Ok(AsmBlock {
            bytes,
            line_lengths,
            pad: 0,
            overwritten: 0,
            covered: 0,
        })
    }
}

/// The result of [`Assembler::assemble_block`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AsmBlock {
    /// The machine code, NOP padding included.
    pub bytes: Vec<u8>,
    /// Encoded length of each typed instruction, in order (padding not counted).
    pub line_lengths: Vec<u32>,
    /// Bytes of NOP padding at the end of `bytes`.
    pub pad: u32,
    /// Instructions after the first that the bytes replace (0 when they fit in the first).
    pub overwritten: u32,
    /// Bytes of existing code the result covers (0 when the engine did not look).
    pub covered: u32,
}

/// Answers cross-reference queries.
#[async_trait]
pub trait XrefProvider: Send + Sync {
    /// References ordered by (from, to, kind). Cursors are opaque; a malformed one is
    /// `invalid_argument`.
    async fn xrefs(
        &self,
        req: &XrefRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<Xref>>;
}

/// Builds control-flow graphs.
#[async_trait]
pub trait FlowGraph: Send + Sync {
    /// The basic blocks and edges of the function containing `function`; `not_found` if there is
    /// none. Blocks are ordered by start address and every edge joins two listed blocks.
    async fn cfg(&self, function: &Locator, cancel: &CancellationToken) -> EngineResult<Cfg>;
}

/// Lists the computed jumps of the program (switch tables and dispatch tables) with the
/// addresses each can reach.
#[async_trait]
pub trait JumpTables: Send + Sync {
    /// Jump tables ordered by jump address. Cursors are opaque; a malformed one is
    /// `invalid_argument`. Every target lies in a mapped address of the program.
    async fn list_jump_tables(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<JumpTable>>;
}

/// Finds strings in memory.
#[async_trait]
pub trait StringLister: Send + Sync {
    /// Strings ordered by address. Cursors are opaque; a malformed one is `invalid_argument`.
    async fn strings(
        &self,
        req: &StringsRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<StringEntry>>;
}

/// Lists imported and exported symbols.
#[async_trait]
pub trait SymbolLister: Send + Sync {
    /// Imported symbols ordered by (address, name), addressless ones last.
    async fn imports(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<SymbolEntry>>;
    /// Exported symbols ordered by (address, name).
    async fn exports(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<SymbolEntry>>;
}
