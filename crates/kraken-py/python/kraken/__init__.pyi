"""Public type surface of the `kraken` package (the implementation is typed inline; this stub
pins what is public and is checked against the runtime `__all__` by the test-suite)."""

from os import PathLike

from .errors import (
    AnalysisIncompleteError as AnalysisIncompleteError,
    CancelledError as CancelledError,
    EngineRejectedError as EngineRejectedError,
    InternalError as InternalError,
    InvalidArgumentError as InvalidArgumentError,
    KrakenError as KrakenError,
    KrakenTimeoutError as KrakenTimeoutError,
    NotFoundError as NotFoundError,
    RejectedByHumanError as RejectedByHumanError,
    StaleReadError as StaleReadError,
    UnsupportedError as UnsupportedError,
)
from .project import (
    CommandSpec as CommandSpec,
    Connection as Connection,
    Function as Function,
    Job as Job,
    KrakenWarning as KrakenWarning,
    Project as Project,
)
from .types import (
    CfgGraph as CfgGraph,
    Comment as Comment,
    Decompiled as Decompiled,
    EditResult as EditResult,
    HistoryEntry as HistoryEntry,
    Import as Import,
    Instruction as Instruction,
    JobProgress as JobProgress,
    JobResult as JobResult,
    MemoryBlock as MemoryBlock,
    ProjectInfo as ProjectInfo,
    Proposal as Proposal,
    StringItem as StringItem,
    Token as Token,
    UndoResult as UndoResult,
    UntrustedStr as UntrustedStr,
    Xref as Xref,
)

__version__: str

def connect(
    daemon: bool | None = None,
    *,
    runtime_dir: str | PathLike[str] | None = None,
    krakend: str | PathLike[str] | None = None,
) -> Connection: ...
def default_connection() -> Connection: ...
def open(
    project_dir: str | PathLike[str],
    *,
    agent: str | None = None,
    run_id: str | None = None,
    connection: Connection | None = None,
) -> Project: ...
def create(
    project_dir: str | PathLike[str],
    binary: str | PathLike[str],
    *,
    agent: str | None = None,
    run_id: str | None = None,
    connection: Connection | None = None,
    engine: str | None = None,
    loader: str | None = None,
    language: str | None = None,
    compiler: str | None = None,
    base: int | str | None = None,
    offset: int | str | None = None,
    length: int | str | None = None,
    entry: int | str | None = None,
) -> Project: ...
