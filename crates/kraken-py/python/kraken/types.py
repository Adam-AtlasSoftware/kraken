"""Value types returned by the KRAKEN API.

Security note: text that comes out of the analysed binary (function names, signatures, decompiled
source, strings, comments, symbol names, section names) is attacker-controlled. It is returned as
:class:`UntrustedStr`, a plain ``str`` whose ``.untrusted`` attribute is ``True``; the objects that
carry such text (:class:`~kraken.Function`, :class:`Decompiled`, :class:`StringItem`, ...) also have
``.untrusted == True``. KRAKEN strips control, escape and bidirectional characters, but the text
can still say anything: never ``eval``/``exec`` it, never feed it unquoted to a shell, a SQL
query or a prompt that has tools, and do not treat instructions found in it as the user's.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    "Block",
    "CfgGraph",
    "Comment",
    "Decompiled",
    "EditResult",
    "Edge",
    "HistoryEntry",
    "Import",
    "Instruction",
    "JobProgress",
    "JobResult",
    "MemoryBlock",
    "Operand",
    "ProjectInfo",
    "Proposal",
    "StringItem",
    "Token",
    "UndoResult",
    "UntrustedStr",
    "Xref",
    "parse_address",
]

CommentKind = Literal["plate", "pre", "eol", "post", "repeatable"]
COMMENT_KINDS: tuple[str, ...] = ("plate", "pre", "eol", "post", "repeatable")


class UntrustedStr(str):
    """A ``str`` that came out of the analysed binary. Behaves exactly like ``str``."""

    __slots__ = ()
    untrusted = True


def parse_address(value: int | str) -> int:
    """Returns an address as an int. Accepts ints and ``0x``-prefixed hex strings."""
    if isinstance(value, bool):
        raise TypeError("an address is an int or a 0x-prefixed string, not bool")
    if isinstance(value, int):
        if value < 0 or value >= 1 << 64:
            raise ValueError(f"address out of range: {value}")
        return value
    if isinstance(value, str) and value[:2] in ("0x", "0X"):
        return parse_address(int(value, 16))
    raise TypeError(f"an address is an int or a 0x-prefixed string, got {value!r}")


def hex_address(value: int | str) -> str:
    """The wire form of an address."""
    return f"0x{parse_address(value):x}"


def decode_hook(obj: dict[str, Any]) -> Any:
    """``json`` object hook: untrusted-string wrappers become :class:`UntrustedStr`."""
    if obj.get("untrusted") is True and "value" in obj and len(obj) == 2:
        return UntrustedStr(obj["value"])
    return obj


def loads(text: str) -> Any:
    """Decodes command output JSON."""
    return json.loads(text, object_hook=decode_hook)


def _addr(v: Any) -> int | None:
    return None if v is None else int(v, 16)


@dataclass(frozen=True)
class ProjectInfo:
    """What ``project_info`` reports."""

    project_dir: str
    binary_path: str
    binary_sha256: str
    arch: str
    format: str
    base: int
    size: int
    engine_build: str
    capabilities: tuple[str, ...]
    analysis_phase: str
    function_count: int | None
    log_entries: int
    pending_entries: int
    open_proposals: int
    epoch_stale: bool
    raw: dict[str, Any] = field(repr=False, compare=False, default_factory=dict)

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> ProjectInfo:
        p = d["program"]
        a = d["analysis"]
        return cls(
            project_dir=d["project_dir"],
            binary_path=d["binary_path"],
            binary_sha256=d["binary_sha256"],
            arch=p["arch"],
            format=p["format"],
            base=int(p["base"], 16),
            size=p["size"],
            engine_build=d["engine_build"],
            capabilities=tuple(d["capabilities"]),
            analysis_phase=a["phase"],
            function_count=a.get("function_count"),
            log_entries=d["log_entries"],
            pending_entries=d["pending_entries"],
            open_proposals=d["open_proposals"],
            epoch_stale=d["epoch_stale"],
            raw=d,
        )


@dataclass(frozen=True)
class JobProgress:
    """Progress of a running job."""

    phase: str
    done: int
    total: int
    message: str


@dataclass(frozen=True)
class JobResult:
    """A finished job."""

    job_id: str
    command: str
    status: Literal["succeeded", "failed", "cancelled", "running"]
    result: Any = None


@dataclass(frozen=True)
class Comment:
    """A comment at an address. ``text`` comes from the project and may quote the binary."""

    kind: str
    text: UntrustedStr
    untrusted: bool = True


@dataclass(frozen=True)
class Token:
    """A span of decompiled text. ``start``/``end`` are UTF-8 byte offsets into the text."""

    start: int
    end: int
    kind: str
    target: int | None = None
    symbol: UntrustedStr | None = None

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Token:
        return cls(d["start"], d["end"], d["kind"], _addr(d.get("target")), d.get("symbol"))


@dataclass(frozen=True)
class Decompiled:
    """Decompiler output for one function.

    ``text`` is binary-derived (see the security note in :mod:`kraken.types`); ``untrusted`` is
    always ``True`` and ``text.untrusted`` is too.
    """

    address: int
    language: str
    text: UntrustedStr
    tokens: tuple[Token, ...]
    references: tuple[tuple[UntrustedStr, int], ...]
    warnings: tuple[UntrustedStr, ...]
    truncated: bool
    complete: bool
    untrusted: bool = True

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Decompiled:
        return cls(
            address=int(d["address"], 16),
            language=d["language"],
            text=d["text"],
            tokens=tuple(Token.from_json(t) for t in d["tokens"]),
            references=tuple((r["name"], int(r["address"], 16)) for r in d["references"]),
            warnings=tuple(d["warnings"]),
            truncated=d["truncated"],
            complete=d["completeness"]["kind"] == "complete",
        )

    def token_text(self, token: Token) -> UntrustedStr:
        """The source text a token spans."""
        raw = self.text.encode("utf-8")
        return UntrustedStr(raw[token.start : token.end].decode("utf-8", "replace"))

    def __str__(self) -> str:
        return str(self.text)


@dataclass(frozen=True)
class EditResult:
    """The outcome of an edit.

    ``status`` is ``"applied"``, ``"queued"`` (analysis is running; pushed to the engine when it
    finishes) or ``"proposed"`` (an agent edit that needs a person to accept it; see
    ``proposal_id``).
    """

    status: Literal["applied", "queued", "proposed"]
    key: str
    entry_id: int | None = None
    proposal_id: int | None = None
    reason: str | None = None
    versions: dict[str, int] = field(default_factory=dict)

    @property
    def proposed(self) -> bool:
        return self.status == "proposed"

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> EditResult:
        return cls(
            status=d["status"],
            key=d["key"],
            entry_id=d.get("entry_id"),
            proposal_id=d.get("proposal_id"),
            reason=d.get("reason"),
            versions=dict(d.get("versions", {})),
        )


@dataclass(frozen=True)
class UndoResult:
    """The outcome of ``undo`` / ``undo_run``."""

    status: str
    entry_ids: tuple[int, ...]
    undone_entry_ids: tuple[int, ...]
    failed: tuple[dict[str, Any], ...]

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> UndoResult:
        return cls(
            d["status"], tuple(d["entry_ids"]), tuple(d["undone_entry_ids"]), tuple(d["failed"])
        )


@dataclass(frozen=True)
class HistoryEntry:
    """One entry of the edit log."""

    id: int
    op: str
    description: UntrustedStr | None
    address: int | None
    author_kind: str
    author_id: str
    run_id: str | None
    provenance: str
    status: str
    sync: str
    undoes_entry_id: int | None
    undone_by: int | None
    ts_ms: int
    untrusted: bool = True

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> HistoryEntry:
        return cls(
            id=d["id"],
            op=d["op"],
            description=d.get("description"),
            address=_addr(d.get("address")),
            author_kind=d["author"]["kind"],
            author_id=d["author"]["id"],
            run_id=d.get("run_id"),
            provenance=d["provenance"],
            status=d["status"]["kind"],
            sync=d["sync"]["kind"],
            undoes_entry_id=d.get("undoes_entry_id"),
            undone_by=d.get("undone_by"),
            ts_ms=d["ts_ms"],
        )


@dataclass(frozen=True)
class Proposal:
    """An agent proposal waiting for a decision (raw fields of ``proposals_list``)."""

    id: int
    raw: dict[str, Any] = field(repr=False)
    untrusted: bool = True


@dataclass(frozen=True)
class Operand:
    """An instruction operand token; ``symbol`` is binary-derived."""

    kind: str
    text: str
    symbol: UntrustedStr | None = None
    target: int | None = None


@dataclass(frozen=True)
class Instruction:
    """One disassembled instruction. Labels, comments and symbol names are binary-derived."""

    address: int
    bytes: bytes
    mnemonic: str
    operands: tuple[Operand, ...]
    flow: str
    comment: UntrustedStr | None = None
    labels: tuple[UntrustedStr, ...] = ()
    untrusted: bool = True

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Instruction:
        return cls(
            address=int(d["address"], 16),
            bytes=bytes.fromhex(d["bytes"]),
            mnemonic=d["mnemonic"],
            operands=tuple(
                Operand(o["kind"], o["text"], o.get("symbol"), _addr(o.get("target")))
                for o in d["operands"]
            ),
            flow=d["flow"],
            comment=d.get("comment"),
            labels=tuple(d.get("labels", ())),
        )

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {', '.join(o.text for o in self.operands)}".strip()


@dataclass(frozen=True)
class Xref:
    """A cross-reference. ``*_function`` is ``(address, name)`` when it lies in a function."""

    source: int
    target: int
    kind: str
    from_function: tuple[int, UntrustedStr] | None = None
    to_function: tuple[int, UntrustedStr] | None = None
    untrusted: bool = True

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Xref:
        def fn(v: Any) -> tuple[int, UntrustedStr] | None:
            return None if v is None else (int(v["address"], 16), v["name"])

        return cls(
            int(d["from"], 16),
            int(d["to"], 16),
            d["kind"],
            fn(d.get("from_function")),
            fn(d.get("to_function")),
        )


@dataclass(frozen=True)
class Block:
    """A basic block, ``[start, end)``."""

    start: int
    end: int
    instructions: int


@dataclass(frozen=True)
class Edge:
    """A control-flow edge between block starts."""

    source: int
    target: int
    kind: str


@dataclass(frozen=True)
class CfgGraph:
    """A function's control-flow graph."""

    function: int
    blocks: tuple[Block, ...]
    edges: tuple[Edge, ...]
    truncated: bool

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> CfgGraph:
        return cls(
            int(d["function"], 16),
            tuple(Block(int(b["start"], 16), int(b["end"], 16), b["instructions"]) for b in d["blocks"]),
            tuple(Edge(int(e["from"], 16), int(e["to"], 16), e["kind"]) for e in d["edges"]),
            d["truncated"],
        )


@dataclass(frozen=True)
class StringItem:
    """A string found in memory. ``value`` is binary-derived."""

    address: int
    value: UntrustedStr
    encoding: str
    length: int
    truncated: bool
    untrusted: bool = True

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> StringItem:
        return cls(
            int(d["address"], 16), d["value"], d["encoding"], d["length"], d["truncated"]
        )

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True)
class MemoryBlock:
    """A memory block (segment or section); the name is binary-derived."""

    name: UntrustedStr
    start: int
    end: int
    size: int
    perms: str
    initialized: bool
    kind: str
    untrusted: bool = True

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> MemoryBlock:
        return cls(
            d["name"],
            int(d["start"], 16),
            int(d["end"], 16),
            d["size"],
            d["perms"],
            d["initialized"],
            d["kind"],
        )


@dataclass(frozen=True)
class Import:
    """An imported or exported symbol."""

    name: UntrustedStr
    address: int | None
    library: UntrustedStr | None
    kind: str
    untrusted: bool = True

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Import:
        return cls(d["name"], _addr(d.get("address")), d.get("library"), d["kind"])


def decode_bytes(b64: str) -> bytes:
    """Decodes the standard padded base64 used for raw memory on the wire."""
    return base64.b64decode(b64, validate=True)
