"""Connections, projects and functions: the scripting API."""

from __future__ import annotations

import atexit
import json
import os
import re
import threading
import time
import warnings
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Literal

from . import _native
from .errors import (
    CancelledError,
    InvalidArgumentError,
    KrakenError,
    KrakenTimeoutError,
    NotFoundError,
    from_proto,
)
from .types import (
    COMMENT_KINDS,
    CfgGraph,
    Comment,
    Decompiled,
    EditResult,
    HistoryEntry,
    Import,
    Instruction,
    JobProgress,
    JobResult,
    MemoryBlock,
    ProjectInfo,
    Proposal,
    StringItem,
    UndoResult,
    UntrustedStr,
    Xref,
    decode_bytes,
    hex_address,
    loads,
    parse_address,
)

__all__ = [
    "CommandSpec",
    "Connection",
    "Debugger",
    "Function",
    "Job",
    "KrakenWarning",
    "Project",
    "connect",
    "create",
    "default_connection",
    "open",
]

Address = int | str
ProgressCallback = Callable[[JobProgress], None]
# Fields a newer daemon may add to a progress report are left out rather than refused.
_PROGRESS_FIELDS = frozenset(JobProgress.__dataclass_fields__)


class KrakenWarning(UserWarning):
    """A non-fatal notice (a stale engine cache, a daemon from another build, a fallback)."""


@dataclass(frozen=True)
class CommandSpec:
    """A registry command with its JSON Schemas (see :meth:`Project.call`)."""

    name: str
    summary: str
    doc: str
    kind: str
    permission: str
    args_schema: dict[str, Any]
    output_schema: dict[str, Any]


def _json_default(o: Any) -> Any:
    if isinstance(o, os.PathLike):
        return os.fspath(o)
    if isinstance(o, (bytes, bytearray)):
        raise TypeError("bytes are not valid command arguments")
    raise TypeError(f"{type(o).__name__} is not JSON serialisable")


class Connection:
    """A connection to ``krakend``, or to the in-process engine.

    Create one with :func:`kraken.connect`. A connection can open any number of projects. Use it as
    a context manager, or call :meth:`close`, to stop engines started in this process; a daemon
    keeps running for other clients and later scripts.
    """

    def __init__(self, native: Any) -> None:
        self._n = native
        self._commands: dict[str, CommandSpec] | None = None
        self._lock = threading.Lock()
        for w in native.warnings:
            warnings.warn(w, KrakenWarning, stacklevel=3)

    @property
    def mode(self) -> Literal["daemon", "local"]:
        """``"daemon"`` or ``"local"`` (in-process)."""
        return self._n.mode  # type: ignore[no-any-return]

    @property
    def daemon_pid(self) -> int | None:
        """The daemon's process id, or ``None`` when running in-process."""
        return self._n.daemon_pid  # type: ignore[no-any-return]

    def commands(self) -> dict[str, CommandSpec]:
        """Every registry command by name, with its argument and output JSON Schemas."""
        with self._lock:
            if self._commands is None:
                items = json.loads(self._n.commands_json())
                self._commands = {c["name"]: CommandSpec(**c) for c in items}
            return dict(self._commands)

    def open(
        self, project_dir: str | os.PathLike[str], *, agent: str | None = None, run_id: str | None = None
    ) -> Project:
        """Opens an existing project. With ``agent`` the edits follow agent policy."""
        path = os.path.abspath(os.fspath(project_dir))
        project = Project(self, path, agent=agent, run_id=run_id)
        project.call("project_open", project_dir=path)
        return project

    def create(
        self,
        project_dir: str | os.PathLike[str],
        binary: str | os.PathLike[str],
        *,
        agent: str | None = None,
        run_id: str | None = None,
        engine: str | None = None,
        loader: str | None = None,
        language: str | None = None,
        compiler: str | None = None,
        base: int | str | None = None,
        offset: int | str | None = None,
        length: int | str | None = None,
        entry: int | str | None = None,
    ) -> Project:
        """Creates a project for ``binary`` in ``project_dir`` (analysis is a separate step).

        For firmware or a ROM with no header pass ``loader="raw"`` and ``language`` (``"cortex-m"``,
        ``"arm"``, ``"aarch64"``, ``"x86"``, ``"x86-64"``, ``"riscv32"`` or a Sleigh language id),
        with ``base`` (where the image lives), and optionally ``offset``, ``length`` and
        ``entry``. Numbers may be ints or ``"0x..."`` strings. ``engine`` is ``"ghidra"``,
        ``"native"`` or ``"auto"``.
        """
        path = os.path.abspath(os.fspath(project_dir))
        project = Project(self, path, agent=agent, run_id=run_id)
        options: dict[str, object] = {}
        for key, value in (
            ("engine", engine),
            ("loader", loader),
            ("language", language),
            ("compiler", compiler),
        ):
            if value is not None:
                options[key] = value
        for key, number in (("base", base), ("offset", offset), ("length", length), ("entry", entry)):
            if number is not None:
                options[key] = hex(number) if isinstance(number, int) else number
        project.call(
            "project_create",
            project_dir=path,
            binary=os.path.abspath(os.fspath(binary)),
            **options,
        )
        return project

    def stop_daemon(self) -> bool:
        """Asks ``krakend`` to exit (other clients lose their connection); ``False`` in-process."""
        return self._n.stop_daemon()  # type: ignore[no-any-return]

    def close(self) -> None:
        """Stops engines started by this process."""
        self._n.close()

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        pid = f", daemon_pid={self.daemon_pid}" if self.daemon_pid else ""
        return f"<kraken.Connection mode={self.mode!r}{pid}>"


class Job:
    """A running (or finished) background job, such as an analysis."""

    def __init__(self, project: Project, job_id: str, command: str) -> None:
        self.project = project
        self.job_id = job_id
        self.command = command

    def status(self) -> dict[str, Any]:
        """The raw ``job_status`` object."""
        return self.project.call("job_status", job_id=self.job_id)  # type: ignore[no-any-return]

    def cancel(self) -> None:
        """Asks the job to stop; partial work is kept."""
        self.project.call("job_cancel", job_id=self.job_id)

    def wait(
        self,
        progress: ProgressCallback | None = None,
        *,
        timeout: float | None = None,
        poll: float = 0.25,
    ) -> JobResult:
        """Waits for the job, calling ``progress(JobProgress)`` when it advances.

        Ctrl-C (``KeyboardInterrupt``) cancels the job before re-raising. A failed job raises the
        error it failed with; a cancelled job raises :class:`~kraken.CancelledError`; running past
        ``timeout`` seconds raises :class:`~kraken.KrakenTimeoutError` and leaves the job running.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        last: dict[str, Any] | None = None
        try:
            while True:
                st = self.project.call("job_await", job_id=self.job_id, timeout_ms=max(1, int(poll * 1000)))
                prog = st.get("progress")
                if prog is not None and prog != last:
                    last = prog
                    if progress is not None:
                        progress(JobProgress(**{k: v for k, v in prog.items() if k in _PROGRESS_FIELDS}))
                if st["status"] != "running":
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    raise KrakenTimeoutError(
                        f"job {self.job_id} still running after {timeout} s", {"job_id": self.job_id}
                    )
        except KeyboardInterrupt:
            self._cancel_quietly()
            raise
        if st["status"] == "failed":
            raise from_proto(st.get("error") or {"code": "internal", "message": "job failed"})
        if st["status"] == "cancelled":
            raise CancelledError(f"job {self.job_id} was cancelled", {"job_id": self.job_id})
        return JobResult(self.job_id, st["command"], st["status"], st.get("result"))

    def _cancel_quietly(self) -> None:
        try:
            self.cancel()
            self.project.call("job_await", job_id=self.job_id, timeout_ms=3000)
        except (KrakenError, KeyboardInterrupt):
            pass

    def __repr__(self) -> str:
        return f"<kraken.Job {self.command} {self.job_id}>"


class Debugger:
    """A debugging session on KRAKEN's emulator (the ``debug_*`` commands).

    The program runs interpreted in a sandboxed child process, never on this computer. Addresses
    are the Listing's. Use it as a context manager so the session ends::

        with project.debug(argv=["-v"]) as dbg:
            dbg.run_to("main")
            print(dbg.registers()["RDI"], dbg.disassemble(count=5)[0]["text"])
            dbg.step_over()
            dbg.cont()
            print(dbg.state()["stdout"])
    """

    def __init__(self, project: Project, start: dict[str, Any]) -> None:
        self.project = project
        self.id: int = start["session"]
        self.arch: str = start["arch"]
        self.address_delta = parse_address(start["address_delta"])
        self.notes: list[str] = start["notes"]

    def _call(self, command: str, **args: Any) -> Any:
        return self.project.call(command, session=self.id, **args)

    def step(self, count: int = 1) -> dict[str, Any]:
        """Executes ``count`` instructions, entering calls."""
        return self._call("debug_step", count=count)  # type: ignore[no-any-return]

    def step_over(self) -> dict[str, Any]:
        """Executes one instruction; a call runs to its return."""
        return self._call("debug_step_over")  # type: ignore[no-any-return]

    def step_out(self) -> dict[str, Any]:
        """Runs until the current function returns."""
        return self._call("debug_step_out")  # type: ignore[no-any-return]

    def cont(self, *, timeout_seconds: int | None = None) -> dict[str, Any]:
        """Runs to the next breakpoint or the end of the program."""
        return self._call("debug_continue", timeout_seconds=timeout_seconds)  # type: ignore[no-any-return]

    def run_to(self, where: Address) -> dict[str, Any]:
        """Runs to an address, or to the function named by a string that is not a hex address."""
        if isinstance(where, str) and not where.lower().startswith("0x"):
            return self._call("debug_run_to", symbol=where)  # type: ignore[no-any-return]
        return self._call("debug_run_to", address=parse_address(where))  # type: ignore[no-any-return]

    def set_breakpoint(self, where: Address) -> list[int]:
        """Sets a breakpoint (an address, or a function symbol); returns all of them."""
        if isinstance(where, str) and not where.lower().startswith("0x"):
            out = self._call("debug_break_set", symbol=where)
        else:
            out = self._call("debug_break_set", address=parse_address(where))
        return [parse_address(a) for a in out["breakpoints"]]

    def remove_breakpoint(self, where: Address) -> list[int]:
        """Removes a breakpoint; returns the remaining ones."""
        if isinstance(where, str) and not where.lower().startswith("0x"):
            out = self._call("debug_break_remove", symbol=where)
        else:
            out = self._call("debug_break_remove", address=parse_address(where))
        return [parse_address(a) for a in out["breakpoints"]]

    def breakpoints(self) -> list[int]:
        """The breakpoints."""
        return [parse_address(a) for a in self._call("debug_break_list")["breakpoints"]]

    def watch(
        self,
        address: int,
        length: int = 8,
        kind: str = "write",
        *,
        emulator_address: bool = False,
    ) -> list[dict[str, Any]]:
        """Stops the program when it writes, reads or accesses (both) the range.

        ``kind`` is ``write``, ``read`` or ``access``. ``cont`` then returns a stop of kind
        ``watch`` whose ``watch`` entry has the old and new bytes as hex. ``emulator_address`` for
        a pointer taken from a register. Returns all watchpoints.
        """
        out = self._call(
            "debug_watch_set",
            address=address,
            length=length,
            kind=kind,
            emulator_address=emulator_address,
        )
        return out["watchpoints"]  # type: ignore[no-any-return]

    def unwatch(
        self,
        address: int,
        length: int = 8,
        kind: str = "write",
        *,
        emulator_address: bool = False,
    ) -> list[dict[str, Any]]:
        """Removes a watchpoint set with the same arguments; returns the remaining ones."""
        out = self._call(
            "debug_watch_remove",
            address=address,
            length=length,
            kind=kind,
            emulator_address=emulator_address,
        )
        return out["watchpoints"]  # type: ignore[no-any-return]

    def reverse_step(self, count: int = 1) -> dict[str, Any]:
        """Goes back ``count`` instructions: registers and memory return to what they were."""
        return self._call("debug_reverse_step", count=count)  # type: ignore[no-any-return]

    def reverse_continue(self, *, timeout_seconds: int | None = None) -> dict[str, Any]:
        """Runs backwards to the previous breakpoint or watchpoint access, or the start."""
        return self._call("debug_reverse_continue", timeout_seconds=timeout_seconds)  # type: ignore[no-any-return]

    def registers(self) -> dict[str, int]:
        """Register values by name (the emulator's own addresses)."""
        out = self._call("debug_regs")
        return {r["name"]: parse_address(r["value"]) for r in out["registers"]}

    def read_memory(self, address: int, length: int = 64, *, emulator_address: bool = False) -> bytes:
        """Reads guest memory; ``emulator_address`` for a pointer taken from a register."""
        out = self._call(
            "debug_mem_read", address=address, length=length, emulator_address=emulator_address
        )
        return bytes.fromhex(out["hex"])

    def disassemble(self, address: int | None = None, count: int = 20) -> list[dict[str, Any]]:
        """Instructions from ``address`` or the program counter."""
        args: dict[str, Any] = {"count": count}
        if address is not None:
            args["address"] = address
        return self._call("debug_disasm", **args)["instructions"]  # type: ignore[no-any-return]

    def state(self) -> dict[str, Any]:
        """Where the program is, how it last stopped and what it printed."""
        return self._call("debug_state")  # type: ignore[no-any-return]

    def stop(self) -> None:
        """Ends the session."""
        self._call("debug_stop")

    def __enter__(self) -> Debugger:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def __repr__(self) -> str:
        return f"<kraken.Debugger session={self.id} arch={self.arch}>"


class Function:
    """A function of the project.

    ``name`` and ``signature`` come from the binary and are untrusted text (see
    :mod:`kraken.types`); ``untrusted`` is always ``True``.
    """

    untrusted = True
    __slots__ = ("project", "address", "name", "size", "signature", "complete")

    def __init__(
        self,
        project: Project,
        address: int,
        name: UntrustedStr,
        size: int | None = None,
        signature: UntrustedStr | None = None,
        complete: bool = False,
    ) -> None:
        self.project = project
        self.address = address
        self.name = name
        self.size = size
        self.signature = signature
        self.complete = complete

    @classmethod
    def _from_json(cls, project: Project, d: dict[str, Any]) -> Function:
        return cls(
            project,
            int(d["address"], 16),
            d["name"],
            d.get("size"),
            d.get("signature"),
            d["completeness"]["kind"] == "complete",
        )

    def decompile(self) -> Decompiled:
        """Decompiles the function. The result's text and tokens are binary-derived."""
        return Decompiled.from_json(self.project.call("decompile", address=self.address))

    def rename(self, name: str) -> EditResult:
        """Renames the function. Updates ``self.name`` unless the edit became a proposal."""
        res = self.project.rename(self.address, name)
        if not res.proposed:
            self.name = UntrustedStr(name)
        return res

    def set_comment(self, kind: str, text: str) -> EditResult:
        """Sets (or, with empty ``text``, clears) a comment of ``kind`` at the entry address.

        ``kind`` is one of ``plate``, ``pre``, ``eol``, ``post`` and ``repeatable``.
        """
        return self.project.set_comment(self.address, kind, text)

    def comments(self) -> list[Comment]:
        """The comments attached to the function entry."""
        d = self.project.call("get_function", address=self.address)
        return [Comment(c["kind"], c["text"]) for c in d["comments"]]

    def callers(self) -> Iterator[Xref]:
        """Call sites that call this function."""
        return self.project._paged_items("callers", Xref.from_json, address=self.address)

    def callees(self) -> Iterator[Xref]:
        """Calls this function makes."""
        return self.project._paged_items("callees", Xref.from_json, address=self.address)

    def disassemble(self) -> Iterator[Instruction]:
        """The function's instructions."""
        return self.project.disassemble(function=self.address)

    def cfg(self) -> CfgGraph:
        """The function's control-flow graph."""
        return self.project.cfg(self.address)

    def refresh(self) -> Function:
        """Re-reads name, signature and size from the project."""
        d = self.project.call("get_function", address=self.address)
        self.name, self.size, self.signature = d["name"], d.get("size"), d.get("signature")
        self.complete = d["completeness"]["kind"] == "complete"
        return self

    def __repr__(self) -> str:
        return f"<kraken.Function {self.name!s} @ 0x{self.address:x}>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Function) and other.project is self.project and other.address == self.address

    def __hash__(self) -> int:
        return hash((id(self.project), self.address))


FunctionFilter = str | re.Pattern[str] | Callable[[Function], bool]


class Project:
    """An open KRAKEN project.

    Edits are attributed to the current user (a script is the user's own work) unless the project
    was opened with ``agent="name"``: then the same edits go through agent policy (additive ones
    apply, others become proposals a person accepts) and are grouped under :attr:`run_id`.
    """

    def __init__(
        self,
        connection: Connection,
        directory: str,
        *,
        agent: str | None = None,
        run_id: str | None = None,
    ) -> None:
        self.connection = connection
        self.directory = directory
        self._h = connection._n.handle(directory, agent, run_id)
        self._approve = False
        self._addr_args: dict[str, frozenset[str]] = {}
        self._keepalive: list[Any] = []

    # -- identity -----------------------------------------------------------------------------

    @property
    def author_kind(self) -> Literal["user", "agent"]:
        return self._h.author_kind  # type: ignore[no-any-return]

    @property
    def author(self) -> str:
        """The user name or agent id edits are logged under."""
        return self._h.author_id  # type: ignore[no-any-return]

    @property
    def agent(self) -> str | None:
        return self.author if self.author_kind == "agent" else None

    @property
    def run_id(self) -> str | None:
        """The agent run id, or ``None`` for a user."""
        return self._h.run_id  # type: ignore[no-any-return]

    # -- generic access -----------------------------------------------------------------------

    def _address_keys(self, command: str) -> frozenset[str]:
        keys = self._addr_args.get(command)
        if keys is None:
            spec = self.connection.commands().get(command)
            props = (spec.args_schema.get("properties") or {}) if spec else {}
            keys = frozenset(k for k, v in props.items() if "Hex64" in json.dumps(v))
            self._addr_args[command] = keys
        return keys

    def call(self, command: str, /, **args: Any) -> Any:
        """Runs any registry command and returns its decoded output.

        Arguments are checked against the command's JSON Schema before anything is sent; a
        problem raises :class:`~kraken.InvalidArgumentError` naming the argument. Integers given
        for address arguments are converted to ``0x`` strings. Binary-derived strings in the output
        are :class:`~kraken.UntrustedStr`. See :meth:`Connection.commands` for the list.

        >>> project.call("memory_map")["blocks"][0]["perms"]   # doctest: +SKIP
        """
        keys = self._address_keys(command)
        wire: dict[str, Any] = {}
        for k, v in args.items():
            if k in keys and isinstance(v, int) and not isinstance(v, bool):
                v = hex_address(v)
            wire[k] = v
        try:
            payload = json.dumps(wire, default=_json_default)
        except (TypeError, ValueError) as e:
            raise InvalidArgumentError(f"arguments of `{command}` are not JSON: {e}") from e
        text, notices = self._h.call(command, payload, self._approve)
        for n in notices:
            warnings.warn(n, KrakenWarning, stacklevel=2)
        return loads(text)

    def commands(self) -> dict[str, CommandSpec]:
        """Every command and its JSON Schemas."""
        return self.connection.commands()

    def _paged(self, command: str, **args: Any) -> Iterator[dict[str, Any]]:
        cursor: str | None = None
        while True:
            page_args = {k: v for k, v in args.items() if v is not None}
            if cursor is not None:
                page_args["cursor"] = cursor
            out = self.call(command, **page_args)
            yield from out["items"]
            cursor = out.get("next_cursor")
            if not cursor:
                return

    def _paged_items(self, command: str, make: Callable[[dict[str, Any]], Any], **args: Any) -> Iterator[Any]:
        for item in self._paged(command, **args):
            yield make(item)

    # -- project ------------------------------------------------------------------------------

    def info(self) -> ProjectInfo:
        """Program, engine and analysis state."""
        return ProjectInfo.from_json(self.call("project_info"))

    def analyze(
        self,
        wait: bool = True,
        progress: ProgressCallback | None = None,
        *,
        timeout: float | None = None,
        poll: float = 0.25,
    ) -> Job | JobResult:
        """Runs the analysis job.

        With ``wait=True`` (default) blocks until it finishes and returns a :class:`JobResult`,
        calling ``progress(JobProgress)`` as it advances; Ctrl-C cancels the job. With
        ``wait=False`` returns the :class:`Job` to ``wait()`` for or ``cancel()`` later.
        """
        out = self.call("analyze")
        job = Job(self, out["job_id"], "analyze")
        if not wait:
            return job
        return job.wait(progress, timeout=timeout, poll=poll)

    # -- functions ----------------------------------------------------------------------------

    def functions(
        self, filter: FunctionFilter | None = None, *, page_size: int = 100
    ) -> Iterator[Function]:
        """Iterates the functions in address order, fetching pages lazily.

        ``filter`` is a ``str`` (case-insensitive substring of the name, applied by the engine),
        a compiled regular expression (``search`` on the name) or a predicate ``f(Function)``.
        """
        server: str | None = None
        predicate: Callable[[Function], bool] | None = None
        if isinstance(filter, str):
            server = filter
        elif isinstance(filter, re.Pattern):
            pat = filter
            predicate = lambda f: pat.search(f.name) is not None  # noqa: E731
        elif callable(filter):
            predicate = filter
        elif filter is not None:
            raise TypeError("filter must be a str, a compiled regex or a callable")
        for item in self._paged("list_functions", name_filter=server, limit=page_size):
            fn = Function._from_json(self, item)
            if predicate is None or predicate(fn):
                yield fn

    def function(self, where: Address) -> Function:
        """The function at (or, for a name, called) ``where``; raises :class:`NotFoundError`."""
        if isinstance(where, str) and not where.lower().startswith("0x"):
            matches = [f for f in self.functions(where) if f.name == where]
            if not matches:
                raise NotFoundError(f"no function named {where!r}")
            return matches[0]
        return Function._from_json(self, self.call("get_function", address=parse_address(where)))

    def rename(self, address: Address, name: str) -> EditResult:
        """Renames the function or label at ``address``."""
        return EditResult.from_json(
            self.call("rename_symbol", address=parse_address(address), new_name=name)
        )

    def set_comment(self, address: Address, kind: str, text: str) -> EditResult:
        """Sets (empty ``text`` clears) a comment of ``kind`` at ``address``."""
        if kind not in COMMENT_KINDS:
            raise InvalidArgumentError(
                f"unknown comment kind {kind!r}; expected one of {', '.join(COMMENT_KINDS)}"
            )
        return EditResult.from_json(
            self.call("set_comment", address=parse_address(address), kind=kind, text=text)
        )

    # -- data ---------------------------------------------------------------------------------

    def read_bytes(self, address: Address, length: int) -> bytes:
        """Reads ``length`` bytes of memory (in chunks of at most 64 KiB)."""
        if length < 0:
            raise InvalidArgumentError("length must not be negative")
        base = parse_address(address)
        out = bytearray()
        while len(out) < length:
            n = min(65536, length - len(out))
            d = self.call("read_bytes", address=base + len(out), length=n)
            chunk = decode_bytes(d["bytes"])
            out += chunk
            if len(chunk) < n:
                break
        return bytes(out)

    def disassemble(
        self,
        address: Address | None = None,
        *,
        function: Address | None = None,
        page_size: int | None = None,
    ) -> Iterator[Instruction]:
        """Iterates instructions linearly from ``address`` or over one ``function``'s body."""
        if (address is None) == (function is None):
            raise InvalidArgumentError("give exactly one of address and function")
        args: dict[str, Any] = {"max_instructions": page_size}
        if address is not None:
            args["address"] = parse_address(address)
        if function is not None:
            args["function"] = parse_address(function)
        return self._paged_items("disassemble", Instruction.from_json, **args)

    def xrefs(
        self,
        address: Address,
        direction: Literal["to", "from"] = "to",
        *,
        kind: str | None = None,
        whole_function: bool = False,
    ) -> Iterator[Xref]:
        """Iterates cross-references to or from ``address``."""
        return self._paged_items(
            "xrefs",
            Xref.from_json,
            address=parse_address(address),
            direction=direction,
            kind=kind,
            whole_function=whole_function or None,
        )

    def cfg(self, function: Address) -> CfgGraph:
        """The control-flow graph of the function at ``function``."""
        return CfgGraph.from_json(self.call("cfg", function=parse_address(function)))

    def strings(self, filter: str | None = None, *, min_len: int | None = None) -> Iterator[StringItem]:
        """Iterates strings in memory; ``filter`` is a case-insensitive substring."""
        return self._paged_items("strings", StringItem.from_json, filter=filter, min_len=min_len)

    def memory_map(self) -> list[MemoryBlock]:
        """The memory blocks."""
        return [MemoryBlock.from_json(b) for b in self.call("memory_map")["blocks"]]

    def imports(self) -> Iterator[Import]:
        """Imported symbols."""
        return self._paged_items("imports", Import.from_json)

    def exports(self) -> Iterator[Import]:
        """Exported symbols and entry points."""
        return self._paged_items("exports", Import.from_json)

    # -- history ------------------------------------------------------------------------------

    def history(self, run_id: str | None = None) -> Iterator[HistoryEntry]:
        """Iterates the edit log, newest first; ``run_id`` keeps one agent run."""
        return self._paged_items("history", HistoryEntry.from_json, run_id=run_id)

    def undo(self) -> UndoResult:
        """Undoes this author's most recent edit."""
        return UndoResult.from_json(self.call("undo"))

    def undo_run(self, run_id: str | None = None) -> UndoResult:
        """Undoes every edit of an agent run, newest first (default: this project's run)."""
        rid = run_id or self.run_id
        if rid is None:
            raise InvalidArgumentError("give a run_id: this project is not an agent run")
        return UndoResult.from_json(self.call("undo_run", run_id=rid))

    def proposals(self, status: Literal["open", "accepted", "rejected", "all"] = "open") -> list[Proposal]:
        """Agent proposals; their content is agent-written and may quote the binary."""
        return [Proposal(p["id"], p) for p in self._paged("proposals_list", status=status)]

    def accept_proposal(self, proposal_id: int) -> Any:
        """Accepts a proposal as the user (not available to agents)."""
        return self.call("proposal_accept", id=proposal_id)

    def reject_proposal(self, proposal_id: int) -> Any:
        """Rejects a proposal as the user (not available to agents)."""
        return self.call("proposal_reject", id=proposal_id)

    # -- debugger -----------------------------------------------------------------------------

    def debug(
        self,
        *,
        argv: list[str] | None = None,
        stdin: str = "",
        patched: bool = False,
    ) -> Debugger:
        """Starts a debugger session on the emulator, stopped before the first instruction."""
        out = self.call("debug_start", argv=argv or [], stdin=stdin, patched=patched)
        return Debugger(self, out)

    # -- lifecycle ----------------------------------------------------------------------------

    def __enter__(self) -> Project:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Releases what the project holds (test helpers also remove their temporary files)."""
        for k in self._keepalive:
            try:
                k.cleanup() if hasattr(k, "cleanup") else k.close()
            except Exception:  # noqa: BLE001 - cleanup must not mask the real error
                pass
        self._keepalive.clear()

    def __repr__(self) -> str:
        who = f"agent={self.agent!r}" if self.agent else f"user={self.author!r}"
        return f"<kraken.Project {self.directory!r} {who}>"


# -- module-level entry points ----------------------------------------------------------------

_default: Connection | None = None
_default_lock = threading.Lock()


def connect(
    daemon: bool | None = None,
    *,
    runtime_dir: str | os.PathLike[str] | None = None,
    krakend: str | os.PathLike[str] | None = None,
) -> Connection:
    """Connects to KRAKEN.

    ``daemon=None`` (default) uses the ``krakend`` daemon, starting it if needed, and falls back to
    running in this process (with a :class:`KrakenWarning`) when that is impossible;
    ``KRAKEN_NO_DAEMON=1`` forces in-process. ``daemon=True`` requires the daemon; ``daemon=False``
    runs the engine inside this Python process (a JVM is started for Ghidra, and stopped by
    :meth:`Connection.close` or at exit).

    ``krakend`` names the daemon binary (default: ``$KRAKEN_KRAKEND``, ``PATH``); ``runtime_dir``
    overrides the per-user runtime directory (``KRAKEN_RUNTIME_DIR``).
    """
    return Connection(
        _native.connect(
            daemon,
            None if runtime_dir is None else os.fspath(runtime_dir),
            None if krakend is None else os.fspath(krakend),
        )
    )


def default_connection() -> Connection:
    """The shared connection used by :func:`open` and :func:`create`, made on first use."""
    global _default
    with _default_lock:
        if _default is None:
            _default = connect()
            atexit.register(_close_default)
        return _default


def _close_default() -> None:
    global _default
    conn, _default = _default, None
    if conn is not None:
        try:
            conn.close()
        except KrakenError:
            pass


def open(  # noqa: A001 - mirrors the builtin on purpose: kraken.open(...)
    project_dir: str | os.PathLike[str],
    *,
    agent: str | None = None,
    run_id: str | None = None,
    connection: Connection | None = None,
) -> Project:
    """Opens an existing project on the shared connection (or ``connection``)."""
    return (connection or default_connection()).open(project_dir, agent=agent, run_id=run_id)


def create(
    project_dir: str | os.PathLike[str],
    binary: str | os.PathLike[str],
    *,
    agent: str | None = None,
    run_id: str | None = None,
    connection: Connection | None = None,
    **options: Any,
) -> Project:
    """Creates a project for ``binary`` on the shared connection (or ``connection``).

    ``options`` are those of :meth:`Connection.create` (``loader="raw"``, ``language``, ``base``...).
    """
    return (connection or default_connection()).create(
        project_dir, binary, agent=agent, run_id=run_id, **options
    )
