"""Exceptions raised by KRAKEN.

Every failure of a command is a :class:`KrakenError`; the subclass follows the protocol's error
code (``not_found`` becomes :class:`NotFoundError`, and so on). ``code`` is the wire string,
``details`` the optional structured details the command attached.

The messages can quote text from the analysed binary. They are sanitised of control characters,
but treat them like any other binary-derived text.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = [
    "AnalysisIncompleteError",
    "CancelledError",
    "EngineRejectedError",
    "InternalError",
    "InvalidArgumentError",
    "KrakenError",
    "KrakenTimeoutError",
    "NotFoundError",
    "RejectedByHumanError",
    "StaleReadError",
    "UnsupportedError",
    "from_proto",
    "from_wire",
]


class KrakenError(Exception):
    """Base class of every error KRAKEN raises for a failed command."""

    code: str = "internal"

    def __init__(self, message: str, details: Any = None, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details
        if code is not None:
            self.code = code

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class NotFoundError(KrakenError, LookupError):
    """The addressed entity (function, project, job, ...) does not exist."""

    code = "not_found"


class InvalidArgumentError(KrakenError, ValueError):
    """An argument is malformed, unknown, or out of range."""

    code = "invalid_argument"


class StaleReadError(KrakenError):
    """The write was based on a read that is no longer current; re-read and retry."""

    code = "conflict_stale_read"


class RejectedByHumanError(KrakenError):
    """A concurrent human edit won over this agent edit."""

    code = "rejected_human_priority"


class EngineRejectedError(KrakenError):
    """The analysis engine refused to apply the change."""

    code = "engine_rejected"


class UnsupportedError(KrakenError):
    """The engine or version does not support this, or an approval was denied."""

    code = "unsupported"


class AnalysisIncompleteError(KrakenError):
    """The result depends on analysis that has not finished."""

    code = "analysis_incomplete"


class KrakenTimeoutError(KrakenError, TimeoutError):
    """The deadline passed before the operation finished."""

    code = "timeout"


class CancelledError(KrakenError):
    """The operation was cancelled."""

    code = "cancelled"


class InternalError(KrakenError):
    """An unexpected internal failure."""

    code = "internal"


_BY_CODE: dict[str, type[KrakenError]] = {
    cls.code: cls
    for cls in (
        NotFoundError,
        InvalidArgumentError,
        StaleReadError,
        RejectedByHumanError,
        EngineRejectedError,
        UnsupportedError,
        AnalysisIncompleteError,
        KrakenTimeoutError,
        CancelledError,
        InternalError,
    )
}


def from_wire(code: str, message: str, details_json: str | None = None) -> KrakenError:
    """Builds the exception for an error code. Unknown codes become :class:`KrakenError`."""
    details = None
    if details_json:
        try:
            details = json.loads(details_json)
        except ValueError:
            details = details_json
    cls = _BY_CODE.get(code)
    if cls is None:
        return KrakenError(message, details, code=code)
    return cls(message, details)


def from_proto(error: dict[str, Any]) -> KrakenError:
    """Builds the exception for a ``ProtoError`` object (as found in a failed job)."""
    return from_wire(
        str(error.get("code", "internal")),
        str(error.get("message", "")),
        None if error.get("details") is None else json.dumps(error["details"]),
    )
