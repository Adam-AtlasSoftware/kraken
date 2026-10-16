"""Test hooks. Not API: only functional in a wheel built with the ``testing`` cargo feature."""

from __future__ import annotations

import os
import tempfile

from . import _native
from .project import Connection, Project

__all__ = ["fake_project"]


def fake_project(
    fixture_path: str | os.PathLike[str],
    *,
    agent: str | None = None,
    run_id: str | None = None,
) -> Project:
    """A new in-process project whose engine replays the recorded fixture at ``fixture_path``.

    No Ghidra, JVM or daemon is involved. The project lives in a temporary directory that
    :meth:`Project.close` removes (and the connection is closed with it).
    """
    if not _native.has_testing():
        raise RuntimeError("this build of kraken has no test hook; build with --features testing")
    conn = Connection(_native.fake_connection(os.fspath(fixture_path)))
    tmp = tempfile.TemporaryDirectory(prefix="kraken-py-test-")
    binary = os.path.join(tmp.name, "prog.bin")
    with open(binary, "wb") as f:
        f.write(b"\x7fELF fake binary contents")
    project = conn.create(os.path.join(tmp.name, "proj"), binary, agent=agent, run_id=run_id)
    project._keepalive.extend([conn, tmp])
    return project
