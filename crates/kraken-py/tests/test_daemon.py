"""The daemon path, Ctrl-C and GIL behaviour, against a private krakend with a scripted fake engine."""

from __future__ import annotations

import _thread
import os
import signal
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

import kraken

from conftest import STRIPPED

pytestmark = [
    pytest.mark.daemon,
    pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets and signals"),
]


def _project_dir(tmp_path: Path) -> tuple[Path, Path]:
    binary = tmp_path / "prog.bin"
    binary.write_bytes(b"\x7fELF fake binary contents")
    return tmp_path / "proj", binary


def test_a_script_drives_the_daemon_end_to_end(daemon_env, tmp_path: Path) -> None:
    runtime, conns = daemon_env
    conn = kraken.connect(daemon=True)
    conns.append(conn)
    assert conn.mode == "daemon" and conn.daemon_pid
    proj_dir, binary = _project_dir(tmp_path)
    proj = conn.create(proj_dir, binary)
    proj.analyze()
    names = [f.name for f in proj.functions()]
    assert len(names) == 26
    fn = proj.function(0x101020)
    assert fn.rename("from_python").status == "applied"
    assert "from_python" in fn.decompile().text or fn.refresh().name == "from_python"

    # A second connection (another script) sees the same project and the edit; edits are the user's.
    other = kraken.connect(daemon=True)
    again = other.open(proj_dir)
    assert again.function(0x101020).name == "from_python"
    assert next(iter(again.history())).author_kind == "user"
    assert other.daemon_pid == conn.daemon_pid


def test_ctrl_c_cancels_the_running_analysis(daemon_env, tmp_path: Path) -> None:
    runtime, conns = daemon_env
    conn = kraken.connect(daemon=True)
    conns.append(conn)
    proj_dir, binary = _project_dir(tmp_path)
    proj = conn.create(proj_dir, binary)

    timer = threading.Timer(0.5, _thread.interrupt_main)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(KeyboardInterrupt):
            proj.analyze(poll=0.1)
    finally:
        timer.cancel()
    assert time.monotonic() - started < 10
    # The job was cancelled (3 stages x 600 ms would otherwise still be running), not abandoned.
    deadline = time.monotonic() + 10
    phase = None
    while time.monotonic() < deadline:
        phase = proj.info().analysis_phase
        if phase != "running":
            break
        time.sleep(0.1)
    assert phase in {"cancelled", "not_started", "failed"}, phase
    with pytest.raises(kraken.CancelledError):
        job = proj.analyze(wait=False)
        job.cancel()
        job.wait()


def test_blocking_calls_release_the_gil_and_honour_ctrl_c(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A krakend that never listens makes connect() block for its whole start timeout."""
    pidfile = tmp_path / "pid"
    fake = tmp_path / "krakend"
    fake.write_text(f"#!/bin/sh\necho $$ > '{pidfile}'\nexec sleep 20\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.delenv("KRAKEN_NO_DAEMON", raising=False)
    runtime = Path(os.environ.get("TMPDIR", "/tmp")) / f"krpy-{os.getpid()}"
    ticks = 0
    stop = threading.Event()

    def count() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            time.sleep(0.001)

    threading.Thread(target=count, daemon=True).start()
    interrupter = threading.Timer(1.0, _thread.interrupt_main)
    interrupter.start()
    started = time.monotonic()
    try:
        with pytest.raises(KeyboardInterrupt):
            kraken.connect(daemon=True, runtime_dir=runtime, krakend=fake)
    finally:
        stop.set()
        interrupter.cancel()
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            except (OSError, ValueError):
                pass
        import shutil

        shutil.rmtree(runtime, ignore_errors=True)
    elapsed = time.monotonic() - started
    assert 0.8 < elapsed < 8, elapsed
    # The counter thread ran during the blocked call: the GIL was released.
    assert ticks > 100, ticks
