"""Shared fixtures.

Nothing here touches a developer's real daemon or Ghidra: in-process tests use the FakeEngine
(needs a wheel built with the `testing` feature), and daemon tests start a private `krakend` with
its scripted fake engine under a private runtime directory, then stop it.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

import kraken
from kraken import _native

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "corpus" / "fixtures"
STRIPPED = FIXTURES / "pie_list-O0-stripped.json"
NAMED = FIXTURES / "pie_list-O0.json"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _native.has_testing():
        return
    skip = pytest.mark.skip(reason="wheel was built without the `testing` feature")
    for item in items:
        if "fake" in item.keywords:
            item.add_marker(skip)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "fake: needs the FakeEngine test hook")
    config.addinivalue_line("markers", "daemon: starts a private krakend")


@pytest.fixture(autouse=True)
def _never_the_real_daemon(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("KRAKEN_NO_DAEMON", "1")
    monkeypatch.setenv("KRAKEN_RUNTIME_DIR", str(tmp_path / "no-daemon-runtime"))


@pytest.fixture
def fake_project():
    from kraken import _testing

    made = []

    def make(fixture: Path = STRIPPED, **kw):
        p = _testing.fake_project(fixture, **kw)
        made.append(p)
        return p

    yield make
    for p in made:
        p.close()


@pytest.fixture
def project(fake_project):
    return fake_project()


def find_krakend() -> Path | None:
    env = os.environ.get("KRAKEN_TEST_KRAKEND")
    if env and Path(env).is_file():
        return Path(env)
    name = "krakend.exe" if sys.platform == "win32" else "krakend"
    target = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target"))
    for profile in ("debug", "release"):
        p = target / profile / name
        if p.is_file():
            return p
    return None


@pytest.fixture
def daemon_env(monkeypatch: pytest.MonkeyPatch):
    """A private runtime dir plus a krakend with a slow scripted fake engine; stops it after."""
    krakend = find_krakend()
    if krakend is None or sys.platform == "win32":
        pytest.skip("no krakend binary (cargo build -p krakend) or not a Unix host")
    # Unix socket paths are short: keep the directory directly under the system temp dir.
    runtime = Path(tempfile.mkdtemp(prefix="krpy-"))
    monkeypatch.delenv("KRAKEN_NO_DAEMON", raising=False)
    monkeypatch.setenv("KRAKEN_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("KRAKEN_KRAKEND", str(krakend))
    monkeypatch.setenv("KRAKEN_FAKE_ENGINE", str(STRIPPED))
    monkeypatch.setenv("KRAKEN_FAKE_STAGE_DELAY_MS", "600")
    conns: list[kraken.Connection] = []
    yield runtime, conns
    for c in conns:
        try:
            c.stop_daemon()
        except kraken.KrakenError:
            pass
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and (runtime / "daemon.json").exists():
        time.sleep(0.05)
    shutil.rmtree(runtime, ignore_errors=True)
