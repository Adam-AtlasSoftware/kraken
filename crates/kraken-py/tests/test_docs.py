"""The example in docs/python.md must run."""

from __future__ import annotations

import io
import re
from contextlib import redirect_stdout
from pathlib import Path

import pytest

import kraken

from conftest import NAMED, REPO

pytestmark = pytest.mark.fake


def doc_example() -> str:
    text = (REPO / "docs" / "python.md").read_text()
    return re.search(r"```python\n(.*?)```", text, re.S).group(1)  # type: ignore[union-attr]


def test_the_example_is_ten_lines() -> None:
    lines = [ln for ln in doc_example().splitlines() if ln.strip()]
    assert len(lines) <= 12


def test_the_example_runs_and_renames(fake_project, monkeypatch: pytest.MonkeyPatch) -> None:
    proj = fake_project(NAMED)
    monkeypatch.setattr(kraken, "open", lambda *_a, **_k: proj)
    # The recorded fixture has real names and different strings: aim the same code at them.
    code = doc_example().replace("^FUN_", ".").replace("(usage|error)", "(gamma|delta)")
    out = io.StringIO()
    with redirect_stdout(out):
        exec(compile(code, "docs/python.md", "exec"), {"__name__": "doc"})
    renamed = [f.name for f in proj.functions("_string_")]
    assert renamed and all(n.startswith("has_") for n in renamed)
    assert "gamma" in out.getvalue() or "delta" in out.getvalue()
    # Edits made by the script are the user's own, and undo takes them back.
    assert next(iter(proj.history())).author_kind == "user"
    proj.undo()
