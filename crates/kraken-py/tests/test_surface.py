"""Import surface, error table and stubs: needs no engine."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import kraken
from kraken import _native, errors
from kraken.types import UntrustedStr, decode_hook, hex_address, parse_address

PKG = Path(kraken.__file__).parent


def test_every_error_code_has_the_class_the_native_table_names() -> None:
    table = dict(_native.error_codes())
    assert len(table) == 10
    for code, class_name in table.items():
        cls = getattr(errors, class_name)
        assert issubclass(cls, errors.KrakenError)
        assert cls.code == code
        exc = errors.from_wire(code, "m", json.dumps({"a": 1}))
        assert type(exc) is cls
        assert exc.details == {"a": 1}
        assert str(exc) == f"{code}: m"


def test_error_classes_are_also_the_natural_builtins() -> None:
    assert issubclass(kraken.InvalidArgumentError, ValueError)
    assert issubclass(kraken.NotFoundError, LookupError)
    assert issubclass(kraken.KrakenTimeoutError, TimeoutError)


def test_unknown_codes_still_raise_kraken_error() -> None:
    exc = errors.from_wire("from_the_future", "hmm")
    assert type(exc) is kraken.KrakenError
    assert exc.code == "from_the_future"
    assert errors.from_proto({"code": "not_found", "message": "x", "details": [1]}).details == [1]


def test_stub_exports_match_runtime_all() -> None:
    tree = ast.parse((PKG / "__init__.pyi").read_text())
    names = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            names.update(a.asname or a.name for a in node.names)
        elif isinstance(node, (ast.FunctionDef, ast.AnnAssign)):
            names.add(node.name if isinstance(node, ast.FunctionDef) else node.target.id)  # type: ignore[attr-defined]
    assert set(kraken.__all__) <= names, set(kraken.__all__) - names
    assert (PKG / "py.typed").exists()


def test_untrusted_strings_are_plain_strs_with_a_marker() -> None:
    s = decode_hook({"untrusted": True, "value": "FUN_1"})
    assert isinstance(s, str) and isinstance(s, UntrustedStr)
    assert s == "FUN_1" and s.untrusted is True
    assert (s + "x") == "FUN_1x"
    assert json.dumps(s) == '"FUN_1"'
    # Other objects, even ones that look similar, are untouched.
    assert decode_hook({"untrusted": True, "value": "a", "extra": 1}) == {
        "untrusted": True,
        "value": "a",
        "extra": 1,
    }


def test_addresses() -> None:
    assert parse_address("0x10") == 16 and parse_address(16) == 16
    assert hex_address(255) == "0xff"
    for bad in ("10", -1, 1 << 64, True, 1.5):
        with pytest.raises((TypeError, ValueError)):
            parse_address(bad)  # type: ignore[arg-type]


def test_in_process_connection_without_a_project() -> None:
    with kraken.connect(daemon=False) as conn:
        assert conn.mode == "local" and conn.daemon_pid is None
        specs = conn.commands()
        assert {"analyze", "decompile", "rename_symbol", "undo_run"} <= set(specs)
        assert specs["rename_symbol"].args_schema["required"] == ["address", "new_name"]
        assert conn.stop_daemon() is False


def test_open_without_a_project_is_a_clean_error(tmp_path: Path) -> None:
    with kraken.connect(daemon=False) as conn:
        with pytest.raises(kraken.KrakenError) as e:
            conn.open(tmp_path / "missing")
        assert e.value.code in {"not_found", "invalid_argument", "internal"}


def test_requiring_a_daemon_that_cannot_start_fails_fast(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("KRAKEN_NO_DAEMON", raising=False)
    monkeypatch.setenv("KRAKEN_KRAKEND", str(tmp_path / "no-such-krakend"))
    with pytest.raises(kraken.KrakenError):
        kraken.connect(daemon=True, runtime_dir=tmp_path / "rt")


def test_auto_mode_falls_back_in_process_with_a_warning(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("KRAKEN_NO_DAEMON", raising=False)
    monkeypatch.setenv("KRAKEN_KRAKEND", str(tmp_path / "no-such-krakend"))
    with pytest.warns(kraken.KrakenWarning, match="running in this process"):
        conn = kraken.connect(runtime_dir=tmp_path / "rt")
    assert conn.mode == "local"
    conn.close()
