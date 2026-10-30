"""The scripting API over a FakeEngine-backed in-process project."""

from __future__ import annotations

import re
from unittest import mock

import pytest

import kraken
from kraken import UntrustedStr

pytestmark = pytest.mark.fake


def test_info_and_analysis_with_progress(project) -> None:
    assert project.info().analysis_phase == "not_started"
    seen: list[kraken.JobProgress] = []
    res = project.analyze(progress=seen.append)
    assert isinstance(res, kraken.JobResult) and res.status == "succeeded"
    assert res.result["function_count"] == 26
    assert seen and seen[-1].done == seen[-1].total
    info = project.info()
    assert info.analysis_phase == "complete" and info.function_count == 26
    assert info.arch.startswith("x86") and info.format == "elf"


def test_next_steps_start_with_analysis_and_carry_the_command(project) -> None:
    steps = project.next_steps()
    assert steps and isinstance(steps[0], kraken.NextStep)
    assert steps[0].id == "analyze" and steps[0].command == "analyze" and steps[0].runnable
    project.analyze()
    assert "analyze" not in [s.id for s in project.next_steps(limit=10)]


def test_analyze_without_waiting_returns_a_job(project) -> None:
    job = project.analyze(wait=False)
    assert isinstance(job, kraken.Job)
    assert job.wait().status == "succeeded"


def test_functions_are_paged_lazily(project) -> None:
    project.analyze()
    real = project.call
    pages = []

    def spy(command, /, **args):
        if command == "list_functions":
            pages.append(args)
        return real(command, **args)

    with mock.patch.object(project, "call", spy):
        it = project.functions(page_size=5)
        assert pages == []  # nothing fetched until iterated
        first = [next(it) for _ in range(3)]
        assert len(pages) == 1 and pages[0]["limit"] == 5
        rest = list(it)
    assert len(first) + len(rest) == 26
    assert len(pages) >= 6  # 26 functions at 5 per page
    assert all(isinstance(f, kraken.Function) and f.untrusted for f in first + rest)
    assert [f.address for f in first + rest] == sorted(f.address for f in first + rest)


def test_function_filters(project) -> None:
    project.analyze()
    by_text = list(project.functions("fun_"))
    assert by_text and all("fun_" in f.name.lower() for f in by_text)
    by_regex = list(project.functions(re.compile(r"^FUN_0010")))
    assert by_regex and all(f.name.startswith("FUN_0010") for f in by_regex)
    by_pred = list(project.functions(lambda f: f.address == 0x101030))
    assert [f.name for f in by_pred] == ["free"]
    with pytest.raises(TypeError):
        list(project.functions(42))  # type: ignore[arg-type]


def test_function_lookup(project) -> None:
    project.analyze()
    assert project.function(0x101030).name == "free"
    assert project.function("0x101030").name == "free"
    assert project.function("free").address == 0x101030
    with pytest.raises(kraken.NotFoundError):
        project.function("no_such_function_anywhere")
    with pytest.raises(kraken.NotFoundError):
        project.function(0x999999)


def test_decompile_marks_binary_text_untrusted(project) -> None:
    project.analyze()
    d = project.function(0x101000).decompile()
    assert isinstance(d, kraken.Decompiled)
    assert d.untrusted is True
    assert isinstance(d.text, str) and isinstance(d.text, UntrustedStr) and d.text.untrusted
    assert "__gmon_start__" in d.text and str(d) == d.text
    assert d.tokens and all(t.start < t.end for t in d.tokens)
    assert any(d.token_text(t) == "__gmon_start__" for t in d.tokens)
    assert d.complete


def test_rename_by_a_user_applies_and_is_logged_as_the_user(project) -> None:
    project.analyze()
    fn = project.function(0x101020)
    res = fn.rename("my_helper")
    assert res.status == "applied" and not res.proposed
    assert fn.name == "my_helper"
    assert project.function(0x101020).name == "my_helper"
    top = next(iter(project.history()))
    assert (top.op, top.author_kind, top.run_id) == ("rename", "user", None)
    assert project.author_kind == "user" and project.run_id is None


def test_undo_restores_the_name(project) -> None:
    project.analyze()
    fn = project.function(0x101020)
    old = str(fn.name)
    fn.rename("temp_name")
    out = project.undo()
    assert out.undone_entry_ids and not out.failed
    assert fn.refresh().name == old


def test_agent_edits_follow_agent_policy_and_undo_by_run(fake_project) -> None:
    p = fake_project(agent="script-bot", run_id="run-test-1")
    p.analyze()
    assert (p.author_kind, p.agent, p.run_id) == ("agent", "script-bot", "run-test-1")
    default_named = next(f for f in p.functions() if f.name.startswith("FUN_"))
    renamed = next(f for f in p.functions() if not f.name.startswith("FUN_"))
    ok = default_named.rename("agent_chosen")
    assert ok.status == "applied"
    prop = renamed.rename("agent_overrides_a_real_name")
    assert prop.status == "proposed" and prop.proposal_id is not None
    assert renamed.refresh().name != "agent_overrides_a_real_name"
    entries = list(p.history(run_id="run-test-1"))
    assert entries and all(e.author_kind == "agent" and e.run_id == "run-test-1" for e in entries)
    assert p.proposals() and p.proposals()[0].id == prop.proposal_id
    undone = p.undo_run()
    assert undone.undone_entry_ids
    assert default_named.refresh().name.startswith("FUN_")
    with pytest.raises(kraken.KrakenError):  # agents cannot decide proposals
        p.accept_proposal(prop.proposal_id)


def test_undo_run_needs_a_run_for_users(project) -> None:
    with pytest.raises(kraken.InvalidArgumentError):
        project.undo_run()


def test_comments(project) -> None:
    project.analyze()
    fn = project.function(0x101030)
    for kind in ("plate", "pre", "eol", "post", "repeatable"):
        assert fn.set_comment(kind, f"{kind} note").status == "applied"
    got = {c.kind: c.text for c in fn.comments()}
    assert got["plate"] == "plate note" and got["eol"] == "eol note"
    assert all(c.untrusted and c.text.untrusted for c in fn.comments())
    fn.set_comment("plate", "")
    assert "plate" not in {c.kind for c in fn.comments()}
    with pytest.raises(kraken.InvalidArgumentError, match="comment kind"):
        fn.set_comment("sideways", "x")


def test_generic_call_validates_against_the_schema(project) -> None:
    project.analyze()
    out = project.call("get_function", address=0x101030)  # int becomes 0x101030
    assert out["name"] == "free" and out["name"].untrusted
    with pytest.raises(kraken.InvalidArgumentError) as e:
        project.call("get_function", address="101030")
    assert e.value.details["path"] == "/address" and "0x401000" in e.value.message
    with pytest.raises(kraken.InvalidArgumentError, match="missing required argument `new_name`"):
        project.call("rename_symbol", address=0x101030)
    with pytest.raises(kraken.InvalidArgumentError, match="unknown argument"):
        project.call("list_functions", limt=3)
    with pytest.raises(kraken.InvalidArgumentError, match="expected integer"):
        project.call("list_functions", limit="three")
    with pytest.raises(kraken.NotFoundError, match="unknown command"):
        project.call("no_such_command")
    with pytest.raises(kraken.InvalidArgumentError, match="not JSON"):
        project.call("get_function", address=object())


def test_engine_errors_map_to_exception_subclasses(project) -> None:
    project.analyze()
    with pytest.raises(kraken.KrakenError) as e:
        project.call("rename_symbol", address=0x999999, new_name="x")
    assert type(e.value) is not kraken.KrakenError and e.value.code == type(e.value).code


def test_data_helpers(project) -> None:
    project.analyze()
    data = project.read_bytes(0x101000, 16)
    assert isinstance(data, bytes) and len(data) == 16
    insns = list(project.disassemble(function=0x101030))
    assert insns and all(i.untrusted for i in insns)
    assert insns[0].address == 0x101030 and isinstance(insns[0].bytes, bytes) and insns[0].text
    assert len(list(project.disassemble(0x101030, page_size=2))) >= 2
    with pytest.raises(kraken.InvalidArgumentError):
        project.disassemble()
    xs = list(project.xrefs(0x101030, "to"))
    assert all(x.target == 0x101030 for x in xs)
    callers = list(project.function(0x101030).callers())
    assert len(callers) == len([x for x in xs if x.kind == "call"])
    g = project.cfg(0x101000)
    assert g.blocks and g.function == 0x101000
    strs = list(project.strings())
    assert strs and all(s.untrusted for s in strs)
    only = list(project.strings("ld-linux"))
    assert only and all("ld-linux" in str(s).lower() for s in only)
    assert any(b.name == ".text" for b in project.memory_map())
    imports = list(project.imports())
    assert imports and all(i.untrusted for i in imports)
    assert list(project.exports()) is not None


def test_job_wait_cancels_the_job_on_ctrl_c(project) -> None:
    job = project.analyze(wait=False)
    real = project.call
    calls: list[str] = []

    def flaky(command, /, **args):
        calls.append(command)
        if command == "job_await" and calls.count("job_await") == 1:
            raise KeyboardInterrupt
        return real(command, **args)

    with mock.patch.object(project, "call", flaky):
        with pytest.raises(KeyboardInterrupt):
            job.wait()
    assert "job_cancel" in calls


def test_job_timeout_raises_and_leaves_the_job(project) -> None:
    job = project.analyze(wait=False)
    real = project.call

    def never_done(command, /, **args):
        out = real(command, **args)
        if command == "job_await":
            out = {**out, "status": "running"}
        return out

    with mock.patch.object(project, "call", never_done):
        with pytest.raises(kraken.KrakenTimeoutError) as e:
            job.wait(timeout=0.3, poll=0.05)
    assert e.value.details == {"job_id": job.job_id}
    job.wait()


def test_two_projects_share_one_connection(fake_project) -> None:
    a, b = fake_project(), fake_project()
    a.analyze()
    assert a.info().analysis_phase == "complete"
    assert b.info().analysis_phase == "not_started"
    a.function(0x101020).rename("only_in_a")
    assert b.function(0x101020).name != "only_in_a"
