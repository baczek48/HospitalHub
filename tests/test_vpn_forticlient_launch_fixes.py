"""Stage 9: regression tests for the four FortiClient launch fixes.

The fixes were made deliberately in *both* places — the legacy
`_open_forticlient_gui` and `FortiClientProvider.launch` — so every test here
runs both against the same described machine and checks the corrected
contract on each side:

A. an ``INSTALLDIR`` that is empty, not text or not an existing directory never
   becomes ``cwd`` (shared rule: :func:`launch_rules.choose_launch_cwd`);
B. a created process whose observation fails is not a failed launch — the pid
   is kept, ``process_started`` / ``observation_failed`` say what happened;
C. explorer → fallback → success is readable attempt by attempt;
D. ``fallback`` means "this attempt ran because an earlier one failed".

Not fixed on purpose (and asserted as such): the Documents folder, the 4 s and
3 s timeouts, the late-explorer race, the probe raising right after explorer.

The harness (fake machine, recording trace, autouse tripwire against any real
process/sleep/status call) is shared with ``test_vpn_forticlient_launch.py``.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import launch_rules  # noqa: E402
import vpn_connect  # noqa: E402
from vpn import VpnRequest  # noqa: E402
from vpn.providers import FortiClientProvider  # noqa: E402
from tests.test_vpn_forticlient_detect import (  # noqa: E402
    DIR_32, DIR_64, FORTI_KEY, GUI_32, GUI_64, LNK,
)
from tests.test_vpn_forticlient_launch import (  # noqa: E402,F401
    EXPL, EXPLORER, FAKE_SECRETS, POPEN, SPAWN64, W3, W4, FakeLaunchSystem,
    legacy_semantics, machine, no_real_system, run_both, run_legacy, run_new,
)


def both(make, monkeypatch, app_path=""):
    """(legacy semantics, new semantics, legacy calls, new calls, raw legacy)."""
    legacy_machine, new_machine = make(), make()
    raw = run_legacy(legacy_machine, app_path, monkeypatch)
    result = run_new(new_machine, app_path)
    from tests.test_vpn_forticlient_launch import new_semantics
    return (legacy_semantics(raw), new_semantics(result), legacy_machine.calls,
            new_machine.calls, raw, result)


def spawn_cwds(calls):
    return [c[2] for c in calls if c[0] == "spawn"]


def launch_steps(raw):
    return [s for s in raw["steps"] if s["step"] == "vpn.launch"]


GHOST = r"D:\Stara\FortiClient"


# ══════════════════════════════════════════════════════════════════════════
# A. cwd
# ══════════════════════════════════════════════════════════════════════════

def test_1_empty_installdir_never_becomes_cwd(monkeypatch):
    make = machine(lnk=False, registry={FORTI_KEY: {"INSTALLDIR": ""}})
    legacy, new, lcalls, ncalls, raw, result = both(make, monkeypatch)
    assert spawn_cwds(lcalls) == spawn_cwds(ncalls) == [DIR_64]
    assert legacy["cwd_source"] == new["cwd_source"] == "exe_dir"
    assert launch_rules.choose_launch_cwd("", GUI_64, lambda p: p == DIR_64) == (
        DIR_64, "exe_dir")


def test_2_missing_installdir_never_becomes_cwd(monkeypatch):
    make = machine(lnk=False, installed=False,
                   registry={FORTI_KEY: {"INSTALLDIR": GHOST}},
                   files=[GUI_32], dirs=[DIR_32])
    legacy, new, lcalls, ncalls, raw, result = both(make, monkeypatch)
    assert GHOST not in spawn_cwds(lcalls) + spawn_cwds(ncalls)
    assert spawn_cwds(lcalls) == spawn_cwds(ncalls) == [DIR_32]


def test_3_valid_executable_launches_despite_bad_installdir(monkeypatch):
    """Before stage 9 both sides returned launch-failed (WinError 267)."""
    make = machine(lnk=False, installed=False,
                   registry={FORTI_KEY: {"INSTALLDIR": GHOST}},
                   files=[GUI_32], dirs=[DIR_32])
    legacy, new, *_ , raw, result = both(make, monkeypatch)
    assert legacy == new
    assert (new["success"], new["started"], new["error_code"]) == (True, True, None)
    assert raw["ok"] is True


@pytest.mark.parametrize("value", [5, b"C:\\Program Files", ["C:\\x"], 0])
def test_4_non_text_installdir_is_never_a_cwd(value, monkeypatch):
    make = machine(lnk=False, registry={FORTI_KEY: {"INSTALLDIR": value}})
    legacy, new, lcalls, ncalls, raw, result = both(make, monkeypatch)
    assert legacy == new and new["success"] is True
    assert spawn_cwds(lcalls) == spawn_cwds(ncalls) == [DIR_64]


def test_4b_rule_rejects_without_touching_the_disk():
    def no_io(path):
        raise AssertionError(f"is_dir nie powinno być wołane dla {path!r}")

    for bad in ("", None, 5, b"x", ["x"]):
        cwd, source = launch_rules.choose_launch_cwd(bad, "", no_io)
        assert (cwd, source) == (None, "inherited")


def test_4c_rule_keeps_the_preference_order():
    dirs = {DIR_64, DIR_32}
    is_dir = dirs.__contains__
    assert launch_rules.choose_launch_cwd(DIR_64, GUI_32, is_dir) == (DIR_64, "install_dir")
    assert launch_rules.choose_launch_cwd(GHOST, GUI_32, is_dir) == (DIR_32, "exe_dir")
    assert launch_rules.choose_launch_cwd(GHOST, r"E:\x\FortiClient.exe", is_dir) == (
        None, "inherited")


# ══════════════════════════════════════════════════════════════════════════
# B. Process created vs. observation failed
# ══════════════════════════════════════════════════════════════════════════

def test_5_spawn_ok_then_probe_raises_is_not_a_start_failure(monkeypatch):
    make = machine(lnk=False, wait_raises=(3.0,))
    legacy, new, lcalls, ncalls, raw, result = both(make, monkeypatch)
    assert legacy == new
    assert new["success"] is True and new["error_code"] is None
    assert (new["process_started"], new["observation_failed"], new["pid"]) == (
        True, True, 4242)
    assert new["started"] is None, "nie wiemy, czy proces widać — nie zgadujemy"
    attempt = result.attempts[-1]
    assert attempt.error_code == "process-started-but-observation-failed"
    assert attempt.reason_code == "RuntimeError"
    step = launch_steps(raw)[-1]
    assert step["status"] == "warn" and step["pid"] == 4242
    assert step["error_code"] == "process-started-but-observation-failed"
    assert raw["msg"].startswith("Otwarto FortiClient")


def test_6_real_popen_failure_still_fails(monkeypatch):
    make = machine(lnk=False, popen="raises")
    legacy, new, lcalls, ncalls, raw, result = both(make, monkeypatch)
    assert legacy == new
    assert new["success"] is False
    assert new["error_code"] == "process-start-failed"
    assert (new["process_started"], new["observation_failed"], new["pid"]) == (
        False, False, None)
    assert "wait" not in [c[0] for c in ncalls], "nie obserwujemy procesu, który nie powstał"
    assert raw["msg"].startswith("Błąd uruchamiania FortiClient")
    assert launch_steps(raw)[-1]["status"] == "fail"


def test_6b_trace_distinguishes_the_two_cases():
    ok = run_new(machine(lnk=False, wait_raises=(3.0,))(), "").to_trace_data()
    bad = run_new(machine(lnk=False, popen="raises")(), "").to_trace_data()
    assert ok["process_started"] is True and ok["observation_failed"] is True
    assert bad["process_started"] is False and "observation_failed" not in bad


def test_6c_new_trace_keys_survive_the_production_redactor(tmp_path, monkeypatch):
    """vpn_connect never imports vpn/, so the keys must be allowed in diagnostics."""
    import diagnostics
    from diagnostics import vpn as vpn_diag

    monkeypatch.setenv(diagnostics.DIR_ENV_VAR, str(tmp_path / "diag"))
    diagnostics.reset_for_tests()
    try:
        m = machine(explorer="documents", wait_raises=(3.0,))()
        # Reuse the legacy wiring, but with a real diagnostics trace.
        from tests.test_vpn_forticlient_launch import _os_shim, FakeWinreg, _Proc
        monkeypatch.setattr(vpn_connect, "winreg", FakeWinreg(m.env))
        monkeypatch.setattr(vpn_connect, "os", _os_shim(m.env))
        monkeypatch.setattr(vpn_connect, "_wait_for_process",
                            lambda name, timeout=3.0: m.wait(name, timeout))
        monkeypatch.setattr(vpn_connect.subprocess, "Popen",
                            lambda cmd, *a, **k: _Proc(m.explorer(cmd[1]))
                            if cmd[0] == "explorer.exe" else _Proc(m.spawn(cmd[0], k["cwd"])))
        trace = vpn_diag.start("vpn.launch_test", provider="FortiClient")
        ok, _ = vpn_connect._open_forticlient_gui("", tr=trace)
        trace.finish("ok")
        text = diagnostics.get_store().read_jsonl()
    finally:
        diagnostics.reset_for_tests()
    assert ok is True
    for fragment in ('"process_started": true', '"observation_failed": true',
                     '"fallback_from": "explorer_lnk"', '"cwd_source": "install_dir"',
                     '"process-started-but-observation-failed"', '"pid": 4242'):
        assert fragment in text, fragment


# ══════════════════════════════════════════════════════════════════════════
# C + D. Fallback semantics
# ══════════════════════════════════════════════════════════════════════════

def test_7_fallback_after_explorer_is_marked(monkeypatch):
    legacy, new, lcalls, ncalls, raw, result = both(machine(explorer="documents"),
                                                    monkeypatch)
    assert legacy == new
    first, second = result.attempts
    assert (first.strategy, first.started, first.fallback) == (EXPL, False, False)
    assert first.error_code == "launch-no-process"
    assert (second.strategy, second.fallback, second.fallback_from) == (POPEN, True, EXPL)
    assert result.success and result.started and result.fallback
    trace = result.to_trace_data()
    assert trace["strategies"] == "explorer_lnk,popen_clean_env"
    assert trace["fallback"] is True and trace["fallback_from"] == "explorer_lnk"
    steps = launch_steps(raw)
    assert [s.get("fallback", False) for s in steps] == [False, True]
    assert steps[1]["fallback_from"] == "explorer_lnk"


@pytest.mark.parametrize("make", [machine(lnk=False), machine(),
                                  machine(lnk=False, popen="raises")],
                         ids=["no-lnk", "explorer-succeeds", "no-lnk-spawn-fails"])
def test_8_no_fallback_is_not_marked_as_fallback(make, monkeypatch):
    legacy, new, lcalls, ncalls, raw, result = both(make, monkeypatch)
    assert legacy == new
    assert all(a.fallback is False and a.fallback_from is None for a in result.attempts)
    assert new["fallback"] is False and "fallback" not in result.to_trace_data()
    assert all(s.get("fallback", False) is False for s in launch_steps(raw))


# ══════════════════════════════════════════════════════════════════════════
# 9–11. pid, cost, secrets
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("make,pid", [
    (machine(lnk=False, pid=5151), 5151),
    (machine(explorer="documents", pid=6161), 6161),
    (machine(lnk=False, wait_raises=(3.0,), pid=7171), 7171),
])
def test_9_final_result_keeps_the_pid(make, pid, monkeypatch):
    legacy, new, lcalls, ncalls, raw, result = both(make, monkeypatch)
    assert legacy["pid"] == new["pid"] == result.pid == pid
    assert result.to_trace_data()["pid"] == pid


@pytest.mark.parametrize("make", [
    machine(lnk=False, registry={FORTI_KEY: {"INSTALLDIR": GHOST}}),
    machine(lnk=False, wait_raises=(3.0,)),
    machine(explorer="documents"),
    machine(lnk=False, popen="raises"),
])
def test_10_fixes_add_no_process_or_polling(make, monkeypatch):
    legacy, new, lcalls, ncalls, *_ = both(make, monkeypatch)
    assert lcalls == ncalls
    kinds = [c[0] for c in ncalls]
    assert kinds.count("spawn") <= 1 and kinds.count("explorer") <= 1
    assert kinds.count("wait") <= 2
    assert all(c[2] in (4.0, 3.0) for c in ncalls if c[0] == "wait")
    # autouse tripwire: no real subprocess, sleep, tasklist or status probe.


def test_10b_timeouts_and_explorer_mechanism_unchanged():
    from vpn.providers import forticlient as fc
    assert (fc.EXPLORER_WAIT_S, fc.POPEN_WAIT_S) == (4.0, 3.0)
    source = ast.unparse(next(
        n for n in ast.walk(ast.parse(open(os.path.join(_PARENT, "vpn_connect.py"),
                                           encoding="utf-8").read()))
        if isinstance(n, ast.FunctionDef) and n.name == "_open_forticlient_gui"))
    assert "subprocess.Popen(['explorer.exe', _FORTI_LNK])" in source
    assert "_wait_for_process('FortiClient.exe', timeout=4.0)" in source
    assert "_wait_for_process('FortiClient.exe', timeout=3.0)" in source


def test_11_no_secrets_in_results_or_traces(monkeypatch):
    monkeypatch.setenv("_MEIPASS2", "SuperSecret123")
    request = VpnRequest(provider_id="forticlient", login="jkowalski",
                         password="SuperSecret123", token="ABC123", group="123456",
                         domain="-----BEGIN PRIVATE KEY-----")
    for make in (machine(lnk=False, wait_raises=(3.0,)), machine(lnk=False, popen="raises"),
                 machine(lnk=False, registry={FORTI_KEY: {"INSTALLDIR": GHOST}})):
        m = make()
        result = FortiClientProvider(m.env, system=FakeLaunchSystem(m)).launch(request)
        raw = run_legacy(make(), "", monkeypatch)
        blob = f"{result!r} {result.to_trace_data()} {launch_steps(raw)}"
        for secret in FAKE_SECRETS + ("jkowalski",):
            assert secret not in blob
        assert "Errno" not in blob and "ACCESS_DENIED" not in blob, "tylko typ wyjątku"


# ══════════════════════════════════════════════════════════════════════════
# 12. Corrected contract, and what stays unfixed
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name,make", [
    ("bad-installdir", machine(lnk=False, installed=False, files=[GUI_32], dirs=[DIR_32],
                               registry={FORTI_KEY: {"INSTALLDIR": GHOST}})),
    ("empty-installdir", machine(lnk=False, registry={FORTI_KEY: {"INSTALLDIR": ""}})),
    ("probe-raises-after-popen", machine(lnk=False, wait_raises=(3.0,))),
    ("explorer-fallback", machine(explorer="documents")),
    ("no-fallback", machine(lnk=False)),
])
def test_12_legacy_and_provider_share_the_corrected_contract(name, make, monkeypatch):
    legacy, new, lcalls, ncalls, *_ = both(make, monkeypatch)
    assert legacy == new and lcalls == ncalls
    assert new["success"] is True


def test_12b_documents_bug_is_still_reproducible(monkeypatch):
    """Explorer that opens a folder still costs a 4 s wait and a fallback."""
    legacy, new, lcalls, ncalls, *_ = both(machine(explorer="documents"), monkeypatch)
    assert lcalls[:2] == ncalls[:2] == [EXPLORER, W4]
    assert new["attempts"][0][3] == "launch-no-process"


def test_12c_probe_raising_after_explorer_is_still_unfixed(monkeypatch):
    make = machine(wait_raises=(4.0,))
    assert legacy_semantics(run_legacy(make(), "", monkeypatch)) == {"raised": "RuntimeError"}
    assert run_new(make(), "").error_code == "launch-failed"


def test_production_legacy_imports_the_rule_not_the_new_architecture():
    tree = ast.parse(open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read())
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert "launch_rules" in modules
    assert not any(m and (m == "vpn" or m.startswith("vpn.")) for m in modules)
    rule_tree = ast.parse(open(launch_rules.__file__, encoding="utf-8").read())
    rule_imports = {a.name for n in ast.walk(rule_tree) if isinstance(n, ast.Import)
                    for a in n.names}
    assert rule_imports == {"os"}, "reguła bez subprocess, bez vpn, bez vpn_connect"
