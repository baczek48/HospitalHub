"""FortiClient launch: does the migrated provider start the client like the legacy?

Nothing real is launched, ever.  Both implementations run against the same
*described machine* — a fake registry/filesystem plus a fake process table —
built fresh for each side, so the legacy and the provider each "launch" their
own copy and never the real FortiClient (and never two at once):

* the legacy `_open_forticlient_gui` sees the machine through patched
  `winreg`, `os`, `subprocess.Popen` and `_wait_for_process` inside
  `vpn_connect`, and reports through a recording trace;
* :class:`FortiClientProvider` sees it through its environment and
  :class:`LaunchSystem` seams.

The comparison is semantic — success, strategy, started, fallback, pid,
requires_user_action, error_code and the ordered attempts — plus the exact
sequence of system calls each side made.

An autouse tripwire blocks every real process/launch/sleep API, so a
forgotten stub fails the test instead of starting a client.
"""

import ast
import copy
import os
import subprocess
import sys
import time

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import vpn  # noqa: E402
import vpn_connect  # noqa: E402
from vpn import (  # noqa: E402
    Capability, LaunchResult, VpnRequest, check_contract, record_result,
)
from vpn.providers import FortiClientProvider  # noqa: E402
from vpn.providers import forticlient as fc  # noqa: E402
from vpn.providers import launch_system as ls  # noqa: E402
from vpn.types import LaunchAttempt  # noqa: E402
from tests.test_vpn_forticlient_detect import (  # noqa: E402
    DIR_32, DIR_64, FORTI_KEY, GUI_32, GUI_64, LNK, FakeEnvironment,
    FakeWinreg, _os_shim,
)

FAKE_SECRETS = ("SuperSecret123", "ABC123", "123456", "-----BEGIN PRIVATE KEY-----")


# ══════════════════════════════════════════════════════════════════════════
# Tripwire: no real process, shell, sleep or status probe in this module
# ══════════════════════════════════════════════════════════════════════════

TRIPPED = []

LEGACY_FORBIDDEN = ("get_status", "_check_adapter_status", "_get_status_from_log",
                    "_is_process_running", "_is_fortivpn_cli_supported",
                    "_wait_forticlient_window", "_autofill_forticlient",
                    "_shell_launch", "invalidate_adapter_cache")


def _tripwire(name):
    def _hit(*a, **k):
        TRIPPED.append(name)
        raise AssertionError(f"test dotknął prawdziwego systemu: {name}")
    return _hit


@pytest.fixture(autouse=True)
def no_real_system(monkeypatch):
    TRIPPED.clear()
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, _tripwire(f"subprocess.{name}"))
    if hasattr(os, "startfile"):
        monkeypatch.setattr(os, "startfile", _tripwire("os.startfile"))
    monkeypatch.setattr(time, "sleep", _tripwire("time.sleep"))
    for name in LEGACY_FORBIDDEN + ("_wait_for_process",):
        monkeypatch.setattr(vpn_connect, name, _tripwire(name))
    monkeypatch.setattr(vpn_connect, "_dbg", lambda *a, **k: None)
    from diagnostics import vpn as vpn_diag
    monkeypatch.setattr(vpn_diag, "note_status", _tripwire("note_status"))
    monkeypatch.setattr(vpn_diag, "mark_status_source", _tripwire("mark_status_source"))
    yield
    assert TRIPPED == [], f"prawdziwe wywołania systemowe: {TRIPPED}"


# ══════════════════════════════════════════════════════════════════════════
# A described machine: registry + disk + process table
# ══════════════════════════════════════════════════════════════════════════

class FakeMachine:
    """What happens when something is launched on an imaginary machine.

    explorer: "starts"    the .lnk really starts FortiClient
              "documents" explorer opens a folder, no FortiClient (hijacked .lnk)
              "raises"    spawning explorer.exe itself fails
    popen:    "starts" | "no-process" | "raises"
    wait_raises: timeouts (4.0 / 3.0) at which the process probe raises
    """

    def __init__(self, env, explorer="starts", popen="starts", wait_raises=(),
                 running=False, pid=4242):
        self.env = env
        self.explorer_mode = explorer
        self.popen_mode = popen
        self.wait_raises = set(wait_raises)
        self.running = running
        self.pid = pid
        self.calls = []

    def explorer(self, path):
        self.calls.append(("explorer", path))
        if self.explorer_mode == "raises":
            raise FileNotFoundError(2, "explorer.exe")
        if self.explorer_mode == "starts":
            self.running = True

    def spawn(self, exe, cwd):
        self.calls.append(("spawn", exe, cwd))
        # CreateProcess semantics: cwd=None inherits the caller's directory;
        # anything else must be text naming an existing directory.
        if cwd is not None:
            if not isinstance(cwd, str):
                raise TypeError("cwd must be str")
            if not self.env.is_dir(cwd):
                raise NotADirectoryError(267, "The directory name is invalid")
        if self.popen_mode == "raises":
            raise PermissionError(5, "ERROR_ACCESS_DENIED")
        if self.popen_mode == "starts":
            self.running = True
        return self.pid

    def wait(self, name, timeout):
        self.calls.append(("wait", name, timeout))
        if timeout in self.wait_raises:
            raise RuntimeError("tasklist padł")
        return self.running


class FakeLaunchSystem(ls.LaunchSystem):
    def __init__(self, machine):
        self.machine = machine

    def open_with_explorer(self, path):
        self.machine.explorer(path)

    def spawn_detached(self, exe, cwd):
        return self.machine.spawn(exe, cwd)

    def wait_for_process(self, image_name, timeout):
        return self.machine.wait(image_name, timeout)


class _Proc:
    def __init__(self, pid):
        self.pid = pid


class RecordingTrace:
    """Same call surface as diagnostics.vpn.VpnTrace, keeps steps in memory."""

    def __init__(self):
        self.steps = []

    def step(self, name, status="ok", error_code=None, **data):
        self.steps.append({"step": name, "status": status,
                           "error_code": error_code, **data})
        return self

    def ok(self, name, **data):
        return self.step(name, "ok", **data)

    def warn(self, name, message=None, **data):
        return self.step(name, "warn", **data)

    def fail(self, name, error_code=None, **data):
        return self.step(name, "fail", error_code, **data)

    def child(self, *a, **k):
        return self

    def finish(self, *a, **k):
        return None


def machine(*, lnk=True, installed=True, registry=None, files=(), dirs=(), **behaviour):
    """Factory: every call builds an identical, independent machine."""
    def make():
        reg = dict(registry) if registry is not None else (
            {FORTI_KEY: {"INSTALLDIR": DIR_64}} if installed else {})
        all_files = list(files) + ([GUI_64] if installed else []) + ([LNK] if lnk else [])
        all_dirs = list(dirs) + ([DIR_64] if installed else [])
        return FakeMachine(FakeEnvironment(registry=reg, files=all_files,
                                           dirs=all_dirs), **behaviour)
    return make


# ══════════════════════════════════════════════════════════════════════════
# Running each side
# ══════════════════════════════════════════════════════════════════════════

def run_legacy(m: FakeMachine, app_path, monkeypatch):
    monkeypatch.setattr(vpn_connect, "winreg", FakeWinreg(m.env))
    monkeypatch.setattr(vpn_connect, "os", _os_shim(m.env))
    monkeypatch.setattr(vpn_connect, "_wait_for_process",
                        lambda name, timeout=3.0: m.wait(name, timeout))

    def fake_popen(cmd, *a, **k):
        if cmd[0] == "explorer.exe":
            m.explorer(cmd[1])
            return _Proc(None)
        return _Proc(m.spawn(cmd[0], k.get("cwd")))

    monkeypatch.setattr(vpn_connect.subprocess, "Popen", fake_popen)
    trace = RecordingTrace()
    try:
        ok, msg = vpn_connect._open_forticlient_gui(app_path, tr=trace)
    except Exception as exc:
        return {"raised": type(exc).__name__, "steps": trace.steps}
    finally:
        monkeypatch.setattr(vpn_connect.subprocess, "Popen", _tripwire("subprocess.Popen"))
    return {"ok": ok, "msg": msg, "steps": trace.steps}


def run_new(m: FakeMachine, app_path, request=None) -> LaunchResult:
    provider = FortiClientProvider(m.env, system=FakeLaunchSystem(m))
    return provider.launch(request or VpnRequest(provider_id="forticlient",
                                                 app_path=app_path))


def legacy_semantics(outcome) -> dict:
    """Normalise (ok, message) + trace steps — the legacy is not reshaped."""
    if "raised" in outcome:
        return {"raised": outcome["raised"]}
    launches = [s for s in outcome["steps"] if s["step"] == "vpn.launch"]
    attempts = tuple((s["strategy"], s.get("started"), bool(s.get("fallback")),
                      s.get("error_code"), s.get("pid"), s.get("process_started"),
                      bool(s.get("observation_failed")), s.get("fallback_from"),
                      s.get("cwd_source"))
                     for s in launches)
    last = launches[-1] if launches else {}
    msg = outcome["msg"]
    failed_steps = [s for s in launches if s["status"] == "fail"]
    if outcome["ok"]:
        error_code = None
    elif msg.startswith("Nie znaleziono FortiClient"):
        error_code = "client-not-found"
    elif failed_steps and failed_steps[-1] is last:
        error_code = last["error_code"]            # e.g. process-start-failed
    elif msg.startswith("Błąd uruchamiania FortiClient"):
        error_code = "launch-failed"
    else:
        error_code = f"unrecognised:{msg[:20]}"
    return {
        "success": outcome["ok"],
        "strategy": last.get("strategy"),
        "started": last.get("started"),
        "fallback": bool(last.get("fallback")),
        "fallback_from": last.get("fallback_from"),
        "pid": last.get("pid"),
        "process_started": last.get("process_started"),
        "observation_failed": bool(last.get("observation_failed")),
        "cwd_source": last.get("cwd_source"),
        "requires_user_action": bool(outcome["ok"])
        and "połącz się w oknie klienta" in msg,
        "error_code": error_code,
        "attempts": attempts,
    }


def new_semantics(result: LaunchResult) -> dict:
    last = result.attempts[-1] if result.attempts else None
    return {
        "success": result.success,
        "strategy": result.strategy,
        "started": result.started,
        "fallback": result.fallback,
        "fallback_from": last.fallback_from if last else None,
        "pid": result.pid,
        "process_started": result.process_started,
        "observation_failed": result.observation_failed,
        "cwd_source": last.cwd_source if last else None,
        "requires_user_action": result.requires_user_action,
        "error_code": result.error_code,
        "attempts": tuple((a.strategy, a.started, a.fallback, a.error_code, a.pid,
                           a.process_started, a.observation_failed,
                           a.fallback_from, a.cwd_source)
                          for a in result.attempts),
    }


def run_both(make, monkeypatch, app_path=""):
    legacy_machine, new_machine = make(), make()
    legacy = legacy_semantics(run_legacy(legacy_machine, app_path, monkeypatch))
    result = run_new(new_machine, app_path)
    return legacy, new_semantics(result), legacy_machine.calls, new_machine.calls, result


# ══════════════════════════════════════════════════════════════════════════
# 10. Parity table
# ══════════════════════════════════════════════════════════════════════════

W4 = ("wait", "FortiClient.exe", 4.0)
W3 = ("wait", "FortiClient.exe", 3.0)
EXPLORER = ("explorer", LNK)
SPAWN64 = ("spawn", GUI_64, DIR_64)
EXPL, POPEN = "explorer_lnk", "popen_clean_env"

SCENARIOS = [
    # Stage 9: legacy and provider share the corrected contract.  Each entry:
    # id, machine, app_path, expected semantics subset, expected call sequence.
    # "attempts" in the expectation compares (strategy, started, fallback,
    # error_code) per attempt; the parity assertion compares everything.
    ("A-explorer-starts", machine(), "",
     dict(success=True, strategy=EXPL, started=True, fallback=False,
          process_started=True, requires_user_action=True, error_code=None,
          attempts=((EXPL, True, False, None),)),
     [EXPLORER, W4]),
    ("A2-no-lnk-popen-is-first-not-a-fallback", machine(lnk=False), "",
     dict(success=True, strategy=POPEN, started=True, fallback=False,
          fallback_from=None, pid=4242, cwd_source="install_dir", error_code=None,
          attempts=((POPEN, True, False, None),)),
     [SPAWN64, W3]),
    ("B-explorer-documents-then-popen", machine(explorer="documents"), "",
     dict(success=True, strategy=POPEN, started=True, fallback=True,
          fallback_from=EXPL, pid=4242, requires_user_action=True,
          attempts=((EXPL, False, False, "launch-no-process"),
                    (POPEN, True, True, None))),
     [EXPLORER, W4, SPAWN64, W3]),
    ("C-explorer-raises-then-popen", machine(explorer="raises"), "",
     dict(success=True, strategy=POPEN, started=True, fallback=True,
          fallback_from=EXPL,
          attempts=((EXPL, False, False, "launch-failed"),
                    (POPEN, True, True, None))),
     [EXPLORER, SPAWN64, W3]),
    ("C2-popen-spawns-but-no-process-still-success",
     machine(explorer="documents", popen="no-process"), "",
     dict(success=True, strategy=POPEN, started=False, fallback=True,
          process_started=True, requires_user_action=True, error_code=None),
     [EXPLORER, W4, SPAWN64, W3]),
    ("D-explorer-fails-and-no-executable",
     machine(explorer="documents", installed=False), "",
     dict(success=False, strategy=EXPL, started=False,
          requires_user_action=False, error_code="client-not-found",
          attempts=((EXPL, False, False, "launch-no-process"),)),
     [EXPLORER, W4]),
    ("D2-explorer-raises-and-popen-raises",
     machine(explorer="raises", popen="raises"), "",
     dict(success=False, strategy=POPEN, started=False, fallback=True,
          process_started=False, error_code="process-start-failed",
          attempts=((EXPL, False, False, "launch-failed"),
                    (POPEN, False, True, "process-start-failed"))),
     [EXPLORER, SPAWN64]),
    ("D3-nothing-at-all", machine(lnk=False, installed=False), "",
     dict(success=False, strategy=None, started=None, error_code="client-not-found",
          attempts=()),
     []),
    ("E-popen-started-user-must-log-in", machine(lnk=False, pid=5151), "",
     dict(success=True, requires_user_action=True, pid=5151, started=True),
     [SPAWN64, W3]),
    ("F-spawn-permission-denied", machine(lnk=False, popen="raises"), "",
     dict(success=False, error_code="process-start-failed", started=False,
          process_started=False, pid=None, fallback=False),
     [SPAWN64]),
    ("F2-probe-raises-after-spawn-pid-kept",
     machine(lnk=False, wait_raises=(3.0,)), "",
     dict(success=True, error_code=None, pid=4242, started=None,
          process_started=True, observation_failed=True, requires_user_action=True,
          attempts=((POPEN, None, False, "process-started-but-observation-failed"),)),
     [SPAWN64, W3]),
    ("F3-fallback-then-probe-raises",
     machine(explorer="documents", wait_raises=(3.0,)), "",
     dict(success=True, pid=4242, fallback=True, fallback_from=EXPL,
          observation_failed=True),
     [EXPLORER, W4, SPAWN64, W3]),
    ("G-already-running-explorer-false-positive",
     machine(explorer="documents", running=True), "",
     dict(success=True, strategy=EXPL, started=True, fallback=False),
     [EXPLORER, W4]),
    ("H-lnk-wins-over-configured-app-path",
     machine(files=[r"D:\Inny\FortiClient.exe"]), r"D:\Inny\FortiClient.exe",
     dict(success=True, strategy=EXPL),
     [EXPLORER, W4]),
    ("H2-app-path-used-when-no-lnk",
     machine(lnk=False, files=[r"D:\Inny\FortiClient.exe"]), r"D:\Inny\FortiClient.exe",
     dict(success=True, strategy=POPEN, cwd_source="install_dir"),
     [("spawn", r"D:\Inny\FortiClient.exe", DIR_64), W3]),
    ("I-fixed-ghost-installdir-not-used-as-cwd",
     machine(lnk=False, registry={FORTI_KEY: {"INSTALLDIR": r"D:\Duch"}},
             installed=False, files=[GUI_32], dirs=[DIR_32]), "",
     dict(success=True, strategy=POPEN, started=True, cwd_source="exe_dir"),
     [("spawn", GUI_32, DIR_32), W3]),
    ("I2-fixed-non-text-installdir-not-used-as-cwd",
     machine(lnk=False, registry={FORTI_KEY: {"INSTALLDIR": 5}}), "",
     dict(success=True, cwd_source="exe_dir"),
     [SPAWN64, W3]),
    ("I3-key-without-installdir-uses-known-dir",
     machine(lnk=False, registry={FORTI_KEY: {"Language": "pl"}}), "",
     dict(success=True, strategy=POPEN, cwd_source="install_dir"),
     [SPAWN64, W3]),
    ("I4-empty-installdir-not-used-as-cwd",
     machine(lnk=False, registry={FORTI_KEY: {"INSTALLDIR": ""}}), "",
     dict(success=True, cwd_source="exe_dir"),
     [SPAWN64, W3]),
    ("I5-no-usable-directory-inherits-cwd",
     machine(lnk=False, installed=False, registry={FORTI_KEY: {"INSTALLDIR": ""}},
             files=["FortiClient.exe"]), "",
     dict(success=True, cwd_source="inherited"),
     [("spawn", "FortiClient.exe", None), W3]),
]


@pytest.mark.parametrize("make,app_path,expected,calls",
                         [s[1:] for s in SCENARIOS], ids=[s[0] for s in SCENARIOS])
def test_parity_legacy_vs_new(make, app_path, expected, calls, monkeypatch):
    """Legacy and provider — both fixed in stage 9 — honour the same contract."""
    legacy, new, legacy_calls, new_calls, _ = run_both(make, monkeypatch, app_path)
    assert new == legacy, f"rozjazd semantyki:\nlegacy={legacy}\nnew   ={new}"
    assert new_calls == legacy_calls, (
        f"rozjazd wywołań systemowych:\nlegacy={legacy_calls}\nnew   ={new_calls}")
    for key, value in expected.items():
        actual = (tuple(a[:4] for a in new["attempts"]) if key == "attempts"
                  else new[key])
        assert actual == value, f"{key}: {actual!r} != {value!r}"
    assert new_calls == calls


def test_parity_difference_probe_raising_after_explorer(monkeypatch):
    """The one documented difference: the legacy lets this exception escape.

    `_wait_for_process` after `explorer.exe` sits outside the legacy `try`,
    so a failing probe propagates out of `_open_forticlient_gui` (and up into
    `connect()`).  The provider contract forbids raising: same failure, as data.
    """
    make = machine(wait_raises=(4.0,))
    legacy_machine, new_machine = make(), make()
    assert legacy_semantics(run_legacy(legacy_machine, "", monkeypatch)) == {
        "raised": "RuntimeError"}
    result = run_new(new_machine, "")
    assert result.success is False
    assert result.error_code == "launch-failed"
    assert result.metadata["reason_code"] == "RuntimeError"
    assert result.attempts == ()
    assert new_machine.calls == legacy_machine.calls == [EXPLORER, W4]


# ══════════════════════════════════════════════════════════════════════════
# 1–8. Behaviour of the migrated launch
# ══════════════════════════════════════════════════════════════════════════

def test_1_basic_strategy_launches():
    result = run_new(machine()(), "")
    assert result.success and result.error_code is None
    assert result.strategy == "explorer_lnk"


def test_2_explorer_lnk_works():
    m = machine()()
    result = run_new(m, "")
    assert m.calls == [EXPLORER, W4], "żadnego Popen, gdy .lnk zadziałał"
    assert result.started is True and result.fallback is False
    assert len(result.attempts) == 1


def test_3_explorer_without_process_falls_back():
    """The "opens Documents instead of FortiClient" machine."""
    m = machine(explorer="documents")()
    result = run_new(m, "")
    first = result.attempts[0]
    assert (first.strategy, first.started, first.error_code) == (
        "explorer_lnk", False, "launch-no-process")
    assert m.calls[:2] == [EXPLORER, W4] and m.calls[2][0] == "spawn"


def test_4_fallback_succeeds():
    result = run_new(machine(explorer="documents")(), "")
    assert result.success is True
    assert (result.strategy, result.started, result.fallback) == (
        "popen_clean_env", True, True)
    assert [a.strategy for a in result.attempts] == ["explorer_lnk", "popen_clean_env"]
    trace = result.to_trace_data()
    assert trace["strategies"] == "explorer_lnk,popen_clean_env"
    assert trace["attempt_count"] == 2


def test_5_strategies_keep_their_order():
    m = machine(explorer="documents")()
    run_new(m, "")
    kinds = [c[0] for c in m.calls]
    assert kinds == ["explorer", "wait", "spawn", "wait"]
    assert [c[2] for c in m.calls if c[0] == "wait"] == [4.0, 3.0]

    m = machine(lnk=False)()
    run_new(m, "")
    assert "explorer" not in [c[0] for c in m.calls], "bez .lnk nie ma etapu explorer"


def test_6_pid_is_passed_through():
    result = run_new(machine(lnk=False, pid=5151)(), "")
    assert result.pid == 5151 and result.attempts[-1].pid == 5151
    assert result.to_trace_data()["pid"] == 5151
    assert run_new(machine()(), "").pid is None, "explorer nie zna pid klienta"


def test_7_started_means_process_seen_not_launch_succeeded():
    # Spawned, no process within 3 s: legacy still reports success.
    result = run_new(machine(lnk=False, popen="no-process")(), "")
    assert (result.success, result.started) == (True, False)
    # A FortiClient that was already running makes explorer look successful.
    result = run_new(machine(explorer="documents", running=True)(), "")
    assert (result.strategy, result.started) == ("explorer_lnk", True)


@pytest.mark.parametrize("make,code", [
    (machine(lnk=False, installed=False), "client-not-found"),
    (machine(explorer="documents", installed=False), "client-not-found"),
    (machine(lnk=False, popen="raises"), "process-start-failed"),     # stage 9
])
def test_8_failure_returns_the_right_error_code(make, code):
    result = run_new(make(), "")
    assert result.success is False and result.error_code == code
    assert result.requires_user_action is False


# ══════════════════════════════════════════════════════════════════════════
# 9–11. Robustness and safety
# ══════════════════════════════════════════════════════════════════════════

def test_9_missing_client_does_not_raise_or_touch_the_system():
    class Exploding(ls.LaunchSystem):
        def __getattribute__(self, name):
            raise AssertionError(f"brak klienta, a launch dotknął systemu: {name}")

    env = FakeEnvironment()
    result = FortiClientProvider(env, system=Exploding()).launch(
        VpnRequest(provider_id="forticlient"))
    assert result.error_code == "client-not-found" and result.attempts == ()
    assert FortiClientProvider(env, system=Exploding()).launch(None).success is False


@pytest.mark.parametrize("exc", [OSError(5, "x"), PermissionError(5, "x"),
                                 RuntimeError("x"), ValueError("x")])
def test_10_system_exceptions_become_results(exc):
    class Raising(FakeLaunchSystem):
        def spawn_detached(self, exe, cwd):
            raise exc

    m = machine(lnk=False)()
    result = FortiClientProvider(m.env, system=Raising(m)).launch(
        VpnRequest(provider_id="forticlient"))
    assert result.success is False and result.error_code == "process-start-failed"
    assert result.process_started is False
    assert result.attempts[-1].reason_code == type(exc).__name__
    blob = f"{result!r} {result.to_trace_data()}"
    assert "Errno" not in blob, "tylko typ wyjątku, nigdy jego komunikat"


def test_10b_environment_exception_becomes_a_result():
    class BrokenEnv(FakeEnvironment):
        def is_file(self, path):
            raise OSError("dysk niedostępny")

    m = machine()()
    result = FortiClientProvider(BrokenEnv(), system=FakeLaunchSystem(m)).launch(None)
    assert (result.success, result.error_code) == (False, "launch-failed")
    assert result.metadata["reason_code"] == "OSError"
    assert m.calls == []


def test_11_result_contains_no_secrets_paths_or_environment(monkeypatch):
    monkeypatch.setenv("_MEIPASS2", "SuperSecret123")
    request = VpnRequest(provider_id="forticlient", login="jkowalski",
                         password="SuperSecret123", token="ABC123",
                         group="123456", domain="-----BEGIN PRIVATE KEY-----",
                         app_path=GUI_64)
    m = machine(explorer="documents")()
    result = FortiClientProvider(m.env, system=FakeLaunchSystem(m)).launch(request)
    blob = f"{result!r} {result.to_trace_data()} {m.calls}"
    for secret in FAKE_SECRETS + ("jkowalski",):
        assert secret not in blob
    trace = str(result.to_trace_data())
    assert "FortiClient.exe" not in trace and ".lnk" not in trace, "bez ścieżek w trace"
    assert set(result.to_trace_data()) <= {
        "strategy", "started", "pid", "fallback", "requires_user_action",
        "strategies", "attempt_count", "reason_code", "process_started",
        "observation_failed", "fallback_from", "cwd_source"}


def test_11b_trace_data_survives_the_existing_redactor(tmp_path, monkeypatch):
    import diagnostics
    from diagnostics import vpn as vpn_diag

    monkeypatch.setenv(diagnostics.DIR_ENV_VAR, str(tmp_path / "diag"))
    diagnostics.reset_for_tests()
    try:
        trace = vpn_diag.start("vpn.launch", provider="forticlient")
        record_result(trace, "vpn.launch", run_new(machine(explorer="documents")(), ""))
        trace.finish("ok")
        text = diagnostics.get_store().read_jsonl()
        assert '"strategies": "explorer_lnk,popen_clean_env"' in text
        assert '"requires_user_action": true' in text and '"pid": 4242' in text
    finally:
        diagnostics.reset_for_tests()


def test_11c_clean_environment_drops_pyinstaller_variables():
    env = ls.clean_pyinstaller_env({"PATH": "x", "_MEIPASS2": "y", "_PYI_X": "z"})
    assert env == {"PATH": "x"}


# ══════════════════════════════════════════════════════════════════════════
# 12–13. No status polling, no extra waiting
# ══════════════════════════════════════════════════════════════════════════

def test_12_launch_does_no_status_polling():
    # The autouse tripwire blocks get_status, adapters, log, tasklist, CLI probe.
    for make in (machine(), machine(explorer="documents"), machine(lnk=False),
                 machine(lnk=False, installed=False)):
        run_new(make(), "")
    source = open(fc.__file__, encoding="utf-8").read()
    tree = ast.parse(source)
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for forbidden in ("get_status", "tasklist", "netstat", "_check_adapter_status",
                      "_is_fortivpn_cli_supported", "sleep", "Popen", "startfile"):
        assert forbidden not in names


def test_13_launch_waits_only_where_the_legacy_waits():
    for make, waits in ((machine(), [4.0]), (machine(explorer="documents"), [4.0, 3.0]),
                        (machine(explorer="raises"), [3.0]),
                        (machine(lnk=False, installed=False), [])):
        m = make()
        run_new(m, "")
        assert [c[2] for c in m.calls if c[0] == "wait"] == waits


def test_13b_real_wait_returns_without_sleeping_when_process_is_there(monkeypatch):
    system = ls.WindowsLaunchSystem()
    monkeypatch.setattr(system, "is_process_running", lambda name: True)
    assert system.wait_for_process("FortiClient.exe", 4.0) is True   # sleep tripwired


def test_13c_real_wait_polls_every_quarter_second_until_timeout(monkeypatch):
    clock = [0.0]
    sleeps = []
    system = ls.WindowsLaunchSystem()
    monkeypatch.setattr(system, "is_process_running", lambda name: False)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])

    def fake_sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(time, "sleep", fake_sleep)
    assert system.wait_for_process("FortiClient.exe", 1.0) is False
    assert sleeps == [0.25] * 4


# ══════════════════════════════════════════════════════════════════════════
# 14–15. Legacy state and the production path are untouched
# ══════════════════════════════════════════════════════════════════════════

def _legacy_mutable_state():
    return {name: copy.deepcopy(value) for name, value in vars(vpn_connect).items()
            if isinstance(value, (dict, list, set)) and not name.startswith("__")}


def test_14_launch_does_not_change_legacy_state():
    before = _legacy_mutable_state()
    lnk_before = vpn_connect._FORTI_LNK
    for scenario in SCENARIOS:
        run_new(scenario[1](), scenario[2])
    assert _legacy_mutable_state() == before
    assert vpn_connect._FORTI_LNK == lnk_before


def test_14b_launch_never_loads_the_legacy_module(monkeypatch):
    code = r"""
import sys, vpn
from vpn.providers.forticlient import FortiClientProvider, DetectionEnvironment
from vpn.providers.launch_system import LaunchSystem
GUI = r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe"
DIR = r"C:\Program Files\Fortinet\FortiClient"
class Env(DetectionEnvironment):
    def registry_value(self, s, n): return None
    def registry_key_exists(self, s): return False
    def registry_subkeys(self, s): return []
    def is_file(self, p): return p == GUI
    def is_dir(self, p): return p == DIR
class System(LaunchSystem):
    def open_with_explorer(self, p): raise AssertionError
    def spawn_detached(self, exe, cwd): return 7
    def wait_for_process(self, name, timeout): return True
r = FortiClientProvider(Env(), system=System()).launch(None)
print(r.success, r.strategy, 'vpn_connect' in sys.modules)
"""
    assert _run_python(code, monkeypatch) == "True popen_clean_env False"


#: The real `subprocess.run`/`Popen`, captured at import — before the autouse
#: tripwire replaces them — so a test can start a fresh *Python* interpreter
#: (`run` calls the module-level `Popen`, so both must be real for that call).
_REAL_SUBPROCESS_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen


def _run_python(code, monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    completed = _REAL_SUBPROCESS_RUN([sys.executable, "-c", code], cwd=_PARENT,
                                     capture_output=True, text=True, timeout=60)
    monkeypatch.setattr(subprocess, "Popen", _tripwire("subprocess.Popen"))
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def test_15_production_connect_still_uses_legacy_launch(tmp_path, monkeypatch):
    import diagnostics
    monkeypatch.setenv(diagnostics.DIR_ENV_VAR, str(tmp_path / "diag"))
    diagnostics.reset_for_tests()

    legacy_calls = []
    monkeypatch.setattr(vpn_connect, "_open_forticlient_gui",
                        lambda app_path="", tr=None: legacy_calls.append(app_path)
                        or (True, "Otwarto FortiClient — połącz się w oknie klienta."))
    monkeypatch.setattr(vpn_connect, "_wait_forticlient_window", lambda timeout=10.0: None)
    monkeypatch.setattr(vpn_connect, "_fill_forti_auth_window", lambda *a, **k: (False, ""))
    monkeypatch.setattr(vpn_connect, "_is_fortivpn_cli_supported", lambda *a, **k: False)
    monkeypatch.setattr(vpn_connect, "find_executable", lambda *a, **k: None)
    monkeypatch.setattr(vpn_connect, "_copy_to_clipboard", lambda *a, **k: True)
    monkeypatch.setattr(FortiClientProvider, "launch",
                        _tripwire("FortiClientProvider.launch"))
    try:
        ok, msg = vpn_connect.connect("FortiClient", "", "", "", "",
                                      profile_name="SZPITAL-A", autofill=False)
    finally:
        diagnostics.reset_for_tests()
    assert ok is True and legacy_calls == [""]


def test_15b_legacy_launch_call_sites_are_unchanged():
    tree = ast.parse(open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read())
    callers = set()
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef):
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == "_open_forticlient_gui"):
                    callers.add(fn.name)
    assert callers == {"connect", "disconnect", "launch_app"}
    source = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    for token in ("FortiClientProvider", "launch_system", "default_registry"):
        assert token not in source


def test_15c_registry_does_not_drive_launch():
    assert not hasattr(vpn.VpnRegistry, "launch")
    provider = vpn.default_registry.get("forticlient")
    assert provider.capabilities() == Capability.LAUNCH
    assert check_contract(provider) == []
    request = VpnRequest(provider_id="forticlient")
    for call in (provider.connect, provider.disconnect, provider.status):
        assert call(request).error_code == "unsupported"


# ══════════════════════════════════════════════════════════════════════════
# The seam itself mirrors the legacy calls
# ══════════════════════════════════════════════════════════════════════════

def _function(name):
    tree = ast.parse(open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read())
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == name)


def test_constants_match_the_legacy_launcher():
    fn = _function("_open_forticlient_gui")
    calls = sorted((c for c in ast.walk(fn)             # ast.walk is breadth-first
                    if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                    and c.func.id == "_wait_for_process"), key=lambda c: c.lineno)
    waits = [(ast.literal_eval(c.args[0]),
              ast.literal_eval(next(k.value for k in c.keywords if k.arg == "timeout")))
             for c in calls]
    assert waits == [(fc.GUI_EXE_NAME, fc.EXPLORER_WAIT_S),
                     (fc.GUI_EXE_NAME, fc.POPEN_WAIT_S)]
    strategies = {k.value.value for c in ast.walk(fn) if isinstance(c, ast.Call)
                  for k in c.keywords
                  if k.arg == "strategy" and isinstance(k.value, ast.Constant)}
    assert strategies == {fc.STRATEGY_EXPLORER_LNK, fc.STRATEGY_POPEN_CLEAN_ENV}
    source = ast.unparse(fn)
    assert "subprocess.Popen(['explorer.exe', _FORTI_LNK])" in source
    assert "subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP" in source
    assert "close_fds=True" in source and "env=_clean_pyinstaller_env()" in source
    assert "ShellExecute" not in source and "startfile" not in source, (
        "legacy FortiClient launch nie używa ShellExecuteW ani os.startfile")


def test_seam_constants_match_the_legacy_process_probe():
    wait_src = ast.unparse(_function("_wait_for_process"))
    probe_src = ast.unparse(_function("_is_process_running"))
    assert f"time.sleep({ls.POLL_INTERVAL_S})" in wait_src
    assert f"timeout={ls.TASKLIST_TIMEOUT_S}" in probe_src
    assert "['tasklist', '/FI', f'IMAGENAME eq {exe_name}', '/NH', '/FO', 'CSV']" in probe_src


def test_windows_launch_system_makes_exactly_the_legacy_calls(monkeypatch):
    seen = []

    def fake_popen(cmd, **kwargs):
        seen.append((cmd, kwargs))
        return _Proc(9090)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)   # imported lazily by the seam
    monkeypatch.setenv("_MEIPASS2", "x")
    system = ls.WindowsLaunchSystem()
    system.open_with_explorer(LNK)
    assert system.spawn_detached(GUI_64, DIR_64) == 9090

    assert seen[0] == (["explorer.exe", LNK], {})
    cmd, kwargs = seen[1]
    assert cmd == [GUI_64] and kwargs["cwd"] == DIR_64
    assert kwargs["close_fds"] is True
    assert kwargs["creationflags"] == (subprocess.DETACHED_PROCESS
                                       | subprocess.CREATE_NEW_PROCESS_GROUP)
    assert "_MEIPASS2" not in kwargs["env"]


def test_windows_probe_matches_legacy_and_swallows_errors(monkeypatch):
    seen = []

    class Done:
        stdout = '"FortiClient.exe","1234","Console","1","50,000 K"'

    def fake_run(cmd, **kwargs):
        seen.append(cmd)
        return Done()

    monkeypatch.setattr(subprocess, "run", fake_run)       # imported lazily by the seam
    system = ls.WindowsLaunchSystem()
    assert system.is_process_running("FortiClient.exe") is True
    assert seen[0] == ["tasklist", "/FI", "IMAGENAME eq FortiClient.exe", "/NH", "/FO", "CSV"]

    monkeypatch.setattr(subprocess, "run", _tripwire_quiet)
    assert system.is_process_running("FortiClient.exe") is False


def _tripwire_quiet(*a, **k):
    raise OSError("tasklist niedostępny")


def test_win32_seams_are_the_only_process_or_input_modules_in_vpn():
    """subprocess/ctypes live only in the isolated Win32 seams.

    launch_system starts processes; input_system synthesises keystrokes for
    autofill (Stage 14).  Both are mockable seams — nothing else in vpn/ may
    reach for that machinery directly."""
    vpn_dir = os.path.join(_PARENT, "vpn")
    importers = set()          # the seams import lazily in several methods
    for root, _dirs, files in os.walk(vpn_dir):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            tree = ast.parse(open(path, encoding="utf-8").read())
            for node in ast.walk(tree):
                mods = ([a.name for a in node.names] if isinstance(node, ast.Import)
                        else [node.module] if isinstance(node, ast.ImportFrom)
                        and node.level == 0 and node.module else [])
                if any(m.split(".")[0] in ("subprocess", "ctypes") for m in mods):
                    importers.add(os.path.relpath(path, _PARENT))
    # msaa_system (Stage 62) is the third seam: it reads a window's MSAA tree
    # through oleacc, read-only, and is faked in every test.
    assert importers == {os.path.join("vpn", "providers", "launch_system.py"),
                         os.path.join("vpn", "providers", "input_system.py"),
                         os.path.join("vpn", "providers", "msaa_system.py")}


def test_detection_never_touches_the_launch_system():
    class Exploding(ls.LaunchSystem):
        def __getattribute__(self, name):
            raise AssertionError(f"detect dotknął systemu uruchamiania: {name}")

    m = machine()()
    result = FortiClientProvider(m.env, system=Exploding()).detect(
        VpnRequest(provider_id="forticlient"))
    assert result.state.value == "installed"


def test_launch_attempt_trace_data_is_flat_and_path_free():
    attempt = LaunchAttempt("popen_clean_env", started=False, fallback=True,
                            error_code="launch-failed", reason_code="PermissionError")
    assert attempt.to_trace_data() == {
        "strategy": "popen_clean_env", "started": False, "fallback": True,
        "error_code": "launch-failed", "reason_code": "PermissionError"}
