"""Stage 11: FortiClient connect split into phases — prepared, not migrated.

Two kinds of tests:

* **Parity table** — the legacy `connect_monitored` / `connect` and the new
  :class:`FortiConnectFlow` run the same scenario; each side's outcome (route,
  success, manual action, pending automation, monitor) and its ordered side
  effects (window probe, restore, autofill start, EMS fill, CLI start, legacy
  client, launch, clipboard, session record) must match.  Identical
  implementation is not required; probes (the cached CLI check) are not
  compared.
* **Unit tests** of the split: phase order, decisions, passing results
  between phases, error propagation, 2FA / manual / autofill distinction, and
  that nothing real is touched.

Nothing real runs: the legacy sees patched functions, a fake `win32gui`, a
synchronous `threading.Thread` and a fake `Popen`; the provider sees fake
seams.  The autouse tripwire from the launch tests blocks every real process,
sleep and status call.
"""

import ast
import os
import sys
import threading
from dataclasses import dataclass, replace
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import vpn  # noqa: E402
import vpn_connect  # noqa: E402
from vpn import (  # noqa: E402
    AutomationMode, Capability, ConnectResult, LaunchResult, TwoFactorMode,
    VpnProvider, VpnRequest, VpnState, check_contract,
)
from vpn.providers import FortiClientProvider  # noqa: E402
from vpn.providers import forticlient_connect as fcc  # noqa: E402
from tests.test_vpn_forticlient_detect import (  # noqa: E402
    DIR_64, GUI_64, FakeEnvironment,
)
from tests.test_vpn_forticlient_launch import (  # noqa: E402,F401
    FAKE_SECRETS, RecordingTrace, _tripwire, no_real_system,
)

FORTIVPN = r"C:\Program Files\Fortinet\FortiClient\FortiVPN.exe"
SSLVPN = r"C:\Program Files\Fortinet\FortiClient\FortiSSLVPNclient.exe"
PASSWORD, TOKEN, LOGIN = "SuperSecret123", "ABC123", "jkowalski"
SERVER, PORT = "vpn.szpital-a.pl", "443"
HWND = 4711

MSG_SUBMITTED = "Łączenie przez FortiClient..."
MSG_MANUAL_CONNECT = "Dane wpisane — kliknij Connect ręcznie."
MSG_LAUNCH_OK = "Otwarto FortiClient — połącz się w oknie klienta."
MSG_LAUNCH_FAIL = "Nie znaleziono FortiClient.\nUruchom klienta VPN ręcznie."


@dataclass(frozen=True)
class Scenario:
    entry: str = fcc.ENTRY_CONNECT_MONITORED
    autofill: bool = True
    password: str = PASSWORD
    profile: str = "SZPITAL-A"
    token: str = ""
    requires_2fa: bool = False
    window: bool = False
    auth: str | None = None           # None | "submitted" | "manual"
    cli: bool = False
    cli_raises: bool = False
    sslvpn: bool = False
    legacy_raises: bool = False
    launch_ok: bool = True


# ══════════════════════════════════════════════════════════════════════════
# Legacy side
# ══════════════════════════════════════════════════════════════════════════

class FinishTrace(RecordingTrace):
    def __init__(self):
        super().__init__()
        self.finished = None

    def finish(self, status=None, error_code=None, **result):
        self.finished = {"status": status, "error_code": error_code, **result}


class SyncThread:
    """threading.Thread that runs its target on start() — no real threads."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None, **_):
        self._target, self._args, self._kwargs = target, args, kwargs or {}

    def start(self):
        self._target(*self._args, **self._kwargs)


class RecordingDict(dict):
    def __init__(self, calls, name):
        super().__init__()
        self._calls, self._name = calls, name

    def __setitem__(self, key, value):
        if self._name:
            self._calls.append(("session_record", value))
        super().__setitem__(key, value)


class _Proc:
    def __init__(self, pid):
        self.pid = pid


def run_legacy(sc: Scenario, monkeypatch):
    calls, trace = [], FinishTrace()
    auth_answers = {None: (False, ""), "submitted": (True, MSG_SUBMITTED),
                    "manual": (True, MSG_MANUAL_CONNECT)}

    monkeypatch.setattr(vpn_connect, "_trace_start", lambda *a, **k: trace)
    monkeypatch.setattr(vpn_connect, "_last_connected", RecordingDict(calls, "session"))
    monkeypatch.setattr(vpn_connect, "_last_connected_meta", RecordingDict(calls, ""))
    monkeypatch.setattr(vpn_connect, "_copy_to_clipboard",
                        lambda text: calls.append(("clipboard",)) or True)
    monkeypatch.setattr(vpn_connect, "_wait_forticlient_window",
                        lambda timeout=10.0: calls.append(("window_probe", timeout))
                        or (HWND if sc.window else None))
    monkeypatch.setitem(sys.modules, "win32gui", SimpleNamespace(
        ShowWindow=lambda hwnd, cmd: calls.append(("restore",)),
        SetForegroundWindow=lambda hwnd: None))
    monkeypatch.setattr(threading, "Thread", SyncThread)
    monkeypatch.setattr(vpn_connect, "_autofill_forticlient",
                        lambda login, password, profile_name="", tr=None:
                        calls.append(("autofill_start", profile_name)))
    monkeypatch.setattr(vpn_connect, "_fill_forti_auth_window",
                        lambda login, password, timeout=3.0:
                        calls.append(("ems_fill", timeout)) or auth_answers[sc.auth])
    monkeypatch.setattr(vpn_connect, "_is_fortivpn_cli_supported",
                        lambda app_path="": sc.cli)
    monkeypatch.setattr(vpn_connect, "_find_fortivpn",
                        lambda app_path="": FORTIVPN if sc.cli else None)
    monkeypatch.setattr(vpn_connect, "find_executable",
                        lambda provider: SSLVPN if sc.sslvpn else None)

    def fake_popen(cmd, *a, **k):
        if "--cli" in cmd:
            calls.append(("cli_start", k.get("stdin") is not None,
                          cmd[cmd.index("--tunnel") + 1], "--token" in cmd))
            if sc.cli_raises:
                raise OSError(5, "ERROR_ACCESS_DENIED")
            return _Proc(777)
        calls.append(("legacy_start", cmd[3]))
        if sc.legacy_raises:
            raise OSError(2, "missing")
        return _Proc(778)

    monkeypatch.setattr(vpn_connect.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(vpn_connect, "_open_forticlient_gui",
                        lambda app_path="", tr=None: calls.append(("launch", app_path))
                        or ((True, MSG_LAUNCH_OK) if sc.launch_ok
                            else (False, MSG_LAUNCH_FAIL)))

    args = ("FortiClient", SERVER, PORT, LOGIN, sc.password, "", "", GUI_64, sc.profile)
    if sc.entry == fcc.ENTRY_CONNECT_MONITORED:
        ok, msg, process = vpn_connect.connect_monitored(*args, token=sc.token,
                                                         autofill=sc.autofill)
    else:
        ok, msg = vpn_connect.connect(*args, autofill=sc.autofill)
        process = None
    monkeypatch.setattr(vpn_connect.subprocess, "Popen", _tripwire("subprocess.Popen"))
    return ok, msg, process, trace, calls


LEGACY_ROUTES = {
    "autofill-started": fcc.ROUTE_WINDOW_RESTORE,
    "window-restored": fcc.ROUTE_WINDOW_RESTORE,
    "ems-auth-filled": fcc.ROUTE_EMS_AUTH_WINDOW,
    "legacy-launched": fcc.ROUTE_LEGACY_CLIENT,
    "gui-launched+autofill": fcc.ROUTE_GUI_LAUNCH,
    "gui-launched": fcc.ROUTE_GUI_LAUNCH,
}


def legacy_semantics(ok, msg, process, trace, calls) -> dict:
    """Normalise the legacy tuple + trace; the legacy is not reshaped."""
    finished = trace.finished or {}
    strategies = [s.get("strategy") for s in trace.steps if s["step"] == "vpn.launch"]
    if finished.get("result") == "cli-launched" or (
            not ok and strategies and strategies[-1] == "fortivpn_cli_monitored"):
        route = (fcc.ROUTE_CLI_MONITORED if "fortivpn_cli_monitored" in strategies
                 else fcc.ROUTE_CLI)
    elif not ok:
        route = fcc.ROUTE_GUI_LAUNCH
    else:
        route = LEGACY_ROUTES[finished["result"]]
    return {
        "success": bool(ok),
        "route": route,
        "requires_user_action": bool(ok) and ("hasło w schowku" in msg
                                              or "kliknij Connect ręcznie" in msg),
        "automation_pending": finished.get("result") in ("autofill-started",
                                                         "gui-launched+autofill"),
        "monitor": process is not None,
        "calls": calls,
    }


# ══════════════════════════════════════════════════════════════════════════
# New side
# ══════════════════════════════════════════════════════════════════════════

class FakeConnectSystem(fcc.FortiConnectSystem):
    def __init__(self, sc: Scenario, calls, raise_in=None, restore_raises=False):
        self.sc, self.calls = sc, calls
        self.raise_in, self.restore_raises = raise_in, restore_raises
        self.probes = 0
        self.seen_credentials = []

    def _hit(self, name, *detail):
        if name == self.raise_in:
            raise RuntimeError(f"{name} padło")
        self.calls.append((name, *detail))

    def record_session(self, profile_name, server):
        self._hit("session_record", profile_name)

    def copy_to_clipboard(self, text):
        self.seen_credentials.append(text)
        self._hit("clipboard")
        return True

    def find_main_window(self, timeout):
        self._hit("window_probe", timeout)
        return HWND if self.sc.window else None

    def restore_window(self, handle):
        self._hit("restore")
        if self.restore_raises:
            raise OSError("SetForegroundWindow")

    def start_autofill(self, login, password, profile_name):
        self.seen_credentials += [login, password]
        self._hit("autofill_start", profile_name)

    def fill_auth_window(self, login, password, timeout):
        self._hit("ems_fill", timeout)
        return fcc.AuthWindowFill(found=self.sc.auth is not None,
                                  submitted=self.sc.auth == "submitted")

    def cli_supported(self, app_path):
        self.probes += 1
        if self.raise_in == "cli_probe":
            raise RuntimeError("sonda padła")
        return self.sc.cli

    def start_cli(self, fortivpn, profile_name, login, password, token, monitored):
        assert fortivpn == FORTIVPN
        self._hit("cli_start", monitored, profile_name, bool(token))
        if self.sc.cli_raises:
            raise OSError(5, "ERROR_ACCESS_DENIED")
        return _Proc(777) if monitored else None

    def start_legacy_client(self, exe, address, login, password):
        assert exe == SSLVPN
        self._hit("legacy_start", address)
        if self.sc.legacy_raises:
            raise OSError(2, "missing")


class ScriptedLaunchProvider(FortiClientProvider):
    """The provider with launch replaced by a script (launch has its own tests)."""

    def __init__(self, sc, calls, launch_error="client-not-found", **kwargs):
        super().__init__(**kwargs)
        self._sc, self._calls, self._launch_error = sc, calls, launch_error

    def launch(self, request=None):
        self._calls.append(("launch", request.app_path))
        if self._sc.launch_ok:
            return LaunchResult(provider_id=self.id, success=True,
                                strategy="popen_clean_env", started=True, pid=4242,
                                requires_user_action=True)
        return LaunchResult(provider_id=self.id, success=False,
                            error_code=self._launch_error)


def request_for(sc: Scenario) -> VpnRequest:
    return VpnRequest(provider_id="forticlient", profile_name=sc.profile,
                      server=SERVER, port=PORT, login=LOGIN, password=sc.password,
                      app_path=GUI_64, token=sc.token, autofill=sc.autofill,
                      requires_2fa=sc.requires_2fa)


def run_new(sc: Scenario, **system_kwargs):
    calls = []
    files = [GUI_64] + ([FORTIVPN] if sc.cli else []) + ([SSLVPN] if sc.sslvpn else [])
    system = FakeConnectSystem(sc, calls, **{k: v for k, v in system_kwargs.items()
                                             if k in ("raise_in", "restore_raises")})
    provider = ScriptedLaunchProvider(
        sc, calls, launch_error=system_kwargs.get("launch_error", "client-not-found"),
        environment=FakeEnvironment(files=files, dirs=[DIR_64]),
        system=_tripwire_launch_system(), connect_system=system)
    result = provider.connect(request_for(sc), entry=sc.entry)
    return result, calls, system


def _tripwire_launch_system():
    from vpn.providers.launch_system import LaunchSystem

    class Tripwire(LaunchSystem):
        def __getattribute__(self, name):
            raise AssertionError(f"connect dotknął prawdziwego launchera: {name}")
    return Tripwire()


def new_semantics(result: ConnectResult, calls) -> dict:
    return {
        "success": result.success,
        "route": result.route,
        "requires_user_action": result.requires_user_action,
        "automation_pending": result.automation_pending,
        "monitor": result.monitor is not None,
        "calls": calls,
    }


# ══════════════════════════════════════════════════════════════════════════
# Parity table
# ══════════════════════════════════════════════════════════════════════════

S = Scenario
W = ("window_probe", 0.5)
E = ("ems_fill", 0.1)
SESSION = ("session_record", "SZPITAL-A")
LAUNCH = ("launch", GUI_64)
AUTOFILL = ("autofill_start", "SZPITAL-A")

TABLE = [
    # id, scenario, route, success, manual, pending, monitor, side effects
    ("M1-cli-monitored", S(cli=True),
     fcc.ROUTE_CLI_MONITORED, True, False, False, True,
     [("cli_start", True, "SZPITAL-A", False)]),
    ("M2-cli-monitored-fails-no-fallback", S(cli=True, cli_raises=True),
     fcc.ROUTE_CLI_MONITORED, False, False, False, False,
     [("cli_start", True, "SZPITAL-A", False)]),
    ("M3-cli-monitored-empty-profile-legacy-bug", S(cli=True, profile=""),
     fcc.ROUTE_CLI_MONITORED, True, False, False, True,
     [("cli_start", True, "", False)]),
    ("M4-cli-but-autofill-off-goes-manual", S(cli=True, autofill=False),
     fcc.ROUTE_GUI_LAUNCH, True, True, False, False,
     [SESSION, ("clipboard",), W, LAUNCH]),
    # Stage 22: the window is NOT raised any more.  Bringing it forward is a
    # foreground steal that Windows refuses from a background process (Stages
    # 18-20), so the flow waits for the user to activate it instead — recorded
    # as LEGACY_BEHAVIOR "window-restore-dropped" and as the parity entry
    # "window-already-open-not-raised".  Everything else about the route is
    # unchanged, which is why these rows still exist.
    ("M5-window-open-autofill", S(window=True),
     fcc.ROUTE_WINDOW_RESTORE, True, False, True, False,
     [SESSION, W, AUTOFILL]),
    ("M6-window-open-manual", S(window=True, autofill=False),
     fcc.ROUTE_WINDOW_RESTORE, True, True, False, False,
     [SESSION, ("clipboard",), W]),
    ("M7-ems-window-submitted", S(auth="submitted"),
     fcc.ROUTE_EMS_AUTH_WINDOW, True, False, False, False, [SESSION, W, E]),
    ("M8-ems-window-no-connect-button", S(auth="manual"),
     fcc.ROUTE_EMS_AUTH_WINDOW, True, True, False, False, [SESSION, W, E]),
    ("M9-legacy-sslvpn-client", S(sslvpn=True),
     fcc.ROUTE_LEGACY_CLIENT, True, False, False, False,
     [SESSION, W, E, ("legacy_start", f"{SERVER}:{PORT}")]),
    ("M10-legacy-client-fails-falls-to-gui", S(sslvpn=True, legacy_raises=True),
     fcc.ROUTE_GUI_LAUNCH, True, False, True, False,
     [SESSION, W, E, ("legacy_start", f"{SERVER}:{PORT}"), LAUNCH, AUTOFILL]),
    ("M11-gui-launch-autofill", S(),
     fcc.ROUTE_GUI_LAUNCH, True, False, True, False, [SESSION, W, E, LAUNCH, AUTOFILL]),
    ("M12-launch-fails", S(launch_ok=False),
     fcc.ROUTE_GUI_LAUNCH, False, False, False, False, [SESSION, W, E, LAUNCH]),
    ("M13-manual-without-password-no-clipboard", S(autofill=False, password=""),
     fcc.ROUTE_GUI_LAUNCH, True, True, False, False, [SESSION, W, LAUNCH]),
    ("M14-cli-monitored-passes-token", S(cli=True, token=TOKEN),
     fcc.ROUTE_CLI_MONITORED, True, False, False, True,
     [("cli_start", True, "SZPITAL-A", True)]),
    ("C1-connect-entry-cli", S(entry=fcc.ENTRY_CONNECT, cli=True),
     fcc.ROUTE_CLI, True, False, False, False,
     [SESSION, W, E, ("cli_start", False, "SZPITAL-A", False)]),
    ("C2-connect-entry-cli-fails-falls-through", S(entry=fcc.ENTRY_CONNECT, cli=True,
                                                    cli_raises=True),
     fcc.ROUTE_GUI_LAUNCH, True, False, True, False,
     [SESSION, W, E, ("cli_start", False, "SZPITAL-A", False), LAUNCH, AUTOFILL]),
    ("C3-connect-entry-cli-needs-profile", S(entry=fcc.ENTRY_CONNECT, cli=True, profile=""),
     fcc.ROUTE_GUI_LAUNCH, True, False, True, False,
     [("session_record", ""), W, E, ("launch", GUI_64), ("autofill_start", "")]),
    ("C4-connect-entry-cli-fails-then-legacy-client",
     S(entry=fcc.ENTRY_CONNECT, cli=True, cli_raises=True, sslvpn=True),
     fcc.ROUTE_LEGACY_CLIENT, True, False, False, False,
     [SESSION, W, E, ("cli_start", False, "SZPITAL-A", False),
      ("legacy_start", f"{SERVER}:{PORT}")]),
]


@pytest.mark.parametrize("sc,route,success,manual,pending,monitor,effects",
                         [t[1:] for t in TABLE], ids=[t[0] for t in TABLE])
def test_parity_legacy_vs_new_flow(sc, route, success, manual, pending, monitor,
                                   effects, monkeypatch):
    legacy = legacy_semantics(*run_legacy(sc, monkeypatch))
    result, calls, _ = run_new(sc)
    new = new_semantics(result, calls)

    # Stage 22 — the one intended divergence, taken out of the comparison
    # deliberately rather than quietly: the legacy raises the client's window,
    # the new flow does not, because that is a foreground steal Windows refuses
    # from a background process (LEGACY_BEHAVIOR "window-restore-dropped").
    # Both halves are asserted, so neither side can drift unnoticed.
    raised = [call for call in legacy["calls"] if call == ("restore",)]
    if sc.window:
        assert raised == [("restore",)], "legacy nadal podnosi okno klienta"
        assert ("restore",) not in new["calls"], "nowy flow już tego nie robi"
        legacy["calls"] = [c for c in legacy["calls"] if c != ("restore",)]
    else:
        assert raised == [], "bez otwartego okna nikt niczego nie podnosi"

    assert new == legacy, f"rozjazd:\nlegacy={legacy}\nnew   ={new}"
    assert (new["route"], new["success"], new["requires_user_action"],
            new["automation_pending"], new["monitor"]) == (
        route, success, manual, pending, monitor)
    assert new["calls"] == effects


# ══════════════════════════════════════════════════════════════════════════
# Phase order and decisions
# ══════════════════════════════════════════════════════════════════════════

def phases(result):
    return [(s.phase, s.status) for s in result.steps]


def test_phase_order_monitored_entry_through_gui():
    # `detect` is the Stage-16 head of the sequence: recorded, never fatal
    # (the legacy discovers the client by trying, and still does below).
    result, _, system = run_new(S())
    assert phases(result) == [
        ("detect", "ok"), ("cli_probe", "none"), ("session_record", "ok"),
        ("window_probe", "none"), ("auth_window_fill", "none"),
        ("launch", "ok"), ("autofill_start", "ok")]
    assert system.probes == 1, "CLI sondowane raz (legacy: dwa razy, drugi z cache)"


def test_phase_order_connect_entry_probes_cli_after_ems():
    result, _, _ = run_new(S(entry=fcc.ENTRY_CONNECT))
    assert [p for p, _ in phases(result)] == [
        "detect", "session_record", "window_probe", "auth_window_fill",
        "cli_probe", "launch", "autofill_start"]


def test_manual_entry_still_probes_cli_like_legacy():
    result, _, system = run_new(S(autofill=False))
    assert "cli_probe" in [p for p, _ in phases(result)]
    assert "auth_window_fill" not in [p for p, _ in phases(result)]
    assert system.probes == 1


def test_window_found_skips_ems_cli_and_launch():
    result, calls, system = run_new(S(window=True, cli=False, sslvpn=True))
    assert [c[0] for c in calls] == ["session_record", "window_probe",
                                     "autofill_start"]
    assert system.probes == 1 and result.launch is None


def test_an_open_window_is_never_raised_for_the_user():
    """Stage 22: the flow stopped trying to steal the foreground."""
    _result, calls, _system = run_new(S(window=True))
    assert "restore" not in [c[0] for c in calls]
    ids = {name for name, _kind, _text in fcc.LEGACY_BEHAVIOR}
    assert "window-restore-dropped" in ids, "różnica ma być zapisana, nie cicha"


def test_autofill_off_never_passes_credentials_to_automation_or_cli():
    result, calls, system = run_new(S(autofill=False, cli=True, sslvpn=True, window=False))
    kinds = [c[0] for c in calls]
    assert "cli_start" not in kinds and "legacy_start" not in kinds
    assert "ems_fill" not in kinds and "autofill_start" not in kinds
    assert system.seen_credentials == [PASSWORD], "tylko schowek, jak w legacy"
    assert result.automation is AutomationMode.MANUAL and result.requires_user_action


# ══════════════════════════════════════════════════════════════════════════
# Passing results between phases
# ══════════════════════════════════════════════════════════════════════════

def test_launch_result_is_passed_into_the_connect_result():
    result, _, _ = run_new(S())
    assert result.launch is not None and result.launch.pid == 4242
    assert result.to_trace_data()["launch_strategy"] == "popen_clean_env"


def test_launch_error_code_propagates():
    result, _, _ = run_new(S(launch_ok=False), launch_error="process-start-failed")
    assert (result.success, result.error_code) == (False, "process-start-failed")
    assert result.steps[-1].phase == "launch" and result.steps[-1].status == "failed"
    assert result.launch.error_code == "process-start-failed"


def test_monitored_cli_returns_the_process_but_never_serialises_it():
    result, _, _ = run_new(S(cli=True))
    assert isinstance(result.monitor, _Proc)
    trace = result.to_trace_data()
    assert trace["process_monitor"] is True and "_Proc" not in str(trace)
    assert result.state is VpnState.CONNECTING and result.automation is AutomationMode.CLI


def test_ems_submitted_versus_manual_click():
    submitted, _, _ = run_new(S(auth="submitted"))
    manual, _, _ = run_new(S(auth="manual"))
    assert (submitted.state, submitted.requires_user_action) == (VpnState.CONNECTING, False)
    assert (manual.state, manual.requires_user_action) == (VpnState.UNKNOWN, True)
    assert submitted.automation is manual.automation is AutomationMode.WM_SETTEXT


# ══════════════════════════════════════════════════════════════════════════
# Errors
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("phase", ["session_record", "window_probe", "ems_fill",
                                   "autofill_start", "cli_probe"])
def test_unexpected_seam_exception_is_contained_at_its_phase(phase):
    result, calls, _ = run_new(S(), raise_in=phase)
    expected_phase = {"ems_fill": "auth_window_fill"}.get(phase, phase)
    assert result.success is False and result.error_code == "connect-failed"
    assert result.metadata["reason_code"] == "RuntimeError"
    last = result.steps[-1]
    assert (last.phase, last.status, last.reason_code) == (
        expected_phase, "failed", "RuntimeError")
    if phase != "autofill_start":
        assert ("launch", GUI_64) not in calls, "po błędzie nie idziemy dalej"


def test_the_restore_phase_is_recorded_as_skipped_not_performed():
    """It used to be attempted and its failure swallowed; now it is not tried.

    The phase stays in the record — a trace still has to show which route the
    connect took — but with status "none" and the reason it was skipped.
    """
    result, calls, _ = run_new(S(window=True), restore_raises=True)
    assert result.success and result.route == fcc.ROUTE_WINDOW_RESTORE
    assert ("window_restore", "none") in phases(result)
    skipped = next(step for step in result.steps
                   if step.phase == "window_restore")
    assert skipped.reason_code == "superseded-by-activation-gate"
    assert "restore" not in [c[0] for c in calls], "seam nawet nie wołany"
    assert calls[-1][0] == "autofill_start"


def test_unknown_entry_is_a_result_not_an_exception():
    calls = []
    provider = ScriptedLaunchProvider(S(), calls, environment=FakeEnvironment(),
                                      system=_tripwire_launch_system(),
                                      connect_system=FakeConnectSystem(S(), calls))
    result = provider.connect(request_for(S()), entry="connect_v2")
    assert result.error_code == "connect-failed" and calls == []
    assert result.metadata["reason_code"] == "unknown-entry"


# ══════════════════════════════════════════════════════════════════════════
# Manual authentication / autofill / 2FA
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("kwargs,expected", [
    (dict(route=fcc.ROUTE_CLI_MONITORED, monitor_available=True, autofill=True,
          requires_2fa=False), TwoFactorMode.PROCESS_STDOUT),
    (dict(route=fcc.ROUTE_CLI_MONITORED, monitor_available=False, autofill=True,
          requires_2fa=True), TwoFactorMode.AUTH_WINDOW),
    (dict(route=fcc.ROUTE_GUI_LAUNCH, monitor_available=False, autofill=True,
          requires_2fa=True), TwoFactorMode.AUTH_WINDOW),
    (dict(route=fcc.ROUTE_GUI_LAUNCH, monitor_available=False, autofill=False,
          requires_2fa=True), TwoFactorMode.IN_CLIENT),
    (dict(route=fcc.ROUTE_WINDOW_RESTORE, monitor_available=False, autofill=True,
          requires_2fa=False), TwoFactorMode.NONE),
])
def test_two_factor_plan(kwargs, expected):
    assert fcc.plan_two_factor(**kwargs) is expected


@pytest.mark.parametrize("sc,mode,automation,manual,pending,two_factor", [
    (S(), "autofill", AutomationMode.TAB_SEQUENCE, False, True, TwoFactorMode.NONE),
    (S(autofill=False), "manual", AutomationMode.MANUAL, True, False, TwoFactorMode.NONE),
    (S(requires_2fa=True), "autofill+2fa", AutomationMode.TAB_SEQUENCE, False, True,
     TwoFactorMode.AUTH_WINDOW),
    (S(autofill=False, requires_2fa=True), "manual+2fa", AutomationMode.MANUAL, True,
     False, TwoFactorMode.IN_CLIENT),
    (S(cli=True), "cli", AutomationMode.CLI, False, False, TwoFactorMode.PROCESS_STDOUT),
])
def test_results_distinguish_manual_autofill_and_2fa(sc, mode, automation, manual,
                                                    pending, two_factor):
    result, _, _ = run_new(sc)
    assert result.automation is automation, mode
    assert (result.requires_user_action, result.automation_pending) == (manual, pending)
    assert result.two_factor is two_factor


def test_failures_plan_no_second_factor():
    result, _, _ = run_new(S(launch_ok=False, requires_2fa=True))
    assert result.two_factor is TwoFactorMode.NONE


# ══════════════════════════════════════════════════════════════════════════
# Safety: secrets, nothing real, production untouched
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("sc", [S(), S(cli=True, token=TOKEN), S(autofill=False),
                                S(auth="manual"), S(sslvpn=True), S(launch_ok=False)])
def test_results_carry_no_credentials(sc):
    result, calls, _ = run_new(sc)
    blob = f"{result!r} {result.to_trace_data()} {[s.to_trace_data() for s in result.steps]} {calls}"
    for secret in FAKE_SECRETS + (LOGIN,):
        assert secret not in blob


def test_registered_provider_connect_is_unsupported_and_touches_nothing():
    provider = vpn.default_registry.get("forticlient")
    result = provider.connect(VpnRequest(provider_id="forticlient", login=LOGIN,
                                         password=PASSWORD, autofill=True))
    assert result.error_code == "unsupported" and result.steps == ()
    assert provider.capabilities() == Capability.LAUNCH, "connect nie jest deklarowany"
    assert check_contract(provider) == []


def test_new_flow_module_imports_no_system_machinery():
    tree = ast.parse(open(fcc.__file__, encoding="utf-8").read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported <= {"__future__", "dataclasses", "typing"}
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for forbidden in ("Popen", "sleep", "win32gui", "EnumWindows", "SendMessage",
                      "vpn_connect", "get_status", "Thread"):
        assert forbidden not in names


def test_constants_match_the_legacy_connect():
    tree = ast.parse(open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read())
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "connect")
    source = ast.unparse(fn)
    assert f"_wait_forticlient_window(timeout={fcc.FAST_PATH_WINDOW_TIMEOUT_S})" in source
    assert f"_fill_forti_auth_window(login, password, timeout={fcc.AUTH_WINDOW_TIMEOUT_S})" in source
    monitored = ast.unparse(next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                                 and n.name == "connect_monitored"))
    assert "if autofill and provider == 'FortiClient' and _is_fortivpn_cli_supported(app_path)" in monitored


def test_production_path_does_not_reach_the_new_connect():
    for rel in ("vpn_connect.py", os.path.join("ui", "vpn_panel.py"),
                os.path.join("ui", "detail_panel.py"), "main.py"):
        source = open(os.path.join(_PARENT, rel), encoding="utf-8").read()
        for token in ("forticlient_connect", "FortiConnectFlow", "FortiConnectSystem",
                      "FortiClientProvider"):
            assert token not in source, f"{rel}: {token}"
    for rel in (os.path.join("ui", "vpn_panel.py"), os.path.join("ui", "detail_panel.py")):
        tree = ast.parse(open(os.path.join(_PARENT, rel), encoding="utf-8").read())
        called = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                  and isinstance(n.value, ast.Name) and n.value.id == "vpn_connect"}
        assert "connect_monitored" in called


def test_base_provider_stays_generic():
    source = open(os.path.join(_PARENT, "vpn", "provider.py"), encoding="utf-8").read()
    base = ast.unparse(next(n for n in ast.walk(ast.parse(source))
                            if isinstance(n, ast.ClassDef) and n.name == "VpnProvider"))
    for forti_specific in ("window", "autofill", "FortiVPN", "EMS", "clipboard", "entry"):
        assert forti_specific not in base, forti_specific
    import inspect
    assert list(inspect.signature(VpnProvider.connect).parameters) == ["self", "request"]


def test_legacy_behavior_catalogue_is_complete_and_classified():
    ids = {item[0] for item in fcc.LEGACY_BEHAVIOR}
    kinds = {item[1] for item in fcc.LEGACY_BEHAVIOR}
    assert kinds <= {"security", "bug", "dead-code", "duplication", "legacy", "ui"}
    assert {"autofill-types-without-focus", "auth-window-matched-by-title-only",
            "password-on-command-line", "clipboard-keeps-password"} <= {
        i for i, k, _ in fcc.LEGACY_BEHAVIOR if k == "security"}
    assert {"connect-cli-branch-unreachable-from-ui", "cli-monitored-no-fallback",
            "cli-monitored-empty-profile", "success-means-initiated"} <= ids
    assert len(ids) == len(fcc.LEGACY_BEHAVIOR), "id unikalne"


def test_request_requires_2fa_is_described_without_a_token():
    meta = VpnRequest(provider_id="forticlient", requires_2fa=True).to_trace_meta()
    assert meta["requires_2fa"] is True
    assert replace(VpnRequest(provider_id="x"), token=TOKEN).to_trace_meta()["requires_2fa"]
