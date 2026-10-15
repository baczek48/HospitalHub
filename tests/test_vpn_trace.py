"""Integration tests for the diagnostic traces emitted by the VPN flow.

No real VPN client is started: every seam that touches the system
(`subprocess.Popen`, window waits, clipboard, process probes) is stubbed, and
the tests assert on what ends up in the trace store.

Two properties matter more than the rest and are tested from several angles:

* **the trace must never contain a credential** — the fake secrets below are
  fed through every argument that carries one;
* **diagnostics must never change the outcome** — a broken diagnostics layer
  has to leave connect()/disconnect() returning exactly what they returned
  before.
"""

import json
import os
import sys
import time

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import diagnostics  # noqa: E402
import vpn_connect  # noqa: E402
from diagnostics import vpn as vpn_diag  # noqa: E402

FAKE_PASSWORD = "SuperSecret123"
FAKE_TOKEN = "ABC123"
FAKE_OTP = "123456"
FAKE_KEY_HEADER = "-----BEGIN PRIVATE KEY-----"
FAKE_LOGIN = "jkowalski"
SECRETS = (FAKE_PASSWORD, FAKE_TOKEN, FAKE_OTP, FAKE_KEY_HEADER, FAKE_LOGIN)


# ── fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated_diag(tmp_path, monkeypatch):
    monkeypatch.setenv(diagnostics.DIR_ENV_VAR, str(tmp_path / "diag"))
    diagnostics.reset_for_tests()
    vpn_diag.reset_status_cache()
    yield
    diagnostics.reset_for_tests()
    vpn_diag.reset_status_cache()


@pytest.fixture(autouse=True)
def no_side_effects(monkeypatch):
    """Nothing in these tests may touch the clipboard or spawn a process."""
    monkeypatch.setattr(vpn_connect, "_copy_to_clipboard", lambda *_a, **_k: True)
    monkeypatch.setattr(vpn_connect, "_get_clipboard_text", lambda *_a, **_k: "")
    monkeypatch.setattr(vpn_connect, "_dbg", lambda *_a, **_k: None)


class FakeProc:
    def __init__(self, pid=4242):
        self.pid = pid


def traces(operation=None):
    """All traces in the store, newest first, as parsed JSONL blocks."""
    store = diagnostics.get_store()
    out = []
    for path in store.list_traces():
        lines = [json.loads(l) for l in
                 path.read_text(encoding="utf-8").splitlines() if l.strip()]
        header = lines[0]
        if operation and header.get("operation") != operation:
            continue
        out.append({"header": header, "steps": lines[1:]})
    return out


def steps_of(trace, name=None):
    return [s for s in trace["steps"] if name is None or s.get("step") == name]


def store_text():
    return diagnostics.get_store().read_jsonl()


def wait_for_trace(operation, timeout=3.0):
    """Autofill runs on its own thread — give it a moment to finish."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        found = traces(operation)
        if found:
            return found
        time.sleep(0.02)
    return []


def stub_forticlient_gui(monkeypatch, lnk_path, explorer_starts,
                         popen_ok=True, gui_found=True):
    """Wire up _open_forticlient_gui without touching the real system.

    `explorer_starts` decides whether the explorer.exe/.lnk strategy appears to
    have started FortiClient — the exact condition behind the "opens Documents
    instead of the client" report.
    """
    calls = []
    monkeypatch.setattr(vpn_connect, "_FORTI_LNK", str(lnk_path))
    monkeypatch.setattr(vpn_connect, "_validate_exe", lambda *_a, **_k: (True, ""))
    monkeypatch.setattr(vpn_connect, "_find_forticlient_gui",
                        lambda *_a, **_k: (r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe"
                                           if gui_found else None))
    monkeypatch.setattr(vpn_connect, "_forti_install_dir",
                        lambda *_a, **_k: r"C:\Program Files\Fortinet\FortiClient")

    waits = iter([explorer_starts, True, True, True])

    def fake_wait(_name, timeout=3.0):
        try:
            return next(waits)
        except StopIteration:
            return True

    monkeypatch.setattr(vpn_connect, "_wait_for_process", fake_wait)

    def fake_popen(cmd, *a, **k):
        calls.append(cmd)
        if not popen_ok:
            raise OSError(5, "ERROR_ACCESS_DENIED")
        return FakeProc()

    monkeypatch.setattr(vpn_connect.subprocess, "Popen", fake_popen)
    return calls


def stub_forticlient_connect(monkeypatch, window=None, cli=False):
    monkeypatch.setattr(vpn_connect, "_wait_forticlient_window",
                        lambda timeout=10.0: window)
    monkeypatch.setattr(vpn_connect, "_is_fortivpn_cli_supported",
                        lambda *_a, **_k: cli)
    monkeypatch.setattr(vpn_connect, "find_executable", lambda *_a, **_k: None)
    monkeypatch.setattr(vpn_connect, "_fill_forti_auth_window",
                        lambda *_a, **_k: (False, ""))


# ══════════════════════════════════════════════════════════════════════════
# 1. Successful connect
# ══════════════════════════════════════════════════════════════════════════

def test_successful_connect_writes_trace(tmp_path, monkeypatch):
    lnk = tmp_path / "FortiClient VPN.lnk"
    lnk.write_text("x", encoding="utf-8")
    stub_forticlient_connect(monkeypatch)
    stub_forticlient_gui(monkeypatch, lnk, explorer_starts=True)

    ok, msg = vpn_connect.connect(
        "FortiClient", "vpn.szpital-a.pl", "443", FAKE_LOGIN, FAKE_PASSWORD,
        profile_name="SZPITAL-A", autofill=False)

    assert ok is True
    found = traces("vpn.connect")
    assert len(found) == 1
    header = found[0]["header"]
    assert header["status"] == "ok"
    assert header["meta"]["provider"] == "FortiClient"
    assert header["meta"]["has_credentials"] is True
    assert header["result"]["result"] == "gui-launched"
    names = [s["step"] for s in found[0]["steps"]]
    assert "vpn.window" in names and "vpn.launch" in names
    assert "vpn.automation" in names


def test_trace_records_step_durations(tmp_path, monkeypatch):
    lnk = tmp_path / "FortiClient VPN.lnk"
    lnk.write_text("x", encoding="utf-8")
    stub_forticlient_connect(monkeypatch)
    stub_forticlient_gui(monkeypatch, lnk, explorer_starts=True)

    vpn_connect.connect("FortiClient", "", "", "", "", profile_name="X",
                        autofill=False)
    trace = traces("vpn.connect")[0]
    assert all("duration_ms" in s for s in trace["steps"])
    assert trace["header"]["duration_ms"] >= 0


# ══════════════════════════════════════════════════════════════════════════
# 2. Failed connect
# ══════════════════════════════════════════════════════════════════════════

def test_failed_connect_writes_trace_with_error_code(tmp_path, monkeypatch):
    lnk = tmp_path / "missing.lnk"          # not created on purpose
    stub_forticlient_connect(monkeypatch)
    stub_forticlient_gui(monkeypatch, lnk, explorer_starts=False,
                         gui_found=False)

    ok, msg = vpn_connect.connect("FortiClient", "", "", "", "",
                                  profile_name="SZPITAL-A", autofill=False)

    assert ok is False
    trace = traces("vpn.connect")[0]
    assert trace["header"]["status"] == "fail"
    assert trace["header"]["error_code"] == "client-not-found"
    detect = steps_of(trace, "vpn.detect")[-1]
    assert detect["status"] == "fail"
    assert detect["error_code"] == "client-not-found"
    assert detect["data"]["installed"] is False


def test_generic_provider_without_client_fails_visibly(monkeypatch):
    ok, msg = vpn_connect.connect("Jakiś Inny VPN", "", "", "", "",
                                  app_path="", autofill=False)
    assert ok is False
    trace = traces("vpn.connect")[0]
    assert trace["header"]["error_code"] == "unsupported-provider"


# ══════════════════════════════════════════════════════════════════════════
# 3. FortiClient: explorer_lnk → fallback
# ══════════════════════════════════════════════════════════════════════════

def test_launch_fallback_is_visible_in_trace(tmp_path, monkeypatch):
    """The known "explorer opened Documents" case must be unambiguous."""
    lnk = tmp_path / "FortiClient VPN.lnk"
    lnk.write_text("x", encoding="utf-8")
    stub_forticlient_connect(monkeypatch)
    stub_forticlient_gui(monkeypatch, lnk, explorer_starts=False)

    ok, _ = vpn_connect.connect("FortiClient", "", "", "", "",
                                profile_name="SZPITAL-A", autofill=False)

    assert ok is True
    launches = steps_of(traces("vpn.connect")[0], "vpn.launch")
    assert [l["data"]["strategy"] for l in launches] == [
        "explorer_lnk", "popen_clean_env"]
    assert launches[0]["status"] == "warn"
    assert launches[0]["data"]["started"] is False
    assert launches[0]["data"]["lnk_present"] is True
    assert launches[0]["error_code"] == "launch-no-process"
    assert launches[1]["status"] == "ok"
    assert launches[1]["data"]["started"] is True
    assert launches[1]["data"]["fallback"] is True
    assert launches[1]["data"]["pid"] == 4242


def test_explorer_strategy_success_shows_no_fallback(tmp_path, monkeypatch):
    lnk = tmp_path / "FortiClient VPN.lnk"
    lnk.write_text("x", encoding="utf-8")
    stub_forticlient_connect(monkeypatch)
    stub_forticlient_gui(monkeypatch, lnk, explorer_starts=True)

    vpn_connect.connect("FortiClient", "", "", "", "", profile_name="X",
                        autofill=False)
    launches = steps_of(traces("vpn.connect")[0], "vpn.launch")
    assert len(launches) == 1
    assert launches[0]["data"]["strategy"] == "explorer_lnk"
    assert launches[0]["status"] == "ok"


# ══════════════════════════════════════════════════════════════════════════
# 4. Automation failure
# ══════════════════════════════════════════════════════════════════════════

def test_automation_failure_has_error_code(monkeypatch):
    monkeypatch.setattr(vpn_connect, "_wait_forticlient_window",
                        lambda timeout=10.0: None)
    trace = vpn_diag.start("vpn.autofill", provider="FortiClient",
                           automation_mode="tab_sequence")
    vpn_connect._autofill_forticlient(FAKE_LOGIN, FAKE_PASSWORD, "SZPITAL-A",
                                      tr=trace)

    found = wait_for_trace("vpn.autofill")
    assert found, "trace autofillu nie powstał"
    header = found[0]["header"]
    assert header["status"] == "fail"
    assert header["error_code"] == "window-not-found"
    window = steps_of(found[0], "vpn.window")[0]
    assert window["data"]["window_found"] is False
    assert window["data"]["timeout_ms"] == 10000


def test_autofill_trace_links_back_to_connect(tmp_path, monkeypatch):
    lnk = tmp_path / "FortiClient VPN.lnk"
    lnk.write_text("x", encoding="utf-8")
    stub_forticlient_connect(monkeypatch)
    stub_forticlient_gui(monkeypatch, lnk, explorer_starts=True)
    # The autofill thread finds no window and gives up immediately.
    monkeypatch.setattr(vpn_connect, "_wait_forticlient_window",
                        lambda timeout=10.0: None)

    vpn_connect.connect("FortiClient", "", "", FAKE_LOGIN, FAKE_PASSWORD,
                        profile_name="SZPITAL-A", autofill=True)

    parent = traces("vpn.connect")[0]["header"]
    child = wait_for_trace("vpn.autofill")[0]["header"]
    assert child["meta"]["parent_trace_id"] == parent["trace_id"]
    assert child["meta"]["automation_mode"] == "tab_sequence"


def test_manual_provider_is_recorded_as_manual(monkeypatch, tmp_path):
    """A provider we only launch must not pretend to have automation."""
    exe = tmp_path / "nacvpn.exe"
    exe.write_text("x", encoding="utf-8")
    started = []
    monkeypatch.setattr(vpn_connect.os, "startfile",
                        lambda p, *a, **k: started.append(p))

    ok, _ = vpn_connect.connect("Barracuda", "", "", "", "",
                                app_path=str(exe), profile_name="SZPITAL-B",
                                autofill=False)
    assert ok is True
    autom = steps_of(traces("vpn.connect")[0], "vpn.automation")
    assert autom[-1]["data"]["automation_mode"] == "manual"
    assert started, "klient powinien zostać uruchomiony jak wcześniej"


def test_clipboard_copy_is_recorded_as_event_without_value(monkeypatch, tmp_path):
    exe = tmp_path / "nacvpn.exe"
    exe.write_text("x", encoding="utf-8")
    monkeypatch.setattr(vpn_connect.os, "startfile", lambda *a, **k: None)

    vpn_connect.connect("Barracuda", "", "", FAKE_LOGIN, FAKE_PASSWORD,
                        app_path=str(exe), autofill=False)
    autom = steps_of(traces("vpn.connect")[0], "vpn.automation")[0]
    assert autom["data"]["event"] == "credential_copy_requested"
    assert autom["data"]["field"] == "password"
    assert FAKE_PASSWORD not in json.dumps(autom)


# ══════════════════════════════════════════════════════════════════════════
# 5. Status
# ══════════════════════════════════════════════════════════════════════════

def test_status_change_writes_trace_with_source(monkeypatch):
    values = iter(["Disconnected", "Connected"])
    monkeypatch.setattr(vpn_connect, "_check_adapter_status",
                        lambda *kw: (vpn_diag.mark_status_source("adapter")
                                     or next(values)))

    first = vpn_connect.get_status("SonicWall NetExtender", profile_name="SZPITAL-A")
    assert traces("vpn.status") == [], "pierwsza obserwacja nie tworzy trace'u"

    second = vpn_connect.get_status("SonicWall NetExtender", profile_name="SZPITAL-A")
    assert (first, second) == ("Disconnected", "Connected")

    found = traces("vpn.status")
    assert len(found) == 1
    step = found[0]["steps"][0]
    assert step["data"]["state"] == "Connected"
    assert step["data"]["source"] == "adapter"


def test_status_polling_does_not_spam_the_store(monkeypatch):
    monkeypatch.setattr(vpn_connect, "_check_adapter_status",
                        lambda *kw: "Connected")
    for _ in range(25):
        vpn_connect.get_status("SonicWall NetExtender", profile_name="SZPITAL-A")
    assert traces("vpn.status") == []


def test_status_wrapper_returns_exactly_what_impl_returns(monkeypatch):
    monkeypatch.setattr(vpn_connect, "_check_adapter_status", lambda *kw: "Connected")
    assert vpn_connect.get_status("Hillstone Secure Connect") == "Connected"
    monkeypatch.setattr(vpn_connect, "_check_adapter_status", lambda *kw: None)
    assert vpn_connect.get_status("Hillstone Secure Connect") == "Disconnected"


# ══════════════════════════════════════════════════════════════════════════
# 6. Disconnect
# ══════════════════════════════════════════════════════════════════════════

def test_disconnect_writes_trace(monkeypatch):
    ok, msg = vpn_connect.disconnect("Barracuda", profile_name="SZPITAL-B")
    assert ok is True
    trace = traces("vpn.disconnect")[0]
    assert trace["header"]["status"] == "ok"
    assert trace["header"]["meta"]["provider"] == "Barracuda"
    step = steps_of(trace, "vpn.disconnect")[0]
    assert step["data"]["method"] == "manual"


def test_disconnect_forticlient_cli_path(monkeypatch):
    monkeypatch.setattr(vpn_connect, "_is_fortivpn_cli_supported",
                        lambda *_a, **_k: True)
    monkeypatch.setattr(vpn_connect, "_find_fortivpn",
                        lambda *_a, **_k: r"C:\FortiVPN.exe")
    monkeypatch.setattr(vpn_connect.subprocess, "run",
                        lambda *a, **k: type("R", (), {"returncode": 0,
                                                       "stdout": "", "stderr": ""})())

    ok, _ = vpn_connect.disconnect("FortiClient", profile_name="SZPITAL-A")
    assert ok is True
    step = steps_of(traces("vpn.disconnect")[0], "vpn.disconnect")[0]
    assert step["data"]["method"] == "fortivpn_cli"


# ══════════════════════════════════════════════════════════════════════════
# 7. No secrets anywhere
# ══════════════════════════════════════════════════════════════════════════

def test_no_secret_reaches_the_trace_store(tmp_path, monkeypatch):
    lnk = tmp_path / "FortiClient VPN.lnk"
    lnk.write_text("x", encoding="utf-8")
    stub_forticlient_connect(monkeypatch)
    stub_forticlient_gui(monkeypatch, lnk, explorer_starts=False)

    vpn_connect.connect("FortiClient", "vpn.szpital-a.pl", "443",
                        FAKE_LOGIN, FAKE_PASSWORD, group=FAKE_TOKEN,
                        domain=FAKE_KEY_HEADER, profile_name="SZPITAL-A",
                        autofill=False)
    vpn_connect.disconnect("Barracuda", server="vpn.szpital-b.pl",
                           profile_name="SZPITAL-B")

    text = store_text()
    assert text
    for secret in SECRETS:
        assert secret not in text, f"sekret w trace: {secret[:6]}…"
    # The profile name identifies the hospital — it must be pseudonymised.
    assert "SZPITAL-A" not in text
    assert "szpital-a.pl" not in text


def test_token_trace_never_contains_the_token(monkeypatch):
    # Stage 12: fill_forticlient_token hands its trace to the window finder.
    monkeypatch.setattr(vpn_connect, "_find_forti_auth_window",
                        lambda timeout=15.0, tr=None: (None, [], []))
    ok, msg = vpn_connect.fill_forticlient_token(FAKE_OTP)
    assert ok is False
    trace = traces("vpn.2fa")[0]
    assert trace["header"]["error_code"] == "otp-window-not-found"
    assert FAKE_OTP not in store_text()
    assert trace["header"]["meta"]["field"] == "token"


def test_command_lines_are_not_stored(monkeypatch):
    """connect() builds command lines containing --password; none may leak."""
    monkeypatch.setattr(vpn_connect, "_wait_forticlient_window",
                        lambda timeout=10.0: None)
    monkeypatch.setattr(vpn_connect, "_is_fortivpn_cli_supported",
                        lambda *_a, **_k: True)
    monkeypatch.setattr(vpn_connect, "_find_fortivpn",
                        lambda *_a, **_k: r"C:\FortiVPN.exe")
    monkeypatch.setattr(vpn_connect, "_fill_forti_auth_window",
                        lambda *_a, **_k: (False, ""))
    monkeypatch.setattr(vpn_connect.subprocess, "Popen",
                        lambda *a, **k: FakeProc())

    ok, _ = vpn_connect.connect("FortiClient", "", "", FAKE_LOGIN, FAKE_PASSWORD,
                                profile_name="SZPITAL-A", autofill=True)
    assert ok is True
    text = store_text()
    assert FAKE_PASSWORD not in text and FAKE_LOGIN not in text
    assert "--password" not in text


# ══════════════════════════════════════════════════════════════════════════
# 8-9. Diagnostics must not change behaviour
# ══════════════════════════════════════════════════════════════════════════

def _run_connect(tmp_path, monkeypatch):
    lnk = tmp_path / "FortiClient VPN.lnk"
    lnk.write_text("x", encoding="utf-8")
    stub_forticlient_connect(monkeypatch)
    stub_forticlient_gui(monkeypatch, lnk, explorer_starts=False)
    return vpn_connect.connect("FortiClient", "", "", FAKE_LOGIN, FAKE_PASSWORD,
                               profile_name="SZPITAL-A", autofill=False)


def test_result_is_identical_with_and_without_diagnostics(tmp_path, monkeypatch):
    with_diag = _run_connect(tmp_path, monkeypatch)

    # Simulate a build without the diagnostics package at all.
    monkeypatch.setattr(vpn_connect, "_trace_start",
                        lambda *a, **k: vpn_connect._TRACE_NULL)
    without_diag = _run_connect(tmp_path, monkeypatch)

    assert with_diag == without_diag


def test_broken_recorder_does_not_break_connect(tmp_path, monkeypatch):
    """Every TraceRecorder method raising must still leave VPN working."""
    class ExplodingRecorder:
        def __init__(self, *a, **k):
            raise RuntimeError("diagnostyka padła")

    monkeypatch.setattr(diagnostics.trace, "TraceRecorder", ExplodingRecorder)
    ok, msg = _run_connect(tmp_path, monkeypatch)
    assert ok is True
    assert "FortiClient" in msg


def test_broken_step_and_finish_do_not_break_connect(tmp_path, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("diagnostyka padła")

    monkeypatch.setattr(diagnostics.trace.TraceRecorder, "add_step", boom)
    monkeypatch.setattr(diagnostics.trace.TraceRecorder, "finish", boom)
    ok, msg = _run_connect(tmp_path, monkeypatch)
    assert ok is True


def test_broken_store_does_not_break_disconnect(monkeypatch):
    def boom(*_a, **_k):
        raise OSError("dysk pełny")

    monkeypatch.setattr(diagnostics.trace.TraceStore, "write", boom)
    ok, msg = vpn_connect.disconnect("Barracuda", profile_name="SZPITAL-B")
    assert ok is True


def test_status_note_failure_does_not_break_polling(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("diagnostyka padła")

    monkeypatch.setattr(vpn_connect, "_check_adapter_status", lambda *kw: "Connected")
    monkeypatch.setattr(diagnostics.trace.TraceRecorder, "add_step", boom)
    assert vpn_connect.get_status("Hillstone Secure Connect") == "Connected"


def test_diagnostics_adds_no_extra_processes(tmp_path, monkeypatch):
    """Requirement: tracing must not run tasklist/netstat/CLI of its own."""
    lnk = tmp_path / "FortiClient VPN.lnk"
    lnk.write_text("x", encoding="utf-8")
    stub_forticlient_connect(monkeypatch)
    calls = stub_forticlient_gui(monkeypatch, lnk, explorer_starts=False)
    monkeypatch.setattr(vpn_connect.subprocess, "run",
                        lambda *a, **k: pytest.fail("diagnostyka nie może uruchamiać procesów"))

    vpn_connect.connect("FortiClient", "", "", "", "", profile_name="X",
                        autofill=False)
    # Exactly the two launches the VPN code always did: explorer + fallback.
    assert len(calls) == 2


# ══════════════════════════════════════════════════════════════════════════
# 10. Regresja: ścieżka 2FA w detail_panel
#
# Historia: detail_panel wołał vpn_connect._find_forticlient_token_window,
# funkcję, która nigdy nie istniała — ścieżka 2FA kończyła się AttributeError
# w wątku QThread. Poniższe testy pilnują obu warstw problemu: że UI odwołuje
# się wyłącznie do istniejących funkcji ORAZ że wynik tej konkretnej funkcji
# jest rozpakowywany (sama krotka jest zawsze prawdziwa).
# ══════════════════════════════════════════════════════════════════════════

import ast  # noqa: E402
import glob  # noqa: E402


def _ui_sources():
    return sorted(glob.glob(os.path.join(_PARENT, "ui", "*.py")))


def test_ui_calls_only_existing_vpn_connect_functions():
    """Każde `vpn_connect.X` w warstwie UI musi istnieć w module."""
    missing = []
    for path in _ui_sources():
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "vpn_connect"
                    and not hasattr(vpn_connect, node.attr)):
                missing.append(f"{os.path.basename(path)}:{node.lineno} "
                               f"vpn_connect.{node.attr}")
    assert not missing, "UI woła nieistniejące funkcje VPN: " + ", ".join(missing)


def test_find_forti_auth_window_returns_triple():
    """Kontrakt funkcji, o którą potknęła się ścieżka 2FA."""
    result = vpn_connect._find_forti_auth_window(timeout=0.0)
    assert isinstance(result, tuple) and len(result) == 3
    hwnd, edits, buttons = result
    assert hwnd is None and edits == [] and buttons == []
    # Sedno błędu: pusty wynik jest FAŁSZYWY dopiero po rozpakowaniu.
    assert bool(result) is True
    assert bool(hwnd) is False


def test_token_waiter_unpacks_the_result():
    """Wywołanie w detail_panel musi przypisywać krotkę, nie pojedynczą nazwę."""
    path = os.path.join(_PARENT, "ui", "detail_panel.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    call_sites = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        call = node.value
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr == "_find_forti_auth_window"):
            call_sites.append(node)
    assert call_sites, "nie znaleziono wywołania _find_forti_auth_window w detail_panel"
    for node in call_sites:
        assert isinstance(node.targets[0], ast.Tuple), (
            "wynik _find_forti_auth_window musi być rozpakowany — inaczej "
            "`if hwnd:` jest zawsze prawdziwe")
        assert len(node.targets[0].elts) == 3


def test_token_window_waiter_path_does_not_raise(monkeypatch):
    """Odtworzenie logiki wątku 2FA bez Qt: brak okna → brak sygnału, bez wyjątku."""
    monkeypatch.setattr(vpn_connect, "_find_forti_auth_window",
                        lambda timeout=3.0: (None, [], []))
    hwnd, _edits, _buttons = vpn_connect._find_forti_auth_window(timeout=20.0)
    assert hwnd is None

    monkeypatch.setattr(vpn_connect, "_find_forti_auth_window",
                        lambda timeout=3.0: (4321, [(1, ""), (2, ""), (3, "")],
                                             [(9, "Connect")]))
    hwnd, _edits, _buttons = vpn_connect._find_forti_auth_window(timeout=20.0)
    assert hwnd == 4321


def test_fill_forticlient_token_success_path_unchanged(monkeypatch):
    """Zachowanie fill_forticlient_token po naprawie ma być bez zmian."""
    import win32gui

    sent = []
    monkeypatch.setattr(vpn_connect, "_find_forti_auth_window",
                        lambda timeout=15.0, tr=None: (4321,
                                                       [(11, ""), (12, ""), (13, "")],
                                                       [(21, "Connect"), (22, "Cancel")]))

    # Stage 12: the token goes only to a window owned by a FortiClient process.
    # Describe one — every control belongs to window 4321 of a trusted image.
    import secure_window

    class TrustedDesktop(secure_window.WindowApi):
        def window_pid(self, hwnd):
            return 4100

        def root_window(self, hwnd):
            return 4321

        def process_image_path(self, pid):
            return r"C:\Program Files\Fortinet\FortiClient\FortiTray.exe"

    monkeypatch.setattr(vpn_connect, "_window_api", lambda: TrustedDesktop())
    monkeypatch.setattr(vpn_connect, "_trusted_forti_dirs",
                        lambda: secure_window.KNOWN_FORTI_DIRS)
    monkeypatch.setattr(win32gui, "SendMessage",
                        lambda hwnd, msg, wp, lp: sent.append((hwnd, msg, lp)))

    ok, msg = vpn_connect.fill_forticlient_token(FAKE_OTP)

    assert ok is True
    assert msg == "Token wpisany, kliknięto Connect."
    assert sent[0][0] == 13, "token trafia do OSTATNIEGO pola edycyjnego"
    assert sent[1][0] == 21, "klikany jest przycisk Connect, nie Cancel"
    # Trace 2FA nadal działa i nadal nie zawiera wartości tokenu.
    trace = traces("vpn.2fa")[0]
    assert trace["header"]["status"] == "ok"
    assert trace["header"]["result"]["result"] == "token-submitted"
    assert FAKE_OTP not in store_text()


def test_autofill_globalprotect_is_still_dead_code():
    """Obserwacja z audytu — funkcja istnieje, ale nikt jej nie woła.

    Ten etap celowo jej nie usuwa ani nie podpina; test pilnuje, żeby stan
    nie zmienił się przypadkiem i żeby obserwacja pozostała aktualna.
    """
    assert hasattr(vpn_connect, "_autofill_globalprotect")
    source = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    tree = ast.parse(source)
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "_autofill_globalprotect"]
    assert calls == [], "GlobalProtect dostał autofill — zaktualizuj audyt"
