"""Stage 58: with ``CONNECT_ENABLED = True`` a test still cannot touch the machine.

The first attempt at the FortiClient cutover flipped the flag in source and ran
the suite: tests that expected the legacy route drove a real session, the real
FortiClient window was filled and the VPN connected.  ``tests/conftest.py`` now
guards the real primitives for the whole session and forces every flag off per
test.  These tests prove that:

S1. the guard is installed on every primitive the Win32 seams use;
S2. each real seam — launch, keystroke, Enter, clipboard, window messages,
    foreground, enumeration — is stopped by it;
S3. the flag is off in every test unless the test turns it on;
S4. both flag states route as they should (False → legacy, True → V2), and one
    provider's flag never arms another;
S5. with the flag **on** and nothing faked above the primitives —
    ``provider.connect()``, ``PanelConnectSession`` and the real
    ``_connect_card`` + ``V2ConnectController`` QThread — every attempt to
    reach the machine ends at the guard, and nothing connects.

Every call on a real seam is made only after the primitive it reaches has been
confirmed guarded, so a missing guard fails the check instead of acting.
"""

import ctypes
import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QLabel, QWidget  # noqa: E402

import models  # noqa: E402
import secure_window as sw  # noqa: E402
import vpn_connect  # noqa: E402
from tests import conftest as guard  # noqa: E402
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import FORTI_DIR, FORTI_GUI  # noqa: E402
from ui import vpn_panel  # noqa: E402
from ui.vpn_panel import VpnPanel  # noqa: E402
from ui.vpn_v2_connect import V2ConnectController  # noqa: E402
from vpn.panel_bridge import (  # noqa: E402
    ROUTE_LEGACY, PanelConnectSession, PanelOutcome, build_request,
    select_connect_route, v2_route_for,
)
from vpn.providers import forticlient as fc  # noqa: E402
from vpn.providers.barracuda import BarracudaProvider  # noqa: E402
from vpn.providers.forticlient import FortiClientProvider  # noqa: E402
from vpn.providers.input_system import VK_RETURN, Win32InputSystem  # noqa: E402
from vpn.providers.launch_system import WindowsLaunchSystem  # noqa: E402
from vpn.providers.stormshield import StormshieldProvider  # noqa: E402
from vpn.providers.window_message_system import Win32WindowMessageSystem  # noqa: E402

LOGIN, PASSWORD = "jkowalski", "SuperSecret123"
FLAGS = (FortiClientProvider, StormshieldProvider, BarracudaProvider)
#: Outcomes that would mean something was typed or a connection started.
ACTING_OUTCOMES = {PanelOutcome.SUBMITTED,
                   PanelOutcome.STARTED, PanelOutcome.TWO_FACTOR_REQUIRED,
                   PanelOutcome.CLI_STARTED, PanelOutcome.MANUAL}


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def vault_profile(provider="FortiClient"):
    return models.VpnProfile(name="Szpital A", provider=provider,
                             server="vpn.example.org", port="10443", login=LOGIN,
                             password=PASSWORD, group="g", domain="d",
                             app_path=FORTI_GUI, profile_name="SZPITAL-A")


def installed_forticlient(monkeypatch):
    """Detection says installed on any machine; everything below it is real."""
    monkeypatch.setattr(fc, "WindowsEnvironment",
                        lambda: FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))


def assert_primitives_guarded():
    import importlib
    assert subprocess.Popen is guard.GuardedPopen
    for name in ("startfile", "system"):
        if hasattr(os, name):
            assert guard.is_guarded(getattr(os, name)), f"os.{name}"
    for module_name, names in guard.MODULE_PRIMITIVES.items():
        module = importlib.import_module(module_name)
        for name in names:
            if hasattr(module, name):
                assert guard.is_guarded(getattr(module, name)), f"{module_name}.{name}"
    for dll, names in guard.DLL_PRIMITIVES.items():
        for lib in (getattr(ctypes.windll, dll), ctypes.WinDLL(dll)):
            for name in names:
                assert guard.is_guarded(getattr(lib, name)), f"{dll}.{name}"


# ══════════════════════════════════════════════════════════════════════════
# S1. The guard is in place
# ══════════════════════════════════════════════════════════════════════════

def test_s1_every_real_primitive_is_guarded():
    assert_primitives_guarded()


def test_s1a_the_guard_survives_a_module_being_reimported(monkeypatch):
    """A test that drops ``win32gui`` from ``sys.modules`` must not leave the
    next import with the real functions."""
    import importlib
    saved = sys.modules.pop("win32gui")
    try:
        fresh = importlib.import_module("win32gui")
        assert guard.is_guarded(fresh.SetForegroundWindow)
        assert guard.is_guarded(fresh.SendMessage)
    finally:
        sys.modules["win32gui"] = saved
    assert_primitives_guarded()


def test_s1b_this_interpreter_can_still_be_started():
    """The import-graph tests start a fresh Python — that stays allowed."""
    out = subprocess.run([sys.executable, "-c", "print('ok')"],
                         capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "ok"


# ══════════════════════════════════════════════════════════════════════════
# S2. Each real seam is stopped at the guard
# ══════════════════════════════════════════════════════════════════════════

REAL_SEAM_CALLS = {
    "launch: explorer": lambda: WindowsLaunchSystem().open_with_explorer(FORTI_GUI),
    "launch: detached": lambda: WindowsLaunchSystem().spawn_detached(FORTI_GUI, FORTI_DIR),
    "launch: capture": lambda: WindowsLaunchSystem().run_capture(["tasklist"], 1.0),
    "launch: monitored": lambda: WindowsLaunchSystem().spawn_monitored(["FortiVPN.exe"]),
    "input: Enter": lambda: Win32InputSystem().press_key(VK_RETURN),
    "input: type": lambda: Win32InputSystem().type_text("x"),
    "input: combo": lambda: Win32InputSystem().press_combo(0x11, 0x56),
    "input: clipboard": lambda: Win32InputSystem().copy_to_clipboard(PASSWORD),
    "messages: set text": lambda: Win32WindowMessageSystem().set_control_text(1, PASSWORD),
    "messages: click": lambda: Win32WindowMessageSystem().click_button(1),
    "messages: enumerate": lambda: Win32WindowMessageSystem().enumerate_controls(1),
    "window: foreground": lambda: sw.Win32WindowApi().set_foreground_window(1),
    "window: attach input": lambda: sw.Win32WindowApi().attach_thread_input(1, 2, True),
    "window: restore": lambda: sw.Win32WindowApi().restore_window(1),
    "window: read foreground": lambda: sw.Win32WindowApi().foreground_window(),
    "window: enumerate": lambda: sw.Win32TitleWindowFinder("FortiClient").candidates(),
    "legacy: Enter": lambda: vpn_connect._press_key(VK_RETURN),
    "legacy: explorer": lambda: vpn_connect.subprocess.Popen(["explorer.exe", "x"]),
}


@pytest.mark.real_system_guard
@pytest.mark.parametrize("name", sorted(REAL_SEAM_CALLS))
def test_s2_a_real_seam_is_stopped_by_the_guard(name):
    assert_primitives_guarded()                 # before anything is called
    start = len(guard.HITS)
    try:
        REAL_SEAM_CALLS[name]()
    except guard.RealSystemBlocked:
        pass                                    # the seam let it propagate
    # Seams that swallow errors (clipboard, foreground read) still knocked.
    assert guard.HITS[start:], f"{name}: nic nie trafiło w guard"


# ══════════════════════════════════════════════════════════════════════════
# S3. Flags are off unless a test turns them on
# ══════════════════════════════════════════════════════════════════════════

def test_s3_every_flag_is_off_by_default_in_a_test():
    for cls in FLAGS:
        assert cls.CONNECT_ENABLED is False, cls.__name__


def test_s3b_a_test_can_turn_one_on(monkeypatch):
    monkeypatch.setattr(FortiClientProvider, "CONNECT_ENABLED", True)
    assert FortiClientProvider.CONNECT_ENABLED is True


def test_s3c_and_it_is_off_again_in_the_next_test():
    assert FortiClientProvider.CONNECT_ENABLED is False


# ══════════════════════════════════════════════════════════════════════════
# S4. Both flag states route as they should
# ══════════════════════════════════════════════════════════════════════════

def test_s4_flag_off_routes_forticlient_to_legacy():
    assert select_connect_route("FortiClient") == ROUTE_LEGACY


def test_s4b_flag_on_routes_forticlient_to_v2_and_nothing_else(monkeypatch):
    monkeypatch.setattr(FortiClientProvider, "CONNECT_ENABLED", True)
    assert select_connect_route("FortiClient") == v2_route_for("forticlient")
    assert select_connect_route("Stormshield") == ROUTE_LEGACY
    assert select_connect_route("Barracuda") == ROUTE_LEGACY
    assert StormshieldProvider.CONNECT_ENABLED is False
    assert BarracudaProvider.CONNECT_ENABLED is False


# ══════════════════════════════════════════════════════════════════════════
# S5. Flag ON, real runtime — only the guard is hit, nothing connects
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.real_system_guard
def test_s5_armed_provider_connect_is_stopped_at_the_guard(monkeypatch):
    assert_primitives_guarded()
    monkeypatch.setattr(FortiClientProvider, "CONNECT_ENABLED", True)
    installed_forticlient(monkeypatch)
    start = len(guard.HITS)

    request = build_request(vault_profile(), app_path=FORTI_GUI, autofill=True)
    try:
        result = FortiClientProvider().connect(request)
    except guard.RealSystemBlocked:
        result = None

    hits = guard.HITS[start:]
    assert hits, "uzbrojony connect musiał sięgnąć po maszynę — i trafić w guard"
    assert result is None or not result.success
    assert "input" not in " ".join(hits)


@pytest.mark.real_system_guard
def test_s5b_armed_panel_session_is_stopped_at_the_guard(monkeypatch):
    assert_primitives_guarded()
    monkeypatch.setattr(FortiClientProvider, "CONNECT_ENABLED", True)
    installed_forticlient(monkeypatch)
    start = len(guard.HITS)

    request = build_request(vault_profile(), app_path=FORTI_GUI, autofill=True)
    outcome = PanelConnectSession(request).run()   # real resolver, real runtime

    assert guard.HITS[start:], "sesja musiała trafić w guard"
    assert outcome.code not in ACTING_OUTCOMES, outcome
    assert PASSWORD not in repr(outcome)


def _bare_panel(profile, label, holder):
    panel = VpnPanel.__new__(VpnPanel)
    panel._profiles = [profile]
    panel._status_labels = {0: label}
    panel._card_widgets = {0: QWidget(holder)}
    panel._v2_controllers = {}
    panel._monitor_workers = {}
    panel._status_timer = SimpleNamespace(stop=lambda: None, start=lambda ms: None)
    panel._resolve_app_path = lambda p: p.app_path or ""
    panel._update_toggle_btn = lambda idx, state: None
    panel._poll_status = lambda: None
    panel._start_monitor = lambda idx, proc: None
    return panel


@pytest.mark.real_system_guard
def test_s5c_armed_click_through_the_real_controller_thread(app, monkeypatch):
    """What caused the incident: a real click, real session, real QThread."""
    assert_primitives_guarded()
    monkeypatch.setattr(FortiClientProvider, "CONNECT_ENABLED", True)
    installed_forticlient(monkeypatch)
    monkeypatch.setattr(vpn_panel, "load_vpn_autofill_enabled", lambda: True)
    monkeypatch.setattr(vpn_panel, "QTimer",
                        SimpleNamespace(singleShot=lambda ms, fn: None))
    legacy = []
    monkeypatch.setattr(vpn_connect, "connect_monitored",
                        lambda *a, **k: legacy.append(a) or (True, "ok", None))
    start = len(guard.HITS)

    holder = QWidget()
    label = QLabel(holder)
    panel = _bare_panel(vault_profile(), label, holder)
    panel._connect_card(0)

    controller = panel._v2_controllers[0]
    assert isinstance(controller, V2ConnectController)
    deadline = time.monotonic() + 20.0
    while not controller.done and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    controller.worker.wait(5000)
    app.processEvents()

    assert controller.done, "sesja nie zakończyła się"
    assert legacy == [], "trasa V2 nie może spaść do legacy"
    assert guard.HITS[start:], "wątek sesji musiał trafić w guard"
    assert "Łączenie" not in label.text(), label.text()
    holder.deleteLater()
