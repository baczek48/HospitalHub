"""2026-10-19 (owner's field test): the V2 connect brings the client forward.

On the owner's machines every V2 connect stopped at "switch to the client
window" — the Stage-22 gate only waited for the user.  HospitalHub is the
foreground program when "Połącz" is clicked, and the foreground program may
hand the foreground on (measured from the connect's worker thread), so the gate
now asks for the verified window to be put in front a few times, then falls
back to waiting.  In the same round: the client is started with the user's own
environment instead of through ``explorer.exe`` (FortiClient's "TraceLog"
crash, the "Dokumenty" folder), Stormshield is started a second time when it
went to the tray, and the card's sentences name the clicked client.

Offscreen, no real window, process or keystroke.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn.providers import SecureWindowTarget  # noqa: E402
from vpn.providers import activation_gate as ag  # noqa: E402
from vpn.providers import launch_system as ls  # noqa: E402
from vpn.providers import stormshield as ss  # noqa: E402
from vpn.providers.activation_gate import (  # noqa: E402
    ActivationGate, ActivationState, CancellationToken,
)
from tests.test_vpn_activation_gate import FakeClock, ScriptedDesktop  # noqa: E402
from tests.test_vpn_secure_target import (  # noqa: E402
    HWND, OTHER, TRUSTED, ListFinder,
)
from tests.test_vpn_stormshield import FakeLaunch, provider  # noqa: E402


class RaisableDesktop(ScriptedDesktop):
    """The client comes to the front only once somebody asks Windows for it.

    `accept` is what ``SetForegroundWindow`` answers; an accepted request puts
    the client in front from the next reading on.
    """

    def __init__(self, *, accept=True, **kwargs):
        super().__init__(foreground_script=lambda n: self._front, **kwargs)
        self._front = OTHER
        self.accept = accept

    def set_foreground_window(self, hwnd):
        self.events.append(("set_foreground", hwnd))
        if self.accept:
            self._front = hwnd
        return self.accept

    def restore_window(self, hwnd):
        self.events.append(("restore", hwnd))
        self.iconic = False


def make_gate(desktop, *, clock=None, cancellation=None, timeout_s=10.0,
              bring=True):
    target = SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder((HWND,)),
                                require_visible=True, raise_window=False)
    return ActivationGate(
        target=target, clock=clock or FakeClock(),
        cancellation=cancellation or CancellationToken(), timeout_s=timeout_s,
        bring_forward=target.bring_forward if bring else None)


def raises(desktop):
    return [e for e in desktop.events if e[0] == "set_foreground"]


# ══════════════════════════════════════════════════════════════════════════
# The gate asks for the window, then decides on a reading
# ══════════════════════════════════════════════════════════════════════════

def test_a_window_behind_another_is_brought_forward_and_observed():
    desktop = RaisableDesktop()
    clock = FakeClock()
    result = make_gate(desktop, clock=clock).wait()
    assert result.state is ActivationState.ACTIVATION_OBSERVED
    assert raises(desktop) == [("set_foreground", HWND)]
    assert clock.slept == [], "zaakceptowana prośba = od razu ponowny odczyt"


def test_a_minimised_window_is_restored_before_it_is_raised():
    desktop = RaisableDesktop(iconic=True)
    result = make_gate(desktop).wait()
    assert result.ok
    kinds = [e[0] for e in desktop.events]
    assert kinds.index("restore") < kinds.index("set_foreground")


def test_a_refusing_windows_gets_three_requests_then_the_user_decides():
    desktop = RaisableDesktop(accept=False)
    clock = FakeClock()
    result = make_gate(desktop, clock=clock, timeout_s=10.0).wait()
    assert result.state is ActivationState.ACTIVATION_TIMEOUT
    assert len(raises(desktop)) == ag.BRING_FORWARD_ATTEMPTS == 3
    # the requests are spaced, not fired back to back
    assert ag.BRING_FORWARD_INTERVAL_S >= ag.POLL_INTERVAL_S
    assert sum(clock.slept) >= 10.0


def test_the_user_can_still_activate_after_windows_refused():
    desktop = RaisableDesktop(accept=False)
    reads = {"n": 0}

    def front(n):
        reads["n"] = n
        return HWND if n > 12 else OTHER

    desktop._script = front
    result = make_gate(desktop, timeout_s=30.0).wait()
    assert result.ok and len(raises(desktop)) == 3


def test_a_client_already_in_front_is_not_touched():
    desktop = RaisableDesktop()
    desktop._front = HWND
    result = make_gate(desktop).wait()
    assert result.ok and desktop.events == []


def test_no_bring_forward_keeps_the_stage_22_wait():
    desktop = RaisableDesktop()
    result = make_gate(desktop, bring=False, timeout_s=2.0).wait()
    assert result.state is ActivationState.ACTIVATION_TIMEOUT
    assert desktop.events == []


def test_a_raising_bring_forward_does_not_break_the_wait():
    desktop = RaisableDesktop()
    gate = make_gate(desktop, timeout_s=2.0)

    def boom(hwnd):
        raise RuntimeError("seam padł")

    gate.bring_forward = boom
    assert gate.wait().state is ActivationState.ACTIVATION_TIMEOUT


def test_a_cancelled_wait_asks_for_nothing():
    desktop = RaisableDesktop()
    token = CancellationToken()
    token.cancel()
    result = make_gate(desktop, cancellation=token).wait()
    assert result.state is ActivationState.CANCELLED
    assert desktop.events == []


# ══════════════════════════════════════════════════════════════════════════
# SecureWindowTarget.bring_forward: verified windows only, nothing typed
# ══════════════════════════════════════════════════════════════════════════

def test_an_untrusted_window_is_never_brought_forward():
    desktop = RaisableDesktop()
    target = SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder((HWND,)))
    assert target.bring_forward(OTHER) is False
    assert desktop.events == []


def test_bring_forward_reports_what_windows_answered():
    for accept in (True, False):
        desktop = RaisableDesktop(accept=accept)
        target = SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder((HWND,)))
        assert target.bring_forward(HWND) is accept


def test_bring_forward_never_attaches_input_or_types():
    tree = ast.parse(open(os.path.join(_PARENT, "vpn", "providers",
                                       "secure_target.py"), encoding="utf-8").read())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "bring_forward")
    called = {n.func.attr for n in ast.walk(fn)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert called <= {"verify_owner", "is_iconic", "restore_window",
                      "set_foreground_window"}, called


@pytest.mark.parametrize("module", ["forticlient_runtime", "stormshield_connect",
                                    "barracuda_connect"])
def test_every_migrated_provider_hands_the_gate_its_bring_forward(module):
    source = open(os.path.join(_PARENT, "vpn", "providers", module + ".py"),
                  encoding="utf-8").read()
    assert "bring_forward=target.bring_forward" in source


# ══════════════════════════════════════════════════════════════════════════
# Stormshield: a first start goes to the tray
# ══════════════════════════════════════════════════════════════════════════

class WaitingLaunch(FakeLaunch):
    def __init__(self, shown_after_spawns, **kwargs):
        super().__init__(**kwargs)
        self.shown_after = shown_after_spawns
        self.waits_for_window = 0

    def wait_until(self, predicate, timeout):
        self.waits_for_window += 1
        return predicate()


def storm(launch):
    p = provider(system=launch)

    class Target:
        def first_verified_candidate(self):
            return (1, None) if len(launch.spawned) >= launch.shown_after else None

    p.secure_window_target = lambda *a, **k: Target()
    return p


def test_stormshield_in_the_tray_is_started_again_to_show_its_window():
    launch = WaitingLaunch(shown_after_spawns=2)
    assert storm(launch).launch().success
    assert len(launch.spawned) == 2


def test_stormshield_with_a_window_is_started_once():
    launch = WaitingLaunch(shown_after_spawns=1)
    storm(launch).launch()
    assert len(launch.spawned) == 1


def test_stormshield_gives_up_after_the_extra_starts():
    launch = WaitingLaunch(shown_after_spawns=99)
    assert storm(launch).launch().success
    assert len(launch.spawned) == 1 + ss.RESHOW_ATTEMPTS


def test_stormshield_without_a_window_wait_starts_once():
    launch = FakeLaunch()
    provider(system=launch).launch()
    assert len(launch.spawned) == 1


# ══════════════════════════════════════════════════════════════════════════
# The client's environment
# ══════════════════════════════════════════════════════════════════════════

def test_the_users_own_environment_is_used(monkeypatch):
    import win32profile
    pristine = {"SystemRoot": r"C:\Windows", "Path": r"C:\Windows\system32"}
    monkeypatch.setattr(win32profile, "CreateEnvironmentBlock",
                        lambda token, inherit: dict(pristine))
    monkeypatch.setenv("_MEIPASS2", "x")
    monkeypatch.setenv("QT_PLUGIN_PATH", "y")
    assert ls.user_environment() == pristine


def test_without_the_profile_call_the_pyinstaller_keys_are_still_dropped(monkeypatch):
    import win32profile

    def broken(token, inherit):
        raise OSError("brak profilu")

    monkeypatch.setattr(win32profile, "CreateEnvironmentBlock", broken)
    monkeypatch.setenv("_MEIPASS2", "x")
    env = ls.user_environment()
    assert "_MEIPASS2" not in env and env


# ══════════════════════════════════════════════════════════════════════════
# The card names the clicked client
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("client", ["FortiClient", "Stormshield", "Barracuda"])
def test_sentences_name_the_clicked_client(client):
    from ui.activation_prompt import STATE_TEMPLATES, ActivationPresenter
    from ui.vpn_v2_connect import OUTCOME_TEMPLATES, present_outcome
    for state in STATE_TEMPLATES:
        text = ActivationPresenter(state, client=client).message
        assert "{" not in text
        if client != "FortiClient":
            assert "FortiClient" not in text
    for code in OUTCOME_TEMPLATES:
        text = present_outcome(code, client=client).text
        assert "{" not in text
        if client != "FortiClient":
            assert "FortiClient" not in text


# ══════════════════════════════════════════════════════════════════════════
# 2026-10-20: Stormshield stayed in the tray on the owner's other machine
# ══════════════════════════════════════════════════════════════════════════

class TrayLaunch(WaitingLaunch):
    """A second start shows nothing; a tray double-click does."""

    def __init__(self, *, tray_shows=True, client_hwnds=(0x77,)):
        super().__init__(shown_after_spawns=99)
        self.tray_shows = tray_shows
        self.client_hwnds = client_hwnds
        self.asked_about = []
        self.tray_clicked = False

    def activate_tray(self, is_client):
        for hwnd in (0x66,) + tuple(self.client_hwnds):
            self.asked_about.append(hwnd)
            if is_client(hwnd):
                self.tray_clicked = self.tray_shows
                return True
        return False


def storm_tray(launch):
    p = provider(system=launch)

    class Owner:
        def __init__(self, ok, image):
            self.verified, self.image_name = ok, image

    class Target:
        def first_verified_candidate(self):
            return (1, None) if launch.tray_clicked else None

        def verify_owner(self, hwnd):
            if hwnd in launch.client_hwnds:
                return Owner(True, ss.GUI_EXE_NAME)
            return Owner(True, "hillstonesecureconnect.exe")    # someone else's tray

    p.secure_window_target = lambda *a, **k: Target()
    return p


def test_stormshield_in_the_tray_is_shown_by_its_tray_icon_before_restarting():
    launch = TrayLaunch()
    assert storm_tray(launch).launch().success
    assert launch.tray_clicked
    assert len(launch.spawned) == 1, "bez kolejnych startow"


def test_another_programs_tray_icon_is_never_clicked():
    launch = TrayLaunch(client_hwnds=())
    storm_tray(launch).launch()
    assert not launch.tray_clicked
    assert 0x66 in launch.asked_about
    assert len(launch.spawned) == 1 + ss.RESHOW_ATTEMPTS, "zostaje ponowny start"


def test_a_tray_click_that_shows_nothing_falls_back_to_starting_again():
    launch = TrayLaunch(tray_shows=False)
    storm_tray(launch).launch()
    assert len(launch.spawned) == 1 + ss.RESHOW_ATTEMPTS
