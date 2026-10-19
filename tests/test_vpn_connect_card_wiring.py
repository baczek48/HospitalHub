"""Stage 52: _connect_card dispatches route → legacy or the V2 chain.

The panel now asks ``select_connect_route`` at the top of ``_connect_card`` and,
only when a provider is armed, builds a session and hands it to
``V2ConnectController``.  With every flag off (production today) every click
still goes to ``vpn_connect.connect_monitored``.

These tests drive the *real* ``VpnPanel._connect_card`` against a lightweight
instance, with the bridge's session/controller replaced by fakes so the
dispatch, lifetime, polling and cancellation wiring can be checked
synchronously — without a real connect and without ever arming a provider.
"""

import os
import sys
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QLabel, QWidget  # noqa: E402

import models  # noqa: E402
import vpn_connect  # noqa: E402
from ui import vpn_panel  # noqa: E402
from ui.vpn_panel import VpnPanel  # noqa: E402
from vpn.panel_bridge import ROUTE_LEGACY  # noqa: E402
from vpn.providers.barracuda import BarracudaProvider  # noqa: E402
from vpn.providers.forticlient import FortiClientProvider  # noqa: E402
from vpn.providers.stormshield import StormshieldProvider  # noqa: E402

SERVER, PORT, LOGIN, PASSWORD, PROFILE = ("vpn.x", "443", "jkowalski",
                                          "SuperSecret123", "SZP-A")


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def profile(provider="FortiClient", login=LOGIN, profile_name=PROFILE, **kw):
    return models.VpnProfile(name="p", provider=provider, server=SERVER,
                             port=PORT, login=login, password=PASSWORD,
                             group="g", domain="d", app_path=r"C:\x\client.exe",
                             profile_name=profile_name, **kw)


class FakeTimer:
    def __init__(self):
        self.events = []

    def stop(self):
        self.events.append("stop")

    def start(self, ms):
        self.events.append(("start", ms))


class _Signal:
    def __init__(self):
        self._slots = []

    def connect(self, fn):
        self._slots.append(fn)

    def emit(self, *a):
        for fn in list(self._slots):
            fn(*a)


class FakeSession:
    instances = []

    def __init__(self, request):
        self.request = request
        self.cancelled = False
        FakeSession.instances.append(self)

    def cancel(self):
        self.cancelled = True


class FakeController:
    instances = []
    raise_on_init = False

    def __init__(self, session, label, *, prompt_parent=None, client=None):
        if FakeController.raise_on_init:
            raise RuntimeError("V2 controller boom")
        self.session = session
        self.client = client
        self.label = label
        self.prompt = QWidget(prompt_parent)
        self.polling_pause = _Signal()
        self.polling_resume = _Signal()
        self.finished = _Signal()
        self.started = False
        #: Mirrors the real controller: started and not yet finished.
        self.active = False
        FakeController.instances.append(self)

    def start(self):
        self.started = True
        self.active = True

    def finish(self, outcome=None):
        """What the real controller does at the end of a session."""
        self.active = False
        self.finished.emit(outcome)


def make_panel(profiles, label):
    """A real VpnPanel instance with just the fields _connect_card touches."""
    panel = VpnPanel.__new__(VpnPanel)
    panel._profiles = profiles
    panel._status_labels = {i: label for i in range(len(profiles))}
    # Real QWidget cards so the controller has a valid prompt parent (the stub
    # panel is not a QWidget — it is built with __new__).
    panel._card_widgets = {i: QWidget() for i in range(len(profiles))}
    panel._v2_controllers = {}
    panel._monitor_workers = {}
    panel._status_timer = FakeTimer()
    panel._resolve_app_path = lambda p: p.app_path or ""
    panel._update_toggle_btn = lambda idx, state: panel.__dict__.setdefault(
        "_toggles", []).append(state)
    panel._poll_status = lambda: None
    panel._start_monitor = lambda idx, proc: None
    return panel


@pytest.fixture(autouse=True)
def reset():
    FakeSession.instances.clear()
    FakeController.instances.clear()
    FakeController.raise_on_init = False


@pytest.fixture
def wire_v2(monkeypatch):
    """Replace the bridge's session/controller with fakes, and let the caller
    force a route."""
    monkeypatch.setattr(vpn_panel, "PanelConnectSession", FakeSession)
    monkeypatch.setattr(vpn_panel, "V2ConnectController", FakeController)
    monkeypatch.setattr(vpn_panel, "load_vpn_autofill_enabled", lambda: True)
    monkeypatch.setattr(vpn_panel, "QTimer",
                        SimpleNamespace(singleShot=lambda ms, fn: None))

    def _route(value):
        monkeypatch.setattr(vpn_panel, "select_connect_route", lambda name: value)
    return _route


def legacy_recorder(monkeypatch):
    calls = []
    monkeypatch.setattr(vpn_connect, "connect_monitored",
                        lambda *a, **k: calls.append((a, k)) or (True, "ok", None))
    monkeypatch.setattr(vpn_connect, "invalidate_adapter_cache", lambda: None)
    return calls


# ══════════════════════════════════════════════════════════════════════════
# A–E, J. Gate off → legacy; no V2 touched
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("provider_name", [
    "FortiClient", "Stormshield", "Barracuda", "GlobalProtect",
    "SonicWall NetExtender", "Windows VPN", "Nieznany provider"])
def test_a_gate_off_every_provider_goes_legacy(app, monkeypatch, provider_name):
    """All flags are False, so the real route is legacy for everyone."""
    for cls in (FortiClientProvider, StormshieldProvider, BarracudaProvider):
        assert cls.CONNECT_ENABLED is False
    monkeypatch.setattr(vpn_panel, "PanelConnectSession", FakeSession)
    monkeypatch.setattr(vpn_panel, "V2ConnectController", FakeController)
    monkeypatch.setattr(vpn_panel, "load_vpn_autofill_enabled", lambda: False)
    monkeypatch.setattr(vpn_panel, "QTimer",
                        SimpleNamespace(singleShot=lambda ms, fn: None))
    calls = legacy_recorder(monkeypatch)

    panel = make_panel([profile(provider=provider_name)], QLabel())
    panel._connect_card(0)

    assert len(calls) == 1, "legacy connect_monitored called exactly once"
    assert calls[0][0][0] == provider_name
    assert FakeSession.instances == [] and FakeController.instances == []
    assert panel._v2_controllers == {}


# ══════════════════════════════════════════════════════════════════════════
# F, K. V2 route → session + controller; legacy NOT called
# ══════════════════════════════════════════════════════════════════════════

def test_f_v2_route_builds_session_and_controller(app, monkeypatch, wire_v2):
    wire_v2("forticlient-v2")
    calls = legacy_recorder(monkeypatch)
    panel = make_panel([profile()], QLabel())

    panel._connect_card(0)

    assert len(FakeSession.instances) == 1
    assert len(FakeController.instances) == 1
    ctrl = FakeController.instances[0]
    assert ctrl.session is FakeSession.instances[0]
    assert ctrl.started is True
    assert calls == [], "legacy connect_monitored must NOT be called on V2 route"


def test_k_v2_path_does_not_call_connect_monitored(app, monkeypatch, wire_v2):
    wire_v2("stormshield-v2")
    calls = legacy_recorder(monkeypatch)
    make_panel([profile(provider="Stormshield")], QLabel())._connect_card(0)
    assert calls == []
    assert len(FakeController.instances) == 1


def test_request_carries_the_clicked_profiles_values(app, monkeypatch, wire_v2):
    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    make_panel([profile()], QLabel())._connect_card(0)
    req = FakeSession.instances[0].request
    assert req.login == LOGIN and req.password == PASSWORD
    assert req.profile_name == PROFILE and req.provider_id == "forticlient"


# ══════════════════════════════════════════════════════════════════════════
# G. Lifetime — controller survives the handler
# ══════════════════════════════════════════════════════════════════════════

def test_g_controller_is_kept_alive_after_the_handler_returns(app, monkeypatch,
                                                              wire_v2):
    wire_v2("barracuda-v2")
    legacy_recorder(monkeypatch)
    panel = make_panel([profile(provider="Barracuda")], QLabel())

    panel._connect_card(0)

    assert panel._v2_controllers.get(0) is FakeController.instances[0], \
        "controller referenced by the panel, not garbage-collectable"


# ══════════════════════════════════════════════════════════════════════════
# H. Polling pause on start, resume on finish
# ══════════════════════════════════════════════════════════════════════════

def test_h_polling_pauses_and_resumes_via_the_controller(app, monkeypatch,
                                                         wire_v2):
    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    panel = make_panel([profile()], QLabel())
    panel._connect_card(0)
    ctrl = FakeController.instances[0]

    panel._status_timer.events.clear()
    ctrl.polling_pause.emit()
    assert panel._status_timer.events == ["stop"]

    ctrl.polling_resume.emit()
    assert panel._status_timer.events == ["stop", ("start", 5000)]


def test_h2_finished_started_flips_the_toggle(app, monkeypatch, wire_v2):
    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    # QTimer.singleShot must actually invoke to exercise cleanup safely.
    monkeypatch.setattr(vpn_panel, "QTimer",
                        SimpleNamespace(singleShot=lambda ms, fn: fn()))
    panel = make_panel([profile()], QLabel())
    panel._connect_card(0)
    ctrl = FakeController.instances[0]

    ctrl.finished.emit(SimpleNamespace(started=True, code="submitted"))
    assert panel.__dict__.get("_toggles") == ["connecting"]


# ══════════════════════════════════════════════════════════════════════════
# I. Cancellation reaches the session through the controller
# ══════════════════════════════════════════════════════════════════════════

def test_i_cancellation_is_available_through_the_live_controller(app, monkeypatch,
                                                                wire_v2):
    """The panel keeps the controller alive, so its Cancel still reaches the
    session after the handler has returned."""
    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    panel = make_panel([profile()], QLabel())
    panel._connect_card(0)

    ctrl = panel._v2_controllers[0]
    session = ctrl.session
    # The controller owns cancellation; here we prove the session it was given
    # is the one the panel can still reach to cancel.
    session.cancel()
    assert session.cancelled is True


def test_i2_real_controller_prompt_cancels_the_session(app, monkeypatch):
    """With the *real* controller, the prompt's Cancel reaches the session."""
    from ui.vpn_v2_connect import V2ConnectController
    monkeypatch.setattr(vpn_panel, "PanelConnectSession", FakeSession)
    monkeypatch.setattr(vpn_panel, "V2ConnectController", V2ConnectController)
    monkeypatch.setattr(vpn_panel, "load_vpn_autofill_enabled", lambda: True)
    monkeypatch.setattr(vpn_panel, "QTimer",
                        SimpleNamespace(singleShot=lambda ms, fn: None))
    monkeypatch.setattr(vpn_panel, "select_connect_route",
                        lambda name: "forticlient-v2")
    # Give the session an observer attr the controller sets, and a run.
    FakeSession.run = lambda self: SimpleNamespace(code="submitted", started=True)
    FakeSession.observer = None

    holder = QWidget()
    panel = make_panel([profile()], QLabel(holder))
    panel._card_widgets = {0: QWidget(holder)}   # a real card to host the prompt
    panel._connect_card(0)

    ctrl = panel._v2_controllers[0]
    ctrl.cancel()                                 # what the Cancel button calls
    assert ctrl._session.cancelled is True


# ══════════════════════════════════════════════════════════════════════════
# L. Routing isolation — one provider never starts another's session
# ══════════════════════════════════════════════════════════════════════════

def test_l_each_click_builds_a_session_for_its_own_card(app, monkeypatch,
                                                       wire_v2):
    """Clicking card A never starts card B's session: each click builds its own
    session (from that profile's data) and its own controller."""
    routes = {"FortiClient": "forticlient-v2", "Stormshield": "stormshield-v2"}
    monkeypatch.setattr(vpn_panel, "select_connect_route",
                        lambda name: routes.get(name, ROUTE_LEGACY))
    legacy_recorder(monkeypatch)
    panel = make_panel([profile(provider="FortiClient", login="userA"),
                        profile(provider="Stormshield", login="userB")], QLabel())

    panel._connect_card(0)
    panel._connect_card(1)

    assert len(FakeSession.instances) == 2
    # Each session carries the *clicked* profile's own data (isolation).
    assert FakeSession.instances[0].request.login == "userA"
    assert FakeSession.instances[1].request.login == "userB"
    # Two distinct controllers, one per card.
    assert panel._v2_controllers[0] is not panel._v2_controllers[1]


# ══════════════════════════════════════════════════════════════════════════
# 9. Integration: mocked gate ON → each provider builds ITS OWN V2 session
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("provider_name,provider_id,route", [
    ("FortiClient", "forticlient", "forticlient-v2"),
    ("Stormshield", "stormshield", "stormshield-v2"),
    ("Barracuda", "barracuda", "barracuda-v2"),
])
def test_9_v2_route_builds_a_session_for_the_clicked_provider(
        app, monkeypatch, wire_v2, provider_name, provider_id, route):
    """With the gate mocked open for one provider, the panel builds a session
    whose request names *that* provider — never a hardcoded FortiClient."""
    monkeypatch.setattr(vpn_panel, "select_connect_route",
                        lambda name, r=route: r if name == provider_name
                        else ROUTE_LEGACY)
    calls = legacy_recorder(monkeypatch)
    make_panel([profile(provider=provider_name)], QLabel())._connect_card(0)

    assert calls == [], "V2 route does not call the legacy connect"
    assert len(FakeSession.instances) == 1
    assert FakeSession.instances[0].request.provider_id == provider_id
    assert len(FakeController.instances) == 1
    # 2026-10-19: the card's sentences name the clicked client, not FortiClient.
    assert FakeController.instances[0].client == provider_name


def test_9b_gate_off_no_provider_builds_a_v2_session(app, monkeypatch):
    """The real gate (all flags off) never builds a session for any provider."""
    monkeypatch.setattr(vpn_panel, "PanelConnectSession", FakeSession)
    monkeypatch.setattr(vpn_panel, "V2ConnectController", FakeController)
    monkeypatch.setattr(vpn_panel, "load_vpn_autofill_enabled", lambda: True)
    monkeypatch.setattr(vpn_panel, "QTimer",
                        SimpleNamespace(singleShot=lambda ms, fn: None))
    legacy_recorder(monkeypatch)
    for name in ("FortiClient", "Stormshield", "Barracuda"):
        make_panel([profile(provider=name)], QLabel())._connect_card(0)
    assert FakeSession.instances == [] and FakeController.instances == []


# ══════════════════════════════════════════════════════════════════════════
# M. Final card state — V2 outcome goes through present_outcome (controller)
#    and legacy keeps its behaviour
# ══════════════════════════════════════════════════════════════════════════

def test_m_legacy_sets_the_status_label_as_before(app, monkeypatch):
    monkeypatch.setattr(vpn_panel, "load_vpn_autofill_enabled", lambda: False)
    monkeypatch.setattr(vpn_panel, "QTimer",
                        SimpleNamespace(singleShot=lambda ms, fn: None))
    monkeypatch.setattr(vpn_connect, "connect_monitored",
                        lambda *a, **k: (True, "Łączenie przez FortiClient...", None))
    monkeypatch.setattr(vpn_connect, "invalidate_adapter_cache", lambda: None)
    label = QLabel()
    panel = make_panel([profile()], label)
    panel._connect_card(0)
    assert label.text() == "Łączenie przez FortiClient..."[:30]


# ══════════════════════════════════════════════════════════════════════════
# N. Exception building/starting V2 does not leave the card stuck
# ══════════════════════════════════════════════════════════════════════════

def test_n_exception_in_v2_is_classified_not_left_connecting(app, monkeypatch,
                                                            wire_v2):
    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    FakeController.raise_on_init = True
    label = QLabel()
    panel = make_panel([profile()], label)

    panel._connect_card(0)                        # must not raise

    assert "V2" in label.text() and "Łączenie" not in label.text()
    assert panel._v2_controllers == {}, "no dangling controller after failure"
    # polling was resumed so the card is not frozen.
    assert ("start", 5000) in panel._status_timer.events


def test_n2_no_automatic_fallback_to_legacy_on_v2_error(app, monkeypatch, wire_v2):
    wire_v2("forticlient-v2")
    calls = legacy_recorder(monkeypatch)
    FakeController.raise_on_init = True
    make_panel([profile()], QLabel())._connect_card(0)
    assert calls == [], "a V2 error must NOT silently fall back to legacy"


# ══════════════════════════════════════════════════════════════════════════
# No provider was armed by any of this
# ══════════════════════════════════════════════════════════════════════════

def test_no_provider_was_activated():
    for cls in (FortiClientProvider, StormshieldProvider, BarracudaProvider):
        assert cls.CONNECT_ENABLED is False


# ═════════════════════════════════════════════════════════════════════════
# O. Re-entrancy (Stage 56) — a second click cannot start a second session
#
# The legacy connect blocks the UI thread, so a second click was impossible
# while one ran.  A V2 connect returns immediately, so it is not: without a
# guard the second click would start a rival session against the same window
# and rebind `_v2_controllers[idx]`, dropping the only reference to a
# controller whose QThread is still running.
# ═════════════════════════════════════════════════════════════════════════

def test_o_second_click_while_a_session_runs_starts_nothing(app, monkeypatch,
                                                            wire_v2):
    wire_v2("forticlient-v2")
    calls = legacy_recorder(monkeypatch)
    panel = make_panel([profile()], QLabel())

    panel._connect_card(0)
    first = FakeController.instances[0]
    panel._connect_card(0)                       # the impatient second click

    assert len(FakeSession.instances) == 1, "no rival session"
    assert len(FakeController.instances) == 1
    assert panel._v2_controllers[0] is first, "the running controller is kept"
    assert calls == [], "and it certainly does not fall back to legacy"


def test_o2_a_finished_session_does_not_wedge_the_card(app, monkeypatch,
                                                       wire_v2):
    """The guard is about *running* sessions only — reconnect still works."""
    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    panel = make_panel([profile()], QLabel())

    panel._connect_card(0)
    FakeController.instances[0].finish(None)     # session over
    panel._v2_controllers.pop(0, None)           # what _on_v2_finished does
    panel._connect_card(0)

    assert len(FakeSession.instances) == 2


def test_o3_another_card_is_never_blocked_by_a_busy_one(app, monkeypatch,
                                                        wire_v2):
    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    panel = make_panel([profile(), profile()], QLabel())

    panel._connect_card(0)
    panel._connect_card(1)

    assert len(FakeSession.instances) == 2
    assert set(panel._v2_controllers) == {0, 1}


# ═════════════════════════════════════════════════════════════════════════
# P. A poll must not write over a card its session owns (Stage 56)
#
# Stopping the repeating timer does not stop a poll another card scheduled with
# QTimer.singleShot, nor one already in flight — and those land in
# _apply_status_results, which used to rewrite every label it was given.
# ═════════════════════════════════════════════════════════════════════════

ACTIVATION_SENTENCE = "Przełącz się na okno FortiClienta..."


def test_p_a_poll_leaves_an_active_cards_label_alone(app, monkeypatch, wire_v2):
    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    label = QLabel()
    panel = make_panel([profile()], label)
    panel._connect_card(0)
    label.setText(ACTIVATION_SENTENCE)           # the controller's sentence

    panel._apply_status_results({0: "Disconnected"})

    assert label.text() == ACTIVATION_SENTENCE, "the user's instruction stands"
    assert panel.__dict__.get("_toggles", []) == [], "and the toggle is left be"


def test_p2_a_poll_still_updates_a_card_with_no_session(app, monkeypatch,
                                                        wire_v2):
    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    busy, idle = QLabel(), QLabel()
    panel = make_panel([profile(), profile()], busy)
    panel._status_labels = {0: busy, 1: idle}
    panel._connect_card(0)
    busy.setText(ACTIVATION_SENTENCE)

    panel._apply_status_results({0: "Disconnected", 1: "Connected"})

    assert busy.text() == ACTIVATION_SENTENCE
    assert idle.text() == "● Połączono", "other cards poll as they always did"


def test_p3_once_the_session_is_over_polling_owns_the_card_again(
        app, monkeypatch, wire_v2):
    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    label = QLabel()
    panel = make_panel([profile()], label)
    panel._connect_card(0)
    FakeController.instances[0].finish(None)

    panel._apply_status_results({0: "Disconnected"})

    assert label.text() == "○ Rozłączono"


def test_p4_the_gate_reads_the_controller_not_a_timer(app, monkeypatch, wire_v2):
    """`active` is the session's own state — not a fixed 14-second window."""
    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    panel = make_panel([profile()], QLabel())
    assert panel._v2_session_active(0) is False
    panel._connect_card(0)
    assert panel._v2_session_active(0) is True
    FakeController.instances[0].finish(None)
    assert panel._v2_session_active(0) is False


# ═════════════════════════════════════════════════════════════════════════
# Q. The CLI monitor the panel does not yet own (Stage 56 — recorded gap)
#
# For `connect_monitored` + autofill the flow tries the CLI route FIRST, and a
# CLI_STARTED outcome carries a live process.  Legacy hands that process to
# `_start_monitor` for stdout 2FA detection; the V2 handler does not.  This
# pins the gap so that wiring it is a deliberate change, not a surprise.
# ═════════════════════════════════════════════════════════════════════════

def test_q_a_cli_outcomes_monitor_is_not_adopted_by_the_panel(app, monkeypatch,
                                                              wire_v2):
    """Documented gap `cli-monitor-not-owned-by-panel`, with its own test.

    When the panel does take the monitor, this test fails and is rewritten —
    which is the point: the behaviour is recorded, not assumed.
    """
    from vpn.panel_bridge import KNOWN_GAPS, PanelConnectOutcome, PanelOutcome

    assert "cli-monitor-not-owned-by-panel" in {gap for gap, _ in KNOWN_GAPS}

    wire_v2("forticlient-v2")
    legacy_recorder(monkeypatch)
    started = []
    panel = make_panel([profile()], QLabel())
    panel._start_monitor = lambda idx, proc: started.append((idx, proc))
    panel._connect_card(0)

    process = object()                       # stands in for the live Popen
    outcome = PanelConnectOutcome(code=PanelOutcome.CLI_STARTED, started=True,
                                  route="cli_monitored", monitor=process)
    assert outcome.monitor is process, "the information reaches the panel"
    panel._on_v2_finished(0, outcome)

    assert started == [], "…and nothing consumes it yet (the recorded gap)"


# ══════════════════════════════════════════════════════════════════════════
# 2026-10-19 (owner's test): status after a V2 connect, and a missing profile
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("provider,expected", [
    ("FortiClient", PROFILE), ("Barracuda", PROFILE), ("Stormshield", SERVER)])
def test_v2_click_tells_the_status_poll_which_profile_connects(
        app, monkeypatch, wire_v2, provider, expected):
    """Without it a FortiClient profile with no server never showed Connected."""
    monkeypatch.setattr(vpn_panel, "select_connect_route", lambda name: "v2")
    monkeypatch.setattr(vpn_connect, "_last_connected", {})
    monkeypatch.setattr(vpn_connect, "_last_connected_meta", {})
    make_panel([profile(provider=provider)], QLabel())._connect_card(0)
    assert vpn_connect._last_connected[provider] == expected
    assert vpn_connect._last_connected_meta[provider] == {
        "server": SERVER, "profile_name": PROFILE}


def test_a_missing_forticlient_profile_is_explained_with_the_ones_that_exist(
        app, monkeypatch):
    from vpn.panel_bridge import PanelConnectOutcome, PanelOutcome
    shown = []
    monkeypatch.setattr(vpn_connect, "get_forti_tunnels_from_registry",
                        lambda: [{"name": "1SZP"}, {"name": "Betanin"}])
    monkeypatch.setattr(vpn_panel, "QTimer",
                        SimpleNamespace(singleShot=lambda ms, fn: None))
    panel = make_panel([profile(profile_name="Wieluń")], QLabel())
    monkeypatch.setattr(panel, "_explain_missing_tunnel",
                        lambda p: shown.append(p.profile_name), raising=False)
    outcome = PanelConnectOutcome(code=PanelOutcome.AUTOFILL_BLOCKED,
                                  reason="requested-tunnel-not-configured")
    panel._on_v2_finished(0, outcome)
    assert shown == ["Wieluń"]

    other = []
    monkeypatch.setattr(panel, "_explain_missing_tunnel",
                        lambda p: other.append(p), raising=False)
    panel._on_v2_finished(0, PanelConnectOutcome(code=PanelOutcome.AUTOFILL_BLOCKED,
                                                 reason="focus-lost"))
    assert other == [], "inne blokady nie udają braku profilu"


def test_the_missing_profile_message_names_the_configured_ones(app, monkeypatch):
    monkeypatch.setattr(vpn_connect, "get_forti_tunnels_from_registry",
                        lambda: [{"name": "1SZP"}, {"name": "Betanin"}])
    host = QWidget()
    panel = make_panel([profile(profile_name="Wieluń")], QLabel())
    shown = []
    monkeypatch.setattr(vpn_panel.QMessageBox, "show",
                        lambda self: shown.append(self.text()))
    vpn_panel.VpnPanel._explain_missing_tunnel.__get__(host)(panel._profiles[0])
    assert shown and "„Wieluń”" in shown[0]
    assert "1SZP, Betanin" in shown[0]
    assert PASSWORD not in shown[0] and LOGIN not in shown[0]
