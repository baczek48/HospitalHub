"""Etap 64 (2026-10-14): what the V2 session and the panel guarantee around a fill.

From the pre-cutover audit of the FortiClient V2 paths:

* L2 — one V2 connect at a time in the process: two sessions would both pass
  the activation gate and type into one client through one clipboard.
* L4 — every armed session leaves a ``vpn.connect.v2`` trace, without a
  credential and without the profile name.
* L5 — a blocked autofill carries its reason code, and the card says what it
  means (a misconfigured profile is not a security incident).
* L7/L8/L14 — the panel does not rebuild a card from under a running session,
  calls sessions off when it is discarded, and releases only its own
  controller.

Fakes only; no window, no key, no VPN.
"""

import os
import sys
import threading
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn import panel_bridge as pb  # noqa: E402
from vpn.types import (  # noqa: E402
    AutofillResult, AutofillStatus, ConnectResult, VpnRequest,
)

LOGIN, PASSWORD, PROFILE = "jkowalski", "TajneHaslo!9", "SZPITAL-A"


def request():
    return VpnRequest(provider_id="forticlient", profile_name=PROFILE,
                      login=LOGIN, password=PASSWORD, server="vpn.example.org")


class Provider:
    """Answers connect() with a prepared result; optionally waits first."""

    CONNECT_ENABLED = False

    def __init__(self, result=None, gate=None, raises=False):
        self.result = result or ConnectResult(provider_id="forticlient", success=True)
        self.gate = gate
        self.raises = raises
        self.calls = 0

    def connect(self, req, entry, *, system):
        self.calls += 1
        if self.gate is not None:
            self.gate["entered"].set()
            self.gate["release"].wait(5)
        if self.raises:
            raise RuntimeError("boom")
        return self.result


def session(provider):
    return pb.PanelConnectSession(
        request(), provider=provider,
        runtime_factory=lambda **kw: SimpleNamespace(**kw))


# ══════════════════════════════════════════════════════════════════════════
# L2 — one session at a time
# ══════════════════════════════════════════════════════════════════════════

def test_l2_a_second_session_while_one_runs_is_busy_and_does_nothing():
    gate = {"entered": threading.Event(), "release": threading.Event()}
    first = Provider(gate=gate)
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("first", session(first).run()))
    t.start()
    assert gate["entered"].wait(5)
    assert pb.v2_session_running()

    second = Provider()
    outcome = session(second).run()
    assert outcome.code is pb.PanelOutcome.BUSY
    assert second.calls == 0, "druga sesja nic nie robi"

    gate["release"].set()
    t.join(5)
    assert out["first"].code is not pb.PanelOutcome.BUSY
    assert not pb.v2_session_running()


def test_l2_the_slot_is_freed_even_when_the_session_raises():
    outcome = session(Provider(raises=True)).run()
    assert outcome.code is pb.PanelOutcome.FAILED
    assert not pb.v2_session_running()
    assert session(Provider()).run().code is not pb.PanelOutcome.BUSY


def test_l2_a_disarmed_provider_never_takes_the_slot():
    provider = Provider()
    outcome = pb.PanelConnectSession(request(), provider=provider).run()
    assert outcome.code is pb.PanelOutcome.UNSUPPORTED
    assert not pb.v2_session_running() and provider.calls == 0


# ══════════════════════════════════════════════════════════════════════════
# L4 — the trace
# ══════════════════════════════════════════════════════════════════════════

class RecTrace:
    def __init__(self, operation, meta):
        self.operation, self.meta, self.finished = operation, meta, None

    def finish(self, **kw):
        self.finished = kw


@pytest.fixture
def traces(monkeypatch):
    from diagnostics import vpn as vpn_diag
    made = []

    def start(operation, **meta):
        made.append(RecTrace(operation, meta))
        return made[-1]
    monkeypatch.setattr(vpn_diag, "start", start)
    return made


def blocked(reason):
    return ConnectResult(
        provider_id="forticlient", success=True,
        autofill=AutofillResult(provider_id="forticlient",
                                status=AutofillStatus.BLOCKED,
                                blocked_at="profile",
                                metadata={"reason_code": reason}))


def test_l4_an_armed_session_writes_one_trace_with_facts_only(traces):
    outcome = session(Provider(result=blocked("requested-tunnel-not-configured"))).run()
    assert len(traces) == 1 and traces[0].operation == "vpn.connect.v2"
    blob = repr(traces[0].meta) + repr(traces[0].finished)
    for secret in (LOGIN, PASSWORD, PROFILE):
        assert secret not in blob, secret
    assert traces[0].meta["has_profile_name"] is True
    assert traces[0].finished["reason_code"] == "requested-tunnel-not-configured"
    assert traces[0].finished["outcome"] == str(outcome.code)


def test_l4_the_redactor_keeps_the_trace_keys():
    """Review 64/N3: keys outside the redactor's allowlist are dropped from an
    exported trace, which would leave it empty of exactly these facts."""
    from diagnostics import redactor
    for key in ("entry", "has_profile_name", "has_credentials", "outcome",
                "reason_code", "activation", "route", "exception", "autofill"):
        assert key in redactor.ALLOWED_KEYS, key


def test_l4_a_session_that_raises_still_finishes_its_trace(traces):
    session(Provider(raises=True)).run()
    assert traces[0].finished["status"] == "fail"
    assert traces[0].finished["exception"] == "RuntimeError"


def test_l4_a_broken_diagnostics_layer_cannot_fail_the_connect(monkeypatch):
    from diagnostics import vpn as vpn_diag

    def broken(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(vpn_diag, "start", broken)
    outcome = session(Provider()).run()
    assert outcome.code is not pb.PanelOutcome.FAILED


# ══════════════════════════════════════════════════════════════════════════
# L5 — the reason reaches the card
# ══════════════════════════════════════════════════════════════════════════

def test_l5_the_blocked_reason_is_carried_as_a_code():
    outcome = pb.classify_connect_result(blocked("profile-not-specified"))
    assert outcome.code is pb.PanelOutcome.AUTOFILL_BLOCKED
    assert outcome.reason == "profile-not-specified"
    done = ConnectResult(provider_id="forticlient", success=True,
                         autofill=AutofillResult(provider_id="forticlient",
                                                 success=True,
                                                 status=AutofillStatus.DONE))
    assert pb.classify_connect_result(done).reason is None


@pytest.fixture
def ui_connect(app):
    from ui import vpn_v2_connect
    return vpn_v2_connect


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.mark.parametrize("reason,needle", [
    ("requested-tunnel-not-configured", "Nazwa profilu w kliencie"),
    ("requested-profile-untrimmed", "Nazwa profilu w kliencie"),
    ("profile-not-specified", "nie ma nazwy profilu"),
    ("unknown-group-label", "IPsec"),
    ("profile-display-not-changeable", "IPsec"),
    ("profile-not-confirmed", "Nie udało się potwierdzić profilu"),
    ("msaa-unavailable", "Nie udało się potwierdzić profilu"),
])
def test_l5_each_profile_reason_has_its_own_sentence(ui_connect, reason, needle):
    update = ui_connect.present_outcome("autofill-blocked", reason)
    assert needle in update.text
    assert "Logowanie nie zostało wysłane" in update.text
    assert update.card_state is None


def test_l5_other_blocks_keep_the_security_sentence(ui_connect):
    generic = ui_connect.OUTCOME_PRESENTATION["autofill-blocked"][0]
    for reason in (None, "", "caret-not-in-text-field", "foreground-changed"):
        assert ui_connect.present_outcome("autofill-blocked", reason).text == generic


def test_l5_busy_has_a_sentence_and_flips_nothing(ui_connect):
    update = ui_connect.present_outcome("busy")
    assert "Trwa inne łączenie" in update.text and update.card_state is None


# ══════════════════════════════════════════════════════════════════════════
# L7 / L8 / L14 — the panel around a running session
# ══════════════════════════════════════════════════════════════════════════

class Controller:
    def __init__(self, active=True, running=True):
        self.active = active
        self.cancelled = False
        self.worker = Worker(running)

    def cancel(self):
        self.cancelled = True


class Signal:
    def __init__(self):
        self.slots = []

    def connect(self, slot):
        self.slots.append(slot)

    def emit(self):
        for slot in self.slots:
            slot()


class Worker:
    def __init__(self, running):
        self._running = running
        self.finished = Signal()

    def isRunning(self):
        return self._running


@pytest.fixture
def panel(app):
    from ui import vpn_panel
    p = vpn_panel.VpnPanel.__new__(vpn_panel.VpnPanel)
    p.__dict__.update(_v2_controllers={})
    return vpn_panel, p


class _Info:
    shown = []

    @staticmethod
    def information(*a, **k):
        _Info.shown.append(a[1] if len(a) > 1 else "")


@pytest.mark.parametrize("action", ["sort", "edit", "add", "import", "settings"])
def test_l7_nothing_that_reorders_the_cards_starts_while_a_session_runs(
        panel, monkeypatch, action):
    """Review 64/B1: a rebuild held back left the cards' buttons pointing at
    shifted indexes — "Kopiuj hasło" on one hospital copied another's
    password.  Nothing that changes the profile list starts during a session."""
    vpn_panel, p = panel
    monkeypatch.setattr(vpn_panel, "QMessageBox", _Info)
    _Info.shown = []
    a, b = SimpleNamespace(name="B szpital"), SimpleNamespace(name="A szpital")
    p.__dict__.update(_profiles=[a, b], _edit_idx=-1)
    p._v2_controllers[0] = Controller(active=True)
    rebuilt = []
    monkeypatch.setattr(vpn_panel.VpnPanel, "_rebuild_cards",
                        lambda self: rebuilt.append(True))

    calls = {"sort": lambda: vpn_panel.VpnPanel._sort_profiles(p, "name"),
             "edit": lambda: vpn_panel.VpnPanel._enter_edit(p, 0),
             "add": lambda: vpn_panel.VpnPanel._add_profile(p),
             "import": lambda: vpn_panel.VpnPanel._import_forti_tunnels(p),
             "settings": lambda: vpn_panel.VpnPanel._open_vpn_settings(p)}
    calls[action]()

    assert p._profiles == [a, b], "kolejność i skład profili bez zmian"
    assert p._edit_idx == -1 and rebuilt == []
    assert _Info.shown == ["Trwa łączenie VPN"]


def test_l7_without_a_session_sorting_works_as_before(panel, monkeypatch):
    vpn_panel, p = panel
    a, b = SimpleNamespace(name="B szpital", provider=""), SimpleNamespace(
        name="A szpital", provider="")
    emitted = []
    p.__dict__.update(_profiles=[a, b],
                      data_changed=SimpleNamespace(emit=lambda: emitted.append(1)))
    monkeypatch.setattr(vpn_panel.VpnPanel, "_rebuild_cards", lambda self: None)
    vpn_panel.VpnPanel._sort_profiles(p, "name")
    assert p._profiles == [b, a] and emitted == [1]


def test_l14_only_the_sessions_own_controller_is_released(panel):
    vpn_panel, p = panel
    old, new = Controller(active=False), Controller(active=True)
    p._v2_controllers[0] = new                    # a new click already started
    vpn_panel.VpnPanel._release_v2(p, 0, old)
    assert p._v2_controllers[0] is new


def test_l8_discarding_the_panel_calls_sessions_off_and_keeps_them_alive(panel):
    vpn_panel, p = panel
    running, idle = Controller(running=True), Controller(running=False)
    p._v2_controllers.update({0: running, 1: idle})
    p.__dict__.update(_status_timer=SimpleNamespace(stop=lambda: None),
                      _status_worker=None, _monitor_workers={})
    vpn_panel.VpnPanel.cleanup(p)

    assert running.cancelled and idle.cancelled
    assert p._v2_controllers == {}
    assert running in vpn_panel._RETIRED_CONTROLLERS, "żyje do końca wątku"
    assert idle not in vpn_panel._RETIRED_CONTROLLERS
    running.worker.finished.emit()
    assert running not in vpn_panel._RETIRED_CONTROLLERS
