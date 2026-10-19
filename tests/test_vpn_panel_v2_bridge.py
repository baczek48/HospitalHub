"""Stage 46: VpnPanel → FortiClient V2, prepared and deliberately not switched on.

Two new modules sit between the card and the provider — ``vpn.panel_bridge``
(gate, request, session, outcome codes) and ``ui.vpn_v2_connect`` (worker,
prompt, card update) — and the panel knows neither.  These tests prove four
things, in this order of importance:

1. **Production still connects through the legacy module**, with the flag off
   *and* with the flag forced on — the panel is not wired, so there is no path
   from a click to V2 at all (``test_1*``).
2. **V2 is not reachable by accident**: no production module names the bridge,
   importing the panel pulls in nothing new, and a disarmed session cannot even
   construct the real runtime (``test_2*``).
3. **The wiring holds its contracts** on a fake machine: the worker owns the
   wait, Cancel reaches the token, a timeout or a lost foreground ends without a
   single keystroke (``test_3*``–``test_5*``).
4. **Every provider result has a card sentence** in the panel's own palette,
   and the UI half cannot see a secret or a window (``test_6*``–``test_7*``).
"""

import ast
import glob
import os
import subprocess
import sys
import threading
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
import vpn_connect  # noqa: E402
from vpn import (  # noqa: E402
    AutofillResult, AutofillStatus, AutomationMode, ConnectResult, ConnectStep,
    VpnRequest, VpnState,
)
from vpn import panel_bridge as pb  # noqa: E402
from vpn.panel_bridge import (  # noqa: E402
    PanelConnectSession, PanelOutcome, build_request, classify_connect_result,
    select_connect_route,
)
from vpn.providers import FortiClientProvider  # noqa: E402
from vpn.providers import forticlient_connect as fcc  # noqa: E402
from vpn.providers import forticlient_runtime as fcr  # noqa: E402
from vpn.providers import input_system as isys  # noqa: E402
from vpn.providers.activation_gate import ActivationState  # noqa: E402
from vpn.providers.launch_system import LaunchSystem  # noqa: E402
from ui import vpn_panel  # noqa: E402
from ui import vpn_v2_connect as v2ui  # noqa: E402
from ui.activation_prompt import STATE_COLOURS, STATE_MESSAGES  # noqa: E402
from ui.vpn_v2_connect import (  # noqa: E402
    OUTCOME_PRESENTATION, CardUpdate, V2ConnectController, present_outcome,
)
from tests.test_vpn_forticlient_2fa import FakeMessages, RecTrace  # noqa: E402
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    TUNNEL_REGISTRY, FakeInput,
)
from tests.test_vpn_forticlient_connect_assembled import (  # noqa: E402
    FORTIVPN, FakeClock, FakeLaunch, FakeMonitor, ScriptedProvider, desktop_with,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import FORTI_DIR, FORTI_GUI, HWND, OTHER  # noqa: E402

LOGIN, PASSWORD = "jkowalski", "SuperSecret123"
PROFILE, SERVER, PORT = "SZPITAL-A", "vpn.example.org", "10443"
NEW_MODULES = (os.path.join("vpn", "panel_bridge.py"),
               os.path.join("ui", "vpn_v2_connect.py"))


@pytest.fixture(scope="module")
def app():
    existing = QApplication.instance()
    yield existing if existing is not None else QApplication([])


@pytest.fixture
def card(app):
    """A card with its status label — a parent, so nothing becomes a window."""
    holder = QWidget()
    label = QLabel("", holder)
    yield SimpleNamespace(holder=holder, label=label)
    holder.deleteLater()


def vault_profile(**overrides):
    values = dict(name="Szpital A", provider="FortiClient", server=SERVER,
                  port=PORT, login=LOGIN, password=PASSWORD, group="grp",
                  domain="dom", app_path=FORTI_GUI, profile_name=PROFILE)
    values.update(overrides)
    return models.VpnProfile(**values)


def machine(*, window=True, foreground=None, timeout_s=2.0, files=None,
            launch=None, auth_window=False):
    """The assembled connect over a fake desktop, reachable only via a factory."""
    inputs = FakeInput()
    launch = launch if launch is not None else FakeLaunch()
    provider = ScriptedProvider(
        environment=FakeEnvironment(
            registry=dict(TUNNEL_REGISTRY),
            files=files if files is not None else [FORTI_GUI], dirs=[FORTI_DIR]),
        main_hwnds=(HWND,) if window else (), system=launch)
    desktop = desktop_with(main_window=window, foreground=foreground,
                           auth_window=auth_window)
    built = []

    def factory(*, cancellation, activation_observer):
        runtime = provider.connect_runtime(
            clock=FakeClock(), launch_system=launch, input_system=inputs,
            window_api=desktop, message_system=FakeMessages(), trace=RecTrace(),
            cancellation=cancellation, activation_observer=activation_observer,
            activation_timeout_s=timeout_s, msaa_system=inputs.msaa)
        built.append(runtime)
        return runtime

    return SimpleNamespace(provider=provider, inputs=inputs, desktop=desktop,
                           factory=factory, launch=launch, built=built)


def session_on(m, *, autofill=True, **profile_overrides):
    request = build_request(vault_profile(**profile_overrides),
                            app_path=FORTI_GUI, autofill=autofill)
    return PanelConnectSession(request, provider=m.provider,
                               runtime_factory=m.factory)


def secret_events(inputs):
    return [e for e in inputs.events if e[0] in ("type", "key", "combo", "clip_set")]


class Harness:
    """The controller on a card, with the UI thread pumped like the real app."""

    def __init__(self, session, card):
        self.session = session
        self.controller = V2ConnectController(session, card.label,
                                              prompt_parent=card.holder)
        self.states, self.updates, self.outcomes = [], [], []
        self.controller.worker.state_changed.connect(self.states.append)
        self.controller.card_update.connect(self.updates.append)
        self.controller.finished.connect(self.outcomes.append)

    def start(self):
        self.controller.start()
        return self

    def pump(self, until, timeout_s=10.0):
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline and not until():
            QApplication.processEvents()
            self.controller.worker.wait(5)
        for _ in range(3):
            QApplication.processEvents()
        return self

    def finish(self):
        self.controller.worker.wait(10000)
        self.pump(until=lambda: bool(self.outcomes))
        assert len(self.outcomes) == 1, self.outcomes
        return self.outcomes[0]


# ══════════════════════════════════════════════════════════════════════════
# 1. The production panel still chooses the legacy connect
# ══════════════════════════════════════════════════════════════════════════

def test_1_the_gate_answers_legacy_while_connect_is_disabled():
    assert FortiClientProvider.CONNECT_ENABLED is False
    for name in models.VPN_PROVIDERS_BUILTIN:
        assert select_connect_route(name) == pb.ROUTE_LEGACY, name


@pytest.mark.parametrize("value", [1, "True", "yes", object(), None])
def test_1b_only_a_real_true_opens_the_gate(monkeypatch, value):
    monkeypatch.setattr(FortiClientProvider, "CONNECT_ENABLED", value)
    assert select_connect_route("FortiClient") == pb.ROUTE_LEGACY


def test_1c_the_gate_opens_for_forticlient_alone(monkeypatch):
    monkeypatch.setattr(FortiClientProvider, "CONNECT_ENABLED", True)
    assert select_connect_route("FortiClient") == pb.ROUTE_FORTICLIENT_V2
    for name in models.VPN_PROVIDERS_BUILTIN:
        if name != "FortiClient":
            assert select_connect_route(name) == pb.ROUTE_LEGACY, name


class _CardStub:
    """Just enough of VpnPanel for its real `_connect_card` to run."""

    def __init__(self, profile, label):
        self._profiles = [profile]
        self._status_labels = {0: label}
        self._status_timer = None
        self.toggles, self.monitors = [], []

    def _resolve_app_path(self, p):
        return vpn_panel.VpnPanel._resolve_app_path(self, p)

    def _update_toggle_btn(self, idx, state):
        self.toggles.append(state)

    def _start_monitor(self, idx, process):
        self.monitors.append(process)

    def _poll_status(self):
        pass


def _v2_tripwires(monkeypatch):
    """Every door into V2; each one records that somebody knocked."""
    knocks = []

    def door(name):
        def knock(*a, **k):
            knocks.append(name)
            raise AssertionError(f"panel sięgnął po V2: {name}")
        return knock

    monkeypatch.setattr(FortiClientProvider, "connect", door("provider.connect"))
    monkeypatch.setattr(FortiClientProvider, "connect_runtime", door("connect_runtime"))
    monkeypatch.setattr(fcr.FortiConnectRuntime, "__init__", door("runtime"))
    monkeypatch.setattr(isys.Win32InputSystem, "__init__", door("Win32InputSystem"))
    monkeypatch.setattr(pb, "select_connect_route", door("select_connect_route"))
    monkeypatch.setattr(PanelConnectSession, "run", door("session.run"))
    monkeypatch.setattr(v2ui.V2ConnectController, "__init__", door("controller"))
    return knocks


@pytest.mark.parametrize("autofill", [True, False])
def test_1d_clicking_connect_goes_through_the_legacy_module(
        monkeypatch, card, autofill):
    """The real `_connect_card`, with the gate off (production state).

    Stage 52 wired the V2 branch, but with FortiClient's flag off the route is
    legacy, so a click still calls ``vpn_connect.connect_monitored`` and touches
    nothing in the V2 chain.
    """
    assert FortiClientProvider.CONNECT_ENABLED is False
    knocks = _v2_tripwires(monkeypatch)
    legacy_calls, timers = [], []

    def legacy_connect(*args, **kwargs):
        legacy_calls.append((args, kwargs))
        return True, "Łączenie przez FortiClient...", None

    monkeypatch.setattr(vpn_connect, "connect_monitored", legacy_connect)
    monkeypatch.setattr(vpn_connect, "invalidate_adapter_cache", lambda: None)
    monkeypatch.setattr(vpn_panel, "load_vpn_autofill_enabled", lambda: autofill)
    monkeypatch.setattr(vpn_panel, "QTimer", SimpleNamespace(
        singleShot=lambda ms, fn: timers.append(ms)))

    stub = _CardStub(vault_profile(), card.label)
    vpn_panel.VpnPanel._connect_card(stub, 0)

    assert knocks == []
    assert legacy_calls == [(
        ("FortiClient", SERVER, PORT, LOGIN, PASSWORD, "grp", "dom", FORTI_GUI,
         PROFILE), {"autofill": autofill})]
    assert stub.toggles == ["connecting"]
    assert card.label.text() == "Łączenie przez FortiClient..."[:30]
    assert timers == [15000 if autofill else 2000], "opóźnienie pollu jak dotąd"


def test_1e_vpn_panel_wires_v2_and_the_hospital_button_uses_the_same_route():
    """Stage 52: ``vpn_panel`` gains the V2 wiring names and keeps the legacy
    call.  2026-10-20 (owner): the hospital window's VPN button takes the same
    route — through ``ui.vpn_panel``'s own gate and bridge names, never its own
    import of the bridge — and keeps the legacy call for every other provider."""
    def parse(rel):
        with open(os.path.join(_PARENT, "ui", rel), encoding="utf-8") as f:
            return ast.parse(f.read())

    def names_in(tree):
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        called = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                  and isinstance(n.value, ast.Name) and n.value.id == "vpn_connect"}
        return names, called

    panel_names, panel_called = names_in(parse("vpn_panel.py"))
    assert "connect_monitored" in panel_called, "legacy call still present"
    for token in ("select_connect_route", "PanelConnectSession",
                  "V2ConnectController", "build_request"):
        assert token in panel_names, ("vpn_panel missing V2 wiring", token)

    detail = parse("detail_panel.py")
    detail_names, detail_called = names_in(detail)
    assert "connect_monitored" in detail_called, "legacy path kept for the rest"
    # Every V2 name it uses is an attribute of ui.vpn_panel (``_vp.<name>``).
    for token in ("select_connect_route", "PanelConnectSession",
                  "V2ConnectController", "build_request"):
        uses = [n for n in ast.walk(detail) if isinstance(n, ast.Attribute)
                and n.attr == token]
        assert uses and all(isinstance(n.value, ast.Name) and n.value.id == "_vp"
                            for n in uses), token
    modules = {n.module for n in ast.walk(detail) if isinstance(n, ast.ImportFrom)}
    modules |= {a.name for n in ast.walk(detail) if isinstance(n, ast.Import)
                for a in n.names}
    assert not any(m and (m == "vpn" or m.startswith("vpn.")) for m in modules)
    assert "ui.vpn_v2_connect" not in modules


# ══════════════════════════════════════════════════════════════════════════
# 2. V2 cannot be reached by accident
# ══════════════════════════════════════════════════════════════════════════

def _production_sources():
    for path in glob.glob(os.path.join(_PARENT, "**", "*.py"), recursive=True):
        rel = os.path.relpath(path, _PARENT)
        # build/ and dist/ are PyInstaller output — copies of the sources the
        # bundle carries, not modules of their own.
        if (rel.split(os.sep)[0] in ("vpn", "tests", "smoke", "build", "dist")
                or "__pycache__" in rel):
            continue
        yield rel, open(path, encoding="utf-8").read()


def test_2_no_production_module_names_the_bridge_or_the_controller():
    for rel, source in _production_sources():
        # The V2 UI halves name their VPN counterpart in prose; ``vpn_panel.py``
        # is the sanctioned integration point (Stage 52) and legitimately wires
        # the bridge + controller.  Every *other* production module must not.
        if rel in (os.path.join("ui", "vpn_v2_connect.py"),
                   os.path.join("ui", "vpn_v2_twofactor.py"),
                   os.path.join("ui", "vpn_panel.py")):
            continue
        if rel == os.path.join("ui", "detail_panel.py"):
            # 2026-10-20: the hospital button goes through ui.vpn_panel's gate
            # (test_1e pins how); it names no bridge module itself.
            for token in ("panel_bridge", "vpn_v2_connect"):
                assert token not in source, (rel, token)
            continue
        for token in ("panel_bridge", "vpn_v2_connect", "V2ConnectController",
                      "PanelConnectSession", "select_connect_route"):
            assert token not in source, (rel, token)


def test_2b_the_ui_controller_cannot_arm_anything_itself():
    """No `vpn` import, no flag, no provider: it runs what it is handed."""
    rel = os.path.join("ui", "vpn_v2_connect.py")
    source = open(os.path.join(_PARENT, rel), encoding="utf-8").read()
    tree = ast.parse(source)
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                for a in n.names}
    assert not any(m and m.split(".")[0] in ("vpn", "vpn_connect") for m in modules)
    for token in ("CONNECT_ENABLED", "FortiClientProvider", "connect_runtime",
                  "default_registry", "VpnRequest"):
        assert token not in source, token


def test_2c_nothing_in_the_vpn_package_imports_the_bridge():
    """Importing `vpn` (as the tests and live scripts do) must not load it."""
    for path in glob.glob(os.path.join(_PARENT, "vpn", "**", "*.py"), recursive=True):
        if path.endswith("panel_bridge.py"):
            continue
        assert "panel_bridge" not in open(path, encoding="utf-8").read(), path


def test_2d_importing_the_application_wires_the_bridge_but_stays_gated_off():
    """Stage 52: importing the app now loads the bridge (the wiring), and with
    every flag off ``select_connect_route`` answers legacy for all providers."""
    code = ("import sys, os\n"
            "os.environ['QT_QPA_PLATFORM'] = 'offscreen'\n"
            "import main, ui.main_window, ui.vpn_panel, ui.detail_panel\n"
            "from vpn.panel_bridge import select_connect_route as r, ROUTE_LEGACY\n"
            "import models\n"
            "assert 'vpn.panel_bridge' in sys.modules, 'bridge wired'\n"
            "bad = [n for n in models.VPN_PROVIDERS_BUILTIN if r(n) != ROUTE_LEGACY]\n"
            "print('ARMED:', bad)\n")
    out = subprocess.run([sys.executable, "-c", code], cwd=_PARENT,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip().splitlines()[-1] == "ARMED: []", out.stdout


def test_2e_the_build_does_not_pull_the_new_modules_in():
    spec = open(os.path.join(_PARENT, "HospitalHubV2.spec"), encoding="utf-8").read()
    for token in ("panel_bridge", "vpn_v2_connect", "activation_prompt", "'vpn'"):
        assert token not in spec, token


def test_2f_a_disarmed_session_does_not_even_build_the_runtime(monkeypatch):
    built = []
    monkeypatch.setattr(fcr.FortiConnectRuntime, "__init__",
                        lambda self, *a, **k: built.append("runtime"))
    monkeypatch.setattr(isys.Win32InputSystem, "__init__",
                        lambda self, *a, **k: built.append("input"))

    class Tripwire(LaunchSystem):
        def __getattribute__(self, name):
            raise AssertionError(f"sesja dotknęła maszyny: {name}")

    provider = FortiClientProvider(
        environment=FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]),
        system=Tripwire())
    request = build_request(vault_profile(), app_path=FORTI_GUI, autofill=True)
    outcome = PanelConnectSession(request, provider=provider).run()

    assert outcome.code is PanelOutcome.UNSUPPORTED and not outcome.started
    assert built == []


def test_2g_the_default_session_uses_the_registered_disarmed_provider():
    request = build_request(vault_profile(), app_path=FORTI_GUI, autofill=True)
    assert PanelConnectSession(request).run().code is PanelOutcome.UNSUPPORTED


def test_2h_a_session_runs_once_and_forgets_the_request():
    m = machine()
    session = session_on(m)
    assert session.run().code is PanelOutcome.SUBMITTED
    assert session._request is None
    assert PASSWORD not in repr(session)
    again = session.run()
    assert again.code is PanelOutcome.FAILED
    assert len(m.built) == 1, "drugi run nie zbudował drugiego runtime"


# ══════════════════════════════════════════════════════════════════════════
# 3. The whole chain on a fake machine: card → worker → provider → card
# ══════════════════════════════════════════════════════════════════════════

def test_3_the_client_in_front_is_filled_and_the_card_says_connecting(card):
    m = machine()
    run = Harness(session_on(m), card).start()
    outcome = run.finish()

    assert outcome.code is PanelOutcome.SUBMITTED and outcome.started
    assert run.states == ["locating-target", "awaiting-activation",
                          "activation-observed"], run.states
    update = run.updates[0]
    assert update == CardUpdate("Łączenie przez FortiClient...", "#58a6ff",
                                "connecting", 2000)
    assert card.label.text() == update.text
    assert card.label.styleSheet() == update.style_sheet
    assert not run.controller.prompt.isVisibleTo(card.holder)
    assert PASSWORD in [e[1] for e in m.inputs.events if e[0] == "clip_set"], \
        "hasło doszło do klienta — przez provider, nie przez UI"


def test_3b_the_worker_reports_the_waiting_state_while_it_waits(card):
    reached, release = threading.Event(), threading.Event()

    def foreground(n):
        if n == 2:
            reached.set()
            release.wait(10)
        return OTHER if n <= 2 else HWND

    m = machine(foreground=foreground)
    run = Harness(session_on(m), card).start()
    run.pump(until=reached.is_set)
    run.pump(until=lambda: run.controller.prompt.presenter.state
             == "awaiting-activation")

    assert card.label.text() == STATE_MESSAGES["awaiting-activation"]
    assert run.controller.prompt.cancel_button.isVisibleTo(run.controller.prompt)
    assert secret_events(m.inputs) == [], "czekamy — nic nie jest wpisywane"

    release.set()
    assert run.finish().code is PanelOutcome.SUBMITTED


# ══════════════════════════════════════════════════════════════════════════
# 4. Cancel reaches the CancellationToken — and only that
# ══════════════════════════════════════════════════════════════════════════

def test_4_cancel_during_the_wait_reaches_the_token_and_types_nothing(card):
    reached, release = threading.Event(), threading.Event()

    def foreground(n):
        if n == 2:
            reached.set()
            release.wait(10)
        return HWND if n > 2 else OTHER      # the client WOULD come forward

    m = machine(foreground=foreground, timeout_s=30.0)
    session = session_on(m)
    run = Harness(session, card).start()
    run.pump(until=reached.is_set)
    run.pump(until=lambda: run.controller.prompt.presenter.state
             == "awaiting-activation")

    run.controller.prompt.cancel_button.click()
    assert session.cancellation.cancelled, "klik doszedł do tokenu"
    assert m.built[0].cancellation is session.cancellation, \
        "ten sam token, który trzyma bramka"
    release.set()
    outcome = run.finish()

    assert outcome.code is PanelOutcome.CANCELLED and not outcome.started
    assert secret_events(m.inputs) == []
    assert card.label.text() == STATE_MESSAGES["cancelled"]
    assert run.updates[0].card_state is None, "karta nie udaje łączenia"


def test_4b_cancel_before_the_start_means_connect_never_runs(card, monkeypatch):
    m = machine()
    calls = []
    original = m.provider.connect
    monkeypatch.setattr(m.provider, "connect",
                        lambda *a, **k: calls.append(1) or original(*a, **k))
    run = Harness(session_on(m), card)
    run.controller.cancel()
    outcome = run.start().finish()

    assert outcome.code is PanelOutcome.CANCELLED
    assert calls == [] and m.built == [], "nawet detekcja się nie odbyła"
    assert m.inputs.events == [] and m.launch.calls == []


def test_4c_cancel_after_the_outcome_changes_nothing(card):
    m = machine(foreground=lambda n: OTHER)
    session = session_on(m)
    run = Harness(session, card).start()
    outcome = run.finish()
    assert outcome.code is PanelOutcome.ACTIVATION_TIMEOUT

    run.controller.cancel()
    run.controller.prompt.request_cancel()
    QApplication.processEvents()
    assert not session.cancellation.cancelled
    assert card.label.text() == STATE_MESSAGES["activation-timeout"]
    assert len(run.outcomes) == 1


# ══════════════════════════════════════════════════════════════════════════
# 5. Timeout and a lost foreground end safely, without an autofill
# ══════════════════════════════════════════════════════════════════════════

def test_5_timeout_ends_with_the_instruction_and_no_keystroke(card):
    m = machine(foreground=lambda n: OTHER, timeout_s=2.0)
    run = Harness(session_on(m), card).start()
    outcome = run.finish()

    assert outcome.code is PanelOutcome.ACTIVATION_TIMEOUT
    assert outcome.state == "activation-timeout" and not outcome.started
    assert m.inputs.events == [], "InputSystem nietknięty"
    assert card.label.text() == STATE_MESSAGES["activation-timeout"]
    assert card.label.styleSheet() == v2ui.label_style_sheet("#f85149")
    assert not run.controller.prompt.isVisibleTo(card.holder)


def test_5b_no_client_window_ends_as_no_target(card):
    m = machine(window=False, timeout_s=2.0)
    outcome = Harness(session_on(m), card).start().finish()
    assert outcome.code is PanelOutcome.NO_TARGET
    assert secret_events(m.inputs) == []


def test_5c_foreground_lost_after_activation_blocks_before_any_secret(card):
    m = machine(foreground=lambda n: HWND if n <= 1 else OTHER)
    run = Harness(session_on(m), card).start()
    outcome = run.finish()

    assert outcome.code is PanelOutcome.FOCUS_LOST and not outcome.started
    assert secret_events(m.inputs) == []
    assert "nic nie zostało wpisane" in card.label.text()


def test_5d_foreground_lost_mid_fill_stops_before_the_password(card):
    m = machine(foreground=lambda n: HWND if n <= 3 else OTHER)
    outcome = Harness(session_on(m), card).start().finish()

    assert outcome.code is PanelOutcome.AUTOFILL_BLOCKED
    assert PASSWORD not in [e[1] for e in m.inputs.events if e[0] == "clip_set"]
    assert ("key", isys.VK_RETURN) not in m.inputs.events, "bez Entera"


def test_5e_a_session_that_raises_reaches_the_card_as_a_plain_failure(card):
    class Exploding:
        observer = None

        def run(self):
            raise RuntimeError(f"C:\\Users\\{LOGIN} {PASSWORD}")

        def cancel(self):
            pass

    run = Harness(Exploding(), card).start()
    run.controller.worker.wait(5000)
    run.pump(until=lambda: bool(run.outcomes))
    assert run.outcomes == [None]
    assert card.label.text() == OUTCOME_PRESENTATION["failed"][0]
    assert PASSWORD not in card.label.text() and LOGIN not in card.label.text()


# ══════════════════════════════════════════════════════════════════════════
# 6. Provider result → the card's statuses and sentences
# ══════════════════════════════════════════════════════════════════════════

def _run_outcome(m, **kwargs):
    return session_on(m, **kwargs).run()


def test_6_mapping_over_the_real_flow():
    assert _run_outcome(machine()).code is PanelOutcome.SUBMITTED
    assert _run_outcome(machine(), autofill=False).code is PanelOutcome.MANUAL
    assert _run_outcome(machine(foreground=lambda n: OTHER)).code \
        is PanelOutcome.ACTIVATION_TIMEOUT
    assert _run_outcome(machine(window=False, files=[])).code \
        is PanelOutcome.CLIENT_NOT_FOUND
    two_factor = _run_outcome(machine(auth_window=True), requires_2fa=True)
    assert two_factor.code is PanelOutcome.TWO_FACTOR_REQUIRED and two_factor.started


def test_6b_the_cli_route_hands_the_monitor_to_the_card():
    """Found while writing this stage: without a token the flow reports
    TOKEN_REQUIRED over PROCESS_STDOUT for *every* monitored CLI.  The panels
    pass no token and let the stdout monitor decide, so the card must say
    "connecting", not "finish 2FA" before the client has asked for anything.
    """
    monitor = FakeMonitor()
    m = machine(window=False, files=[FORTI_GUI, FORTIVPN],
                launch=FakeLaunch(monitored=monitor))
    session = session_on(m)
    outcome = session.run()
    assert outcome.code is PanelOutcome.CLI_STARTED and outcome.started
    assert outcome.monitor is monitor and outcome.state is None
    assert outcome.route == fcc.ROUTE_CLI_MONITORED


def test_6b2_a_blocked_cli_token_is_still_the_users_move():
    from vpn import TwoFactorMode, TwoFactorResult, TwoFactorStatus
    result = ConnectResult(
        provider_id="forticlient", success=True, state=VpnState.CONNECTING,
        automation=AutomationMode.CLI, route=fcc.ROUTE_CLI_MONITORED,
        monitor=FakeMonitor(), requires_user_action=True,
        two_factor_result=TwoFactorResult(
            provider_id="forticlient", status=TwoFactorStatus.BLOCKED,
            mode=TwoFactorMode.PROCESS_STDOUT, blocked_at="process"))
    assert classify_connect_result(result).code is PanelOutcome.TWO_FACTOR_REQUIRED


@pytest.mark.parametrize("result,expected", [
    (ConnectResult(provider_id="forticlient", success=False,
                   error_code="unsupported"), PanelOutcome.UNSUPPORTED),
    (ConnectResult(provider_id="forticlient", success=False,
                   error_code="process-start-failed"), PanelOutcome.FAILED),
    (ConnectResult(provider_id="forticlient", success=False,
                   error_code="connect-failed"), PanelOutcome.FAILED),
    (ConnectResult(provider_id="forticlient", success=True,
                   state=VpnState.UNKNOWN, automation=AutomationMode.MANUAL,
                   requires_user_action=True, error_code="focus-failed",
                   steps=(ConnectStep(fcc.PHASE_AWAIT_ACTIVATION, "failed",
                                      "focus-failed", "target-changed"),)),
     PanelOutcome.TARGET_CHANGED),
    (ConnectResult(provider_id="forticlient", success=True,
                   state=VpnState.UNKNOWN, automation=AutomationMode.MANUAL,
                   requires_user_action=True,
                   autofill=AutofillResult(provider_id="forticlient",
                                           status=AutofillStatus.NO_FOCUS)),
     PanelOutcome.AUTOFILL_BLOCKED),
    (ConnectResult(provider_id="forticlient", success=True,
                   state=VpnState.CONNECTING, automation=AutomationMode.TAB_SEQUENCE,
                   automation_pending=True), PanelOutcome.STARTED),
])
def test_6c_mapping_of_the_remaining_shapes(result, expected):
    assert classify_connect_result(result).code is expected


def test_6d_every_outcome_has_a_card_sentence_and_every_gate_ending_is_an_outcome():
    assert {o.value for o in PanelOutcome} == set(OUTCOME_PRESENTATION)
    endings = {s.value for s in ActivationState} - {
        "locating-target", "awaiting-activation", "activation-observed"}
    assert endings <= {o.value for o in PanelOutcome}


def test_6e_the_gate_endings_reuse_the_prompts_own_sentences():
    for state in ("activation-timeout", "no-target", "target-changed", "cancelled"):
        update = present_outcome(state)
        assert update.text == STATE_MESSAGES[state]
        assert update.colour == STATE_COLOURS[state]


def test_6f_started_outcomes_flip_the_card_like_a_legacy_ok():
    for code in pb.STARTED_OUTCOMES:
        update = present_outcome(code)
        assert update.card_state == "connecting" and update.poll_after_ms == 2000
    for code in set(PanelOutcome) - set(pb.STARTED_OUTCOMES):
        assert present_outcome(code).card_state is None, code


def test_6g_card_colours_are_the_panels_own():
    panel = open(os.path.join(_PARENT, "ui", "vpn_panel.py"), encoding="utf-8").read()
    for _text, colour, _state in OUTCOME_PRESENTATION.values():
        assert f"color: {colour}; font-size: 10px;" in panel, colour


def test_6h_an_unknown_code_fails_safe():
    update = present_outcome("stage-47-invented-this")
    assert update.text == OUTCOME_PRESENTATION["failed"][0]
    assert update.card_state is None


def test_6i_no_sentence_carries_a_diagnostic_or_a_secret():
    blob = " ".join(text for text, _c, _s in OUTCOME_PRESENTATION.values()).lower()
    for leak in ("hwnd", "pid", "0x", "error", "reason", "traceback",
                 "forticlient.exe", LOGIN.lower(), PASSWORD.lower()):
        assert leak not in blob, leak


def test_6j_outcomes_carry_no_secret():
    for m, kwargs in ((machine(), {}), (machine(), {"autofill": False}),
                      (machine(foreground=lambda n: OTHER), {})):
        outcome = _run_outcome(m, **kwargs)
        assert PASSWORD not in repr(outcome) and LOGIN not in repr(outcome)
    # `reason` (2026-10-14, L5) is the autofill's reason code — a code such as
    # "requested-tunnel-not-configured", never a value or a name.
    assert set(pb.PanelConnectOutcome.__dataclass_fields__) == {
        "code", "state", "started", "route", "error_code", "monitor", "reason"}


def test_6k_the_request_mirrors_the_legacy_call_arguments():
    profile = vault_profile(requires_2fa=True)
    request = build_request(profile, app_path=FORTI_GUI, autofill=False)
    assert request == VpnRequest(
        provider_id="forticlient", profile_name=PROFILE, server=SERVER,
        port=PORT, login=LOGIN, password=PASSWORD, group="grp", domain="dom",
        app_path=FORTI_GUI, autofill=False, requires_2fa=True)
    assert request.token == ""


# ══════════════════════════════════════════════════════════════════════════
# 7. What the UI half may never reach for
# ══════════════════════════════════════════════════════════════════════════

WIN32_MODULES = ("ctypes", "win32gui", "win32con", "win32api", "win32process",
                 "keyboard", "pyautogui", "secure_window")
WINDOW_AND_INPUT_NAMES = (
    "Win32InputSystem", "InputSystem", "input_system", "SendInput",
    "keybd_event", "SetForegroundWindow", "set_foreground_window", "SW_RESTORE",
    "ShowWindow", "restore_window", "BringWindowToTop", "SetWindowPos",
    "HWND_TOPMOST", "AttachThreadInput", "acquire_focus", "acquire",
    "press_key", "press_combo", "type_text", "copy_to_clipboard", "WM_SETTEXT")


def _imports_and_names(rel):
    tree = ast.parse(open(os.path.join(_PARENT, rel), encoding="utf-8").read())
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                for a in n.names}
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    return modules, names


@pytest.mark.parametrize("rel", [os.path.join("ui", name) for name in (
    "vpn_v2_connect.py", "activation_prompt.py", "vpn_panel.py", "detail_panel.py")])
def test_7_vpn_ui_imports_no_input_system_and_no_window_raising(rel):
    modules, names = _imports_and_names(rel)
    for module in modules:
        root = (module or "").split(".")[0]
        assert root not in WIN32_MODULES, (rel, module)
        assert not (module or "").endswith("input_system"), (rel, module)
    for banned in WINDOW_AND_INPUT_NAMES:
        assert banned not in names, (rel, banned)


def test_7b_the_controller_does_not_touch_focus_clipboard_or_timers():
    _modules, names = _imports_and_names(os.path.join("ui", "vpn_v2_connect.py"))
    for banned in ("clipboard", "QClipboard", "activateWindow", "raise_",
                   "setFocus", "QTimer", "singleShot", "processEvents", "sleep"):
        assert banned not in names, banned


def test_7c_the_controller_is_never_handed_a_credential():
    import inspect
    for fn in (V2ConnectController.__init__, V2ConnectController.start,
               V2ConnectController.cancel, present_outcome):
        params = set(inspect.signature(fn).parameters)
        assert not ({"login", "password", "token", "request", "secret",
                     "credentials", "profile"} & params), fn.__qualname__
    _modules, names = _imports_and_names(os.path.join("ui", "vpn_v2_connect.py"))
    for field_name in ("password", "login", "token", "request", "hwnd"):
        assert field_name not in names, field_name
    assert set(CardUpdate.__dataclass_fields__) == {
        "text", "colour", "card_state", "poll_after_ms"}


def test_7d_the_bridge_itself_has_no_system_machinery():
    modules, names = _imports_and_names(os.path.join("vpn", "panel_bridge.py"))
    for module in modules:
        assert (module or "").split(".")[0] not in (
            *WIN32_MODULES, "subprocess", "PyQt6", "ui", "vpn_connect"), module
    for banned in WINDOW_AND_INPUT_NAMES:
        assert banned not in names, banned


def test_7e_the_known_gaps_are_recorded():
    ids = {gap for gap, _ in pb.KNOWN_GAPS}
    # The remaining real gaps before a switched-on Connect (Stage 56 re-read
    # the whole table against the code; this is what actually survives).
    assert {"detail-panel-not-covered", "cli-live-unverified",
            "cli-monitor-not-owned-by-panel",
            "connect-runtime-not-live-armed"} <= ids
    # Gaps closed in earlier stages must not linger in the list: a cutover is
    # decided from this table, so a stale entry is a wrong decision waiting.
    assert "stdout-2fa-monitor" not in ids, "domknięte w Stage 50"
    assert "status-polling-not-paused" not in ids, "domknięte w Stage 47"
    assert "panel-not-wired" not in ids, "domknięte w Stage 52"
    assert "no-cancel-during-autofill" not in ids, "domknięte w Stage 47"
    assert "no-live-run-through-ui" not in ids, "domknięte w Stage 51"
    for _gap, description in pb.KNOWN_GAPS:
        assert len(description) > 40
