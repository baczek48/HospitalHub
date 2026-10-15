"""Stage 16: the assembled `FortiClientProvider.connect()`.

The previous stages each migrated one responsibility; this one wires them into
a single flow and proves the wiring — that the phases run in the legacy order,
that each component's outcome reaches :class:`ConnectResult`, that nothing runs
twice, that a security refusal anywhere stops the secret rather than the
report, and that the whole thing is still switched off for production.

The machine is entirely fake: a desktop (:class:`WindowApi`) with the client's
window on it, an :class:`InputSystem` that records keystrokes, a
:class:`WindowMessageSystem` that records ``WM_SETTEXT``, a
:class:`LaunchSystem` that records command lines and starts nothing.  No
FortiClient, no window, no SendInput, no clipboard, no process.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import vpn  # noqa: E402
from vpn import (  # noqa: E402
    AutofillStatus, AutomationMode, Capability, DetectionResult, DetectionState,
    LaunchResult, TwoFactorMode, TwoFactorStatus, VpnRequest, VpnState,
)
from vpn.providers import FortiClientProvider  # noqa: E402
from vpn.providers import forticlient_connect as fcc  # noqa: E402
from vpn.providers import forticlient_runtime as fcr  # noqa: E402
from vpn.providers.activation_gate import Clock  # noqa: E402
from vpn.providers.launch_system import LaunchSystem  # noqa: E402
from tests.test_vpn_forticlient_2fa import (  # noqa: E402
    AUTH_HWND, B_CONNECT, E_TOKEN, FakeMessages, RecTrace, auth_windows,
)
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    TUNNEL_REGISTRY, FakeInput,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import (  # noqa: E402
    EVIL_EXE, EVIL_PID, FORTI_DIR, FORTI_GUI, FORTI_PID, HWND, OTHER,
    FakeDesktop, ListFinder,
)

TOKEN = "845217"
LOGIN, PASSWORD = "jkowalski", "SuperSecret123"
SECRETS = (LOGIN, PASSWORD, TOKEN)
PROFILE, SERVER, PORT = "SZPITAL-A", "vpn.example.org", "10443"
FORTIVPN = FORTI_DIR + r"\FortiVPN.exe"
SSLVPN = r"C:\Program Files (x86)\Fortinet\SslvpnClient\FortiSSLVPNclient.exe"

FORTI_TID = 41


class FakeClock(Clock):
    """Time that only moves when somebody waits — no test spends a real second."""

    def __init__(self):
        self.now = 0.0
        self.slept = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


class FakeLaunch(LaunchSystem):
    """Records command lines; starts nothing.  `probe_output` drives the CLI probe."""

    def __init__(self, probe_output="tunnel: up", monitored=None,
                 raise_on_spawn=False):
        self.calls = []
        self.probe_output = probe_output
        self.monitored = monitored
        self.raise_on_spawn = raise_on_spawn

    def run_capture(self, cmd, timeout):
        self.calls.append(("run_capture", tuple(cmd)))
        return 0, self.probe_output

    def spawn_hidden(self, cmd):
        self.calls.append(("spawn_hidden", tuple(cmd)))
        if self.raise_on_spawn:
            raise OSError(5, "ERROR_ACCESS_DENIED")
        return 4242

    def spawn_monitored(self, cmd):
        self.calls.append(("spawn_monitored", tuple(cmd)))
        if self.raise_on_spawn:
            raise OSError(5, "ERROR_ACCESS_DENIED")
        return self.monitored

    # launching the GUI is covered by the launch stage's own tests
    def open_with_explorer(self, path):
        raise AssertionError("connect nie uruchamia explorera bezpośrednio")

    def spawn_detached(self, exe, cwd):
        self.calls.append(("spawn_detached", exe))
        return 4243

    def wait_for_process(self, image_name, timeout):
        return True


class FakeMonitor:
    """The Popen-shaped handle a monitored CLI hands back."""

    def __init__(self, pid=FORTI_PID, lines=()):
        self.pid = pid
        self.stdin = _Pipe()
        self.stdout = _Pipe(lines)


class _Pipe:
    def __init__(self, lines=()):
        self._lines = [line.encode() for line in lines]
        self.written = []

    def readline(self):
        return self._lines.pop(0) if self._lines else b""

    def write(self, data):
        self.written.append(data)

    def flush(self):
        pass


class LiveDesktop(FakeDesktop):
    """A desktop where taking focus actually changes the foreground window.

    The connect flow touches two different windows (the client's main window
    and its authentication dialog), so a fixed foreground would make the
    second acquisition always fail for the wrong reason.
    """

    def __init__(self, *, start=HWND, **kwargs):
        super().__init__(**kwargs)
        self.current = start

    def foreground_window(self):
        self.fg_checks += 1
        if self._forced is not None:
            return self._forced(self.fg_checks)
        return self.current

    def set_foreground_window(self, hwnd):
        self.events.append(("set_foreground",))
        self.current = hwnd
        return True


def desktop_with(main_window=True, auth_window=False, foreground=None, **kwargs):
    """A desktop carrying the client's main window and/or its auth window."""
    windows = {OTHER: (EVIL_PID, 99, OTHER)}
    if main_window:
        windows[HWND] = (FORTI_PID, FORTI_TID, HWND)
    if auth_window:
        windows.update(auth_windows())
    kwargs.setdefault("windows", windows)
    desktop = LiveDesktop(**kwargs)
    desktop._forced = foreground
    return desktop


class ScriptedProvider(FortiClientProvider):
    """The provider with a scripted finder — the window search has its own tests."""

    def __init__(self, *, main_hwnds=(HWND,), auth_hwnds=(AUTH_HWND,), **kwargs):
        super().__init__(**kwargs)
        self._main_hwnds, self._auth_hwnds = main_hwnds, auth_hwnds

    def secure_window_target(self, api=None, finder=None):
        return super().secure_window_target(
            api=api, finder=finder or ListFinder(self._main_hwnds))

    def auth_window_target(self, api=None, finder=None):
        return super().auth_window_target(
            api=api, finder=finder or ListFinder(self._auth_hwnds))

    def auth_credentials_target(self, api=None, finder=None):
        # Stage 58: without this the credentials fill (Stage 48) enumerated
        # the real desktop's windows.
        return super().auth_credentials_target(
            api=api, finder=finder or ListFinder(self._auth_hwnds))


#: What `_free_edition` reads: FA_FCM "installed" == 0 means the VPN-only build.
FREE_EDITION_REGISTRY = {r"SOFTWARE\Fortinet\FortiClient\FA_FCM": {"installed": 0}}


def fake_runtime(provider, **seams):
    """`connect_runtime` with the MSAA view of the same fake input (Stage 63),
    so a profile is read from the combo the keys act on — never from the real
    machine."""
    inputs = seams.setdefault("input_system", FakeInput())
    seams.setdefault("msaa_system", inputs.msaa)
    return provider.connect_runtime(**seams)


def build(*, window=True, cli=False, sslvpn=False, auth_window=False,
          desktop=None, launch=None, messages=None, main_hwnds=None,
          free_edition=False):
    files = [FORTI_GUI] + ([FORTIVPN] if cli else []) + ([SSLVPN] if sslvpn else [])
    registry = dict(TUNNEL_REGISTRY)
    if free_edition:
        registry.update(FREE_EDITION_REGISTRY)
    provider = ScriptedProvider(
        environment=FakeEnvironment(registry=registry, files=files,
                                    dirs=[FORTI_DIR]),
        main_hwnds=main_hwnds if main_hwnds is not None else ((HWND,) if window else ()),
        system=launch or FakeLaunch())
    desktop = desktop if desktop is not None else desktop_with(
        main_window=window, auth_window=auth_window)
    inputs = FakeInput()
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=launch or FakeLaunch(), input_system=inputs,
        window_api=desktop, message_system=messages or FakeMessages(),
        trace=RecTrace(), msaa_system=inputs.msaa)
    return provider, runtime, desktop


def request(**kwargs):
    kwargs.setdefault("profile_name", PROFILE)
    kwargs.setdefault("autofill", True)
    return VpnRequest(provider_id="forticlient", server=SERVER, port=PORT,
                      login=LOGIN, password=PASSWORD, app_path=FORTI_GUI, **kwargs)


def connect(provider, runtime, req=None, entry=fcc.ENTRY_CONNECT_MONITORED):
    return provider.connect(req if req is not None else request(), entry,
                            system=runtime)


def phases(result):
    return [(step.phase, step.status) for step in result.steps]


def phase_names(result):
    return [step.phase for step in result.steps]


# ══════════════════════════════════════════════════════════════════════════
# GUI: 1–5
# ══════════════════════════════════════════════════════════════════════════

def test_1_client_already_running_is_filled_without_a_launch():
    launch = FakeLaunch()
    provider, runtime, _ = build(window=True, launch=launch)
    result = connect(provider, runtime)

    assert result.success and result.state is VpnState.CONNECTING
    assert result.route == fcc.ROUTE_WINDOW_RESTORE
    assert result.launch is None, "działający klient nie jest uruchamiany"
    assert result.automation is AutomationMode.TAB_SEQUENCE
    assert result.autofill.status is AutofillStatus.DONE
    assert result.autofill.login_entered and result.autofill.password_entered
    assert [c[0] for c in launch.calls] == [], "żaden proces nie wystartował"


def test_2_client_not_running_is_launched_then_filled():
    provider, runtime, desktop = build(window=False)
    # The window appears once the launch has run — the finder is asked again.
    launched = {"done": False}

    original = provider.launch

    def launching(req=None):
        launched["done"] = True
        provider._main_hwnds = (HWND,)
        desktop.windows[HWND] = (FORTI_PID, FORTI_TID, HWND)
        return original(req)

    provider.launch = launching
    result = connect(provider, runtime)

    assert launched["done"] and result.launch is not None and result.launch.success
    assert result.route == fcc.ROUTE_GUI_LAUNCH
    assert result.autofill.status is AutofillStatus.DONE
    assert phase_names(result).count("launch") == 1


def test_3_gui_manual_copies_the_password_and_types_nothing():
    inputs = FakeInput()
    provider, _runtime, desktop = build(window=True)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=FakeLaunch(), input_system=inputs, window_api=desktop,
        message_system=FakeMessages())
    result = connect(provider, runtime, request(autofill=False))

    assert result.success and result.requires_user_action
    assert result.automation is AutomationMode.MANUAL
    assert result.state is VpnState.UNKNOWN, "nic nie zostało wysłane do klienta"
    assert result.autofill is None and result.two_factor_result is None
    assert inputs.events == [("clip_set", PASSWORD)], "tylko schowek"


def test_4_gui_two_factor_puts_the_token_in_the_auth_window():
    messages = FakeMessages()
    provider, _r, desktop = build(window=True, auth_window=True)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=FakeLaunch(), input_system=FakeInput(), window_api=desktop,
        message_system=messages)
    result = connect(provider, runtime, request(requires_2fa=True, token=TOKEN))

    assert result.success
    assert result.two_factor is TwoFactorMode.AUTH_WINDOW
    assert result.two_factor_result.status is TwoFactorStatus.SUBMITTED
    assert ("set_text", E_TOKEN, TOKEN) in messages.events
    assert ("click", B_CONNECT) in messages.events
    assert not result.requires_user_action


def test_5_autofill_and_two_factor_run_in_that_order_exactly_once():
    messages = FakeMessages()
    provider, _r, desktop = build(window=True, auth_window=True)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=FakeLaunch(), input_system=FakeInput(), window_api=desktop,
        message_system=messages)
    result = connect(provider, runtime, request(requires_2fa=True, token=TOKEN))

    names = phase_names(result)
    assert names.index("autofill_start") < names.index("two_factor")
    assert names.count("autofill_start") == 1
    assert names.count("two_factor") == 1
    assert len([e for e in messages.events if e[0] == "set_text"]) == 1


def test_gui_two_factor_without_a_token_asks_the_caller_and_sends_nothing():
    messages = FakeMessages()
    provider, _r, desktop = build(window=True, auth_window=True)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=FakeLaunch(), input_system=FakeInput(), window_api=desktop,
        message_system=messages)
    result = connect(provider, runtime, request(requires_2fa=True))

    assert result.success and result.requires_user_action
    assert result.two_factor_result.status is TwoFactorStatus.TOKEN_REQUIRED
    assert [e for e in messages.events if e[0] == "set_text"] == []


# ══════════════════════════════════════════════════════════════════════════
# GUI: 6–10 — everything that stops the flow
# ══════════════════════════════════════════════════════════════════════════

def test_6_no_target_window_falls_through_to_the_launch():
    provider, runtime, _ = build(window=False)
    result = connect(provider, runtime)
    assert result.route == fcc.ROUTE_GUI_LAUNCH
    assert ("window_probe", "none") in phases(result)


def test_7_a_window_of_a_foreign_process_is_not_the_client():
    """A title match owned by somebody else must not become the target."""
    desktop = desktop_with(main_window=True, images={FORTI_PID: EVIL_EXE,
                                                     EVIL_PID: EVIL_EXE})
    provider, _r, _ = build(window=True, desktop=desktop)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=FakeLaunch(), input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages())
    result = connect(provider, runtime)
    assert ("window_probe", "none") in phases(result), "obce okno nie jest klientem"
    assert result.route == fcc.ROUTE_GUI_LAUNCH


def test_8_a_blocked_autofill_is_reported_and_the_password_stays_home():
    inputs = FakeInput()
    # The window is the client's up to the login paste, then somebody else
    # takes the foreground: the guard refuses before the password is touched.
    desktop = desktop_with(foreground=lambda n: HWND if n <= 7 else OTHER)
    provider, _r, _ = build(window=True, desktop=desktop)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=FakeLaunch(), input_system=inputs, window_api=desktop,
        message_system=FakeMessages())
    result = connect(provider, runtime)

    assert result.success, "connect wystartował — automatyka tylko nie dokończyła"
    assert result.state is VpnState.UNKNOWN
    assert result.automation is AutomationMode.MANUAL and result.requires_user_action
    assert result.autofill.status is AutofillStatus.BLOCKED
    assert result.autofill.password_entered is False
    assert result.error_code == "secret-input-blocked"
    assert ("autofill_start", "failed") in phases(result)
    assert PASSWORD not in [e[1] for e in inputs.events if e[0] == "clip_set"],         "hasło nigdy nie trafiło nawet do schowka"


def test_8b_a_blocked_autofill_stops_the_flow_before_two_factor():
    desktop = desktop_with(auth_window=True,
                           foreground=lambda n: HWND if n <= 7 else OTHER)
    desktop.windows[HWND] = (FORTI_PID, FORTI_TID, HWND)
    messages = FakeMessages()
    provider, _r, _ = build(window=True, desktop=desktop)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=FakeLaunch(), input_system=FakeInput(), window_api=desktop,
        message_system=messages)
    result = connect(provider, runtime, request(requires_2fa=True, token=TOKEN))

    assert result.autofill.status is AutofillStatus.BLOCKED
    assert "two_factor" not in phase_names(result)
    assert result.two_factor_result is None
    assert [e for e in messages.events if e[0] == "set_text"] == []


def test_9_a_blocked_two_factor_is_reported_without_failing_the_connect():
    # No auth window on the desktop: the token has nowhere trusted to go.
    provider, _r, desktop = build(window=True, auth_window=False)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=FakeLaunch(), input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages())
    result = connect(provider, runtime, request(requires_2fa=True, token=TOKEN))

    assert result.success and result.requires_user_action
    assert result.two_factor_result.status is TwoFactorStatus.FAILED
    assert result.two_factor_result.error_code == "otp-window-not-found"
    assert ("two_factor", "failed") in phases(result)


def test_10_launch_failure_fails_the_connect_with_the_real_reason():
    provider, runtime, _ = build(window=False)
    provider.launch = lambda req=None: LaunchResult(
        provider_id="forticlient", success=False,
        error_code="process-start-failed")
    result = connect(provider, runtime)

    assert result.success is False
    assert result.error_code == "process-start-failed"
    assert result.route == fcc.ROUTE_GUI_LAUNCH
    assert ("launch", "failed") in phases(result)
    assert result.autofill is None and result.two_factor_result is None


# ══════════════════════════════════════════════════════════════════════════
# CLI: 11–15
# ══════════════════════════════════════════════════════════════════════════

def test_11_cli_start_succeeds_and_carries_the_legacy_command_line():
    monitor = FakeMonitor()
    launch = FakeLaunch(monitored=monitor)
    provider, _r, desktop = build(window=False, cli=True, launch=launch)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=launch, input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages())
    result = connect(provider, runtime)

    assert result.success and result.route == fcc.ROUTE_CLI_MONITORED
    assert result.automation is AutomationMode.CLI
    assert result.monitor is monitor
    assert result.state is VpnState.CONNECTING
    spawned = [cmd for kind, cmd in launch.calls if kind == "spawn_monitored"]
    assert spawned == [(FORTIVPN, "--cli", "--connect", "--tunnel", PROFILE,
                        "--username", LOGIN, "--password", PASSWORD,
                        "--savecredentials")]
    assert result.launch is None, "CLI nie otwiera GUI"


def test_12_a_cli_challenge_reaches_the_two_factor_component():
    monitor = FakeMonitor(lines=["Connecting...\n", "Please enter your token:\n"])
    provider, _r, desktop = build(window=False, cli=True)
    outcome = provider.answer_two_factor_challenge(
        request(requires_2fa=True, token=TOKEN), monitor, api=desktop)

    assert outcome is not None and outcome.status is TwoFactorStatus.SUBMITTED
    assert outcome.mode is TwoFactorMode.PROCESS_STDOUT


def test_12b_stdout_that_never_asks_produces_no_answer():
    monitor = FakeMonitor(lines=["Connecting...\n", "tunnel up\n"])
    provider, _r, desktop = build(window=False, cli=True)
    assert provider.answer_two_factor_challenge(
        request(token=TOKEN), monitor, api=desktop) is None
    assert monitor.stdin.written == []


def test_13_the_token_is_written_to_the_verified_client_process_only():
    monitor = FakeMonitor(lines=["Enter your OTP:\n"])
    provider, _r, desktop = build(window=False, cli=True)
    provider.answer_two_factor_challenge(request(token=TOKEN), monitor, api=desktop)
    assert monitor.stdin.written == [(TOKEN + "\n").encode()]

    # ...and not to anything else, however convincingly named.
    other = FakeMonitor(pid=EVIL_PID, lines=["Enter your OTP:\n"])
    outcome = provider.answer_two_factor_challenge(request(token=TOKEN), other,
                                                   api=desktop)
    assert outcome.status is TwoFactorStatus.BLOCKED
    assert other.stdin.written == []


def test_14_a_cli_that_cannot_start_fails_the_monitored_connect():
    launch = FakeLaunch(raise_on_spawn=True)
    provider, _r, desktop = build(window=False, cli=True, launch=launch)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=launch, input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages())
    result = connect(provider, runtime)

    assert result.success is False and result.error_code == "launch-failed"
    assert result.route == fcc.ROUTE_CLI_MONITORED
    assert result.metadata["reason_code"] == "OSError"


def test_14b_the_same_failure_through_the_connect_entry_falls_through():
    """Legacy asymmetry, preserved: connect() keeps going, connect_monitored does not."""
    launch = FakeLaunch(raise_on_spawn=True)
    provider, _r, desktop = build(window=False, cli=True, launch=launch)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=launch, input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages())
    result = connect(provider, runtime, entry=fcc.ENTRY_CONNECT)
    assert result.route == fcc.ROUTE_GUI_LAUNCH


def test_15_cli_is_skipped_when_the_user_turned_automation_off():
    launch = FakeLaunch()
    provider, _r, desktop = build(window=True, cli=True, launch=launch)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=launch, input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages())
    result = connect(provider, runtime, request(autofill=False))

    assert result.route == fcc.ROUTE_WINDOW_RESTORE
    assert result.automation is AutomationMode.MANUAL
    assert [c for c in launch.calls if c[0].startswith("spawn")] == [], \
        "bez autofillu żadne poświadczenia nie idą do wiersza poleceń"


def test_cli_probe_never_runs_on_the_free_edition():
    launch = FakeLaunch()
    provider, _r, desktop = build(window=False, cli=True, launch=launch,
                                  free_edition=True)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=launch, input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages())
    connect(provider, runtime)
    assert [c for c in launch.calls if c[0] == "run_capture"] == []


def test_cli_probe_answer_is_cached_like_the_legacy():
    launch = FakeLaunch()
    provider, _r, desktop = build(window=False, cli=True, launch=launch)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=launch, input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages())
    assert runtime.cli_supported(FORTI_GUI) is True
    assert runtime.cli_supported(FORTI_GUI) is True
    assert len([c for c in launch.calls if c[0] == "run_capture"]) == 1


@pytest.mark.parametrize("output", ["Error parsing arguments",
                                    "The option does not exist"])
def test_cli_probe_reads_the_legacy_markers(output):
    launch = FakeLaunch(probe_output=output)
    provider, _r, desktop = build(window=False, cli=True, launch=launch)
    runtime = fake_runtime(provider, clock=FakeClock(), launch_system=launch, window_api=desktop)
    assert runtime.cli_supported(FORTI_GUI) is False


# ══════════════════════════════════════════════════════════════════════════
# 16–23: propagation, order, nothing twice
# ══════════════════════════════════════════════════════════════════════════

def test_16_a_detection_failure_is_recorded_and_never_decides_the_connect():
    provider, runtime, _ = build(window=True)
    provider.detect = lambda req=None: DetectionResult(
        provider_id="forticlient", success=False, state=DetectionState.ERROR,
        error_code="detection-failed")
    result = connect(provider, runtime)

    assert ("detect", "none") in phases(result)
    assert result.steps[0].error_code == "detection-failed"
    assert result.success, "działający klient nadal zostaje znaleziony"
    assert result.route == fcc.ROUTE_WINDOW_RESTORE


def test_17_a_request_without_a_profile_still_follows_the_legacy_route():
    launch = FakeLaunch(monitored=FakeMonitor())
    provider, _r, desktop = build(window=False, cli=True, launch=launch)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=launch, input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages())
    result = connect(provider, runtime, request(profile_name=""))

    # LEGACY_BEHAVIOR "cli-monitored-empty-profile": --tunnel '' and success.
    assert result.success and result.route == fcc.ROUTE_CLI_MONITORED
    spawned = [cmd for kind, cmd in launch.calls if kind == "spawn_monitored"][0]
    assert spawned[spawned.index("--tunnel") + 1] == ""


def test_17b_a_request_without_credentials_omits_them_from_the_command_line():
    launch = FakeLaunch(monitored=FakeMonitor())
    provider, _r, desktop = build(window=False, cli=True, launch=launch)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=launch, input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages())
    connect(provider, runtime, VpnRequest(provider_id="forticlient",
                                          profile_name=PROFILE,
                                          app_path=FORTI_GUI))
    spawned = [cmd for kind, cmd in launch.calls if kind == "spawn_monitored"][0]
    assert "--username" not in spawned and "--password" not in spawned


def test_18_every_phase_result_reaches_the_connect_result():
    messages = FakeMessages()
    # auth_window=False on purpose (Stage 48): with the EMS credentials window
    # now migrated, an auth window on screen would take the EMS route and there
    # would be no launch/autofill to observe.  This test wants the launch path,
    # so it starts with no window at all and grows one in `launching`.
    provider, _r, desktop = build(window=False, auth_window=False)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=FakeLaunch(), input_system=FakeInput(), window_api=desktop,
        message_system=messages)

    original = provider.launch

    def launching(req=None):
        # The client appears only now: the main window for the autofill, and
        # the EMS authentication window for the token step.  Growing the auth
        # window *after* the fall-through means the migrated EMS-credentials
        # route (Stage 48) does not intercept it before the launch.
        provider._main_hwnds = (HWND,)
        desktop.windows[HWND] = (FORTI_PID, FORTI_TID, HWND)
        from tests.test_vpn_forticlient_2fa import auth_windows as _auth_windows
        desktop.windows.update(_auth_windows())
        return original(req)

    provider.launch = launching
    result = connect(provider, runtime, request(requires_2fa=True, token=TOKEN))

    assert result.launch is not None and result.launch.success
    assert result.autofill is not None and result.autofill.success
    assert result.two_factor_result is not None and result.two_factor_result.success
    trace = result.to_trace_data()
    assert trace["autofill_status"] == "done"
    assert trace["two_factor_status"] == "submitted"
    assert trace["launch_strategy"]


def test_19_the_phase_order_is_the_legacy_order_with_detect_in_front():
    provider, runtime, _ = build(window=True)
    result = connect(provider, runtime, request(requires_2fa=True, token=TOKEN))
    assert phase_names(result)[:4] == ["detect", "cli_probe", "session_record",
                                       "window_probe"]
    assert phase_names(result)[-4:] == ["window_restore", "await_activation",
                                        "autofill_start", "two_factor"]


def test_20_a_running_client_is_never_launched():
    provider, runtime, _ = build(window=True)
    calls = []
    provider.launch = lambda req=None: calls.append("launch")
    result = connect(provider, runtime)
    assert calls == [] and result.launch is None


def test_21_the_client_is_launched_at_most_once():
    provider, runtime, desktop = build(window=False)
    calls = []
    original = provider.launch

    def counting(req=None):
        calls.append("launch")
        provider._main_hwnds = (HWND,)
        desktop.windows[HWND] = (FORTI_PID, FORTI_TID, HWND)
        return original(req)

    provider.launch = counting
    result = connect(provider, runtime)
    assert calls == ["launch"] and phase_names(result).count("launch") == 1


def test_22_the_form_is_filled_at_most_once():
    inputs = FakeInput()
    provider, _r, desktop = build(window=True)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=FakeLaunch(), input_system=inputs, window_api=desktop,
        message_system=FakeMessages())
    result = connect(provider, runtime)
    assert phase_names(result).count("autofill_start") == 1
    assert [e for e in inputs.events if e[0] == "clip_set"].count(
        ("clip_set", PASSWORD)) == 1


def test_23_the_token_is_submitted_at_most_once():
    messages = FakeMessages()
    provider, _r, desktop = build(window=True, auth_window=True)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=FakeLaunch(), input_system=FakeInput(), window_api=desktop,
        message_system=messages)
    connect(provider, runtime, request(requires_2fa=True, token=TOKEN))
    assert len([e for e in messages.events if e[0] == "set_text"]) == 1
    assert len([e for e in messages.events if e[0] == "click"]) == 1


def test_started_is_not_connected_on_any_successful_route():
    """Success means the attempt was started; only status can say "up"."""
    provider, runtime, _ = build(window=True)
    gui = connect(provider, runtime)

    launch = FakeLaunch(monitored=FakeMonitor())
    cli_provider, _r, desktop = build(window=False, cli=True, launch=launch)
    cli = connect(cli_provider, fake_runtime(cli_provider, clock=FakeClock(), 
        launch_system=launch, input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages()))

    manual_provider, manual_runtime, _ = build(window=True)
    manual = connect(manual_provider, manual_runtime, request(autofill=False))

    for result in (gui, cli, manual):
        assert result.success, result.route
        assert result.state is not VpnState.CONNECTED, result.route
    assert gui.state is cli.state is VpnState.CONNECTING
    assert manual.state is VpnState.UNKNOWN, "nic nie zostało wysłane"
    # Nothing in the flow asks about the tunnel — that stays a status question.
    assert all(step.phase != "status" for step in gui.steps)


# ══════════════════════════════════════════════════════════════════════════
# 24 + 12 (architecture): secrets and seams
# ══════════════════════════════════════════════════════════════════════════

def test_24_no_secret_reaches_a_result_or_a_trace():
    scenarios = [
        dict(),
        dict(req=request(autofill=False)),
        dict(req=request(requires_2fa=True, token=TOKEN)),
    ]
    for kwargs in scenarios:
        trace = RecTrace()
        provider, _r, desktop = build(window=True, auth_window=True)
        runtime = fake_runtime(provider, clock=FakeClock(), 
            launch_system=FakeLaunch(), input_system=FakeInput(),
            window_api=desktop, message_system=FakeMessages(), trace=trace)
        result = connect(provider, runtime, kwargs.get("req"))
        blob = (f"{result!r} {result.to_trace_data()} {result.metadata} "
                f"{[s.__dict__ if hasattr(s, '__dict__') else s for s in result.steps]} "
                f"{trace.steps}")
        for secret in SECRETS:
            assert secret not in blob, (secret, kwargs)


def test_24b_a_command_line_with_a_password_never_reaches_a_result():
    launch = FakeLaunch(monitored=FakeMonitor())
    provider, _r, desktop = build(window=False, cli=True, launch=launch)
    runtime = fake_runtime(provider, clock=FakeClock(), 
        launch_system=launch, input_system=FakeInput(), window_api=desktop,
        message_system=FakeMessages())
    result = connect(provider, runtime)
    assert PASSWORD in str(launch.calls), "legacy naprawdę podaje je procesowi"
    assert PASSWORD not in f"{result!r} {result.to_trace_data()} {result.steps}"


def test_12_connect_has_no_direct_path_to_the_machine():
    """The orchestration names none of the dangerous machinery."""
    for module in (fcc, fcr):
        tree = ast.parse(open(module.__file__, encoding="utf-8").read())
        imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                     for a in n.names}
        assert not any(m and m.split(".")[0] in
                       ("ctypes", "win32gui", "win32con", "win32clipboard",
                        "subprocess", "vpn_connect")
                       for m in imported), (module.__name__, imported)
        # `AutomationMode.WM_SETTEXT` is a *label* for a route, not a call:
        # count only names that are not reached through an enum.
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                 and not (isinstance(n.value, ast.Name)
                          and n.value.id == "AutomationMode")}
        names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        for banned in ("SendInput", "WM_SETTEXT", "BM_CLICK", "SendMessage",
                       "EnumWindows", "Popen", "OpenClipboard"):
            assert banned not in names, (module.__name__, banned)


def test_12b_the_provider_itself_stays_free_of_win32_and_processes():
    import vpn.providers.forticlient as fc
    tree = ast.parse(open(fc.__file__, encoding="utf-8").read())
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                 for a in n.names}
    for forbidden in ("subprocess", "ctypes", "win32gui", "threading"):
        assert forbidden not in imported


# ══════════════════════════════════════════════════════════════════════════
# Production is still the legacy
# ══════════════════════════════════════════════════════════════════════════

def test_the_registered_provider_is_not_armed():
    registered = vpn.default_registry.get("forticlient")
    assert registered.CONNECT_ENABLED is False
    result = registered.connect(request())
    assert result.success is False and result.error_code == "unsupported"


def test_an_unarmed_provider_touches_nothing_when_connect_is_called():
    """A stray call must not start a client or type into a window."""
    class Tripwire(LaunchSystem):
        def __getattribute__(self, name):
            raise AssertionError(f"connect dotknął maszyny: {name}")

    provider = FortiClientProvider(
        environment=FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]),
        system=Tripwire())
    result = provider.connect(request())
    assert result.error_code == "unsupported"


def test_capabilities_do_not_yet_advertise_connecting():
    assert vpn.default_registry.get("forticlient").capabilities() is Capability.LAUNCH


def test_no_production_module_calls_the_new_connect():
    for root, dirs, files in os.walk(_PARENT):
        dirs[:] = [d for d in dirs
                   if d not in ("vpn", "tests", "smoke", "__pycache__",
                                ".pytest_cache")]
        for name in files:
            if not name.endswith(".py"):
                continue
            text = open(os.path.join(root, name), encoding="utf-8",
                        errors="replace").read()
            for banned in ("connect_runtime", "CONNECT_ENABLED",
                           "answer_two_factor_challenge", "FortiConnectRuntime"):
                assert banned not in text, (name, banned)


def test_the_legacy_connect_is_untouched():
    legacy = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    for name in ("def connect(", "def connect_monitored(", "def _autofill_forticlient(",
                 "def fill_forticlient_token(", "def _fill_forti_auth_window("):
        assert name in legacy, name
    for panel in ("ui/detail_panel.py", "ui/vpn_panel.py"):
        text = open(os.path.join(_PARENT, panel), encoding="utf-8").read()
        assert "vpn_connect.connect_monitored(" in text, panel


# ══════════════════════════════════════════════════════════════════════════
# The parity table
# ══════════════════════════════════════════════════════════════════════════

def test_the_parity_table_is_complete_and_names_its_security_differences():
    kinds = {"same", "security", "information", "not-migrated"}
    ids = set()
    for entry in fcc.CONNECT_PARITY:
        assert len(entry) == 6, entry
        scenario_id, given, legacy, new, difference, kind = entry
        assert kind in kinds, (scenario_id, kind)
        assert scenario_id not in ids, f"duplikat: {scenario_id}"
        ids.add(scenario_id)
        for field in (given, legacy, new, difference):
            assert field and len(field) > 3, scenario_id
        if kind == "same":
            assert difference.startswith("brak"), scenario_id

    required = {"client-already-open", "client-not-running", "gui-autofill",
                "gui-autofill-blocked", "gui-manual", "gui-two-factor", "cli",
                "cli-two-factor", "cli-failure", "launch-failure", "detection",
                "no-profile", "no-credentials", "ems-credentials-window"}
    assert required <= ids, required - ids
    security = {i for i, *_rest in
                [(e[0], e[5]) for e in fcc.CONNECT_PARITY] if _rest[0] == "security"}
    assert {"client-already-open", "gui-autofill-blocked", "cli-two-factor",
            "gui-two-factor"} <= security


def test_the_stage_16_caveats_are_recorded():
    ids = {name for name, _kind, _text in fcc.LEGACY_BEHAVIOR}
    assert {"autofill-is-synchronous-here", "ems-credentials-not-migrated",
            "two-factor-inline-when-token-known",
            "cli-challenge-not-read-by-connect"} <= ids
