"""Stage 39: Stormshield V2 — detect, launch and window discovery.

The second provider, and the real question behind it: is the machinery built
for FortiClient an architecture, or was it FortiClient all along?  So these
tests deliberately do **not** re-test the shared layer.  The activation gate,
`SecureWindowTarget`, `require_visible` and `raise_window` were validated
against FortiClient and then live on a real desktop; re-running them with a
different provider's name attached would measure nothing new.

What is tested here is only what is genuinely Stormshield's: where the client
is found, how it is started, which windows may be considered, and that the
three things the legacy does to a window — tray click, TOPMOST, foreground —
did not come along for the ride.

No credentials appear anywhere in this file.  At this stage the flow stops
before anything could be typed, which is itself one of the assertions.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn import (  # noqa: E402
    AutomationMode, Capability, DetectionState, ErrorCode, VpnRequest,
)
from vpn.providers import stormshield as ss  # noqa: E402
from vpn.providers.stormshield import StormshieldProvider  # noqa: E402
from vpn.providers.stormshield_connect import (  # noqa: E402
    PHASE_AWAIT_ACTIVATION, PHASE_DETECT, PHASE_LAUNCH, PHASE_WINDOW_PROBE,
    StormshieldConnectFlow, StormshieldConnectSystem,
)
from vpn.providers.secure_target import VerifiedWindow  # noqa: E402
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import FakeDesktop, ListFinder  # noqa: E402

GUI = ss.GUI_PATHS[0]
INSTALL_DIR = ss.INSTALL_DIRS[0]
ELSEWHERE = r"C:\Users\Sebastian\Downloads\sslvpn_client.exe"

HWND, PID, TID = 0x5001, 4242, 77
OTHER_HWND, OTHER_PID = 0x5002, 9999


def provider(*, files=(GUI,), dirs=(INSTALL_DIR,), system=None):
    return StormshieldProvider(
        environment=FakeEnvironment(files=list(files), dirs=list(dirs)),
        system=system)


class FakeLaunch:
    """Records what would have been started; starts nothing."""

    def __init__(self, *, spawn_raises=False, running=True, probe_raises=False):
        self.spawned: list[tuple] = []
        self.waited: list[tuple] = []
        self._spawn_raises = spawn_raises
        self._running = running
        self._probe_raises = probe_raises

    def spawn_detached(self, exe, cwd):
        self.spawned.append((exe, cwd))
        if self._spawn_raises:
            raise OSError("spawn odmowil")
        return 1234

    def wait_for_process(self, image_name, timeout):
        self.waited.append((image_name, timeout))
        if self._probe_raises:
            raise OSError("tasklist padl")
        return self._running

    def open_with_explorer(self, path):
        raise AssertionError("Stormshield nie uruchamia sie przez explorer")


class Desktop(FakeDesktop):
    """A desktop holding one Stormshield window and one stranger."""

    def __init__(self, *, image=None, **kwargs):
        kwargs.setdefault("windows", {HWND: (PID, TID, HWND),
                                      OTHER_HWND: (OTHER_PID, 78, OTHER_HWND)})
        kwargs.setdefault("images", {
            PID: image if image is not None else os.path.join(INSTALL_DIR,
                                                              ss.GUI_EXE_NAME),
            OTHER_PID: r"C:\Users\Sebastian\Downloads\evil.exe"})
        kwargs.setdefault("foreground", lambda n: HWND)
        super().__init__(**kwargs)


# ══════════════════════════════════════════════════════════════════════════
# Detection
# ══════════════════════════════════════════════════════════════════════════

def test_1_installed_at_a_known_path():
    result = provider().detect()
    assert result.state is DetectionState.INSTALLED
    assert result.path == GUI
    assert result.source == "known_paths"


def test_2_not_installed_says_so_without_failing():
    result = provider(files=(), dirs=()).detect()
    assert result.state is DetectionState.NOT_INSTALLED
    assert result.success, "brak klienta to odpowiedz, nie blad"
    assert result.path is None


def test_3_app_path_wins_over_the_known_paths():
    """A profile pointing somewhere unusual keeps working, as in the legacy."""
    result = provider(files=(GUI, ELSEWHERE)).detect(
        VpnRequest(provider_id="stormshield", app_path=ELSEWHERE))
    assert result.state is DetectionState.INSTALLED
    assert result.path == ELSEWHERE
    assert result.source == "app_path"


def test_3b_an_app_path_that_does_not_exist_falls_back():
    result = provider().detect(
        VpnRequest(provider_id="stormshield", app_path=r"C:\nie\ma\takiego.exe"))
    assert result.path == GUI and result.source == "known_paths"


def test_4_a_broken_environment_is_an_error_not_a_crash():
    class Broken:
        def is_file(self, path):
            raise OSError("dysk odmowil")

        def is_dir(self, path):
            return False

    result = StormshieldProvider(environment=Broken()).detect()
    assert result.state is DetectionState.ERROR
    assert result.error_code == ErrorCode.DETECTION_FAILED.value
    assert "dysk odmowil" not in repr(result), "komunikat wyjatku nie wychodzi"


# ══════════════════════════════════════════════════════════════════════════
# Trusted directories
# ══════════════════════════════════════════════════════════════════════════

def test_5_the_install_directories_are_trusted():
    dirs = provider().trusted_window_dirs()
    assert INSTALL_DIR in dirs
    assert all("Program Files" in d for d in dirs)


def test_6_an_app_path_outside_program_files_earns_no_trust():
    """It may launch the client; it may not make its window trusted.

    The whole basis of the trust is that writing to Program Files needs
    administrator rights.  A copy in Downloads has no such property, so the
    window it owns is refused a secret later — the same rule FortiClient
    applies to a registry INSTALLDIR outside those roots.
    """
    prov = provider(files=(GUI, ELSEWHERE)).with_app_path(ELSEWHERE)
    dirs = prov.trusted_window_dirs()
    assert os.path.dirname(ELSEWHERE) not in dirs
    assert INSTALL_DIR in dirs


def test_6b_an_app_path_inside_program_files_is_added():
    other = r"C:\Program Files\Stormshield\Inny\sslvpn_client.exe"
    prov = provider(files=(GUI, other),
                    dirs=(INSTALL_DIR, os.path.dirname(other))).with_app_path(other)
    assert os.path.dirname(other) in prov.trusted_window_dirs()


# ══════════════════════════════════════════════════════════════════════════
# Window discovery — the title proposes, the image decides
# ══════════════════════════════════════════════════════════════════════════

def target(desktop, *, hwnds=(HWND,), files=(GUI,)):
    return provider(files=files).secure_window_target(
        api=desktop, finder=ListFinder(hwnds))


def test_7_a_genuine_client_window_is_accepted():
    found = target(Desktop()).first_verified_candidate()
    assert found is not None
    hwnd, owner = found
    assert hwnd == HWND and owner.pid == PID
    assert owner.image_name == ss.GUI_EXE_NAME.lower()


def test_8_a_window_titled_stormshield_but_owned_by_something_else_is_refused():
    """The legacy's entire check is the title.  Here the title buys nothing.

    This is the case that matters: any program can put "Stormshield" in its
    title bar, and the legacy autofill would type a password into it.
    """
    desktop = Desktop(image=r"C:\Users\Sebastian\Downloads\sslvpn_client.exe")
    assert target(desktop).first_verified_candidate() is None


def test_9_a_different_pid_is_refused():
    desktop = Desktop()
    assert target(desktop, hwnds=(OTHER_HWND,)).first_verified_candidate() is None


def test_10_no_window_at_all_is_not_an_error():
    assert target(Desktop(), hwnds=()).first_verified_candidate() is None


def test_11_the_finder_carries_no_forticlient_assumptions():
    """No inherited exclusions, no class-name guesses — one honest substring."""
    finder = provider().window_finder()
    assert finder._must_contain == ("Stormshield",)
    assert finder._must_not_contain is None, \
        "wykluczenie 'Authentication' nalezy do FortiClienta"


# ══════════════════════════════════════════════════════════════════════════
# Launch
# ══════════════════════════════════════════════════════════════════════════

def test_12_launch_goes_through_the_launch_system_detached():
    launch = FakeLaunch()
    result = provider(system=launch).launch()
    assert result.success and result.started
    assert result.strategy == ss.STRATEGY_POPEN_CLEAN_ENV
    assert launch.spawned == [(GUI, INSTALL_DIR)]
    assert launch.waited == [(ss.GUI_EXE_NAME, ss.POPEN_WAIT_S)]


def test_13_no_client_means_no_spawn():
    launch = FakeLaunch()
    result = provider(files=(), dirs=(), system=launch).launch()
    assert not result.success
    assert result.error_code == ErrorCode.CLIENT_NOT_FOUND.value
    assert launch.spawned == []


def test_14_a_spawn_that_raises_is_reported_not_raised():
    result = provider(system=FakeLaunch(spawn_raises=True)).launch()
    assert not result.success
    assert result.error_code == ErrorCode.LAUNCH_FAILED.value
    assert "spawn odmowil" not in repr(result)


def test_15_spawned_but_never_seen_is_success_with_started_false():
    """Legacy shape: the spawn worked, the process was not observed."""
    result = provider(system=FakeLaunch(running=False)).launch()
    assert result.success and result.started is False
    assert result.error_code is None
    assert result.attempts[-1].error_code == ErrorCode.LAUNCH_NO_PROCESS.value


def test_16_a_broken_process_probe_does_not_deny_the_spawn():
    result = provider(system=FakeLaunch(probe_raises=True)).launch()
    assert result.success and result.started
    assert result.observation_failed


def test_17_launch_never_reaches_for_the_window():
    """It starts the client.  Whether it comes forward is the user's business."""
    launch = FakeLaunch()
    provider(system=launch).launch()
    assert not hasattr(launch, "activated")
    assert launch.spawned, "jedyne dzialanie to spawn"


# ══════════════════════════════════════════════════════════════════════════
# Contract configuration
# ══════════════════════════════════════════════════════════════════════════

def test_18_the_main_target_is_the_stage_29_34_contract():
    tgt = provider().secure_window_target()
    assert tgt._require_visible is True
    assert tgt._raise_window is False


def test_19_connect_is_not_armed():
    assert StormshieldProvider.CONNECT_ENABLED is False


def test_20_capabilities_match_the_real_client():
    prov = provider()
    assert prov.capabilities() == Capability.LAUNCH
    assert prov.automation_mode() is AutomationMode.MANUAL
    for absent in (Capability.CLI_CONNECT, Capability.TWO_FACTOR,
                   Capability.AUTOFILL):
        assert not prov.supports(absent), absent


def test_21_the_provider_is_not_registered_yet():
    """Parity first, registration after — the same rule FortiClient followed."""
    import vpn
    from vpn.providers import BUILTIN_PROVIDERS

    assert StormshieldProvider not in BUILTIN_PROVIDERS
    assert not any(isinstance(p, StormshieldProvider) for p in vpn.default_registry)


# ══════════════════════════════════════════════════════════════════════════
# Nothing that touches a window came along
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("module", [ss, sys.modules[
    "vpn.providers.stormshield_connect"]])
def test_22_no_tray_topmost_or_foreground_api(module):
    tree = ast.parse(open(module.__file__, encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("SetWindowPos", "HWND_TOPMOST", "PostMessage", "SendMessage",
                   "ShowWindow", "SW_RESTORE", "SetForegroundWindow",
                   "AttachThreadInput", "SendInput", "_activate_qt_tray_icon",
                   "_bring_window_to_front", "ShellExecuteW"):
        assert banned not in names, (module.__name__, banned)


def test_23_the_new_modules_do_not_import_the_legacy():
    for module in (ss, sys.modules["vpn.providers.stormshield_connect"]):
        tree = ast.parse(open(module.__file__, encoding="utf-8").read())
        modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                    for a in n.names}
        assert not any(m and m.split(".")[0] in ("vpn_connect", "ctypes",
                                                 "win32gui", "win32con")
                       for m in modules), module.__name__


# ══════════════════════════════════════════════════════════════════════════
# Flow — phase order, and where it deliberately stops
# ══════════════════════════════════════════════════════════════════════════

class Recording(StormshieldConnectSystem):
    def __init__(self, *, detection=None, launch=None, handle=HWND,
                 activation=None, still=None):
        self.calls: list[str] = []
        self._detection, self._launch = detection, launch
        self._handle, self._activation, self._still = handle, activation, still

    def detect(self, request):
        self.calls.append("detect")
        return self._detection

    def launch(self, request):
        self.calls.append("launch")
        return self._launch

    def find_main_window(self, timeout):
        self.calls.append("find_main_window")
        return self._handle

    def await_activation(self):
        self.calls.append("await_activation")
        return self._activation

    def activation_still_holds(self, hwnd):
        self.calls.append("activation_still_holds")
        return self._still

    def autofill(self, request):
        """2026-10-19: the flows fill the verified window after activation."""
        from vpn.types import AutofillResult, AutofillStatus
        self.calls.append("autofill")
        return AutofillResult(
            provider_id=request.provider_id, success=True,
            status=AutofillStatus.DONE, login_entered=bool(request.login),
            password_entered=bool(request.password),
            metadata={"submitted": False, "filled_only": True})


class Answer:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def flow(system):
    return StormshieldConnectFlow(provider(), system)


def installed():
    return Answer(state=DetectionState.INSTALLED)


def launched():
    return Answer(success=True, error_code=None)


def observed(ok=True, state="activation-observed"):
    return Answer(ok=ok, state=Answer(value=state), hwnd=HWND)


def test_24_the_phases_run_in_order_and_stop_before_any_typing():
    system = Recording(detection=installed(), launch=launched(),
                       activation=observed(), still=Answer(ok=True))
    result = flow(system).run(VpnRequest(provider_id="stormshield"))

    assert system.calls == ["detect", "launch", "find_main_window",
                            "await_activation", "activation_still_holds"]
    assert [s.phase for s in result.steps] == [
        PHASE_DETECT, PHASE_LAUNCH, PHASE_WINDOW_PROBE, PHASE_AWAIT_ACTIVATION]
    assert result.requires_user_action
    assert result.automation is AutomationMode.MANUAL


def test_25_a_missing_client_stops_at_detect():
    system = Recording(detection=Answer(state=DetectionState.NOT_INSTALLED))
    result = flow(system).run(VpnRequest(provider_id="stormshield"))
    assert system.calls == ["detect"]
    assert not result.success
    assert result.error_code == ErrorCode.CLIENT_NOT_FOUND.value


def test_26_a_failed_launch_stops_before_the_window():
    system = Recording(detection=installed(),
                       launch=Answer(success=False, error_code="launch-failed"))
    result = flow(system).run(VpnRequest(provider_id="stormshield"))
    assert system.calls == ["detect", "launch"]
    assert not result.success


def test_27_no_activation_is_a_user_action_not_a_failure():
    """The client is open; the person simply never brought it forward."""
    system = Recording(detection=installed(), launch=launched(),
                       activation=observed(ok=False, state="activation-timeout"))
    result = flow(system).run(VpnRequest(provider_id="stormshield"))

    assert "activation_still_holds" not in system.calls
    assert result.success and result.requires_user_action
    assert result.error_code == ErrorCode.FOCUS_FAILED.value


def test_28_an_activation_that_no_longer_holds_stops_the_flow():
    system = Recording(detection=installed(), launch=launched(),
                       activation=observed(),
                       still=Answer(ok=False, reason="target-minimised"))
    result = flow(system).run(VpnRequest(provider_id="stormshield"))

    assert system.calls[-1] == "activation_still_holds"
    assert result.error_code == ErrorCode.FOCUS_FAILED.value
    last = result.steps[-1]
    assert last.phase == PHASE_AWAIT_ACTIVATION
    assert last.reason_code == "target-minimised"


def test_29_a_bare_system_does_nothing_to_the_machine():
    """The default seams answer "nothing happened" — a stray call is inert."""
    system = StormshieldConnectSystem()
    request = VpnRequest(provider_id="stormshield")
    assert system.detect(request) is None
    assert system.launch(request) is None
    assert system.find_main_window(0.5) is None
    assert system.await_activation() is None
    assert system.activation_still_holds(HWND) is None


def test_30_no_verified_window_is_produced_by_this_stage():
    """The flow never acquires: the next keystroke belongs to the next stage."""
    system = Recording(detection=installed(), launch=launched(),
                       activation=observed(), still=Answer(ok=True))
    result = flow(system).run(VpnRequest(provider_id="stormshield"))
    assert not isinstance(result, VerifiedWindow)

    source = open(sys.modules["vpn.providers.stormshield_connect"].__file__,
                  encoding="utf-8").read()
    for banned in ("acquire_any", "acquire(", "start_autofill", "run_guarded"):
        assert banned not in source, banned


def test_31_the_result_carries_no_credential():
    request = VpnRequest(provider_id="stormshield", login="jkowalski",
                         password="SuperSecret123", app_path=GUI)
    system = Recording(detection=installed(), launch=launched(),
                       activation=observed(), still=Answer(ok=True))
    result = flow(system).run(request)

    blob = repr(result) + repr(result.steps)
    for secret in ("jkowalski", "SuperSecret123"):
        assert secret not in blob, secret


def test_32_legacy_is_untouched_by_this_provider():
    legacy = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    for token in ("StormshieldProvider", "stormshield_connect",
                  "StormshieldConnectFlow"):
        assert token not in legacy, token
