"""Stage 48: Barracuda V2 — detect, launch, window discovery, and a hard stop.

The third provider, and the first whose live UI is unmeasured on any machine we
have.  So these tests cover exactly the foundation this stage builds — where the
client is found, how it is started, which windows may be *considered*, and that
the flow stops before a single keystroke with an unambiguous reason — and they
assert the negatives that matter: the legacy's broad title matcher, its
``candidates[0]``, its blind Enter and its foreground steal did **not** come
along.

The shared layer (activation gate, ``SecureWindowTarget``, ``require_visible`` /
``raise_window``) was validated against FortiClient and Stormshield and is not
re-tested here.  No credentials appear anywhere: at this stage nothing can type,
which is itself one of the assertions.
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
    AutomationMode, Capability, DetectionState, ErrorCode, VpnRegistry,
    VpnRequest, check_contract,
)
from vpn.providers import barracuda as ba  # noqa: E402
from vpn.providers.barracuda import BarracudaProvider  # noqa: E402
from vpn.providers.barracuda_connect import (  # noqa: E402
    PHASE_AWAIT_ACTIVATION, PHASE_DETECT, PHASE_LAUNCH, PHASE_WINDOW_PROBE,
    STOP_REASON, BarracudaConnectFlow, BarracudaConnectRuntime,
    BarracudaConnectSystem,
)
from vpn.providers.activation_gate import CancellationToken  # noqa: E402
from vpn.providers.secure_target import VerifiedWindow  # noqa: E402
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import FakeDesktop, ListFinder  # noqa: E402

GUI = ba.GUI_PATHS[0]                       # ...\Network Access Client\vpnclient.exe
INSTALL_DIR = ba.INSTALL_DIRS[0]
ELSEWHERE = r"C:\Users\Sebastian\Downloads\vpnclient.exe"

HWND, PID, TID = 0x6001, 4343, 88
OTHER_HWND, OTHER_PID = 0x6002, 9998


def provider(*, files=(GUI,), dirs=(INSTALL_DIR,), system=None):
    return BarracudaProvider(
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
            raise OSError("spawn odmówił")
        return 1234

    def wait_for_process(self, image_name, timeout):
        self.waited.append((image_name, timeout))
        if self._probe_raises:
            raise OSError("tasklist padł")
        return self._running

    def open_with_explorer(self, path):
        raise AssertionError("Barracuda nie uruchamia się przez explorer")


class Desktop(FakeDesktop):
    """A desktop holding one Barracuda window and one stranger."""

    def __init__(self, *, image=None, **kwargs):
        kwargs.setdefault("windows", {HWND: (PID, TID, HWND),
                                      OTHER_HWND: (OTHER_PID, 78, OTHER_HWND)})
        kwargs.setdefault("images", {
            PID: image if image is not None else os.path.join(INSTALL_DIR,
                                                              "vpnclient.exe"),
            OTHER_PID: r"C:\Users\Sebastian\Downloads\evil.exe"})
        kwargs.setdefault("foreground", lambda n: HWND)
        super().__init__(**kwargs)


# ══════════════════════════════════════════════════════════════════════════
# Registration & capabilities
# ══════════════════════════════════════════════════════════════════════════

def test_1_registers_in_a_fresh_registry_and_satisfies_the_contract():
    registry = VpnRegistry([BarracudaProvider()])
    assert registry.get("barracuda") is not None
    assert check_contract(BarracudaProvider()) == []


def test_2_is_not_in_the_default_registry_yet():
    """Like Stormshield: implemented, not registered — production is unchanged."""
    assert "barracuda" not in vpn.default_registry.ids()
    assert vpn.default_registry.ids() == ["forticlient"]


def test_3_capabilities_are_launch_only_and_connect_is_disarmed():
    prov = BarracudaProvider()
    assert prov.capabilities() is Capability.LAUNCH
    assert prov.automation_mode() is AutomationMode.MANUAL
    assert BarracudaProvider.CONNECT_ENABLED is False


def test_3b_the_spec_still_records_the_full_client():
    """capabilities() is this stage; the catalog keeps the whole picture."""
    assert BarracudaProvider.spec.legacy_name == "Barracuda"
    assert Capability.AUTOFILL in BarracudaProvider.spec.capabilities


# ══════════════════════════════════════════════════════════════════════════
# Detection
# ══════════════════════════════════════════════════════════════════════════

def test_4_installed_at_a_known_path():
    result = provider().detect()
    assert result.state is DetectionState.INSTALLED
    assert result.path == GUI and result.source == "known_paths"


def test_5_not_installed_says_so_without_failing():
    result = provider(files=(), dirs=()).detect()
    assert result.state is DetectionState.NOT_INSTALLED and result.success


def test_6_app_path_wins_over_the_known_paths():
    result = provider(files=(ELSEWHERE,)).detect(
        VpnRequest(provider_id="barracuda", app_path=ELSEWHERE))
    assert result.state is DetectionState.INSTALLED
    assert result.path == ELSEWHERE and result.source == "app_path"


def test_6b_an_app_path_that_does_not_exist_falls_back_to_known():
    result = provider(files=(GUI,)).detect(
        VpnRequest(provider_id="barracuda", app_path=ELSEWHERE))
    assert result.path == GUI and result.source == "known_paths"


def test_7_a_broken_environment_is_an_error_not_a_crash():
    class Boom(FakeEnvironment):
        def is_file(self, path):
            raise OSError("filesystem padł")

    result = BarracudaProvider(environment=Boom(files=[], dirs=[])).detect()
    assert result.state is DetectionState.ERROR
    assert result.error_code == ErrorCode.DETECTION_FAILED.value


# ══════════════════════════════════════════════════════════════════════════
# Trusted paths — a name is not trust
# ══════════════════════════════════════════════════════════════════════════

def test_8_the_install_directories_are_trusted():
    dirs = provider().trusted_window_dirs()
    assert INSTALL_DIR in dirs
    assert all("Barracuda" in d for d in dirs)


def test_9_an_app_path_outside_program_files_earns_no_trust():
    """A look-alike vpnclient.exe in Downloads is refused as a trust anchor."""
    prov = provider(files=(ELSEWHERE,)).with_app_path(ELSEWHERE)
    dirs = prov.trusted_window_dirs()
    assert os.path.dirname(ELSEWHERE) not in dirs
    assert all("Barracuda" in d for d in dirs)


def test_9b_an_app_path_inside_program_files_is_added():
    pf_path = os.path.join(r"C:\Program Files\Barracuda\Custom", "vpnclient.exe")
    prov = provider(files=(pf_path,), dirs=(INSTALL_DIR,)).with_app_path(pf_path)
    assert os.path.dirname(pf_path) in prov.trusted_window_dirs()


# ══════════════════════════════════════════════════════════════════════════
# Window ownership — HWND → PID → trusted image
# ══════════════════════════════════════════════════════════════════════════

def test_10_a_genuine_client_window_is_accepted():
    target = provider().secure_window_target(api=Desktop(),
                                             finder=ListFinder((HWND,)))
    found = target.first_verified_candidate()
    assert found is not None and found[0] == HWND


def test_11_a_window_titled_barracuda_but_owned_by_something_else_is_refused():
    """The core legacy gap: title says Barracuda, owner is a stranger."""
    desktop = Desktop(images={PID: r"C:\Users\x\Downloads\evil.exe",
                              OTHER_PID: r"C:\Users\x\Downloads\evil.exe"})
    target = provider().secure_window_target(api=desktop,
                                             finder=ListFinder((HWND,)))
    assert target.first_verified_candidate() is None


def test_12_a_foreign_pid_window_is_never_a_candidate():
    """A window of another process, even if the finder proposes it, is refused."""
    target = provider().secure_window_target(api=Desktop(),
                                             finder=ListFinder((OTHER_HWND,)))
    assert target.first_verified_candidate() is None


def test_13_no_window_at_all_is_not_an_error():
    target = provider().secure_window_target(api=Desktop(),
                                             finder=ListFinder(()))
    assert target.first_verified_candidate() is None


def test_14_the_finder_carries_no_cross_product_title_list():
    """The legacy matched vpn/credential/sonicwall/pulse/globalprotect too.

    The banned words may appear in prose explaining the gap; what must never
    exist is a *collection literal* of them used as a matcher (the legacy shape).
    """
    assert ba.WINDOW_TITLE_HINT == "Barracuda"
    tree = ast.parse(open(ba.__file__, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            strings = [e.value.lower() for e in node.elts
                       if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            for banned in ("sonicwall", "pulse", "globalprotect", "credential"):
                assert not any(banned in s for s in strings), (banned, strings)


# ══════════════════════════════════════════════════════════════════════════
# require_visible / raise_window contract
# ══════════════════════════════════════════════════════════════════════════

def test_15_the_main_target_is_the_stage_29_34_contract():
    target = provider().secure_window_target(api=Desktop())
    assert target._require_visible is True and target._raise_window is False


def test_16_a_minimised_window_is_refused_before_any_focus():
    desktop = Desktop(iconic=True)
    target = provider().secure_window_target(api=desktop,
                                             finder=ListFinder((HWND,)))
    result = target.acquire(HWND)
    assert not isinstance(result, VerifiedWindow)          # TargetRejected


def test_17_a_foreground_race_is_reported_by_the_strict_reading():
    desktop = Desktop(foreground=lambda n: OTHER_HWND)      # somebody else in front
    target = provider().secure_window_target(api=desktop,
                                             finder=ListFinder((HWND,)))
    check = target.strict_foreground_check(HWND)
    assert not check.ok


# ══════════════════════════════════════════════════════════════════════════
# Launch
# ══════════════════════════════════════════════════════════════════════════

def test_18_launch_goes_through_the_launch_system_detached():
    launch = FakeLaunch()
    result = provider(system=launch).launch(VpnRequest(provider_id="barracuda"))
    assert result.success and result.pid == 1234
    assert launch.spawned == [(GUI, INSTALL_DIR)]
    assert launch.waited and launch.waited[0][0] == "nacvpn.exe"


def test_19_no_client_means_no_spawn():
    launch = FakeLaunch()
    result = provider(files=(), dirs=(), system=launch).launch(
        VpnRequest(provider_id="barracuda"))
    assert not result.success
    assert result.error_code == ErrorCode.CLIENT_NOT_FOUND.value
    assert launch.spawned == []


def test_20_a_spawn_that_raises_is_reported_not_raised():
    result = provider(system=FakeLaunch(spawn_raises=True)).launch(
        VpnRequest(provider_id="barracuda"))
    assert not result.success and result.error_code == ErrorCode.LAUNCH_FAILED.value


def test_21_spawned_but_never_seen_is_success_with_started_false():
    result = provider(system=FakeLaunch(running=False)).launch(
        VpnRequest(provider_id="barracuda"))
    assert result.success and result.started is False


def test_22_a_broken_process_probe_does_not_deny_the_spawn():
    result = provider(system=FakeLaunch(probe_raises=True)).launch(
        VpnRequest(provider_id="barracuda"))
    assert result.success and result.observation_failed is True


def test_23_launch_reaches_for_no_window():
    launch = FakeLaunch()
    provider(system=launch).launch(VpnRequest(provider_id="barracuda"))
    # FakeLaunch has no window API; if launch touched one this would raise.
    assert launch.spawned


def test_24_the_app_path_directory_is_the_wait_cwd():
    launch = FakeLaunch()
    provider(files=(ELSEWHERE,), system=launch).launch(
        VpnRequest(provider_id="barracuda", app_path=ELSEWHERE))
    assert launch.spawned == [(ELSEWHERE, os.path.dirname(ELSEWHERE))]
    assert launch.waited[0][0] == "vpnclient.exe"


# ══════════════════════════════════════════════════════════════════════════
# Connect flow — stops before typing, with a reason
# ══════════════════════════════════════════════════════════════════════════

class Recording(BarracudaConnectSystem):
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


class Answer:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def flow(system):
    return BarracudaConnectFlow(provider(), system)


def installed():
    return Answer(state=DetectionState.INSTALLED)


def launched():
    return Answer(success=True, error_code=None)


def observed(ok=True, state="activation-observed"):
    return Answer(ok=ok, state=Answer(value=state), hwnd=HWND)


def test_25_the_phases_run_in_order_and_stop_before_any_typing():
    system = Recording(detection=installed(), launch=launched(),
                       activation=observed(), still=Answer(ok=True))
    result = flow(system).run(VpnRequest(provider_id="barracuda"))

    assert system.calls == ["detect", "launch", "find_main_window",
                            "await_activation", "activation_still_holds"]
    assert [s.phase for s in result.steps] == [
        PHASE_DETECT, PHASE_LAUNCH, PHASE_WINDOW_PROBE, PHASE_AWAIT_ACTIVATION]
    assert result.requires_user_action
    assert result.automation is AutomationMode.MANUAL


def test_26_the_stop_before_autofill_is_unambiguous():
    system = Recording(detection=installed(), launch=launched(),
                       activation=observed(), still=Answer(ok=True))
    result = flow(system).run(VpnRequest(provider_id="barracuda"))
    assert result.metadata.get("stopped_before_autofill") == STOP_REASON
    assert result.metadata.get("ui_contract_verified") is False
    assert STOP_REASON == "ui-contract-unverified"


def test_27_a_missing_client_stops_at_detect():
    system = Recording(detection=Answer(state=DetectionState.NOT_INSTALLED))
    result = flow(system).run(VpnRequest(provider_id="barracuda"))
    assert system.calls == ["detect"] and not result.success
    assert result.error_code == ErrorCode.CLIENT_NOT_FOUND.value


def test_28_a_failed_launch_stops_before_the_window():
    system = Recording(detection=installed(),
                       launch=Answer(success=False, error_code="launch-failed"))
    result = flow(system).run(VpnRequest(provider_id="barracuda"))
    assert system.calls == ["detect", "launch"] and not result.success


def test_29_no_activation_is_a_user_action_not_a_failure():
    system = Recording(detection=installed(), launch=launched(),
                       activation=observed(ok=False, state="activation-timeout"))
    result = flow(system).run(VpnRequest(provider_id="barracuda"))
    assert "activation_still_holds" not in system.calls
    assert result.success and result.requires_user_action
    assert result.error_code == ErrorCode.FOCUS_FAILED.value


def test_30_a_foreground_race_after_activation_stops_the_flow():
    system = Recording(detection=installed(), launch=launched(),
                       activation=observed(),
                       still=Answer(ok=False, reason="foreground-is-other-window"))
    result = flow(system).run(VpnRequest(provider_id="barracuda"))
    assert system.calls[-1] == "activation_still_holds"
    assert result.error_code == ErrorCode.FOCUS_FAILED.value
    assert result.steps[-1].reason_code == "foreground-is-other-window"
    # And it never advertised a completed connect.
    assert result.metadata.get("stopped_before_autofill") is None


def test_31_a_bare_system_does_nothing_to_the_machine():
    system = BarracudaConnectSystem()
    request = VpnRequest(provider_id="barracuda")
    for call in (lambda: system.detect(request), lambda: system.launch(request),
                 lambda: system.find_main_window(0.5),
                 lambda: system.await_activation(),
                 lambda: system.activation_still_holds(HWND)):
        assert call() is None
    assert not hasattr(system, "start_autofill")
    assert not hasattr(system, "autofill_login_password")


# ══════════════════════════════════════════════════════════════════════════
# Cancellation through the real runtime — nothing to type, so nothing typed
# ══════════════════════════════════════════════════════════════════════════

def test_32_a_cancelled_connect_stops_at_activation_and_touches_nothing():
    desktop = Desktop()
    token = CancellationToken()
    token.cancel()
    prov = provider(system=FakeLaunch())          # so the real launch succeeds
    runtime = BarracudaConnectRuntime(
        prov, window_api=desktop, finder=ListFinder((HWND,)), cancellation=token)
    result = BarracudaConnectFlow(prov, runtime).run(
        VpnRequest(provider_id="barracuda"))
    # detect + launch run for real; the cancelled gate then ends the wait with
    # nothing left to do — there is no autofill after it.
    assert result.requires_user_action
    assert result.error_code == ErrorCode.FOCUS_FAILED.value
    assert desktop.events == [], "pulpit tylko czytany — nic nie aktywowano"
    assert result.metadata.get("stopped_before_autofill") is None


def test_33_the_runtime_has_no_way_to_type():
    runtime = BarracudaConnectRuntime(provider(), window_api=Desktop())
    for banned in ("start_autofill", "autofill_login_password",
                   "copy_to_clipboard", "press_key"):
        assert not hasattr(runtime, banned), banned


# ══════════════════════════════════════════════════════════════════════════
# Security negatives — no credential, no clipboard, no Enter, no tray/topmost
# ══════════════════════════════════════════════════════════════════════════

def test_34_the_connect_flow_still_stops_before_any_typing():
    """The connect FLOW never acquires or types — it stops at activation.

    The provider now has an ``autofill_login_password`` (Stage 50C, via the
    guarded UI Automation seam), but the connect *flow* (``barracuda_connect``)
    is unchanged: it stops before the autofill and produces no verified window.
    """
    system = Recording(detection=installed(), launch=launched(),
                       activation=observed(), still=Answer(ok=True))
    result = flow(system).run(VpnRequest(provider_id="barracuda"))
    assert not isinstance(result, VerifiedWindow)
    tree = ast.parse(open(sys.modules["vpn.providers.barracuda_connect"].__file__,
                          encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("acquire_any", "acquire", "start_autofill", "run_guarded",
                   "autofill_login_password"):
        assert banned not in names, banned


def test_35_the_result_carries_no_credential():
    request = VpnRequest(provider_id="barracuda", login="jkowalski",
                         password="SuperSecret123", app_path=GUI)
    system = Recording(detection=installed(), launch=launched(),
                       activation=observed(), still=Answer(ok=True))
    result = flow(system).run(request)
    blob = repr(result) + repr(result.steps)
    for secret in ("jkowalski", "SuperSecret123"):
        assert secret not in blob, secret


@pytest.mark.parametrize("module_name", ["vpn.providers.barracuda",
                                         "vpn.providers.barracuda_connect"])
def test_36_no_clipboard_no_enter_no_win32_input(module_name):
    tree = ast.parse(open(sys.modules[module_name].__file__,
                          encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("copy_to_clipboard", "read_clipboard", "OpenClipboard",
                   "press_key", "press_combo", "type_text", "VK_RETURN",
                   "SendInput", "keybd_event", "BM_CLICK", "WM_SETTEXT",
                   "click_button", "set_control_text"):
        assert banned not in names, (module_name, banned)


@pytest.mark.parametrize("module_name", ["vpn.providers.barracuda",
                                         "vpn.providers.barracuda_connect"])
def test_37_no_tray_topmost_or_foreground_activation(module_name):
    tree = ast.parse(open(sys.modules[module_name].__file__,
                          encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("SetForegroundWindow", "SetWindowPos", "HWND_TOPMOST",
                   "ShowWindow", "SW_RESTORE", "AttachThreadInput",
                   "_bring_window_to_front", "_activate_qt_tray_icon",
                   "ShellExecuteW", "restore_window"):
        assert banned not in names, (module_name, banned)


def test_38_the_new_modules_do_not_import_the_legacy():
    for module_name in ("vpn.providers.barracuda",
                        "vpn.providers.barracuda_connect"):
        tree = ast.parse(open(sys.modules[module_name].__file__,
                              encoding="utf-8").read())
        modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
                   and n.level == 0}
        modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                    for a in n.names}
        assert not any(m and m.split(".")[0] in ("vpn_connect", "ctypes",
                                                 "win32gui", "win32con")
                       for m in modules), module_name


def test_39_legacy_barracuda_flow_is_untouched():
    legacy = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    assert "def _autofill_native_vpn_window(" in legacy
    assert 'elif provider == "Barracuda":' in legacy
    # Nothing outside vpn/ and tests names the new provider.
    for root, dirs, files in os.walk(_PARENT):
        dirs[:] = [d for d in dirs if d not in ("vpn", "tests", "smoke",
                                                "__pycache__", ".pytest_cache")]
        for name in files:
            if name.endswith(".py"):
                text = open(os.path.join(root, name), encoding="utf-8",
                            errors="replace").read()
                assert "BarracudaProvider" not in text, (name, "BarracudaProvider")
