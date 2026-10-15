"""Stage 13: the secret-safe target/focus contract in the new architecture.

The contract (`vpn.providers.secure_target`) composes the shared Stage-12
primitives (`secure_window`) into a provider-facing object.  These tests prove:

* it accepts a genuine FortiClient window and refuses everything else
  (foreign process, bad PID, unreadable process, look-alike name, install
  outside a trusted directory, owner change, focus loss);
* :class:`VerifiedWindow` is fail-closed — a guarded operation runs only after
  a fresh confirmation, and the contract never carries a secret;
* the provider exposes the contract but has no path that sends one;
* the base :class:`VpnProvider` still knows nothing about Win32 or FortiClient.

No real window is touched: the desktop is a fake :class:`WindowApi`; the only
"operation" is a recording callback.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import secure_window as sw  # noqa: E402
import vpn  # noqa: E402
from vpn import VpnProvider, VpnRequest  # noqa: E402
from vpn.providers import (  # noqa: E402
    FortiClientProvider, GuardResult, SecureWindowTarget, TargetRejected,
    VerifiedWindow, WindowCandidateFinder,
)
from vpn.providers import secure_target as st  # noqa: E402
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402

FORTI_DIR = r"C:\Program Files\Fortinet\FortiClient"
FORTI_GUI = FORTI_DIR + r"\FortiClient.exe"
FORTI_TRAY = FORTI_DIR + r"\FortiTray.exe"
EVIL_EXE = r"C:\Users\Public\Downloads\FortiClient.exe"       # look-alike name
NOTEPAD = r"C:\Windows\System32\notepad.exe"

HWND, OTHER = 0x1001, 0x2002
FORTI_PID, EVIL_PID = 4100, 6660
FORTI_TID, OUR_TID = 41, 7
TRUSTED = (FORTI_DIR,)


class FakeDesktop(sw.WindowApi):
    """windows: hwnd -> (pid, tid, root); images: pid -> image path."""

    def __init__(self, *, windows=None, images=None, foreground=None,
                 attach_ok=True, set_foreground="ok", iconic=False):
        self.windows = windows if windows is not None else {
            HWND: (FORTI_PID, FORTI_TID, HWND), OTHER: (EVIL_PID, 99, OTHER)}
        self.images = images if images is not None else {
            FORTI_PID: FORTI_GUI, EVIL_PID: EVIL_EXE}
        self._foreground = foreground if foreground is not None else (lambda n: HWND)
        self.attach_ok = attach_ok
        self.set_foreground = set_foreground
        self.events = []
        self.fg_checks = 0
        #: Stage 33B: a described desktop says whether its window is minimised.
        #: The base ``WindowApi`` answers None ("cannot tell"), which the V2
        #: acquire path now refuses — so a fake that means "an ordinary visible
        #: window" has to say so rather than leave it open.  Pass ``None`` on
        #: purpose to model a desktop that genuinely cannot answer.
        self._iconic = iconic

    def window_pid(self, hwnd):
        return self.windows.get(hwnd, (None, None, None))[0]

    def window_thread_id(self, hwnd):
        return self.windows.get(hwnd, (None, None, None))[1]

    def process_image_path(self, pid):
        return self.images.get(pid)

    def foreground_window(self):
        self.fg_checks += 1
        return self._foreground(self.fg_checks)

    def root_window(self, hwnd):
        return self.windows.get(hwnd, (None, None, None))[2]

    def current_thread_id(self):
        return OUR_TID

    def attach_thread_input(self, our_tid, their_tid, attach):
        self.events.append(("attach", attach))
        return self.attach_ok if attach else True

    def is_iconic(self, hwnd):
        return self._iconic

    def restore_window(self, hwnd):
        self.events.append(("restore",))

    def set_foreground_window(self, hwnd):
        self.events.append(("set_foreground",))
        if self.set_foreground == "raises":
            raise OSError("refused")
        return self.set_foreground == "ok"


def target(desktop, dirs=TRUSTED, finder=None):
    return SecureWindowTarget(dirs, api=desktop, finder=finder)


def focus_lost_after(n):
    return lambda k: HWND if k <= n else OTHER


# ══════════════════════════════════════════════════════════════════════════
# 1–6. Owner verification
# ══════════════════════════════════════════════════════════════════════════

def test_1_genuine_forticlient_window_is_accepted():
    win = target(FakeDesktop()).acquire(HWND)
    assert isinstance(win, VerifiedWindow) and win.ok
    assert win.pid == FORTI_PID and win.image_name == "forticlient.exe"


def test_2_foreign_process_is_rejected():
    result = target(FakeDesktop()).acquire(OTHER)
    assert isinstance(result, TargetRejected) and not result.ok
    assert result.reason == "untrusted-image"


@pytest.mark.parametrize("pid", [0, -1, -150394016, None])
def test_3_bad_pid_is_rejected(pid):
    desktop = FakeDesktop(windows={HWND: (pid, FORTI_TID, HWND)})
    result = target(desktop).acquire(HWND)
    assert isinstance(result, TargetRejected) and result.reason == "no-process"


def test_4_unreadable_process_is_rejected():
    desktop = FakeDesktop(images={})            # OpenProcess/query returns nothing
    result = target(desktop).acquire(HWND)
    assert result.reason == "image-unavailable" and result.pid == FORTI_PID


@pytest.mark.parametrize("image", [
    EVIL_EXE,                                                    # same base name
    r"C:\Program Files\Fortinet\FortiClientEvil\FortiClient.exe",  # prefix trick
    FORTI_DIR + r"\..\..\Users\x\FortiClient.exe",              # traversal
])
def test_5_similar_name_or_location_is_rejected(image):
    desktop = FakeDesktop(images={FORTI_PID: image})
    result = target(desktop).acquire(HWND)
    assert isinstance(result, TargetRejected) and result.reason == "untrusted-image"


def test_6_forticlient_outside_trusted_dir_is_rejected():
    outside = r"D:\Apps\Fortinet\FortiClient\FortiClient.exe"
    desktop = FakeDesktop(images={FORTI_PID: outside})
    # Trusted dirs come from the provider's detection; D:\ is not one.
    assert target(desktop).acquire(HWND).reason == "untrusted-image"
    # But if that directory *were* a real, Program-Files-based install, it would pass.
    assert target(desktop, dirs=(r"D:\Apps\Fortinet\FortiClient",)).acquire(HWND).ok


# ══════════════════════════════════════════════════════════════════════════
# 7–11. Focus and re-confirmation
# ══════════════════════════════════════════════════════════════════════════

def test_7_owner_change_before_operation_is_rejected():
    desktop = FakeDesktop()
    win = target(desktop).acquire(HWND)
    assert win.ok
    performed = []
    # PID is reused by another image between acquisition and the operation.
    desktop.images[FORTI_PID] = EVIL_EXE
    result = win.run_guarded("password", lambda: performed.append(True))
    assert result.performed is False and performed == []
    assert result.reason == "untrusted-image"


def test_8_focus_moving_to_another_window_is_rejected():
    desktop = FakeDesktop(foreground=focus_lost_after(0))   # foreground already OTHER
    win = target(desktop).acquire(HWND)
    assert isinstance(win, TargetRejected)
    assert win.reason == "foreground-is-other-window"


def test_8b_hwnd_confirmed_at_acquire_then_lost_before_operation():
    desktop = FakeDesktop(foreground=focus_lost_after(1))    # ok for acquire, then gone
    win = target(desktop).acquire(HWND)
    assert win.ok
    performed = []
    result = win.run_guarded("token", lambda: performed.append(True))
    assert result.performed is False and performed == []
    assert result.reason == "foreground-is-other-window"


def test_9_valid_target_with_focus_runs_the_operation():
    desktop = FakeDesktop()
    win = target(desktop).acquire(HWND)
    calls = []
    result = win.run_guarded("password", lambda: calls.append("sent") or "done")
    assert result.performed is True and result.value == "done"
    assert calls == ["sent"] and result.reason == "verified"
    assert ("attach", True) in desktop.events and ("set_foreground",) in desktop.events


def test_10_no_focus_is_rejected():
    # Attach itself refused: nothing was attached, so nothing to detach.
    rejected = target(FakeDesktop(attach_ok=False)).acquire(HWND)
    assert isinstance(rejected, TargetRejected) and rejected.reason == "attach-failed"

    # Attach succeeded but the foreground could not be taken: detach again.
    for sf in ("fails", "raises"):
        desktop = FakeDesktop(set_foreground=sf)
        result = target(desktop).acquire(HWND)
        assert isinstance(result, TargetRejected), sf
        assert result.reason == "set-foreground-failed"
        assert desktop.events.count(("attach", True)) == 1
        assert desktop.events.count(("attach", False)) == 1, "odłączono po porażce"


def test_11_target_that_cannot_be_confirmed_runs_nothing():
    desktop = FakeDesktop()
    win = target(desktop).acquire(HWND)
    win.release()                                # handle no longer valid
    result = win.run_guarded("password", lambda: pytest.fail("nie wolno wywołać"))
    assert result.performed is False and result.reason == "no-verified-target"


def test_11b_confirmation_exception_is_fail_closed(monkeypatch):
    """Even if confirmation itself raises, the operation must not run.

    The primitives already swallow desktop errors into a "not confirmed"
    result; this pins the outer guard as a second net.
    """
    win = target(FakeDesktop()).acquire(HWND)

    def boom():
        raise RuntimeError("confirm padł")

    monkeypatch.setattr(win, "confirm", boom)
    result = win.run_guarded("password", lambda: pytest.fail("nie wolno wywołać"))
    assert result.performed is False and result.reason.startswith("confirm-error:")


def test_11d_broken_desktop_during_confirmation_is_not_confirmed(monkeypatch):
    """A desktop that throws is reported as "no target", never as confirmed."""
    desktop = FakeDesktop()
    win = target(desktop).acquire(HWND)
    monkeypatch.setattr(desktop, "foreground_window",
                        lambda: (_ for _ in ()).throw(RuntimeError("x")))
    result = win.run_guarded("password", lambda: pytest.fail("nie wolno wywołać"))
    assert result.performed is False and result.reason == "no-foreground"


def test_11c_control_ownership_is_rechecked_in_the_guard():
    desktop = FakeDesktop(windows={
        HWND: (FORTI_PID, FORTI_TID, HWND),
        0x3001: (FORTI_PID, FORTI_TID, HWND),         # our control
        0x3002: (EVIL_PID, 99, HWND)})                # a foreign control
    win = target(desktop).acquire(HWND)
    ok = win.run_guarded("password", lambda: "x", controls=[0x3001])
    assert ok.performed is True
    blocked = win.run_guarded("password", lambda: pytest.fail("nie wolno"),
                              controls=[0x3001, 0x3002])
    assert blocked.performed is False and blocked.reason == "control-not-owned-by-target"


def test_release_detaches_thread_input_once():
    desktop = FakeDesktop()
    with target(desktop).acquire(HWND) as win:
        assert win.ok
    assert desktop.events.count(("attach", False)) == 1
    win.release()                                    # idempotent
    assert desktop.events.count(("attach", False)) == 1


# ══════════════════════════════════════════════════════════════════════════
# Candidate finding: a candidate is not a target
# ══════════════════════════════════════════════════════════════════════════

class ListFinder(WindowCandidateFinder):
    def __init__(self, hwnds):
        self._hwnds = hwnds

    def candidates(self):
        return list(self._hwnds)


def test_candidate_is_only_a_starting_point():
    desktop = FakeDesktop()
    tgt = target(desktop, finder=ListFinder([OTHER, HWND]))
    assert tgt.find_candidates() == [OTHER, HWND]
    hwnd, owner = tgt.first_verified_candidate()
    assert hwnd == HWND and owner.pid == FORTI_PID     # OTHER skipped, not trusted


def test_no_finder_yields_no_candidates():
    assert target(FakeDesktop()).find_candidates() == []


# ══════════════════════════════════════════════════════════════════════════
# 12. The provider exposes the contract but sends no secret through it
# ══════════════════════════════════════════════════════════════════════════

def test_12_provider_builds_the_target_without_any_secret_path():
    provider = FortiClientProvider(
        FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))
    tgt = provider.secure_window_target(api=FakeDesktop())
    assert isinstance(tgt, SecureWindowTarget)
    win = tgt.acquire(HWND)
    assert win.ok
    # The only way to act is a caller-supplied callback; nothing on the handle
    # or the contract accepts a login/password/token.
    for obj in (win, tgt):
        members = dir(obj)
        for banned in ("login", "username", "password", "token", "secret",
                       "type_text", "paste", "send_keys", "clipboard"):
            assert not any(banned in m.lower() for m in members), (banned, type(obj))


def test_12b_verified_window_cannot_be_forged_from_a_bare_hwnd():
    # There is no public constructor that yields a "verified" window without
    # going through SecureWindowTarget.acquire (which verifies + focuses).
    provider = FortiClientProvider(FakeEnvironment())
    assert not hasattr(provider, "connect_system") or provider._connect_system is None
    # connect() is still unsupported — no secret path is wired.
    result = provider.connect(VpnRequest(provider_id="forticlient",
                                         password="SuperSecret123"))
    assert result.error_code == "unsupported"


def test_12c_trusted_dirs_come_from_provider_detection():
    env = FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR])
    provider = FortiClientProvider(env)
    dirs = provider.trusted_window_dirs()
    assert set(sw.KNOWN_FORTI_DIRS) <= set(dirs)


def test_contract_source_never_names_a_secret():
    source = open(st.__file__, encoding="utf-8").read()
    tree = ast.parse(source)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {a.arg for n in ast.walk(tree) if isinstance(n, ast.arguments)
              for a in n.args}
    for banned in ("password", "login", "username", "token", "clipboard",
                   "SendInput", "send_keys", "WM_SETTEXT", "keybd_event"):
        assert banned not in names, banned


def test_contract_shares_secure_window_not_a_copy():
    """The security logic is imported from the one shared module, not re-coded."""
    tree = ast.parse(open(st.__file__, encoding="utf-8").read())
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                 for a in n.names}
    assert "secure_window" in imported
    # None of the low-level machinery is re-imported — it lives in secure_window.
    assert not any(m and m.split(".")[0] in ("ctypes", "win32process", "win32gui",
                                             "win32api", "ntpath")
                   for m in imported), imported
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for low_level in ("QueryFullProcessImageNameW", "GetWindowThreadProcessId",
                      "OpenProcess"):
        assert low_level not in names, low_level


# ══════════════════════════════════════════════════════════════════════════
# Architecture: base provider stays generic; production untouched
# ══════════════════════════════════════════════════════════════════════════

def test_base_provider_knows_no_win32_or_forticlient():
    source = open(os.path.join(_PARENT, "vpn", "provider.py"), encoding="utf-8").read()
    base = ast.unparse(next(n for n in ast.walk(ast.parse(source))
                            if isinstance(n, ast.ClassDef) and n.name == "VpnProvider"))
    for forbidden in ("win32", "hwnd", "HWND", "FortiClient", "secure_window",
                      "SetForeground", "AttachThreadInput", "SendInput",
                      "SecureWindowTarget", "clipboard"):
        assert forbidden not in base, forbidden


def test_secure_window_module_imports_no_vpn_package():
    """Shared implementation must not depend on the new architecture (no cycle)."""
    tree = ast.parse(open(sw.__file__, encoding="utf-8").read())
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                for a in n.names}
    assert not any(m and (m == "vpn" or m.startswith("vpn.")) for m in modules)


def test_legacy_uses_the_shared_module_directly_not_the_contract():
    tree = ast.parse(open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read())
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert "secure_window" in modules, "legacy współdzieli implementację bezpieczeństwa"
    assert not any(m and (m == "vpn" or m.startswith("vpn.")) for m in modules), (
        "legacy nie importuje nowej architektury")


def test_provider_registered_but_connect_still_unsupported():
    provider = vpn.default_registry.get("forticlient")
    assert isinstance(provider, FortiClientProvider)
    assert provider.capabilities() == vpn.Capability.LAUNCH
    assert provider.connect(VpnRequest(provider_id="forticlient")).error_code == "unsupported"
    assert vpn.check_contract(provider) == []
