"""Stage 58: the test suite never reaches the real machine.

Before this stage a test was only isolated if it happened to stub the right
seam.  With ``FortiClientProvider.CONNECT_ENABLED`` flipped in source, tests
that relied on the flag being off (e.g. a real ``_connect_card`` expecting the
legacy route) drove a real ``PanelConnectSession`` in a QThread: the real
FortiClient window was filled, Enter was sent and the VPN connected.

Two layers, both for the whole session:

1. **Real-machine guard** — installed once at configure time and never
   undone, so a worker thread that outlives its test is still blocked.  It
   replaces the OS primitives the Win32 seams reach for lazily (`subprocess`,
   `os.startfile`, pywin32, `ctypes` user32/shell32, comtypes) with tripwires
   that record the attempt and raise :class:`RealSystemBlocked`.  A test that
   exercises a real seam keeps doing what it already did — monkeypatching the
   primitive with a fake — and gets the guard back on teardown.  Starting this
   very Python interpreter (the import-graph checks) stays allowed.

   Any attempt fails the test it happened in; one that lands between tests
   (a stray thread) fails the session.  A test that *means* to hit the guard
   says so with ``@pytest.mark.real_system_guard``.

2. **Flags off by default** — every ``CONNECT_ENABLED`` is forced to ``False``
   for each test, whatever the source says; a test that wants the V2 route
   sets it to ``True`` itself.  The source values are pinned separately
   (``test_17`` in ``test_vpn_v2_routing_gate.py``).
"""

from __future__ import annotations

import ntpath
import os
import subprocess
import sys
import threading

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


class RealSystemBlocked(Exception):
    """A test tried to touch the real machine."""


#: Every blocked attempt, in order: the primitive's name.
HITS: list[str] = []
_HITS_LOCK = threading.Lock()
#: Attempts made inside tests marked ``real_system_guard`` (expected ones).
_EXPECTED = [0]

GUARD_ATTR = "__real_system_guard__"


def _record(name: str) -> None:
    with _HITS_LOCK:
        HITS.append(name)


def blocked(name: str):
    def tripwire(*args, **kwargs):
        _record(name)
        raise RealSystemBlocked(f"test sięgnął po prawdziwy system: {name}")
    setattr(tripwire, GUARD_ATTR, name)
    return tripwire


def is_guarded(obj) -> bool:
    return getattr(obj, GUARD_ATTR, None) is not None


# -- processes -------------------------------------------------------------- #

_REAL_POPEN = subprocess.Popen


def _is_own_interpreter(args) -> bool:
    if not isinstance(args, (list, tuple)) or not args:
        return False
    exe = os.path.normcase(os.path.abspath(str(args[0])))
    return exe == os.path.normcase(os.path.abspath(sys.executable))


class GuardedPopen(_REAL_POPEN):
    """Only this Python interpreter may be started (import-graph checks)."""

    def __init__(self, args, *a, **k):
        if not _is_own_interpreter(args):
            _record("subprocess.Popen")
            raise RealSystemBlocked("test sięgnął po prawdziwy system: subprocess.Popen")
        super().__init__(args, *a, **k)


setattr(GuardedPopen, GUARD_ATTR, "subprocess.Popen")

# -- pywin32 / comtypes: module attributes ---------------------------------- #

MODULE_PRIMITIVES = {
    "win32gui": ("SetForegroundWindow", "SendMessage", "SendMessageTimeout",
                 "PostMessage", "ShowWindow", "SetWindowPos", "BringWindowToTop",
                 "SetWindowText", "SetFocus", "SetActiveWindow", "EnumWindows",
                 "EnumChildWindows", "GetForegroundWindow", "FindWindow",
                 "FindWindowEx"),
    "win32api": ("keybd_event", "mouse_event", "SendMessage", "PostMessage",
                 "SetCursorPos", "ShellExecute", "WinExec"),
    "win32clipboard": ("OpenClipboard", "EmptyClipboard", "SetClipboardText",
                       "SetClipboardData", "GetClipboardData"),
    "win32process": ("CreateProcess",),
    "comtypes.client": ("CreateObject", "GetModule"),
}

# -- ctypes: functions resolved from these DLLs ----------------------------- #

DLL_PRIMITIVES = {
    "user32": frozenset({
        "SendInput", "keybd_event", "mouse_event", "SetForegroundWindow",
        "AttachThreadInput", "ShowWindow", "ShowWindowAsync", "SendMessageW",
        "SendMessageA", "PostMessageW", "PostMessageA", "SetWindowTextW",
        "BringWindowToTop", "SetFocus", "SetActiveWindow", "SetCursorPos",
        "SetWindowPos", "SwitchToThisWindow", "OpenClipboard", "EmptyClipboard",
        "SetClipboardData", "GetForegroundWindow", "EnumWindows",
        "EnumChildWindows", "LockSetForegroundWindow", "AllowSetForegroundWindow"}),
    "shell32": frozenset({"ShellExecuteW", "ShellExecuteA", "ShellExecuteExW"}),
    # Windows Credential Manager: ui/rdp.py resolves these at import and writes
    # TERMSRV/<ip> entries with them (2026-10-14).
    "advapi32": frozenset({"CredWriteW", "CredDeleteW", "CredReadW"}),
}


def _dll_key(lib) -> str:
    name = ntpath.basename(str(getattr(lib, "_name", "") or "")).lower()
    return name[:-4] if name.endswith(".dll") else name


def _install_ctypes_guard() -> None:
    import ctypes

    real_getattr = ctypes.CDLL.__getattr__
    real_getitem = ctypes.CDLL.__getitem__

    def _guarded(lib, name):
        names = DLL_PRIMITIVES.get(_dll_key(lib))
        if names is not None and name in names:
            return blocked(f"{_dll_key(lib)}.{name}")
        return None

    def __getattr__(self, name):
        return _guarded(self, name) or real_getattr(self, name)

    def __getitem__(self, name):
        return _guarded(self, name) or real_getitem(self, name)

    ctypes.CDLL.__getattr__ = __getattr__
    ctypes.CDLL.__getitem__ = __getitem__
    # Anything resolved before the guard is cached on the loaded library.
    for dll in DLL_PRIMITIVES:
        lib = ctypes.windll.__dict__.get(dll)
        if lib is not None:
            for name in DLL_PRIMITIVES[dll]:
                lib.__dict__.pop(name, None)


def _guard_module(module) -> None:
    for name in MODULE_PRIMITIVES.get(module.__name__, ()):
        if hasattr(module, name):
            setattr(module, name, blocked(f"{module.__name__}.{name}"))


class _GuardOnImport:
    """Re-guards a module every time it is imported.

    A test that swaps ``sys.modules["win32gui"]`` for a fake and then deletes
    it makes the next ``import win32gui`` build a fresh module with the real
    functions — so the guard has to be applied at import, not only once.
    """

    def find_spec(self, fullname, path, target=None):
        if fullname not in MODULE_PRIMITIVES:
            return None
        for finder in sys.meta_path:
            find = getattr(finder, "find_spec", None)
            if finder is self or find is None:
                continue
            spec = find(fullname, path, target)
            if spec is not None and spec.loader is not None:
                real_exec = spec.loader.exec_module

                def exec_module(module, _real=real_exec):
                    _real(module)
                    _guard_module(module)

                spec.loader.exec_module = exec_module
                return spec
        return None


def install_real_system_guard() -> None:
    import importlib

    subprocess.Popen = GuardedPopen
    for name in ("startfile", "system"):
        if hasattr(os, name):
            setattr(os, name, blocked(f"os.{name}"))
    sys.meta_path.insert(0, _GuardOnImport())
    for module_name in MODULE_PRIMITIVES:
        try:
            _guard_module(importlib.import_module(module_name))
        except Exception:
            continue
    _install_ctypes_guard()


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_system_guard: the test deliberately hits the "
                   "real-machine guard (its attempts are expected)")
    install_real_system_guard()


@pytest.fixture(autouse=True)
def _real_system_guard(request):
    start = len(HITS)
    yield
    new = HITS[start:]
    if request.node.get_closest_marker("real_system_guard") is not None:
        _EXPECTED[0] += len(new)
    elif new:
        pytest.fail(f"test sięgnął po prawdziwy system: {sorted(set(new))}",
                    pytrace=False)


@pytest.fixture(autouse=True)
def _connect_flags_off(monkeypatch):
    from vpn.providers.barracuda import BarracudaProvider
    from vpn.providers.forticlient import FortiClientProvider
    from vpn.providers.stormshield import StormshieldProvider

    for cls in (FortiClientProvider, StormshieldProvider, BarracudaProvider):
        monkeypatch.setattr(cls, "CONNECT_ENABLED", False)


@pytest.fixture(autouse=True)
def _no_modal_file_dialogs(monkeypatch):
    """A Qt file dialog in a test opens a real modal window on the desktop and
    the run hangs until someone closes it (2026-10-14: a test that missed one
    stub did exactly that).  Every static file dialog is a tripwire instead."""
    from PyQt6.QtWidgets import QFileDialog
    for name in ("getOpenFileName", "getOpenFileNames", "getSaveFileName",
                 "getExistingDirectory"):
        monkeypatch.setattr(QFileDialog, name,
                            staticmethod(blocked(f"QFileDialog.{name}")))


@pytest.fixture(autouse=True)
def _isolated_appdata(monkeypatch, tmp_path):
    """config.py writes APPDATA/HospitalHubV2/config.json; a test must
    never touch the real one (2026-10-14).  Each test gets an empty APPDATA."""
    appdata = tmp_path / "AppData"
    appdata.mkdir()
    monkeypatch.setenv("APPDATA", str(appdata))


def pytest_sessionfinish(session, exitstatus):
    stray = len(HITS) - _EXPECTED[0]
    if stray > 0:
        # Attempts outside any test that failed for them: a thread that
        # outlived its test.  The session must not pass.
        _unaccounted = [h for h in HITS]
        sys.stderr.write(f"\nREAL SYSTEM GUARD: {stray} nieprzypisanych prób: "
                         f"{sorted(set(_unaccounted))}\n")
        session.exitstatus = 1
