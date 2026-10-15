"""Diagnostic collectors: facts about this machine, gathered on demand.

A collector is a zero-argument callable returning a plain dict.  It never
formats, never masks and never writes — redaction happens in one place
(:mod:`diagnostics.redactor`), so a collector cannot accidentally opt out of it.

Collectors must not raise: :func:`collect` wraps each one and records the
failure as data, because a diagnostics package that refuses to be produced is
worse than one with a missing section.

Only host/app facts live here.  VPN, RDP and SSH collectors arrive with their
respective stages — this module deliberately ships without them so that
nothing in the running application changes yet.
"""

from __future__ import annotations

import ctypes
import locale
import os
import platform
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

from . import redactor
from .redactor import Masker, Mode

Collector = Callable[[], dict]

_COLLECTORS: dict[str, Collector] = {}


# --------------------------------------------------------------------------- #
# Registry                                                                     #
# --------------------------------------------------------------------------- #

def register(name: str, fn: Collector | None = None):
    """Register a collector. Usable as ``@register("vpn")`` or directly."""
    def _wrap(func: Collector) -> Collector:
        _COLLECTORS[name] = func
        return func
    return _wrap if fn is None else _wrap(fn)


def unregister(name: str) -> None:
    _COLLECTORS.pop(name, None)


def available() -> list[str]:
    return sorted(_COLLECTORS)


def collect(names: list[str] | None = None, safe: bool = True,
            masker: Masker | None = None, mode: Mode = Mode.RUNTIME) -> dict:
    """Run collectors and return ``{section: data}``.

    With ``safe=True`` (the default) the result is already redacted, so it can
    be shown in the UI or written anywhere.  ``safe=False`` returns raw data
    and exists for exactly one caller: :mod:`diagnostics.export`, which applies
    EXPORT-mode redaction so that a collector leaking a secret fails loudly
    instead of silently.
    """
    wanted = names if names is not None else available()
    out: dict[str, Any] = {}
    for name in wanted:
        func = _COLLECTORS.get(name)
        if func is None:
            out[name] = {"error": "nieznany kolektor", "status": "fail"}
            continue
        try:
            out[name] = func() or {}
        except Exception as exc:                       # collectors never raise
            out[name] = {"status": "fail", "error_code": type(exc).__name__,
                         "error": str(exc)[:200]}
    if not safe:
        return out
    return redactor.redact(out, mode=mode, masker=masker)


# --------------------------------------------------------------------------- #
# UI Automation model (structure only — no field values, ever)                 #
# --------------------------------------------------------------------------- #

@dataclass
class UiaNode:
    """One control in a window's automation tree.

    **Values are never read.**  There is no `value` field here and there never
    will be: the whole point of walking the tree is to learn *where* the login
    and password fields are, not what is typed into them.  `has_value_pattern`
    records only that a control supports ValuePattern — useful to know when
    deciding whether automation can set a field at all.

    `name` is a label, but labels occasionally embed a user name ("Zalogowany
    jako …"), so it goes through the redactor like any other free text.
    """

    control_type: str = ""
    automation_id: str = ""
    name: str = ""
    class_name: str = ""
    pid: int | None = None
    is_enabled: bool | None = None
    is_offscreen: bool | None = None
    depth: int = 0
    has_value_pattern: bool | None = None
    children: list["UiaNode"] = field(default_factory=list)

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "control_type": self.control_type,
            "automation_id": self.automation_id,
            "name": self.name,
            "class_name": self.class_name,
            "depth": self.depth,
        }
        if self.pid is not None:
            out["pid"] = self.pid
        if self.is_enabled is not None:
            out["is_enabled"] = self.is_enabled
        if self.is_offscreen is not None:
            out["is_offscreen"] = self.is_offscreen
        if self.has_value_pattern is not None:
            out["has_value_pattern"] = self.has_value_pattern
        if self.children:
            out["children"] = [c.to_dict() for c in self.children]
        return out

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    def summary(self) -> dict:
        nodes = list(self.walk())
        return {
            "control_count": len(nodes),
            "tree_depth": max((n.depth for n in nodes), default=0),
        }


@dataclass
class WindowInfo:
    """A top-level window, described without touching its contents."""

    hwnd: int | None = None
    title: str = ""
    class_name: str = ""
    pid: int | None = None
    visible: bool | None = None
    width: int | None = None
    height: int | None = None

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"title": self.title, "class_name": self.class_name}
        for key, value in (("hwnd", self.hwnd), ("pid", self.pid),
                           ("visible", self.visible), ("width", self.width),
                           ("height", self.height)):
            if value is not None:
                out[key] = value
        return out


# --------------------------------------------------------------------------- #
# Built-in collectors                                                          #
# --------------------------------------------------------------------------- #

@register("app")
def _collect_app() -> dict:
    from . import APP_NAME, APP_VARIANT, APP_VERSION, base_dir

    frozen = bool(getattr(sys, "frozen", False))
    return {
        "app_name": APP_NAME,
        "app_variant": APP_VARIANT,
        "app_version": APP_VERSION,
        "frozen": frozen,
        "executable": sys.executable or "",
        "install_dir": os.path.dirname(os.path.abspath(__file__)),
        "cwd": os.getcwd(),
        "config_path": str(base_dir()),
        "python_version": platform.python_version(),
        "qt_version": _qt_version(),
    }


def _qt_version() -> str:
    """PyQt's version without importing QtWidgets (no GUI side effects)."""
    try:
        from PyQt6.QtCore import QT_VERSION_STR  # type: ignore
        return str(QT_VERSION_STR)
    except Exception:
        return ""


@register("system")
def _collect_system() -> dict:
    data: dict[str, Any] = {
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "arch": platform.machine(),
        "processor": platform.processor()[:120],
        "cpu_count": os.cpu_count(),
        "encoding": sys.getfilesystemencoding(),
        "is_admin": _is_admin(),
    }
    try:
        lang, enc = locale.getlocale()
        data["locale"] = lang or ""
        data["code_page"] = enc or ""
    except Exception:
        pass
    if sys.platform == "win32":
        data.update(_windows_facts())
    return data


def _is_admin() -> bool | None:
    if sys.platform != "win32":
        return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


def _windows_facts() -> dict:
    out: dict[str, Any] = {}
    try:
        info = sys.getwindowsversion()
        out["os_build"] = getattr(info, "build", None)
    except Exception:
        pass
    try:
        class _MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

        status = _MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            out["ram_mb"] = int(status.ullTotalPhys // (1024 * 1024))
            out["ram_free_mb"] = int(status.ullAvailPhys // (1024 * 1024))
    except Exception:
        pass
    try:
        user32 = ctypes.windll.user32
        out["display"] = {
            "width": int(user32.GetSystemMetrics(0)),
            "height": int(user32.GetSystemMetrics(1)),
            "monitor_count": int(user32.GetSystemMetrics(80)),
            "dpi": _system_dpi(),
        }
    except Exception:
        pass
    return out


def _system_dpi() -> int | None:
    try:
        return int(ctypes.windll.user32.GetDpiForSystem())
    except Exception:
        return None


@register("runtime")
def _collect_runtime() -> dict:
    """Process-level facts that explain odd behaviour of child processes.

    The `_MEI*` flag matters in practice: a PyInstaller-tainted environment is
    what makes FortiClient's Electron logger crash, and today we can only guess
    whether a given machine was affected.
    """
    env = os.environ
    return {
        "pid": os.getpid(),
        "frozen": bool(getattr(sys, "frozen", False)),
        "has_meipass": bool(getattr(sys, "_MEIPASS", None)),
        "meipass_env_present": any(k.startswith(("_MEI", "_PYI")) for k in env),
        "path_entry_count": len(env.get("PATH", "").split(os.pathsep)),
        "temp_dir": env.get("TEMP", ""),
        "session_type": "interactive" if sys.stdin and sys.stdin.isatty() else "windowed",
    }


@register("diagnostics")
def _collect_diagnostics_self() -> dict:
    from . import get_store

    store = get_store()
    stats = store.stats() if store else {"count": 0, "retention": 0, "size_bytes": 0}
    return {
        "dir": str(store.directory) if store else "",
        "count": stats.get("count", 0),
        "retention": stats.get("retention", 0),
        "size_bytes": stats.get("size_bytes", 0),
    }


# Keys emitted by the collectors above that are not part of the generic
# allowlist.  Declared here, next to the code that produces them.
redactor.allow_keys("has_meipass", "meipass_env_present", "path_entry_count",
                    "session_type")
