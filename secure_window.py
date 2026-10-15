"""Guard for handing a secret (login, password, 2FA token) to another program's window.

Rule: **no confirmed target → no operation on a secret.**

Owner of a window
-----------------
HWND → owning PID (``GetWindowThreadProcessId``) → full image path of that
process (``QueryFullProcessImageNameW``) → the image must lie inside a trusted
FortiClient installation directory.  A window title or class never
establishes trust here; callers may use them only to pick candidates.

Trusted directories are the FortiClient directories under Program Files.
Writing there needs administrator rights, so a process an ordinary user can
start does not pass by being called ``FortiClient.exe`` or by copying the
title.  The registry ``INSTALLDIR`` is added only when it exists and itself
lies under a Program Files root; any other location is not trusted (the
autofill is then refused rather than risked).

Focus
-----
``AttachThreadInput`` and ``SetForegroundWindow`` must both report success,
and the foreground window must then resolve (``GetAncestor(GA_ROOT)``) to the
verified window and be owned by the same verified process — re-checked
immediately before every operation on a secret, because the user (or another
program) can change the foreground window at any moment.

No I/O at import; win32/ctypes are touched only inside :class:`Win32WindowApi`,
so every decision here can be tested with a described desktop.
"""

from __future__ import annotations

import ntpath
import os
from dataclasses import dataclass, field, replace

__all__ = [
    "WindowApi", "Win32WindowApi", "OwnerCheck", "TargetCheck", "FocusResult",
    "KNOWN_FORTI_DIRS", "program_files_roots", "trusted_install_dirs", "is_inside",
    "verify_window_owner", "confirm_target", "acquire_focus", "controls_belong_to",
    "partition_controls", "operation_controls_verified", "ControlPartition",
    "WindowCandidateFinder", "Win32TitleWindowFinder", "FOCUS_DIAGNOSTIC_KEYS",
]

KNOWN_FORTI_DIRS = (
    r"C:\Program Files\Fortinet\FortiClient",
    r"C:\Program Files (x86)\Fortinet\FortiClient",
)
_DEFAULT_PROGRAM_FILES = (r"C:\Program Files", r"C:\Program Files (x86)")
_PROGRAM_FILES_ENV = ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")

# Reasons — stable strings, written to traces.
REASON_VERIFIED = "verified"
REASON_NO_WINDOW = "no-window"
REASON_NO_PROCESS = "no-process"
REASON_IMAGE_UNAVAILABLE = "image-unavailable"
REASON_UNTRUSTED_IMAGE = "untrusted-image"
REASON_FOCUSED = "focused"
REASON_NO_THREAD = "no-thread"
REASON_ATTACH_FAILED = "attach-failed"
REASON_SET_FOREGROUND_FAILED = "set-foreground-failed"
REASON_NO_FOREGROUND = "no-foreground"
REASON_OTHER_WINDOW = "foreground-is-other-window"
REASON_OWNER_CHANGED = "owner-changed"
REASON_CONTROL_FOREIGN = "control-not-owned-by-target"
#: A control that belongs to the right process but sits in a different
#: window.  Reported only by the newer per-control API; the older
#: :func:`controls_belong_to` folds it into REASON_CONTROL_FOREIGN so the
#: strings it has always produced stay exactly as they were.
REASON_CONTROL_OUTSIDE_WINDOW = "control-outside-window"

_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_GA_ROOT = 2
_SW_RESTORE = 9


@dataclass(frozen=True)
class OwnerCheck:
    verified: bool
    reason: str
    pid: int | None = None
    #: Base name of the owning image (e.g. "fortitray.exe") — never a path.
    image_name: str | None = None


@dataclass(frozen=True)
class TargetCheck:
    ok: bool
    reason: str


@dataclass(frozen=True)
class FocusResult:
    ok: bool
    reason: str
    #: AttachThreadInput succeeded — the caller must detach, whatever `ok` is.
    attached: bool = False
    our_tid: int | None = None
    their_tid: int | None = None
    #: Why the desktop answered the way it did — filled only when the caller
    #: asks for it (``acquire_focus(..., diagnose=True)``), empty otherwise.
    #: Numbers, handles and booleans only; see :data:`FOCUS_DIAGNOSTIC_KEYS`.
    diagnostics: dict = field(default_factory=dict)


#: Every key :func:`acquire_focus` may put in :attr:`FocusResult.diagnostics`.
#:
#: Deliberately all numbers, handles and booleans.  No window title (a title is
#: a document name, a patient name, whatever the user happens to have open), no
#: image path (it contains the user's profile directory), no clipboard, no
#: credential.  A window handle and a pid identify a window to a developer
#: reading a trace and say nothing about the person using the machine.
FOCUS_DIAGNOSTIC_KEYS = (
    "foreground_before", "foreground_after",
    "foreground_pid_before", "foreground_pid_after", "foreground_tid_before",
    "target_pid", "target_tid", "target_iconic",
    "attach_ok", "set_foreground_ok", "set_foreground_error",
    "idle_s", "confirm_reason", "confirm_ok",
)


# --------------------------------------------------------------------------- #
# Seam                                                                         #
# --------------------------------------------------------------------------- #

class WindowApi:
    """The few window/process facts the guard needs.  Tests describe a desktop."""

    def window_pid(self, hwnd) -> int | None:
        raise NotImplementedError

    def window_thread_id(self, hwnd) -> int | None:
        raise NotImplementedError

    def process_image_path(self, pid) -> str | None:
        raise NotImplementedError

    def foreground_window(self):
        raise NotImplementedError

    def root_window(self, hwnd):
        raise NotImplementedError

    def current_thread_id(self) -> int:
        raise NotImplementedError

    def attach_thread_input(self, our_tid, their_tid, attach: bool) -> bool:
        raise NotImplementedError

    def restore_window(self, hwnd) -> None:
        raise NotImplementedError

    # -- read-only extras, used only when a caller asks to be told why -------- #
    #
    # Each has a harmless default so that every existing WindowApi — the fakes
    # in the test suite included — keeps working untouched.  "Unknown" is a
    # legitimate answer: the diagnostics are an explanation, never a decision.

    def set_foreground_window_detail(self, hwnd) -> tuple:
        """``(succeeded, win32 error or None)``.

        The same call and the same answer as :meth:`set_foreground_window` —
        this one just keeps the error code that the boolean throws away.
        """
        return bool(self.set_foreground_window(hwnd)), None

    def user_idle_seconds(self):
        """Seconds since the last real keyboard/mouse input, or None."""
        return None

    def is_iconic(self, hwnd):
        """Is the window minimised?  None when the seam cannot tell."""
        return None

    def set_foreground_window(self, hwnd) -> bool:
        raise NotImplementedError


class Win32WindowApi(WindowApi):
    """The real desktop.  Every failure answers "unknown", never raises."""

    @staticmethod
    def _thread_and_process(hwnd):
        """(tid, pid) or (None, None).

        For an invalid HWND the API returns thread id 0 and leaves the PID
        out-parameter *uninitialised* — pywin32 then hands back garbage
        (observed: -150394016).  A garbage PID could collide with a real
        process, so a zero thread id or a non-positive PID means "unknown".
        """
        try:
            import win32process
            tid, pid = win32process.GetWindowThreadProcessId(hwnd)
        except Exception:
            return None, None
        if not tid or not isinstance(pid, int) or pid <= 0:
            return None, None
        return tid, pid

    def window_pid(self, hwnd):
        return self._thread_and_process(hwnd)[1]

    def window_thread_id(self, hwnd):
        return self._thread_and_process(hwnd)[0]

    def process_image_path(self, pid):
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            open_process = kernel32.OpenProcess
            open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_process.restype = wintypes.HANDLE
            query = kernel32.QueryFullProcessImageNameW
            query.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                              ctypes.POINTER(wintypes.DWORD)]
            query.restype = wintypes.BOOL
            close = kernel32.CloseHandle
            close.argtypes = [wintypes.HANDLE]
            close.restype = wintypes.BOOL

            handle = open_process(_PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
            if not handle:
                return None
            try:
                size = wintypes.DWORD(32768)
                buffer = ctypes.create_unicode_buffer(size.value)
                if not query(handle, 0, buffer, ctypes.byref(size)):
                    return None
                return buffer.value or None
            finally:
                close(handle)
        except Exception:
            return None

    def foreground_window(self):
        try:
            import win32gui
            return win32gui.GetForegroundWindow() or None
        except Exception:
            return None

    def root_window(self, hwnd):
        try:
            import ctypes
            from ctypes import wintypes
            get_ancestor = ctypes.WinDLL("user32").GetAncestor
            get_ancestor.argtypes = [wintypes.HWND, wintypes.UINT]
            get_ancestor.restype = wintypes.HWND
            return get_ancestor(hwnd, _GA_ROOT) or None
        except Exception:
            return None

    def current_thread_id(self):
        import ctypes
        return ctypes.windll.kernel32.GetCurrentThreadId()

    def attach_thread_input(self, our_tid, their_tid, attach):
        try:
            import ctypes
            from ctypes import wintypes
            attach_input = ctypes.WinDLL("user32").AttachThreadInput
            attach_input.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
            attach_input.restype = wintypes.BOOL
            return bool(attach_input(our_tid, their_tid, bool(attach)))
        except Exception:
            return False

    def restore_window(self, hwnd):
        import win32gui
        win32gui.ShowWindow(hwnd, _SW_RESTORE)

    def set_foreground_window(self, hwnd):
        return self.set_foreground_window_detail(hwnd)[0]

    def set_foreground_window_detail(self, hwnd):
        """Unchanged decision, with the refusal reason kept.

        ``win32gui.SetForegroundWindow`` raises when Windows refuses, and the
        exception carries ``winerror`` — which the boolean-only version threw
        away, leaving "refused by the foreground rules" indistinguishable from
        "bad handle".  Everything about *what the caller does next* is the same
        as before: an exception is False, a return is True.
        """
        try:
            import win32gui
            win32gui.SetForegroundWindow(hwnd)     # raises when Windows refuses
            return True, None
        except Exception as exc:
            return False, getattr(exc, "winerror", None)

    def user_idle_seconds(self):
        try:
            import ctypes
            from ctypes import wintypes

            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

            info = LASTINPUTINFO()
            info.cbSize = ctypes.sizeof(info)
            if not ctypes.WinDLL("user32").GetLastInputInfo(ctypes.byref(info)):
                return None
            ticks = ctypes.WinDLL("kernel32").GetTickCount()
            return max(0.0, round((ticks - info.dwTime) / 1000.0, 1))
        except Exception:
            return None

    def is_iconic(self, hwnd):
        try:
            import win32gui
            return bool(win32gui.IsIconic(hwnd))
        except Exception:
            return None


# --------------------------------------------------------------------------- #
# Trusted locations                                                            #
# --------------------------------------------------------------------------- #

def _norm(path: str) -> str:
    text = str(path)
    if text.startswith("\\\\?\\"):
        text = text[4:]
    return ntpath.normcase(ntpath.normpath(text))


def is_inside(path, directory) -> bool:
    """True when `path` lies strictly below `directory` (no ``..`` tricks,
    no ``...\\FortiClientEvil`` prefix confusion, case-insensitive)."""
    if not isinstance(path, str) or not isinstance(directory, str):
        return False
    if not path.strip() or not directory.strip():
        return False
    return _norm(path).startswith(_norm(directory).rstrip("\\") + "\\")


def program_files_roots(environ=None) -> tuple[str, ...]:
    env = os.environ if environ is None else environ
    roots: list[str] = []
    for candidate in (*_DEFAULT_PROGRAM_FILES, *(env.get(k) for k in _PROGRAM_FILES_ENV)):
        if isinstance(candidate, str) and candidate.strip():
            if _norm(candidate) not in {_norm(r) for r in roots}:
                roots.append(candidate)
    return tuple(roots)


def trusted_install_dirs(install_dir, is_dir=os.path.isdir, roots=None) -> tuple[str, ...]:
    """FortiClient directories whose processes may receive a secret."""
    roots = program_files_roots() if roots is None else roots
    dirs = list(KNOWN_FORTI_DIRS)
    if (isinstance(install_dir, str) and install_dir.strip()
            and any(is_inside(install_dir, root) for root in roots)):
        try:
            exists = bool(is_dir(install_dir))
        except Exception:
            exists = False
        if exists and _norm(install_dir) not in {_norm(d) for d in dirs}:
            dirs.append(install_dir)
    return tuple(dirs)


# --------------------------------------------------------------------------- #
# Checks                                                                       #
# --------------------------------------------------------------------------- #

def verify_window_owner(hwnd, trusted_dirs, api: WindowApi) -> OwnerCheck:
    if not hwnd:
        return OwnerCheck(False, REASON_NO_WINDOW)
    try:
        pid = api.window_pid(hwnd)
    except Exception:
        pid = None
    # Defense in depth: the Win32 seam already drops a non-positive PID, but a
    # zero/negative/garbage PID must never reach the image lookup even if some
    # other WindowApi hands one back.
    if not isinstance(pid, int) or pid <= 0:
        return OwnerCheck(False, REASON_NO_PROCESS)
    try:
        image = api.process_image_path(pid)
    except Exception:
        image = None
    if not isinstance(image, str) or not image:
        return OwnerCheck(False, REASON_IMAGE_UNAVAILABLE, pid)
    name = ntpath.basename(_norm(image))
    if not any(is_inside(image, directory) for directory in trusted_dirs):
        return OwnerCheck(False, REASON_UNTRUSTED_IMAGE, pid, name)
    return OwnerCheck(True, REASON_VERIFIED, pid, name)


def confirm_target(hwnd, expected_pid, trusted_dirs, api: WindowApi) -> TargetCheck:
    """Is the verified window — of the verified process — in the foreground *now*?"""
    try:
        foreground = api.foreground_window()
    except Exception:
        foreground = None
    if not foreground:
        return TargetCheck(False, REASON_NO_FOREGROUND)
    try:
        root = api.root_window(foreground)
    except Exception:
        root = None
    if (root or foreground) != hwnd:
        return TargetCheck(False, REASON_OTHER_WINDOW)
    owner = verify_window_owner(foreground, trusted_dirs, api)
    if not owner.verified:
        return TargetCheck(False, owner.reason)
    if expected_pid is not None and owner.pid != expected_pid:
        return TargetCheck(False, REASON_OWNER_CHANGED)
    return TargetCheck(True, REASON_FOCUSED)


def acquire_focus(hwnd, expected_pid, trusted_dirs, api: WindowApi, *,
                  diagnose: bool = False,
                  raise_window: bool = True) -> FocusResult:
    """Bring the verified window forward; succeed only if that is confirmed.

    `raise_window` (default ``True``) is the legacy behaviour, unchanged: the
    window is restored and pushed to the foreground before it is confirmed.

    ``raise_window=False`` means one thing and nothing else: **the window must
    already be active.**  It is not a second way of activating one.  Stages 18
    to 20 measured that a background process cannot take the foreground from
    another process' window, and Stage 22 concluded that the connect should
    therefore wait for the user instead of trying; but ``restore_window`` here
    still undid that decision for anyone who had put the client away.  With
    this off, nothing is restored, nothing is raised, and ``confirm_target``
    decides on the desktop exactly as it found it — fail-closed, because a
    window that is not in front simply does not confirm.

    `diagnose` adds **observation, never a decision**: every branch below is
    taken on exactly the same condition as before, and with `diagnose` off not
    one extra call is made to the desktop.  That matters twice over — it keeps
    the production path identical, and it keeps the measurement from disturbing
    what it measures (reading the foreground window is itself an observation
    the fake desktops in the test suite count).

    What lands in :attr:`FocusResult.diagnostics` is listed in
    :data:`FOCUS_DIAGNOSTIC_KEYS`: handles, pids, thread ids, booleans, an idle
    time and a Win32 error number.  Never a window title, never a path.
    """
    notes = _FocusNotes(api, diagnose)
    notes.before(hwnd, expected_pid)
    try:
        their_tid = api.window_thread_id(hwnd)
    except Exception:
        their_tid = None
    if not their_tid:
        return notes.finish(FocusResult(False, REASON_NO_THREAD))
    our_tid = api.current_thread_id()
    notes.record("target_tid", their_tid)
    try:
        attached = bool(api.attach_thread_input(our_tid, their_tid, True))
    except Exception:
        attached = False
    notes.record("attach_ok", attached)
    if not attached:
        return notes.finish(
            FocusResult(False, REASON_ATTACH_FAILED, False, our_tid, their_tid))
    if raise_window:
        try:
            api.restore_window(hwnd)
            foreground_set, error = notes.set_foreground(hwnd)
        except Exception:
            foreground_set, error = False, None
        notes.record("set_foreground_ok", foreground_set)
        notes.record("set_foreground_error", error)
        if not foreground_set:
            return notes.finish(FocusResult(False, REASON_SET_FOREGROUND_FAILED,
                                            True, our_tid, their_tid))
    check = confirm_target(hwnd, expected_pid, trusted_dirs, api)
    notes.record("confirm_ok", check.ok)
    notes.record("confirm_reason", check.reason)
    return notes.finish(FocusResult(check.ok, check.reason, True, our_tid,
                                    their_tid))


class _FocusNotes:
    """Collects the why of a focus attempt.  Does nothing at all when off."""

    def __init__(self, api: WindowApi, enabled: bool):
        self._api = api
        self._on = bool(enabled)
        self._data: dict = {}

    def record(self, key, value) -> None:
        if self._on and value is not None:
            self._data[key] = value

    def _safely(self, call, *args):
        try:
            return call(*args)
        except Exception:
            return None

    def before(self, hwnd, expected_pid) -> None:
        if not self._on:
            return
        foreground = self._safely(self._api.foreground_window)
        self.record("foreground_before", foreground)
        if foreground:
            self.record("foreground_pid_before",
                        self._safely(self._api.window_pid, foreground))
            self.record("foreground_tid_before",
                        self._safely(self._api.window_thread_id, foreground))
        self.record("target_pid", expected_pid
                    if expected_pid is not None
                    else self._safely(self._api.window_pid, hwnd))
        self.record("target_iconic", self._safely(self._api.is_iconic, hwnd))
        self.record("idle_s", self._safely(self._api.user_idle_seconds))

    def set_foreground(self, hwnd) -> tuple:
        """The same call either way; the detail variant only keeps the error."""
        if not self._on:
            return bool(self._api.set_foreground_window(hwnd)), None
        succeeded, error = self._api.set_foreground_window_detail(hwnd)
        return bool(succeeded), error

    def finish(self, result: FocusResult) -> FocusResult:
        if not self._on:
            return result
        foreground = self._safely(self._api.foreground_window)
        self.record("foreground_after", foreground)
        if foreground:
            self.record("foreground_pid_after",
                        self._safely(self._api.window_pid, foreground))
        unknown = set(self._data) - set(FOCUS_DIAGNOSTIC_KEYS)
        assert not unknown, f"nieudokumentowany klucz diagnostyczny: {unknown}"
        return replace(result, diagnostics=self._data)


@dataclass(frozen=True)
class ControlPartition:
    """Which of the handles offered may take part in an operation, and which
    may not.  Neutral on purpose: it reports, the caller decides.

    `owner` is the verified owner of the window the controls were checked
    against, or None when the window itself failed verification — in which case
    everything is foreign and nothing may be used.
    """

    usable: tuple = ()
    foreign: tuple = ()
    reason: str = REASON_VERIFIED
    owner: "OwnerCheck | None" = None

    @property
    def ok(self) -> bool:
        """True when every offered control may be used."""
        return not self.foreign and self.owner is not None


def partition_controls(hwnd, controls, trusted_dirs,
                       api: WindowApi) -> ControlPartition:
    """Split `controls` into those that belong to the verified window and those
    that do not.  **Presence of a foreign child does not condemn the window.**

    That distinction is not theoretical.  A real FortiClient main window is an
    Electron window: among its children are a render-widget surface owned by
    the client's own process and a Direct3D surface owned by a *different*
    FortiClient process.  Asking "is every child of this window mine?" answers
    "no" for a perfectly genuine client, while proving nothing whatsoever about
    where a secret would go.  The question that matters is asked per control:
    *may this particular handle receive the operation?*

    The rule per control is unchanged and unrelaxed: same owning process as the
    window, and rooted in that same window.  A handle that merely lives inside
    a trusted window is not trusted by that fact.
    """
    owner = verify_window_owner(hwnd, trusted_dirs, api)
    if not owner.verified:
        return ControlPartition((), tuple(controls), owner.reason, None)

    usable, foreign, reason = [], [], REASON_VERIFIED
    for control in controls:
        try:
            pid = api.window_pid(control)
            root = api.root_window(control)
        except Exception:
            foreign.append(control)
            reason = REASON_CONTROL_FOREIGN
            continue
        if pid != owner.pid:
            foreign.append(control)
            reason = REASON_CONTROL_FOREIGN
        elif root != hwnd:
            foreign.append(control)
            if reason is REASON_VERIFIED:
                reason = REASON_CONTROL_OUTSIDE_WINDOW
        else:
            usable.append(control)
    return ControlPartition(tuple(usable), tuple(foreign), reason, owner)


def operation_controls_verified(hwnd, controls, trusted_dirs,
                                api: WindowApi) -> TargetCheck:
    """May *these* controls receive the operation that is about to happen?

    `controls` is the **operation set** — the handles the caller is about to
    write to, click, or otherwise rely on.  Never pass a window's whole child
    list: see :func:`partition_controls` for why that question is the wrong one.
    Fail-closed: one unusable handle and the answer is no.
    """
    partition = partition_controls(hwnd, controls, trusted_dirs, api)
    if partition.owner is None:
        return TargetCheck(False, partition.reason)
    if partition.foreign:
        return TargetCheck(False, partition.reason)
    return TargetCheck(True, REASON_VERIFIED)


def controls_belong_to(hwnd, controls, trusted_dirs, api: WindowApi) -> TargetCheck:
    """Before WM_SETTEXT/BM_CLICK: window verified and every control is its own.

    The long-standing entry point, kept to the letter for the legacy module and
    for the EMS layout-integrity rule ("a foreign Edit/Button anywhere in this
    window and the whole window is out").  Every caller passes a *curated* set:
    the legacy hands it the two credential fields, or the token field, plus the
    buttons — never the window's raw child list.

    Same rule as :func:`operation_controls_verified`; it differs only in
    reporting, collapsing both ways a control can be wrong into the single
    reason string this function has always produced.
    """
    partition = partition_controls(hwnd, controls, trusted_dirs, api)
    if partition.owner is None:
        return TargetCheck(False, partition.reason)
    if partition.foreign:
        return TargetCheck(False, REASON_CONTROL_FOREIGN)
    return TargetCheck(True, REASON_VERIFIED)


# --------------------------------------------------------------------------- #
# Candidate finding (Win32 seam)                                               #
# --------------------------------------------------------------------------- #
# A "candidate" is a window worth *checking* — never a trusted target. It is
# nothing until verify_window_owner passes on it, so this seam may match on
# title (cheap and Win32-specific) precisely because the decision that matters
# is made elsewhere by the process-image checks above.

class WindowCandidateFinder:
    """Finds candidate windows.  Isolated so tests can inject a list."""

    def candidates(self) -> list:
        raise NotImplementedError


class Win32TitleWindowFinder(WindowCandidateFinder):
    """Visible top-level windows whose title contains `must_contain` and not
    `must_not_contain`.  win32 is imported lazily, so importing this module
    stays cheap and free of a hard pywin32 dependency.

    `must_contain` may be a tuple, in which case *every* substring has to be
    present — the FortiClient authentication window is matched by "FortiClient"
    and "Authentication" together, exactly as the legacy enumerator does it.
    """

    def __init__(self, must_contain, must_not_contain: str | None = None):
        self._must_contain = ((must_contain,) if isinstance(must_contain, str)
                              else tuple(must_contain))
        self._must_not_contain = must_not_contain

    def candidates(self) -> list:
        try:
            import win32gui
        except Exception:
            return []
        found: list = []

        def _cb(hwnd, _):
            try:
                if not win32gui.IsWindowVisible(hwnd):
                    return True
                title = win32gui.GetWindowText(hwnd)
            except Exception:
                return True
            if title and all(part in title for part in self._must_contain) and (
                    not self._must_not_contain or self._must_not_contain not in title):
                found.append(hwnd)
            return True

        try:
            win32gui.EnumWindows(_cb, None)
        except Exception:
            pass
        return found
