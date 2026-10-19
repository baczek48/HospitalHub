"""Stormshield SSL VPN Client — detection, launch and window discovery.

The second provider to be migrated, and the first chance to find out whether
the architecture built around FortiClient is an architecture or just
FortiClient with the serial numbers filed off.  Deliberately different in
every way that matters: Qt5 instead of Electron, no CLI, no second factor, no
submit, and a login form whose cursor starts on the *password* field.

What this stage covers
----------------------
``detect`` → ``launch`` → window discovery, plus the skeleton of the connect
flow up to the point where the user has activated the window.  No autofill, no
keystroke, no secret.  ``StormshieldConnectFlow`` stops after
``activation_still_holds`` and reports ``requires_user_action``.

Three decisions carried over from the Stage-38 analysis, each measured rather
than assumed:

* **No elevation.**  ``sslvpn_client.exe`` ships a ``level="asInvoker"``
  manifest, so it starts with the caller's rights and needs no UAC prompt.
  The legacy comment claiming otherwise names *Stormshield SN VPN*, which is a
  different product.  Launch therefore goes through the ordinary
  :meth:`LaunchSystem.spawn_detached`, whose PyInstaller-free environment is
  the one real difference between ``ShellExecuteW`` and ``Popen`` here.
* **No tray click.**  The legacy posts a synthetic double-click to the client's
  Qt tray window to make it show itself.  That is the same class of act as
  ``SW_RESTORE`` — reaching into another program's window to change what the
  user sees — and it is not migrated.  A hidden window simply means the gate
  has nothing to observe, and the user opens it themselves.
* **No TOPMOST.**  ``_bring_window_to_front`` forces a window forward with
  ``SetWindowPos(HWND_TOPMOST)``.  Not migrated, for the same reason.

Window discovery
----------------
The title is a *candidate filter only*.  Legacy accepts any visible window
whose title contains "stormshield" and types a password into it; here the
title merely proposes, and acceptance is the same three-step test every
migrated path uses: HWND → PID → the process image must live in a trusted
install directory under Program Files.  No class-name assumptions and none of
FortiClient's title exclusions are carried over — Stormshield has no second
window to exclude.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from secure_window import (
    Win32TitleWindowFinder, WindowApi, WindowCandidateFinder, is_inside,
    program_files_roots,
)

from ..catalog import STORMSHIELD as STORMSHIELD_SPEC
from ..provider import VpnProvider
from ..types import (
    AutomationMode, Capability, ConnectResult, DetectionResult, DetectionState,
    ErrorCode, LaunchAttempt, LaunchResult, VpnRequest, unsupported,
)
from .forticlient import DetectionEnvironment, WindowsEnvironment
from .launch_system import LaunchSystem, WindowsLaunchSystem
from .stormshield_connect import (
    StormshieldConnectFlow, StormshieldConnectRuntime,
)
from .secure_target import SecureWindowTarget

__all__ = ["StormshieldProvider", "GUI_PATHS", "INSTALL_DIRS", "GUI_EXE_NAME",
           "WINDOW_TITLE_HINT", "STRATEGY_POPEN_CLEAN_ENV", "POPEN_WAIT_S"]

#: Where the client is installed.  The legacy has `_PATHS["Stormshield"] == []`
#: — it can only be launched when the user has pointed at the executable by
#: hand — which is why detection here starts from known paths like every other
#: migrated provider.  The x86 variant is listed because the installer creates
#: a `Program Files (x86)\Stormshield` tree as well; on this machine it exists
#: but is empty, so it costs one `is_file` and answers the question honestly.
GUI_PATHS = (
    r"C:\Program Files\Stormshield\Stormshield SSL VPN Client\sslvpn_client.exe",
    r"C:\Program Files (x86)\Stormshield\Stormshield SSL VPN Client\sslvpn_client.exe",
)
INSTALL_DIRS = tuple(os.path.dirname(path) for path in GUI_PATHS)

GUI_EXE_NAME = "sslvpn_client.exe"

#: Title substring the legacy enumerator uses.  A *candidate* filter: it says
#: which windows are worth verifying, never which window may be trusted.
WINDOW_TITLE_HINT = "Stormshield"

SOURCE_APP_PATH = "app_path"
SOURCE_KNOWN_PATHS = "known_paths"

#: One strategy, unlike FortiClient's two: there is no public `.lnk` to hand to
#: explorer, and no reason to invent one.
STRATEGY_POPEN_CLEAN_ENV = "popen_clean_env"
POPEN_WAIT_S = 3.0

#: 2026-10-19, measured on the real client: a first start goes to the tray
#: with no window; starting the executable again while it runs makes the
#: running instance show its window, in front.  How long to wait for a window
#: after a start, and how many extra starts to try.
WINDOW_WAIT_S = 4.0
RESHOW_ATTEMPTS = 2


@dataclass(frozen=True)
class _Findings:
    """What detection saw.  No paths leave this object without being asked."""

    gui_path: str | None = None
    source: str | None = None
    install_dir: str | None = None


class StormshieldProvider(VpnProvider):
    """Stormshield SSL VPN Client, migrated as far as window discovery."""

    id = "stormshield"
    display_name = STORMSHIELD_SPEC.display_name
    legacy_name = STORMSHIELD_SPEC.legacy_name

    #: What the client can do in principle (see `vpn.catalog`).
    spec = STORMSHIELD_SPEC

    #: Not armed, and for the same reason as FortiClient: the flow exists but
    #: the application must keep going through `vpn_connect.py` until parity is
    #: proven.  This stage has no autofill to arm anyway.
    CONNECT_ENABLED = False

    def __init__(self, environment: DetectionEnvironment | None = None,
                 system: LaunchSystem | None = None):
        # No I/O in either constructor — safe to build at import time.
        self._env = environment or WindowsEnvironment()
        self._system = system if system is not None else WindowsLaunchSystem()

    def capabilities(self) -> Capability:
        """What **this implementation** does today: find it and start it.

        Not what the client can do — that is :attr:`spec`, which also records
        the autofill and the manual disconnect.  Deliberately absent, because
        the real client does not have them: no CLI connect, no second factor,
        no automatic submit.
        """
        return Capability.LAUNCH

    def automation_mode(self) -> AutomationMode:
        """Manual until the autofill is migrated — nothing is typed here yet."""
        return AutomationMode.MANUAL

    # -- detection --------------------------------------------------------- #

    def detect(self, request: VpnRequest | None = None) -> DetectionResult:
        app_path = request.app_path if request is not None else ""
        try:
            findings = self._gather(app_path or "")
        except Exception as exc:                    # environment misbehaving
            return DetectionResult(
                provider_id=self.id, success=False, state=DetectionState.ERROR,
                error_code=ErrorCode.DETECTION_FAILED.value,
                metadata={"reason_code": type(exc).__name__})

        if not findings.gui_path:
            return DetectionResult(
                provider_id=self.id, success=True,
                state=DetectionState.NOT_INSTALLED)
        return DetectionResult(
            provider_id=self.id, success=True, state=DetectionState.INSTALLED,
            path=findings.gui_path, source=findings.source)

    def _gather(self, app_path: str) -> _Findings:
        gui, source = self._gui_executable(app_path)
        install_dir = os.path.dirname(gui) if gui else None
        return _Findings(gui_path=gui, source=source, install_dir=install_dir)

    def _gui_executable(self, app_path: str = "") -> tuple[str | None, str | None]:
        """The client's executable: what the user configured, else a known path.

        `app_path` wins because that is the only thing the legacy has — a
        profile pointing somewhere unusual keeps working.  It buys no trust:
        whether a *window* owned by that executable may receive anything is
        decided by :meth:`trusted_window_dirs`, not by this.
        """
        if app_path and self._env.is_file(app_path):
            return app_path, SOURCE_APP_PATH
        for path in GUI_PATHS:
            if self._env.is_file(path):
                return path, SOURCE_KNOWN_PATHS
        return None, None

    # -- secure target ----------------------------------------------------- #

    def trusted_window_dirs(self) -> tuple[str, ...]:
        """Directories a window's process must live in to be trusted later.

        The known install directories, plus the directory of a configured
        `app_path` **only when it sits under Program Files** — writing there
        needs administrator rights, which is the whole basis of the trust.  An
        `app_path` anywhere else launches fine and is still refused a secret,
        exactly as FortiClient treats a registry INSTALLDIR outside those roots.
        """
        dirs: list[str] = [d for d in INSTALL_DIRS]
        configured = self._configured_dir
        if configured:
            roots = program_files_roots()
            known = {os.path.normcase(os.path.normpath(d)) for d in dirs}
            if (any(is_inside(configured, root) for root in roots)
                    and os.path.normcase(os.path.normpath(configured)) not in known):
                dirs.append(configured)
        return tuple(dirs)

    #: Set by a caller that knows the profile's `app_path`; empty otherwise.
    _configured_dir: str = ""

    def with_app_path(self, app_path: str) -> "StormshieldProvider":
        """Remember a profile's executable directory for the trust decision."""
        self._configured_dir = (os.path.dirname(app_path)
                                if app_path and self._env.is_file(app_path)
                                else "")
        return self

    def window_finder(self) -> WindowCandidateFinder:
        """Visible windows whose title mentions Stormshield — candidates only.

        No `must_not_contain`: FortiClient needs one to keep its authentication
        dialog out of the main-window search, and Stormshield has no second
        window to exclude.  Copying that exclusion would be cargo cult.
        """
        return Win32TitleWindowFinder(WINDOW_TITLE_HINT)

    def secure_window_target(self, api: WindowApi | None = None,
                             finder: WindowCandidateFinder | None = None
                             ) -> SecureWindowTarget:
        """The window contract, configured the way Stages 29–34 settled it.

        ``require_visible=True`` and ``raise_window=False``: the client must
        already be in front and not minimised, and nothing here will put it
        there.  Same configuration as FortiClient's main window, for the same
        reasons, and reached through the same shared code.
        """
        return SecureWindowTarget(
            self.trusted_window_dirs(), api=api, require_visible=True,
            raise_window=False,
            finder=finder if finder is not None else self.window_finder())

    # -- autofill ---------------------------------------------------------- #

    def autofill_login_password(self, request, *, target=None,
                                input_system=None, trace=None, uia=None,
                                cancellation=None):
        """Fill the client's form (Stage 41; fields by AutomationId since
        2026-10-19).  Every step goes through the guard, and the sequence stops
        before the submit, as the legacy does.
        """
        from .stormshield_autofill import autofill_login_password
        return autofill_login_password(self, request, target=target,
                                       input_system=input_system, trace=trace,
                                       uia=uia, cancellation=cancellation)

    # -- launch ------------------------------------------------------------ #

    def launch(self, request: VpnRequest | None = None) -> LaunchResult:
        """Start the client and nothing else.

        One strategy: detached, with a PyInstaller-free environment.  No
        elevation (the manifest is ``asInvoker``), no tray click, no attempt to
        raise or focus whatever appears — the user activates the window, and
        until they do, the gate simply waits.
        """
        app_path = request.app_path if request is not None else ""
        attempts: list[LaunchAttempt] = []
        try:
            return self._launch(app_path or "", attempts)
        except Exception as exc:
            return self._result(False, attempts, ErrorCode.LAUNCH_FAILED,
                                reason_code=type(exc).__name__)

    def _launch(self, app_path: str, attempts: list[LaunchAttempt]) -> LaunchResult:
        gui, _source = self._gui_executable(app_path)
        if not gui:
            return self._result(False, attempts, ErrorCode.CLIENT_NOT_FOUND)

        cwd = os.path.dirname(gui)
        try:
            pid = self._system.spawn_detached(gui, cwd)
        except Exception as exc:
            attempts.append(LaunchAttempt(
                STRATEGY_POPEN_CLEAN_ENV, started=False, process_started=False,
                error_code=ErrorCode.LAUNCH_FAILED.value,
                reason_code=type(exc).__name__))
            return self._result(False, attempts, ErrorCode.LAUNCH_FAILED,
                                reason_code="process-start-failed")

        try:
            started = bool(self._system.wait_for_process(GUI_EXE_NAME,
                                                         POPEN_WAIT_S))
            observation_failed = False
        except Exception:
            # The spawn succeeded; only the observation broke.  Saying "not
            # started" here would be a lie about what happened to the machine.
            started, observation_failed = True, True

        attempts.append(LaunchAttempt(
            STRATEGY_POPEN_CLEAN_ENV, started=started, process_started=True,
            pid=pid, observation_failed=observation_failed,
            error_code=None if started else ErrorCode.LAUNCH_NO_PROCESS.value))
        if started:
            self._show_from_tray(gui, cwd)
        return self._result(True, attempts)

    def _show_from_tray(self, gui: str, cwd: str) -> None:
        """Start the client again while no window of it is on screen.

        The running instance answers a second start by showing its window
        (measured 2026-10-19); that replaces the tray click the legacy posts.
        Only with a launch system that can wait for a window — the fakes in
        the test suite cannot, and then nothing extra happens.
        """
        wait_until = getattr(self._system, "wait_until", None)
        if wait_until is None:
            return

        def shown() -> bool:
            return self.secure_window_target().first_verified_candidate() is not None

        if wait_until(shown, WINDOW_WAIT_S):
            return
        for _ in range(RESHOW_ATTEMPTS):
            try:
                self._system.spawn_detached(gui, cwd)
            except Exception:
                return
            if wait_until(shown, WINDOW_WAIT_S):
                return

    def _result(self, success: bool, attempts: list[LaunchAttempt],
                error_code: ErrorCode | None = None,
                reason_code: str | None = None) -> LaunchResult:
        last = attempts[-1] if attempts else None
        return LaunchResult(
            provider_id=self.id, success=success,
            strategy=last.strategy if last else None,
            started=last.started if last else False,
            pid=last.pid if last else None,
            process_started=last.process_started if last else None,
            observation_failed=bool(last.observation_failed) if last else False,
            requires_user_action=True,
            attempts=tuple(attempts),
            error_code=error_code.value if error_code else None,
            metadata={"reason_code": reason_code} if reason_code else {})

    # -- diagnostics ------------------------------------------------------- #

    # -- connect ----------------------------------------------------------- #

    def connect(self, request: VpnRequest, entry: str = "", *,
                system=None) -> ConnectResult:
        """The whole connect, over this provider's own flow (Stage 54).

        Same shape and same fail-closed rules as FortiClient's: a system has to
        be supplied — passed here, or enabled by flipping
        :attr:`CONNECT_ENABLED` — or this answers ``unsupported``.  What runs is
        :class:`~vpn.providers.stormshield_connect.StormshieldConnectFlow`, not
        FortiClient's: one client, one window, one route, and a deliberate stop
        before any typing.

        ``entry`` exists only because the caller's contract has it (FortiClient
        follows two legacy entry points).  Stormshield has a single route, so
        the value is accepted and ignored rather than pretended to matter.
        """
        if system is None:
            if not self.CONNECT_ENABLED:
                return unsupported(self.id, ConnectResult)
            system = self.connect_runtime()
        return StormshieldConnectFlow(self, system).run(request)

    def connect_runtime(self, **seams):
        """Build the real connect system (see :meth:`connect`).

        Every collaborator is injectable — ``window_api``, ``launch_system``,
        ``finder``, ``clock``, ``cancellation``, ``activation_observer``,
        ``trace`` — which is how the flow is exercised against a fake machine.
        """
        return StormshieldConnectRuntime(self, **seams)

    def diagnostics(self, request: VpnRequest | None = None) -> dict:
        """Machine facts only — no path of the user's, no credential."""
        detection = self.detect(request)
        return {"installed": detection.state is DetectionState.INSTALLED,
                "source": detection.source or "",
                "trusted_dirs": len(self.trusted_window_dirs())}

    def __repr__(self) -> str:
        return f"<StormshieldProvider id={self.id!r}>"

