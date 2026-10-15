"""Barracuda Network Access Client — detection, launch and window discovery.

The third provider to be migrated, and the first whose live UI contract is
**not yet known on any machine we have**.  So this stage builds only the
foundation every migrated provider shares — find it, start it, and decide which
window may later be trusted — and stops there, deliberately, *before* a single
keystroke.  The autofill is not implemented and is not guessed: the legacy
Barracuda path (`_autofill_native_vpn_window`) is a hybrid of ``WM_SETTEXT`` and
a blind ``SendInput`` sequence, and which branch a real Barracuda window needs,
in what field order, is exactly what a read-only probe has to measure first on a
machine that actually has the client.

Why the legacy discovery is not carried over
--------------------------------------------
The legacy accepts *any* visible window whose title contains one of
``vpn / barracuda / credential / sonicwall / pulse / globalprotect`` and types a
password into ``candidates[0]`` with no owner verification.  That would send
Barracuda's credentials into a SonicWall or GlobalProtect window.  None of it is
migrated.  Here the title is a **candidate filter only** — and the narrowest
one the legacy contract justifies, the product name alone — while acceptance is
the same three-step test every migrated path uses: HWND → PID → the owning
process image must live in a trusted install directory under Program Files.

CONTRACT-ONLY on this machine
-----------------------------
Barracuda is not installed here, so the executable name(s), the window title and
the control layout below are taken from the legacy contract and the product's
documented layout, **not measured**.  They are marked and must be confirmed by
the probe before the autofill stage.  Nothing about correctness depends on them
being complete: trust is anchored to the directory of whatever executable is
actually found (a configured ``app_path`` or a known path under Program Files),
so a real install pointed at by ``app_path`` is verified correctly even if the
guessed known paths are wrong.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from secure_window import (
    Win32TitleWindowFinder, WindowApi, WindowCandidateFinder, is_inside,
    program_files_roots,
)

from ..catalog import BARRACUDA as BARRACUDA_SPEC
from ..provider import VpnProvider
from ..types import (
    AutomationMode, Capability, ConnectResult, DetectionResult, DetectionState,
    ErrorCode, LaunchAttempt, LaunchResult, VpnRequest, unsupported,
)
from .barracuda_connect import BarracudaConnectFlow, BarracudaConnectRuntime
from .forticlient import DetectionEnvironment, WindowsEnvironment
from .launch_system import LaunchSystem, WindowsLaunchSystem
from .secure_target import SecureWindowTarget

__all__ = ["BarracudaProvider", "GUI_EXE_NAMES", "INSTALL_DIRS", "GUI_PATHS",
           "WINDOW_TITLE_HINT", "STRATEGY_POPEN_CLEAN_ENV", "POPEN_WAIT_S",
           "UI_CONTRACT_VERIFIED"]

#: The legacy has ``_PATHS["Barracuda"] == []`` — it can only be launched from a
#: configured ``app_path`` — so, like every other migrated provider, detection
#: here also starts from known paths.  **Measured on a real install (Stage 50B):**
#: the GUI executable is ``nacvpn.exe`` under "Barracuda\Network Access Client".
#: The two earlier guesses (``vpnclient.exe`` / ``phionvpn.exe``) were wrong and
#: are dropped.  Both Program Files roots are listed so the answer is honest on
#: 32- and 64-bit installs; trust is anchored to the directory, not the name.
GUI_EXE_NAMES = ("nacvpn.exe",)
INSTALL_DIRS = (
    r"C:\Program Files\Barracuda\Network Access Client",
    r"C:\Program Files (x86)\Barracuda\Network Access Client",
)
GUI_PATHS = tuple(os.path.join(directory, name)
                  for directory in INSTALL_DIRS for name in GUI_EXE_NAMES)

#: Title substring used only to *propose* candidate windows.  The product name
#: alone — the narrowest filter the legacy title match justifies — never the
#: cross-product ``vpn/credential/sonicwall/...`` list.  CONTRACT-ONLY: the
#: probe must confirm the real login window's title (and class) before autofill.
WINDOW_TITLE_HINT = "Barracuda"

#: Stage 50C: the UI contract has now been measured on a real install (WPF,
#: fields ``TextBoxUser`` / ``PasswordBoxUser`` set by UI Automation), so the
#: autofill exists.  It is still not wired to production — like FortiClient and
#: Stormshield, the application keeps going through ``vpn_connect.py`` and
#: ``CONNECT_ENABLED`` stays ``False``.
UI_CONTRACT_VERIFIED = True

SOURCE_APP_PATH = "app_path"
SOURCE_KNOWN_PATHS = "known_paths"

#: One launch strategy: detached, clean environment.  No public ``.lnk`` to hand
#: to explorer, no elevation (the legacy uses plain ``os.startfile`` — no UAC),
#: no tray click, no TOPMOST.  Until a probe proves Barracuda needs any of that,
#: launch only starts the client and observes the process.
STRATEGY_POPEN_CLEAN_ENV = "popen_clean_env"
POPEN_WAIT_S = 3.0


@dataclass(frozen=True)
class _Findings:
    """What detection saw.  No path leaves this object without being asked."""

    gui_path: str | None = None
    source: str | None = None
    install_dir: str | None = None


class BarracudaProvider(VpnProvider):
    """Barracuda Network Access Client, migrated as far as window discovery."""

    id = "barracuda"
    display_name = BARRACUDA_SPEC.display_name
    legacy_name = BARRACUDA_SPEC.legacy_name

    #: What the client can do in principle (see `vpn.catalog`).
    spec = BARRACUDA_SPEC

    #: Not armed, like FortiClient and Stormshield: the flow exists but the
    #: application keeps going through `vpn_connect.py`.  This stage has no
    #: autofill to arm anyway.
    CONNECT_ENABLED = False

    def __init__(self, environment: DetectionEnvironment | None = None,
                 system: LaunchSystem | None = None):
        # No I/O in either constructor — safe to build at import time.
        self._env = environment or WindowsEnvironment()
        self._system = system if system is not None else WindowsLaunchSystem()

    def capabilities(self) -> Capability:
        """What **this implementation** does today: find it and start it.

        Not what the client can do — that is :attr:`spec`, which records the
        native-window autofill and the manual disconnect.  Deliberately absent
        here: the autofill is a later stage and must not be advertised before it
        exists (and before its UI contract is measured).
        """
        return Capability.LAUNCH

    def automation_mode(self) -> AutomationMode:
        """Manual until the autofill is migrated — nothing is typed here yet.

        The client's real mode is ``NATIVE_WINDOW`` (:attr:`spec`); this
        implementation types nothing, so it reports ``MANUAL`` honestly.
        """
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

        ``app_path`` wins because that is the only thing the legacy has — a
        profile pointing somewhere unusual keeps working, and it is also the
        only *verified* path on a machine where the guessed known paths may be
        wrong.  It buys no trust: whether a *window* owned by that executable
        may receive anything is decided by :meth:`trusted_window_dirs`, not by
        this.  A whole-disk search and process-name-only matching are
        deliberately not used.
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
        ``app_path`` **only when it sits under Program Files** — writing there
        needs administrator rights, which is the whole basis of the trust.  An
        ``app_path`` anywhere else launches fine and is still refused a secret,
        exactly as FortiClient and Stormshield treat an executable outside those
        roots.  Trust is thus anchored to a real directory under Program Files,
        never to the executable's *name* — so a look-alike ``vpnclient.exe`` in
        a user folder is refused even though its basename matches.
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

    #: Set by a caller that knows the profile's ``app_path``; empty otherwise.
    _configured_dir: str = ""

    def with_app_path(self, app_path: str) -> "BarracudaProvider":
        """Remember a profile's executable directory for the trust decision."""
        self._configured_dir = (os.path.dirname(app_path)
                                if app_path and self._env.is_file(app_path)
                                else "")
        return self

    def window_finder(self) -> WindowCandidateFinder:
        """Visible windows whose title mentions Barracuda — candidates only.

        CONTRACT-ONLY.  The legacy matched a broad list; this narrows to the
        product name, which the legacy contract justifies, and nothing wider.
        No ``must_not_contain`` and no class-name assumption: Barracuda's exact
        login-window title and class are unmeasured (the probe fills that in),
        so this proposes as little as it safely can and lets the owner check
        decide.  A candidate is nothing until :class:`SecureWindowTarget`
        verifies its owning process.
        """
        return Win32TitleWindowFinder(WINDOW_TITLE_HINT)

    def secure_window_target(self, api: WindowApi | None = None,
                             finder: WindowCandidateFinder | None = None
                             ) -> SecureWindowTarget:
        """The window contract, configured the way Stages 29–34 settled it.

        ``require_visible=True`` and ``raise_window=False``: the client must
        already be in front and not minimised, and nothing here will put it
        there.  Identical to FortiClient's and Stormshield's main window, for
        the same reasons and through the same shared code — no new foreground
        activation mechanism is introduced.
        """
        return SecureWindowTarget(
            self.trusted_window_dirs(), api=api, require_visible=True,
            raise_window=False,
            finder=finder if finder is not None else self.window_finder())

    # -- autofill ---------------------------------------------------------- #

    def autofill_login_password(self, request, *, target=None, uia=None,
                                cancellation=None, trace=None):
        """Fill User Name + User Password by AutomationId (Stage 50C).

        Prepared, not wired to production — the running application still fills
        Barracuda through the legacy module, and ``CONNECT_ENABLED`` stays
        ``False``.  Every value goes through the secure-window guard *and* the
        UI Automation seam's owner check; the sequence stops before Connect and
        never presses Enter.  The OTP/certificate fields are not touched.
        """
        from .barracuda_autofill import autofill_login_password
        return autofill_login_password(self, request, target=target, uia=uia,
                                       cancellation=cancellation, trace=trace)

    # -- launch ------------------------------------------------------------ #

    def launch(self, request: VpnRequest | None = None) -> LaunchResult:
        """Start the client and nothing else.

        One strategy: detached, with a PyInstaller-free environment through the
        shared :class:`LaunchSystem`.  No elevation (the legacy uses plain
        ``os.startfile`` — no UAC), no tray click, no attempt to raise or focus
        whatever appears.  The user activates the window; until they do, the
        gate simply waits.
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

        # The wait name is the basename of the executable actually launched, not
        # a hardcoded constant: with two possible exe names and none confirmed,
        # observing "the thing we started" is the only honest question.
        exe_name = os.path.basename(gui)
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
            started = bool(self._system.wait_for_process(exe_name, POPEN_WAIT_S))
            observation_failed = False
        except Exception:
            # The spawn succeeded; only the observation broke.  Saying "not
            # started" here would be a lie about what happened to the machine.
            started, observation_failed = True, True

        attempts.append(LaunchAttempt(
            STRATEGY_POPEN_CLEAN_ENV, started=started, process_started=True,
            pid=pid, observation_failed=observation_failed,
            error_code=None if started else ErrorCode.LAUNCH_NO_PROCESS.value))
        return self._result(True, attempts)

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

        Same shape and same fail-closed rules as the other two providers': a
        system has to be supplied — passed here, or enabled by flipping
        :attr:`CONNECT_ENABLED` — or this answers ``unsupported``.  What runs is
        :class:`~vpn.providers.barracuda_connect.BarracudaConnectFlow`, which
        stops after the activation gate: the autofill exists
        (:meth:`autofill_login_password`, measured live in Stage 50C) but is
        deliberately not part of the flow, so an armed connect opens and
        verifies the client and then hands over to the user.

        ``entry`` is accepted and ignored — there is one route to this client,
        and the parameter exists only because the caller's contract has it.
        """
        if system is None:
            if not self.CONNECT_ENABLED:
                return unsupported(self.id, ConnectResult)
            system = self.connect_runtime()
        return BarracudaConnectFlow(self, system).run(request)

    def connect_runtime(self, **seams):
        """Build the real connect system (see :meth:`connect`).

        Every collaborator is injectable — ``window_api``, ``launch_system``,
        ``finder``, ``clock``, ``cancellation``, ``activation_observer``,
        ``trace`` — which is how the flow is exercised against a fake machine.
        """
        return BarracudaConnectRuntime(self, **seams)

    def diagnostics(self, request: VpnRequest | None = None) -> dict:
        """Machine facts only — no path of the user's, no credential."""
        detection = self.detect(request)
        return {"installed": detection.state is DetectionState.INSTALLED,
                "source": detection.source or "",
                "trusted_dirs": len(self.trusted_window_dirs()),
                "ui_contract_verified": UI_CONTRACT_VERIFIED}

    def __repr__(self) -> str:
        return f"<BarracudaProvider id={self.id!r}>"
