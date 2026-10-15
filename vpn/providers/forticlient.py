"""FortiClient — detection and launch.

Migrated out of `vpn_connect.py` one responsibility at a time:

* :meth:`FortiClientProvider.detect` — *is FortiClient installed, where, and
  what can we safely say about it?*
* :meth:`FortiClientProvider.launch` — *start the client*, mirroring legacy
  ``_open_forticlient_gui`` strategy by strategy (see "Launch" below).

Connecting, autofill, 2FA and status stay in the legacy module and are
untouched.  The provider is registered in :data:`vpn.default_registry`, but
the running application does not call it: the UI still goes through
`vpn_connect.py` for every VPN operation.

Launch
------
The legacy sequence, with the same four fixes applied to the legacy itself in
stage 9 (both sides pinned by ``tests/test_vpn_forticlient_launch.py`` and
``tests/test_vpn_forticlient_launch_fixes.py``):

1. ``explorer_lnk`` — when the public-desktop ``FortiClient VPN.lnk`` exists,
   hand it to ``explorer.exe`` and wait up to 4 s for ``FortiClient.exe``.
   A spawn error or no process falls through.  ``app_path`` is not consulted
   in this stage.  On a machine whose ``.lnk`` association is hijacked,
   explorer opens the user's Documents folder instead — that is *not* fixed
   here; it shows up as ``started=False, error_code="launch-no-process"``.
2. ``popen_clean_env`` — locate the executable (the detection lookups), start
   it detached with a PyInstaller-free environment, wait up to 3 s.

   * ``cwd`` comes from :func:`launch_rules.choose_launch_cwd`: the install dir
     only if it is an existing directory, else the executable's directory.
   * ``fallback=True`` (and ``fallback_from="explorer_lnk"``) only when stage 1
     was actually tried and failed.
   * Spawn raised → ``process-start-failed``.  Spawned but the process probe
     raised → still a success, ``process_started=True``,
     ``observation_failed=True``, pid kept.
   * Spawned, probe fine but no process within 3 s → success with
     ``started=False`` (unchanged legacy behaviour).

Not fixed on purpose: the Documents folder, the 4 s / 3 s timeouts, a client
that explorer starts after the 4 s window (a second instance may follow), and
a probe raising right after explorer (legacy lets it escape; here it becomes
``launch-failed``).

System calls go through :class:`~vpn.providers.launch_system.LaunchSystem`;
detection never touches it.

Parity, not improvement
-----------------------
The goal of this stage is to match the existing behaviour exactly — including
the parts that are arguably wrong.  Two of those are preserved on purpose and
called out below, because "fixing" them here would make the parity tests lie
about what the application does today:

* :func:`_install_dir` returns the registry's ``INSTALLDIR`` **without
  checking that the directory exists**, and only falls back to the known paths
  when the registry read itself fails (legacy ``_forti_install_dir``,
  vpn_connect.py:162).
* :func:`_gui_executable` reads the same registry value but *does* fall
  through to the known paths when the resulting file is missing (legacy
  ``_find_forticlient_gui``, vpn_connect.py:233).  So the two functions answer
  the same question differently.

What is deliberately **not** here
---------------------------------
* **Version.** The legacy code never reads a FortiClient version — not from
  the registry, not from the file. Inventing one here would be a new feature
  wearing a migration's clothes.
* **The CLI probe.** ``_is_fortivpn_cli_supported`` decides whether the EMS
  CLI exists by *running* ``FortiVPN.exe --cli --status``. Detection must not
  start processes, so this provider reports only whether ``FortiVPN.exe``
  is present on disk and leaves the probe where it is.
* **Tunnel import.** ``get_forti_tunnels_from_registry`` is a separate
  capability (``PROFILE_IMPORT``) and tunnel names identify hospitals; it
  migrates on its own terms, later.
* **HKCU, the 32-bit registry view and PATH.** The legacy code uses none of
  them — every read is ``HKEY_LOCAL_MACHINE`` in the default view.

Everything the environment touches goes through :class:`DetectionEnvironment`,
so tests can describe a machine (registry + filesystem) without a real one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from diagnostics.redactor import allow_keys
from launch_rules import choose_launch_cwd

from ..catalog import FORTICLIENT as FORTICLIENT_SPEC
from ..provider import VpnProvider
from ..types import (
    Capability, ConnectResult, DetectionResult, DetectionState, ErrorCode,
    LaunchAttempt, LaunchResult, TwoFactorMode, VpnRequest, unsupported,
)
from .forticlient_connect import (
    ENTRY_CONNECT_MONITORED, FortiConnectFlow, FortiConnectSystem,
)
from .launch_system import LaunchSystem, WindowsLaunchSystem
from .secure_target import SecureWindowTarget
from secure_window import (
    WindowApi, WindowCandidateFinder, Win32TitleWindowFinder, trusted_install_dirs,
)

#: Substrings a window title must contain / must not contain to be a
#: FortiClient main-window *candidate*.  A candidate is nothing until
#: SecureWindowTarget verifies its owner process; the title is never trusted.
WINDOW_TITLE_MUST_CONTAIN = "FortiClient"
WINDOW_TITLE_MUST_NOT_CONTAIN = "Authentication"

#: ...and the other window: the EMS edition's WinForms authentication dialog,
#: whose title carries both words (legacy ``_find_forti_auth_window``).  It is
#: a separate target because it is a separate window with separate controls.
AUTH_WINDOW_TITLE_MUST_CONTAIN = ("FortiClient", "Authentication")

__all__ = ["FortiClientProvider", "DetectionEnvironment", "WindowsEnvironment"]

# --------------------------------------------------------------------------- #
# Constants — mirrored from vpn_connect.py; a test asserts they stay identical #
# --------------------------------------------------------------------------- #

#: HKLM key whose mere existence the legacy `is_forticlient_installed` uses.
REGISTRY_KEY = r"SOFTWARE\Fortinet\FortiClient"
#: Value under REGISTRY_KEY holding the installation directory.
INSTALL_DIR_VALUE = "INSTALLDIR"
#: Subkey + value the legacy edition check reads first.
FA_FCM_KEY = r"SOFTWARE\Fortinet\FortiClient\FA_FCM"
FA_FCM_VALUE = "installed"
#: Where the legacy edition check looks second.
UNINSTALL_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
#: DisplayName values that mean "free / VPN-only edition" (exact match, lower).
FREE_EDITION_NAMES = ("forticlient vpn", "forticlient free")

GUI_PATHS = (
    r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe",
    r"C:\Program Files (x86)\Fortinet\FortiClient\FortiClient.exe",
)
FORTIVPN_PATHS = (
    r"C:\Program Files\Fortinet\FortiClient\FortiVPN.exe",
    r"C:\Program Files (x86)\Fortinet\FortiClient\FortiVPN.exe",
)
SSLVPN_CLIENT_PATHS = (
    r"C:\Program Files\Fortinet\FortiClient\FortiSSLVPNclient.exe",
    r"C:\Program Files (x86)\Fortinet\FortiClient\FortiSSLVPNclient.exe",
)
INSTALL_DIRS = (
    r"C:\Program Files\Fortinet\FortiClient",
    r"C:\Program Files (x86)\Fortinet\FortiClient",
)
LNK_PATH = r"C:\Users\Public\Desktop\FortiClient VPN.lnk"

GUI_EXE_NAME = "FortiClient.exe"
FORTIVPN_EXE_NAME = "FortiVPN.exe"

#: Where the executable was found. Reported so a diagnostics package can say
#: "we used the registry" rather than just "we found it".
SOURCE_APP_PATH = "app_path"
SOURCE_REGISTRY = "registry"
SOURCE_KNOWN_PATHS = "known_paths"

#: Launch strategies — the exact names the legacy writes into its traces.
STRATEGY_EXPLORER_LNK = "explorer_lnk"
STRATEGY_POPEN_CLEAN_ENV = "popen_clean_env"
#: ``_wait_for_process("FortiClient.exe", timeout=...)`` after each strategy.
EXPLORER_WAIT_S = 4.0
POPEN_WAIT_S = 3.0

# Metadata keys this provider emits (declared next to the code that produces
# them, as the diagnostics allowlist requires).
allow_keys("free_edition", "registry_present", "sslvpn_client_present",
           "fortivpn_present")


# --------------------------------------------------------------------------- #
# Environment seam                                                             #
# --------------------------------------------------------------------------- #

class DetectionEnvironment:
    """Everything detection is allowed to touch: the registry and the disk.

    No processes, no windows, no waiting — a detection run must be cheap and
    repeatable. Tests substitute this with a description of a machine.
    """

    def registry_value(self, subkey: str, name: str) -> Any | None:
        """HKLM value, or None when the key/value is unavailable."""
        raise NotImplementedError

    def registry_key_exists(self, subkey: str) -> bool:
        raise NotImplementedError

    def registry_subkeys(self, subkey: str) -> list[str]:
        """Subkey names, or an empty list when the key cannot be read."""
        raise NotImplementedError

    def is_file(self, path: str) -> bool:
        raise NotImplementedError

    def is_dir(self, path: str) -> bool:
        raise NotImplementedError


class WindowsEnvironment(DetectionEnvironment):
    """The real machine — the same APIs and the same views the legacy uses."""

    def registry_value(self, subkey: str, name: str) -> Any | None:
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey)
        except OSError:
            return None
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None
        finally:
            winreg.CloseKey(key)

    def registry_key_exists(self, subkey: str) -> bool:
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey)
        except OSError:
            return False
        winreg.CloseKey(key)
        return True

    def registry_subkeys(self, subkey: str) -> list[str]:
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey)
        except OSError:
            return []
        names: list[str] = []
        try:
            index = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, index))
                except OSError:
                    break
                index += 1
        finally:
            winreg.CloseKey(key)
        return names

    def is_file(self, path: str) -> bool:
        return bool(path) and os.path.isfile(path)

    def is_dir(self, path: str) -> bool:
        return bool(path) and os.path.isdir(path)


# --------------------------------------------------------------------------- #
# Provider                                                                     #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Findings:
    """Raw answers before they are turned into a result."""

    gui_path: str | None = None
    gui_source: str | None = None
    install_dir: Any = None             # raw registry value, like the legacy
    registry_present: bool = False
    free_edition: bool = False
    lnk_present: bool = False
    sslvpn_client: str | None = None
    fortivpn: str | None = None


class FortiClientProvider(VpnProvider):
    """FortiClient, migrated as far as detection and no further."""

    id = "forticlient"
    display_name = FORTICLIENT_SPEC.display_name
    legacy_name = FORTICLIENT_SPEC.legacy_name

    #: What the client can do in principle (see `vpn.catalog`). Not what this
    #: class implements — that is :meth:`capabilities`.
    spec = FORTICLIENT_SPEC

    def __init__(self, environment: DetectionEnvironment | None = None,
                 system: LaunchSystem | None = None,
                 connect_system: FortiConnectSystem | None = None):
        # Both constructors are free of I/O — safe for registration at import.
        self._env = environment or WindowsEnvironment()
        self._system = system if system is not None else WindowsLaunchSystem()
        # No default on purpose: without an injected connect system the flow
        # never runs (see connect()), so the registered provider cannot touch
        # windows, the clipboard or FortiVPN.exe.
        self._connect_system = connect_system

    #: Stage 16: the migrated connect is complete, and switched off.  Turning
    #: this on makes :meth:`connect` build a real runtime for a provider that
    #: was constructed without one — i.e. it makes the registered provider able
    #: to start FortiClient and type into it.  That is the production switch
    #: and is not this stage's to flip.
    CONNECT_ENABLED = False

    def capabilities(self) -> Capability:
        """What **this implementation** can do today.

        Detection is mandatory in the contract and has no flag; launching is
        the one further operation migrated so far.  Connect, disconnect and
        status still belong to the legacy module and answer `unsupported`
        here.  The full picture of what the client can do lives in
        :attr:`spec`.
        """
        return Capability.LAUNCH

    # -- detection --------------------------------------------------------- #

    def detect(self, request: VpnRequest | None = None) -> DetectionResult:
        app_path = request.app_path if request is not None else ""
        try:
            findings = self._gather(app_path)
        except Exception as exc:                    # environment misbehaving
            return DetectionResult(
                provider_id=self.id, success=False, state=DetectionState.ERROR,
                error_code=ErrorCode.DETECTION_FAILED.value,
                metadata={"reason_code": type(exc).__name__},
            )

        if findings.gui_path:
            state = DetectionState.INSTALLED
        elif findings.registry_present:
            # The registry says it is installed but we cannot point at the
            # executable — the same dead end the legacy launch path hits.
            state = DetectionState.INCOMPLETE
        else:
            state = DetectionState.NOT_INSTALLED

        return DetectionResult(
            provider_id=self.id,
            success=state is DetectionState.INSTALLED,
            state=state,
            # No version: the legacy code never reads one (see module docstring).
            version=None,
            edition="free" if findings.free_edition else None,
            path=findings.gui_path,
            source=findings.gui_source,
            error_code=None if state is DetectionState.INSTALLED
            else ErrorCode.CLIENT_NOT_FOUND.value,
            metadata={
                "install_dir": ("" if findings.install_dir is None
                                else str(findings.install_dir)),
                "registry_present": findings.registry_present,
                "free_edition": findings.free_edition,
                "lnk_present": findings.lnk_present,
                "sslvpn_client_present": bool(findings.sslvpn_client),
                "fortivpn_present": bool(findings.fortivpn),
            },
        )

    # -- connect (prepared, not migrated) ------------------------------------ #

    def connect(self, request: VpnRequest,
                entry: str = ENTRY_CONNECT_MONITORED, *,
                system=None) -> ConnectResult:
        """The whole connect, over the migrated components (Stage 16).

        The orchestration is :class:`FortiConnectFlow` (the legacy phase order,
        established in Stage 11); the work of each phase is done by
        :class:`~vpn.providers.forticlient_runtime.FortiConnectRuntime`, which
        calls detection, launch, the secure target, the autofill and the 2FA
        component.  `entry` selects which legacy entry point's order is
        followed (``connect_monitored`` is what the UI calls).

        **Deliberately not armed.**  A system has to be supplied — injected at
        construction, passed here, or enabled by flipping
        :attr:`CONNECT_ENABLED` — or this answers ``unsupported`` exactly as it
        did before.  The registered provider has none, so a stray call on it
        cannot start a client, type a password or touch the clipboard; the
        production path is still `vpn_connect.py`, and arming this is the
        separate, deliberate decision that switches it over.
        """
        system = system if system is not None else self._connect_system
        if system is None:
            if not self.CONNECT_ENABLED:
                return unsupported(self.id, ConnectResult)
            system = self.connect_runtime()
        return FortiConnectFlow(self, system).run(request, entry)

    def connect_runtime(self, **seams):
        """Build the real connect system (see :meth:`connect`).

        Every collaborator is injectable — `launch_system`, `input_system`,
        `window_api`, `message_system`, `session`, `trace` — which is how the
        whole of connect is exercised against a fake machine.
        """
        from .forticlient_runtime import FortiConnectRuntime
        return FortiConnectRuntime(self, **seams)

    def answer_two_factor_challenge(self, request: VpnRequest, monitor, *,
                                    api=None, trace=None):
        """Wait for a monitored client to ask for a token, then answer it.

        The contract for :attr:`ConnectResult.monitor`, and deliberately *not*
        part of ``connect()``: reading a pipe until the client prompts blocks
        for as long as the client takes, which is why the legacy does it in a
        UI thread.  Connect hands the monitor out; whoever owns a thread calls
        this.  Returns ``None`` when no challenge ever came.
        """
        from .forticlient_2fa import supply_token, watch_for_challenge
        from .process_channel import PopenProcessChannel

        channel = PopenProcessChannel(monitor)
        watch = watch_for_challenge(channel, trace=trace)
        if not watch.detected:
            return None
        return supply_token(self, request, mode=TwoFactorMode.PROCESS_STDOUT,
                            channel=channel, api=api, trace=trace)

    def _sslvpn_client_executable(self) -> str | None:
        """Mirrors legacy ``find_executable("FortiClient")``."""
        return self._first_existing(SSLVPN_CLIENT_PATHS)

    # -- secure target (Stage 13) ------------------------------------------ #

    def trusted_window_dirs(self) -> tuple[str, ...]:
        """FortiClient install directories a window's process must live in to
        be allowed to receive a secret later — from this provider's own
        detection (registry ``INSTALLDIR`` only when under Program Files)."""
        return trusted_install_dirs(self._install_dir(), self._env.is_dir)

    def secure_window_target(self, api: WindowApi | None = None,
                             finder: WindowCandidateFinder | None = None
                             ) -> SecureWindowTarget:
        """A secret-free contract for confirming a FortiClient window and
        taking focus, for a future ``connect()`` to build its autofill on.

        This does **not** send anything: it verifies and hands back a
        :class:`~vpn.providers.secure_target.VerifiedWindow` whose only
        interaction method re-confirms the target and runs a caller-supplied
        callback.  No login, password or token passes through it.

        ``require_visible`` is on here and nowhere else: this is the window the
        autofill types into, and its guards must ask the same question the
        activation gate asked — in front **and** not minimised.  Without it a
        client the user minimised mid-sequence still satisfied every guard
        (Stage 25).  The EMS authentication target is deliberately left alone:
        it is a different path, filled by ``WM_SETTEXT`` rather than
        keystrokes, and changing it was not part of the Stage 28 analysis.
        """
        return SecureWindowTarget(
            self.trusted_window_dirs(), api=api, require_visible=True,
            raise_window=False,
            finder=finder if finder is not None else Win32TitleWindowFinder(
                WINDOW_TITLE_MUST_CONTAIN, WINDOW_TITLE_MUST_NOT_CONTAIN))

    def auth_window_target(self, api: WindowApi | None = None,
                           finder: WindowCandidateFinder | None = None
                           ) -> SecureWindowTarget:
        """The same secret-free contract, aimed at the EMS authentication
        window instead of the main one (Stage 15).

        Separate from :meth:`secure_window_target` on purpose: the main window
        target explicitly *excludes* "Authentication" titles, and a token must
        never be typed into the main window's login form by accident.
        """
        return SecureWindowTarget(
            self.trusted_window_dirs(), api=api,
            finder=finder if finder is not None else Win32TitleWindowFinder(
                AUTH_WINDOW_TITLE_MUST_CONTAIN))

    def auth_credentials_target(self, api: WindowApi | None = None,
                                finder: WindowCandidateFinder | None = None
                                ) -> SecureWindowTarget:
        """The EMS authentication window, for the **login + password** fill
        (Stage 48).

        Same window and same title candidates as :meth:`auth_window_target`,
        but with the main-window contract rather than the token one:
        ``require_visible=True`` and ``raise_window=False``.  The credentials
        fill types the two most sensitive fields of the connect, so it asks the
        same question the main-window autofill asks — the window must be in
        front **and** not minimised, and this side never raises or activates it
        to make that true.  Kept separate from :meth:`auth_window_target` so the
        token path (Stage 15), which may raise the dialog, is left exactly as it
        was.
        """
        return SecureWindowTarget(
            self.trusted_window_dirs(), api=api, require_visible=True,
            raise_window=False,
            finder=finder if finder is not None else Win32TitleWindowFinder(
                AUTH_WINDOW_TITLE_MUST_CONTAIN))

    def two_factor_mode(self, request, *, route=None, monitor_available=False,
                        trace=None):
        """How a second factor could be supplied after this connect (Stage 15)."""
        from .forticlient_2fa import two_factor_mode
        return two_factor_mode(request, route=route,
                               monitor_available=monitor_available, trace=trace)

    def supply_two_factor(self, request, *, mode=None, channel=None, target=None,
                          message_system=None, api=None, trace=None):
        """Deliver the second factor the way this connect allows (Stage 15).

        Prepared for a future ``connect()`` and **not wired to production** —
        the running application still fills the token through the legacy
        ``fill_forticlient_token`` / stdout monitor.  The token goes only to a
        verified, focused FortiClient authentication window, or to the stdin of
        a verified FortiClient process; every other outcome sends nothing.
        """
        from .forticlient_2fa import supply_token
        return supply_token(self, request, mode=mode, channel=channel,
                            target=target, message_system=message_system,
                            api=api, trace=trace)

    def autofill_login_password(self, request, *, target=None,
                                input_system=None, trace=None,
                                cancellation=None, msaa=None, tunnels=None):
        """Enter login + password into the FortiClient window (Stage 14).

        Prepared for a future ``connect()`` and **not wired to production** —
        the running application still autofills through the legacy module.
        Every secret goes through the Stage-13 guard; nothing is sent to a
        window that is not a verified, focused FortiClient window.  2FA is not
        handled here.
        """
        from .forticlient_autofill import autofill_login_password
        return autofill_login_password(self, request, target=target,
                                       input_system=input_system, trace=trace,
                                       cancellation=cancellation, msaa=msaa,
                                       tunnels=tunnels)

    def configured_tunnels(self):
        """Tunnel names from the registry, per kind — key names only.

        What the profile step checks a requested and a displayed profile
        against (Stage 63).  Read through the provider's environment, so a test
        describes the machine instead of having one.
        """
        from .forticlient_profile import configured_tunnels
        return configured_tunnels(self._env)

    # -- launch ------------------------------------------------------------ #

    def launch(self, request: VpnRequest | None = None) -> LaunchResult:
        """Start FortiClient — mirrors legacy ``_open_forticlient_gui``.

        Never raises.  The one place the legacy lets an exception escape (the
        process wait after ``explorer.exe`` sits outside its ``try``) comes
        back here as ``launch-failed`` with the exception type as
        ``reason_code``.
        """
        app_path = request.app_path if request is not None else ""
        attempts: list[LaunchAttempt] = []
        try:
            return self._launch(app_path or "", attempts)
        except Exception as exc:
            return self._launch_result(False, attempts, ErrorCode.LAUNCH_FAILED,
                                       reason_code=type(exc).__name__)

    def _launch(self, app_path: str, attempts: list[LaunchAttempt]) -> LaunchResult:
        # Stage 1 — explorer.exe <public .lnk> (vpn_connect.py:1402).
        if self._env.is_file(LNK_PATH) and self._valid_exe(LNK_PATH):
            try:
                self._system.open_with_explorer(LNK_PATH)
            except Exception as exc:
                attempts.append(LaunchAttempt(
                    STRATEGY_EXPLORER_LNK, started=False, process_started=False,
                    error_code=ErrorCode.LAUNCH_FAILED.value,
                    reason_code=type(exc).__name__))
            else:
                # Legacy: outside the try — an exception here escapes (not
                # fixed in stage 9); launch() turns it into launch-failed.
                started = bool(self._system.wait_for_process(GUI_EXE_NAME,
                                                             EXPLORER_WAIT_S))
                attempts.append(LaunchAttempt(
                    STRATEGY_EXPLORER_LNK, started=started, process_started=True,
                    error_code=None if started
                    else ErrorCode.LAUNCH_NO_PROCESS.value))
                if started:
                    return self._launch_result(True, attempts)
                # No process: hijacked .lnk association ("opens Documents").

        # Stage 2 — direct executable, clean env, detached (vpn_connect.py:1438).
        gui, _source = self._gui_executable(app_path)
        install_dir = self._install_dir()
        if not gui:
            return self._launch_result(False, attempts, ErrorCode.CLIENT_NOT_FOUND)
        if not self._valid_exe(gui):
            return self._launch_result(False, attempts, ErrorCode.LAUNCH_FAILED,
                                       reason_code="invalid-executable")
        # Fix A (with the legacy): only an existing directory becomes cwd.
        cwd, cwd_source = choose_launch_cwd(install_dir, gui, self._env.is_dir)
        # Fix D: a fallback only after an attempt that actually failed.
        fallback_from = attempts[-1].strategy if attempts else None
        common = {"fallback": fallback_from is not None,
                  "fallback_from": fallback_from, "cwd_source": cwd_source}
        try:
            pid = self._system.spawn_detached(gui, cwd)
        except Exception as exc:
            # No process was created: a genuine launch failure.
            attempts.append(LaunchAttempt(
                STRATEGY_POPEN_CLEAN_ENV, started=False, process_started=False,
                error_code=ErrorCode.PROCESS_START_FAILED.value,
                reason_code=type(exc).__name__, **common))
            return self._launch_result(False, attempts,
                                       ErrorCode.PROCESS_START_FAILED)
        try:
            started = bool(self._system.wait_for_process(GUI_EXE_NAME, POPEN_WAIT_S))
        except Exception as exc:
            # Fix B: the process exists (pid); only observing it failed.
            attempts.append(LaunchAttempt(
                STRATEGY_POPEN_CLEAN_ENV, started=None, pid=pid,
                process_started=True, observation_failed=True,
                error_code=ErrorCode.PROCESS_OBSERVATION_FAILED.value,
                reason_code=type(exc).__name__, **common))
            return self._launch_result(True, attempts)
        # Unchanged legacy behaviour: success even when no process was seen.
        attempts.append(LaunchAttempt(STRATEGY_POPEN_CLEAN_ENV, started=started,
                                      pid=pid, process_started=True, **common))
        return self._launch_result(True, attempts)

    def _valid_exe(self, path: str) -> bool:
        """Mirrors legacy ``_validate_exe``: exists, not a directory, a file."""
        return bool(path) and self._env.is_file(path)

    def _launch_result(self, success: bool, attempts: list[LaunchAttempt],
                       error_code: ErrorCode | None = None,
                       reason_code: str | None = None) -> LaunchResult:
        last = attempts[-1] if attempts else None
        return LaunchResult(
            provider_id=self.id,
            success=success,
            error_code=None if success or error_code is None else error_code.value,
            strategy=last.strategy if last else None,
            started=last.started if last else None,
            pid=last.pid if last else None,
            fallback=last.fallback if last else False,
            process_started=last.process_started if last else None,
            observation_failed=last.observation_failed if last else False,
            # Legacy success message: "połącz się w oknie klienta" — launching
            # only opens the window, logging in is still up to the user.
            requires_user_action=success,
            attempts=tuple(attempts),
            metadata={"reason_code": reason_code} if reason_code else {},
        )

    # -- the individual lookups, each mirroring one legacy function --------- #

    def _gather(self, app_path: str) -> _Findings:
        gui_path, gui_source = self._gui_executable(app_path)
        return _Findings(
            gui_path=gui_path,
            gui_source=gui_source,
            install_dir=self._install_dir(),
            registry_present=self._env.registry_key_exists(REGISTRY_KEY),
            free_edition=self._free_edition(),
            lnk_present=self._env.is_file(LNK_PATH),
            sslvpn_client=self._first_existing(SSLVPN_CLIENT_PATHS),
            fortivpn=self._fortivpn_executable(app_path),
        )

    def _install_dir(self) -> Any:
        """Mirrors legacy ``_forti_install_dir`` (vpn_connect.py:162).

        Note the preserved quirk: a value read from the registry is returned
        as-is, even if no such directory exists, and the known-path fallback is
        reached only when the registry read fails.
        """
        value = self._env.registry_value(REGISTRY_KEY, INSTALL_DIR_VALUE)
        if value is not None:
            # As-is, like the legacy: an empty string or a non-text value is
            # "a successful read" and never reaches the known-path fallback.
            return value
        for directory in INSTALL_DIRS:
            if self._env.is_dir(directory):
                return directory
        return None

    def _gui_executable(self, app_path: str = "") -> tuple[str | None, str | None]:
        """Mirrors legacy ``_find_forticlient_gui`` (vpn_connect.py:233)."""
        if app_path and self._env.is_file(app_path):
            return app_path, SOURCE_APP_PATH

        value = self._env.registry_value(REGISTRY_KEY, INSTALL_DIR_VALUE)
        # Legacy joins whatever the registry returned: a non-text value makes
        # os.path.join raise (swallowed -> known paths), while an empty string
        # yields a bare "FortiClient.exe", i.e. a lookup relative to the
        # current working directory. Both preserved.
        if isinstance(value, str):
            candidate = os.path.join(value, GUI_EXE_NAME)
            if self._env.is_file(candidate):
                return candidate, SOURCE_REGISTRY

        found = self._first_existing(GUI_PATHS)
        return (found, SOURCE_KNOWN_PATHS) if found else (None, None)

    def _fortivpn_executable(self, app_path: str = "") -> str | None:
        """Mirrors legacy ``_find_fortivpn`` (vpn_connect.py:223) — path only.

        Whether that executable supports ``--cli`` is a separate question the
        legacy answers by running it; detection does not run anything.
        """
        if app_path:
            candidate = os.path.join(os.path.dirname(app_path), FORTIVPN_EXE_NAME)
            if self._env.is_file(candidate):
                return candidate
        return self._first_existing(FORTIVPN_PATHS)

    def _free_edition(self) -> bool:
        """Mirrors legacy ``_is_forti_free_edition`` (vpn_connect.py:310).

        Registry only — no executable is started. The second stage walks the
        uninstall list and accepts only an exact DisplayName match, which is
        why a localised or renamed package reads as "not free".
        """
        installed = self._env.registry_value(FA_FCM_KEY, FA_FCM_VALUE)
        if installed == 0:
            return True
        for subkey in self._env.registry_subkeys(UNINSTALL_KEY):
            display_name = self._env.registry_value(
                f"{UNINSTALL_KEY}\\{subkey}", "DisplayName")
            if display_name is None:            # value missing -> skipped
                continue
            # No type check on purpose: the legacy calls .lower() on whatever
            # the registry returned, so a non-text DisplayName anywhere in the
            # uninstall list raises out of the whole check. detect() turns that
            # into DetectionState.ERROR; the legacy lets it propagate.
            if "forticlient" not in display_name.lower():
                continue
            if display_name.strip().lower() in FREE_EDITION_NAMES:
                return True
        return False

    def _first_existing(self, paths) -> str | None:
        for path in paths:
            if self._env.is_file(path):
                return path
        return None
