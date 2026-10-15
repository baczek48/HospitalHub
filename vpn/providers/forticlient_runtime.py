"""The real :class:`FortiConnectSystem` — the migrated components, wired up.

Stage 16 is an integration stage, and this module is where the integration
lives.  :class:`~vpn.providers.forticlient_connect.FortiConnectFlow` decides
*which* phases run in *what* order (that was settled in Stage 11 against the
legacy); this class performs each phase by calling the component that already
owns it:

======================  =====================================================
phase                   component
======================  =====================================================
``record_session``      an in-memory :class:`SessionLog` — deliberately **not**
                        the legacy ``_last_connected`` dict, so the two
                        systems cannot influence each other's status
``copy_to_clipboard``   ``InputSystem`` (Stage 14 seam)
``find_main_window``    ``SecureWindowTarget.first_verified_candidate`` — HWND
                        → PID → trusted image (Stage 13)
``restore_window``      ``SecureWindowTarget.acquire`` (restore + foreground +
                        confirm), released immediately
``start_autofill``      ``FortiClientProvider.autofill_login_password``
                        (Stage 14)
``await_activation``    ``ActivationGate`` — waits, read-only, for the user
                        to bring the client forward (Stage 22)
``activation_still``    ``SecureWindowTarget.foreground_check`` — one last
``_holds``              reading before the autofill, so an activation the user
                        has since revoked cannot be acted on (Stage 26)
``fill_auth_window``    **not migrated** — see the caveat below
``cli_supported``       provider detection + one ``--cli --status`` probe
``start_cli``           ``LaunchSystem.spawn_hidden`` /
                        ``spawn_monitored`` (Stage 16 additions)
``start_legacy_client`` ``LaunchSystem.spawn_hidden``
``supply_two_factor``   ``FortiClientProvider.supply_two_factor`` (Stage 15)
======================  =====================================================

There is nothing else here: no Win32, no ``subprocess``, no clipboard code, no
window search, no ``WM_SETTEXT``, no regexes.  Every one of those lives behind
a seam that already carries its own guard, which is exactly what makes a
security review of connect tractable — this file cannot send a secret anywhere
on its own.

What it does *not* do
---------------------
``fill_auth_window`` (the EMS **credentials** window — login + password by
``WM_SETTEXT``, legacy ``_fill_forti_auth_window``) was never migrated: Stage
15 moved the token out of that window, not the credentials.  Rather than
inventing a second, unreviewed path to a password, this system answers "no
such window" and the flow falls through to the CLI / legacy client / GUI
launch, exactly as it does on a machine where that window is not on screen.
Recorded as a caveat, not repaired here.
"""

from __future__ import annotations

from ..types import (
    AutofillResult, TwoFactorMode, TwoFactorResult, VpnRequest,
)
from .activation_gate import (
    ACTIVATION_TIMEOUT_S, CancellationToken, Clock, SystemClock,
)
from .forticlient_connect import AuthWindowFill, FortiConnectSystem
from .input_system import InputSystem, Win32InputSystem
from .launch_system import CLI_PROBE_TIMEOUT_S, LaunchSystem, WindowsLaunchSystem
from .process_channel import PopenProcessChannel

__all__ = ["FortiConnectRuntime", "SessionLog", "CLI_PROBE_ARGS",
           "CLI_UNSUPPORTED_MARKERS"]

#: ``_is_fortivpn_cli_supported``: the probe and the two phrases that mean "no".
CLI_PROBE_ARGS = ("--cli", "--status")
CLI_UNSUPPORTED_MARKERS = ("error parsing", "does not exist")


class SessionLog:
    """What connect last aimed at, per provider — the legacy ``_last_connected``.

    Its only consumer is a future migrated ``status()``; nothing reads it yet.
    Separate storage on purpose: writing into the legacy dict would make the
    two connects share state while both exist.
    """

    def __init__(self):
        self.profile_name: str = ""
        self.server: str = ""
        self.records: list[tuple[str, str]] = []

    def record(self, profile_name: str, server: str) -> None:
        self.profile_name, self.server = profile_name or "", server or ""
        self.records.append((self.profile_name, self.server))


class FortiConnectRuntime(FortiConnectSystem):
    """Performs the phases of a connect by delegating to migrated components.

    Every collaborator is injectable, so the whole of connect can be driven
    against a fake machine — that is how Stage 16 is tested, and why no test
    needs a real FortiClient.
    """

    def __init__(self, provider, *, launch_system: LaunchSystem | None = None,
                 input_system: InputSystem | None = None,
                 window_api=None, message_system=None,
                 session: SessionLog | None = None, trace=None,
                 clock: Clock | None = None,
                 cancellation: CancellationToken | None = None,
                 activation_timeout_s: float = ACTIVATION_TIMEOUT_S,
                 activation_observer=None, msaa_system=None):
        self._provider = provider
        #: The MSAA reader the profile step confirms the VPN Name combo with
        #: (Stage 63).  ``None`` = the real one, created only when a profile is
        #: actually chosen.
        self._msaa = msaa_system
        self._clock = clock
        #: Set this to call off a wait that is already running (Stage 22).
        self.cancellation = (cancellation if cancellation is not None
                             else CancellationToken())
        self.activation_timeout_s = activation_timeout_s
        #: Told every state the activation wait passes through, in the waiting
        #: thread (Stage 46).  It receives a state and nothing else — this is
        #: how a panel's worker learns what to show without polling the gate.
        self.activation_observer = activation_observer
        self._launch = launch_system if launch_system is not None else WindowsLaunchSystem()
        self._input = input_system if input_system is not None else Win32InputSystem()
        self._window_api = window_api
        self._messages = message_system
        self.session = session if session is not None else SessionLog()
        self._trace = trace
        self._cli_probe_cache: dict[str, bool] = {}

    # -- session ----------------------------------------------------------- #

    def record_session(self, profile_name: str, server: str) -> None:
        self.session.record(profile_name, server)

    # -- clipboard --------------------------------------------------------- #

    def copy_to_clipboard(self, text: str) -> bool:
        return bool(self._input.copy_to_clipboard(text))

    # -- the client's main window ------------------------------------------ #

    def find_main_window(self, timeout: float):
        """A *verified* FortiClient window, or None.

        The legacy polls for up to `timeout`; here one look is enough, because
        the caller's timeout (0.5 s) is the legacy's "is it already open?"
        question, not a wait for something to appear.  Finding is not sending:
        this returns a handle only the secure target may act on.
        """
        found = self._target().first_verified_candidate()
        return found[0] if found else None

    def restore_window(self, handle) -> None:
        """Bring the verified window forward.  **The flow no longer calls this.**

        Kept because the seam is part of the published contract and the legacy
        module still raises the window here; Stage 22 stopped asking for it,
        because a background process cannot take the foreground from another
        process' window and pretending otherwise hid the real condition.
        """
        acquired = self._target().acquire(handle)
        if not getattr(acquired, "ok", False):
            raise OSError(f"window-not-verified:{getattr(acquired, 'reason', '?')}")
        acquired.release()

    def await_activation(self):
        """Wait for the user to bring the client forward (Stage 22).

        Read-only throughout: the gate looks at the desktop and nothing else.
        The credentials never come near it, and its success is permission to
        start the autofill — not a promise that survives into it.
        """
        from .activation_gate import ActivationGate

        return ActivationGate(
            target=self._target(),
            clock=self._clock if self._clock is not None else SystemClock(),
            cancellation=self.cancellation,
            timeout_s=self.activation_timeout_s,
            observer=self.activation_observer,
            trace=self._trace).wait()

    def activation_still_holds(self, hwnd):
        """One more reading of the pinned window, with the gate's own criteria.

        Deliberately ``foreground_check`` and not ``confirm_target``: the two
        disagree about a minimised window (Stage 25 pinned that down), and the
        stricter of them is the one that matches what the gate promised the
        user.  Nothing is restored, raised, focused or typed here — this is the
        same read-only call the gate polls with.
        """
        return self._target().foreground_check(hwnd)

    def _target(self):
        return self._provider.secure_window_target(api=self._window_api)

    # -- form fill --------------------------------------------------------- #

    def start_autofill(self, login: str, password: str,
                       profile_name: str) -> AutofillResult:
        """Run the Stage-14 autofill and report what it achieved.

        Synchronous, unlike the legacy's background thread: the flow can then
        say whether the password was actually entered or a guard refused —
        information the legacy throws away.  See the caveat.
        """
        request = VpnRequest(provider_id=self._provider.id, login=login,
                             password=password, profile_name=profile_name)
        # The same token the gate waited on (Stage 47): a Cancel that arrives
        # after the activation stops the fill at its next operation.
        return self._provider.autofill_login_password(
            request, input_system=self._input,
            target=self._provider.secure_window_target(api=self._window_api),
            trace=self._trace, cancellation=self.cancellation, msaa=self._msaa)

    def cancel_requested(self) -> bool:
        """The flow asks this before each side effect (Stage 47)."""
        return bool(self.cancellation.cancelled)

    def fill_auth_window(self, login: str, password: str,
                         timeout: float) -> AuthWindowFill:
        """Fill the EMS credentials window (Stage 48).

        Delegates to :func:`submit_credentials_to_window`, which locates the
        window through the provider's :meth:`auth_window_target`, takes focus,
        and sends the login then the password through
        :meth:`VerifiedWindow.run_guarded` — the same verified path the token
        uses.  The shared :attr:`cancellation` is honoured before every send, so
        a Cancel between the login and the password stops before the password.
        Translates the rich result into the flow's :class:`AuthWindowFill`.
        """
        from .forticlient_auth_window import submit_credentials_to_window

        request = VpnRequest(provider_id=self._provider.id, login=login,
                             password=password)
        result = submit_credentials_to_window(
            self._provider, request,
            target=self._provider.auth_credentials_target(api=self._window_api),
            message_system=self._messages, api=self._window_api,
            cancellation=self.cancellation, timeout=timeout, trace=self._trace)
        return AuthWindowFill(
            found=result.located, submitted=result.submitted,
            blocked=result.blocked, cancelled=result.cancelled,
            error_code=result.error_code, reason=result.reason)

    # -- second factor ----------------------------------------------------- #

    def supply_two_factor(self, request: VpnRequest, mode: TwoFactorMode,
                          monitor) -> TwoFactorResult:
        channel = PopenProcessChannel(monitor) if monitor is not None else None
        return self._provider.supply_two_factor(
            request, mode=mode, channel=channel, api=self._window_api,
            message_system=self._messages, trace=self._trace)

    # -- command line ------------------------------------------------------ #

    def cli_supported(self, app_path: str) -> bool:
        """``_is_fortivpn_cli_supported``: never probe the free edition.

        The registry answer comes from the provider's own detection; only when
        it says "not the free edition" is ``FortiVPN.exe --cli --status``
        actually run, and the answer is cached per executable exactly as the
        legacy caches it.
        """
        fortivpn = self._provider._fortivpn_executable(app_path)
        if not fortivpn:
            return False
        if fortivpn in self._cli_probe_cache:
            return self._cli_probe_cache[fortivpn]
        if self._provider._free_edition():
            self._cli_probe_cache[fortivpn] = False
            return False
        _rc, output = self._launch.run_capture([fortivpn, *CLI_PROBE_ARGS],
                                               CLI_PROBE_TIMEOUT_S)
        low = (output or "").lower()
        supported = not any(marker in low for marker in CLI_UNSUPPORTED_MARKERS)
        self._cli_probe_cache[fortivpn] = supported
        return supported

    def start_cli(self, fortivpn: str, profile_name: str, login: str,
                  password: str, token: str, monitored: bool):
        cmd = [fortivpn, "--cli", "--connect", "--tunnel", profile_name]
        if login:
            cmd += ["--username", login]
        if password:
            cmd += ["--password", password]
        if token:
            cmd += ["--token", token]
        cmd.append("--savecredentials")
        if monitored:
            return self._launch.spawn_monitored(cmd)
        self._launch.spawn_hidden(cmd)
        return None

    def start_legacy_client(self, exe: str, address: str, login: str,
                            password: str) -> None:
        cmd = [exe, "connect", "-s", address, "-u", login]
        if password:
            cmd += ["-p", password]
        self._launch.spawn_hidden(cmd)
