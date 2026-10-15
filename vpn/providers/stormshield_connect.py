"""Stormshield connect — the skeleton, up to the moment the user is ready.

Five phases and then a deliberate stop::

    detect → launch → window_probe → await_activation → activation_still_holds

Nothing follows, because the next thing would be a keystroke and the autofill
is not migrated yet.  The flow ends by saying so: ``requires_user_action=True``
with ``AutomationMode.MANUAL``, which is the honest description of a client
that is open, verified, and waiting for a person to type into it.

Why a separate flow rather than FortiClient's
---------------------------------------------
``FortiConnectFlow`` is a faithful record of one legacy function, branches and
all: fast-path window, EMS authentication window, CLI, the legacy SSL client,
GUI launch, two entry points, second factor.  Stormshield has none of that —
one client, one window, one way in.  Reusing that flow would mean carrying six
dead branches and then explaining, in every test, why they are dead.

What *is* reused is everything that decides whether an operation is safe: the
activation gate, ``SecureWindowTarget``, ``strict_foreground_check`` and the
``require_visible`` / ``raise_window`` contract.  None of it is re-implemented
here, and none of it knows which provider is asking.

Not here, on purpose
--------------------
No tray click, no ``SW_RESTORE``, no ``SetForegroundWindow``, no
``SetWindowPos``.  The flow launches the client and then *waits* — if the
window never comes forward, that is an outcome to report, not a problem to
solve by reaching into somebody else's window.
"""

from __future__ import annotations

from typing import Any

from ..types import (
    AutomationMode, ConnectResult, ConnectStep, DetectionState, ErrorCode,
    VpnRequest, VpnState,
)
from .activation_gate import (
    ACTIVATION_TIMEOUT_S, CancellationToken, Clock, SystemClock,
)

__all__ = ["StormshieldConnectFlow", "StormshieldConnectSystem",
           "StormshieldConnectRuntime",
           "PHASE_DETECT", "PHASE_LAUNCH", "PHASE_WINDOW_PROBE",
           "PHASE_AWAIT_ACTIVATION", "ROUTE_GUI"]

PHASE_DETECT = "detect"
PHASE_LAUNCH = "launch"
PHASE_WINDOW_PROBE = "window_probe"
PHASE_AWAIT_ACTIVATION = "await_activation"

STEP_OK = "ok"
STEP_FAILED = "failed"
STEP_NONE = "none"

#: Only one route exists for this client.
ROUTE_GUI = "gui"


class StormshieldConnectSystem:
    """What the flow is allowed to do to the machine.

    Every method answers "nothing happened" by default, so a system that has
    not been wired up cannot start a client or touch a window — the same
    fail-inert shape ``FortiConnectSystem`` uses, and the reason the registered
    provider is harmless.
    """

    def detect(self, request: VpnRequest) -> Any:
        return None

    def launch(self, request: VpnRequest) -> Any:
        return None

    def find_main_window(self, timeout: float) -> Any:
        """A *verified* client window, or None.  Finding is not sending."""
        return None

    def await_activation(self) -> Any:
        """Wait, read-only, for the user to bring the client forward."""
        return None

    def activation_still_holds(self, hwnd) -> Any:
        """Does the observed activation still hold?  Read-only; None = unknown."""
        return None


class StormshieldConnectRuntime(StormshieldConnectSystem):
    """The real system: provider detection/launch + secure target + gate.

    The counterpart of :class:`~vpn.providers.barracuda_connect.BarracudaConnectRuntime`,
    and deliberately its twin: the same five read-only capabilities, the same
    injected seams, the same activation gate carrying the caller's
    :class:`CancellationToken`.  Written now because the panel's V2 session
    builds a provider's runtime by name (Stage 54) — until this existed,
    Stormshield had a flow and no way for the session to run it.

    No autofill method, on purpose.  Stormshield *has* a migrated autofill
    (:mod:`vpn.providers.stormshield_autofill`), but the flow stops before
    typing, so the system it runs on is given nothing that could type.
    """

    def __init__(self, provider, *, window_api=None, launch_system=None,
                 finder=None, clock: Clock | None = None,
                 cancellation: CancellationToken | None = None,
                 activation_timeout_s: float = ACTIVATION_TIMEOUT_S,
                 activation_observer=None, trace=None):
        self._provider = provider
        self._window_api = window_api
        self._launch_system = launch_system
        #: Injected only in tests; production uses the provider's own title
        #: finder.  Read-only either way.
        self._finder = finder
        self._clock = clock
        self.cancellation = (cancellation if cancellation is not None
                             else CancellationToken())
        self.activation_timeout_s = activation_timeout_s
        self.activation_observer = activation_observer
        self._trace = trace

    def _target(self):
        return self._provider.secure_window_target(api=self._window_api,
                                                   finder=self._finder)

    def detect(self, request: VpnRequest):
        return self._provider.detect(request)

    def launch(self, request: VpnRequest):
        return self._provider.launch(request)

    def find_main_window(self, timeout: float):
        found = self._target().first_verified_candidate()
        return found[0] if found else None

    def await_activation(self):
        from .activation_gate import ActivationGate

        return ActivationGate(
            target=self._target(),
            clock=self._clock if self._clock is not None else SystemClock(),
            cancellation=self.cancellation,
            timeout_s=self.activation_timeout_s,
            observer=self.activation_observer,
            trace=self._trace).wait()

    def activation_still_holds(self, hwnd):
        """One more strict reading before anything could reach for the window.

        Read-only — foreground, verified owner, not minimised.  Nothing is
        restored, raised or focused; the client stays where the user put it.
        """
        return self._target().foreground_check(hwnd)


class StormshieldConnectFlow:
    """The phase order, and nothing else.

    Holds no Win32, no timing and no knowledge of how a window is verified; it
    decides *which* phase runs next and records what each one answered.
    """

    def __init__(self, provider, system: StormshieldConnectSystem):
        self._provider = provider
        self._system = system

    def run(self, request: VpnRequest) -> ConnectResult:
        steps: list[ConnectStep] = []

        # -- detect --------------------------------------------------------- #
        detection = self._system.detect(request)
        state = getattr(detection, "state", None)
        installed = state in (DetectionState.INSTALLED, DetectionState.INCOMPLETE)
        steps.append(ConnectStep(PHASE_DETECT, STEP_OK if installed else STEP_FAILED,
                                 None if installed else ErrorCode.CLIENT_NOT_FOUND.value,
                                 state.value if state is not None else None))
        if not installed:
            return self._failure(steps, ErrorCode.CLIENT_NOT_FOUND)

        # -- launch --------------------------------------------------------- #
        launch = self._system.launch(request)
        launched = bool(getattr(launch, "success", False))
        steps.append(ConnectStep(PHASE_LAUNCH, STEP_OK if launched else STEP_FAILED,
                                 None if launched else getattr(launch, "error_code",
                                                               ErrorCode.LAUNCH_FAILED.value)))
        if not launched:
            return self._failure(steps, ErrorCode.LAUNCH_FAILED, launch=launch)

        # -- window probe --------------------------------------------------- #
        handle = self._system.find_main_window(0.5)
        steps.append(ConnectStep(PHASE_WINDOW_PROBE,
                                 STEP_OK if handle else STEP_NONE))

        # -- activation ----------------------------------------------------- #
        # The window is not raised here and never will be: the user brings it
        # forward, the gate watches, and the flow believes the desktop.
        activation = self._system.await_activation()
        if activation is not None:
            ok = bool(getattr(activation, "ok", False))
            state_value = getattr(getattr(activation, "state", None), "value", None)
            steps.append(ConnectStep(
                PHASE_AWAIT_ACTIVATION, STEP_OK if ok else STEP_FAILED,
                None if ok else ErrorCode.FOCUS_FAILED.value, state_value))
            if not ok:
                return self._user_action(steps, launch,
                                         ErrorCode.FOCUS_FAILED.value)

            # One more reading before anything could reach for the window.
            still = self._system.activation_still_holds(
                getattr(activation, "hwnd", None))
            if still is not None and not getattr(still, "ok", False):
                steps.append(ConnectStep(PHASE_AWAIT_ACTIVATION, STEP_FAILED,
                                         ErrorCode.FOCUS_FAILED.value,
                                         getattr(still, "reason", None)))
                return self._user_action(steps, launch,
                                         ErrorCode.FOCUS_FAILED.value)

        # -- and stop ------------------------------------------------------- #
        # The autofill is the next stage.  Until it exists, the client is open
        # and verified and the person in front of it does the typing.
        return self._user_action(steps, launch)

    # -- results ------------------------------------------------------------ #

    def _user_action(self, steps, launch=None, error_code=None) -> ConnectResult:
        return ConnectResult(
            provider_id=self._provider.id, success=True,
            state=VpnState.UNKNOWN, automation=AutomationMode.MANUAL,
            requires_user_action=True, route=ROUTE_GUI,
            steps=tuple(steps), launch=launch, error_code=error_code)

    def _failure(self, steps, error_code: ErrorCode, launch=None) -> ConnectResult:
        return ConnectResult(
            provider_id=self._provider.id, success=False,
            state=VpnState.UNKNOWN, automation=AutomationMode.NONE,
            route=ROUTE_GUI, steps=tuple(steps), launch=launch,
            error_code=error_code.value)
