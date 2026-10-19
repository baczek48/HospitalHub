"""Barracuda connect — the skeleton, and a deliberate stop before any typing.

Five phases and then a stop the caller cannot misread::

    detect → launch → window_probe → await_activation → activation_still_holds
                                                              │
                                                      requires_user_action
                                                      ui_contract_verified=False

The autofill is the next stage, and it is not written yet — Barracuda's login
window has not been measured on any machine, so typing into it would be a guess.
The flow therefore ends by saying two things at once: the client is open and
verified (``requires_user_action=True``, ``AutomationMode.MANUAL``), **and** the
reason nothing was typed is that the UI contract is unverified, not that
something failed.  The second half is carried in ``metadata`` and in
:data:`STOP_REASON` so a future autofill stage — or the panel — cannot mistake
"we stopped on purpose" for "the client rejected us".

Reused, not re-implemented
--------------------------
The activation gate, ``SecureWindowTarget``, ``strict_foreground_check`` and the
``require_visible`` / ``raise_window`` contract — all shared, none re-created
here, none aware which provider is asking.  No tray click, no ``SW_RESTORE``, no
``SetForegroundWindow``, no ``SetWindowPos``: the flow launches the client and
waits.

The real system
---------------
``BarracudaConnectSystem`` is fail-inert (every method answers "nothing"), so a
system that was never wired cannot touch the machine.  ``BarracudaConnectRuntime``
is the real one: it delegates to the provider's detection, launch and secure
target, and runs the activation gate with the caller's :class:`CancellationToken`.
It has **no autofill method at all** — there is nothing here that can type.
"""

from __future__ import annotations

from typing import Any

from ..types import (
    AutofillStatus, AutomationMode, ConnectResult, ConnectStep, DetectionState,
    ErrorCode, VpnRequest, VpnState,
)
from .activation_gate import (
    ACTIVATION_TIMEOUT_S, CancellationToken, Clock, SystemClock,
)

__all__ = ["BarracudaConnectFlow", "BarracudaConnectSystem",
           "BarracudaConnectRuntime", "PHASE_DETECT", "PHASE_LAUNCH",
           "PHASE_WINDOW_PROBE", "PHASE_AWAIT_ACTIVATION", "ROUTE_GUI",
           "STOP_REASON"]

PHASE_DETECT = "detect"
PHASE_LAUNCH = "launch"
PHASE_WINDOW_PROBE = "window_probe"
PHASE_AWAIT_ACTIVATION = "await_activation"
PHASE_AUTOFILL = "autofill"

STEP_OK = "ok"
STEP_FAILED = "failed"
STEP_NONE = "none"

#: Only one route exists for this client.
ROUTE_GUI = "gui"

#: Why the flow stops after activation without typing.  Not an error — a
#: statement that the autofill stage has not measured this client's UI yet.
STOP_REASON = "ui-contract-unverified"


class BarracudaConnectSystem:
    """What the flow is allowed to do to the machine.

    Every method answers "nothing happened" by default, so a system that has
    not been wired up cannot start a client or touch a window — the same
    fail-inert shape the other providers use, and the reason an unwired flow is
    harmless.  There is deliberately **no** autofill method: this stage cannot
    type even if someone wired a system.
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


class BarracudaConnectRuntime(BarracudaConnectSystem):
    """The real system: provider detection/launch + secure target + gate.

    No autofill, no clipboard, no keystroke — there is no method here that could
    produce one.  The activation gate carries the caller's cancellation, so a
    cancelled connect stops waiting and, because there is nothing after the
    wait, touches nothing.
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

        target = self._target()
        return ActivationGate(
            target=target,
            bring_forward=target.bring_forward,
            clock=self._clock if self._clock is not None else SystemClock(),
            cancellation=self.cancellation,
            timeout_s=self.activation_timeout_s,
            observer=self.activation_observer,
            trace=self._trace).wait()

    def autofill(self, request):
        """Fill the verified client window (2026-10-19)."""
        return self._provider.autofill_login_password(
            request, target=self._target(), cancellation=self.cancellation,
            trace=self._trace)

    def activation_still_holds(self, hwnd):
        """One more strict reading before anything could reach for the window.

        The same read-only call every migrated provider uses — foreground,
        verified owner, not minimised.  Nothing is restored, raised, focused or
        typed; there is, in this stage, nothing that *could* type.
        """
        return self._target().foreground_check(hwnd)


class BarracudaConnectFlow:
    """The phase order, and nothing else.

    Holds no Win32, no timing and no knowledge of how a window is verified; it
    decides *which* phase runs next, records what each answered, and stops
    before the autofill with an unambiguous reason.
    """

    def __init__(self, provider, system: BarracudaConnectSystem):
        self._provider = provider
        self._system = system

    def run(self, request: VpnRequest) -> ConnectResult:
        steps: list[ConnectStep] = []

        # -- detect --------------------------------------------------------- #
        detection = self._system.detect(request)
        state = getattr(detection, "state", None)
        installed = state in (DetectionState.INSTALLED, DetectionState.INCOMPLETE)
        steps.append(ConnectStep(
            PHASE_DETECT, STEP_OK if installed else STEP_FAILED,
            None if installed else ErrorCode.CLIENT_NOT_FOUND.value,
            state.value if state is not None else None))
        if not installed:
            return self._failure(steps, ErrorCode.CLIENT_NOT_FOUND)

        # -- launch --------------------------------------------------------- #
        launch = self._system.launch(request)
        launched = bool(getattr(launch, "success", False))
        steps.append(ConnectStep(
            PHASE_LAUNCH, STEP_OK if launched else STEP_FAILED,
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
                                         error_code=ErrorCode.FOCUS_FAILED.value)

            # One more reading before anything could reach for the window.
            still = self._system.activation_still_holds(
                getattr(activation, "hwnd", None))
            if still is not None and not getattr(still, "ok", False):
                steps.append(ConnectStep(PHASE_AWAIT_ACTIVATION, STEP_FAILED,
                                         ErrorCode.FOCUS_FAILED.value,
                                         getattr(still, "reason", None)))
                return self._user_action(steps, launch,
                                         error_code=ErrorCode.FOCUS_FAILED.value)


        # -- autofill (2026-10-19) ------------------------------------------ #
        # The window is verified and in front.  Fill it field by field
        # (vpn.providers.field_fill); every step re-confirms the window.
        if request.autofill and (request.login or request.password):
            filled = self._system.autofill(request)
            if filled.status is AutofillStatus.CANCELLED:
                steps.append(ConnectStep(PHASE_AUTOFILL, STEP_NONE,
                                         ErrorCode.CANCELLED.value, filled.blocked_at))
                return ConnectResult(
                    provider_id=self._provider.id, success=False,
                    state=VpnState.UNKNOWN, automation=AutomationMode.NONE,
                    route=ROUTE_GUI, steps=tuple(steps), launch=launch,
                    autofill=filled, error_code=ErrorCode.CANCELLED.value)
            done = filled.status is AutofillStatus.DONE
            steps.append(ConnectStep(PHASE_AUTOFILL, STEP_OK if done else STEP_FAILED,
                                     None if done else filled.error_code,
                                     None if done else filled.blocked_at))
            submitted = bool((filled.metadata or {}).get("submitted"))
            return ConnectResult(
                provider_id=self._provider.id, success=True,
                state=VpnState.CONNECTING if submitted else VpnState.UNKNOWN,
                automation=AutomationMode.UIA_FOCUS_TYPE,
                requires_user_action=not submitted, route=ROUTE_GUI,
                steps=tuple(steps), launch=launch, autofill=filled,
                error_code=None if done else filled.error_code)

        # Autofill off, or nothing to type: the person does the typing.
        return self._user_action(steps, launch, stopped_before_autofill=True)

    # -- results ------------------------------------------------------------ #

    def _user_action(self, steps, launch=None, *, error_code=None,
                     stopped_before_autofill: bool = False) -> ConnectResult:
        metadata: dict = {}
        if stopped_before_autofill:
            # The unambiguous signal: we did not type, and here is why.
            metadata = {"stopped_before_autofill": STOP_REASON,
                        "ui_contract_verified": False}
        return ConnectResult(
            provider_id=self._provider.id, success=True,
            state=VpnState.UNKNOWN, automation=AutomationMode.MANUAL,
            requires_user_action=True, route=ROUTE_GUI,
            steps=tuple(steps), launch=launch, error_code=error_code,
            metadata=metadata)

    def _failure(self, steps, error_code: ErrorCode, launch=None) -> ConnectResult:
        return ConnectResult(
            provider_id=self._provider.id, success=False,
            state=VpnState.UNKNOWN, automation=AutomationMode.NONE,
            route=ROUTE_GUI, steps=tuple(steps), launch=launch,
            error_code=error_code.value)
