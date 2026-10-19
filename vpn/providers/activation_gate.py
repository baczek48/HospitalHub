"""Wait until the client window is in front.  Types nothing, sends nothing.

Stages 18-20 measured that a *background* process cannot take the foreground
away from another process' window, and Stage 22 concluded that the connect
should wait for the user to bring the client forward.  The field test of
2026-10-19 showed what that costs: every connect stopped at "switch to the
window".  HospitalHub is, however, the foreground program at the moment
"Połącz" is clicked, and the foreground program may hand the foreground on --
measured, from the connect's worker thread.  So the gate now also *asks* for
the window to be put in front (:attr:`ActivationGate.bring_forward`, a few
times while the window is pinned and not yet active) and keeps waiting for the
user when Windows says no.

What it still cannot do
-----------------------
It never focuses a control and never types, and it accepts no login, no
password and no token, because nothing it does could need one.  Bringing a
window forward is a request, not a decision: the gate reports
:attr:`ActivationState.ACTIVATION_OBSERVED` only once a reading
(:meth:`SecureWindowTarget.foreground_check`) has seen the verified window in
front.

What "observed" does and does not mean
--------------------------------------
:attr:`ActivationState.ACTIVATION_OBSERVED` is permission to *start*, not proof
that will hold.  Between the observation and the first keystroke the foreground
can change again, and this module makes no attempt to prevent that: the
decision that matters stays where it already was -- ``acquire_focus``'s own
confirmation and then the per-secret guards of the autofill, which re-read the
desktop before every single operation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .secure_target import ForegroundCheck, SecureWindowTarget

__all__ = [
    "ActivationGate", "ActivationResult", "ActivationState", "Clock",
    "SystemClock", "CancellationToken", "wait_for_activation",
    "ACTIVATION_TIMEOUT_S", "POLL_INTERVAL_S", "MAX_REPINS",
    "BRING_FORWARD_ATTEMPTS", "BRING_FORWARD_INTERVAL_S",
]

#: How long the user is given to switch to the client.  A budget for giving up
#: — never evidence of anything.  Long enough for "alt-tab, find the window,
#: click it", short enough that a forgotten connect does not wait for ever.
ACTIVATION_TIMEOUT_S = 60.0

#: The same cadence the rest of this package polls at.
POLL_INTERVAL_S = 0.5

#: How many times the gate asks for the pinned window to be put in front, and
#: how far apart.  A client that has just started may still be building its
#: window, so one request is not always enough; after these, the user decides.
BRING_FORWARD_ATTEMPTS = 3
BRING_FORWARD_INTERVAL_S = 1.0

#: How many times the client may be replaced by a *different* window of the
#: same program while we wait.  One restart is ordinary; three is a client in
#: trouble and waiting longer helps nobody.  Counted only before activation:
#: afterwards there is no re-pin at all.
MAX_REPINS = 3


class ActivationState(StrEnum):
    """Where the wait ended."""

    #: No trusted client window has been seen yet.
    LOCATING_TARGET = "locating-target"
    #: A window is pinned; it is not the one in front.
    AWAITING_ACTIVATION = "awaiting-activation"
    #: The pinned window is in front and visible — the autofill may start.
    ACTIVATION_OBSERVED = "activation-observed"
    #: The client kept being replaced, or was replaced by a different program.
    TARGET_CHANGED = "target-changed"
    #: The budget ran out with a window pinned but never activated.
    ACTIVATION_TIMEOUT = "activation-timeout"
    #: The budget ran out without ever finding a trusted client window.
    NO_TARGET = "no-target"
    #: Somebody called off the wait.
    CANCELLED = "cancelled"


#: States in which the wait is over for good.
TERMINAL_STATES = (ActivationState.ACTIVATION_OBSERVED,
                   ActivationState.TARGET_CHANGED,
                   ActivationState.ACTIVATION_TIMEOUT,
                   ActivationState.NO_TARGET,
                   ActivationState.CANCELLED)

#: ``ConnectStep.phase`` / ``AutofillResult.blocked_at`` for this wait.
PHASE_AWAIT_ACTIVATION = "await-activation"


@dataclass(frozen=True)
class ActivationResult:
    """How the wait went.  Handles and counters — no title, no path, no secret."""

    state: ActivationState
    reason: str | None = None
    hwnd: Any = None
    pid: int | None = None
    image_name: str | None = None
    polls: int = 0
    repins: int = 0
    waited_s: float = 0.0

    @property
    def ok(self) -> bool:
        """True only when the user really did activate the verified client."""
        return self.state is ActivationState.ACTIVATION_OBSERVED

    def to_trace_data(self) -> dict:
        return {key: value for key, value in (
            ("event", "await-activation"), ("state", self.state.value),
            ("reason", self.reason), ("pid", self.pid),
            ("image_name", self.image_name), ("polls", self.polls),
            ("repins", self.repins), ("waited_s", round(self.waited_s, 1)),
        ) if value is not None}


# --------------------------------------------------------------------------- #
# Seams                                                                        #
# --------------------------------------------------------------------------- #

class Clock:
    """Time, injected — so a test can wait a minute without taking one."""

    def monotonic(self) -> float:
        raise NotImplementedError

    def sleep(self, seconds: float) -> None:
        raise NotImplementedError


class SystemClock(Clock):
    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


@dataclass
class CancellationToken:
    """Call off the wait.  Terminal: a cancelled wait never starts an autofill.

    Deliberately not a UI concept — a Cancel button would set it, and so would
    a timeout elsewhere, a disconnect, or a test.
    """

    cancelled: bool = False

    def cancel(self) -> None:
        self.cancelled = True


class _Trace:
    """Null-safe wrapper: the caller may pass a diagnostics trace or None."""

    def __init__(self, trace):
        self._t = trace

    def ok(self, name, **data):
        if self._t is not None:
            self._t.ok(name, **data)

    def fail(self, name, **data):
        if self._t is not None:
            self._t.fail(name, **data)


# --------------------------------------------------------------------------- #
# The gate                                                                     #
# --------------------------------------------------------------------------- #

@dataclass
class ActivationGate:
    """Polls a target until its window is in front, or the wait ends.

    The whole state machine is here and it is small on purpose: one reading per
    poll, one pinned identity, one counter.
    """

    target: SecureWindowTarget
    clock: Clock = field(default_factory=SystemClock)
    cancellation: CancellationToken = field(default_factory=CancellationToken)
    timeout_s: float = ACTIVATION_TIMEOUT_S
    poll_interval_s: float = POLL_INTERVAL_S
    max_repins: int = MAX_REPINS
    trace: Any = None

    #: Called with every state the wait passes through, in the waiting thread.
    #: The reason it exists: a caller that wants to *show* the wait would
    #: otherwise have to poll :attr:`state` from a timer, and a UI polling a
    #: state machine that already knows when it changed is a second, worse
    #: state machine.  Anything raised here is swallowed — an observer that
    #: breaks must not be able to abort a wait or, worse, leave it half-done.
    observer: Any = None

    #: ``bring_forward(hwnd) -> bool`` asks for the pinned window to be put in
    #: front (:meth:`SecureWindowTarget.bring_forward`).  ``None`` keeps the
    #: Stage-22 behaviour: wait for the user only.
    bring_forward: Any = None
    bring_forward_attempts: int = BRING_FORWARD_ATTEMPTS
    bring_forward_interval_s: float = BRING_FORWARD_INTERVAL_S

    #: Filled as the wait runs; readable by a caller that cannot take a callback.
    state: ActivationState = ActivationState.LOCATING_TARGET

    def _set_state(self, state: ActivationState) -> None:
        """Move to `state` and tell the observer, if there is one."""
        self.state = state
        if self.observer is not None:
            try:
                self.observer(state)
            except Exception:
                pass

    def wait(self) -> ActivationResult:
        """Block (against the injected clock) until the wait is over."""
        tr = _Trace(self.trace)
        started = self.clock.monotonic()
        pinned: tuple | None = None
        polls = repins = 0
        brought = 0
        last_bring: float | None = None

        tr.ok("vpn.activation", event="await-activation-start",
              timeout_ms=int(self.timeout_s * 1000))

        while True:
            if self.cancellation.cancelled:
                return self._finish(ActivationState.CANCELLED, "cancelled",
                                    pinned, polls, repins, started, tr)

            check = self._look(pinned)
            polls += 1

            if check.found:
                if pinned is None:
                    pinned = check.identity
                    self._set_state(ActivationState.AWAITING_ACTIVATION)
                    tr.ok("vpn.activation", event="target-pinned",
                          pid=check.pid, image_name=check.image_name)
                elif check.identity != pinned:
                    # A different window is offering itself.  It is already
                    # verified — `foreground_check` only returns windows whose
                    # process image is a trusted client — but "trusted" is not
                    # "the same".  A different *program* is refused outright; a
                    # new window of the same program costs a re-pin.
                    if check.image_name != pinned[2]:
                        return self._finish(
                            ActivationState.TARGET_CHANGED,
                            "image-identity-changed", pinned, polls, repins,
                            started, tr)
                    repins += 1
                    if repins > self.max_repins:
                        return self._finish(ActivationState.TARGET_CHANGED,
                                            "too-many-repins", pinned, polls,
                                            repins, started, tr)
                    pinned = check.identity
                    tr.ok("vpn.activation", event="target-repinned",
                          pid=check.pid, repins=repins)

                if check.ok and check.identity == pinned:
                    # Asked again, deliberately.  A Cancel that landed while
                    # this very reading was in flight must still win: it means
                    # "do not type", and the only thing an observation is good
                    # for is permission to type.  Losing that race would start
                    # an autofill the user had already called off.
                    if self.cancellation.cancelled:
                        return self._finish(ActivationState.CANCELLED,
                                            "cancelled-during-observation",
                                            pinned, polls, repins, started, tr)
                    return self._finish(ActivationState.ACTIVATION_OBSERVED,
                                        check.reason, pinned, polls, repins,
                                        started, tr)

            if (pinned is not None and self.bring_forward is not None
                    and brought < self.bring_forward_attempts
                    and (last_bring is None
                         or self.clock.monotonic() - last_bring
                         >= self.bring_forward_interval_s)):
                brought += 1
                last_bring = self.clock.monotonic()
                try:
                    accepted = bool(self.bring_forward(pinned[0]))
                except Exception:
                    accepted = False
                tr.ok("vpn.activation", event="bring-forward", attempt=brought,
                      accepted=accepted)
                if accepted:
                    continue      # read the desktop again straight away

            waited = self.clock.monotonic() - started
            if waited >= self.timeout_s:
                ran_out = (ActivationState.ACTIVATION_TIMEOUT if pinned
                           else ActivationState.NO_TARGET)
                return self._finish(ran_out, check.reason, pinned, polls,
                                    repins, started, tr)
            self.clock.sleep(self.poll_interval_s)

    # -- one reading -------------------------------------------------------- #

    def _look(self, pinned) -> ForegroundCheck:
        """Ask about the pinned window; if it is gone, look for a successor.

        Two readings in one poll at most, and only when the window we were
        waiting for has disappeared — the client restarting is the case this
        covers.
        """
        if pinned is None:
            return self.target.foreground_check()
        check = self.target.foreground_check(pinned[0])
        if check.found:
            return check
        return self.target.foreground_check()

    def _finish(self, state, reason, pinned, polls, repins, started,
                tr) -> ActivationResult:
        self._set_state(state)
        hwnd, pid, image_name = pinned if pinned else (None, None, None)
        result = ActivationResult(state, reason, hwnd, pid, image_name, polls,
                                  repins, self.clock.monotonic() - started)
        if result.ok:
            tr.ok("vpn.activation", **result.to_trace_data())
        else:
            tr.fail("vpn.activation", error_code=PHASE_AWAIT_ACTIVATION,
                    **result.to_trace_data())
        return result


def wait_for_activation(target: SecureWindowTarget, *, clock: Clock | None = None,
                        cancellation: CancellationToken | None = None,
                        timeout_s: float = ACTIVATION_TIMEOUT_S,
                        poll_interval_s: float = POLL_INTERVAL_S,
                        max_repins: int = MAX_REPINS,
                        observer=None, trace=None,
                        bring_forward=None) -> ActivationResult:
    """Convenience over :class:`ActivationGate`.

    Note what is *not* in this signature: no login, no password, no token, no
    request.  Nothing this function does could need one.
    """
    return ActivationGate(
        target=target,
        clock=clock if clock is not None else SystemClock(),
        cancellation=cancellation if cancellation is not None
        else CancellationToken(),
        timeout_s=timeout_s, poll_interval_s=poll_interval_s,
        max_repins=max_repins, observer=observer, trace=trace,
        bring_forward=bring_forward).wait()
