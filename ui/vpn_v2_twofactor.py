"""The CLI second-factor monitor, on a worker thread — prepared, not wired.

Stage 50.  When a FortiClient EMS/ZTNA connect starts through the CLI, its
stdout asks for a one-time code in plain text and its stdin accepts the answer.
Reading that pipe blocks, so it cannot happen on the UI thread; and the live
process has to stay owned by *someone* from the moment it starts until the token
is in, the process ends, it times out, or the user cancels — otherwise the
"enter your code" prompt would appear with no live pipe behind it.

This module is the Qt half.  The VPN half — the object that actually owns the
:class:`~vpn.providers.process_channel.ProcessChannel` and talks to the guarded
second-factor component — is ``vpn.panel_bridge.TwoFactorMonitorSession``.  As
with the connect controller, **this file imports nothing from ``vpn``**: the
session is handed in, and the worker only ever calls three plain callables and
reads back short string codes.  The token passes from the UI dialog straight
into the session's ``submit`` and is dropped; it is never stored on the worker,
never logged, never put in a signal.

Threading contract
------------------
* :class:`TwoFactorMonitorWorker` runs the blocking ``watch`` off the UI thread,
  then — if a challenge appeared — **blocks its own thread** waiting for a token
  (or a cancel, or a deadline) and runs the blocking ``submit`` off the UI
  thread too.  The UI thread never blocks on the pipe.
* Cancellation reaches the worker from the UI thread (:meth:`cancel`), which
  both trips the session's cancellation (so a blocked-between-reads ``watch``
  gives up) and wakes the token wait — and after it, nothing is submitted.
* A token supplied after the process has already gone is handed to ``submit``
  like any other; the guarded component turns a dead pipe into a failure, so no
  token is ever "sent into the void" as success.
"""

from __future__ import annotations

import threading

from PyQt6.QtCore import QObject, QThread, pyqtSignal

__all__ = ["TwoFactorMonitorWorker", "TwoFactorController",
           "PHASE_CHALLENGE", "PHASE_NO_CHALLENGE", "PHASE_CANCELLED",
           "PHASE_ERROR", "OUTCOME_SUBMITTED", "OUTCOME_FAILED",
           "OUTCOME_CANCELLED", "DEFAULT_TOKEN_TIMEOUT_S"]

#: String codes the session's ``watch`` returns.  They mirror
#: ``vpn.panel_bridge.MonitorPhase`` value-for-value; a test pins the two lists
#: together so this UI file can stay free of any ``vpn`` import.
PHASE_CHALLENGE = "challenge"
PHASE_NO_CHALLENGE = "no-challenge"
PHASE_CANCELLED = "cancelled"
PHASE_ERROR = "error"

#: …and the codes ``submit`` returns (mirror ``TwoFactorOutcome``).
OUTCOME_SUBMITTED = "submitted"
OUTCOME_FAILED = "failed"
OUTCOME_CANCELLED = "cancelled"

#: How long the worker waits for the UI to hand back a token before giving up.
#: A code the user never types must not pin the process open for ever.
DEFAULT_TOKEN_TIMEOUT_S = 120.0


class TwoFactorMonitorWorker(QThread):
    """Runs watch → (challenge) → wait-for-token → submit, off the UI thread.

    Driven by three callables so it needs nothing from ``vpn``:

    * ``watch()`` → one of the ``PHASE_*`` codes (blocking);
    * ``submit(token)`` → one of the ``OUTCOME_*`` codes (blocking);
    * ``cancel()`` → trip the session's cancellation (non-blocking).

    Emits exactly one terminal signal.
    """

    #: stdout asked for a code — the UI should collect one and call
    #: :meth:`provide_token`.
    challenge_detected = pyqtSignal()
    #: the CLI connected (or ended) without ever asking for a second factor.
    no_challenge = pyqtSignal()
    #: the token reached the process.
    token_submitted = pyqtSignal()
    #: a write / verify / pipe error — the token did not go, or reading failed.
    failed = pyqtSignal()
    #: the wait was called off; nothing was submitted.
    cancelled = pyqtSignal()
    #: a challenge appeared but no token arrived within the deadline.
    timed_out = pyqtSignal()

    def __init__(self, watch, submit, cancel, *,
                 token_timeout_s: float = DEFAULT_TOKEN_TIMEOUT_S,
                 parent=None):
        super().__init__(parent)
        self._watch = watch
        self._submit = submit
        self._cancel = cancel
        self._token_timeout_s = token_timeout_s
        self._token: str | None = None
        self._token_event = threading.Event()
        self._cancel_flag = False

    # -- reached from the UI thread ---------------------------------------- #

    def provide_token(self, token: str) -> None:
        """Hand a token to the waiting worker.  Ignored once it is no longer
        waiting (cancelled, timed out, already submitting)."""
        self._token = token
        self._token_event.set()

    def cancel(self) -> None:
        """Call the whole exchange off.  Safe before, during and after the wait."""
        self._cancel_flag = True
        try:
            self._cancel()
        except Exception:
            pass
        self._token_event.set()

    # -- the worker thread -------------------------------------------------- #

    def run(self) -> None:
        try:
            phase = self._watch()
        except Exception:
            self.failed.emit()
            return
        if self._cancel_flag or phase == PHASE_CANCELLED:
            self.cancelled.emit()
            return
        if phase == PHASE_ERROR:
            self.failed.emit()
            return
        if phase != PHASE_CHALLENGE:
            self.no_challenge.emit()
            return

        # A challenge is on screen; ask the UI and wait — but not for ever, and
        # not past a cancel.
        self.challenge_detected.emit()
        got = self._token_event.wait(self._token_timeout_s)
        if self._cancel_flag:
            self.cancelled.emit()
            return
        if not got or self._token is None:
            self.timed_out.emit()
            return

        token, self._token = self._token, None      # drop it immediately
        try:
            outcome = self._submit(token)
        except Exception:
            self.failed.emit()
            return
        del token
        if outcome == OUTCOME_SUBMITTED:
            self.token_submitted.emit()
        elif outcome == OUTCOME_CANCELLED:
            self.cancelled.emit()
        else:
            self.failed.emit()


class TwoFactorController(QObject):
    """Puts a :class:`TwoFactorMonitorWorker` behind the seven panel signals.

    Handed a session (``vpn.panel_bridge.TwoFactorMonitorSession``) — which it
    treats as an opaque owner of the process channel exposing ``watch``,
    ``submit`` and ``cancel`` — it turns the worker's outcome into the vocabulary
    the card speaks.  It does not build a dialog: the call site connects
    :attr:`token_required` to whatever collects a code and calls
    :meth:`provide_token`.
    """

    cli_started = pyqtSignal()          # the monitor is now owned and running
    token_required = pyqtSignal()       # collect a code, then provide_token()
    token_submitted = pyqtSignal()      # the code reached the process
    connected = pyqtSignal()            # STARTED — no second factor was needed
    failed = pyqtSignal()
    timed_out = pyqtSignal()
    cancelled = pyqtSignal()
    #: one terminal string code, after any of the above, for a call site that
    #: prefers a single slot.
    finished = pyqtSignal(str)

    #: Terminal codes carried by :attr:`finished`.
    CODE_SUBMITTED = "token-submitted"
    CODE_CONNECTED = "connected"
    CODE_FAILED = "failed"
    CODE_TIMEOUT = "timeout"
    CODE_CANCELLED = "cancelled"

    def __init__(self, session, *, token_timeout_s: float = DEFAULT_TOKEN_TIMEOUT_S,
                 parent=None):
        super().__init__(parent)
        self._session = session
        self._started = False
        self._done = False
        self.worker = TwoFactorMonitorWorker(
            session.watch, session.submit, session.cancel,
            token_timeout_s=token_timeout_s)
        self.worker.challenge_detected.connect(self._on_challenge)
        self.worker.no_challenge.connect(
            lambda: self._finish(self.CODE_CONNECTED, self.connected))
        self.worker.token_submitted.connect(
            lambda: self._finish(self.CODE_SUBMITTED, self.token_submitted))
        self.worker.failed.connect(
            lambda: self._finish(self.CODE_FAILED, self.failed))
        self.worker.timed_out.connect(
            lambda: self._finish(self.CODE_TIMEOUT, self.timed_out))
        self.worker.cancelled.connect(
            lambda: self._finish(self.CODE_CANCELLED, self.cancelled))

    @property
    def done(self) -> bool:
        return self._done

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self.cli_started.emit()
        self.worker.start()

    def provide_token(self, token: str) -> None:
        if not self._done:
            self.worker.provide_token(token)

    def cancel(self) -> None:
        if not self._done:
            self.worker.cancel()

    def _on_challenge(self) -> None:
        # Not terminal: the exchange continues to a token.
        self.token_required.emit()

    def _finish(self, code: str, signal) -> None:
        if self._done:
            return
        self._done = True
        signal.emit()
        self.finished.emit(code)
