"""Telling the user to switch to FortiClient — and nothing else.

Windows does not let a background process take the foreground away from
another program's window; three stages of measurement settled that, and the
conclusion was to stop trying.  The connect flow now waits until the user has
brought the client forward themselves (``vpn.providers.activation_gate``), and
this is the piece that says so on screen.

What it is allowed to do is exactly one thing: **show a sentence and offer a
Cancel button.**  It cannot raise the client, cannot focus it, cannot type into
it, and cannot read or write the clipboard — because a UI that could do any of
that would be the foreground theft we just removed, wearing a friendlier face.

Where the sentence goes
-----------------------
Into the status line the VPN card already has.  ``VpnPanel`` gives every
profile a small ``QLabel`` and writes "◌ Łączenie…", "● Połączono", "Brak
konfig." into it with a colour per meaning; waiting for an activation is one
more thing that can be true of a connection, not a new kind of information, so
it reuses that label and that palette (:data:`STATE_COLOURS`) rather than
introducing a second place where the VPN says how it is doing.  Hand the
existing label to :class:`ActivationPrompt` and it writes there; hand it
nothing and it makes an identical one, which is what the tests do.

The one thing the card has no room for is a Cancel button, and that is what
this widget adds — a button, not a status system.

Why this module imports nothing from ``vpn``
--------------------------------------------
The running application must not depend on the migrated architecture while the
legacy module is still production; a test walks the whole tree to enforce it.
So nothing here knows what an ``ActivationGate`` is.  The worker is handed a
callable to run and the presenter is handed a **state name as a string**.  The
wiring — which gate, which cancellation token — happens at the call site, which
today is only the tests.  That is not a workaround: a banner has no business
knowing how a window is verified.
"""

from __future__ import annotations

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget

__all__ = ["ActivationPresenter", "ActivationPrompt", "ActivationWorker",
           "STATE_MESSAGES", "STATE_TEMPLATES", "STATE_COLOURS", "WAITING_STATES",
           "DEFAULT_CLIENT", "label_style_sheet", "state_message"]

#: What the user reads, per state name.  Deliberately free of: any promise that
#: the switch will happen by itself or within some time, the words "click Done"
#: (there is nothing to click — the signal is the client window becoming
#: active), and every diagnostic detail.  No handle, no pid, no error code, and
#: of course no login, password or token: none of that is the user's problem
#: and none of it belongs on a screen somebody might be standing behind.
STATE_TEMPLATES = {
    "locating-target": "Uruchamiam {client}…",
    "awaiting-activation":
        "Okno {client} jest otwarte, ale nieaktywne — kliknij je, "
        "aby wpisać dane.",
    "activation-observed": "Okno {client} jest aktywne — wypełniam dane…",
    "activation-timeout":
        "Okno {client} nie zostało aktywowane — nic nie wpisano. Spróbuj "
        "ponownie albo wpisz dane ręcznie.",
    "no-target":
        "Nie pojawiło się okno {client}. Otwórz je (np. z zasobnika) i "
        "spróbuj ponownie.",
    "target-changed":
        "Okno {client} zmieniło się w trakcie oczekiwania. Spróbuj ponownie.",
    "cancelled": "Anulowano — nic nie zostało wpisane.",
}

#: The client named when the caller names none (the first migrated provider).
DEFAULT_CLIENT = "FortiClient"


def state_message(state, client: str | None = None) -> str | None:
    """The sentence for `state`, naming `client`; None for an unknown state.

    2026-10-19: every provider used to read "FortiClient" here — a Barracuda
    connect said "FortiClient został uruchomiony".
    """
    template = STATE_TEMPLATES.get(str(state))
    if template is None:
        return None
    return template.format(client=client or DEFAULT_CLIENT)


#: The sentences as FortiClient reads them (kept for callers and tests that
#: name no client).
STATE_MESSAGES = {state: state_message(state) for state in STATE_TEMPLATES}

#: The panel's own status palette, used with the panel's own meanings: amber is
#: "in progress" (it is what "◌ Łączenie…" uses), green "it worked", red "it
#: did not", grey "nothing is happening" (what "○ Rozłączono" uses).  A
#: cancelled wait is grey, not red: the user asked for it.
STATE_COLOURS = {
    "locating-target": "#d29922",
    "awaiting-activation": "#d29922",
    "activation-observed": "#3fb950",
    "activation-timeout": "#f85149",
    "no-target": "#f85149",
    "target-changed": "#f85149",
    "cancelled": "#8b949e",
}

#: While in one of these, the wait is still running and Cancel means something.
WAITING_STATES = ("locating-target", "awaiting-activation")

#: States in which a *held* prompt still offers Cancel although the wait itself
#: is over (Stage 47): the activation was observed and the operation it
#: permitted — the autofill — is running now, and it honours the same token.
HELD_STATES = ("activation-observed",)

#: Shown when a state arrives that this version does not know.  Fail-safe: an
#: unknown state is treated as finished and unsuccessful, never as "carry on".
UNKNOWN_MESSAGE = "Nie udało się przygotować wypełniania danych."
UNKNOWN_COLOUR = "#f85149"


def label_style_sheet(colour: str) -> str:
    """The card status label's stylesheet, byte for byte as the panel writes it."""
    return f"color: {colour}; font-size: 10px; border: none;"


class ActivationPresenter:
    """What to show, given a state name.  No Qt, no timers, no I/O.

    Separated from the widget so that the contract — which sentence, whether
    Cancel is offered, whether the wait is over — can be tested without a
    screen, and so the widget stays a renderer with nothing to get wrong.
    """

    def __init__(self, state: str = "locating-target", *,
                 hold_cancel: bool = False, client: str | None = None):
        self.state = str(state)
        #: The client named in the sentences ("FortiClient", "Stormshield"…).
        self.client = client or DEFAULT_CLIENT
        #: Keep Cancel through :data:`HELD_STATES` until released (Stage 47).
        #: Off by default: a prompt that only watches the gate ends with it.
        self.hold_cancel = bool(hold_cancel)

    def update(self, state) -> "ActivationPresenter":
        self.state = str(state)
        return self

    @property
    def known(self) -> bool:
        return self.state in STATE_MESSAGES

    @property
    def message(self) -> str:
        return state_message(self.state, self.client) or UNKNOWN_MESSAGE

    @property
    def colour(self) -> str:
        return STATE_COLOURS.get(self.state, UNKNOWN_COLOUR)

    @property
    def style_sheet(self) -> str:
        return label_style_sheet(self.colour)

    @property
    def waiting(self) -> bool:
        """The gate is still running; the user can still change the outcome."""
        return self.state in WAITING_STATES

    @property
    def cancel_visible(self) -> bool:
        """Cancel is offered only while cancelling would change anything.

        For a held prompt that includes the operation the activation let
        start; an unknown state still never offers it.
        """
        return self.waiting or (self.hold_cancel and self.state in HELD_STATES)

    @property
    def finished(self) -> bool:
        return not self.waiting

    @property
    def succeeded(self) -> bool:
        return self.state == "activation-observed"


class ActivationWorker(QThread):
    """Runs the wait off the UI thread and reports back with signals.

    ``QThread`` + ``pyqtSignal`` is how this project already moves VPN work off
    the UI thread (``StatusWorker``, ``VpnMonitorWorker``); this is the same
    shape, and for the same reason — the wait can last a minute and a frozen
    window is exactly what the user must not get while they are being asked to
    click another one.

    It takes a plain callable and does not know what it is running, which is
    why this module needs nothing from ``vpn``.  Intermediate states arrive
    through :meth:`report_state`, which the caller hands to the gate as its
    observer; the UI never polls anything.
    """

    #: State name, as a string, every time the wait moves on.
    state_changed = pyqtSignal(str)
    #: The object the callable returned, whatever it is.
    finished_with = pyqtSignal(object)
    #: The callable raised — the message is its exception type, never its text.
    failed = pyqtSignal(str)

    def __init__(self, run, *, initial_state: str = "locating-target",
                 parent=None):
        super().__init__(parent)
        self._run = run
        self._initial_state = str(initial_state)
        self._last_state: str | None = None

    def report_state(self, state) -> None:
        """Observer for the wait.  Safe to call from the worker thread.

        Repeats are dropped.  The terminal state arrives twice — once from the
        gate as it finishes, once from the result this worker unwraps — and a
        signal called ``state_changed`` that fires without a change is lying
        about what it means.  Rendering is idempotent, so nothing broke; the
        point is that a listener which counts transitions (a log, a trace, a
        test) can trust the count.  Only this thread calls it.
        """
        state = str(state)
        if state == self._last_state:
            return
        self._last_state = state
        self.state_changed.emit(state)

    def run(self) -> None:
        self.report_state(self._initial_state)
        try:
            result = self._run()
        except Exception as exc:
            self.failed.emit(type(exc).__name__)
            return
        state = getattr(result, "state", None)
        if state is not None:
            self.report_state(state)
        self.finished_with.emit(result)


class ActivationPrompt(QWidget):
    """A one-line, non-modal banner: the sentence, and Cancel.

    Non-modal on purpose.  The user has to be able to reach another window —
    the client's — and a modal dialog is precisely a thing that stops them.

    Pressing Cancel does steal the foreground, and that is fine: cancelling is
    terminal, so there is nothing left for the focus to matter to.
    """

    cancelled = pyqtSignal()

    def __init__(self, parent=None, *, status_label: QLabel | None = None,
                 hold_cancel: bool = False, client: str | None = None):
        super().__init__(parent)
        self.presenter = ActivationPresenter(hold_cancel=hold_cancel,
                                             client=client)

        #: True when the sentence goes into a label this widget does not own —
        #: the VPN card's existing status line.
        self.borrowed_label = status_label is not None
        self._label = status_label if status_label is not None else QLabel()
        self._label.setWordWrap(True)

        self._cancel = QPushButton("Anuluj")
        self._cancel.setToolTip("Przerwij — nic więcej nie zostanie wpisane")
        self._cancel.clicked.connect(self.request_cancel)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        if not self.borrowed_label:
            layout.addWidget(self._label, 1)
        else:
            layout.addStretch(1)
        layout.addWidget(self._cancel, 0)
        self._apply()

    # -- state in, pixels out ---------------------------------------------- #

    def apply_state(self, state) -> None:
        """Slot for :attr:`ActivationWorker.state_changed`."""
        self.presenter.update(state)
        self._apply()

    def _apply(self) -> None:
        self._label.setText(self.presenter.message)
        self._label.setStyleSheet(self.presenter.style_sheet)
        self._apply_visibility()

    def _apply_visibility(self) -> None:
        self._cancel.setVisible(self.presenter.cancel_visible)
        # The button is the only thing this widget owns when the label is
        # borrowed, so "the prompt is over" and "hide the button" are the same
        # statement — the card keeps showing the closing sentence either way.
        self.setVisible(self.presenter.cancel_visible)

    # -- the only thing the user can tell us -------------------------------- #

    def request_cancel(self) -> None:
        """Emit :attr:`cancelled`.  Whoever owns the wait decides what that means.

        This widget does not cancel anything itself; it has no gate, no token
        and no thread.  It reports a click.
        """
        self.cancelled.emit()

    def release(self) -> None:
        """The operation this prompt was held open for has finished.

        Drops Cancel and leaves the label alone — whoever held the prompt is
        about to write the outcome there.
        """
        self.presenter.hold_cancel = False
        self._apply_visibility()

    @property
    def message(self) -> str:
        return self._label.text()

    @property
    def status_label(self) -> QLabel:
        return self._label

    @property
    def cancel_button(self) -> QPushButton:
        return self._cancel
