"""A FortiClient V2 connect, as a VPN card would show it — prepared, not wired.

Stage 46.  The panel still connects through the legacy module and does not
import this file; nothing in the running application does.  This is the Qt
half of the eventual switch-over (the VPN-layer half is ``vpn.panel_bridge``):

* :class:`V2ConnectController` puts one connect session on an
  :class:`~ui.activation_prompt.ActivationWorker`, points the worker's state
  reports at an :class:`~ui.activation_prompt.ActivationPrompt` that writes
  into the card's existing status label, and routes the prompt's Cancel click
  to the session's cancellation.  That is the Stage-23 wiring, unchanged: the
  worker owns the wait, the prompt renders states, the click reaches a token.
* :func:`present_outcome` turns the session's outcome **code** into what the
  card already knows how to show — a sentence, one of the panel's colours, and
  whether the toggle goes to "connecting".

What this module is not allowed to know
---------------------------------------
It imports nothing from ``vpn``.  The session is handed in by whoever builds
it, and the only things this module ever reads from it are ``run``,
``cancel``, ``observer`` and, afterwards, the outcome's ``code``.  No login,
no password, no request, no window handle and no input machinery pass through
here: the credentials travel inside the session, from the vault to the
provider, past this file rather than through it.
"""

from __future__ import annotations

from dataclasses import dataclass

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QLabel, QWidget

from .activation_prompt import (
    DEFAULT_CLIENT, STATE_COLOURS, STATE_TEMPLATES, ActivationPrompt,
    ActivationWorker, label_style_sheet,
)

__all__ = ["CardUpdate", "OUTCOME_PRESENTATION", "V2ConnectController",
           "OUTCOME_TEMPLATES", "present_outcome", "POLL_AFTER_START_MS"]

#: The panel's own palette, with the panel's own meanings (see
#: ``VpnPanel._connect_card`` and ``_apply_status_results``).
COLOUR_OK = "#58a6ff"          # a legacy connect that returned ok
COLOUR_ERROR = "#f85149"       # a legacy connect that returned not ok
COLOUR_PROGRESS = "#d29922"    # "◌ Łączenie..."
COLOUR_IDLE = "#8b949e"        # "○ Rozłączono"

#: After a legacy ``ok`` the panel polls status 2 s later (15 s while the
#: legacy autofill thread is still typing).  A V2 session has already finished
#: its autofill when it reports, so the short delay is the honest one.
POLL_AFTER_START_MS = 2000

CARD_CONNECTING = "connecting"

#: Outcome code → (sentence, colour, card state or None to leave the card).
#: Sentences reuse the legacy module's wording where the situation is the same.
#: Sentences name the client through ``{client}`` (2026-10-19: they all said
#: "FortiClient", whichever provider was connecting).
OUTCOME_TEMPLATES: dict[str, tuple[str, str, str | None]] = {
    "submitted": ("Łączenie przez {client}...", COLOUR_OK, CARD_CONNECTING),
    "filled": ("Dane wpisane — kliknij „Log in” / „Connect” w {client}.",
               COLOUR_OK, CARD_CONNECTING),
    "two-factor-required": (
        "Dane wpisane — dokończ weryfikację dwuetapową w {client}.",
        COLOUR_PROGRESS, CARD_CONNECTING),
    "cli-started": ("Łączenie przez {client}...", COLOUR_OK, CARD_CONNECTING),
    "manual": ("{client} — hasło w schowku.", COLOUR_OK, CARD_CONNECTING),
    "started": ("Łączenie przez {client}...", COLOUR_OK, CARD_CONNECTING),
    "activation-timeout": (STATE_TEMPLATES["activation-timeout"],
                           STATE_COLOURS["activation-timeout"], None),
    "no-target": (STATE_TEMPLATES["no-target"], STATE_COLOURS["no-target"], None),
    "target-changed": (STATE_TEMPLATES["target-changed"],
                       STATE_COLOURS["target-changed"], None),
    "cancelled": (STATE_TEMPLATES["cancelled"], STATE_COLOURS["cancelled"], None),
    "focus-lost": (
        "Okno {client} przestało być aktywne — nic nie zostało wpisane. "
        "Wpisz dane ręcznie albo spróbuj ponownie.", COLOUR_ERROR, None),
    "autofill-blocked": (
        "Wypełnianie przerwane dla bezpieczeństwa. Dokończ logowanie ręcznie "
        "w {client}.", COLOUR_ERROR, None),
    "client-not-found": ("Nie znaleziono {client}.\nUruchom klienta VPN ręcznie.",
                         COLOUR_ERROR, None),
    "unsupported": ("Nowe łączenie {client} jest wyłączone.", COLOUR_IDLE, None),
    "busy": ("Trwa inne łączenie VPN — dokończ je albo anuluj, potem spróbuj ponownie.",
             COLOUR_IDLE, None),
    "failed": ("Nie udało się połączyć z {client}.", COLOUR_ERROR, None),
}

#: The same, as FortiClient reads it.
OUTCOME_PRESENTATION: dict[str, tuple[str, str, str | None]] = {
    code: (text.format(client=DEFAULT_CLIENT), colour, state)
    for code, (text, colour, state) in OUTCOME_TEMPLATES.items()}

#: Fail-safe for a code this version does not know: unsuccessful, card untouched.
UNKNOWN_OUTCOME = OUTCOME_PRESENTATION["failed"]

#: A blocked autofill told apart by *why* (2026-10-14, L5).  Codes come from
#: ``vpn.providers.forticlient_profile`` / ``forticlient_autofill`` as plain
#: strings — this module imports nothing from ``vpn``.  Every sentence is true
#: whichever step stopped: nothing was submitted.
_PROFILE_CONFIG = (
    "Nazwa profilu z karty nie odpowiada profilowi w FortiClient — popraw pole "
    "„Nazwa profilu w kliencie”. Logowanie nie zostało wysłane.")
_PROFILE_UNSPECIFIED = (
    "Karta nie ma nazwy profilu, a w FortiClient nie da się jednoznacznie "
    "ustalić właściwego — uzupełnij „Nazwa profilu w kliencie”. "
    "Logowanie nie zostało wysłane.")
_PROFILE_UNSUPPORTED = (
    "FortiClient pokazuje profil, którego nie da się bezpiecznie przełączyć "
    "(np. IPsec). Wybierz profil ręcznie i zaloguj się. "
    "Logowanie nie zostało wysłane.")
_PROFILE_UNCONFIRMED = (
    "Nie udało się potwierdzić profilu VPN w FortiClient. Wybierz profil "
    "ręcznie i zaloguj się. Logowanie nie zostało wysłane.")
BLOCKED_REASON_TEXT = {
    "requested-tunnel-not-configured": _PROFILE_CONFIG,
    "requested-profile-untrimmed": _PROFILE_CONFIG,
    "requested-profile-empty": _PROFILE_CONFIG,
    "tunnel-catalog-unavailable": _PROFILE_CONFIG,
    "tunnel-name-collides-with-group-label": _PROFILE_CONFIG,
    "ambiguous-tunnel-kind": _PROFILE_CONFIG,
    "profile-not-specified": _PROFILE_UNSPECIFIED,
    "profile-display-not-changeable": _PROFILE_UNSUPPORTED,
    "unknown-group-label": _PROFILE_UNSUPPORTED,
}
#: Any other profile-step code (unreadable, not confirmed, list did not open…).
_PROFILE_PREFIXES = ("profile-", "msaa-")


@dataclass(frozen=True)
class CardUpdate:
    """What the card should show once the session is over.  Plain values."""

    text: str
    colour: str
    #: ``"connecting"`` → flip the toggle like a legacy ok; ``None`` → leave it.
    card_state: str | None = None
    #: When to poll status again, or ``None`` to leave the regular timer alone.
    poll_after_ms: int | None = None

    @property
    def style_sheet(self) -> str:
        return label_style_sheet(self.colour)


def present_outcome(code, reason=None, client: str | None = None) -> CardUpdate:
    text, colour, card_state = OUTCOME_TEMPLATES.get(
        str(code), OUTCOME_TEMPLATES["failed"])
    text = text.format(client=client or DEFAULT_CLIENT)
    if str(code) == "autofill-blocked" and reason:
        reason = str(reason)
        if reason in BLOCKED_REASON_TEXT:
            text = BLOCKED_REASON_TEXT[reason]
        elif reason.startswith(_PROFILE_PREFIXES):
            text = _PROFILE_UNCONFIRMED
    return CardUpdate(text=text, colour=colour, card_state=card_state,
                      poll_after_ms=POLL_AFTER_START_MS if card_state else None)


class V2ConnectController(QObject):
    """One session, one worker, one prompt — and the card label they share.

    Does nothing until :meth:`start`.  The prompt is created as a child of
    `prompt_parent` (the card) so it never becomes a window of its own; where
    it sits in the card's layout is the call site's choice.
    """

    #: A :class:`CardUpdate`, once, when the session is over.
    card_update = pyqtSignal(object)
    #: The session's outcome object (``None`` if the session raised).
    finished = pyqtSignal(object)
    #: Status polling should stand down for this profile — emitted once, at
    #: :meth:`start`, before the worker runs (Stage 47).
    polling_pause = pyqtSignal()
    #: Status polling may resume its normal schedule — emitted once, when the
    #: session is over, whatever the outcome.  Paired one-to-one with
    #: :attr:`polling_pause`, so a call site can ``stop()`` the timer on pause
    #: and ``start(5000)`` it on resume without counting.
    polling_resume = pyqtSignal()

    def __init__(self, session, status_label: QLabel, *,
                 prompt_parent: QWidget, parent: QObject | None = None,
                 client: str | None = None):
        super().__init__(parent)
        #: The client named in every sentence the card shows.
        self._client = client
        self._session = session
        self._label = status_label
        self._started = False
        self._done = False
        # hold_cancel: keep Cancel through the autofill, not only the wait
        # (Stage 47).  The worker stops reporting states once the gate says
        # "activation-observed", but `session.run` keeps going into the fill;
        # the held prompt leaves Cancel on screen, and a click reaches the same
        # token the fill checks before every keystroke.
        self.prompt = ActivationPrompt(prompt_parent, status_label=status_label,
                                       hold_cancel=True, client=client)
        self.worker = ActivationWorker(session.run)
        session.observer = self.worker.report_state
        self.worker.state_changed.connect(self.prompt.apply_state)
        self.worker.finished_with.connect(self._on_finished)
        self.worker.failed.connect(self._on_failed)
        self.prompt.cancelled.connect(self.cancel)

    @property
    def done(self) -> bool:
        return self._done

    @property
    def active(self) -> bool:
        """A session is running: started and not yet finished.

        The one fact status polling needs.  While this is true the card is
        owned by the session — its status label is showing the activation
        sentence or the fill's progress — so a poll result must not be written
        over it.  Unlike the legacy 14-second timer, this is the real state of
        the session, so a fill that finishes in three seconds frees polling in
        three, and one that waits a minute for the user holds it a minute.
        """
        return self._started and not self._done

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        # Pause polling before the worker touches the client: the autofill's
        # keystrokes must not race a status subprocess (the legacy jitter that
        # made paste/Enter fire early), and a poll must not overwrite the
        # activation sentence.
        self.polling_pause.emit()
        self.worker.start()

    def cancel(self) -> None:
        """Reach the session's cancellation — and nothing else.

        After the session has reported, cancelling means nothing and changes
        nothing: an outcome is an outcome.
        """
        if not self._done:
            self._session.cancel()

    def _on_finished(self, outcome) -> None:
        self._finish(present_outcome(getattr(outcome, "code", ""),
                                     getattr(outcome, "reason", None),
                                     self._client), outcome)

    def _on_failed(self, _exception_type: str) -> None:
        self._finish(present_outcome("failed", client=self._client), None)

    def _finish(self, update: CardUpdate, outcome) -> None:
        if self._done:
            return
        self._done = True
        try:
            self.prompt.release()      # the fill is over — drop the held Cancel
            self.prompt.setVisible(False)
            self._label.setText(update.text)
            self._label.setStyleSheet(update.style_sheet)
        except RuntimeError:
            # The card was deleted (its vault window closed mid-session):
            # nothing left to show it on; the signals below still fire.
            pass
        self.card_update.emit(update)
        self.finished.emit(outcome)
        # Resume last: the card now shows the final sentence, so the next poll
        # is free to update it, and never before that.  Paired with the pause
        # in start(), it fires exactly once regardless of outcome.
        self.polling_resume.emit()
