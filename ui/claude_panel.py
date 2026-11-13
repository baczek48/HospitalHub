"""The "Wsparcie Claude" panel: a conversation with Claude about one terminal.

Sits beside the SSH terminal.  The owner talks here; Claude reads the shared
tab — the screen and its scrollback — and answers: what it sees, what is
wrong, which command to type next.  It cannot type: the owner runs every
command himself (the read-only start chosen on 2026-10-20).

The panel knows nothing about SSH.  It is handed a *target* with three
methods — ``label()``, ``alive()`` and ``read(lines)`` — and the Claude side
lives in :mod:`claude_support`.
"""

from __future__ import annotations

import re
import threading

import math

from PyQt6.QtCore import QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QPen, QTextDocument
from PyQt6.QtWidgets import (
    QApplication, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QScrollArea,
    QSizePolicy, QVBoxLayout, QWidget,
)

import claude_support as cs

__all__ = ["ClaudeSupportPanel", "system_prompt"]

#: Live mode: how often the tab is looked at, how long it must stay still
#: before its news is sent, the least time between two updates (each one is a
#: turn of the owner's subscription), and the most one update carries.
_LIVE_POLL_MS = 1000
_LIVE_QUIET_S = 2.0
_LIVE_MIN_GAP_S = 15.0
_LIVE_MAX_LINES = 120
#: What Claude answers in live mode when nothing deserves a comment.
LIVE_SILENT = "OK"

#: What one read may carry back (the model needs the end, not 50 000 lines).
_MAX_LINES = 2000
_MAX_CHARS = 60000
#: Longest the tool server waits for the UI thread to answer a read.
_READ_TIMEOUT_S = 30

#: Session ids of the conversations running in this process — a sweep of
#: records left by a crash must not delete theirs (claude_threads keeps it).
from claude_threads import LIVE_SESSIONS as _LIVE_SESSIONS  # noqa: E402

#: Claude's orange — the panel's frame and the SSH window's button share it.
ACCENT = "#d97757"
ACCENT_HOVER = "#e88a6b"
ACCENT_DIM = "#5c3322"

_PANEL_STYLE = f"""
QWidget#claudePanel {{ background: #0d1117; border: 1px solid {ACCENT};
                       border-radius: 10px; }}
QLabel {{ color: #c9d1d9; }}
QLabel#claudeTitle {{ color: {ACCENT}; font-weight: bold; font-size: 13px; }}
QScrollArea {{ border: none; background: #0d1117; }}
QPlainTextEdit {{ background: #161b22; color: #e6edf3; border: 1px solid #30363d;
                 border-radius: 6px; padding: 6px; font-size: 12px; }}
QPlainTextEdit:focus {{ border: 1px solid {ACCENT}; }}
QPushButton {{ background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
              border-radius: 6px; padding: 5px 12px; font-size: 11px; }}
QPushButton:hover {{ background: #30363d; border-color: {ACCENT}; }}
QPushButton:disabled {{ color: #484f58; border-color: #30363d; }}
QPushButton#claudeSend {{ background: {ACCENT}; color: #ffffff; border: none;
                          font-weight: bold; }}
QPushButton#claudeSend:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#claudeSend:disabled {{ background: {ACCENT_DIM}; color: #a8806f; }}
QPushButton#claudeLive:checked {{ background: {ACCENT}; color: #ffffff;
                                  border-color: {ACCENT}; }}
"""


def system_prompt(label: str) -> str:
    return (
        "Działasz w HospitalHub jako „Wsparcie Claude” dla jednej karty terminala "
        f"SSH: {label}. Rozmawiasz z administratorem po polsku, krótko i konkretnie.\n"
        "Masz jedno narzędzie: terminal_read — odczyt ekranu i historii tego "
        "terminala. Nie możesz niczego wpisać ani uruchomić: komendy wpisuje "
        "administrator. Gdy potrzebujesz więcej informacji, podaj mu dokładną "
        "komendę w bloku kodu (jedna linia, gotowa do przepisania) i jednym "
        "zdaniem napisz, po co; po jej wykonaniu przeczytaj terminal ponownie.\n"
        "Zasady: to serwery szpitalne, często produkcyjne. Najpierw proponuj "
        "komendy tylko do odczytu (ps, ls, cat, tail -n, grep, df, free, "
        "systemctl status, journalctl -n, docker ps/logs --tail/inspect). Gdy "
        "proponujesz coś, co zmienia stan (restart, rm, edycja plików, docker "
        "compose up/down, kill, zmiana uprawnień), wyraźnie to zaznacz i opisz "
        "skutki. Unikaj komend bez końca (top, less, tail -f) — podawaj wersje z "
        "limitem. Nigdy nie proś o hasła. Logi mogą zawierać dane osobowe "
        "pacjentów — nie powtarzaj ich bez potrzeby. Numery PESEL są przed "
        "wysłaniem do Ciebie zamieniane przez HospitalHub na "
        f"{cs.PESEL_MASK} — nie proś o nie i nie próbuj ich odtworzyć.\n"
        "Zanim odpowiesz na pierwsze pytanie, przeczytaj terminal (terminal_read).\n"
        "Tryb „na żywo”: wiadomości zaczynające się od [NA ŻYWO] zawierają nowe "
        "wyjście terminala, wysłane automatycznie. Odpowiedz na nie tylko wtedy, "
        "gdy jest coś ważnego (błąd, ostrzeżenie, wynik komendy, o którą prosiłeś "
        "albo o który pytał administrator) — krótko. Jeśli nic istotnego, odpowiedz "
        f"dokładnie jednym słowem: {LIVE_SILENT}"
    )


def screen_system_prompt(label: str) -> str:
    """An RDP tab (2026-11-13): Claude looks at screenshots, read only."""
    return (
        "Działasz w HospitalHub jako „Wsparcie Claude” dla jednej sesji pulpitu "
        f"zdalnego (RDP): {label}. Rozmawiasz z administratorem po polsku, krótko "
        "i konkretnie.\n"
        "Masz jedno narzędzie: screen_capture — zrzut ekranu tej sesji RDP. Nie "
        "możesz niczego kliknąć, wpisać ani uruchomić: wszystko robi administrator. "
        "Gdy coś trzeba zrobić, opisz dokładnie, gdzie kliknąć lub co wpisać "
        "(komendy PowerShell/cmd w bloku kodu, jedna linia, gotowe do przepisania) "
        "i jednym zdaniem napisz, po co; potem zrób nowy zrzut i sprawdź wynik.\n"
        "Zasady: to komputery i serwery szpitalne, często produkcyjne. Najpierw "
        "proponuj czynności tylko do odczytu (podgląd zdarzeń, usługi, menedżer "
        "zadań, Get-Service, Get-EventLog -Newest, Get-Process, dir, type). Gdy "
        "proponujesz coś, co zmienia stan (restart usługi lub komputera, usuwanie "
        "plików, zmiany w rejestrze, instalacja), wyraźnie to zaznacz i opisz "
        "skutki. Nigdy nie proś o hasła. Na ekranie mogą być dane osobowe "
        "pacjentów — zrzuty NIE są maskowane: nie przepisuj tych danych w "
        "odpowiedzi i nie opisuj ich bez potrzeby.\n"
        "Zanim odpowiesz na pierwsze pytanie, zrób zrzut ekranu (screen_capture)."
    )


#: A screenshot for Claude: the long side at most this many pixels (more
#: is scaled down by the model anyway, and costs the owner's subscription),
#: and at most this many bytes before it is sent as JPEG instead of PNG.
_SCREEN_MAX_SIDE = 1568
_SCREEN_MAX_PNG = 2_500_000


def encode_screenshot(image) -> tuple[str, str, int, int]:
    """(base64, mime type, width, height) of a screenshot for Claude."""
    import base64
    from PyQt6.QtCore import QBuffer, QByteArray, QIODevice
    if max(image.width(), image.height()) > _SCREEN_MAX_SIDE:
        image = image.scaled(_SCREEN_MAX_SIDE, _SCREEN_MAX_SIDE,
                             Qt.AspectRatioMode.KeepAspectRatio,
                             Qt.TransformationMode.SmoothTransformation)

    def encode(fmt: str, quality: int = -1) -> bytes:
        data = QByteArray()
        buf = QBuffer(data)
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        image.save(buf, fmt, quality)
        buf.close()
        return bytes(data)

    raw, mime = encode("PNG"), "image/png"
    if len(raw) > _SCREEN_MAX_PNG:
        raw, mime = encode("JPG", 85), "image/jpeg"
    return base64.b64encode(raw).decode("ascii"), mime, image.width(), image.height()


def new_lines(previous: list[str], current: list[str]) -> list[str]:
    """What `current` adds after `previous`: the rows after the last place
    where the end of `previous` appears in `current` (all of `current` when
    it does not — a cleared screen)."""
    anchor = [line for line in previous if line.strip()][-4:]
    if not anchor:
        return [line for line in current]
    rows = current
    for start in range(len(rows) - len(anchor), -1, -1):
        if [r for r in rows[start:start + len(anchor)]] == anchor:
            return rows[start + len(anchor):]
    return list(rows)


class _Job:
    """One tool call from the server thread, answered by the UI thread."""

    def __init__(self, name: str, arguments: dict):
        self.name = name
        self.arguments = arguments
        self.event = threading.Event()
        self.result: tuple[str, bool] = ("HospitalHub: brak odpowiedzi.", True)

    def finish(self, text: str, is_error: bool = False) -> None:
        if not self.event.is_set():
            self.result = (text, is_error)
            self.event.set()


#: Fenced code blocks of an answer — the commands it proposes.
_CODE_BLOCK = re.compile(r"```[^\n]*\n(.*?)```", re.S)


def code_blocks(markdown: str) -> list[str]:
    return [b.strip() for b in _CODE_BLOCK.findall(markdown or "") if b.strip()]


def wrapped_html(markdown: str) -> str:
    """Markdown as HTML in which code wraps too (a long command line pushed
    the whole conversation wider than the panel — measured 2026-10-20)."""
    doc = QTextDocument()
    doc.setMarkdown(markdown or "")
    html = doc.toHtml()
    return html.replace("white-space:pre;", "white-space:pre-wrap;").replace(
        "white-space: pre;", "white-space: pre-wrap;")


def _trim(text: str) -> str:
    lines = text.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines[-_MAX_LINES:])[-_MAX_CHARS:]


class TypingBubble(QWidget):
    """A speech bubble with three dots rising and fading in a wave — Claude is
    writing, or looking at new output in live mode (owner, 2026-10-20)."""

    _SIZE = (58, 30)
    _FRAME_MS = 40

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(*self._SIZE)
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(self._FRAME_MS)
        self._timer.timeout.connect(self._step)

    def start(self) -> None:
        self._timer.start()
        self.show()

    def stop(self) -> None:
        self._timer.stop()
        self.hide()

    def running(self) -> bool:
        return self._timer.isActive()

    def _step(self) -> None:
        self._phase = (self._phase + 0.22) % (2 * math.pi)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        body = QRectF(1, 1, w - 2, h - 7)
        p.setPen(QPen(QColor(ACCENT_DIM), 1))
        p.setBrush(QColor("#161b22"))
        p.drawRoundedRect(body, 11, 11)
        # the little tail at the bottom left
        from PyQt6.QtGui import QPolygonF
        from PyQt6.QtCore import QPointF
        p.setPen(Qt.PenStyle.NoPen)
        p.drawPolygon(QPolygonF([QPointF(9, h - 7), QPointF(17, h - 7), QPointF(7, h - 1)]))
        p.setPen(QPen(QColor(ACCENT_DIM), 1))
        p.drawLine(QPointF(7, h - 1), QPointF(9, h - 7.5))
        p.drawLine(QPointF(7, h - 1), QPointF(17, h - 7.5))
        cy = body.center().y()
        for i in range(3):
            wave = math.sin(self._phase - i * 0.75)          # -1 … 1
            lift = max(0.0, wave) * 3.0
            colour = QColor(ACCENT)
            colour.setAlphaF(0.35 + 0.65 * (wave + 1) / 2)
            p.setBrush(colour)
            p.setPen(Qt.PenStyle.NoPen)
            p.drawEllipse(QPointF(w / 2 - 12 + i * 12, cy - lift), 3.2, 3.2)
        p.end()


class ClaudeSupportPanel(QWidget):
    """The conversation and the Claude Code process behind it."""

    closed = pyqtSignal()
    #: "Zamknij" after the end: the owner wants the panel gone (2026-10-21).
    dismissed = pyqtSignal()
    _tool_request = pyqtSignal(object)
    _process_event = pyqtSignal(str, object)

    _titled = pyqtSignal(str)

    def __init__(self, target, parent=None, *, process_factory=None,
                 server_factory=None, find_claude=None, store=None, thread=None,
                 title_maker=None):
        super().__init__(parent)
        # Threads (2026-11-13): with a store, the conversation is a Claude
        # Code session of our id, kept only when the owner saves it;
        # `thread` resumes a saved one.  Without a store nothing is kept.
        self._store = store
        self._thread = thread
        self._saved = thread is not None
        self._title = thread.get("title", "") if thread else ""
        self._log: list[dict] = list(thread.get("messages", [])) if thread else []
        self._title_maker = title_maker
        if store is not None:
            import claude_threads as ct
            self._session_id = thread["id"] if thread else ct.new_session_id()
        else:
            self._session_id = None
        self._titled.connect(self._on_titled, Qt.ConnectionType.QueuedConnection)
        self.setObjectName("claudePanel")
        # A plain QWidget paints a style-sheet border only with this.
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(_PANEL_STYLE)
        self.setMinimumWidth(320)
        self._target = target
        #: An RDP tab: screenshots instead of text, no live mode (2026-11-13).
        self._screen = getattr(target, "kind", lambda: "terminal")() == "screen"
        self._process_factory = process_factory or cs.ClaudeProcess
        self._server_factory = server_factory or cs.ToolServer
        self._find_claude = find_claude or cs.find_claude
        self._server = None
        self._process = None
        self._busy = False
        self._ended = False
        self._live_timer = QTimer(self)
        self._live_timer.setInterval(_LIVE_POLL_MS)
        self._live_timer.timeout.connect(self._live_tick)
        self._live_seen: list[str] = []
        self._live_text = None
        self._live_changed = 0.0
        self._live_sent_at = 0.0
        self._live_turn = False
        self._live_spoke = False
        self._typing_row = None
        self._tool_request.connect(self._on_tool_request,
                                   Qt.ConnectionType.QueuedConnection)
        self._process_event.connect(self._on_process_event,
                                    Qt.ConnectionType.QueuedConnection)
        self._build()

    # -- layout -------------------------------------------------------------- #

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 8, 10, 10)
        root.setSpacing(6)

        head = QHBoxLayout()
        title = QLabel("Wsparcie Claude")
        title.setObjectName("claudeTitle")
        head.addWidget(title)
        head.addStretch()
        self._btn_live = QPushButton("Na żywo")
        self._btn_live.setObjectName("claudeLive")
        self._btn_live.setCheckable(True)
        self._btn_live.setToolTip(
            "Claude śledzi terminal i komentuje nowe wyjście, gdy jest w nim coś "
            "ważnego (najwyżej co 15 s; każda aktualizacja zużywa subskrypcję)")
        self._btn_live.toggled.connect(self._toggle_live)
        head.addWidget(self._btn_live)
        # RDP: a screenshot only when the owner asks something (his choice
        # of 2026-11-13) — no live mode sending the screen by itself.
        self._btn_live.setVisible(not self._screen)
        self._btn_save = QPushButton("Zapamiętaj")
        self._btn_save.setToolTip(
            "Zapisz tę rozmowę jako wątek — dostanie nazwę z treści i wrócisz do "
            "niej z listy „Wątki” (Claude będzie pamiętał całą rozmowę)")
        self._btn_save.clicked.connect(self._save_thread)
        self._btn_save.setVisible(self._store is not None)
        head.addWidget(self._btn_save)
        self._btn_end = QPushButton("Zakończ")
        self._btn_end.setToolTip("Zakończ wsparcie — Claude traci dostęp do terminala")
        self._btn_end.clicked.connect(self._end_or_dismiss)
        head.addWidget(self._btn_end)
        root.addLayout(head)

        self._masked = 0
        self._shots = 0
        self._scope = QLabel(self._scope_text())
        self._scope.setWordWrap(True)
        self._scope.setStyleSheet("color: #8b949e; font-size: 11px;")
        root.addWidget(self._scope)
        self._thread_lbl = QLabel("")
        self._thread_lbl.setWordWrap(True)
        self._thread_lbl.setStyleSheet(f"color: {ACCENT_HOVER}; font-size: 12px;"
                                       " font-weight: bold;")
        self._thread_lbl.hide()
        root.addWidget(self._thread_lbl)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        body = QWidget()
        self._messages = QVBoxLayout(body)
        self._messages.setContentsMargins(0, 0, 0, 0)
        self._messages.setSpacing(8)
        self._messages.addStretch()
        self._scroll.setWidget(body)
        root.addWidget(self._scroll, 1)

        self._state = QLabel("")
        self._state.setStyleSheet("color: #8b949e; font-size: 11px;")
        root.addWidget(self._state)

        row = QHBoxLayout()
        self._input = QPlainTextEdit()
        self._input.setPlaceholderText(
            "Napisz, co sprawdzić… (Enter — wyślij, Shift+Enter — nowa linia)")
        self._input.setFixedHeight(64)
        self._input.installEventFilter(self)
        row.addWidget(self._input, 1)
        self._btn_send = QPushButton("Wyślij")
        self._btn_send.setObjectName("claudeSend")
        self._btn_send.clicked.connect(self._send)
        row.addWidget(self._btn_send)
        root.addLayout(row)

    def eventFilter(self, obj, event):
        from PyQt6.QtCore import QEvent
        if (obj is self._input and event.type() == QEvent.Type.KeyPress
                and event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
                and not event.modifiers() & Qt.KeyboardModifier.ShiftModifier):
            self._send()
            return True
        return super().eventFilter(obj, event)

    def _add(self, widget: QWidget) -> None:
        self._messages.insertWidget(self._messages.count() - 1, widget)
        if self._typing_row is not None and self._typing_row.isVisible():
            # Claude is still at it: the dots stay under the newest message.
            self._messages.removeWidget(self._typing_row)
            self._messages.insertWidget(self._messages.count() - 1, self._typing_row)
        QTimer.singleShot(30, lambda: self._scroll.verticalScrollBar().setValue(
            self._scroll.verticalScrollBar().maximum()))

    def _show_typing(self) -> None:
        if self._typing_row is None:
            row = QWidget()
            lay = QHBoxLayout(row)
            lay.setContentsMargins(2, 0, 0, 0)
            self._typing = TypingBubble(row)
            lay.addWidget(self._typing)
            lay.addStretch()
            self._typing_row = row
        else:
            self._messages.removeWidget(self._typing_row)
        self._typing_row.show()
        self._add(self._typing_row)
        self._typing.start()

    def _hide_typing(self) -> None:
        if self._typing_row is not None:
            self._typing.stop()
            self._typing_row.hide()

    def _bubble(self, text: str, who: str, *, replay: bool = False) -> QLabel:
        if not replay and who in ("user", "claude"):
            self._log.append({"who": who, "text": text})
        lbl = QLabel()
        lbl.setWordWrap(True)
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse
                                    | Qt.TextInteractionFlag.LinksAccessibleByMouse)
        lbl.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        if who == "user":
            lbl.setTextFormat(Qt.TextFormat.PlainText)
            lbl.setStyleSheet("background: #1f3a5f; color: #e6edf3; border-radius: 8px;"
                              " padding: 8px; font-size: 12px;")
        elif who == "claude":
            lbl.setTextFormat(Qt.TextFormat.RichText)
            lbl.setStyleSheet("background: #161b22; color: #e6edf3; border-radius: 8px;"
                              " padding: 8px; font-size: 12px;")
            lbl.setText(wrapped_html(text))
            self._add(lbl)
            self._copy_buttons(code_blocks(text))
            return lbl
        else:
            lbl.setTextFormat(Qt.TextFormat.PlainText)
            colour = "#f85149" if who == "error" else "#8b949e"
            lbl.setStyleSheet(f"color: {colour}; font-size: 11px; padding: 0 4px;")
        lbl.setText(text)
        self._add(lbl)
        return lbl

    def _copy_buttons(self, commands: list[str]) -> None:
        """A "Kopiuj" under each proposed command — the owner types (pastes)
        every command himself."""
        for command in commands[:4]:
            row = QWidget()
            lay = QHBoxLayout(row)
            lay.setContentsMargins(4, 0, 0, 0)
            shown = command if len(command) <= 60 else command[:57] + "…"
            btn = QPushButton(f"Kopiuj: {shown}")
            btn.setToolTip(command)
            btn.setStyleSheet("QPushButton { text-align: left; font-family: Consolas, "
                              "monospace; font-size: 11px; padding: 3px 8px; }")
            btn.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
            btn.clicked.connect(lambda _, c=command, b=btn: self._copy(c, b))
            lay.addWidget(btn)
            self._add(row)

    def _copy(self, command: str, button: QPushButton) -> None:
        QApplication.clipboard().setText(command)
        button.setText("Skopiowano — wklej w terminalu (prawy klik / Ctrl+Shift+V)")

    def _set_busy(self, busy: bool, text: str = "") -> None:
        self._busy = busy
        self._btn_send.setEnabled(not busy and not self._ended)
        self._state.setText(text)
        if busy and not self._ended:
            self._show_typing()
        else:
            self._hide_typing()

    # -- lifecycle ----------------------------------------------------------- #

    def start(self) -> bool:
        """Start the tool server and Claude Code.  False when it cannot run."""
        if not self._find_claude():
            self._bubble("Nie znaleziono Claude Code na tym komputerze. Zainstaluj "
                         "Claude Code i zaloguj się (uruchom raz „claude” w terminalu), "
                         "potem otwórz wsparcie ponownie.", "error")
            self._finish_ui()
            return False
        on_event = lambda kind, payload: self._process_event.emit(kind, payload)  # noqa: E731
        session = {}
        if self._store is not None:
            import claude_threads as ct
            session = dict(session_id=self._session_id, resume=self._saved,
                           cwd=ct.workdir())
            # Records of conversations that never ended cleanly go now.
            self._store.sweep(keep=_LIVE_SESSIONS | {self._session_id})
            if self._saved:
                # The sealed record back where Claude Code reads it — readable
                # only while this conversation runs (2026-11-13).
                try:
                    opened = self._store.open_record(self._session_id)
                except ct.ThreadsLocked:
                    opened = False
                if not opened:
                    self._bubble("Nie można otworzyć zapisu tego wątku. Wątki są "
                                 "zaszyfrowane hasłem vaulta — zaloguj się do vaulta, "
                                 "w którym rozmowa została zapamiętana.", "error")
                    self._finish_ui()
                    return False
            self._store.started(self._session_id, saved=self._saved)
            _LIVE_SESSIONS.add(self._session_id)
        if self._screen:
            self._server = self._server_factory(self._handle_tool,
                                                tools=cs.SCREEN_TOOLS)
            url = self._server.start()
            self._process = self._process_factory(
                url, self._server.token, screen_system_prompt(self._target.label()),
                on_event, tools=cs.SCREEN_TOOLS, **session)
        else:
            self._server = self._server_factory(self._handle_tool)
            url = self._server.start()
            self._process = self._process_factory(
                url, self._server.token, system_prompt(self._target.label()),
                on_event, **session)
        try:
            self._process.start()
        except Exception as exc:
            self._bubble(f"Nie udało się uruchomić Claude Code ({type(exc).__name__}).",
                         "error")
            self.end()
            return False
        if self._thread is not None:
            self._replay(self._thread)
            return True
        if self._screen:
            self._bubble("Claude widzi tę jedną sesję RDP — robi zrzut ekranu, gdy "
                         "o coś zapytasz, i podpowiada, co zrobić; klikasz i piszesz "
                         "sam. UWAGA: zrzut trafia do Claude'a w całości — obrazu nie "
                         "da się zamaskować, więc dane pacjentów widoczne na ekranie "
                         "(także PESEL) zostaną wysłane. Zasłoń je przed pytaniem.",
                         "info")
        else:
            self._bubble("Claude widzi tę jedną kartę terminala (ekran i historię) i "
                         "podpowiada komendy — wpisujesz je sam. Treść terminala trafia "
                         "do Claude'a; numery PESEL są przed wysłaniem zamieniane na "
                         f"{cs.PESEL_MASK}, inne dane pacjentów — nie.", "info")
        self._set_busy(False, "Gotowy.")
        self._input.setFocus()
        return True

    def ended(self) -> bool:
        """The conversation is over (the panel stays for reading)."""
        return self._ended

    def end(self) -> None:
        """Stop Claude Code and the tool server."""
        if self._ended:
            return
        self._ended = True
        process, self._process = self._process, None
        if process is not None:
            try:
                process.stop()
            except Exception:
                pass
        server, self._server = self._server, None
        if server is not None:
            server.stop()
        self._close_thread()
        self._finish_ui()
        self.closed.emit()

    # -- threads (2026-11-13) ------------------------------------------------ #

    def _replay(self, thread: dict) -> None:
        """A saved thread comes back: its messages, then "resumed"."""
        for m in thread.get("messages", []):
            if m.get("who") in ("user", "claude"):
                self._bubble(m.get("text", ""), m["who"], replay=True)
        self._show_thread_title()
        self._bubble(f"Wznowiono wątek „{self._title}” — Claude pamięta tę rozmowę. "
                     f"Teraz: {self._target.label()}.", "info")
        self._set_busy(False, "Gotowy.")
        self._input.setFocus()

    def _show_thread_title(self) -> None:
        self._thread_lbl.setText(f"Wątek: {self._title}")
        self._thread_lbl.show()
        self._btn_save.setText("Zapamiętano")
        self._btn_save.setEnabled(False)
        self._btn_save.setToolTip("Ta rozmowa jest zapisana — lista „Wątki” obok "
                                  "przycisku Wsparcie Claude")

    def thread_id(self) -> str | None:
        return self._session_id

    def _save_thread(self) -> None:
        """"Zapamiętaj": saved at once under a provisional name, then renamed
        by Claude from the content (a short Haiku call in the background)."""
        if self._store is None or self._saved or self._ended:
            return
        import claude_threads as ct
        if not self._store.unlocked:
            self._bubble("Nie można zapamiętać: wątki są szyfrowane hasłem vaulta, "
                         "a klucz jeszcze nie jest odblokowany. Zaloguj się do vaulta "
                         "szpitali i spróbuj ponownie.", "error")
            return
        self._saved = True
        self._title = ct.fallback_title(self._log)
        self._store.save(self._session_id, title=self._title, kind=self._kind(),
                         label=self._target.label(), messages=self._log)
        self._show_thread_title()
        self._btn_save.setText("Nadaję nazwę…")
        maker = self._title_maker or ct.make_title
        messages, label = list(self._log), self._target.label()
        threading.Thread(target=lambda: self._titled.emit(maker(messages, label)),
                         name="claude-title", daemon=True).start()

    def _on_titled(self, title: str) -> None:
        if not title or self._store is None:
            return
        self._title = title
        try:
            self._store.rename(self._session_id, title)
        except Exception:
            pass
        self._show_thread_title()

    def _kind(self) -> str:
        return "screen" if self._screen else "terminal"

    def _sync_thread(self) -> None:
        """A saved thread keeps its newest messages."""
        if self._store is not None and self._saved:
            try:
                self._store.save(self._session_id, title=self._title,
                                 kind=self._kind(), label=self._target.label(),
                                 messages=self._log)
            except Exception:
                pass                         # locked meanwhile: the record stays

    def _close_thread(self) -> None:
        if self._store is None or self._session_id is None:
            return
        _LIVE_SESSIONS.discard(self._session_id)
        if self._saved:
            self._sync_thread()
        # Once the process has let go of Claude Code's record: a saved thread's
        # is sealed (encrypted, the plain file deleted), an unsaved one deleted.
        store, sid = self._store, self._session_id
        timer = threading.Timer(4.0, lambda: store.finished(sid))
        timer.daemon = True
        timer.start()

    def _finish_ui(self) -> None:
        self._ended = True
        self._hide_typing()
        self._live_timer.stop()
        self._btn_live.setEnabled(False)
        self._input.setEnabled(False)
        self._btn_send.setEnabled(False)
        # The panel stays for reading — an error included ("Claude Code not
        # found", no connection) — and "Zakończ" becomes "Zamknij": before,
        # it was disabled and nothing closed the panel short of closing the
        # tab (owner, 2026-10-21).
        self._btn_end.setText("Zamknij")
        self._btn_end.setToolTip("Zamknij panel wsparcia")
        if not self._saved:
            # The record of an unsaved conversation is deleted at the end.
            self._btn_save.setEnabled(False)
            self._btn_save.setToolTip("Zapamiętać można rozmowę, która trwa")
        self._state.setText("Wsparcie zakończone.")

    def _end_or_dismiss(self) -> None:
        if self._ended:
            self.dismissed.emit()
        else:
            self.end()

    def target_gone(self) -> None:
        self._bubble("Karta terminala została zamknięta.", "info")
        self.end()

    # -- PESEL masking (2026-10-21) ------------------------------------------ #

    def _scope_text(self) -> str:
        if self._screen:
            text = (f"RDP: {self._target.label()} · tylko odczyt · zrzuty ekranu "
                    f"bez maskowania")
            if self._shots:
                text += f" · wysłane zrzuty: {self._shots}"
            return text
        text = f"Terminal: {self._target.label()} · tylko odczyt"
        if self._masked:
            text += f" · zamaskowane PESEL: {self._masked}"
        return text

    def _mask(self, text: str) -> str:
        """Every text for Claude passes here (cs.mask_pesel); the header
        counts what was masked."""
        text, n = cs.mask_pesel(text)
        if n:
            self._masked += n
            self._scope.setText(self._scope_text())
        return text

    # -- talking ------------------------------------------------------------- #

    def _send(self) -> None:
        text = self._input.toPlainText().strip()
        if not text or self._busy or self._ended or self._process is None:
            return
        self._input.clear()
        text = self._mask(text)          # the bubble shows what was sent
        self._bubble(text, "user")
        try:
            self._process.send(text)
        except Exception as exc:
            self._bubble(f"Claude Code nie odpowiada ({type(exc).__name__}).", "error")
            return
        self._set_busy(True, "Claude myśli…")

    def _on_process_event(self, kind: str, payload) -> None:
        if self._ended:
            return
        if kind == "ready" and not payload.get("connected", False):
            # Without the terminal there is nothing to talk about: ended at
            # once, so "Zamknij" is one click away (2026-10-21).
            self._bubble("Claude Code nie połączył się z terminalem HospitalHub. "
                         "Zamknij panel i spróbuj ponownie.", "error")
            self.end()
        elif kind == "text":
            if self._live_turn and str(payload).strip().rstrip(".") == LIVE_SILENT:
                pass                      # nothing worth saying about the news
            else:
                self._live_spoke = True
                self._bubble(str(payload), "claude")
        elif kind == "tool":
            self._state.setText("Claude patrzy na ekran…" if self._screen
                                else "Claude czyta terminal…")
        elif kind == "turn_end":
            if payload.get("is_error"):
                self._bubble(_login_hint(payload.get("text", "")), "error")
            live, self._live_turn = self._live_turn, False
            spoke, self._live_spoke = self._live_spoke, False
            self._set_busy(False, "Na żywo: bez uwag." if live and not spoke else "")
            self._sync_thread()
        elif kind == "exit":
            stderr = str(payload.get("stderr") or "")
            self._bubble("Claude Code zakończył działanie."
                         + (f"\n{_login_hint(stderr)}" if stderr else ""), "error")
            self.end()

    # -- live mode --------------------------------------------------------- #

    def _toggle_live(self, on: bool) -> None:
        if self._ended or self._screen:
            return
        if on:
            self._live_seen = self._tail()
            self._live_text = None
            self._live_sent_at = 0.0
            self._live_timer.start()
            self._bubble("Na żywo: Claude śledzi terminal i odezwie się, gdy w nowym "
                         "wyjściu będzie coś ważnego.", "info")
        else:
            self._live_timer.stop()
            self._bubble("Na żywo wyłączone.", "info")

    def _tail(self) -> list[str]:
        if not self._target.alive():
            return []
        return self._target.read(_LIVE_MAX_LINES * 2).splitlines()

    def _live_tick(self) -> None:
        import time
        if self._ended or not self._target.alive():
            return
        text = "\n".join(self._tail())
        now = time.monotonic()
        if text != self._live_text:
            self._live_text, self._live_changed = text, now
            return
        if (self._busy or now - self._live_changed < _LIVE_QUIET_S
                or now - self._live_sent_at < _LIVE_MIN_GAP_S):
            return
        current = text.splitlines()
        added = [line for line in new_lines(self._live_seen, current)]
        if not any(line.strip() for line in added):
            return
        self._live_seen = current
        self._live_sent_at = now
        chunk = self._mask("\n".join(added[-_LIVE_MAX_LINES:]).strip())
        try:
            self._process.send(f"[NA ŻYWO] Nowe wyjście w terminalu:\n```\n{chunk}\n```")
        except Exception:
            return
        self._live_turn = True
        self._set_busy(True, "Na żywo: Claude patrzy na nowe wyjście…")

    # -- the read tool (server thread → UI thread) ---------------------------- #

    def _handle_tool(self, name: str, arguments: dict):
        """Runs in the tool server's thread; the terminal is read in the UI's."""
        if name != (cs.TOOL_SCREEN if self._screen else cs.TOOL_READ):
            return "Nieznane narzędzie.", True
        job = _Job(name, arguments)
        self._tool_request.emit(job)
        if not job.event.wait(_READ_TIMEOUT_S):
            return "HospitalHub nie odpowiedział — spróbuj ponownie.", True
        return job.result

    def _on_tool_request(self, job: _Job) -> None:
        if self._ended:
            return job.finish("Wsparcie zakończone.", True)
        if not self._target.alive():
            return job.finish("Karta terminala jest zamknięta albo rozłączona.", True)
        if self._screen:
            return self._capture_for(job)
        try:
            lines = int(job.arguments.get("lines") or 150)
        except (TypeError, ValueError):
            lines = 150
        lines = max(10, min(lines, 2000))
        job.finish(_trim(self._mask(self._target.read(lines)))
                   or "(terminal jest pusty)")


    def _capture_for(self, job: _Job) -> None:
        """A screenshot of the RDP tab for Claude, shown small in the
        conversation too — the owner sees what left."""
        image = self._target.capture()
        if image is None:
            return job.finish("Nie udało się zrobić zrzutu — sesja RDP nie jest "
                              "połączona albo jej karta nie jest widoczna. Poproś "
                              "administratora, żeby przełączył się na tę kartę.", True)
        try:
            data, mime, w, h = encode_screenshot(image)
        except Exception as exc:
            return job.finish(f"Zrzut się nie udał ({type(exc).__name__}).", True)
        self._shots += 1
        self._scope.setText(self._scope_text())
        self._thumbnail(image)
        job.finish(cs.image_result(data, mime, f"Zrzut ekranu sesji RDP, {w}×{h} px."))

    def _thumbnail(self, image) -> None:
        from PyQt6.QtGui import QPixmap
        lbl = QLabel()
        thumb = image.scaledToWidth(min(260, image.width()),
                                    Qt.TransformationMode.SmoothTransformation)
        lbl.setPixmap(QPixmap.fromImage(thumb))
        lbl.setToolTip("Ten zrzut ekranu został wysłany do Claude'a")
        lbl.setStyleSheet(f"border: 1px solid {ACCENT_DIM}; border-radius: 4px;")
        row = QWidget()
        lay = QVBoxLayout(row)
        lay.setContentsMargins(4, 0, 0, 0)
        lay.setSpacing(2)
        cap = QLabel("Wysłany zrzut ekranu:")
        cap.setStyleSheet("color: #8b949e; font-size: 11px;")
        lay.addWidget(cap)
        lay.addWidget(lbl, 0, Qt.AlignmentFlag.AlignLeft)
        self._add(row)


def _login_hint(text: str) -> str:
    low = text.lower()
    if any(k in low for k in ("login", "log in", "authenticate", "api key", "unauthorized")):
        return ("Claude Code nie jest zalogowany na tym komputerze. Uruchom „claude” "
                "w terminalu, zaloguj się (/login) i otwórz wsparcie ponownie.")
    return text.strip()[:600] or "Błąd Claude Code."
