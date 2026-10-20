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

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QTextDocument
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
        "pacjentów — nie powtarzaj ich bez potrzeby.\n"
        "Zanim odpowiesz na pierwsze pytanie, przeczytaj terminal (terminal_read).\n"
        "Tryb „na żywo”: wiadomości zaczynające się od [NA ŻYWO] zawierają nowe "
        "wyjście terminala, wysłane automatycznie. Odpowiedz na nie tylko wtedy, "
        "gdy jest coś ważnego (błąd, ostrzeżenie, wynik komendy, o którą prosiłeś "
        "albo o który pytał administrator) — krótko. Jeśli nic istotnego, odpowiedz "
        f"dokładnie jednym słowem: {LIVE_SILENT}"
    )


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


class ClaudeSupportPanel(QWidget):
    """The conversation and the Claude Code process behind it."""

    closed = pyqtSignal()
    _tool_request = pyqtSignal(object)
    _process_event = pyqtSignal(str, object)

    def __init__(self, target, parent=None, *, process_factory=None,
                 server_factory=None, find_claude=None):
        super().__init__(parent)
        self.setObjectName("claudePanel")
        # A plain QWidget paints a style-sheet border only with this.
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(_PANEL_STYLE)
        self.setMinimumWidth(320)
        self._target = target
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
        self._btn_end = QPushButton("Zakończ")
        self._btn_end.setToolTip("Zakończ wsparcie — Claude traci dostęp do terminala")
        self._btn_end.clicked.connect(self.end)
        head.addWidget(self._btn_end)
        root.addLayout(head)

        self._scope = QLabel(f"Terminal: {self._target.label()} · tylko odczyt")
        self._scope.setWordWrap(True)
        self._scope.setStyleSheet("color: #8b949e; font-size: 11px;")
        root.addWidget(self._scope)

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
        QTimer.singleShot(30, lambda: self._scroll.verticalScrollBar().setValue(
            self._scroll.verticalScrollBar().maximum()))

    def _bubble(self, text: str, who: str) -> QLabel:
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

    # -- lifecycle ----------------------------------------------------------- #

    def start(self) -> bool:
        """Start the tool server and Claude Code.  False when it cannot run."""
        if not self._find_claude():
            self._bubble("Nie znaleziono Claude Code na tym komputerze. Zainstaluj "
                         "Claude Code i zaloguj się (uruchom raz „claude” w terminalu), "
                         "potem otwórz wsparcie ponownie.", "error")
            self._finish_ui()
            return False
        self._server = self._server_factory(self._handle_tool)
        url = self._server.start()
        self._process = self._process_factory(
            url, self._server.token, system_prompt(self._target.label()),
            lambda kind, payload: self._process_event.emit(kind, payload))
        try:
            self._process.start()
        except Exception as exc:
            self._bubble(f"Nie udało się uruchomić Claude Code ({type(exc).__name__}).",
                         "error")
            self.end()
            return False
        self._bubble("Claude widzi tę jedną kartę terminala (ekran i historię) i "
                     "podpowiada komendy — wpisujesz je sam. Treść terminala trafia "
                     "do Claude'a: pamiętaj o danych pacjentów.", "info")
        self._set_busy(False, "Gotowy.")
        self._input.setFocus()
        return True

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
        self._finish_ui()
        self.closed.emit()

    def _finish_ui(self) -> None:
        self._ended = True
        self._live_timer.stop()
        self._btn_live.setEnabled(False)
        self._input.setEnabled(False)
        self._btn_send.setEnabled(False)
        self._btn_end.setEnabled(False)
        self._state.setText("Wsparcie zakończone.")

    def target_gone(self) -> None:
        self._bubble("Karta terminala została zamknięta.", "info")
        self.end()

    # -- talking ------------------------------------------------------------- #

    def _send(self) -> None:
        text = self._input.toPlainText().strip()
        if not text or self._busy or self._ended or self._process is None:
            return
        self._input.clear()
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
            self._bubble("Claude Code nie połączył się z terminalem HospitalHub.", "error")
        elif kind == "text":
            if self._live_turn and str(payload).strip().rstrip(".") == LIVE_SILENT:
                pass                      # nothing worth saying about the news
            else:
                self._live_spoke = True
                self._bubble(str(payload), "claude")
        elif kind == "tool":
            self._state.setText("Claude czyta terminal…")
        elif kind == "turn_end":
            if payload.get("is_error"):
                self._bubble(_login_hint(payload.get("text", "")), "error")
            live, self._live_turn = self._live_turn, False
            spoke, self._live_spoke = self._live_spoke, False
            self._set_busy(False, "Na żywo: bez uwag." if live and not spoke else "")
        elif kind == "exit":
            stderr = str(payload.get("stderr") or "")
            self._bubble("Claude Code zakończył działanie."
                         + (f"\n{_login_hint(stderr)}" if stderr else ""), "error")
            self.end()

    # -- live mode --------------------------------------------------------- #

    def _toggle_live(self, on: bool) -> None:
        if self._ended:
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
        chunk = "\n".join(added[-_LIVE_MAX_LINES:]).strip()
        try:
            self._process.send(f"[NA ŻYWO] Nowe wyjście w terminalu:\n```\n{chunk}\n```")
        except Exception:
            return
        self._live_turn = True
        self._set_busy(True, "Na żywo: Claude patrzy na nowe wyjście…")

    # -- the read tool (server thread → UI thread) ---------------------------- #

    def _handle_tool(self, name: str, arguments: dict):
        """Runs in the tool server's thread; the terminal is read in the UI's."""
        if name != cs.TOOL_READ:
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
        try:
            lines = int(job.arguments.get("lines") or 150)
        except (TypeError, ValueError):
            lines = 150
        lines = max(10, min(lines, 2000))
        job.finish(_trim(self._target.read(lines)) or "(terminal jest pusty)")


def _login_hint(text: str) -> str:
    low = text.lower()
    if any(k in low for k in ("login", "log in", "authenticate", "api key", "unauthorized")):
        return ("Claude Code nie jest zalogowany na tym komputerze. Uruchom „claude” "
                "w terminalu, zaloguj się (/login) i otwórz wsparcie ponownie.")
    return text.strip()[:600] or "Błąd Claude Code."
