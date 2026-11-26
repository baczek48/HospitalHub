"""The "Aktualizacja" tab of HospitalHub Portable (2026-11-15, owner).

The upgrade of a hospital done from one place:

* the machines of the upgrade in a list whose order is the order of the
  tabs — "Otwórz karty po kolei" opens an SSH tab for each one not open yet;
* "Instrukcja aktualizacji" (2026-11-26, owner): the hospital's own upgrade
  notes ("nasz plik upgrade") on top — read here, edited or loaded from a
  .txt in a bigger window;
* groups (AMMS / WildFly, Platforma / Tomcat, Zdarzenia medyczne, Balancer…)
  with their machines and editable command buttons — a click types the
  command into the terminal of every machine of the group at once, so each
  terminal shows what is going on, and the result comes back here per
  machine (✓ kod 0 / ✗ kod N).

The plan is data of the hospital (``Hospital.upgrade``, see upgrade_plan);
every edit emits ``data_changed`` and the window saves the vault.  Typing
into the terminals is the window's job (``run_requested`` /
``interrupt_requested``); it reports back with ``set_status``.
"""

from __future__ import annotations

import time

from PyQt6.QtCore import Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import (
    QDesktopServices, QFont, QKeySequence, QShortcut, QTextCharFormat,
    QTextCursor, QTextDocument,
)
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFrame,
    QGridLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMenu, QPlainTextEdit, QPushButton, QScrollArea,
    QSizePolicy, QTextEdit, QToolButton, QVBoxLayout, QWidget,
)

import upgrade_plan as up
from ui.hd_download import HdDownloadBox
from ui.icons import set_icon
from ui.utils import confirm

__all__ = ["UpgradePanel", "CommandDialog", "MachinePickDialog", "NotesDialog"]


_MENU_QSS = (
    "QMenu{background:#1a1d28;color:#e1e4eb;border:1px solid #2a2d3a;"
    "border-radius:10px;padding:6px;}"
    "QMenu::item{padding:6px 18px;border-radius:6px;}"
    "QMenu::item:selected{background:#4a5adf;color:#fff;}"
    "QMenu::item:disabled{color:#5a5f72;}"
    "QMenu::separator{height:1px;background:#2a2d3a;margin:4px 10px;}"
)

_BTN_QSS = (
    "QPushButton, QToolButton {{ background:{bg}; color:{fg};"
    " border:1px solid {border}; border-radius:6px; padding:5px 8px;"
    " font-size:11px; }}"
    "QPushButton:hover, QToolButton:hover {{ background:{hover}; color:#fff; }}"
    "QPushButton:disabled {{ color:#5a5f72; }}"
    "QToolButton::menu-indicator {{ width:0; height:0; }}"
)

_CMD_QSS = _BTN_QSS.format(bg="#1a2040", fg="#a5b4ff", border="#3a4070",
                           hover="#4a5adf")
_CMD_DANGER_QSS = _BTN_QSS.format(bg="#2a1a1a", fg="#ff9b8f", border="#5a2d2d",
                                  hover="#b33a3a")
_GREEN_QSS = _BTN_QSS.format(bg="#0d1f0d", fg="#3fb950", border="#1b3d1b",
                             hover="#2d5a2d")
_GREY_QSS = _BTN_QSS.format(bg="#151b23", fg="#8b949e", border="#21262d",
                            hover="#30363d")

_BOX_QSS = (
    "QFrame#upgradeBox { background:#1a1d28; border:1px solid #2a2d3a;"
    " border-radius:10px; }"
    "QLabel { border:none; background:transparent; }"
)

_FIELD_QSS = (
    "QLineEdit, QPlainTextEdit, QTextEdit { background:#14161e; border:1px solid #2a2d3a;"
    " border-radius:6px; padding:4px 6px; color:#c9d1d9; }"
    "QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus { border-color:#4a5adf; }"
)

_SCROLL_QSS = (
    "QScrollBar:vertical { background:#14161e; width:6px; border:none;"
    " border-radius:3px; margin:2px; }"
    "QScrollBar::handle:vertical { background:#2a2d3a; border-radius:3px;"
    " min-height:20px; }"
    "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }"
)

#: state → (mark, colour) of a machine's last result in a group.
STATES = {
    "run":  ("▶", "#58a6ff"),
    "ok":   ("✓", "#3fb950"),
    "fail": ("✗", "#f85149"),
    "miss": ("–", "#d29922"),
    "stop": ("■", "#d29922"),
}


def machine_label(m) -> str:
    return m.ip + (f"  {m.name}" if m.name else "")


def _shrinkable(w):
    """A button may be narrower than its text: the panel is narrow and its
    width is the user's (the splitter) — never pushed out of it."""
    w.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
    w.setMinimumWidth(40)
    return w


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ── Dialogs ──────────────────────────────────────────────────────────────

class CommandDialog(QDialog):
    """Edit one command button."""

    def __init__(self, parent, cmd: dict, group: dict):
        super().__init__(parent)
        self.setWindowTitle("Komenda")
        self.setMinimumWidth(560)
        self.setStyleSheet(_FIELD_QSS)
        lay = QVBoxLayout(self)

        lay.addWidget(QLabel("Nazwa przycisku:"))
        self.label = QLineEdit(cmd.get("label", ""))
        lay.addWidget(self.label)

        lay.addWidget(QLabel("Komendy (każda w osobnej linii — wykonywane po "
                             "kolei, błąd przerywa resztę):"))
        self.text = QPlainTextEdit(cmd.get("text", ""))
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.text.setFont(mono)
        self.text.setMinimumHeight(140)
        lay.addWidget(self.text)

        hint = QLabel("{WERSJA} — wersja wpisana u góry zakładki, "
                      "{DATA} — dzisiejsza data (RRRRMMDD). Linie z # są pomijane.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#8b949e; font-size:10px;")
        lay.addWidget(hint)

        self.confirm = QCheckBox("Pytaj przed wykonaniem")
        self.confirm.setChecked(bool(cmd.get("confirm")))
        lay.addWidget(self.confirm)

        pattern = (group.get("process") or "").strip()
        self.stopped = QCheckBox(
            f"Wymaga zatrzymanej usługi grupy (proces: {pattern})" if pattern
            else "Wymaga zatrzymanej usługi grupy (ustaw proces w grupie)")
        self.stopped.setToolTip(
            "Przed komendą sprawdzany jest proces tej grupy (pgrep -f). "
            "Gdy działa — nic się nie wykona.\nSprawdzany jest tylko proces "
            "tej usługi, nie każda java: WildFly i Tomcat mogą stać na "
            "jednej maszynie.")
        self.stopped.setChecked(bool(cmd.get("requires_stopped")))
        lay.addWidget(self.stopped)

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("Zapisz")
        bb.button(QDialogButtonBox.StandardButton.Cancel).setText("Anuluj")
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _accept(self):
        if not self.label.text().strip() or not self.text.toPlainText().strip():
            self.label.setFocus()
            return
        self.accept()

    def values(self) -> dict:
        return {"label": self.label.text().strip(),
                "text": self.text.toPlainText().rstrip(),
                "confirm": self.confirm.isChecked(),
                "requires_stopped": self.stopped.isChecked()}


def read_text_file(path: str) -> str:
    """A .txt as the user wrote it: UTF-8, else the Windows code page."""
    with open(path, "rb") as f:
        raw = f.read()
    for enc in ("utf-8-sig", "cp1250"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


#: 2026-11-26 (owner): the AMMS GitLab, one click away from the upgrade.
GITLAB_URL = "https://amms.asseco.pl/gitlab/dashboard/projects/member"


def open_gitlab() -> None:
    QDesktopServices.openUrl(QUrl(GITLAB_URL))


#: Base print of the notes; A+ / A− step from it (points).
NOTES_PT = 10
_NOTES_MIN_PT, _NOTES_MAX_PT = 8, 28


def _clean_text(text: str) -> str:
    return text.rstrip() + "\n" if text.strip() else ""


def notes_rich(plan: dict) -> str:
    """The formatted notes, if they still hold the plain notes' text."""
    html = plan.get("notes_html", "") or ""
    if not html:
        return ""
    doc = QTextDocument()
    doc.setHtml(html)
    same = _clean_text(doc.toPlainText()) == _clean_text(plan.get("notes", "") or "")
    return html if same else ""


def _has_format(doc) -> bool:
    """Any bold or resized text — otherwise plain notes are enough."""
    block = doc.begin()
    while block.isValid():
        it = block.begin()
        while not it.atEnd():
            f = it.fragment().charFormat()
            size = f.fontPointSize()
            if f.fontWeight() >= QFont.Weight.DemiBold.value or (
                    size and abs(size - NOTES_PT) > 0.1):
                return True
            it += 1
        block = block.next()
    return False


class NotesDialog(QDialog):
    """The hospital's upgrade instructions, big enough to read and edit.

    2026-11-26 (owner): not modal — the main window stays usable while it
    is open; "Przypnij" keeps it above every window, so a click on the
    main window (or the RDP / browser beside it) does not hide it.  Without
    a parent: unpinned, it may go behind the main window like any window.
    """

    #: (plain text, rich text or "" when nothing is formatted)
    saved = pyqtSignal(str, str)

    def __init__(self, parent, text: str, title: str = "", html: str = ""):
        super().__init__(None)
        self.setWindowFlag(Qt.WindowType.Window, True)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)
        self.setWindowFlag(Qt.WindowType.WindowMinimizeButtonHint, True)
        self.setModal(False)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.setWindowTitle("Instrukcja aktualizacji AMMS"
                            + (f" — {title}" if title else ""))
        if parent is not None and parent.window() is not None:
            self.setWindowIcon(parent.window().windowIcon())
        # Own dark background: without a parent it would get the light
        # system one, with the panel's pale text on it.
        self.setObjectName("notesDialog")
        self.setStyleSheet("QDialog#notesDialog { background:#0d1117; }"
                           "QLabel, QCheckBox { color:#e1e4eb; }")
        self.resize(760, 640)
        lay = QVBoxLayout(self)
        hint = QLabel("Notatki aktualizacji tego szpitala (maszyny, ścieżki, skrypty "
                      "bazy). Zapisywane w vaulcie razem ze szpitalem.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#8b949e; font-size:10px;")
        lay.addWidget(hint)
        # 2026-11-26 (owner): bold and bigger print for what matters.
        fmt_row = QHBoxLayout()
        fmt_row.setSpacing(4)
        self.bold_btn = QToolButton()
        self.bold_btn.setText("B")
        self.bold_btn.setCheckable(True)
        self.bold_btn.setToolTip("Pogrubienie zaznaczenia (Ctrl+B)")
        self.bold_btn.setStyleSheet(_GREY_QSS + "QToolButton { font-weight:bold; "
                                    "min-width:22px; } QToolButton:checked {"
                                    " background:#1c2240; color:#fff; }")
        self.bold_btn.clicked.connect(self.toggle_bold)
        fmt_row.addWidget(self.bold_btn)
        for label, tip, step in (("A+", "Większa czcionka zaznaczenia (Ctrl++)", 2),
                                 ("A−", "Mniejsza czcionka zaznaczenia (Ctrl+-)", -2)):
            b = QToolButton()
            b.setText(label)
            b.setToolTip(tip)
            b.setStyleSheet(_GREY_QSS + "QToolButton { min-width:22px; }")
            b.clicked.connect(lambda _c=False, st=step: self.change_size(st))
            fmt_row.addWidget(b)
        plain = QToolButton()
        plain.setText("Zwykły tekst")
        plain.setToolTip("Usuń pogrubienie i rozmiar z zaznaczenia")
        plain.setStyleSheet(_GREY_QSS)
        plain.clicked.connect(self.clear_format)
        fmt_row.addWidget(plain)
        tip = QLabel("bez zaznaczenia — cała bieżąca linia")
        tip.setStyleSheet("color:#5a5f72; font-size:10px;")
        fmt_row.addWidget(tip)
        fmt_row.addStretch()
        lay.addLayout(fmt_row)

        self.text = QTextEdit()
        self.text.setAcceptRichText(False)      # pasted text comes in plain
        self.text.setStyleSheet(_FIELD_QSS + _SCROLL_QSS + _SCROLL_QSS.replace(
            "vertical", "horizontal").replace("width:6px", "height:6px")
            .replace("min-height", "min-width").replace("{ height:0; }", "{ width:0; }"))
        self.text.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        mono.setPointSize(NOTES_PT)
        self.text.setFont(mono)
        self.text.document().setDefaultFont(mono)
        self.text.cursorPositionChanged.connect(self._show_bold)
        lay.addWidget(self.text, 1)
        for keys, slot in (("Ctrl+B", self.toggle_bold),
                           ("Ctrl++", lambda: self.change_size(2)),
                           ("Ctrl+=", lambda: self.change_size(2)),
                           ("Ctrl+-", lambda: self.change_size(-2))):
            QShortcut(QKeySequence(keys), self.text, activated=slot)
        self._fill(text, html)
        self._clean = (self.value(), self.html())

        row = QHBoxLayout()
        load = QPushButton("Wczytaj z pliku…")
        set_icon(load, "folder", "#8b949e", size=13)
        load.setStyleSheet(_GREY_QSS)
        load.setAutoDefault(False)
        load.clicked.connect(self._load)
        row.addWidget(load)
        git = QPushButton("GitLab AMMS")
        set_icon(git, "external", "#a5b4ff", size=13)
        git.setStyleSheet(_CMD_QSS)
        git.setAutoDefault(False)
        git.setToolTip(GITLAB_URL)
        git.clicked.connect(open_gitlab)
        row.addWidget(git)
        self.pin = QCheckBox("Przypnij (zawsze na wierzchu)")
        self.pin.setStyleSheet("QCheckBox { color:#e1e4eb; font-size:11px; }")
        self.pin.setToolTip("Okno zostaje nad innymi oknami — kliknięcie w główne "
                            "okno go nie chowa")
        self.pin.toggled.connect(self.set_pinned)
        row.addWidget(self.pin)
        row.addStretch()
        self.save_btn = QPushButton("Zapisz")
        self.save_btn.setAutoDefault(False)
        self.save_btn.setStyleSheet(_GREEN_QSS)
        self.save_btn.clicked.connect(self._save)
        row.addWidget(self.save_btn)
        close = QPushButton("Zamknij")
        close.setAutoDefault(False)
        close.setStyleSheet(_GREY_QSS)
        close.clicked.connect(self.close)
        row.addWidget(close)
        lay.addLayout(row)

    # ── pinning ──
    def set_pinned(self, on: bool) -> None:
        if self.pin.isChecked() != on:
            self.pin.setChecked(on)     # comes back here through toggled
            return
        visible = self.isVisible()
        geo = self.geometry()
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, on)
        if visible:                     # a flag change hides the window
            self.setGeometry(geo)
            self.show()
            self.raise_()

    def is_pinned(self) -> bool:
        return bool(self.windowFlags() & Qt.WindowType.WindowStaysOnTopHint)

    # ── text ──
    def _load(self):
        path, _f = QFileDialog.getOpenFileName(
            self, "Wczytaj instrukcję aktualizacji", "",
            "Pliki tekstowe (*.txt *.md *.log);;Wszystkie pliki (*)")
        if not path:
            return
        try:
            text = read_text_file(path)
        except OSError as e:
            self.text.appendPlainText(f"\n[nie udało się wczytać pliku: {e}]")
            return
        if self.text.toPlainText().strip() and not confirm(
                self, "Instrukcja aktualizacji",
                "Zastąpić obecną treść zawartością pliku?"):
            return
        self.text.setPlainText(text)

    def _fill(self, text: str, html: str) -> None:
        if html:
            self.text.setHtml(html)
        else:
            self.text.setPlainText(text)

    # ── formatting ──
    def _target(self) -> QTextCursor:
        cur = self.text.textCursor()
        if not cur.hasSelection():
            cur.movePosition(QTextCursor.MoveOperation.StartOfBlock)
            cur.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                             QTextCursor.MoveMode.KeepAnchor)
        return cur

    def toggle_bold(self) -> None:
        cur = self._target()
        bold = cur.charFormat().fontWeight() >= QFont.Weight.DemiBold.value
        f = QTextCharFormat()
        f.setFontWeight(QFont.Weight.Normal if bold else QFont.Weight.Bold)
        cur.mergeCharFormat(f)
        self._show_bold()

    def change_size(self, step: int) -> None:
        cur = self._target()
        start = QTextCursor(cur)
        start.setPosition(min(cur.anchor(), cur.position()) + 1)
        size = start.charFormat().fontPointSize() or NOTES_PT
        f = QTextCharFormat()
        f.setFontPointSize(max(_NOTES_MIN_PT, min(_NOTES_MAX_PT, size + step)))
        cur.mergeCharFormat(f)

    def clear_format(self) -> None:
        cur = self._target()
        f = QTextCharFormat()
        f.setFontWeight(QFont.Weight.Normal)
        f.setFontPointSize(NOTES_PT)
        cur.mergeCharFormat(f)
        self._show_bold()

    def _show_bold(self) -> None:
        w = self.text.textCursor().charFormat().fontWeight()
        self.bold_btn.setChecked(w >= QFont.Weight.DemiBold.value)

    # ── values ──
    def value(self) -> str:
        return _clean_text(self.text.toPlainText())

    def html(self) -> str:
        """The rich text — only when something is bold or resized."""
        doc = self.text.document()
        return doc.toHtml() if self.value() and _has_format(doc) else ""

    def dirty(self) -> bool:
        return (self.value(), self.html()) != self._clean

    def _save(self) -> None:
        self._clean = (self.value(), self.html())
        self.saved.emit(*self._clean)

    def set_text(self, text: str, html: str = "") -> None:
        """The hospital changed under the window (another one opened)."""
        self._fill(text, html)
        self._clean = (self.value(), self.html())

    # ── closing: Esc and the title bar's × too ──
    def reject(self) -> None:
        self.close()

    def closeEvent(self, event) -> None:
        if self.dirty():
            from PyQt6.QtWidgets import QMessageBox
            box = QMessageBox(QMessageBox.Icon.Question, "Instrukcja aktualizacji",
                              "Zapisać zmiany w instrukcji?", parent=self)
            yes = box.addButton("Zapisz", QMessageBox.ButtonRole.AcceptRole)
            no = box.addButton("Nie zapisuj", QMessageBox.ButtonRole.DestructiveRole)
            box.addButton("Anuluj", QMessageBox.ButtonRole.RejectRole)
            box.exec()
            if box.clickedButton() is yes:
                self._save()
            elif box.clickedButton() is not no:
                event.ignore()
                return
        event.accept()


class MachinePickDialog(QDialog):
    """Tick machines from a list (in the list's order)."""

    def __init__(self, parent, title: str, machines: list, chosen: set,
                 extra: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(380)
        self.setStyleSheet(_FIELD_QSS)
        lay = QVBoxLayout(self)
        if extra is not None:
            lay.addWidget(extra)
        self._boxes = []
        for m in machines:
            cb = QCheckBox(machine_label(m))
            cb.setChecked(m.id in chosen)
            if m.description:
                cb.setToolTip(m.description)
            self._boxes.append((cb, m))
            lay.addWidget(cb)
        if not machines:
            lay.addWidget(QLabel("Brak maszyn SSH w tym szpitalu."))
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("Zapisz")
        bb.button(QDialogButtonBox.StandardButton.Cancel).setText("Anuluj")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def chosen_ids(self) -> list:
        return [m.id for cb, m in self._boxes if cb.isChecked()]


# ── The panel ────────────────────────────────────────────────────────────

class UpgradePanel(QWidget):
    data_changed = pyqtSignal()
    #: machines to open, in order (only those without a tab — the window checks)
    open_requested = pyqtSignal(list)
    #: (group, command, machines in plan order)
    run_requested = pyqtSignal(dict, dict, list)
    #: (group, machines) — Ctrl+C in their terminals
    interrupt_requested = pyqtSignal(dict, list)

    def __init__(self, hospital=None, admin_unlocked: bool = False, parent=None):
        super().__init__(parent)
        self._hospital = None
        self._plan: dict = up.default_plan()
        self._admin_unlocked = admin_unlocked
        #: (group id, machine id) → (state, text, HH:MM:SS)
        self._status: dict[tuple, tuple] = {}
        self._status_labels: dict[str, QLabel] = {}
        self._select_row = -1
        #: the open (non-modal) instructions window, if any
        self._notes_dlg = None

        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # 2026-11-26 (owner): what this tab is about, also when its tab
        # title is cut short in a narrow panel.
        title = QLabel("Aktualizacja AMMS")
        title.setStyleSheet("color:#e1e4eb; font-size:13px; font-weight:bold;")
        root.addWidget(title)

        row = QHBoxLayout()
        lbl = QLabel("Wersja:")
        lbl.setStyleSheet("color:#c9d1d9; font-size:11px;")
        row.addWidget(lbl)
        self._version = QLineEdit()
        self._version.setPlaceholderText("np. 6.10.01.83")
        self._version.setStyleSheet(_FIELD_QSS)
        self._version.setToolTip("Wstawiana do komend w miejsce {WERSJA}")
        self._version.editingFinished.connect(self._version_edited)
        row.addWidget(self._version, 1)
        self._day = QLabel()
        self._day.setStyleSheet("color:#8b949e; font-size:10px;")
        self._day.setToolTip("{DATA} w komendach")
        row.addWidget(self._day)
        root.addLayout(row)

        # Outside the scrolled plan: a rebuild never drops a running download.
        self.hd_box = HdDownloadBox(lambda: self._plan.get("hd") or up.default_hd())
        self.hd_box.settings_changed.connect(self._hd_settings)
        self.hd_box.version_found.connect(self._hd_version)
        root.addWidget(self.hd_box)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll.setStyleSheet(
            "QScrollArea { background:transparent; border:none; }"
            "QScrollBar:vertical { background:#14161e; width:6px; border:none;"
            " border-radius:3px; margin:2px; }"
            "QScrollBar::handle:vertical { background:#2a2d3a; border-radius:3px;"
            " min-height:20px; }"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }")
        root.addWidget(self._scroll, 1)

        if hospital is not None:
            self.set_hospital(hospital)

    # ── What the window calls ─────────────────────────────────────────────

    @property
    def plan(self) -> dict:
        return self._plan

    def version(self) -> str:
        return self._version.text().strip()

    def set_hospital(self, hospital) -> None:
        self._hospital = hospital
        self._plan = up.normalize_plan(getattr(hospital, "upgrade", None))
        self._status.clear()
        self._version.setText(self._plan.get("version", ""))
        if not self.hd_box.busy():
            self.hd_box.show_idle()
        if self._notes_dlg is not None:
            self._notes_dlg.set_text(self._plan.get("notes", ""),
                                     notes_rich(self._plan))
        self._rebuild()

    def refresh(self) -> None:
        """The hospital's machines changed (edited in "Maszyny")."""
        self._rebuild()

    def set_admin_mode(self, unlocked: bool) -> None:
        self._admin_unlocked = unlocked
        self._rebuild()

    def set_status(self, group_id: str, machine_id: str, state: str,
                   text: str = "") -> None:
        self._status[(group_id, machine_id)] = (state, text,
                                                time.strftime("%H:%M:%S"))
        self._show_status(group_id)

    def machines_of(self, group: dict) -> list:
        """The group's machines in the order of the upgrade list."""
        ids = set(group.get("machines", []))
        ordered = [m for m in self._order_machines() if m.id in ids]
        rest = [m for m in self._ssh_machines()
                if m.id in ids and m not in ordered]
        return ordered + rest

    # ── Data ──────────────────────────────────────────────────────────────

    def _ssh_machines(self) -> list:
        h = self._hospital
        if h is None:
            return []
        return [m for m in h.machines
                if getattr(m, "connection_type", "SSH") == "SSH"
                and (self._admin_unlocked or not m.admin_only)]

    def _order_machines(self) -> list:
        return up.plan_machines(self._plan, self._ssh_machines())

    def _commit(self, rebuild: bool = True) -> None:
        if self._hospital is not None:
            self._hospital.upgrade = up.copy_plan(self._plan)
        if rebuild:
            # Later: the edit may come from a signal of a widget the
            # rebuild deletes (the drag of the list).
            QTimer.singleShot(0, self._rebuild)
        self.data_changed.emit()

    def _hd_settings(self, values: dict) -> None:
        self._plan["hd"] = up.normalize_hd(values)
        self._commit(rebuild=False)

    def _hd_version(self, version: str) -> None:
        """The newest version on hd.asseco.pl goes into {WERSJA}."""
        if version and version != self._plan.get("version"):
            self._version.setText(version)
            self._plan["version"] = version
            self._commit(rebuild=False)

    def _version_edited(self) -> None:
        v = self._version.text().strip()
        if v != self._plan.get("version", ""):
            self._plan["version"] = v
            self._commit(rebuild=False)

    # ── Building ──────────────────────────────────────────────────────────

    def _rebuild(self) -> None:
        self._day.setText(f"data: {up.today_stamp()}")
        self._status_labels.clear()
        box = QWidget()
        box.setStyleSheet("background:transparent;")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(0, 0, 4, 0)
        lay.setSpacing(8)
        lay.addWidget(self._notes_box())
        lay.addWidget(self._order_box())
        for g in self._plan["groups"]:
            lay.addWidget(self._group_box(g))
        add = _shrinkable(QPushButton("Dodaj grupę"))
        set_icon(add, "plus", "#3fb950", size=13)
        add.setStyleSheet(_GREEN_QSS)
        add.clicked.connect(self._add_group)
        lay.addWidget(add)
        lay.addStretch()
        self._scroll.setWidget(box)
        for g in self._plan["groups"]:
            self._show_status(g["id"])

    @staticmethod
    def _section(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("color:#8b949e; font-size:9px; font-weight:bold;"
                          " letter-spacing:2px;")
        return lbl

    def _notes_box(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("upgradeBox")
        frame.setStyleSheet(_BOX_QSS)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(6)
        lay.addWidget(self._section("INSTRUKCJA AKTUALIZACJI"))
        notes = self._plan.get("notes", "")
        if notes.strip():
            view = QTextEdit()
            view.setReadOnly(True)
            # Narrow panel: long lines wrap here; unwrapped in the big window.
            view.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
            view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            view.setStyleSheet(_FIELD_QSS + _SCROLL_QSS)
            mono = QFont("Consolas")
            mono.setStyleHint(QFont.StyleHint.Monospace)
            mono.setPointSize(9)
            view.setFont(mono)
            view.document().setDefaultFont(mono)
            rich = notes_rich(self._plan)
            if rich:
                view.setHtml(rich)
            else:
                view.setPlainText(notes)
            self._notes_view = view
            view.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
            view.setFixedHeight(min(220, 16 + 15 * max(3, notes.count("\n") + 1)))
            lay.addWidget(view)
        else:
            empty = QLabel("Brak instrukcji — wklej albo wczytaj plik z opisem "
                           "aktualizacji tego szpitala.")
            empty.setWordWrap(True)
            empty.setStyleSheet("color:#5a5f72; font-size:10px;")
            lay.addWidget(empty)
        edit = _shrinkable(QPushButton("Otwórz / edytuj…" if notes.strip()
                                       else "Dodaj instrukcję…"))
        set_icon(edit, "pencil", "#8b949e", size=13)
        edit.setStyleSheet(_GREY_QSS)
        edit.clicked.connect(self._edit_notes)
        row = QHBoxLayout()
        row.setSpacing(4)
        row.addWidget(edit, 1)
        git = _shrinkable(QPushButton("GitLab AMMS"))
        set_icon(git, "external", "#a5b4ff", size=13)
        git.setStyleSheet(_CMD_QSS)
        git.setToolTip(GITLAB_URL)
        git.clicked.connect(open_gitlab)
        row.addWidget(git, 1)
        lay.addLayout(row)
        return frame

    def _edit_notes(self) -> None:
        """Non-modal (2026-11-26): one window per panel, raised if open."""
        dlg = self._notes_dlg
        if dlg is not None:
            dlg.showNormal()
            dlg.raise_()
            dlg.activateWindow()
            return
        name = getattr(self._hospital, "name", "") or ""
        dlg = NotesDialog(self, self._plan.get("notes", ""), name,
                          notes_rich(self._plan))
        dlg.saved.connect(self._notes_saved)
        dlg.destroyed.connect(lambda *_a: setattr(self, "_notes_dlg", None))
        self._notes_dlg = dlg
        # The panel goes (window closed): its notes window goes with it.
        self.destroyed.connect(dlg.deleteLater)
        dlg.show()

    def close_notes(self) -> bool:
        """The window closes: the notes window too (it may ask to save).
        False — the user chose to stay."""
        dlg = self._notes_dlg
        if dlg is None:
            return True
        if not dlg.close():
            return False
        self._notes_dlg = None
        return True

    def _notes_saved(self, value: str, html: str = "") -> None:
        if (value, html) != (self._plan.get("notes", ""),
                             self._plan.get("notes_html", "")):
            self._plan["notes"] = value
            self._plan["notes_html"] = html
            self._commit()

    def _order_box(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("upgradeBox")
        frame.setStyleSheet(_BOX_QSS)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(6)
        lay.addWidget(self._section("KOLEJNOŚĆ KART"))

        machines = self._order_machines()
        self._list = QListWidget()
        self._list.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self._list.setDefaultDropAction(Qt.DropAction.MoveAction)
        self._list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list.setTextElideMode(Qt.TextElideMode.ElideRight)
        self._list.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self._list.setStyleSheet(
            "QListWidget { background:#14161e; border:1px solid #2a2d3a;"
            " border-radius:6px; color:#c9d1d9; font-size:11px; }"
            "QListWidget::item { padding:3px 4px; }"
            "QListWidget::item:selected { background:#1c2240; color:#fff; }")
        groups_of = {}
        for g in self._plan["groups"]:
            for mid in g.get("machines", []):
                groups_of.setdefault(mid, []).append(g["name"].split(" (")[0])
        for i, m in enumerate(machines, 1):
            tags = groups_of.get(m.id, [])
            item = QListWidgetItem(f"{i}. {machine_label(m)}"
                                   + (f"   [{', '.join(tags)}]" if tags else ""))
            item.setData(Qt.ItemDataRole.UserRole, m.id)
            if m.description:
                item.setToolTip(m.description)
            self._list.addItem(item)
        self._list.setFixedHeight(min(240, 12 + 20 * max(1, len(machines))))
        self._list.model().rowsMoved.connect(lambda *_a: self._order_dragged())
        if 0 <= self._select_row < len(machines):
            self._list.setCurrentRow(self._select_row)
        self._select_row = -1
        lay.addWidget(self._list)
        if not machines:
            empty = QLabel("Dodaj maszyny aktualizacji — ich kolejność to "
                           "kolejność otwierania kart.")
            empty.setWordWrap(True)
            empty.setStyleSheet("color:#5a5f72; font-size:10px;")
            lay.addWidget(empty)

        row = QHBoxLayout()
        row.setSpacing(4)
        open_btn = QPushButton("Otwórz karty po kolei")
        set_icon(open_btn, "connect", "#3fb950", size=13)
        open_btn.setStyleSheet(_GREEN_QSS)
        open_btn.setEnabled(bool(machines))
        open_btn.setToolTip("Otwiera kartę SSH każdej maszyny z listy, "
                            "w tej kolejności (już otwarte są pomijane)")
        open_btn.clicked.connect(lambda: self.open_requested.emit(self._order_machines()))
        row.addWidget(_shrinkable(open_btn), 1)
        for name, tip, step in (("up", "W górę", -1), ("chevron-down", "W dół", 1)):
            b = QToolButton()
            set_icon(b, name, "#8b949e", size=13)
            b.setToolTip(tip)
            b.setStyleSheet(_GREY_QSS)
            b.clicked.connect(lambda _c=False, s=step: self._move_selected(s))
            row.addWidget(b)
        pick = QToolButton()
        set_icon(pick, "pencil", "#8b949e", size=13)
        pick.setStyleSheet(_GREY_QSS)
        pick.setToolTip("Wybierz maszyny aktualizacji")
        pick.clicked.connect(self._pick_order)
        row.addWidget(pick)
        lay.addLayout(row)
        return frame

    def _group_box(self, g: dict) -> QFrame:
        frame = QFrame()
        frame.setObjectName("upgradeBox")
        frame.setStyleSheet(_BOX_QSS)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(6)

        head = QHBoxLayout()
        title = QLabel(_esc(g["name"]))
        title.setStyleSheet("color:#e1e4eb; font-size:12px; font-weight:bold;")
        title.setWordWrap(True)
        title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        head.addWidget(title, 1)
        more = QToolButton()
        set_icon(more, "more", "#8b949e", size=14)
        more.setStyleSheet(_GREY_QSS)
        more.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(more)
        menu.setStyleSheet(_MENU_QSS)
        menu.addAction("Maszyny grupy…", lambda gg=g: self._pick_group_machines(gg))
        menu.addAction("Dodaj komendę…", lambda gg=g: self._add_command(gg))
        menu.addAction("Nazwa i proces usługi…", lambda gg=g: self._edit_group(gg))
        menu.addSeparator()
        menu.addAction("Usuń grupę", lambda gg=g: self._delete_group(gg))
        more.setMenu(menu)
        head.addWidget(more)
        lay.addLayout(head)

        ms = self.machines_of(g)
        who = QLabel(", ".join(m.ip for m in ms) if ms
                     else "brak maszyn — ⋯ → Maszyny grupy…")
        who.setWordWrap(True)
        who.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        who.setStyleSheet("color:#8b949e; font-size:10px;" if ms
                          else "color:#d29922; font-size:10px;")
        if g.get("process"):
            who.setToolTip(f"Proces usługi: {g['process']}")
        lay.addWidget(who)

        grid = QGridLayout()
        grid.setSpacing(4)
        cmds = g.get("commands", [])
        for i, c in enumerate(cmds):
            b = _shrinkable(QPushButton(c["label"]))
            b.setStyleSheet(_CMD_DANGER_QSS if c.get("confirm") else _CMD_QSS)
            b.setToolTip(_esc(c["text"]).replace("\n", "<br>")
                         + "<br><i>prawy klik — edycja</i>")
            b.setEnabled(bool(ms))
            b.clicked.connect(lambda _c=False, gg=g, cc=c:
                              self.run_requested.emit(gg, cc, self.machines_of(gg)))
            b.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            b.customContextMenuRequested.connect(
                lambda _p, gg=g, cc=c, bb=b: self._command_menu(gg, cc, bb))
            grid.addWidget(b, i // 2, i % 2)
        lay.addLayout(grid)

        row = QHBoxLayout()
        row.setSpacing(4)
        stop = QPushButton("Ctrl+C")
        set_icon(stop, "stop", "#d29922", size=12)
        stop.setStyleSheet(_GREY_QSS)
        stop.setToolTip("Przerwij to, co działa w terminalach tej grupy "
                        "(np. tail -f po starcie)")
        stop.setEnabled(bool(ms))
        _shrinkable(stop)
        stop.clicked.connect(lambda _c=False, gg=g:
                             self.interrupt_requested.emit(gg, self.machines_of(gg)))
        row.addWidget(stop)
        add = QPushButton("+ komenda")
        add.setStyleSheet(_GREY_QSS)
        add.clicked.connect(lambda _c=False, gg=g: self._add_command(gg))
        row.addWidget(_shrinkable(add))
        lay.addLayout(row)

        status = QLabel()
        status.setWordWrap(True)
        status.setTextFormat(Qt.TextFormat.RichText)
        status.setStyleSheet("font-size:10px;")
        status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        status.setVisible(False)
        self._status_labels[g["id"]] = status
        lay.addWidget(status)
        return frame

    def _show_status(self, group_id: str) -> None:
        lbl = self._status_labels.get(group_id)
        group = next((g for g in self._plan["groups"] if g["id"] == group_id), None)
        if lbl is None or group is None:
            return
        rows = []
        for m in self.machines_of(group):
            st = self._status.get((group_id, m.id))
            if st is None:
                continue
            state, text, at = st
            mark, color = STATES.get(state, ("·", "#8b949e"))
            rows.append(f"<span style='color:{color}'>{mark}</span> "
                        f"<span style='color:#c9d1d9'>{_esc(m.ip)}</span> "
                        f"<span style='color:#8b949e'>{_esc(text)} · {at}</span>")
        lbl.setText("<br>".join(rows))
        lbl.setVisible(bool(rows))

    # ── Order ─────────────────────────────────────────────────────────────

    def _order_dragged(self) -> None:
        ids = [self._list.item(i).data(Qt.ItemDataRole.UserRole)
               for i in range(self._list.count())]
        self._set_order(ids)

    def _set_order(self, shown_ids: list) -> None:
        # Hidden (admin-only) machines keep their places at the end.
        hidden = [i for i in self._plan["order"] if i not in shown_ids]
        self._plan["order"] = list(shown_ids) + hidden
        self._commit()

    def _move_selected(self, step: int) -> None:
        row = self._list.currentRow()
        ids = [self._list.item(i).data(Qt.ItemDataRole.UserRole)
               for i in range(self._list.count())]
        to = row + step
        if row < 0 or not 0 <= to < len(ids):
            return
        ids[row], ids[to] = ids[to], ids[row]
        self._select_row = to
        self._set_order(ids)

    def _pick_order(self) -> None:
        all_m = self._ssh_machines()
        current = [m.id for m in self._order_machines()]
        shown = (self._order_machines()
                 + [m for m in all_m if m.id not in current])
        dlg = MachinePickDialog(self, "Maszyny aktualizacji", shown, set(current))
        if not dlg.exec():
            return
        chosen = dlg.chosen_ids()
        keep = [i for i in current if i in chosen]
        self._set_order(keep + [i for i in chosen if i not in keep])

    # ── Groups and commands ───────────────────────────────────────────────

    def _pick_group_machines(self, g: dict) -> None:
        all_m = self._ssh_machines()
        order_ids = [m.id for m in self._order_machines()]
        shown = (self._order_machines()
                 + [m for m in all_m if m.id not in order_ids])
        dlg = MachinePickDialog(self, f"Maszyny — {g['name']}", shown,
                                set(g.get("machines", [])))
        if not dlg.exec():
            return
        visible = {m.id for m in all_m}
        hidden = [i for i in g.get("machines", []) if i not in visible]
        g["machines"] = dlg.chosen_ids() + hidden
        # A machine of a group is a machine of the upgrade.
        for mid in g["machines"]:
            if mid in visible and mid not in self._plan["order"]:
                self._plan["order"].append(mid)
        self._commit()

    def _edit_group(self, g: dict) -> None:
        name, ok = QInputDialog.getText(self, "Grupa", "Nazwa grupy:",
                                        text=g["name"])
        if not ok or not name.strip():
            return
        proc, ok = QInputDialog.getText(
            self, "Grupa",
            "Proces usługi (wzorzec pgrep -f), np. java.*WildflyAMMS\n"
            "Puste — bez sprawdzania „wymaga zatrzymanej usługi”:",
            text=g.get("process", ""))
        if not ok:
            return
        g["name"], g["process"] = name.strip(), proc.strip()
        self._commit()

    def _add_group(self) -> None:
        name, ok = QInputDialog.getText(self, "Nowa grupa", "Nazwa grupy:")
        if not ok or not name.strip():
            return
        self._plan["groups"].append({"id": up.new_id(), "name": name.strip(),
                                     "process": "", "machines": [],
                                     "commands": []})
        self._commit()

    def _delete_group(self, g: dict) -> None:
        if not confirm(self, "Usuń grupę",
                       f"Usunąć grupę „{g['name']}” razem z jej komendami?"):
            return
        self._plan["groups"] = [x for x in self._plan["groups"] if x is not g]
        self._commit()

    def _add_command(self, g: dict) -> None:
        dlg = CommandDialog(self, {"label": "", "text": ""}, g)
        if not dlg.exec():
            return
        g["commands"].append({"id": up.new_id(), **dlg.values()})
        self._commit()

    def _command_menu(self, g: dict, c: dict, button) -> None:
        menu = QMenu(self)
        menu.setStyleSheet(_MENU_QSS)
        cmds = g["commands"]
        i = cmds.index(c)
        menu.addAction("Edytuj…", lambda: self._edit_command(g, c))
        a = menu.addAction("Przesuń wcześniej", lambda: self._move_command(g, c, -1))
        a.setEnabled(i > 0)
        a = menu.addAction("Przesuń dalej", lambda: self._move_command(g, c, 1))
        a.setEnabled(i < len(cmds) - 1)
        menu.addSeparator()
        menu.addAction("Usuń", lambda: self._delete_command(g, c))
        menu.exec(button.mapToGlobal(button.rect().bottomLeft()))

    def _edit_command(self, g: dict, c: dict) -> None:
        dlg = CommandDialog(self, c, g)
        if dlg.exec():
            c.update(dlg.values())
            self._commit()

    def _move_command(self, g: dict, c: dict, step: int) -> None:
        cmds = g["commands"]
        i = cmds.index(c)
        j = i + step
        if 0 <= j < len(cmds):
            cmds[i], cmds[j] = cmds[j], cmds[i]
            self._commit()

    def _delete_command(self, g: dict, c: dict) -> None:
        if confirm(self, "Usuń komendę", f"Usunąć przycisk „{c['label']}”?"):
            g["commands"] = [x for x in g["commands"] if x is not c]
            self._commit()
