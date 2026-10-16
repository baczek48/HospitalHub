from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QMessageBox, QSizePolicy

# Polish alphabetical order: each letter with a diacritic right after its base
# letter (… s, ś, t … z, ź, ż).  Code-point order put "ś" after "z".
_PL_ALPHABET = "aąbcćdeęfghijklłmnńoópqrsśtuvwxyzźż"
_PL_RANK = {ch: i for i, ch in enumerate(_PL_ALPHABET)}
# Other accented Latin letters (é, ü, …) sort next to their base letter.
_FOLD = str.maketrans("àáâãäåçèéêëìíîïñòôõöøùúûüýÿ", "aaaaaaceeeeiiiinooooouuuuyy")


def polish_key(text: str) -> tuple:
    """Sort key for names in Polish alphabetical order, case-insensitive.

    Digits and punctuation keep their place before letters (as in a file
    manager); identical-looking names stay stable by their original text.
    Independent of the Windows locale, so it sorts the same everywhere."""
    folded = (text or "").casefold()
    out = []
    for ch in folded:
        rank = _PL_RANK.get(ch)
        if rank is None:
            base = ch.translate(_FOLD)
            rank = _PL_RANK.get(base)
            out.append((1, rank, 1) if rank is not None else (0, ord(ch), 0))
        else:
            out.append((1, rank, 0))
    return (tuple(out), text or "")


def plural(n: int, one: str, few: str, many: str) -> str:
    """'{n} {noun}' with Polish declension: 1 → `one`; 2–4, 22–24, … (not
    12–14) → `few`; everything else → `many`."""
    if n == 1:
        return f"{n} {one}"
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return f"{n} {few}"
    return f"{n} {many}"


def confirm(parent, title: str, text: str, yes: str = "Tak",
            no: str = "Nie") -> bool:
    """Polish confirmation; True only when the user clicked `yes`.

    "Nie" is the default and the Escape button (UX audit 2026-10-16, E-07):
    every caller asks before deleting something, and with the focus on "Tak"
    one stray Enter removed a hospital with all its machines.
    """
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(QMessageBox.Icon.Question)
    btn_yes = box.addButton(yes, QMessageBox.ButtonRole.YesRole)
    btn_no = box.addButton(no, QMessageBox.ButtonRole.NoRole)
    box.setDefaultButton(btn_no)
    box.setEscapeButton(btn_no)
    box.exec()
    return box.clickedButton() is btn_yes


class ElidedLabel(QLabel):
    """One-line label that ends in "…" when it does not fit and shows the
    whole text as a tooltip (UX audit V-02/V-03: hospital and VPN profile
    names were cut mid-letter or pushed the buttons out of the window)."""

    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self._full = ""
        self.setSizePolicy(QSizePolicy.Policy.Ignored,
                           QSizePolicy.Policy.Preferred)
        self.setMinimumWidth(40)
        self.setText(text)

    def setText(self, text: str) -> None:
        self._full = text or ""
        self._apply()

    def text(self) -> str:
        return self._full

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._apply()

    def _apply(self) -> None:
        shown = self.fontMetrics().elidedText(
            self._full, Qt.TextElideMode.ElideRight, max(0, self.width()))
        QLabel.setText(self, shown)
        self.setToolTip(self._full if shown != self._full else "")


def parse_port(text: str, default: int | None = None) -> int | None:
    """A TCP port typed by the user: 1–65535, `default` when empty, None
    when it is not a port (UX audit E-14/S-11 — "abc" and "22a" became 22
    without a word, 99999 failed only when connecting)."""
    text = (text or "").strip()
    if not text:
        return default
    if not text.isdigit():
        return None
    port = int(text)
    return port if 1 <= port <= 65535 else None


def split_host_port(text: str) -> tuple[str, str]:
    """"10.0.0.1:2222" → ("10.0.0.1", "2222"); an IPv6 address or a plain
    host stays as it is with ""."""
    text = (text or "").strip()
    if text.count(":") == 1:
        host, port = text.split(":")
        if host and port.isdigit():
            return host, port
    return text, ""


class EmptyHint:
    """Mixin for item views (put before the Qt class): a centred, grey line
    while the view has no rows — an empty frame looked like a failed load
    (UX audit V-15, REDESIGN_V2.md R3).  Set ``empty_hint`` and call
    ``viewport().update()``."""

    empty_hint = ""

    def paintEvent(self, event):
        super().paintEvent(event)
        model = self.model()
        if not self.empty_hint or model is None or model.rowCount() > 0:
            return
        from PyQt6.QtGui import QColor, QPainter
        from ui import theme
        painter = QPainter(self.viewport())
        painter.setPen(QColor(theme.paint("#8b949e")))
        painter.drawText(self.viewport().rect().adjusted(12, 8, -12, -8),
                         Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
                         self.empty_hint)
        painter.end()


def resize_within_screen(widget, width: int, height: int) -> None:
    """resize() that never makes a window bigger than the screen it is on —
    1200×700 at 150 % on a 1366×768 laptop went past the taskbar (V-23)."""
    from PyQt6.QtGui import QGuiApplication
    screen = widget.screen() or QGuiApplication.primaryScreen()
    if screen is not None:
        area = screen.availableGeometry()
        width = min(width, area.width())
        height = min(height, area.height())
    widget.resize(width, height)
