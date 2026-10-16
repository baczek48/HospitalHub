from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QMessageBox, QSizePolicy


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
