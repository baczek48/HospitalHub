"""One look for the forms (Etap 71C, REDESIGN_V2.md §3, module R1).

The windows (vault, VPN, SSH) were written in the GitHub-dark palette with
inline stylesheets; the data and security dialogs had none and fell back to
Qt's grey Fusion look — flat buttons, fields that blend into the background,
placeholders barely visible (UX audit V-20).  :class:`FormStyled` gives a
dialog the windows' palette the first time it is shown.

The sheet is set on the dialog itself, so it reaches that dialog's children
only — no window outside the forms changes.  In the light theme it passes
through :func:`ui.theme.remap` like every other stylesheet (the patched
``setStyleSheet``).  A sheet the dialog already had stays after this one and
wins where both say something.

Buttons: the one the code marks as default (``setDefault(True)``) is the
primary action and gets the accent; ``setProperty("danger", True)`` marks a
destructive one.
"""

from PyQt6.QtWidgets import QPushButton

FORM_QSS = """
QDialog { background: #161b22; color: #c9d1d9; }
QLabel { color: #c9d1d9; background: transparent; }
QLineEdit, QComboBox, QTextEdit, QPlainTextEdit {
    background: #0d1117; color: #e6edf3; border: 1px solid #30363d;
    border-radius: 5px; padding: 5px 8px; selection-background-color: #1f6feb;
}
QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #1f6feb;
}
QLineEdit:disabled, QComboBox:disabled { color: #6e7681; background: #161b22; }
QComboBox QAbstractItemView {
    background: #161b22; color: #c9d1d9; border: 1px solid #30363d;
    selection-background-color: #1f6feb;
}
QPushButton {
    background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
    border-radius: 5px; padding: 6px 14px;
}
QPushButton:hover { background: #30363d; border-color: #484f58; }
QPushButton:focus { border-color: #58a6ff; }
QPushButton:disabled { color: #6e7681; background: #161b22; border-color: #21262d; }
QPushButton[primary="true"] { background: #1f6feb; color: #ffffff; border-color: #1f6feb; }
QPushButton[primary="true"]:hover { background: #388bfd; border-color: #388bfd; }
QPushButton[danger="true"] { color: #f85149; }
QPushButton[danger="true"]:hover { background: #3d1a1a; border-color: #f85149; }
QCheckBox { color: #c9d1d9; spacing: 6px; }
QCheckBox::indicator {
    width: 14px; height: 14px; border: 1px solid #6e7681;
    border-radius: 3px; background: #0d1117;
}
QCheckBox::indicator:hover { border-color: #58a6ff; }
QCheckBox::indicator:checked { background: #1f6feb; border-color: #58a6ff; }
QTableWidget {
    background: #0d1117; alternate-background-color: #161b22; color: #c9d1d9;
    border: 1px solid #30363d; border-radius: 5px; gridline-color: #21262d;
}
QHeaderView::section {
    background: #21262d; color: #8b949e; border: none;
    border-bottom: 1px solid #30363d; padding: 4px 6px;
}
QTableCornerButton::section { background: #21262d; border: none; }
"""


def refresh(widget) -> None:
    """Re-apply the style after a dynamic property changed."""
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)


def apply_form(dialog) -> None:
    dialog.setStyleSheet(FORM_QSS + (dialog.styleSheet() or ""))
    for button in dialog.findChildren(QPushButton):
        if button.isDefault() and button.property("primary") is None:
            button.setProperty("primary", True)
            refresh(button)


class FormStyled:
    """Mixin for QDialog subclasses: the form look on first show."""

    _form_styled = False

    def showEvent(self, event):
        if not self._form_styled:
            self._form_styled = True
            apply_form(self)
        super().showEvent(event)
