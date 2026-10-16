from PyQt6.QtWidgets import QMessageBox


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
