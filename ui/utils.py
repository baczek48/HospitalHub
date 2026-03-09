from PyQt6.QtWidgets import QMessageBox


def confirm(parent, title: str, text: str) -> bool:
    """Polish Yes/No confirmation dialog. Returns True if user clicked 'Tak'."""
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(QMessageBox.Icon.Question)
    btn_yes = box.addButton("Tak", QMessageBox.ButtonRole.YesRole)
    box.addButton("Nie", QMessageBox.ButtonRole.NoRole)
    box.exec()
    return box.clickedButton() is btn_yes
