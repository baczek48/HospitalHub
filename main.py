# Copyright © 2026 Sebastian Bąk. All rights reserved.

import atexit
import shutil
import sys
import os
import tempfile

# Ensure vault_app directory is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _cleanup_sftp_temp():
    """Remove SFTP temp directory on exit (best-effort)."""
    tmp_dir = os.path.join(tempfile.gettempdir(),
                           f'HospitalHub_{os.getpid()}')
    if os.path.isdir(tmp_dir):
        shutil.rmtree(tmp_dir, ignore_errors=True)


atexit.register(_cleanup_sftp_temp)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPalette, QColor, QIcon, QPixmap, QPainter, QPainterPath, QPen
from PyQt6.QtCore import Qt, QRectF

from ui.login_dialog import LoginDialog
from ui.main_window import MainWindow


def apply_dark_theme(app: QApplication):
    app.setStyle("Fusion")
    palette = QPalette()

    dark_bg = QColor(30, 30, 35)
    mid_bg = QColor(42, 42, 48)
    light_bg = QColor(55, 55, 62)
    highlight = QColor(0, 120, 215)
    text = QColor(220, 220, 220)
    dim_text = QColor(140, 140, 140)

    palette.setColor(QPalette.ColorRole.Window, dark_bg)
    palette.setColor(QPalette.ColorRole.WindowText, text)
    palette.setColor(QPalette.ColorRole.Base, mid_bg)
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(36, 36, 42))
    palette.setColor(QPalette.ColorRole.ToolTipBase, light_bg)
    palette.setColor(QPalette.ColorRole.ToolTipText, text)
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, light_bg)
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 80, 80))
    palette.setColor(QPalette.ColorRole.Link, highlight)
    palette.setColor(QPalette.ColorRole.Highlight, highlight)
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, dim_text)
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, dim_text)
    palette.setColor(QPalette.ColorRole.Mid, light_bg)
    palette.setColor(QPalette.ColorRole.Dark, QColor(20, 20, 24))

    app.setPalette(palette)


def make_icon() -> QIcon:
    """Draws a shield with a medical cross — used as the app icon."""
    size = 256
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)

    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Shield shape
    shield = QPainterPath()
    w, h = size, size
    shield.moveTo(w * 0.5, h * 0.05)
    shield.lineTo(w * 0.92, h * 0.22)
    shield.cubicTo(w * 0.92, h * 0.60, w * 0.72, h * 0.85, w * 0.50, h * 0.96)
    shield.cubicTo(w * 0.28, h * 0.85, w * 0.08, h * 0.60, w * 0.08, h * 0.22)
    shield.closeSubpath()

    # Fill shield — dark blue gradient feel via solid color
    p.fillPath(shield, QColor(18, 52, 96))

    # Shield border
    pen = QPen(QColor(41, 128, 215), size * 0.03)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.drawPath(shield)

    # Medical cross — white, centered
    cx, cy = w * 0.5, h * 0.50
    arm = w * 0.14
    thick = w * 0.10
    cross = QPainterPath()
    cross.addRoundedRect(QRectF(cx - thick / 2, cy - arm - thick / 2, thick, arm * 2 + thick), 4, 4)
    cross.addRoundedRect(QRectF(cx - arm - thick / 2, cy - thick / 2, arm * 2 + thick, thick), 4, 4)
    p.setPen(Qt.PenStyle.NoPen)
    p.fillPath(cross, QColor(235, 245, 255))

    p.end()
    return QIcon(px)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("HospitalHub")
    app.setApplicationDisplayName("HospitalHub")
    apply_dark_theme(app)
    app.setWindowIcon(make_icon())

    login = LoginDialog()
    if login.exec():
        vault_path, password, hospitals, admin_hash, admin_salt = login.get_result()
        window = MainWindow(vault_path, password, hospitals, admin_hash, admin_salt)
        window.show()
        sys.exit(app.exec())
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
