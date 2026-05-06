import locale
import os
import sys

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QTextEdit, QScrollArea, QStackedWidget,
    QMessageBox, QFrame, QApplication, QFileDialog,
    QCheckBox, QDialog, QDialogButtonBox,
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QSize, QThread
from PyQt6.QtGui import QFont, QIcon, QPixmap, QPainter, QColor, QPen

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import models
import vpn_connect
from config import (load_vpn_provider_paths, save_vpn_provider_paths,
                    load_custom_vpn_providers, save_custom_vpn_providers,
                    load_vpn_autofill_enabled, save_vpn_autofill_enabled)

# ------------------------------------------------------------------ #
# 2FA dialog                                                           #
# ------------------------------------------------------------------ #

class TwoFactorDialog(QDialog):
    def __init__(self, profile_name: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Weryfikacja dwuetapowa")
        self.setModal(True)
        self.setFixedWidth(320)
        self.setStyleSheet("background: #0d1117; color: #c9d1d9;")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(10)

        icon_lbl = QLabel("🔐")
        icon_lbl.setStyleSheet("font-size: 28px; background: transparent;")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(icon_lbl)

        title = QLabel("Kod weryfikacyjny")
        title.setStyleSheet("color: #c9d1d9; font-size: 13px; font-weight: bold; background: transparent;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(title)

        desc = QLabel(f"<span style='color:#8b949e;font-size:11px;'>Profil: <b style='color:#58a6ff;'>{profile_name}</b><br>Wpisz kod z SMS, e-mail lub aplikacji.</span>")
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet("background: transparent;")
        lay.addWidget(desc)

        self._code_edit = QLineEdit()
        self._code_edit.setPlaceholderText("Kod 2FA...")
        self._code_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._code_edit.setStyleSheet(
            "QLineEdit { background: #21262d; border: 1px solid #30363d; border-radius: 6px;"
            " padding: 8px; color: #c9d1d9; font-size: 16px; letter-spacing: 3px; }"
            "QLineEdit:focus { border-color: #1f6feb; }"
        )
        self._code_edit.returnPressed.connect(self.accept)
        lay.addWidget(self._code_edit)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.setStyleSheet(
            "QDialogButtonBox QPushButton { background: #21262d; color: #c9d1d9;"
            " border: 1px solid #30363d; border-radius: 4px; padding: 5px 16px; min-width: 70px; }"
            "QDialogButtonBox QPushButton:hover { background: #30363d; }"
            "QDialogButtonBox QPushButton[text='OK'] { background: #1f6feb; color: #fff; border-color: #1f6feb; }"
            "QDialogButtonBox QPushButton[text='OK']:hover { background: #388bfd; }"
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

        self._code_edit.setFocus()

    def code(self) -> str:
        return self._code_edit.text().strip()


# ------------------------------------------------------------------ #
# VPN Settings dialog                                                  #
# ------------------------------------------------------------------ #

_DLG_STYLE = "background: #0d1117; color: #c9d1d9;"
_FIELD_STYLE = (
    "QLineEdit { background: #21262d; border: 1px solid #30363d; border-radius: 4px;"
    " padding: 5px 8px; color: #c9d1d9; font-size: 11px; }"
    "QLineEdit:focus { border-color: #1f6feb; }"
)
_SMALL_BTN = (
    "QPushButton { background: #21262d; color: #c9d1d9; border: 1px solid #30363d;"
    " border-radius: 4px; font-size: 11px; padding: 3px 8px; }"
    "QPushButton:hover { background: #30363d; }"
)


class _CheckmarkCheckBox(QCheckBox):
    """QCheckBox that overpaints a ✓ glyph on top of the styled indicator,
    instead of Qt's default solid fill or platform-native tick. Works with any
    stylesheet because the checkmark is drawn separately on top."""

    def paintEvent(self, event):
        super().paintEvent(event)
        if not self.isChecked():
            return
        from PyQt6.QtWidgets import QStyle, QStyleOptionButton
        opt = QStyleOptionButton()
        self.initStyleOption(opt)
        r = self.style().subElementRect(
            QStyle.SubElement.SE_CheckBoxIndicator, opt, self
        )
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor("#58a6ff"))
        pen.setWidthF(2.0)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        # Tick inside the indicator rect: P1 → P2 → P3 (bottom-left → mid → top-right).
        x, y, w, h = r.x(), r.y(), r.width(), r.height()
        from PyQt6.QtCore import QPointF
        p.drawPolyline(
            QPointF(x + w * 0.22, y + h * 0.55),
            QPointF(x + w * 0.43, y + h * 0.76),
            QPointF(x + w * 0.80, y + h * 0.28),
        )
        p.end()


class VpnSettingsDialog(QDialog):
    """Global VPN settings: provider exe paths + custom provider list."""
    import_forti_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Ustawienia VPN")
        self.setModal(True)
        self.setMinimumWidth(500)
        self.setMinimumHeight(420)
        self.setStyleSheet(_DLG_STYLE)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(10)

        # --- Section: Provider paths ---
        lbl_paths = QLabel("Ścieżki klientów VPN (globalne)")
        lbl_paths.setStyleSheet("color: #c9d1d9; font-size: 12px; font-weight: bold;")
        lay.addWidget(lbl_paths)

        desc = QLabel("Ścieżki ustawione tutaj dotyczą wszystkich profili danego providera.\n"
                       "Profil może nadpisać ścieżkę w swoich ustawieniach.")
        desc.setStyleSheet("color: #8b949e; font-size: 10px;")
        desc.setWordWrap(True)
        lay.addWidget(desc)

        paths_scroll = QScrollArea()
        paths_scroll.setWidgetResizable(True)
        paths_scroll.setMaximumHeight(200)
        paths_scroll.setStyleSheet("QScrollArea { border: 1px solid #21262d; background: #0d1117; }")
        paths_widget = QWidget()
        self._paths_layout = QVBoxLayout(paths_widget)
        self._paths_layout.setContentsMargins(4, 4, 4, 4)
        self._paths_layout.setSpacing(4)

        self._path_edits: dict[str, QLineEdit] = {}
        saved_paths = load_vpn_provider_paths()
        for provider in models.VPN_PROVIDERS:
            row = QHBoxLayout()
            row.setSpacing(4)
            lbl = QLabel(provider)
            lbl.setFixedWidth(160)
            lbl.setStyleSheet("color: #8b949e; font-size: 11px;")
            row.addWidget(lbl)
            edit = QLineEdit()
            edit.setPlaceholderText("np. C:\\...\\client.exe")
            edit.setStyleSheet(_FIELD_STYLE)
            edit.setText(saved_paths.get(provider, ""))
            row.addWidget(edit, 1)
            btn_browse = QPushButton("...")
            btn_browse.setFixedSize(28, 28)
            btn_browse.setStyleSheet(_SMALL_BTN)
            btn_browse.clicked.connect(lambda _, e=edit: self._browse_path(e))
            row.addWidget(btn_browse)
            self._paths_layout.addLayout(row)
            self._path_edits[provider] = edit

        self._paths_layout.addStretch()
        paths_scroll.setWidget(paths_widget)
        lay.addWidget(paths_scroll)

        # --- Section: Custom providers ---
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #30363d;")
        lay.addWidget(sep)

        lbl_custom = QLabel("Dodatkowi providerzy VPN")
        lbl_custom.setStyleSheet("color: #c9d1d9; font-size: 12px; font-weight: bold;")
        lay.addWidget(lbl_custom)

        self._custom_list: list[str] = list(load_custom_vpn_providers())

        custom_row = QHBoxLayout()
        custom_row.setSpacing(4)
        self._custom_edit = QLineEdit()
        self._custom_edit.setPlaceholderText("Nazwa nowego providera...")
        self._custom_edit.setStyleSheet(_FIELD_STYLE)
        self._custom_edit.returnPressed.connect(self._add_custom)
        custom_row.addWidget(self._custom_edit, 1)
        btn_add_custom = QPushButton("+ Dodaj")
        btn_add_custom.setStyleSheet(
            "QPushButton { background: #238636; color: #fff; border: none; border-radius: 4px;"
            " padding: 4px 10px; font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: #2ea043; }"
        )
        btn_add_custom.clicked.connect(self._add_custom)
        custom_row.addWidget(btn_add_custom)
        lay.addLayout(custom_row)

        self._custom_container = QVBoxLayout()
        self._custom_container.setSpacing(2)
        lay.addLayout(self._custom_container)
        self._rebuild_custom_list()

        # --- Section: Automation ---
        sep_auto = QFrame()
        sep_auto.setFrameShape(QFrame.Shape.HLine)
        sep_auto.setStyleSheet("color: #30363d;")
        lay.addWidget(sep_auto)

        lbl_auto = QLabel("Automatyzacja")
        lbl_auto.setStyleSheet("color: #c9d1d9; font-size: 12px; font-weight: bold;")
        lay.addWidget(lbl_auto)

        self._autofill_cb = _CheckmarkCheckBox("Automatycznie uzupełniaj pola w oknach VPN")
        self._autofill_cb.setChecked(load_vpn_autofill_enabled())
        self._autofill_cb.setStyleSheet(
            "QCheckBox { color: #c9d1d9; font-size: 11px; spacing: 8px; padding: 2px 0; }"
            "QCheckBox::indicator { width: 16px; height: 16px; border-radius: 3px;"
            " border: 1px solid #30363d; background: #21262d; }"
            "QCheckBox::indicator:hover { border-color: #58a6ff; }"
            "QCheckBox::indicator:checked { border-color: #58a6ff; background: #21262d; }"
        )
        lay.addWidget(self._autofill_cb)

        desc_auto = QLabel(
            "Gdy włączone — login, hasło i token są automatycznie wpisywane w okno klienta VPN.\n"
            "Gdy wyłączone — okno zostanie tylko otwarte, a hasło skopiowane do schowka (Ctrl+V)."
        )
        desc_auto.setStyleSheet("color: #8b949e; font-size: 10px; padding-left: 24px;")
        desc_auto.setWordWrap(True)
        lay.addWidget(desc_auto)

        lay.addStretch()

        # --- Import FortiClient ---
        if vpn_connect.is_forticlient_installed():
            sep2 = QFrame()
            sep2.setFrameShape(QFrame.Shape.HLine)
            sep2.setStyleSheet("color: #30363d;")
            lay.addWidget(sep2)

            btn_import = QPushButton("Importuj tunele z FortiClient")
            btn_import.setToolTip("Importuj profile VPN z rejestru FortiClient")
            btn_import.setStyleSheet(
                "QPushButton { background: #1a3a5c; color: #58a6ff; border: 1px solid #1f6feb;"
                " border-radius: 4px; padding: 6px 14px; font-size: 11px; }"
                "QPushButton:hover { background: #1f6feb; color: #fff; }"
            )
            btn_import.clicked.connect(lambda: self.import_forti_requested.emit())
            lay.addWidget(btn_import)

        # --- Buttons ---
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_save = QPushButton("Zapisz")
        btn_save.setStyleSheet(
            "QPushButton { background: #1f6feb; color: #fff; border: none; border-radius: 4px;"
            " padding: 6px 20px; font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: #388bfd; }"
        )
        btn_save.clicked.connect(self.accept)
        btn_row.addWidget(btn_save)
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.setStyleSheet(_SMALL_BTN)
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        lay.addLayout(btn_row)

    def _browse_path(self, edit: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(
            self, "Wybierz klienta VPN", "",
            "Pliki wykonywalne (*.exe);;Wszystkie pliki (*)"
        )
        if path:
            edit.setText(path)

    def _add_custom(self):
        name = self._custom_edit.text().strip()
        if not name:
            return
        if name in models.VPN_PROVIDERS or name in self._custom_list:
            return
        self._custom_list.append(name)
        self._custom_edit.clear()
        self._rebuild_custom_list()

    def _remove_custom(self, name: str):
        if name in self._custom_list:
            self._custom_list.remove(name)
            self._rebuild_custom_list()

    def _rebuild_custom_list(self):
        while self._custom_container.count():
            item = self._custom_container.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        for name in self._custom_list:
            row_w = QWidget()
            row_l = QHBoxLayout(row_w)
            row_l.setContentsMargins(0, 0, 0, 0)
            row_l.setSpacing(4)
            lbl = QLabel(name)
            lbl.setStyleSheet("color: #c9d1d9; font-size: 11px;")
            row_l.addWidget(lbl, 1)
            btn_rm = QPushButton("×")
            btn_rm.setFixedSize(22, 22)
            btn_rm.setStyleSheet(
                "QPushButton { background: #2a1515; color: #f85149; border: 1px solid #5a2020;"
                " border-radius: 3px; font-size: 12px; font-weight: bold; padding: 0; }"
                "QPushButton:hover { background: #da3633; color: #fff; }"
            )
            btn_rm.clicked.connect(lambda _, n=name: self._remove_custom(n))
            row_l.addWidget(btn_rm)
            self._custom_container.addWidget(row_w)

    def get_paths(self) -> dict:
        return {k: v.text().strip() for k, v in self._path_edits.items() if v.text().strip()}

    def get_custom_providers(self) -> list:
        return list(self._custom_list)

    def get_autofill_enabled(self) -> bool:
        return self._autofill_cb.isChecked()


# ------------------------------------------------------------------ #
# VPN monitor worker (stdout 2FA auto-detection)                      #
# ------------------------------------------------------------------ #

class VpnMonitorWorker(QThread):
    twofa_detected = pyqtSignal(int)   # profile idx

    def __init__(self, idx: int, process, parent=None):
        super().__init__(parent)
        self._idx = idx
        self._process = process

    def run(self):
        try:
            for raw in iter(self._process.stdout.readline, b""):
                line = raw.decode("utf-8", errors="replace")
                if vpn_connect.is_2fa_prompt(line):
                    self.twofa_detected.emit(self._idx)
                    return
        except Exception:
            pass

    def send_token(self, token: str):
        try:
            self._process.stdin.write((token + "\n").encode())
            self._process.stdin.flush()
        except Exception:
            pass


# ------------------------------------------------------------------ #
# Status polling worker (runs subprocess calls off the UI thread)      #
# ------------------------------------------------------------------ #

class StatusWorker(QThread):
    results_ready = pyqtSignal(dict)  # {idx: status_str}

    def __init__(self, profiles, resolve_app_path=None, parent=None):
        super().__init__(parent)
        self._profiles = [
            (i, p.provider,
             resolve_app_path(p) if resolve_app_path else p.app_path,
             p.profile_name, p.server)
            for i, p in enumerate(profiles)
        ]

    def run(self):
        results = {}
        for idx, provider, app_path, profile_name, server in self._profiles:
            try:
                status = vpn_connect.get_status(provider, app_path, profile_name, server)
                if status:
                    results[idx] = status
            except Exception:
                pass
        self.results_ready.emit(results)


# ------------------------------------------------------------------ #
# Icon helpers                                                         #
# ------------------------------------------------------------------ #

def _make_connect_icon(size: int = 24) -> QIcon:
    """Green power-on icon (play triangle)."""
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#238636"))
    from PyQt6.QtGui import QPolygonF
    from PyQt6.QtCore import QPointF
    m = size * 0.2
    tri = QPolygonF([
        QPointF(m, m * 0.6),
        QPointF(size - m * 0.4, size / 2),
        QPointF(m, size - m * 0.6),
    ])
    p.drawPolygon(tri)
    p.end()
    return QIcon(px)


def _make_disconnect_icon(size: int = 24) -> QIcon:
    """Red stop icon (square)."""
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#da3633"))
    m = size * 0.25
    p.drawRoundedRect(int(m), int(m), int(size - 2 * m), int(size - 2 * m), 2, 2)
    p.end()
    return QIcon(px)


# Pre-build icons once
_ICON_CONNECT = None
_ICON_DISCONNECT = None

def _icons():
    global _ICON_CONNECT, _ICON_DISCONNECT
    if _ICON_CONNECT is None:
        _ICON_CONNECT = _make_connect_icon(20)
        _ICON_DISCONNECT = _make_disconnect_icon(20)
    return _ICON_CONNECT, _ICON_DISCONNECT


# Compact list window size vs edit window size
_LIST_SIZE = (420, 400)
_EDIT_SIZE = (520, 560)


class VpnPanel(QWidget):
    data_changed = pyqtSignal()

    def __init__(self, profiles: list, parent=None):
        super().__init__(parent)
        # Load custom providers before building UI
        models.refresh_vpn_providers(load_custom_vpn_providers())
        self._profiles = profiles
        self._edit_idx = -1
        self._updating = False
        self._status_labels = {}   # idx -> QLabel
        self._toggle_btns = {}     # idx -> QPushButton
        self._card_states = {}     # idx -> "connected" | "disconnected" | "connecting"
        self._card_widgets = {}    # idx -> QFrame (for search filtering)
        self._monitor_workers = {} # idx -> VpnMonitorWorker
        self._status_worker = None
        self._setup_ui()
        self._rebuild_cards()

        # Poll VPN status every 5 seconds — większy interval ogranicza spawn
        # subprocesów (ipconfig/netsh/PS) do akceptowalnego poziomu. Status VPN
        # nie zmienia się tak szybko, by potrzebne było odświeżanie co 3s.
        self._status_timer = QTimer(self)
        self._status_timer.timeout.connect(self._poll_status)
        self._status_timer.start(5000)

    def cleanup(self):
        """Stop timers and workers — call before discarding this panel."""
        self._status_timer.stop()
        if self._status_worker and self._status_worker.isRunning():
            self._status_worker.quit()
            self._status_worker.wait(1000)
        for w in self._monitor_workers.values():
            if w.isRunning():
                w.quit()
                w.wait(500)
        self._monitor_workers.clear()

    def get_profiles(self) -> list:
        return self._profiles

    # ------------------------------------------------------------------ #
    # Window resize helper                                                 #
    # ------------------------------------------------------------------ #

    def _resize_window(self, w: int, h: int):
        win = self.window()
        if win and win is not self:
            win.resize(w, h)
            win.setMinimumSize(w - 60, h - 60)

    # ------------------------------------------------------------------ #
    # UI setup                                                             #
    # ------------------------------------------------------------------ #

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._stack = QStackedWidget()
        root.addWidget(self._stack)

        # ---- Page 0: Compact card list ---- #
        self._list_page = QWidget()
        self._list_page.setStyleSheet("background: #0d1117;")
        list_layout = QVBoxLayout(self._list_page)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(0)

        # Top bar
        top_bar = QHBoxLayout()
        top_bar.setContentsMargins(12, 8, 12, 6)

        lbl_title = QLabel("Profile VPN")
        font = QFont()
        font.setBold(True)
        font.setPointSize(11)
        lbl_title.setFont(font)
        lbl_title.setStyleSheet("color: #c9d1d9;")
        top_bar.addWidget(lbl_title)
        top_bar.addStretch()

        btn_settings = QPushButton("⚙")
        btn_settings.setFixedHeight(26)
        btn_settings.setFixedWidth(30)
        btn_settings.setToolTip("Ustawienia VPN — ścieżki klientów, providery")
        btn_settings.setStyleSheet(
            "QPushButton { background: #21262d; color: #8b949e; border: 1px solid #30363d;"
            " border-radius: 4px; font-size: 13px; padding: 0; }"
            "QPushButton:hover { background: #30363d; color: #c9d1d9; }"
        )
        btn_settings.clicked.connect(self._open_vpn_settings)
        top_bar.addWidget(btn_settings)

        btn_add = QPushButton("+  Dodaj")
        btn_add.setFixedHeight(26)
        btn_add.setStyleSheet(
            "QPushButton { background: #238636; color: #fff; border: none; border-radius: 4px;"
            " padding: 0 10px; font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: #2ea043; }"
        )
        btn_add.clicked.connect(self._add_profile)
        top_bar.addWidget(btn_add)
        list_layout.addLayout(top_bar)

        # Search bar
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Szukaj profilu...")
        self._search_edit.setClearButtonEnabled(True)
        self._search_edit.setStyleSheet(
            "QLineEdit { background: #21262d; border: 1px solid #30363d; border-radius: 4px;"
            " padding: 5px 8px; color: #c9d1d9; font-size: 11px; margin: 0 10px 4px 10px; }"
            "QLineEdit:focus { border-color: #1f6feb; }"
        )
        self._search_edit.textChanged.connect(self._filter_cards)
        list_layout.addWidget(self._search_edit)

        # Scrollable card area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            "QScrollArea { border: none; background: #0d1117; }"
            "QScrollBar:vertical { background: #0d1117; width: 6px; }"
            "QScrollBar::handle:vertical { background: #30363d; border-radius: 3px; }"
        )
        self._cards_container = QWidget()
        self._cards_layout = QVBoxLayout(self._cards_container)
        self._cards_layout.setContentsMargins(10, 2, 10, 10)
        self._cards_layout.setSpacing(4)
        self._cards_layout.addStretch()
        scroll.setWidget(self._cards_container)
        list_layout.addWidget(scroll)

        self._stack.addWidget(self._list_page)

        # ---- Page 1: Edit view ---- #
        self._edit_page = QWidget()
        self._edit_page.setStyleSheet("background: #0d1117;")
        edit_layout = QVBoxLayout(self._edit_page)
        edit_layout.setContentsMargins(0, 0, 0, 0)
        edit_layout.setSpacing(0)

        # Edit top bar
        edit_top = QHBoxLayout()
        edit_top.setContentsMargins(12, 8, 12, 6)

        btn_back = QPushButton("<-  Wróć")
        btn_back.setStyleSheet(
            "QPushButton { background: #21262d; color: #c9d1d9; border: 1px solid #30363d;"
            " border-radius: 4px; padding: 4px 10px; font-size: 11px; }"
            "QPushButton:hover { background: #30363d; }"
        )
        btn_back.clicked.connect(self._exit_edit)
        edit_top.addWidget(btn_back)

        self._edit_title = QLabel("Edycja profilu")
        font2 = QFont()
        font2.setBold(True)
        font2.setPointSize(11)
        self._edit_title.setFont(font2)
        self._edit_title.setStyleSheet("color: #c9d1d9; padding-left: 8px;")
        edit_top.addWidget(self._edit_title)
        edit_top.addStretch()

        btn_del = QPushButton("Usuń")
        btn_del.setStyleSheet(
            "QPushButton { background: #21262d; color: #f85149; border: 1px solid #da3633;"
            " border-radius: 4px; padding: 4px 10px; font-size: 11px; font-weight: bold; }"
            "QPushButton:hover { background: #da3633; color: #fff; }"
        )
        btn_del.clicked.connect(self._del_profile)
        edit_top.addWidget(btn_del)
        edit_layout.addLayout(edit_top)

        # Edit form in scroll area
        edit_scroll = QScrollArea()
        edit_scroll.setWidgetResizable(True)
        edit_scroll.setStyleSheet(
            "QScrollArea { border: none; background: #0d1117; }"
        )
        edit_form_widget = QWidget()
        self._edit_form = QVBoxLayout(edit_form_widget)
        self._edit_form.setContentsMargins(12, 6, 12, 12)
        self._edit_form.setSpacing(5)

        self._name_edit = self._make_field("Nazwa profilu...")
        self._name_edit.setStyleSheet(
            "QLineEdit { background: #21262d; border: 1px solid #30363d; border-radius: 4px;"
            " padding: 6px 10px; color: #c9d1d9; font-size: 13px; font-weight: bold; }"
            "QLineEdit:focus { border-color: #1f6feb; }"
        )
        self._edit_form.addWidget(self._name_edit)
        self._edit_form.addSpacing(2)

        self._provider_combo = QComboBox()
        self._provider_combo.addItems(models.VPN_PROVIDERS)
        self._provider_combo.setStyleSheet(
            "QComboBox { background: #21262d; border: 1px solid #30363d; border-radius: 4px;"
            " padding: 5px 8px; color: #c9d1d9; font-size: 11px; }"
            "QComboBox::drop-down { border: none; }"
            "QComboBox QAbstractItemView { background: #21262d; color: #c9d1d9;"
            " selection-background-color: #1f6feb; }"
        )
        self._provider_combo.currentIndexChanged.connect(self._on_field_changed)
        self._add_labeled(self._edit_form, "Provider", self._provider_combo)

        # Profile name
        self._profile_name_edit = self._make_field("Nazwa profilu/połączenia w kliencie VPN")
        self._profile_name_edit.textChanged.connect(self._update_field_visibility)
        self._add_labeled(self._edit_form, "Nazwa profilu w kliencie", self._profile_name_edit)

        # Login / password row
        row2 = QHBoxLayout()
        row2.setSpacing(6)
        self._login_edit = self._make_field("Login")
        row2.addWidget(self._wrap_labeled("Login", self._login_edit), 1)

        pass_widget = QWidget()
        pass_lay = QHBoxLayout(pass_widget)
        pass_lay.setContentsMargins(0, 0, 0, 0)
        pass_lay.setSpacing(3)
        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.setPlaceholderText("Hasło")
        self._pass_edit.setStyleSheet(self._field_style())
        self._pass_edit.textChanged.connect(self._on_field_changed)
        pass_lay.addWidget(self._pass_edit)
        btn_eye = QPushButton("👁")
        btn_eye.setFixedSize(28, 28)
        btn_eye.setStyleSheet(
            "QPushButton { background: #21262d; border: 1px solid #30363d; border-radius: 4px; font-size: 10px; }"
            "QPushButton:hover { background: #30363d; }"
        )
        btn_eye.clicked.connect(lambda: self._pass_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if self._pass_edit.echoMode() == QLineEdit.EchoMode.Password
            else QLineEdit.EchoMode.Password
        ))
        pass_lay.addWidget(btn_eye)
        btn_copy = QPushButton("📋")
        btn_copy.setFixedSize(28, 28)
        btn_copy.setStyleSheet(
            "QPushButton { background: #21262d; border: 1px solid #30363d; border-radius: 4px; font-size: 10px; }"
            "QPushButton:hover { background: #30363d; }"
        )
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(self._pass_edit.text()))
        pass_lay.addWidget(btn_copy)
        row2.addWidget(self._wrap_labeled("Hasło", pass_widget), 1)
        self._edit_form.addLayout(row2)

        # Server / port row (hideable)
        self._server_port_widget = QWidget()
        row1 = QHBoxLayout(self._server_port_widget)
        row1.setContentsMargins(0, 0, 0, 0)
        row1.setSpacing(6)
        self._server_edit = self._make_field("Adres serwera")
        self._port_edit = self._make_field("Port")
        self._port_edit.setMaximumWidth(80)
        row1.addWidget(self._wrap_labeled("Serwer", self._server_edit), 1)
        row1.addWidget(self._wrap_labeled("Port", self._port_edit), 0)
        self._edit_form.addWidget(self._server_port_widget)

        # Group / domain row (hideable)
        self._group_domain_widget = QWidget()
        row3 = QHBoxLayout(self._group_domain_widget)
        row3.setContentsMargins(0, 0, 0, 0)
        row3.setSpacing(6)
        self._group_edit = self._make_field("Grupa / Realm")
        self._domain_edit = self._make_field("Domena")
        row3.addWidget(self._wrap_labeled("Grupa / Realm", self._group_edit), 1)
        row3.addWidget(self._wrap_labeled("Domena", self._domain_edit), 1)
        self._edit_form.addWidget(self._group_domain_widget)

        # Notes
        lbl_notes = QLabel("Notatki")
        lbl_notes.setStyleSheet("color: #8b949e; font-size: 10px; margin-top: 2px;")
        self._edit_form.addWidget(lbl_notes)
        self._notes_edit = QTextEdit()
        self._notes_edit.setMaximumHeight(60)
        self._notes_edit.setStyleSheet(
            "QTextEdit { background: #21262d; border: 1px solid #30363d; border-radius: 4px;"
            " padding: 4px; color: #c9d1d9; font-size: 11px; }"
            "QTextEdit:focus { border-color: #1f6feb; }"
        )
        self._notes_edit.textChanged.connect(self._on_field_changed)
        self._edit_form.addWidget(self._notes_edit)

        # Launch client button
        self._btn_launch = QPushButton("Otwórz klienta VPN")
        self._btn_launch.setStyleSheet(
            "QPushButton { background: #1a3a5c; color: #58a6ff; border: 1px solid #1f6feb;"
            " border-radius: 4px; padding: 7px 14px; font-size: 11px; }"
            "QPushButton:hover { background: #1f6feb; color: #fff; }"
        )
        self._btn_launch.clicked.connect(self._launch_vpn_client)
        self._edit_form.addWidget(self._btn_launch)

        self._edit_form.addStretch()

        edit_scroll.setWidget(edit_form_widget)
        edit_layout.addWidget(edit_scroll)

        self._stack.addWidget(self._edit_page)
        self._stack.setCurrentIndex(0)

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _field_style():
        return (
            "QLineEdit { background: #21262d; border: 1px solid #30363d; border-radius: 4px;"
            " padding: 5px 8px; color: #c9d1d9; font-size: 11px; }"
            "QLineEdit:focus { border-color: #1f6feb; }"
        )

    def _make_field(self, placeholder: str) -> QLineEdit:
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        edit.setStyleSheet(self._field_style())
        edit.textChanged.connect(self._on_field_changed)
        return edit

    def _wrap_labeled(self, label: str, widget: QWidget) -> QWidget:
        c = QWidget()
        lay = QVBoxLayout(c)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(1)
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #8b949e; font-size: 10px;")
        lay.addWidget(lbl)
        lay.addWidget(widget)
        return c

    def _add_labeled(self, layout, label: str, widget: QWidget):
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #8b949e; font-size: 10px;")
        layout.addWidget(lbl)
        if widget:
            layout.addWidget(widget)

    def _update_field_visibility(self):
        """All fields always visible."""
        pass

    # ------------------------------------------------------------------ #
    # Card list                                                            #
    # ------------------------------------------------------------------ #

    def _rebuild_cards(self):
        self._status_labels.clear()
        self._toggle_btns.clear()
        self._card_states.clear()
        self._card_widgets.clear()
        while self._cards_layout.count() > 1:
            item = self._cards_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        if not self._profiles:
            lbl = QLabel("Brak profili VPN.\nDodaj nowy przyciskiem powyżej.")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet("color: #484f58; font-size: 12px; padding: 30px;")
            self._cards_layout.insertWidget(0, lbl)
            return

        for i, p in enumerate(self._profiles):
            card = self._make_card(i, p)
            self._card_widgets[i] = card
            self._cards_layout.insertWidget(self._cards_layout.count() - 1, card)

        self._filter_cards(self._search_edit.text() if hasattr(self, '_search_edit') else "")
        self._poll_status()

    def _filter_cards(self, text: str):
        """Show/hide cards based on search text."""
        query = text.strip().lower()
        for idx, card in self._card_widgets.items():
            if not query:
                card.setVisible(True)
                continue
            p = self._profiles[idx]
            searchable = f"{p.name} {p.provider} {p.profile_name} {p.server}".lower()
            card.setVisible(query in searchable)

    def _sort_profiles(self, key: str):
        """Sort profiles by name or provider and rebuild cards."""
        if not self._profiles:
            return
        try:
            locale.setlocale(locale.LC_COLLATE, "pl_PL.UTF-8")
        except locale.Error:
            try:
                locale.setlocale(locale.LC_COLLATE, "Polish_Poland.1250")
            except locale.Error:
                pass
        sk = locale.strxfrm
        if key == "name":
            self._profiles.sort(key=lambda p: sk((p.name or "").lower()))
        elif key == "provider":
            self._profiles.sort(key=lambda p: (sk((p.provider or "").lower()), sk((p.name or "").lower())))
        self._rebuild_cards()
        self.data_changed.emit()

    def _make_card(self, idx: int, p) -> QFrame:
        card = QFrame()
        card.setStyleSheet(
            "QFrame { background: #161b22; border: 1px solid #30363d; border-radius: 6px; }"
        )
        lay = QHBoxLayout(card)
        lay.setContentsMargins(10, 6, 8, 6)
        lay.setSpacing(8)

        # Info column (name + details + status on separate lines)
        info = QVBoxLayout()
        info.setSpacing(1)

        name_lbl = QLabel(p.name or "(bez nazwy)")
        name_lbl.setStyleSheet("color: #c9d1d9; font-size: 12px; font-weight: bold; border: none;")
        info.addWidget(name_lbl)

        if p.profile_name:
            det_text = f"{p.provider}  ·  {p.profile_name}"
            det_lbl = QLabel(det_text)
            det_lbl.setStyleSheet("color: #58a6ff; font-size: 10px; border: none;")
        else:
            details = f"{p.provider}  ·  {p.server}" + (f":{p.port}" if p.port else "")
            det_lbl = QLabel(details)
            det_lbl.setStyleSheet("color: #8b949e; font-size: 10px; border: none;")
        info.addWidget(det_lbl)

        # Status label — under info, not squeezed between buttons
        status_lbl = QLabel("")
        status_lbl.setStyleSheet("color: #8b949e; font-size: 10px; border: none;")
        info.addWidget(status_lbl)
        self._status_labels[idx] = status_lbl

        lay.addLayout(info, 1)

        # Toggle connect/disconnect button — single button that swaps icon
        icon_conn, icon_disc = _icons()
        btn_toggle = QPushButton()
        btn_toggle.setFixedSize(30, 30)
        btn_toggle.setIcon(icon_conn)
        btn_toggle.setIconSize(QSize(18, 18))
        btn_toggle.setToolTip("Połącz")
        btn_toggle.setStyleSheet(
            "QPushButton { background: #21262d; border: 1px solid #30363d; border-radius: 6px; }"
            "QPushButton:hover { background: rgba(35,134,54,0.15); border: 1px solid #238636; }"
            "QPushButton:pressed { background: rgba(35,134,54,0.30); border: 1px solid #2ea043; }"
        )
        btn_toggle.clicked.connect(lambda _, i=idx: self._toggle_connection(i))
        lay.addWidget(btn_toggle)
        self._toggle_btns[idx] = btn_toggle
        self._card_states[idx] = "disconnected"

        # Copy login button
        if p.login:
            btn_copy_login = QPushButton("👤")
            btn_copy_login.setFixedSize(30, 30)
            btn_copy_login.setToolTip(f"Kopiuj login: {p.login}")
            btn_copy_login.setStyleSheet(
                "QPushButton { background: #21262d; color: #8b949e; border: 1px solid #30363d;"
                " border-radius: 6px; font-size: 12px; }"
                "QPushButton:hover { background: #30363d; color: #c9d1d9; }"
            )
            btn_copy_login.clicked.connect(lambda _, i=idx: self._copy_login(i))
            lay.addWidget(btn_copy_login)

        # Copy password button
        if p.password:
            btn_copy = QPushButton("🔑")
            btn_copy.setFixedSize(30, 30)
            btn_copy.setToolTip("Kopiuj hasło")
            btn_copy.setStyleSheet(
                "QPushButton { background: #21262d; color: #c9a227; border: 1px solid #30363d;"
                " border-radius: 6px; font-size: 12px; }"
                "QPushButton:hover { background: #2a2515; color: #f0d050; border-color: #c9a227; }"
            )
            btn_copy.clicked.connect(lambda _, i=idx: self._copy_password(i))
            lay.addWidget(btn_copy)

        # Edit button
        btn_edit = QPushButton("✎")
        btn_edit.setFixedSize(30, 30)
        btn_edit.setToolTip("Edytuj")
        btn_edit.setStyleSheet(
            "QPushButton { background: #21262d; color: #8b949e; border: 1px solid #30363d;"
            " border-radius: 6px; font-size: 12px; }"
            "QPushButton:hover { background: #30363d; color: #c9d1d9; }"
        )
        btn_edit.clicked.connect(lambda _, i=idx: self._enter_edit(i))
        lay.addWidget(btn_edit)

        return card

    def _update_toggle_btn(self, idx: int, state: str):
        """Update toggle button icon based on connection state."""
        btn = self._toggle_btns.get(idx)
        if not btn:
            return
        icon_conn, icon_disc = _icons()
        self._card_states[idx] = state
        if state == "connected":
            btn.setIcon(icon_disc)
            btn.setToolTip("Rozłącz")
            btn.setStyleSheet(
                "QPushButton { background: #21262d; border: 1px solid #30363d; border-radius: 6px; }"
                "QPushButton:hover { background: rgba(218,54,51,0.15); border: 1px solid #da3633; }"
                "QPushButton:pressed { background: rgba(218,54,51,0.30); border: 1px solid #f85149; }"
            )
        else:
            btn.setIcon(icon_conn)
            btn.setToolTip("Połącz")
            btn.setStyleSheet(
                "QPushButton { background: #21262d; border: 1px solid #30363d; border-radius: 6px; }"
                "QPushButton:hover { background: rgba(35,134,54,0.15); border: 1px solid #238636; }"
                "QPushButton:pressed { background: rgba(35,134,54,0.30); border: 1px solid #2ea043; }"
            )

    def _copy_login(self, idx: int):
        """Copy login to clipboard and show brief feedback."""
        if idx >= len(self._profiles):
            return
        p = self._profiles[idx]
        if p.login:
            QApplication.clipboard().setText(p.login)
            lbl = self._status_labels.get(idx)
            if lbl:
                old_text = lbl.text()
                old_style = lbl.styleSheet()
                lbl.setText("Login skopiowany!")
                lbl.setStyleSheet("color: #58a6ff; font-size: 10px; font-weight: bold; border: none;")
                QTimer.singleShot(1500, lambda: (lbl.setText(old_text), lbl.setStyleSheet(old_style)))

    def _copy_password(self, idx: int):
        """Copy password to clipboard and show brief tooltip."""
        if idx >= len(self._profiles):
            return
        p = self._profiles[idx]
        if p.password:
            QApplication.clipboard().setText(p.password)
            lbl = self._status_labels.get(idx)
            if lbl:
                old_text = lbl.text()
                old_style = lbl.styleSheet()
                lbl.setText("Skopiowano!")
                lbl.setStyleSheet("color: #3fb950; font-size: 10px; font-weight: bold; border: none;")
                QTimer.singleShot(1500, lambda: (lbl.setText(old_text), lbl.setStyleSheet(old_style)))

    def _toggle_connection(self, idx: int):
        """Connect or disconnect based on current state."""
        if idx >= len(self._profiles):
            return
        state = self._card_states.get(idx, "disconnected")
        if state == "connected":
            self._disconnect_card(idx)
        else:
            self._connect_card(idx)

    # ------------------------------------------------------------------ #
    # Status polling                                                       #
    # ------------------------------------------------------------------ #

    def _poll_status(self):
        if self._stack.currentIndex() != 0:
            return
        if self._status_worker and self._status_worker.isRunning():
            return  # previous poll still running
        self._status_worker = StatusWorker(self._profiles, self._resolve_app_path, self)
        self._status_worker.results_ready.connect(self._apply_status_results)
        self._status_worker.start()

    def _apply_status_results(self, results: dict):
        for idx, status in results.items():
            lbl = self._status_labels.get(idx)
            if not lbl:
                continue
            if status == "Connected":
                lbl.setStyleSheet("color: #3fb950; font-size: 10px; font-weight: bold; border: none;")
                lbl.setText("● Połączono")
                self._update_toggle_btn(idx, "connected")
            elif "Connecting" in status:
                lbl.setStyleSheet("color: #d29922; font-size: 10px; border: none;")
                lbl.setText("◌ Łączenie...")
                self._update_toggle_btn(idx, "connecting")
            elif "Disconnected" in status:
                lbl.setStyleSheet("color: #8b949e; font-size: 10px; border: none;")
                lbl.setText("○ Rozłączono")
                self._update_toggle_btn(idx, "disconnected")
            else:
                lbl.setStyleSheet("color: #8b949e; font-size: 10px; border: none;")
                lbl.setText(status)

    # ------------------------------------------------------------------ #
    # Actions                                                              #
    # ------------------------------------------------------------------ #

    def _launch_vpn_client(self):
        if self._edit_idx < 0 or self._edit_idx >= len(self._profiles):
            return
        p = self._profiles[self._edit_idx]
        path = self._resolve_app_path(p)
        if not path:
            QMessageBox.information(self, "Klient VPN",
                                    "Nie ustawiono ścieżki do klienta VPN.\n"
                                    "Ustaw globalnie w ⚙ Ustawienia VPN.")
            return
        ok, msg = vpn_connect.launch_app(path)
        if not ok:
            QMessageBox.warning(self, "Klient VPN", msg)

    def _resolve_app_path(self, p) -> str:
        """Return profile app_path, falling back to global provider path."""
        if p.app_path:
            return p.app_path
        return load_vpn_provider_paths().get(p.provider, "")

    def _connect_card(self, idx: int):
        if idx >= len(self._profiles):
            return
        p = self._profiles[idx]
        app_path = self._resolve_app_path(p)
        lbl = self._status_labels.get(idx)
        if not p.server and not app_path and not p.profile_name:
            if lbl:
                lbl.setStyleSheet("color: #f85149; font-size: 10px; border: none;")
                lbl.setText("Brak konfig.")
            return

        ok, msg, process = vpn_connect.connect_monitored(
            p.provider, p.server, p.port, p.login, p.password, p.group, p.domain,
            app_path, p.profile_name,
            autofill=load_vpn_autofill_enabled(),
        )
        if lbl:
            color = "#58a6ff" if ok else "#f85149"
            lbl.setStyleSheet(f"color: {color}; font-size: 10px; border: none;")
            lbl.setText(msg[:30])
        if ok:
            self._update_toggle_btn(idx, "connecting")
            # Start stdout monitor for auto-detection (even when checkbox is set,
            # in case the provider ignores --token and still prompts via stdout)
            if process is not None:
                self._start_monitor(idx, process)
            # Invalidate adapter cache — następny poll musi widzieć świeży stan
            # adapterów, nie odpowiedź sprzed connectu (cache trzyma do 15s).
            vpn_connect.invalidate_adapter_cache()
            QTimer.singleShot(2000, self._poll_status)

    def _start_monitor(self, idx: int, process):
        # Stop any previous worker for this idx
        old = self._monitor_workers.pop(idx, None)
        if old and old.isRunning():
            old.terminate()

        worker = VpnMonitorWorker(idx, process, self)
        worker.twofa_detected.connect(self._on_2fa_detected)
        worker.finished.connect(lambda i=idx: self._monitor_workers.pop(i, None))
        self._monitor_workers[idx] = worker
        worker.start()

    def _on_2fa_detected(self, idx: int):
        if idx >= len(self._profiles):
            return
        p = self._profiles[idx]
        worker = self._monitor_workers.get(idx)
        if not worker:
            return
        dlg = TwoFactorDialog(p.name or p.profile_name or p.server, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            worker.send_token(dlg.code())

    def _disconnect_card(self, idx: int):
        if idx >= len(self._profiles):
            return
        p = self._profiles[idx]
        lbl = self._status_labels.get(idx)
        app_path = self._resolve_app_path(p)
        ok, msg = vpn_connect.disconnect(p.provider, p.server, app_path, p.profile_name)
        if lbl:
            color = "#58a6ff" if ok else "#f85149"
            lbl.setStyleSheet(f"color: {color}; font-size: 10px; border: none;")
            lbl.setText(msg[:30])
        if ok:
            self._update_toggle_btn(idx, "disconnected")
            # Invalidate adapter cache — bez tego pierwszy poll po disconnect
            # mógłby zwrócić stary "Connected" z cache (TTL 4s/15s).
            vpn_connect.invalidate_adapter_cache()
            # Poll quickly after disconnect to catch status change
            QTimer.singleShot(1000, self._poll_status)
            QTimer.singleShot(3000, self._poll_status)

    # ------------------------------------------------------------------ #
    # VPN Settings                                                         #
    # ------------------------------------------------------------------ #

    def _open_vpn_settings(self):
        dlg = VpnSettingsDialog(self)
        dlg.import_forti_requested.connect(lambda: self._import_forti_tunnels_from_settings(dlg))
        if dlg.exec():
            save_vpn_provider_paths(dlg.get_paths())
            custom = dlg.get_custom_providers()
            save_custom_vpn_providers(custom)
            save_vpn_autofill_enabled(dlg.get_autofill_enabled())
            models.refresh_vpn_providers(custom)
            # Apply global paths to profiles that have no custom path
            global_paths = dlg.get_paths()
            for p in self._profiles:
                if not p.app_path and p.provider in global_paths:
                    p.app_path = global_paths[p.provider]
            # Refresh provider combo in edit view
            self._provider_combo.clear()
            self._provider_combo.addItems(models.VPN_PROVIDERS)
            self._rebuild_cards()

    # ------------------------------------------------------------------ #
    # Add / delete                                                         #
    # ------------------------------------------------------------------ #

    def _import_forti_tunnels_from_settings(self, settings_dlg):
        """Import FortiClient tunnels while settings dialog is open."""
        self._import_forti_tunnels()

    def _import_forti_tunnels(self):
        """Import VPN tunnels from FortiClient registry."""
        tunnels = vpn_connect.get_forti_tunnels_from_registry()
        if not tunnels:
            QMessageBox.information(self, "Import FortiClient",
                                    "Nie znaleziono tuneli VPN w FortiClient.")
            return

        # Filter out tunnels that already exist (by profile_name)
        existing_names = {p.profile_name for p in self._profiles if p.provider == "FortiClient"}
        new_tunnels = [t for t in tunnels if t["name"] not in existing_names]

        if not new_tunnels:
            QMessageBox.information(self, "Import FortiClient",
                                    f"Wszystkie tunele ({len(tunnels)}) już zaimportowane.")
            return

        for t in new_tunnels:
            p = models.VpnProfile(
                name=t["name"],
                provider="FortiClient",
                server=t["server"],
                port=t["port"],
                profile_name=t["name"],
            )
            self._profiles.append(p)

        self._rebuild_cards()
        self.data_changed.emit()
        QMessageBox.information(
            self, "Import FortiClient",
            f"Zaimportowano {len(new_tunnels)} tunel(i) z FortiClient."
        )

    def _add_profile(self):
        p = models.VpnProfile(name="Nowy profil VPN")
        self._profiles.append(p)
        self._enter_edit(len(self._profiles) - 1)
        self._name_edit.selectAll()
        self.data_changed.emit()

    def _del_profile(self):
        if self._edit_idx < 0 or self._edit_idx >= len(self._profiles):
            return
        name = self._profiles[self._edit_idx].name or "(nowy profil)"
        ans = QMessageBox.question(self, "Usuń profil",
                                   f"Usunąć profil \"{name}\"?")
        if ans != QMessageBox.StandardButton.Yes:
            return
        self._profiles.pop(self._edit_idx)
        self._edit_idx = -1
        self._exit_edit()
        self.data_changed.emit()

    # ------------------------------------------------------------------ #
    # Edit mode                                                            #
    # ------------------------------------------------------------------ #

    def _enter_edit(self, idx: int):
        self._edit_idx = idx
        self._load_detail()
        self._edit_title.setText("Edycja profilu")
        self._stack.setCurrentIndex(1)
        self._resize_window(*_EDIT_SIZE)
        self._name_edit.setFocus()

    def _exit_edit(self):
        self._edit_idx = -1
        self._rebuild_cards()
        self._stack.setCurrentIndex(0)
        self._resize_window(*_LIST_SIZE)

    def _load_detail(self):
        self._updating = True
        p = self._profiles[self._edit_idx]
        self._name_edit.setText(p.name)
        idx = self._provider_combo.findText(p.provider)
        self._provider_combo.setCurrentIndex(max(idx, 0))
        self._profile_name_edit.setText(p.profile_name)
        self._login_edit.setText(p.login)
        self._pass_edit.setText(p.password)
        self._server_edit.setText(p.server)
        self._port_edit.setText(p.port)
        self._group_edit.setText(p.group)
        self._domain_edit.setText(p.domain)
        self._notes_edit.setPlainText(p.notes)
        self._updating = False
        self._update_field_visibility()

    def _on_field_changed(self):
        if self._updating or self._edit_idx < 0:
            return
        if self._edit_idx >= len(self._profiles):
            return
        p = self._profiles[self._edit_idx]
        p.name = self._name_edit.text()
        p.provider = self._provider_combo.currentText()
        p.profile_name = self._profile_name_edit.text()
        p.server = self._server_edit.text()
        p.port = self._port_edit.text()
        p.login = self._login_edit.text()
        p.password = self._pass_edit.text()
        p.group = self._group_edit.text()
        p.domain = self._domain_edit.text()
        p.notes = self._notes_edit.toPlainText()
        self.data_changed.emit()
