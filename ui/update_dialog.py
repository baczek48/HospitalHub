"""„Sprawdź aktualizacje…” — check GitHub, download, verify, install.

HospitalHub: the verified installer is started after the app has closed the
way "Zamknij wszystko" closes it (unsaved vaults are asked about first), and
the installer starts HospitalHub again when it is done.
Portable: the verified zip lands in Pobrane — the folder is replaced by hand,
because its vault and settings live next to the exe.
"""

from __future__ import annotations

import os
from pathlib import Path

from PyQt6.QtCore import QThread, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices, QTextBlockFormat, QTextCursor
from PyQt6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QMessageBox, QProgressBar, QPushButton,
    QTextBrowser, QVBoxLayout,
)

import app_version
import updater

#: Set by main.py: ``quit_all(before_quit) -> bool`` — closes HospitalHub like
#: "Zamknij wszystko"; calls ``before_quit()`` only once nothing stops it.
_quit_all_hook = None


def set_quit_all_hook(hook) -> None:
    global _quit_all_hook
    _quit_all_hook = hook


def _date(iso: str) -> str:
    parts = (iso or "").split("-")
    return ".".join(reversed(parts)) if len(parts) == 3 else iso


def _airy(doc) -> None:
    """Line height and a gap after each paragraph / list item, so a long
    list of changes does not read as one block."""
    cursor = QTextCursor(doc)
    block = doc.begin()
    while block.isValid():
        cursor.setPosition(block.position())
        fmt = QTextBlockFormat()
        fmt.setLineHeight(135.0, QTextBlockFormat.LineHeightTypes.ProportionalHeight.value)
        fmt.setBottomMargin(8.0)
        if block.textList() is not None:
            fmt.setTopMargin(2.0)
        cursor.mergeBlockFormat(fmt)
        block = block.next()


class _Check(QThread):
    done = pyqtSignal(object, str)          # Release | None, error

    def run(self):
        try:
            self.done.emit(updater.fetch_latest(), "")
        except updater.UpdateError as exc:
            self.done.emit(None, str(exc))
        except Exception as exc:            # never let the thread die silently
            self.done.emit(None, f"Błąd sprawdzania ({type(exc).__name__}).")


class _Download(QThread):
    progress = pyqtSignal(int, int)
    done = pyqtSignal(str, str)             # path, error

    def __init__(self, asset, dest_dir, parent=None):
        super().__init__(parent)
        self._asset = asset
        self._dest = dest_dir
        self.stop = False

    def run(self):
        try:
            path = updater.download(self._asset, self._dest,
                                    progress=lambda d, t: self.progress.emit(d, t),
                                    cancelled=lambda: self.stop)
            self.done.emit(path, "")
        except updater.UpdateError as exc:
            self.done.emit("", str(exc))
        except Exception as exc:
            self.done.emit("", f"Błąd pobierania ({type(exc).__name__}).")


class UpdateDialog(QDialog):
    def __init__(self, variant: str = "V2", parent=None, *, check=True):
        super().__init__(parent)
        self._variant = variant
        self._release = None
        self._thread = None
        self.setWindowTitle("Aktualizacja HospitalHub")
        self.setMinimumWidth(520)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 16)
        lay.setSpacing(10)
        self._status = QLabel()
        self._status.setWordWrap(True)
        self._status.setStyleSheet("font-size: 14px;")
        lay.addWidget(self._status)
        self._detail = QLabel()
        self._detail.setWordWrap(True)
        self._detail.setStyleSheet("color: #8b949e;")
        lay.addWidget(self._detail)
        # 2026-11-26 (owner): the list of changes was cramped (200 px, small
        # print) — now it takes the window, grows with it, and reads easier.
        self._notes = QTextBrowser()
        self._notes.setOpenExternalLinks(True)
        self._notes.setMinimumHeight(220)
        font = self._notes.font()
        font.setPointSizeF(max(font.pointSizeF(), 9.0) + 1.5)
        self._notes.setFont(font)
        self._notes.document().setDocumentMargin(14)
        self._notes.setStyleSheet(
            # Palette colours: right on the light and the dark theme.
            "QTextBrowser { background:palette(base); color:palette(text);"
            " border:1px solid palette(mid); border-radius:8px; }")
        self._notes.hide()
        lay.addWidget(self._notes, 1)
        self._bar = QProgressBar()
        self._bar.hide()
        lay.addWidget(self._bar)

        row = QHBoxLayout()
        self._page = QPushButton("Strona wydania")
        self._page.clicked.connect(self._open_page)
        self._page.hide()
        self._action = QPushButton()
        self._action.setDefault(True)
        self._action.clicked.connect(self._start_download)
        self._action.hide()
        self._close = QPushButton("Zamknij")
        self._close.clicked.connect(self.reject)
        row.addWidget(self._page)
        row.addStretch(1)
        row.addWidget(self._action)
        row.addWidget(self._close)
        lay.addLayout(row)

        if check:
            self._check()

    # -- 1. check ------------------------------------------------------- #

    def _check(self):
        self._status.setText("Sprawdzam najnowszą wersję na GitHubie…")
        self._detail.setText(f"Ta wersja: {app_version.version_label()}")
        self._bar.setRange(0, 0)
        self._bar.show()
        self._thread = _Check(self)
        self._thread.done.connect(self.show_result)
        self._thread.start()

    def show_result(self, release, error: str = ""):
        self._bar.hide()
        if release is None:
            self._status.setText("Nie udało się sprawdzić aktualizacji.")
            self._detail.setText(error)
            return
        self._release = release
        self._page.show()
        current = app_version.VERSION
        cmp = updater.compare(release.version, current)
        latest = f"v{release.version}"
        when = f" (wydano {_date(release.published)})" if release.published else ""
        asset = release.asset_for(self._variant)
        if cmp == 1:
            self._status.setText(f"Dostępna nowa wersja: {latest}{when}")
            self._detail.setText(f"Ta wersja: {app_version.version_label()}")
            if release.notes:
                self._notes.setMarkdown(updater.changes_only(release.notes))
                _airy(self._notes.document())
                self._notes.show()
                # Room to read: bigger than the bare minimum the first time.
                self.resize(max(self.width(), 760), max(self.height(), 620))
            if asset is None:
                self._detail.setText(self._detail.text() + " — brak pliku do pobrania, "
                                     "zobacz stronę wydania.")
            else:
                mb = asset.size / 1_048_576
                self._action.setText(("Pobierz i zainstaluj" if self._variant == "V2"
                                      else "Pobierz zip") + f" ({mb:.0f} MB)")
                self._action.show()
        elif cmp == 0:
            self._status.setText(f"Masz najnowszą wersję ({latest}).")
        elif cmp == -1:
            self._status.setText(f"Ta wersja ({app_version.version_label()}) jest nowsza "
                                 f"niż najnowsze wydanie na GitHubie ({latest}).")
            self._detail.setText("To wersja testowa — nic do aktualizowania.")
        else:
            self._status.setText(f"Najnowsze wydanie na GitHubie: {latest}{when}")
            self._detail.setText("Ta kopia nie ma numeru wersji (uruchomiona ze źródeł "
                                 "albo zbudowana bez numeru) — nie da się porównać.")

    def _open_page(self):
        if self._release and self._release.page:
            QDesktopServices.openUrl(QUrl(self._release.page))

    # -- 2. download ---------------------------------------------------- #

    def _start_download(self):
        asset = self._release.asset_for(self._variant) if self._release else None
        if asset is None:
            return
        dest = None
        if self._variant != "V2":
            dest = str(Path.home() / "Downloads")
            os.makedirs(dest, exist_ok=True)
        self._action.setEnabled(False)
        self._close.setText("Anuluj")
        self._status.setText(f"Pobieram {asset.name}…")
        self._bar.setRange(0, max(asset.size, 1))
        self._bar.setValue(0)
        self._bar.show()
        self._thread = _Download(asset, dest, self)
        self._thread.progress.connect(lambda d, t: self._bar.setValue(d))
        self._thread.done.connect(self._downloaded)
        self._thread.start()

    def reject(self):
        if isinstance(self._thread, _Download) and self._thread.isRunning():
            self._thread.stop = True
            self._thread.wait(5000)
        super().reject()

    def _downloaded(self, path: str, error: str):
        self._close.setText("Zamknij")
        self._bar.hide()
        if error:
            self._status.setText("Aktualizacja nie powiodła się.")
            self._detail.setText(error)
            self._action.setEnabled(True)
            return
        self._action.hide()
        if self._variant != "V2":
            self._status.setText("Pobrano i sprawdzono (SHA-256 zgodna).")
            self._detail.setText(f"{path}\nZamknij HospitalHub Portable i podmień folder "
                                 "programu zawartością zipa (vault i ustawienia zostaw).")
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(path)))
            return
        self._status.setText("Pobrano i sprawdzono (SHA-256 zgodna).")
        self.install(path)

    # -- 3. install ----------------------------------------------------- #

    def install(self, path: str) -> bool:
        if _quit_all_hook is None:
            self._detail.setText(f"Uruchom instalator ręcznie: {path}")
            return False
        box = QMessageBox(self)
        box.setWindowTitle("Instalacja aktualizacji")
        box.setIcon(QMessageBox.Icon.Question)
        box.setText("HospitalHub zamknie się teraz całkowicie (jak „Zamknij wszystko”), "
                    "a potem uruchomi się instalator.\n\nWindows zapyta o zgodę "
                    "administratora. Po instalacji HospitalHub otworzy się sam.")
        go = box.addButton("Zainstaluj", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Później", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is not go:
            self._detail.setText(f"Instalator czeka w: {path}")
            return False
        failed = []

        def hand_over() -> bool:
            try:
                updater.start_installer_after_exit(path)
                return True
            except Exception as exc:
                failed.append(type(exc).__name__)
                return False

        self.accept()
        quitting = _quit_all_hook(hand_over)
        if not quitting and failed:
            QMessageBox.warning(self.parentWidget(), "Aktualizacja",
                                f"Nie udało się uruchomić instalatora ({failed[0]}).\n"
                                f"Uruchom go ręcznie: {path}")
        return bool(quitting)
