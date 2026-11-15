"""Download of the newest AMMS release from hd.asseco.pl, in the
"Aktualizacja" tab (2026-11-15, owner).

One button: log in, find the newest AMMS publication, download every package
but the skipped ones (PACZKI-KONFIGURACYJNE) into the chosen folder, unpack
each at once (a zip inside a package, like ``AMMS/upgrade-06.10.07.95.zip``,
into its own folder beside it) and (by default) delete the package's zip.  A package already unpacked
(its marker file ``<folder>/<version>/.pobrano-<package>`` exists) is not
downloaded again, so a second click goes on where a broken run stopped.

The account, the folder and the options live in the upgrade plan
(``plan["hd"]``), that is in the encrypted vault.
"""

from __future__ import annotations

import os
import re

from PyQt6.QtCore import Qt, QThread, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QFrame,
    QHBoxLayout, QLabel, QLineEdit, QProgressBar, QPushButton, QSizePolicy,
    QToolButton, QVBoxLayout, QWidget,
)

import hd_asseco as hd
from ui.icons import set_icon

__all__ = ["HdSettingsDialog", "HdWorker", "HdDownloadBox", "marker_name"]

_FIELD_QSS = (
    "QLineEdit { background:#14161e; border:1px solid #2a2d3a;"
    " border-radius:6px; padding:4px 6px; color:#c9d1d9; }"
    "QLineEdit:focus { border-color:#4a5adf; }"
)
_BTN = (
    "QPushButton, QToolButton {{ background:{bg}; color:{fg};"
    " border:1px solid {border}; border-radius:6px; padding:5px 8px;"
    " font-size:11px; }}"
    "QPushButton:hover, QToolButton:hover {{ background:{hover}; color:#fff; }}"
    "QPushButton:disabled {{ color:#5a5f72; }}"
)
_GO_QSS = _BTN.format(bg="#0d1f0d", fg="#3fb950", border="#1b3d1b", hover="#2d5a2d")
_GREY_QSS = _BTN.format(bg="#151b23", fg="#8b949e", border="#21262d", hover="#30363d")


def marker_name(package_name: str) -> str:
    return ".pobrano-" + re.sub(r"[^A-Za-z0-9._-]+", "_", package_name)


def _mb(n: int) -> str:
    return f"{n / 1048576:,.0f} MB".replace(",", " ")


class HdSettingsDialog(QDialog):
    def __init__(self, parent, settings: dict):
        super().__init__(parent)
        self.setWindowTitle("hd.asseco.pl — pobieranie")
        self.setMinimumWidth(480)
        self.setStyleSheet(_FIELD_QSS)
        lay = QVBoxLayout(self)
        form = QFormLayout()
        self.login = QLineEdit(settings.get("login", ""))
        self.password = QLineEdit(settings.get("password", ""))
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Login:", self.login)
        form.addRow("Hasło:", self.password)
        row = QHBoxLayout()
        self.folder = QLineEdit(settings.get("folder", ""))
        pick = QPushButton("Wybierz…")
        pick.clicked.connect(self._pick)
        row.addWidget(self.folder, 1)
        row.addWidget(pick)
        form.addRow("Folder:", row)
        self.skip = QLineEdit(settings.get("skip", ""))
        self.skip.setToolTip("Paczki pomijane — fragmenty nazw, po przecinku")
        form.addRow("Pomijaj paczki:", self.skip)
        lay.addLayout(form)
        self.delete_zip = QCheckBox("Usuń zip po rozpakowaniu")
        self.delete_zip.setChecked(bool(settings.get("delete_zip", True)))
        lay.addWidget(self.delete_zip)
        note = QLabel("Login i hasło są zapisywane w zaszyfrowanym vaulcie "
                      "razem z planem aktualizacji.")
        note.setWordWrap(True)
        note.setStyleSheet("color:#8b949e; font-size:10px;")
        lay.addWidget(note)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("Zapisz")
        bb.button(QDialogButtonBox.StandardButton.Cancel).setText("Anuluj")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _pick(self):
        d = QFileDialog.getExistingDirectory(self, "Folder na instalki",
                                             self.folder.text() or "C:\\")
        if d:
            self.folder.setText(os.path.normpath(d))

    def values(self) -> dict:
        return {"login": self.login.text().strip(),
                "password": self.password.text(),
                "folder": self.folder.text().strip(),
                "skip": self.skip.text().strip(),
                "delete_zip": self.delete_zip.isChecked()}


class HdWorker(QThread):
    #: (text, percent 0–100 or -1 for "busy")
    progress = pyqtSignal(str, int)
    #: the newest version, as soon as it is known
    found = pyqtSignal(str)
    #: (ok, message)
    finished_ok = pyqtSignal(bool, str)

    def __init__(self, settings: dict, client_factory=hd.HdClient, parent=None):
        super().__init__(parent)
        self._s = dict(settings)
        self._factory = client_factory
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def _cancelled(self) -> bool:
        return self._cancel

    def run(self):
        try:
            self.finished_ok.emit(True, self._work())
        except hd.HdError as e:
            self.finished_ok.emit(False, str(e))
        except OSError as e:
            self.finished_ok.emit(False, f"Błąd sieci lub dysku: {e}")
        except Exception as e:   # never leave the panel "busy"
            self.finished_ok.emit(False, f"Błąd: {e}")

    def _work(self) -> str:
        s = self._s
        folder = s.get("folder", "").strip()
        if not folder:
            raise hd.HdError("Wybierz folder na instalki (koło zębate obok)")
        self.progress.emit("Logowanie do hd.asseco.pl…", -1)
        client = self._factory()
        client.login(s.get("login", ""), s.get("password", ""))
        self.progress.emit("Szukam najnowszej wersji AMMS…", -1)
        release = hd.newest(client.releases("AMMS"))
        if release is None:
            raise hd.HdError("Nie znaleziono publikacji AMMS z plikami")
        self.found.emit(release.version)
        skip = [x.strip() for x in s.get("skip", "").split(",") if x.strip()]
        packages = hd.wanted_packages(release, skip)
        if not packages:
            raise hd.HdError(f"AMMS {release.version}: brak paczek do pobrania")
        vdir = os.path.join(folder, release.version)
        done_names, skipped = [], []
        for i, p in enumerate(packages, 1):
            if self._cancel:
                raise hd.HdError("Przerwano")
            marker = os.path.join(vdir, marker_name(p.name))
            if os.path.exists(marker):
                skipped.append(p.name)
                continue
            tag = f"[{i}/{len(packages)}] {p.name.split(' ', 1)[-1]}"

            def dl_progress(done, total, tag=tag):
                pct = int(done * 100 / total) if total else -1
                self.progress.emit(f"{tag}: pobieranie {_mb(done)}"
                                   + (f" / {_mb(total)}" if total else ""), pct)

            path = client.download(p.url, folder, dl_progress, self._cancelled)

            def ex_progress(done, total, tag=tag):
                self.progress.emit(f"{tag}: rozpakowywanie",
                                   int(done * 100 / total) if total else -1)

            self.progress.emit(f"{tag}: rozpakowywanie", 0)
            written: list = []
            hd.safe_extract(path, folder, ex_progress, self._cancelled, written)
            # A zip inside the package (AMMS/upgrade-06.10.07.95.zip): into
            # its own folder beside it (owner, 2026-11-15).
            for inner in hd.nested_zips(written):
                name = os.path.basename(inner)
                self.progress.emit(f"{tag}: rozpakowywanie {name}", 0)
                hd.extract_nested(
                    inner,
                    lambda d, t, n=name, tag=tag: self.progress.emit(
                        f"{tag}: rozpakowywanie {n}", int(d * 100 / t) if t else -1),
                    self._cancelled)
            os.makedirs(vdir, exist_ok=True)
            with open(marker, "w", encoding="utf-8") as f:
                f.write(p.url + "\n")
            if s.get("delete_zip", True):
                try:
                    os.remove(path)
                except OSError:
                    pass
            done_names.append(p.name)
        msg = f"AMMS {release.version} gotowe w {vdir}"
        if skipped and not done_names:
            msg = f"AMMS {release.version} było już pobrane ({vdir})"
        elif skipped:
            msg += f" (wcześniej pobrane: {len(skipped)})"
        return msg


class HdDownloadBox(QFrame):
    """The download strip above the plan: settings, go, progress."""

    settings_changed = pyqtSignal(dict)
    version_found = pyqtSignal(str)

    def __init__(self, settings_getter, parent=None):
        super().__init__(parent)
        self._get = settings_getter
        self._worker: HdWorker | None = None
        self.setObjectName("hdBox")
        self.setStyleSheet(
            "QFrame#hdBox { background:#1a1d28; border:1px solid #2a2d3a;"
            " border-radius:10px; }"
            "QLabel { border:none; background:transparent; }")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(6)
        title = QLabel("POBIERANIE  ·  hd.asseco.pl")
        title.setStyleSheet("color:#8b949e; font-size:9px; font-weight:bold;"
                            " letter-spacing:2px;")
        lay.addWidget(title)

        row = QHBoxLayout()
        row.setSpacing(4)
        self.go = QPushButton("Pobierz najnowszą AMMS")
        set_icon(self.go, "download", "#3fb950", size=13)
        self.go.setStyleSheet(_GO_QSS)
        self.go.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self.go.setMinimumWidth(40)
        self.go.clicked.connect(self._start_or_cancel)
        row.addWidget(self.go, 1)
        self.open_btn = QToolButton()
        set_icon(self.open_btn, "folder-open", "#e2b340", size=13)
        self.open_btn.setToolTip("Otwórz folder z instalkami")
        self.open_btn.setStyleSheet(_GREY_QSS)
        self.open_btn.clicked.connect(self._open_folder)
        row.addWidget(self.open_btn)
        self.cfg = QToolButton()
        set_icon(self.cfg, "gear", "#8b949e", size=13)
        self.cfg.setToolTip("Login, hasło, folder, rozpakowywanie")
        self.cfg.setStyleSheet(_GREY_QSS)
        self.cfg.clicked.connect(self.edit_settings)
        row.addWidget(self.cfg)
        lay.addLayout(row)

        self.bar = QProgressBar()
        self.bar.setFixedHeight(8)
        self.bar.setTextVisible(False)
        self.bar.setStyleSheet(
            "QProgressBar { background:#14161e; border:none; border-radius:4px; }"
            "QProgressBar::chunk { background:#3fb950; border-radius:4px; }")
        self.bar.hide()
        lay.addWidget(self.bar)
        self.status = QLabel()
        self.status.setWordWrap(True)
        self.status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.status.setStyleSheet("color:#8b949e; font-size:10px;")
        lay.addWidget(self.status)
        self.show_idle()

    # ── State ─────────────────────────────────────────────────────────────

    def busy(self) -> bool:
        return self._worker is not None

    def show_idle(self) -> None:
        s = self._get()
        if not s.get("login") or not s.get("password"):
            self.status.setText("Ustaw login i hasło (koło zębate obok)")
        else:
            self.status.setText(f"Folder: {s.get('folder') or '—'}")

    def edit_settings(self) -> None:
        dlg = HdSettingsDialog(self, self._get())
        if dlg.exec():
            self.settings_changed.emit(dlg.values())
            if not self.busy():
                self.show_idle()

    def _open_folder(self) -> None:
        folder = self._get().get("folder", "")
        if folder and os.path.isdir(folder):
            QDesktopServices.openUrl(QUrl.fromLocalFile(folder))
        else:
            self.status.setText(f"Folder jeszcze nie istnieje: {folder or '—'}")

    # ── Run ───────────────────────────────────────────────────────────────

    def _start_or_cancel(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self.go.setEnabled(False)
            self.status.setText("Przerywanie…")
            return
        s = self._get()
        if not s.get("login") or not s.get("password") or not s.get("folder"):
            self.edit_settings()
            s = self._get()
            if not s.get("login") or not s.get("password") or not s.get("folder"):
                return
        free = hd.free_bytes(s["folder"])
        if 0 <= free < 6 * 1024 ** 3:
            self.status.setText(f"Mało miejsca na dysku ({_mb(free)} wolne) — "
                                "paczki AMMS to ok. 2,5 GB plus rozpakowanie.")
        self.start(s)

    def start(self, settings: dict, client_factory=hd.HdClient) -> None:
        w = HdWorker(settings, client_factory, self)
        w.progress.connect(self._on_progress)
        w.found.connect(self.version_found.emit)
        w.finished_ok.connect(self._on_done)
        self._worker = w
        self.go.setText("Przerwij")
        set_icon(self.go, "stop", "#d29922", size=13)
        self.cfg.setEnabled(False)
        self.bar.setRange(0, 0)
        self.bar.show()
        w.start()

    def _on_progress(self, text: str, pct: int) -> None:
        self.status.setStyleSheet("color:#8b949e; font-size:10px;")
        self.status.setText(text)
        if pct < 0:
            self.bar.setRange(0, 0)
        else:
            self.bar.setRange(0, 100)
            self.bar.setValue(pct)

    def _on_done(self, ok: bool, msg: str) -> None:
        w, self._worker = self._worker, None
        if w is not None:
            w.wait(2000)
            w.deleteLater()
        self.go.setEnabled(True)
        self.go.setText("Pobierz najnowszą AMMS")
        set_icon(self.go, "download", "#3fb950", size=13)
        self.cfg.setEnabled(True)
        self.bar.hide()
        self.status.setText(("✓ " if ok else "✗ ") + msg)
        self.status.setStyleSheet(
            f"color:{'#3fb950' if ok else '#f85149'}; font-size:10px;")

    def shutdown(self) -> None:
        """Window closing: stop a running download."""
        if self._worker is not None:
            self._worker.cancel()
            self._worker.wait(5000)
