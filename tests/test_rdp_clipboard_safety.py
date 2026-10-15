"""RDP and clipboard fixes (2026-10-14, Etap 67) — on fakes only.

No mstsc, no PowerShell, no certificate store, no Credential Manager: every
system call of ``ui.rdp`` is replaced, and the conftest guard traps the rest
(``advapi32.Cred*`` included).

* C2-01 — the certificate fast path repairs a missing TrustedPublisher/Root.
* C2-02 — only drive letters reach the signed .rdp file.
* C2-03 — only a 40-hex thumbprint reaches a PowerShell script.
* C2-04 — two launches to one address keep their credential; the exit path
  removes what is pending; the diagnostic log carries no login.
* C3-01 — a copied secret is kept out of the Win+V history and cloud sync,
  and wiped at exit if still on the clipboard.
"""

import os
import sys
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

TP = "A" * 40


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def rdp(app, monkeypatch, tmp_path):
    from ui import rdp as module
    monkeypatch.setattr(module, "_DIAG_LOG", str(tmp_path / "rdp.log"))
    monkeypatch.setattr(module, "_PENDING_CREDENTIALS", {})
    monkeypatch.setattr(module, "_TRUST_REPAIR_TRIED", set())
    monkeypatch.setattr(module, "_VERIFIED_THUMBPRINT", [None])
    return module


# ══════════════════════════════════════════════════════════════════════════
# C2-02 — drives
# ══════════════════════════════════════════════════════════════════════════

def test_c202_only_drive_letters_reach_the_rdp_file(rdp, monkeypatch, tmp_path):
    monkeypatch.setattr(rdp.tempfile, "gettempdir", lambda: str(tmp_path))
    machine = SimpleNamespace(rdp_drives=[
        "c:", "D:", "C:", "E:\r\nalternate shell:s:cmd.exe", "drivestoredirect:s:*",
        "Z", 7, None])
    path = rdp._make_rdp_file("10.0.0.5", machine)
    text = open(path, "rb").read().decode("utf-8")
    lines = text.split("\r\n")
    assert "drivestoredirect:s:C:\\;D:\\;" in lines
    assert "alternate shell" not in text
    assert sum(1 for line in lines if line.startswith("drivestoredirect")) == 1
    assert text.count("\n") == text.count("\r\n")


@pytest.mark.parametrize("drives,expected", [
    (["C:", "d:"], ["C:", "D:"]), ([], []), (None, []), (["C:", "C:"], ["C:"]),
    (["CC:", ":", "C", "C:\\"], [])])
def test_c202_valid_drives(rdp, drives, expected):
    assert rdp._valid_drives(drives) == expected


# ══════════════════════════════════════════════════════════════════════════
# C2-01 / C2-03 — the signing certificate
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("value,ok", [
    (TP, True), ("a" * 40, True), ("A" * 39, False), ("A" * 41, False),
    (TP + "'; Remove-Item x", False), ("", False), ("G" * 40, False)])
def test_c203_thumbprint_shape(rdp, value, ok):
    assert (rdp._valid_thumbprint(value) is not None) is ok


class PowerShell:
    def __init__(self, answers):
        self.answers = list(answers)
        self.scripts = []

    def __call__(self, script, timeout):
        self.scripts.append(script)
        return self.answers.pop(0) if self.answers else (0, "", "")


@pytest.fixture
def no_registry(rdp, monkeypatch):
    monkeypatch.setattr(rdp, "_ensure_publisher_bypass", lambda tp: None)
    monkeypatch.setattr(rdp, "_ensure_local_devices_trust", lambda tp: None)


def test_c201_a_trusted_cert_needs_no_repair(rdp, monkeypatch, no_registry):
    ps = PowerShell([(0, f"{TP}|True|True", "")])
    monkeypatch.setattr(rdp, "_powershell", ps)
    assert rdp._ensure_signing_cert() == TP
    assert len(ps.scripts) == 1


@pytest.mark.parametrize("flags", ["False|True", "True|False", "False|False", ""])
def test_c201_a_cert_without_trust_is_repaired(rdp, monkeypatch, no_registry, flags):
    ps = PowerShell([(0, f"{TP}|{flags}" if flags else TP, ""), (0, "", "")])
    monkeypatch.setattr(rdp, "_powershell", ps)
    assert rdp._ensure_signing_cert() == TP
    assert len(ps.scripts) == 2
    assert "TrustedPublisher" in ps.scripts[1] and "Root" in ps.scripts[1]
    assert TP in ps.scripts[1]


def test_c203_a_malformed_fast_path_answer_is_not_used(rdp, monkeypatch, no_registry):
    ps = PowerShell([(0, "x' ; evil|True|True", ""), (1, "", "fail")])
    monkeypatch.setattr(rdp, "_powershell", ps)
    assert rdp._ensure_signing_cert() is None
    assert all("evil" not in s for s in ps.scripts[1:])


def test_c203_the_repair_refuses_a_bad_thumbprint(rdp, monkeypatch):
    ps = PowerShell([])
    monkeypatch.setattr(rdp, "_powershell", ps)
    rdp._repair_cert_trust("not-a-thumbprint'; x")
    assert ps.scripts == []


# ══════════════════════════════════════════════════════════════════════════
# C2-04 — credentials and the log
# ══════════════════════════════════════════════════════════════════════════

def test_c204_two_launches_to_one_address_keep_the_credential(rdp, monkeypatch):
    deleted = []
    monkeypatch.setattr(rdp, "_cmdkey_delete", deleted.append)
    rdp._hold_credential("10.0.0.5")
    rdp._hold_credential("10.0.0.5")
    rdp._release_credential("10.0.0.5")          # the first one's timer
    assert deleted == [], "druga sesja wciąż potrzebuje poświadczenia"
    rdp._release_credential("10.0.0.5")
    assert deleted == ["10.0.0.5"]


def test_c204_the_exit_path_removes_what_is_pending(rdp, monkeypatch):
    deleted = []
    monkeypatch.setattr(rdp, "_cmdkey_delete", deleted.append)
    rdp._hold_credential("10.0.0.5")
    rdp._hold_credential("10.0.0.6")
    rdp.cleanup_pending_credentials()
    assert sorted(deleted) == ["10.0.0.5", "10.0.0.6"]
    assert rdp._PENDING_CREDENTIALS == {}


def test_c204_main_cleans_up_before_the_hard_exit():
    src = open(os.path.join(_PARENT, "main.py"), encoding="utf-8").read()
    tail = src[src.index("exit_code = app.exec()"):]
    assert tail.index("cleanup_pending_credentials()") < tail.index("os._exit(")
    assert tail.index("clear_secret_from_clipboard()") < tail.index("os._exit(")


def test_c204_the_diagnostic_log_carries_no_login(rdp):
    src = open(rdp.__file__, encoding="utf-8").read()
    assert "user={cred.login" not in src


def test_c204_the_diagnostic_log_is_bounded(rdp):
    with open(rdp._DIAG_LOG, "wb") as f:
        f.write(b"x" * (600 * 1024))
    rdp._diag("next line")
    assert os.path.getsize(rdp._DIAG_LOG) < 300 * 1024


# ══════════════════════════════════════════════════════════════════════════
# C3-01 — clipboard
# ══════════════════════════════════════════════════════════════════════════

def test_c301_a_copied_secret_is_marked_private(app):
    from ui import dialogs
    data = dialogs.private_mime_data("Haslo!23")
    assert data.text() == "Haslo!23"
    for fmt in ("ExcludeClipboardContentFromMonitorProcessing",
                "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"):
        key = f'application/x-qt-windows-mime;value="{fmt}"'
        assert data.hasFormat(key), fmt
        assert bytes(data.data(key)) == b"\x00\x00\x00\x00"


class FakeClipboard:
    def __init__(self):
        self.mime, self.cleared = None, 0

    def setMimeData(self, data):
        self.mime = data

    def text(self):
        return self.mime.text() if self.mime is not None else ""

    def clear(self):
        self.cleared += 1
        self.mime = None


@pytest.fixture
def clipboard(app, monkeypatch):
    from ui import dialogs
    cb = FakeClipboard()
    monkeypatch.setattr(dialogs.QApplication, "clipboard", staticmethod(lambda: cb))
    monkeypatch.setattr(dialogs.QTimer, "singleShot", staticmethod(lambda ms, fn: None))
    return dialogs, cb


def test_c301_every_copy_goes_through_the_private_helper(clipboard):
    dialogs, cb = clipboard
    dialogs._clipboard_copy("Haslo!23")
    assert cb.text() == "Haslo!23"
    assert cb.mime.hasFormat(
        'application/x-qt-windows-mime;value="CanIncludeInClipboardHistory"')


def test_c301_exit_wipes_the_secret_only_if_it_is_still_there(clipboard):
    dialogs, cb = clipboard
    dialogs._clipboard_copy("Haslo!23")
    dialogs.clear_secret_from_clipboard()
    assert cb.cleared == 1

    dialogs._clipboard_copy("Haslo!23")
    from PyQt6.QtCore import QMimeData
    other = QMimeData()
    other.setText("cos innego uzytkownika")
    cb.mime = other
    dialogs.clear_secret_from_clipboard()
    assert cb.cleared == 1 and cb.text() == "cos innego uzytkownika"


def test_c301_the_vpn_panel_copies_passwords_through_the_helper():
    src = open(os.path.join(_PARENT, "ui", "vpn_panel.py"), encoding="utf-8").read()
    assert "clipboard().setText(p.password)" not in src
    assert "clipboard().setText(self._pass_edit.text())" not in src


# ══════════════════════════════════════════════════════════════════════════
# C3-02 — SQL Developer launch
# ══════════════════════════════════════════════════════════════════════════

def test_c302_an_admin_only_credential_stays_home_while_locked(app, monkeypatch):
    from ui import db_connect
    copied, shown = [], []
    monkeypatch.setattr(db_connect, "_clipboard_copy", copied.append)
    monkeypatch.setattr(db_connect.subprocess, "Popen", lambda *a, **k: None)
    monkeypatch.setattr(db_connect, "_find_sqldeveloper", lambda: "C:/sqld.exe")
    monkeypatch.setattr(db_connect.QMessageBox, "information",
                        staticmethod(lambda p, t, text: shown.append(text)))
    admin = SimpleNamespace(login="sys", password="ADMIN-PASS", admin_only=True)
    user = SimpleNamespace(login="app", password="user-pass", admin_only=False)
    db = SimpleNamespace(credentials=[admin, user], host="h", port="1521", name="DB")

    db_connect.connect_db(db)
    assert copied == ["user-pass"]
    assert "15 s" in shown[-1]

    copied.clear()
    db_connect.connect_db(db, admin_unlocked=True)
    assert copied == ["ADMIN-PASS"]


def test_r1_the_trust_repair_runs_at_most_once_per_process(rdp, monkeypatch,
                                                           no_registry):
    """Review 67/R1: a declined Root prompt must not come back, blocking the
    UI, on every RDP launch."""
    ps = PowerShell([(0, f"{TP}|False|False", ""), (0, "", ""),
                     (0, f"{TP}|False|False", "")])
    monkeypatch.setattr(rdp, "_powershell", ps)
    rdp._ensure_signing_cert()
    rdp._ensure_signing_cert()
    repairs = [s for s in ps.scripts if "X509Store($n" in s]
    assert len(repairs) == 1


def test_r2_a_failure_before_launch_releases_the_credential(rdp, monkeypatch):
    """Review 67/R2: an exception between injecting the credential and
    launching mstsc left TERMSRV/<ip> pending until exit."""
    deleted, shown = [], []
    monkeypatch.setattr(rdp.os.path, "exists", lambda p: True)
    monkeypatch.setattr(rdp, "_cmdkey_add", lambda ip, login, pw: True)
    monkeypatch.setattr(rdp, "_cmdkey_delete", deleted.append)
    monkeypatch.setattr(rdp, "_diag_saved_cred_policy", lambda: None)

    def broken(target, machine):
        raise OSError("disk full")
    monkeypatch.setattr(rdp, "_make_rdp_file", broken)
    monkeypatch.setattr(rdp.QMessageBox, "critical",
                        staticmethod(lambda *a: shown.append(a[1])))
    cred = SimpleNamespace(login="u", password="p", admin_only=False)
    machine = SimpleNamespace(ip="10.0.0.5", rdp_port="", credentials=[cred],
                              rdp_drives=[])
    rdp.connect_rdp(machine)
    assert deleted == ["10.0.0.5"] and rdp._PENDING_CREDENTIALS == {}
    assert shown == ["Błąd RDP"]


# ══════════════════════════════════════════════════════════════════════════
# C3-01 for the V2 autofill's own clipboard writes
# ══════════════════════════════════════════════════════════════════════════

class FakeWin32Clipboard:
    def __init__(self, fail_register=False):
        self.calls, self.fail_register = [], fail_register
        self.formats = {}

    def OpenClipboard(self):
        self.calls.append("open")

    def EmptyClipboard(self):
        self.calls.append("empty")

    def SetClipboardText(self, text):
        self.calls.append(("text", text))

    def RegisterClipboardFormat(self, name):
        if self.fail_register:
            raise OSError("no")
        return self.formats.setdefault(name, 0xC000 + len(self.formats))

    def SetClipboardData(self, fmt, data):
        self.calls.append(("data", fmt, data))

    def CloseClipboard(self):
        self.calls.append("close")


def test_c301_the_v2_fill_marks_its_clipboard_writes_private(monkeypatch):
    from vpn.providers.input_system import Win32InputSystem
    fake = FakeWin32Clipboard()
    monkeypatch.setitem(sys.modules, "win32clipboard", fake)
    assert Win32InputSystem().copy_to_clipboard("Haslo!23") is True
    assert ("text", "Haslo!23") in fake.calls
    assert set(fake.formats) == {"ExcludeClipboardContentFromMonitorProcessing",
                                 "CanIncludeInClipboardHistory",
                                 "CanUploadToCloudClipboard"}
    data = [c for c in fake.calls if c[0] == "data"]
    assert len(data) == 3 and all(c[2] == b"\x00\x00\x00\x00" for c in data)
    assert fake.calls[-1] == "close"


def test_c301_the_text_is_set_even_if_the_marks_cannot_be(monkeypatch):
    from vpn.providers.input_system import Win32InputSystem
    fake = FakeWin32Clipboard(fail_register=True)
    monkeypatch.setitem(sys.modules, "win32clipboard", fake)
    assert Win32InputSystem().copy_to_clipboard("x") is True
    assert ("text", "x") in fake.calls and fake.calls[-1] == "close"


def test_d09_powershell_runs_once_per_process(rdp, monkeypatch, no_registry):
    """Audit D-09: every RDP launch started PowerShell on the UI thread."""
    ps = PowerShell([(0, f"{TP}|True|True", "")])
    monkeypatch.setattr(rdp, "_powershell", ps)
    assert rdp._ensure_signing_cert() == TP
    assert rdp._ensure_signing_cert() == TP
    assert rdp._ensure_signing_cert() == TP
    assert len(ps.scripts) == 1


def test_d09_a_failed_lookup_is_not_cached(rdp, monkeypatch, no_registry):
    ps = PowerShell([(1, "", "err"), (1, "", "err"), (0, f"{TP}|True|True", "")])
    monkeypatch.setattr(rdp, "_powershell", ps)
    assert rdp._ensure_signing_cert() is None
    assert rdp._ensure_signing_cert() == TP
