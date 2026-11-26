"""2026-11-15 (owner): the "Aktualizacja" tab of HospitalHub Portable —
an editable upgrade plan, typed into the terminals of a group's machines at
once, with the exit code read back per machine."""

import os
import sys
import time

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import models  # noqa: E402
import upgrade_plan as up  # noqa: E402


# ── The plan ─────────────────────────────────────────────────────────────

def test_the_default_plan_is_the_owners_notes():
    plan = up.default_plan()
    names = [g["name"] for g in plan["groups"]]
    assert names[0].startswith("AMMS") and "Balancer" in names
    amms = plan["groups"][0]
    install = next(c for c in amms["commands"] if c["label"] == "Instaluj")
    assert "AMMS_{WERSJA}-standard.jar /u01/upgrade.xml" in install["text"]
    assert install["requires_stopped"] and install["confirm"]
    # Its own service, not "any java": WildFly and Tomcat share machines.
    assert amms["process"] == "java.*WildflyAMMS"
    assert plan["groups"][1]["process"] == "java.*integrationPlatform"


def test_normalize_keeps_a_saved_plan_and_fills_an_empty_one():
    assert up.normalize_plan({})["groups"]
    assert up.normalize_plan(None)["groups"]
    saved = {"version": "6.10", "order": ["a"], "groups": [
        {"id": "g", "name": "X", "machines": ["a"],
         "commands": [{"id": "c", "label": "L", "text": "ls"}]}]}
    plan = up.normalize_plan(saved)
    assert plan["version"] == "6.10" and plan["order"] == ["a"]
    assert plan["groups"][0]["commands"][0] == {
        "id": "c", "label": "L", "text": "ls", "confirm": False,
        "requires_stopped": False}
    assert plan["groups"][0]["process"] == ""


def test_the_plan_is_saved_with_the_hospital():
    h = models.Hospital(name="S")
    assert "upgrade" not in models.to_dict([h])["hospitals"][0]
    h.upgrade = {"version": "1", "order": [], "groups": []}
    back = models.from_dict(models.to_dict([h]))[0]
    assert back.upgrade == h.upgrade
    assert models.from_dict({"hospitals": [{"name": "old"}]})[0].upgrade == {}


def test_variables_are_filled_in():
    assert up.expand("a_{WERSJA}_{DATA}", " 6.10.01.83 ", "20261115") == \
        "a_6.10.01.83_20261115"


def test_the_marker_is_not_found_in_the_echoed_command():
    cmd = {"text": "echo hi"}
    line = up.build_line(cmd, {}, "", "tok123")
    assert not up.marker_re("tok123").search(line)
    assert up.marker_re("tok123").search("\x1b[90m[HH tok123] kod 0\x1b[0m")
    assert up.strip_ansi("\x1b[1;31mX\x1b[0m") == "X"


def test_comments_and_empty_lines_are_left_out():
    line = up.build_line({"text": "# stop\n\nsystemctl stop amms\n"}, {}, "", "t")
    assert line.startswith("systemctl stop amms; __hh=$?")


# ── The panel and the window ─────────────────────────────────────────────

@pytest.fixture(scope="module")
def app():
    pytest.importorskip("PyQt6")
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def pump(ms):
    from PyQt6.QtCore import QEvent
    from PyQt6.QtWidgets import QApplication
    end = time.monotonic() + ms / 1000
    while time.monotonic() < end:
        QApplication.processEvents()
        QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        time.sleep(0.005)


def _hospital():
    c = models.Credential(login="root", password="pw")
    ms = [models.Machine(ip=f"10.0.0.{n}", name=nm, credentials=[c])
          for n, nm in ((45, "srvJBoss1"), (46, "srvJBoss2"), (50, "pi1"))]
    ms.append(models.Machine(ip="10.0.0.53", name="win",
                             connection_type="RDP"))
    return models.Hospital(name="Szpital", machines=ms)


def test_the_panel_lists_ssh_machines_in_the_plan_order(app):
    from ui.upgrade_panel import UpgradePanel
    h = _hospital()
    a, b, c = h.machines[:3]
    h.upgrade = up.default_plan()
    h.upgrade["order"] = [c.id, a.id]
    h.upgrade["groups"][0]["machines"] = [a.id, b.id]
    p = UpgradePanel(h)
    saves = []
    p.data_changed.connect(lambda: saves.append(1))
    assert [m.ip for m in p._order_machines()] == ["10.0.0.50", "10.0.0.45"]
    # A group's machines follow the list order; those not in it come last.
    assert [m.ip for m in p.machines_of(h.upgrade["groups"][0])] == \
        ["10.0.0.45", "10.0.0.46"]
    p._list.setCurrentRow(1)
    p._move_selected(-1)
    pump(50)
    assert h.upgrade["order"] == [a.id, c.id] and saves
    assert p._list.currentRow() == 0
    opened = []
    p.open_requested.connect(opened.append)
    p._order_machines() and p.open_requested.emit(p._order_machines())
    assert [m.ip for m in opened[0]] == ["10.0.0.45", "10.0.0.50"]


class _FakeWorker:
    def __init__(self):
        self.sent = []
        self._channel = object()

    def send(self, data):
        self.sent.append(data)


@pytest.fixture
def window(app, tmp_path):
    from crypto import encrypt
    from ui.remote_window import RemoteWindow
    h = _hospital()
    h.upgrade = up.default_plan()
    a, b, c = h.machines[:3]
    h.upgrade["order"] = [a.id, b.id, c.id]
    h.upgrade["groups"][0]["machines"] = [a.id, b.id]
    path = tmp_path / "s.vault"
    path.write_bytes(encrypt(models.to_dict([h]), "p"))
    w = RemoteWindow(str(path), "p", models.from_dict(models.to_dict([h])))
    yield w
    w._sessions.clear()
    w.close_without_asking()
    pump(50)


def _fake_session(window, machine):
    class S:
        is_rdp = False
        reconnecting = False
    s = S()
    s.machine, s.worker = machine, _FakeWorker()
    window._sessions.append(s)
    return s


def test_the_upgrade_tab_sits_next_to_the_machines(window):
    tabs = window._left_tabs
    assert [tabs.tabText(i) for i in range(tabs.count())] ==         ["Maszyny", "Pliki", "Aktualizacja AMMS", "SI"]


def test_a_command_goes_to_every_machine_of_the_group(window, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox
    h = window._hospital
    a, b = h.machines[:2]
    sa, sb = _fake_session(window, a), _fake_session(window, b)
    panel = window._upgrade_panel
    group = panel.plan["groups"][0]
    stop = next(c for c in group["commands"] if c["label"] == "Procesy java")
    window._run_upgrade_command(group, stop, panel.machines_of(group))
    for s in (sa, sb):
        assert len(s.worker.sent) == 1
        assert s.worker.sent[0].decode().startswith("pgrep -af java")
        assert s.worker.sent[0].endswith(b"\r")
    assert panel._status[(group["id"], a.id)][0] == "run"

    token = window._upgrade_wait[id(sa)]["re"].pattern.split(" ")[1].rstrip("\\]")
    window._upgrade_output(sa, "[HH " + token[:4])
    window._upgrade_output(sa, token[4:] + "]\x1b[0m kod 0\r\n")
    assert panel._status[(group["id"], a.id)][0] == "ok"
    tok_b = window._upgrade_wait[id(sb)]["re"].pattern.split(" ")[1].rstrip("\\]")
    window._upgrade_output(sb, f"\x1b[90m[HH {tok_b}] kod 3\x1b[0m")
    assert panel._status[(group["id"], b.id)] [0] == "fail"
    assert not window._upgrade_wait


def test_a_missing_version_or_tab_is_reported(window, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox
    warned = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: warned.append(a))
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: warned.append(a))
    panel = window._upgrade_panel
    group = panel.plan["groups"][0]
    install = next(c for c in group["commands"] if c["label"] == "Instaluj")
    window._run_upgrade_command(group, install, panel.machines_of(group))
    assert "wersję" in warned[-1][2]
    other = next(c for c in group["commands"] if c["label"] == "Procesy java")
    window._run_upgrade_command(group, other, panel.machines_of(group))
    assert "Otwórz karty po kolei" in warned[-1][2]


def test_a_confirmed_command_asks_and_ctrl_c_ends_a_wait(window, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox
    asked = []

    def fake_exec(box):
        asked.append(box.text())
        return 0
    monkeypatch.setattr(QMessageBox, "exec", fake_exec)
    h = window._hospital
    sa = _fake_session(window, h.machines[0])
    panel = window._upgrade_panel
    panel._version.setText("6.10.01.83")
    group = panel.plan["groups"][0]
    install = next(c for c in group["commands"] if c["label"] == "Instaluj")
    window._run_upgrade_command(group, install, panel.machines_of(group))
    assert asked and "AMMS_6.10.01.83-standard.jar" in asked[0]
    assert "10.0.0.46" in asked[0] and "POMINIĘTE" in asked[0]
    assert not sa.worker.sent                      # "Anuluj" by default

    start = next(c for c in group["commands"] if c["label"] == "Start + log")
    window._run_upgrade_command(group, start, panel.machines_of(group)[:1])
    assert b"tail -f" in sa.worker.sent[-1]
    sent_ctrl = []
    monkeypatch.setattr(window, "_send_one", lambda s, d, c: sent_ctrl.append(d))
    window._interrupt_upgrade(group, panel.machines_of(group))
    assert sent_ctrl == [b"\x03"]
    assert panel._status[(group["id"], h.machines[0].id)][0] == "stop"


# ── 2026-11-26 (owner): "Aktualizacja AMMS" + the hospital's upgrade notes ──

def test_the_notes_are_kept_in_the_plan():
    assert up.default_plan()["notes"] == ""
    saved = up.default_plan()
    saved["notes"] = "AMMS\nsystemctl stop amms\n"
    assert up.normalize_plan(saved)["notes"] == saved["notes"]
    # A plan without groups (all deleted) still keeps its notes.
    assert up.normalize_plan({"notes": "x", "groups": []})["notes"] == "x"
    assert up.normalize_plan({"groups": saved["groups"]})["notes"] == ""


def test_a_notes_file_is_read_in_utf8_or_the_windows_code_page(tmp_path):
    from ui.upgrade_panel import read_text_file
    (tmp_path / "u8.txt").write_bytes("zażółć\r\nlinia".encode("utf-8-sig"))
    (tmp_path / "cp.txt").write_bytes("zażółć\r\nlinia".encode("cp1250"))
    assert read_text_file(str(tmp_path / "u8.txt")) == "zażółć\nlinia"
    assert read_text_file(str(tmp_path / "cp.txt")) == "zażółć\nlinia"


def test_the_panel_shows_and_saves_the_notes(app):
    from PyQt6.QtWidgets import QTextEdit
    import ui.upgrade_panel as panel
    h = _hospital()
    p = panel.UpgradePanel(h)
    saves = []
    p.data_changed.connect(lambda: saves.append(1))
    p._edit_notes()
    dlg = p._notes_dlg
    # Not modal (owner): the main window stays usable while it is open.
    assert dlg is not None and dlg.isVisible() and not dlg.isModal()
    dlg.text.setPlainText("aktualizacja z 192.0.2.53")
    assert dlg.dirty()
    dlg.save_btn.click()
    pump(50)
    assert h.upgrade["notes"] == "aktualizacja z 192.0.2.53\n" and saves
    assert not dlg.dirty() and dlg.isVisible()      # saved, still open
    views = [w for w in p._scroll.widget().findChildren(QTextEdit)
             if w.isReadOnly()]
    assert views and "192.0.2.53" in views[0].toPlainText()
    back = models.from_dict(models.to_dict([h]))[0]
    assert back.upgrade["notes"] == h.upgrade["notes"]
    # A second click brings the same window back, not a new one.
    p._edit_notes()
    assert p._notes_dlg is dlg
    # Pinned = above every window, so a click on the main one never hides it.
    dlg.pin.setChecked(True)
    pump(20)
    assert dlg.is_pinned() and dlg.isVisible()
    dlg.pin.setChecked(False)
    pump(20)
    assert not dlg.is_pinned() and dlg.isVisible()
    assert p.close_notes() and p._notes_dlg is None


def test_the_gitlab_link_is_the_projects_page(app, monkeypatch):
    import ui.upgrade_panel as panel
    opened = []
    monkeypatch.setattr(panel.QDesktopServices, "openUrl",
                        lambda url: opened.append(url.toString()))
    panel.open_gitlab()
    assert opened == ["https://amms.asseco.pl/gitlab/dashboard/projects/member"]


def test_the_notes_dialog_returns_the_edited_text(app):
    from ui.upgrade_panel import NotesDialog
    d = NotesDialog(None, "a")
    d.text.setPlainText("linia 1\nlinia 2\n\n\n")
    assert d.value() == "linia 1\nlinia 2\n"
    d.text.setPlainText("   \n")
    assert d.value() == ""


def test_bold_and_bigger_print_are_saved_and_shown(app):
    from PyQt6.QtGui import QFont, QTextCursor
    import ui.upgrade_panel as panel
    h = _hospital()
    p = panel.UpgradePanel(h)
    p._edit_notes()
    dlg = p._notes_dlg
    dlg.text.setPlainText("AMMS\nsystemctl stop amms")
    # No selection: the whole current line (the first one).
    cur = dlg.text.textCursor()
    cur.movePosition(QTextCursor.MoveOperation.Start)
    dlg.text.setTextCursor(cur)
    dlg.toggle_bold()
    dlg.change_size(4)
    assert dlg.bold_btn.isChecked()
    assert dlg.html() and dlg.dirty()
    dlg.save_btn.click()
    pump(50)
    plan = h.upgrade
    assert plan["notes"] == "AMMS\nsystemctl stop amms\n" and plan["notes_html"]
    assert panel.notes_rich(plan) == plan["notes_html"]
    # The preview in the panel keeps it.
    doc = p._notes_view.document()
    first = doc.begin().begin().fragment().charFormat()
    assert first.fontWeight() >= QFont.Weight.DemiBold.value
    assert first.fontPointSize() == panel.NOTES_PT + 4
    # Reopened: the formatting is back in the editor.
    assert p.close_notes()
    p._edit_notes()
    assert p._notes_dlg.html() and not p._notes_dlg.dirty()
    # "Zwykły tekst" takes it off — the notes are plain again.
    d2 = p._notes_dlg
    d2.text.selectAll()
    d2.clear_format()
    assert d2.html() == ""
    d2.save_btn.click()
    pump(50)
    assert h.upgrade["notes_html"] == ""
    assert p.close_notes()


def test_stale_formatting_gives_way_to_changed_plain_notes(app):
    import ui.upgrade_panel as panel
    from PyQt6.QtGui import QTextDocument
    doc = QTextDocument()
    doc.setPlainText("stara treść")
    plan = {"notes": "stara treść\n", "notes_html": doc.toHtml()}
    assert panel.notes_rich(plan)
    plan["notes"] = "nowa treść (scalona)\n"
    assert panel.notes_rich(plan) == ""
    assert up.normalize_plan(plan)["notes_html"] == plan["notes_html"]
