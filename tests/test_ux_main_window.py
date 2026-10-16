"""Main window and VPN window (UX audit 2026-10-16, Etap 71).

E-06 duplicate hospital: warned, the NEW one selected
E-10 search by machine IP/name and database; Enter/Down go to the list;
     a hospital hidden by the filter is selected again when it is cleared
E-26 typing in the notes does not rebuild the hospital list
E-12 Tab leaves the tables
V-02/V-03 elided names with tooltips
V-19 the VPN window keeps a size the user can shrink
"""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def _hospitals():
    import models
    a = models.Hospital(name="SPZOZ Kraków", machines=[
        models.Machine(ip="10.20.1.10", name="pacs-prod", description="PACS")])
    b = models.Hospital(name="Centrum Onkologii",
                        databases=[models.Database(host="db7.local", name="HIS")])
    return [a, b]


@pytest.fixture
def win(app, tmp_path, monkeypatch):
    from ui import main_window as mw
    monkeypatch.setattr(mw, "load_hospital_sort_order", lambda: "none", raising=False)
    w = mw.MainWindow(str(tmp_path / "never.vault"), "pw", _hospitals())
    yield w
    w._unsaved = False


def names(w):
    return [w._hospital_list.item(i).text() for i in range(w._hospital_list.count())]


def test_e10_search_finds_a_hospital_by_machine_ip_and_database(win):
    win._search_edit.setText("10.20.1.10")
    assert names(win) == ["SPZOZ Kraków"]
    assert "pacs-prod" in win._hospital_list.item(0).toolTip()
    win._search_edit.setText("db7")
    assert names(win) == ["Centrum Onkologii"]


def test_e10_enter_selects_the_first_result(win):
    win._search_edit.setText("onko")
    win._search_edit.returnPressed.emit()
    assert win._detail_panel.current_hospital.name == "Centrum Onkologii"


def test_e10_clearing_the_filter_brings_the_selection_back(win):
    win._hospital_list.setCurrentRow(0)
    chosen = win._detail_panel.current_hospital
    win._search_edit.setText("onko")             # hides the selected one
    win._search_edit.setText("")
    assert win._detail_panel.current_hospital is chosen
    assert win._hospital_list.currentRow() == 0


def test_e06_a_duplicate_name_asks_and_selects_the_new_hospital(win, monkeypatch):
    from ui import main_window as mw
    asked = []
    monkeypatch.setattr(mw, "confirm", lambda *a, **k: asked.append(a[2]) or True)

    class Dlg:
        def __init__(self, parent):
            pass

        def exec(self):
            return True

        def get_name(self):
            return "spzoz kraków "
    monkeypatch.setattr(mw, "HospitalDialog", Dlg)
    win._add_hospital()
    assert asked, "ostrzeżenie o duplikacie"
    current = win._detail_panel.current_hospital
    assert current is win._hospitals[-1] and current.machines == []


def test_e06_declining_the_duplicate_adds_nothing(win, monkeypatch):
    from ui import main_window as mw
    monkeypatch.setattr(mw, "confirm", lambda *a, **k: False)

    class Dlg:
        def __init__(self, parent):
            pass

        def exec(self):
            return True

        def get_name(self):
            return "Centrum Onkologii"
    monkeypatch.setattr(mw, "HospitalDialog", Dlg)
    win._add_hospital()
    assert len(win._hospitals) == 2


def test_e26_notes_do_not_rebuild_the_list(win):
    win._hospital_list.setCurrentRow(0)
    first = win._hospital_list.item(0)
    win._detail_panel._notes_edit.setPlainText("nowa notatka")
    assert win._hospital_list.item(0) is first


def test_e12_tab_leaves_the_machine_table(win):
    assert win._detail_panel._machines_table.tabKeyNavigation() is False
    assert win._detail_panel._db_table.tabKeyNavigation() is False


def test_v03_long_names_are_elided_with_a_tooltip(app):
    from ui.utils import ElidedLabel
    lbl = ElidedLabel("Szpital Wojewódzki im. Kardynała Stefana Wyszyńskiego w Lublinie")
    lbl.resize(150, 20)
    lbl.show()
    assert QLabel_text(lbl).endswith("…") and lbl.toolTip() == lbl.text()
    lbl.resize(2000, 20)
    assert QLabel_text(lbl) == lbl.text() and lbl.toolTip() == ""


def QLabel_text(lbl):
    from PyQt6.QtWidgets import QLabel
    return QLabel.text(lbl)


def test_v19_entering_and_leaving_edit_keeps_a_shrinkable_window(app):
    from types import SimpleNamespace
    from PyQt6.QtWidgets import QMainWindow
    from ui.vpn_panel import VpnPanel
    host = QMainWindow()
    fake = SimpleNamespace(window=lambda: host)
    VpnPanel._resize_window(fake, 520, 560)      # edit page
    VpnPanel._resize_window(fake, 420, 700)      # back to the list
    assert host.width() == 420 and host.height() == 700
    assert host.minimumHeight() == 640 and host.minimumWidth() == 360
