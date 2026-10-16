"""Machine and database tables (Etap 71C, module R2; UX audit V-05, E-08, E-09)."""

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


@pytest.fixture
def panel(app):
    import models
    from ui.detail_panel import DetailPanel
    m = models.Machine(ip="10.0.0.1", name="pacs", description="opis " * 20,
                       credentials=[models.Credential(login="admin", password="pw1"),
                                    models.Credential(login="root", password="pw2")])
    d = models.Database(host="db.local", name="HIS", note="n" * 50,
                        credentials=[models.Credential(login="sa", password="pw3")])
    h = models.Hospital(name="H", machines=[m], databases=[d])
    p = DetailPanel()
    p.show_hospital(h, [h])
    p.machine, p.db = m, d
    return p


def _actions_visible(table, akcje_col):
    x = table.columnViewportPosition(akcje_col)
    return x >= 0 and x + table.columnWidth(akcje_col) <= table.viewport().width() + 1


@pytest.mark.parametrize("width", [1000, 700, 520])
def test_v05_the_actions_column_stays_on_screen(app, panel, width):
    from ui import detail_panel as dp
    panel.resize(width, 700)
    panel.show()
    app.processEvents()
    assert _actions_visible(panel._machines_table, dp._MACHINES_AKCJE_COL)
    assert _actions_visible(panel._db_table, dp._DB_AKCJE_COL)
    panel.hide()


def test_v05_columns_come_back_when_there_is_room(app, panel):
    from ui import detail_panel as dp
    panel.resize(520, 700); panel.show(); app.processEvents()
    assert panel._db_table.isColumnHidden(4)
    panel.resize(1400, 700); app.processEvents()
    assert not any(panel._db_table.isColumnHidden(c) for c in range(5))
    panel.hide()


def _menu_texts(menu):
    out = []
    for a in menu.actions():
        out.append(a.text())
        if a.menu():
            out += ["  " + t for t in _menu_texts(a.menu())]
    return out


def test_e08_e09_the_row_menu_offers_every_account(panel):
    texts = _menu_texts(panel._row_menu(panel.machine, 'machine'))
    for want in ("👤  Kopiuj login: admin", "🔑  Kopiuj hasło: admin",
                 "👤  Kopiuj login: root", "🔑  Kopiuj hasło: root",
                 "  admin", "  root"):
        assert want in texts, texts


def test_e08_copy_login_puts_the_login_on_the_clipboard(panel, monkeypatch):
    from ui import detail_panel as dp
    copied = []
    monkeypatch.setattr(dp, "_clipboard_copy", copied.append)
    menu = panel._row_menu(panel.machine, 'machine')
    next(a for a in menu.actions() if a.text() == "👤  Kopiuj login: root").trigger()
    assert copied == ["root"]


def test_e09_connect_as_uses_the_chosen_account(panel, monkeypatch):
    opened = []
    monkeypatch.setattr(panel, "_open_ssh", opened.append)
    panel._connect_as(panel.machine, panel.machine.credentials[1])
    assert opened[0].credentials[0].login == "root"
    assert panel.machine.credentials[0].login == "admin", "oryginał bez zmian"


def test_the_key_button_still_copies_the_password(panel, monkeypatch):
    from PyQt6.QtWidgets import QPushButton
    from ui import detail_panel as dp
    copied = []
    monkeypatch.setattr(dp, "_clipboard_copy", copied.append)
    cell = panel._machines_table.cellWidget(0, dp._MACHINES_AKCJE_COL)
    btn = next(b for b in cell.findChildren(QPushButton) if b.text().startswith("🔑"))
    btn.click()
    assert copied == ["pw1"]


def test_v15_empty_tables_and_lists_say_so(app, tmp_path):
    import models
    from ui.detail_panel import DetailPanel
    from ui.main_window import MainWindow
    h = models.Hospital(name="Pusty", machines=[models.Machine(ip="1.1.1.1", admin_only=True)])
    p = DetailPanel()
    p.show_hospital(h, [h])
    assert "odblokuj tryb admina" in p._machines_table.empty_hint
    assert p._db_table.empty_hint.startswith("Brak baz danych")
    w = MainWindow(str(tmp_path / "x.vault"), "pw", [h])
    w._search_edit.setText("nic-takiego")
    assert w._hospital_list.empty_hint == "Brak wyników dla „nic-takiego”."
    w._search_edit.setText("")
    w._unsaved = False
