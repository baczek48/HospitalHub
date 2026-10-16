"""UX audit 2026-10-16 (Etap 71): E-07 safe confirmations, V-07 Polish plurals."""

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


@pytest.mark.parametrize("n, want", [
    (0, "0 plików"), (1, "1 plik"), (2, "2 pliki"), (4, "4 pliki"),
    (5, "5 plików"), (12, "12 plików"), (14, "14 plików"), (21, "21 plików"),
    (22, "22 pliki"), (24, "24 pliki"), (112, "112 plików"), (102, "102 pliki"),
])
def test_plural(n, want):
    from ui.utils import plural
    assert plural(n, "plik", "pliki", "plików") == want


@pytest.fixture
def boxes(app, monkeypatch):
    """Every QMessageBox shown: its default/escape button and text; no click."""
    from PyQt6.QtWidgets import QMessageBox
    seen = []

    def exec_(self):
        seen.append(dict(text=self.text(),
                         default=self.defaultButton().text() if self.defaultButton() else None,
                         escape=self.escapeButton().text() if self.escapeButton() else None))
        return 0
    monkeypatch.setattr(QMessageBox, "exec", exec_)
    return seen


def test_confirm_defaults_to_no_and_enter_deletes_nothing(boxes):
    from ui.utils import confirm
    assert confirm(None, "Usuń", "Usunąć?") is False
    assert boxes[0]["default"] == "Nie" and boxes[0]["escape"] == "Nie"


def test_deleting_a_hospital_names_what_goes_and_defaults_to_cancel(boxes):
    import models
    from ui.detail_panel import DetailPanel
    h = models.Hospital(name="H", machines=[
        models.Machine(ip=f"10.0.0.{i}", credentials=[models.Credential(login="a")])
        for i in range(22)])
    panel = DetailPanel()
    panel.show_hospital(h, [h])
    panel.delete_hospital()
    box = boxes[-1]
    assert "22 maszyny" in box["text"] and "0 baz" in box["text"]
    assert "22 poświadczenia" in box["text"]
    assert box["default"] == "Anuluj" and box["escape"] == "Anuluj"
    assert panel.current_hospital is h, "nic nie usunięte bez kliknięcia"


def test_the_badge_counts_hidden_entries_in_polish(app):
    import models
    from ui.detail_panel import DetailPanel
    h = models.Hospital(name="H", machines=[
        models.Machine(ip="10.0.0.1", admin_only=True),
        models.Machine(ip="10.0.0.2")])
    panel = DetailPanel()
    panel.show_hospital(h, [h])
    text = panel._stats_badge.text()
    assert "1 maszyna" in text and "1 ukryta pozycja" in text
