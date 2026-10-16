"""2026-10-16 (owner's request): two extra looks to choose from — Nocny
granat (dark navy) and Miętowy (light mint) — over the same role table as
the light theme, which must stay exactly as it was."""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_every_palette_fills_every_role():
    from ui import theme
    roles = set(theme._ROLES.values())
    for tid, (_label, pal, _light) in theme.THEMES.items():
        if pal is not None:
            assert roles <= set(pal), tid


def test_light_map_is_unchanged():
    from ui import theme
    assert theme._MAPS[theme.LIGHT]["#0d1117"] == theme.WINDOW == "#e7e8ec"
    assert theme._MAPS[theme.LIGHT]["#1f6feb"] == "#1f6feb"
    assert len(theme._MAPS[theme.LIGHT]) == 124


@pytest.mark.parametrize("tid,light", [("dark", False), ("navy", False),
                                       ("light", True), ("mint", True)])
def test_remap_and_light_flag_follow_the_theme(monkeypatch, tid, light):
    from ui import theme
    monkeypatch.setattr(theme, "_active", tid)
    assert theme.is_light() is light
    css = "background: #0d1117; color: #c9d1d9;"
    if tid == "dark":
        assert theme.remap(css) == css and theme.paint("#0d1117") == "#0d1117"
    else:
        pal = theme.THEMES[tid][1]
        assert theme.remap(css) == f"background: {pal['WINDOW']}; color: {pal['TXT']};"
        assert theme.paint("#58A6FF") == pal["BLUE2"]


@pytest.mark.parametrize("value,expected", [("navy", "navy"), ("mint", "mint"),
                                            ("light", "light"), ("purple", "dark")])
def test_config_keeps_only_known_themes(value, expected):
    import config
    config.save_theme(value)
    try:
        assert config.load_theme() == expected
    finally:
        config.save_theme("dark")


def test_menu_offers_four_themes_and_saves_the_choice(app, tmp_path, monkeypatch):
    import config
    from PyQt6.QtWidgets import QMessageBox
    from ui import main_window as mw
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    w = mw.MainWindow(str(tmp_path / "v.vault"), "pw", [])
    try:
        view = next(a.menu() for a in w.menuBar().actions() if a.text() == "Widok")
        sub = next(a.menu() for a in view.actions() if a.text() == "Motyw")
        labels = [a.text() for a in sub.actions()]
        assert labels == ["Ciemny (domyślny)", "Nocny granat", "Jasny", "Miętowy"]
        navy = sub.actions()[1]
        navy.trigger()
        assert navy.isChecked() and config.load_theme() == "navy"
    finally:
        config.save_theme("dark")
        w._unsaved = False
