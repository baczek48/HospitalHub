"""2026-10-16 (owner's requests): Polish alphabetical order ("ś" after "s",
not after "z"); vector icons instead of colour emoji, sharp at any pixel
ratio; a visible "copied" flash in the light theme."""

import glob
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


# ── sorting ──────────────────────────────────────────────────────────────

def test_polish_alphabet_order():
    from ui.utils import polish_key
    names = ["Żary", "Szpital", "Środa Śląska", "Zabrze", "Łódź", "Lublin",
             "Ćmielów", "Cieszyn", "Sanok", "Tarnów", "Źródła", "Ełk", "Elbląg"]
    assert sorted(names, key=polish_key) == [
        "Cieszyn", "Ćmielów", "Elbląg", "Ełk", "Lublin", "Łódź", "Sanok",
        "Szpital", "Środa Śląska", "Tarnów", "Zabrze", "Źródła", "Żary"]


def test_polish_order_is_case_insensitive_and_digits_first():
    from ui.utils import polish_key
    assert sorted(["b", "A", "ą", "2x", "Ą"], key=polish_key) == ["2x", "A", "Ą", "ą", "b"]


def test_hospital_list_sorts_s_acute_after_s(app, tmp_path):
    import models
    from ui.main_window import MainWindow
    hs = [models.Hospital(name=n) for n in ("Zabrze", "Środa", "Sanok", "Żary")]
    w = MainWindow(str(tmp_path / "v.vault"), "pw", hs)
    w._sort_order = "asc"
    assert [h.name for h in w._filtered_hospitals()] == ["Sanok", "Środa", "Zabrze", "Żary"]
    w._unsaved = False


def test_vpn_profiles_sort_without_touching_the_locale(app, monkeypatch):
    import locale
    import models
    from ui import vpn_panel
    monkeypatch.setattr(vpn_panel.VpnPanel, "_poll_status", lambda self: None)
    monkeypatch.setattr(locale, "setlocale",
                        lambda *a: pytest.fail("process-wide locale changed"))
    ps = [models.VpnProfile(name=n, provider="FortiClient") for n in ("Żary", "Środa", "Sanok")]
    panel = vpn_panel.VpnPanel(ps)
    try:
        panel._sort_profiles("name")
        assert [p.name for p in panel.get_profiles()] == ["Sanok", "Środa", "Żary"]
    finally:
        panel.cleanup()


# ── icons ────────────────────────────────────────────────────────────────

_EMOJI = set("⚙🔒＋🔑➕⇆🔓🖥🌐👤📑✏🗑⬆⬇📋🗄⌂↻▾✕📄📂📁⊞⋮🔍🔐👁✎")


def test_no_emoji_icons_left_in_the_ui():
    found = []
    for path in glob.glob(os.path.join(_ROOT, "ui", "*.py")) + [os.path.join(_ROOT, "main.py")]:
        for i, line in enumerate(open(path, encoding="utf-8"), 1):
            code = line.split("#", 1)[0]
            if '"""' in line or "icons.py" in path:
                continue
            if any(c in _EMOJI for c in code):
                found.append(f"{os.path.basename(path)}:{i}")
    assert found == []


@pytest.mark.parametrize("ratio", [1.0, 1.25, 1.5, 2.0, 3.0])
def test_icons_are_drawn_for_the_pixel_ratio(app, ratio):
    from PyQt6.QtCore import QSize
    from ui import icons
    for name in sorted(icons.NAMES):
        pm = icons.icon(name, "#c9d1d9").pixmap(QSize(16, 16), ratio)
        assert pm.width() == round(16 * ratio), name     # real pixels, not stretched
        assert not pm.toImage().isNull()


def test_painter_icons_scale_their_drawing(app):
    from PyQt6.QtCore import QSize
    from ui import ssh_panel as sp
    pm = sp._sftp_icon("folder").pixmap(QSize(16, 16), 2.0)
    assert pm.width() == 32 and pm.devicePixelRatio() == 2.0


def test_icon_survives_many_paints(app):
    """The engine must not keep QSvgRenderer objects (deleted under us)."""
    import gc
    from PyQt6.QtCore import QSize
    from ui import icons
    ic = icons.icon("gear", "#123456")
    for _ in range(3):
        gc.collect()
        assert not ic.pixmap(QSize(20, 20), 1.0).isNull()


def test_badge_replaces_items_without_a_ghost(app):
    from PyQt6.QtWidgets import QLabel
    from ui.icons import IconBadge
    b = IconBadge("#58a6ff", "border: 1px solid #21262d;")
    b.set_items([("monitor", "1 maszyna"), ("database", "2 bazy")])
    b.show()
    b.set_items([("monitor", "3 maszyny")])
    app.processEvents()
    visible = [w for w in b.findChildren(QLabel) if w.isVisible()]
    assert len(visible) == 2 and b.text() == "3 maszyny"
    b.hide()


# ── copy flash ───────────────────────────────────────────────────────────

def test_copy_flash_is_visible_in_the_light_theme(app, monkeypatch):
    from PyQt6.QtWidgets import QApplication, QPushButton
    from ui import detail_panel as dp
    from ui import theme
    monkeypatch.setattr(theme, "_active", theme.LIGHT)
    btn = QPushButton("root")
    btn.setStyleSheet("QPushButton { background: #f6f8fa; }")
    dp._pulse_copy_button(btn)
    anim = btn._copy_pulse_anim
    anim.pause()
    anim.setCurrentTime(int(anim.duration() * 0.25))      # the held peak
    bg, bd = dp._PULSE_LIGHT
    assert f"background: {bg}" in btn.styleSheet()
    assert f"border-color: {bd}" in btn.styleSheet()
    anim.setCurrentTime(anim.duration())
    anim.stop()
    anim.finished.emit()
    QApplication.processEvents()
    assert btn.styleSheet() == btn._pulse_base_css
