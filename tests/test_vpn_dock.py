"""2026-10-26 (owner): with both vaults open the VPN one is a pane of the
main window (a dock, like a pane in Word) — one window on the taskbar,
maximised together with the VPN pane keeping its width; taken out again
before the main window goes away."""

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
def pair(app, tmp_path, monkeypatch):
    import models
    from ui import main_window as mw
    from ui import detail_panel as dp
    from ui.vpn_panel import VpnPanel
    monkeypatch.setattr(mw, "save_personal_vpn_vault", lambda p: None)
    # Status polling asks the real VPN clients — not in a test.
    monkeypatch.setattr(VpnPanel, "_poll_status", lambda self: None)
    main = mw.MainWindow(str(tmp_path / "m.vault"), "pw", [models.Hospital(name="A")])
    vpn = mw.MainWindow(str(tmp_path / "v.vault"), "pw",
                        [models.VpnProfile(name="A")], vault_type="vpn")
    main.show()
    vpn.show()
    yield main, vpn
    from ui import vpn_dock
    vpn_dock.undock(vpn)
    for w in (main, vpn):
        w._unsaved = False
        w.hide()
    vpn._vpn_panel.cleanup()
    dp.share_vpn_window(None)


def test_1_docked_the_vpn_window_is_a_pane_of_the_main_one(pair, app):
    from ui import vpn_dock
    main, vpn = pair
    d = vpn_dock.dock(main, vpn)
    app.processEvents()
    assert not vpn.isWindow() and vpn.window() is main
    assert vpn_dock.dock_of(vpn) is d and vpn_dock.host_of(vpn) is main
    assert vpn_dock.docked_in(main) == [vpn]
    assert main.dockWidgetArea(d).name == "RightDockWidgetArea"
    assert vpn_dock.dock(main, vpn) is d             # twice = once


def test_2_the_pane_title_follows_the_vpn_vault(pair, app):
    from ui import vpn_dock
    main, vpn = pair
    d = vpn_dock.dock(main, vpn)
    vpn._unsaved = True
    vpn._update_title()
    assert d.windowTitle() == vpn.windowTitle() and "niezapisane" in d.windowTitle()


def test_3_closing_the_vpn_pane_hides_only_the_pane(pair, app):
    from ui import vpn_dock
    main, vpn = pair
    d = vpn_dock.dock(main, vpn)
    vpn._close_to_tray()
    app.processEvents()
    assert not d.isVisible() and main.isVisible()
    assert not vpn_dock.pane_visible(vpn)
    vpn_dock.show_pane(vpn)
    app.processEvents()
    assert vpn_dock.pane_visible(vpn)


def test_4_the_edit_page_widens_the_pane_never_the_main_window(pair, app):
    from ui import vpn_dock
    from ui.vpn_panel import _EDIT_SIZE
    main, vpn = pair
    d = vpn_dock.dock(main, vpn)
    main.resize(1500, 760)              # room for the edit page
    for _ in range(5):
        app.processEvents()
    size = main.size()
    narrow = d.width()
    vpn._vpn_panel._enter_edit(0)
    app.processEvents()
    assert main.size() == size
    assert d.width() >= _EDIT_SIZE[0] - 2
    vpn._vpn_panel._exit_edit()
    app.processEvents()
    assert main.size() == size and abs(d.width() - narrow) <= 2


def test_5_undocked_it_is_a_window_of_its_own_again(pair, app):
    from ui import vpn_dock
    from ui.window_layout import VPN_SIZE
    main, vpn = pair
    vpn_dock.dock(main, vpn)
    assert vpn_dock.undock(vpn)
    app.processEvents()
    assert vpn.isWindow() and vpn_dock.dock_of(vpn) is None
    assert vpn_dock.docked_in(main) == []
    assert (vpn.width(), vpn.height()) == VPN_SIZE
    assert not vpn_dock.undock(vpn)                  # not docked: nothing to do
    # Its title still reaches the tray (only the pane's sync was cut).
    seen = []
    vpn.title_changed.connect(lambda: seen.append(1))
    vpn._update_title()
    assert seen


def test_6_the_app_manager_docks_and_undocks(pair, app, monkeypatch):
    import main as hh
    from ui import vpn_dock
    main, vpn = pair
    mgr = hh.AppManager.__new__(hh.AppManager)
    mgr._windows = [main, vpn]
    mgr._trays = {}
    mgr._app = app
    mgr._default_icon = mgr._vpn_icon = None
    monkeypatch.setattr("config.load_vpn_pane", lambda: "right")
    mgr._dock_vpn()
    assert vpn_dock.host_of(vpn) is main
    # The main vault closes: the VPN one stays, as a window of its own.
    mgr.remove_window(main)
    app.processEvents()
    assert vpn.isWindow() and vpn.isVisible() and vpn_dock.dock_of(vpn) is None


def test_7_ctrl_s_saves_the_vault_where_the_focus_is(pair, app, monkeypatch):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    from ui import vpn_dock
    main, vpn = pair
    saved = []
    monkeypatch.setattr(main, "_do_save", lambda path: saved.append("main") or True)
    monkeypatch.setattr(vpn, "_do_save", lambda path: saved.append("vpn") or True)
    vpn_dock.dock(main, vpn)
    main.activateWindow()
    app.processEvents()
    for target, who in ((main._search_edit, "main"), (vpn._vpn_panel, "vpn")):
        target.setFocus()
        app.processEvents()
        QTest.keyClick(target, Qt.Key.Key_S, Qt.KeyboardModifier.ControlModifier)
        app.processEvents()
        assert saved[-1:] == [who]
    # Undocked: the VPN window's own keys cover the whole window again.
    vpn_dock.undock(vpn)
    for act in vpn_dock._menu_shortcuts(vpn) + vpn_dock._menu_shortcuts(main):
        assert act.shortcutContext() == Qt.ShortcutContext.WindowShortcut


def test_8_the_pane_never_gets_narrower_than_the_cards_and_never_floats(pair, app):
    from PyQt6.QtWidgets import QDockWidget
    from ui import vpn_dock
    main, vpn = pair
    d = vpn_dock.dock(main, vpn)
    assert vpn.minimumWidth() == vpn_dock.PANE_MIN_WIDTH
    main.resizeDocks([d], [200], __import__("PyQt6.QtCore", fromlist=["Qt"]).Qt.Orientation.Horizontal)
    app.processEvents()
    assert d.width() >= vpn_dock.PANE_MIN_WIDTH
    assert not d.features() & QDockWidget.DockWidgetFeature.DockWidgetFloatable
    vpn_dock.undock(vpn)
    assert vpn.minimumWidth() == vpn_dock.WINDOW_MIN_WIDTH


def test_9_odepnij_makes_it_a_window_of_its_own_shown(pair, app):
    from ui import vpn_dock
    main, vpn = pair
    d = vpn_dock.dock(main, vpn)
    vpn_dock.header_buttons(vpn)[0].click()
    for _ in range(3):
        app.processEvents()
    assert vpn.isWindow() and vpn.isVisible() and vpn_dock.dock_of(vpn) is None


def test_10_dropped_at_an_edge_of_the_main_window_it_docks_there(pair, app):
    from PyQt6.QtCore import QPoint, Qt
    from ui import vpn_dock
    main, vpn = pair
    main.move(100, 100)
    main.resize(1200, 700)
    app.processEvents()
    g = main.frameGeometry()
    mid_y = g.y() + g.height() // 2
    assert vpn_dock.drop_area(main, QPoint(g.right() - 10, mid_y)) == Qt.DockWidgetArea.RightDockWidgetArea
    assert vpn_dock.drop_area(main, QPoint(g.x() + 10, mid_y)) == Qt.DockWidgetArea.LeftDockWidgetArea
    assert vpn_dock.drop_area(main, QPoint(g.x() + g.width() // 2, mid_y)) is None
    assert vpn_dock.drop_area(main, QPoint(g.right() + 50, mid_y)) is None
    assert vpn_dock.drop_area(None, QPoint(0, 0)) is None


def test_11_przypnij_from_the_menu_docks_into_the_main_window(pair, app):
    from ui import vpn_dock
    main, vpn = pair
    vpn_dock.set_host_finder(lambda: main)
    try:
        assert vpn_dock.redock(vpn)
        assert vpn_dock.host_of(vpn) is main
        assert not vpn_dock.redock(vpn)          # already in
    finally:
        vpn_dock.set_host_finder(None)


def test_12_dragging_near_an_edge_lights_up_where_it_would_go(pair, app, monkeypatch):
    from PyQt6.QtCore import QPoint, Qt
    from ui import vpn_dock
    main, vpn = pair
    main.move(100, 100)
    main.resize(1200, 700)
    app.processEvents()
    vpn_dock.set_host_finder(lambda: main)
    g = main.frameGeometry()
    where = {"pos": QPoint(g.right() - 10, g.y() + 300)}
    monkeypatch.setattr(vpn_dock.QCursor, "pos", staticmethod(lambda: where["pos"]))
    try:
        vpn_dock.drag_hover(vpn)
        hint = vpn_dock._hint[0]
        assert hint is not None and hint.isVisible() and hint.parentWidget() is main
        assert hint.geometry() == vpn_dock.drop_hint_rect(main, Qt.DockWidgetArea.RightDockWidgetArea)
        assert hint.geometry().right() == main.width() - 1
        where["pos"] = QPoint(g.x() + g.width() // 2, g.y() + 300)     # middle: nothing
        vpn_dock.drag_hover(vpn)
        assert vpn_dock._hint[0] is None
        where["pos"] = QPoint(g.x() + 5, g.y() + 300)
        vpn_dock.drag_hover(vpn)
        assert vpn_dock._hint[0].geometry().x() == 0
        vpn_dock.drag_end()
        assert vpn_dock._hint[0] is None
    finally:
        vpn_dock.drag_end()
        vpn_dock.set_host_finder(None)


def _tray_click(mgr, window):
    from PyQt6.QtWidgets import QSystemTrayIcon
    mgr._on_tray_activated(QSystemTrayIcon.ActivationReason.Trigger, window)


def _manager(app, windows):
    import main as hh
    mgr = hh.AppManager.__new__(hh.AppManager)
    mgr._windows = list(windows)
    mgr._trays = {}
    mgr._app = app
    mgr._default_icon = mgr._vpn_icon = None
    return mgr


def test_13_tray_click_on_a_minimised_window_brings_it_up(pair, app):
    """2026-10-26 (owner): minimised, the tray click only hid it from the
    taskbar and the next one showed it still minimised."""
    main, vpn = pair
    mgr = _manager(app, [main, vpn])
    vpn.showMaximized()
    app.processEvents()
    vpn.showMinimized()
    app.processEvents()
    _tray_click(mgr, vpn)
    app.processEvents()
    assert vpn.isVisible() and not vpn.isMinimized() and vpn.isMaximized()
    _tray_click(mgr, vpn)                       # on the screen: hides as before
    app.processEvents()
    assert not vpn.isVisible()
    _tray_click(mgr, vpn)
    app.processEvents()
    assert vpn.isVisible() and not vpn.isMinimized()


def test_14_tray_click_on_the_pane_of_a_minimised_main_window(pair, app):
    from ui import vpn_dock
    main, vpn = pair
    mgr = _manager(app, [main, vpn])
    vpn_dock.dock(main, vpn)
    main.showMinimized()
    app.processEvents()
    assert not vpn_dock.pane_visible(vpn)
    _tray_click(mgr, vpn)
    app.processEvents()
    assert not main.isMinimized() and vpn_dock.pane_visible(vpn)


def test_15_docked_one_menu_bar_and_the_vpn_menu_in_it(pair, app):
    """2026-10-26 (owner): docked, no second menu bar and no second title —
    the VPN vault's menu is "VPN" in the main window's menu bar."""
    from ui import vpn_dock
    main, vpn = pair
    d = vpn_dock.dock(main, vpn)
    app.processEvents()
    assert not vpn.menuBar().isVisible()
    assert d.titleBarWidget().sizeHint().height() <= 0 or not d.titleBarWidget().isVisible() \
        or d.titleBarWidget().height() == 0
    titles = [a.text() for a in main.menuBar().actions()]
    assert titles.count("VPN") == 1
    m = vpn_dock.vpn_menu(vpn)
    texts = [a.text() for a in m.actions()]
    assert "Zapisz" in texts and "Sortuj" in texts and "Odepnij panel" in texts
    # Unsaved VPN vault: said in the menu's name.
    vpn._unsaved = True
    vpn._update_title()
    assert m.title() == "VPN (niezapisane)"
    vpn._unsaved = False
    vpn._update_title()
    # The other side.
    next(a for a in m.actions() if a.text().startswith("Przenieś")).trigger()
    app.processEvents()
    assert main.dockWidgetArea(d) == __import__("PyQt6.QtCore", fromlist=["Qt"]).Qt.DockWidgetArea.LeftDockWidgetArea
    # Undocked: everything back where it was.
    vpn_dock.undock(vpn)
    app.processEvents()
    assert "VPN" not in [a.text() for a in main.menuBar().actions()]
    assert vpn.menuBar().isVisibleTo(vpn)
    assert "separator" not in main.styleSheet()


def test_16_odepnij_and_x_stand_in_the_header(pair, app):
    from ui import vpn_dock
    main, vpn = pair
    d = vpn_dock.dock(main, vpn)
    app.processEvents()
    out, hide = vpn_dock.header_buttons(vpn)
    bar = vpn._vpn_panel._top_bar
    assert bar.indexOf(out) >= 0 and bar.indexOf(hide) >= 0
    hide.click()
    app.processEvents()
    assert not d.isVisible()
    vpn_dock.undock(vpn)
    app.processEvents()
    assert bar.indexOf(out) < 0 and bar.indexOf(hide) < 0


def test_17_the_vpn_menu_has_no_duplicates_of_the_main_plik(pair, app):
    from ui import vpn_dock
    main, vpn = pair
    vpn_dock.dock(main, vpn)
    acts = vpn_dock.vpn_menu(vpn).actions()
    texts = [a.text() for a in acts]
    for gone in ("Otwórz vault...", "Otwieraj terminal SSH zmaksymalizowany", "Zamknij okno"):
        assert gone not in texts
    assert not acts[0].isSeparator()
    assert not any(a.isSeparator() and b.isSeparator() for a, b in zip(acts, acts[1:]))
    vpn_dock.undock(vpn)
    own = [a.text() for a in vpn._file_menu.actions()]
    assert "Otwórz vault..." in own and "Zamknij okno" in own     # its own menu intact



def _click_through_window(app, window, widget):
    """A click the way Windows delivers it: to the top-level QWindow at a
    position, Qt finds the widget and maps the position itself."""
    from PyQt6.QtCore import QPoint, Qt
    from PyQt6.QtTest import QTest
    pt = widget.mapTo(window, QPoint(widget.width() // 2, widget.height() // 2))
    QTest.mouseClick(window.windowHandle(), Qt.MouseButton.LeftButton,
                     Qt.KeyboardModifier.NoModifier, pt)
    app.processEvents()


def _edit_button(vpn):
    from PyQt6.QtWidgets import QPushButton
    return next(b for b in vpn._vpn_panel.findChildren(QPushButton)
                if b.isVisible() and b.toolTip() == "Edytuj")


def test_18_after_moving_to_the_other_side_the_buttons_still_click(pair, app):
    """2026-10-26 (owner): moved to the other side from the VPN menu, no
    button of the pane reacted — Qt mapped clicks through the VPN window's
    native window left over from when it stood on its own."""
    from ui import vpn_dock
    main, vpn = pair
    vpn_dock.dock(main, vpn)
    for _ in range(3):
        app.processEvents()
    assert vpn.windowHandle() is None
    for _ in range(2):                                   # left, then right again
        next(a for a in vpn_dock.vpn_menu(vpn).actions()
             if a.text().startswith("Przenieś")).trigger()
        for _ in range(3):
            app.processEvents()
        _click_through_window(app, main, _edit_button(vpn))
        assert vpn._vpn_panel._stack.currentIndex() == 1
        vpn._vpn_panel._exit_edit()
        app.processEvents()


def test_19_the_layout_the_user_leaves_is_remembered(pair, app, monkeypatch):
    from PyQt6.QtCore import QPoint
    from ui import vpn_dock
    main, vpn = pair
    saved = []
    vpn_dock.set_host_finder(lambda: main, save_layout=saved.append)
    try:
        d = vpn_dock.dock(main, vpn)
        assert saved == []                         # docking by itself: no choice made
        vpn_dock._other_side(d)
        assert saved[-1] == vpn_dock.LEFT
        vpn_dock.header_buttons(vpn)[0].click()    # Odepnij
        for _ in range(3):
            app.processEvents()
        assert saved[-1] == vpn_dock.WINDOW
        assert vpn_dock.redock(vpn) and saved[-1] == vpn_dock.RIGHT
        vpn_dock.undock(vpn)                       # the main window closing: not a choice
        assert saved[-1] == vpn_dock.RIGHT
        g = main.frameGeometry()
        monkeypatch.setattr(vpn_dock.QCursor, "pos",
                            staticmethod(lambda: QPoint(g.x() + 5, g.y() + 200)))
        assert vpn_dock.redock_if_dropped(vpn) and saved[-1] == vpn_dock.LEFT
    finally:
        vpn_dock.set_host_finder(None)


def test_20_the_next_start_puts_it_where_it_was_left(pair, app, monkeypatch):
    from PyQt6.QtCore import Qt
    from ui import vpn_dock
    main, vpn = pair
    mgr = _manager(app, [main, vpn])
    monkeypatch.setattr("config.load_vpn_pane", lambda: "left")
    mgr._dock_vpn()
    assert main.dockWidgetArea(vpn_dock.dock_of(vpn)) == Qt.DockWidgetArea.LeftDockWidgetArea
    vpn_dock.undock(vpn)
    monkeypatch.setattr("config.load_vpn_pane", lambda: "window")
    mgr._dock_vpn()
    assert vpn_dock.dock_of(vpn) is None and vpn.isWindow()


def test_21_the_remembered_layout_survives_a_bad_value(tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "_config_path", lambda: tmp_path / "config.json")
    assert config.load_vpn_pane() == "right"
    config.save_vpn_pane("left")
    assert config.load_vpn_pane() == "left"
    config.save_vpn_pane("nonsense")
    assert config.load_vpn_pane() == "left"
