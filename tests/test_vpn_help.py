"""2026-10-26 (owner): the "?" of the VPN list — a quick guide to what HH
does with each client.  Every built-in provider has to be in it."""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


def test_1_every_builtin_provider_is_described():
    import models
    from ui import vpn_help
    described = {name for _t, _c, items in vpn_help.GROUPS for name, _ in items}
    assert set(models.VPN_PROVIDERS_BUILTIN) <= described


def test_2_what_disconnects_by_itself_matches_the_disconnect_code():
    """The guide's "Rozłącz z karty" is said only of the clients whose
    disconnect in vpn_connect.py does something (CLI / clicking the client)."""
    import inspect
    import vpn_connect
    from ui import vpn_help
    src = inspect.getsource(vpn_connect.disconnect)
    manual = {"SonicWall NetExtender", "Hillstone Secure Connect", "Barracuda"}
    for name in manual:
        block = src.split(f'provider == "{name}"', 1)[1].split("elif provider", 1)[0]
        assert "Rozłącz ręcznie" in block, name
    texts = {name: text for _t, _c, items in vpn_help.GROUPS for name, text in items}
    for name in manual:
        assert "tylko" in texts[name] and "Rozłącz z karty" not in texts[name]
    for name in ("FortiClient", "Stormshield", "GlobalProtect"):
        assert "Rozłącz z karty" in texts[name]


def test_3_the_dialog_shows_the_guide(qapp=None):
    from PyQt6.QtWidgets import QApplication, QTextBrowser
    app = QApplication.instance() or QApplication([])
    from ui.vpn_help import VpnHelpDialog
    dlg = VpnHelpDialog()
    text = dlg.findChild(QTextBrowser).toPlainText()
    assert "FortiClient" in text and "Windows VPN" in text and "kopiuj hasło" in text
    dlg.deleteLater()
    app.processEvents()
