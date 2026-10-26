"""The "?" of the VPN list: what HospitalHub does with each VPN client
(2026-10-26, owner) — which ones it connects by itself, which ones must be
disconnected by hand, which ones it only starts so the login and password are
copied in by the user.

The text follows what ``vpn_connect.py`` and the V2 providers do today
(``vpn/catalog.py`` holds the evidence); ``tests/test_vpn_help.py`` checks
that every built-in provider is described.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QPushButton, QTextBrowser, QVBoxLayout, QHBoxLayout

#: (group title, colour, [(provider, what happens)])
GROUPS = [
    ("Łączy i rozłącza sam", "#3fb950", [
        ("FortiClient",
         "HH uruchamia klienta i wpisuje login oraz hasło. Gdy okno FortiClient "
         "jest otwarte, ale nieaktywne, karta prosi: <i>kliknij je</i> — dopiero "
         "wtedy dane są wpisywane. Kod 2FA HH zbiera we własnym okienku. "
         "Rozłącz z karty (■)."),
        ("Stormshield",
         "HH uruchamia klienta (może zapytać UAC) i wpisuje dane. Rozłącz z karty: "
         "HH wyciąga okno klienta i zatwierdza rozłączenie."),
    ]),
    ("Łączy sam, rozłączasz ręcznie", "#d29922", [
        ("Barracuda",
         "HH uruchamia klienta i wpisuje dane w jego okno. Rozłączenie tylko "
         "w kliencie Barracuda."),
    ]),
    ("Tylko uruchamia — logujesz się sam (kopiuj login / hasło)", "#58a6ff", [
        ("GlobalProtect",
         "HH łączy z portalem i otwiera okno klienta; login i hasło wklejasz sam. "
         "Rozłącz z karty (■)."),
        ("SonicWall NetExtender",
         "HH otwiera klienta; dane wklejasz sam. Rozłączenie tylko w kliencie."),
        ("Hillstone Secure Connect",
         "HH otwiera klienta (może zapytać UAC); dane wklejasz sam. Rozłączenie "
         "tylko w kliencie."),
        ("Inne programy (np. AnyDesk)",
         "HH uruchamia program wskazany w ustawieniach (zębatka). Dla narzędzi "
         "zdalnego pulpitu status nie jest pokazywany."),
    ]),
    ("Tylko z Windowsa", "#8b949e", [
        ("Windows VPN",
         "Bez przycisku Połącz — połącz z listy VPN w Windowsie (ikona sieci "
         "na pasku). Login i hasło są w profilu Windows, nie w HH."),
    ]),
]

BUTTONS = [
    ("AMMS", "lewy klik: otwiera AMMS i loguje; prawy: edycja, kopiuj hasło"),
    ("▶ / ■", "Połącz / Rozłącz (gdy klient na to pozwala — patrz wyżej)"),
    ("ludzik", "kopiuj login"),
    ("klucz", "kopiuj hasło — wklejasz w kliencie Ctrl+V"),
    ("ołówek", "edycja profilu"),
    ("zębatka", "ścieżki do programów klientów, własni providerzy"),
]

STATUSES = "○ Rozłączono &nbsp;·&nbsp; ◌ Łączenie… &nbsp;·&nbsp; ● Połączono"


def guide_html() -> str:
    parts = ['<div style="font-size:10pt">']
    for title, colour, items in GROUPS:
        parts.append(f'<p style="margin:10px 0 4px 0"><b style="color:{colour}">'
                     f'● {title}</b></p><ul style="margin-top:0">')
        for name, text in items:
            parts.append(f"<li><b>{name}</b> — {text}</li>")
        parts.append("</ul>")
    parts.append('<p style="margin:12px 0 4px 0"><b>Guziki na karcie</b></p><ul style="margin-top:0">')
    for name, text in BUTTONS:
        parts.append(f"<li><b>{name}</b> — {text}</li>")
    parts.append("</ul>")
    parts.append(f'<p style="margin:10px 0 0 0"><b>Status:</b> {STATUSES}</p>')
    parts.append("</div>")
    return "".join(parts)


class VpnHelpDialog(QDialog):
    """Non-modal: it can stay open next to the list while connecting."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("VPN — jak to działa")
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)
        self.resize(520, 560)
        lay = QVBoxLayout(self)
        view = QTextBrowser()
        view.setOpenExternalLinks(False)
        view.setHtml(guide_html())
        lay.addWidget(view)
        row = QHBoxLayout()
        row.addStretch()
        btn = QPushButton("Zamknij")
        btn.clicked.connect(self.close)
        row.addWidget(btn)
        lay.addLayout(row)
