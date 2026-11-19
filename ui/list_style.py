"""One look for every list of HospitalHub Portable (owner, 2026-11-19: "listy
są jak z Windowsa 98") — trees, lists and tables: flat headers, roomy rows
with a hover, rounded selection, thin scroll bars without arrow buttons and
our own chevrons instead of Fusion's triangles.

``application_qss()`` is the application-wide sheet (remote_main installs
it); widgets keep their own inline sheets and those win where they say
something, so this fills in what the native style used to draw.  Colours are
the dark palette and go through ``theme.remap`` like every inline sheet.
"""

from __future__ import annotations

import os
import tempfile

from ui import theme

__all__ = ["application_qss", "install", "chevron_paths"]

_CHEVRON = ('<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" '
            'viewBox="0 0 24 24" fill="none" stroke="{c}" stroke-width="2.6" '
            'stroke-linecap="round" stroke-linejoin="round">'
            '<path d="{d}"/></svg>')
_RIGHT = "M9 5l7 7-7 7"
_DOWN = "M5 9l7 7 7-7"


def chevron_paths(color: str) -> tuple[str, str]:
    """Two small SVG files (closed, open) in the colour given — a stylesheet
    can only take an image from a file."""
    folder = os.path.join(tempfile.gettempdir(), "hh_portable_ui")
    os.makedirs(folder, exist_ok=True)
    tag = color.lstrip("#")
    paths = []
    for name, d in (("right", _RIGHT), ("down", _DOWN)):
        p = os.path.join(folder, f"chevron-{name}-{tag}.svg")
        if not os.path.exists(p):
            with open(p, "w", encoding="utf-8") as f:
                f.write(_CHEVRON.format(c=color, d=d))
        paths.append(p.replace("\\", "/"))
    return paths[0], paths[1]


def application_qss() -> str:
    right, down = chevron_paths(theme.paint("#8b949e"))
    css = f"""
QTreeView, QListView, QTableView {{
    background:#14161e; alternate-background-color:#1a1d28;
    border:1px solid #2a2d3a; border-radius:8px; color:#c9d1d9;
    outline:0; show-decoration-selected:1;
    selection-background-color:#1f2a4a; selection-color:#e6edf3;
}}
QTreeView::item, QListView::item, QTableView::item {{
    padding:4px 4px; border:none; min-height:20px;
}}
QTreeView::item:hover, QListView::item:hover, QTableView::item:hover {{
    background:#1a1d28;
}}
QTreeView::item:selected, QListView::item:selected, QTableView::item:selected {{
    background:#1f2a4a; color:#e6edf3;
}}
QTreeView::branch {{ background:transparent; }}
QTreeView::branch:hover {{ background:#1a1d28; }}
QTreeView::branch:selected {{ background:#1f2a4a; }}
QTreeView::branch:has-children:!has-siblings:closed,
QTreeView::branch:closed:has-children:has-siblings {{
    border-image:none; image:url({right});
}}
QTreeView::branch:open:has-children:!has-siblings,
QTreeView::branch:open:has-children:has-siblings {{
    border-image:none; image:url({down});
}}
QHeaderView {{ background:transparent; border:none; }}
QHeaderView::section {{
    background:#1a1d28; color:#8b949e; border:none;
    border-bottom:1px solid #2a2d3a; border-right:1px solid #21262d;
    padding:6px 8px; font-weight:600;
}}
QHeaderView::section:last {{ border-right:none; }}
QHeaderView::section:hover {{ background:#21262d; color:#c9d1d9; }}
QTableCornerButton::section {{ background:#1a1d28; border:none; }}
QScrollBar:vertical {{
    background:transparent; width:10px; margin:2px; border:none;
}}
QScrollBar::handle:vertical {{
    background:#30363d; border-radius:4px; min-height:28px;
}}
QScrollBar::handle:vertical:hover {{ background:#484f58; }}
QScrollBar:horizontal {{
    background:transparent; height:10px; margin:2px; border:none;
}}
QScrollBar::handle:horizontal {{
    background:#30363d; border-radius:4px; min-width:28px;
}}
QScrollBar::handle:horizontal:hover {{ background:#484f58; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width:0; height:0; border:none; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background:transparent; }}
QComboBox::drop-down {{
    subcontrol-origin:padding; subcontrol-position:center right;
    width:22px; border:none; background:transparent;
}}
QComboBox::down-arrow {{ image:url({down}); width:12px; height:12px; }}
QComboBox QAbstractItemView {{
    background:#1a1d28; color:#c9d1d9; border:1px solid #2a2d3a;
    border-radius:6px; padding:4px; outline:0;
    selection-background-color:#1f2a4a; selection-color:#e6edf3;
}}
"""
    return theme.remap(css)


def install(app) -> None:
    """Add the list look to whatever sheet the application already has."""
    app.setStyleSheet((app.styleSheet() or "") + application_qss())
