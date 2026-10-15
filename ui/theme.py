"""Light/dark theming for HospitalHub.

The whole UI is authored in a GitHub-dark palette via inline ``setStyleSheet``
strings. Rather than rewrite every literal, the *dark* styles stay the single
source of truth and, when the user picks the light theme, we transparently
remap each dark hex colour to its warm-ivory counterpart.

How it works:
  * ``install(app, theme)`` is called once at startup, before any window is
    built. In light mode it (a) sets a light ``QPalette`` for the native Fusion
    widgets that have no inline style, and (b) monkeypatches
    ``QWidget.setStyleSheet`` so every stylesheet string is passed through
    :func:`remap` before being applied.
  * ``remap`` only touches strings handed to ``setStyleSheet``. Colours used in
    QPainter / ``QColor(...)`` painting (the SSH terminal, the file-type icons)
    never pass through here, so they keep their original look — the terminal
    stays conventionally dark and readable.

Switching themes takes effect after an application restart (stylesheets are
applied once, at widget construction time).
"""

import re

DARK = "dark"
LIGHT = "light"

# Active theme for the running process. Set by install().
_active = DARK


# --- Light palette anchors (clean, high-contrast — white cards on light grey) #
# Tuned after user feedback that the first warm-ivory pass was too low-contrast
# ("zlane"): surfaces, borders and text were all near the same luminance. Here
# the window is a clear light grey so WHITE cards visibly lift off it, borders
# are distinctly darker, and text is near-black. A faint warmth is kept so it
# isn't clinical, but separation/readability come first (cf. FortiClient white).
WINDOW   = "#e7e8ec"   # app background — light grey (cards pop against it)
ELEV     = "#ffffff"   # cards / panels / tables — white
INPUT    = "#f5f6f8"   # inputs, hover (off-white so its border reads)
ALT      = "#f2f3f6"   # alternate table rows (subtle stripe)
INPUT2   = "#e9ebef"   # pressed / stronger fill
BORDER   = "#c5cad2"   # default border — clearly visible
BORDER2  = "#a7aeb8"   # stronger border / disabled
TXT      = "#15181d"   # primary text — near-black
TXT_HI   = "#0a0c10"   # headings
MUT      = "#525861"   # secondary text (readable, not washed)
DIM      = "#787e88"   # dim / placeholder text

BLUE     = "#1f6feb"   # brand accent (selected item, focus) — kept
BLUE2    = "#0a5fd0"   # links / lighter accents -> darker for white bg
INDIGO   = "#3640c0"   # periwinkle accents
BLUE_BG  = "#dbeafe"   # blue badge background
BLUE_BD  = "#a8c7f0"   # blue badge border

GREEN    = "#157f3a"
GREEN2   = "#0d6b2e"
GREEN_BG = "#dcf3e3"
GREEN_BD = "#a3d6b4"

RED      = "#c5202d"
RED2     = "#9c0f1d"
RED_BG   = "#fbe0e2"
RED_BD   = "#f0b3b8"

AMBER    = "#8a5d00"
AMBER_BG = "#fbeec9"
AMBER_BD = "#e6cb91"

PURPLE   = "#7c3aed"
PURPLE_BG = "#f0e8fd"
PURPLE_BD = "#d2bcf2"


# Map: dark hex (lowercase) -> light hex. Any colour not listed is left as-is.
_MAP = {
    # --- deep backgrounds -> window ---
    "#0a0c10": WINDOW, "#010409": WINDOW, "#0c1018": WINDOW, "#0d1117": WINDOW,
    "#0d1525": WINDOW, "#14161e": WINDOW, "#131920": WINDOW, "#13171c": WINDOW,
    "#111820": WINDOW, "#0c1018": WINDOW,
    # --- elevated surfaces -> cards ---
    "#161b22": ELEV, "#1a1d28": ELEV, "#1c2128": ALT, "#151b23": ELEV,
    "#1c1f26": ELEV, "#1a1e24": ELEV, "#1e1e23": ELEV, "#22242e": ELEV,
    "#1e1e1e": ELEV,
    # --- input / hover / alternate -> input ---
    "#21262d": INPUT, "#2a2d3a": INPUT, "#1e2733": INPUT, "#263040": INPUT,
    "#2d333b": INPUT,
    "#1e2233": INPUT, "#22242e": ELEV,
    # --- borders ---
    "#30363d": BORDER, "#484f58": BORDER2, "#3a3f55": BORDER2, "#5a5f72": BORDER2,
    "#555753": BORDER2,
    # --- primary / bright text ---
    "#c9d1d9": TXT, "#e6edf3": TXT_HI, "#e1e4eb": TXT_HI, "#c8ccd6": TXT,
    "#d3d7cf": TXT, "#eeeeec": TXT_HI,
    # --- muted / dim text ---
    "#8b949e": MUT, "#6e7681": DIM, "#7d8590": MUT, "#8a90a4": MUT,
    # --- brand / link blues ---
    "#1f6feb": BLUE, "#1158c7": BLUE, "#58a6ff": BLUE2, "#388bfd": BLUE2,
    "#79c0ff": BLUE2, "#3a82c8": BLUE2, "#3465a4": BLUE2, "#729fcf": BLUE2,
    "#5a80b0": BLUE2, "#b0c0ff": BLUE2, "#c0d0f0": BLUE2,
    # --- indigo / periwinkle ---
    "#4a5adf": INDIGO, "#6382ff": INDIGO, "#5a6aef": INDIGO, "#3a4070": INDIGO,
    # --- blue badge backgrounds/borders ---
    "#1f4a70": BLUE_BG, "#1a3a5c": BLUE_BG, "#1f3a5f": BLUE_BG, "#1a3050": BLUE_BG,
    "#1a2540": BLUE_BG, "#152540": BLUE_BG, "#1a2040": BLUE_BG, "#1c2240": BLUE_BG,
    "#0f2535": BLUE_BG, "#1a4a70": BLUE_BG, "#1a2a3a": BLUE_BG, "#1a2830": BLUE_BG,
    "#1c2433": BLUE_BG, "#2a4a6a": BLUE_BD, "#2a4070": BLUE_BD,
    # --- greens ---
    "#3fb950": GREEN, "#2ea043": GREEN, "#238636": GREEN2, "#8ae234": GREEN,
    "#a0de4a": GREEN, "#7ee787": GREEN, "#6e9a6e": GREEN, "#8fe4c4": GREEN,
    "#40c090": GREEN, "#2a8a6a": GREEN, "#1abc9c": GREEN, "#4e9a06": GREEN,
    "#2d5a2d": GREEN_BD, "#2d5a1a": GREEN_BD, "#2d4d2d": GREEN_BD,
    "#2a3d2a": GREEN_BD, "#253d1a": GREEN_BD, "#2a4d2a": GREEN_BD,
    "#1a2a1a": GREEN_BG, "#1b3d1b": GREEN_BG, "#0d1f0d": GREEN_BG,
    "#152b15": GREEN_BG, "#1a3a1a": GREEN_BG,
    # --- reds ---
    "#f85149": RED, "#da3633": RED2, "#cc0000": RED2, "#ef2929": RED,
    "#e74c3c": RED, "#c0392b": RED2, "#e05555": RED,
    "#5a2020": RED_BG, "#3d1a1a": RED_BG, "#2a1515": RED_BG, "#2d1117": RED_BG,
    "#3d1f1f": RED_BG, "#5a2d2d": RED_BD,
    # --- ambers / yellows ---
    "#d29922": AMBER, "#e2b340": AMBER, "#fce94f": AMBER, "#c9a227": AMBER,
    "#c4a000": AMBER, "#f0c850": AMBER, "#f0d050": AMBER, "#da8b45": AMBER,
    "#2a2515": AMBER_BG,
    # --- purples (admin) ---
    "#c084fc": PURPLE, "#7c3aed": PURPLE, "#d4a0ff": PURPLE, "#ad7fa8": PURPLE,
    "#75507b": PURPLE, "#6b3fa0": PURPLE_BD, "#3d2550": PURPLE_BD,
    "#5a3a8a": PURPLE_BD, "#2a1a35": PURPLE_BG, "#2a1a40": PURPLE_BG,
}

_HEX_RE = re.compile(r"#[0-9a-fA-F]{6}")


def active() -> str:
    return _active


def paint(dark_hex: str) -> str:
    """Theme-aware colour for QColor/QPainter code paths (which never pass
    through :func:`remap`). Returns the light-mapped hex in light mode, else the
    original. Use this for ``item.setBackground``/``setForeground`` and any
    QColor that must follow the theme (e.g. the table press-flash, SFTP item
    text). Painting that should stay fixed (terminal, icons) must NOT call this.
    """
    if _active != LIGHT:
        return dark_hex
    return _MAP.get(dark_hex.lower(), dark_hex)


def remap(stylesheet: str) -> str:
    """Return the stylesheet with dark hexes swapped for light ones.

    No-op unless the light theme is active. Colours absent from the map are
    left untouched.
    """
    if _active != LIGHT or not stylesheet:
        return stylesheet

    def _sub(m):
        return _MAP.get(m.group(0).lower(), m.group(0))

    return _HEX_RE.sub(_sub, stylesheet)


def light_palette():
    """A warm-ivory QPalette for the Fusion style (native widgets w/o inline CSS)."""
    from PyQt6.QtGui import QPalette, QColor

    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(WINDOW))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(TXT))
    pal.setColor(QPalette.ColorRole.Base, QColor(ELEV))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(INPUT))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(ELEV))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(TXT))
    pal.setColor(QPalette.ColorRole.Text, QColor(TXT))
    pal.setColor(QPalette.ColorRole.Button, QColor(INPUT))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(TXT))
    pal.setColor(QPalette.ColorRole.BrightText, QColor(RED2))
    pal.setColor(QPalette.ColorRole.Link, QColor(BLUE2))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(BLUE))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(DIM))
    pal.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(DIM))
    pal.setColor(QPalette.ColorRole.Mid, QColor(BORDER))
    pal.setColor(QPalette.ColorRole.Dark, QColor(BORDER2))
    return pal


def install(app, theme: str):
    """Activate ``theme`` for the whole application.

    Must be called once, right after QApplication is created and BEFORE any
    window is built. Dark mode is a no-op here (main applies its own palette).
    """
    global _active
    _active = LIGHT if theme == LIGHT else DARK
    if _active != LIGHT:
        return

    from PyQt6.QtWidgets import QWidget

    app.setStyle("Fusion")
    app.setPalette(light_palette())

    # Transparently remap every inline stylesheet to the light palette.
    if not getattr(QWidget, "_hh_theme_patched", False):
        _orig = QWidget.setStyleSheet

        def _patched(self, sheet, _orig=_orig):
            _orig(self, remap(sheet))

        QWidget.setStyleSheet = _patched
        QWidget._hh_theme_patched = True
