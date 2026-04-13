# Copyright © 2026 Sebastian Bąk. All rights reserved.

import hashlib
import json
import math
import os
import queue as _queue
import re
import stat
import sys
import tempfile
import threading
from datetime import datetime

# ──────────────────────────────────────── Log colorizer ──────────────────────

_ANSI_PRESENT   = re.compile(r'\x1b\[')
_STACK_TRACE_RE = re.compile(r'^\s+at\s+[\w$.]+\(')   # Java: "    at pkg.Class.method("
# Shell prompt patterns — used to colorize user-typed commands
_SHELL_PROMPT_RE = re.compile(
    r'^(\s*(?:\[[\w@.\-]+ [^\]]*\][#$%>]'  # [user@host dir]# or $
    r'|[\w@.\-]+:[~\w/\-]*[#$%>]'          # user@host:dir$ or #
    r'|\$|#|>>>|\.\.\.)\s+)'                # bare $ / # / >>> / ...
)

_LOG_RULES = [
    # Errors — red bold
    (re.compile(r'\b(ERROR|FATAL|CRITICAL|FAIL(?:ED)?|EXCEPTION|SEVERE)\b'),
     '\x1b[1;31m'),
    # "Caused by:" (Java stack trace header) — red bold, matched case-sensitively
    (re.compile(r'(Caused by:)'),
     '\x1b[1;31m'),
    # Denial / negative — red (lookbehind (?<!=) avoids =false in Java args)
    (re.compile(r'(?<!=)\b(no|NO|denied|DENIED|disabled|DISABLED|rejected|REJECTED'
                r'|refused|REFUSED|unreachable|UNREACHABLE|inactive|INACTIVE'
                r'|stopped|STOPPED|down|DOWN|dead|DEAD|false|FALSE|off|OFF)\b'),
     '\x1b[0;31m'),
    # Warnings — yellow
    (re.compile(r'\b(WARN(?:ING)?)\b'),
     '\x1b[1;33m'),
    # Info — cyan
    (re.compile(r'\b(INFO(?:RMATION)?)\b'),
     '\x1b[1;36m'),
    # Debug/trace — dim gray
    (re.compile(r'\b(DEBUG|TRACE|VERBOSE|FINE(?:R|ST)?)\b'),
     '\x1b[2;37m'),
    # Success / positive — green
    (re.compile(
        r'\b(OK|ACCEPT(?:ED)?|SUCCESS(?:FUL(?:LY)?)?|SUKCES(?:FUL(?:NIE)?)?'
        r'|DONE|PASS(?:ED)?|STARTED|RUNNING|UP'
        r'|DEPLOYED|REDEPLOYED|REGISTERED)\b'),
     '\x1b[1;32m'),
    # Affirmative — green (lookbehind (?<!=) avoids =true in Java args)
    (re.compile(r'(?<!=)\b(yes|YES|enabled|ENABLED|active|ACTIVE|true|TRUE'
                r'|online|ONLINE|alive|ALIVE|loaded|LOADED)\b'),
     '\x1b[0;32m'),
    # Maven/Gradle build result — override with specific color per word
    (re.compile(r'\b(BUILD SUCCESS(?:FUL)?)\b'),
     '\x1b[1;32m'),
    (re.compile(r'\b(BUILD FAIL(?:URE|ED)?)\b'),
     '\x1b[1;31m'),
    # Docker image/container lifecycle
    (re.compile(r'\b(Pulling|Pulled|Pushing|Pushed|Building|Built|Created|Removed)\b'),
     '\x1b[0;36m'),
    # IPv4 with optional port — bright cyan IP, bright magenta port
    # (uses special callback in _colorize_log via _IPV4_PORT_TAG marker)
    (re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?\b'),
     '_IPV4_PORT'),
    # IPv6 addresses (4+ groups to avoid matching HH:MM:SS timestamps) — bright cyan
    (re.compile(r'(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}(?::(?:\d{1,3}\.){3}\d{1,3})?'),
     '\x1b[0;96m'),
    # MAC addresses — dim cyan
    (re.compile(r'\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b'),
     '\x1b[0;36m'),
    # Dates: 2024-01-15, 15/01/2024 — dim white
    (re.compile(r'\b\d{4}[-/]\d{2}[-/]\d{2}\b|\b\d{2}[-/]\d{2}[-/]\d{4}\b'),
     '\x1b[0;37m'),
    # Email-like addresses (require dot in domain) — bright green
    # Avoids shell prompts like [root@Jboss0 ~]# where there's no dot
    (re.compile(r'\b[\w.-]+@[\w-]+\.[\w.-]+\b'),
     '\x1b[0;92m'),
    # HTTP methods — bright yellow
    (re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b'),
     '\x1b[1;93m'),
    # HTTP status codes: 2xx green, 4xx yellow, 5xx red
    # (?<![.,:\d]) prevents matching inside IPs (dots), timestamps (commas/colons),
    # and longer numbers; (?![.\d]) prevents matching IP-leading octets.
    (re.compile(r'(?<![.,:\d])\b(2\d{2})\b(?![.\d])'), '\x1b[0;32m'),
    (re.compile(r'(?<![.,:\d])\b(4\d{2})\b(?![.\d])'), '\x1b[0;33m'),
    (re.compile(r'(?<![.,:\d])\b(5\d{2})\b(?![.\d])'), '\x1b[0;31m'),
]

def _ipv4_port_sub(m):
    """Color IPv4 in cyan and optional :port in magenta."""
    ip = m.group(1)
    port = m.group(2)
    result = f'\x1b[0;96m{ip}\x1b[0m'
    if port:
        result += f'\x1b[0;95m:{port}\x1b[0m'
    return result

_PLACEHOLDER_RE = re.compile(r'\x00(\d+)\x00')

def _colorize_log(text: str) -> str:
    """Add ANSI keyword highlighting to plain-text log lines.

    Uses placeholder markers (\x00idx\x00) so that text already colored by an
    earlier rule is invisible to later regexes — prevents e.g. HTTP-status
    rules from re-coloring octets inside an already-highlighted IPv4 address.
    """
    lines = text.split('\n')
    for i, line in enumerate(lines):
        if _ANSI_PRESENT.search(line):
            continue   # already colored (e.g. shell prompt sequences)
        # Java stack trace lines get the whole line dimmed
        if _STACK_TRACE_RE.match(line):
            lines[i] = f'\x1b[2;37m{line}\x1b[0m'
            continue
        # Shell prompt line — color the command part bright white
        prompt_m = _SHELL_PROMPT_RE.match(line)
        if prompt_m:
            prompt_part = prompt_m.group(1)
            cmd_part = line[prompt_m.end():]
            if cmd_part.strip():
                lines[i] = f'{prompt_part}\x1b[1;97m{cmd_part}\x1b[0m'
                continue
        # Stash: list of colored fragments; replaced by \x00idx\x00 in `line`
        stash: list[str] = []
        def _stash(fragment: str) -> str:
            idx = len(stash)
            stash.append(fragment)
            return f'\x00{idx}\x00'
        for pat, color in _LOG_RULES:
            if color == '_IPV4_PORT':
                line = pat.sub(lambda m: _stash(_ipv4_port_sub(m)), line)
            else:
                line = pat.sub(
                    lambda m, c=color: _stash(f'{c}{m.group()}\x1b[0m'), line)
        # Restore stashed fragments
        if stash:
            line = _PLACEHOLDER_RE.sub(lambda m: stash[int(m.group(1))], line)
        # Always append reset on plain-text lines so pyte never carries
        # a stale foreground color across visual line-wrap boundaries.
        line += '\x1b[0m'
        lines[i] = line
    return '\n'.join(lines)




from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QSplitter, QWidget,
    QPushButton, QLabel, QApplication,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QFileDialog, QProgressBar, QMenu, QInputDialog, QMessageBox,
    QLineEdit, QTabWidget, QStackedWidget, QScrollArea,
    QCheckBox, QGroupBox, QGridLayout, QFrame, QFormLayout, QSizePolicy,
    QScrollBar, QToolButton,
)
from PyQt6.QtCore import Qt, QThread, QTimer, QSize, QEvent, pyqtSignal, QMimeData, QUrl
from PyQt6.QtGui import (
    QFont, QFontInfo, QFontMetricsF, QColor, QPainter, QKeySequence,
    QDesktopServices, QIcon, QPixmap, QPen, QBrush, QPainterPath,
)

from ui.rdp import connect_rdp as _connect_rdp

try:
    import pyte
    _PYTE_OK = True

    class _TermScreen(pyte.HistoryScreen):
        """HistoryScreen that saves visible content to scrollback before full-screen erases.

        This ensures that running full-screen apps (top, less, vim) always leaves
        their pre-run content accessible via scrollback, even if no lines had
        naturally scrolled off the top yet.
        """
        _ALT_SCREEN = 1049          # DECSET 1049: alternate screen buffer
        _ALT_SCREEN_FLAG = 1049 << 5  # pyte stores private modes shifted by 5

        # Track which rows are continuations of the previous row (soft-wrap).
        # A row number in this set means it continues the line from the row above.
        _soft_wrapped: set
        _in_draw: bool = False

        def __init__(self, *args, **kwargs):
            self._soft_wrapped = set()
            super().__init__(*args, **kwargs)

        def reset(self):
            super().reset()
            self._soft_wrapped = set()
            self._in_draw = False

        def draw(self, *args, **kwargs):
            self._in_draw = True
            try:
                super().draw(*args, **kwargs)
            finally:
                self._in_draw = False

        def index(self):
            top, bottom = self.margins or (0, self.lines - 1)
            will_scroll = self.cursor.y == bottom
            super().index()
            if will_scroll:
                # Content in scroll region shifted up by 1 row.
                new_set = set()
                for r in self._soft_wrapped:
                    if r > top and r <= bottom:
                        new_set.add(r - 1)
                    elif r < top or r > bottom:
                        new_set.add(r)
                self._soft_wrapped = new_set
            if self._in_draw:
                self._soft_wrapped.add(self.cursor.y)
            else:
                self._soft_wrapped.discard(self.cursor.y)

        def _push_visible_to_history(self):
            """Append each non-empty visible row to history.top (oldest→newest order)."""
            for y in range(self.lines):
                try:
                    row = self.buffer[y]
                    if any(getattr(c, 'data', ' ') not in (' ', '')
                           for c in row.values()):
                        self.history.top.append(dict(row))
                except Exception:
                    pass

        def resize(self, lines=None, columns=None):
            """Resize with text reflow — narrowing wraps long lines,
            widening unwraps them back."""
            import collections as _c
            lines   = lines   or self.lines
            columns = columns or self.columns
            if lines == self.lines and columns == self.columns:
                return

            old_cols = self.columns

            # Reflow when column count changes (skip alternate screen —
            # full-screen apps handle their own resize via SIGWINCH).
            if columns != old_cols and self._ALT_SCREEN_FLAG not in self.mode:
                self._reflow(old_cols, columns, lines)
            else:
                # Row-only change (or alternate screen).
                if lines < self.lines:
                    n_scroll = max(0, self.cursor.y - (lines - 1))
                    if n_scroll > 0:
                        for y in range(n_scroll):
                            self.history.top.append(self.buffer[y])
                        for y in range(self.lines - n_scroll):
                            self.buffer[y] = self.buffer[y + n_scroll]
                        for y in range(self.lines - n_scroll, self.lines):
                            self.buffer.pop(y, None)
                        self.cursor.y -= n_scroll
                    self.cursor.y = min(self.cursor.y, lines - 1)
                    self.cursor.x = min(self.cursor.x, columns - 1)
                self.lines   = lines
                self.columns = columns

            self.dirty.update(range(self.lines))
            self.set_margins()

        def _reflow(self, old_cols, new_cols, new_lines):
            """Reflow buffer content when column width changes."""
            import collections as _c
            dc = self.default_char

            # ── Step 1: extract logical lines ─────────────────────────
            logical_lines = []   # list[list[Char]]
            cur_chars     = []
            cursor_ll     = 0    # which logical line the cursor is on
            cursor_co     = 0    # char offset within that logical line

            for y in range(self.lines):
                row = self.buffer[y]

                # Track cursor
                if y == self.cursor.y:
                    cursor_ll = len(logical_lines)
                    cursor_co = len(cur_chars) + self.cursor.x

                # Rightmost non-space column (may exceed old_cols if chars
                # were preserved from a previous wider layout).
                content_max = -1
                for x in row.keys():
                    if isinstance(x, int) and row[x].data not in (' ', ''):
                        if x > content_max:
                            content_max = x

                # Collect characters
                for x in range(content_max + 1):
                    cur_chars.append(row.get(x, dc))

                # Check if the NEXT row is a continuation (soft-wrapped
                # from this row).  _soft_wrapped tracks actual wraps set by
                # draw(), so we no longer rely on the "row fills to edge"
                # heuristic which wrongly joins long log lines.
                if y < self.lines - 1 and (y + 1) in self._soft_wrapped:
                    continue   # continuation of same logical line

                logical_lines.append(cur_chars)
                cur_chars = []

            if cur_chars:
                logical_lines.append(cur_chars)

            # Trim trailing empty logical lines (keep up to cursor row)
            last_nonempty = cursor_ll
            for i in range(len(logical_lines) - 1, -1, -1):
                if logical_lines[i]:
                    last_nonempty = max(last_nonempty, i)
                    break
            logical_lines = logical_lines[:last_nonempty + 1]

            # ── Step 2: re-wrap at new width ──────────────────────────
            new_rows = []        # list[dict[int, Char]]
            new_sw   = set()     # soft-wrap flags for new layout
            nc_y = nc_x = 0
            cursor_placed = False

            for li, chars in enumerate(logical_lines):
                if not chars:
                    new_rows.append({})
                    if li == cursor_ll:
                        nc_y = len(new_rows) - 1
                        nc_x = min(cursor_co, new_cols - 1)
                        cursor_placed = True
                    continue

                first_chunk = True
                for i in range(0, len(chars), new_cols):
                    row = {}
                    for j, ch in enumerate(chars[i:i + new_cols]):
                        row[j] = ch
                    if not first_chunk:
                        new_sw.add(len(new_rows))
                    new_rows.append(row)
                    first_chunk = False

                    if li == cursor_ll and i <= cursor_co < i + new_cols:
                        nc_y = len(new_rows) - 1
                        nc_x = cursor_co - i
                        cursor_placed = True

                # Cursor at end of logical line (e.g. after typing exactly
                # N chars that filled a row — cursor wrapped to next row).
                if li == cursor_ll and cursor_co >= len(chars) and not cursor_placed:
                    nc_y = len(new_rows)
                    nc_x = 0

            # ── Step 3: push overflow to history ──────────────────────
            overflow = max(0, len(new_rows) - new_lines)
            if overflow:
                for y in range(overflow):
                    self.history.top.append(new_rows[y])
                new_rows = new_rows[overflow:]
                nc_y = max(0, nc_y - overflow)
                new_sw = {r - overflow for r in new_sw if r >= overflow}

            # ── Step 4: rebuild buffer ────────────────────────────────
            new_buf = _c.defaultdict(
                lambda: _c.defaultdict(lambda: dc))
            for y, row in enumerate(new_rows):
                for x, ch in row.items():
                    new_buf[y][x] = ch
            self.buffer = new_buf
            self._soft_wrapped = new_sw

            self.lines   = new_lines
            self.columns = new_cols
            self.cursor.y = min(nc_y, new_lines - 1)
            self.cursor.x = min(nc_x, new_cols - 1)

        def erase_in_display(self, how=0, *args, **kwargs):
            if how == 3:
                # CSI 3 J — explicit "erase scrollback buffer" command.
                self.history.top.clear()
                self.history.bottom.clear()
                self._soft_wrapped.clear()
                return
            if how == 2:
                if self._ALT_SCREEN_FLAG not in self.mode:
                    # CSI 2 J on main screen — save visible content to
                    # scrollback before clearing display.  Do NOT wipe
                    # existing history here; only CSI 3 J should do that.
                    # Programs like top/vim use alt screen and are unaffected.
                    if not getattr(self, '_suppress_history_push', False):
                        self._push_visible_to_history()
                    self._suppress_history_push = False
                super().erase_in_display(how, *args, **kwargs)
                if self._ALT_SCREEN_FLAG not in self.mode:
                    self._soft_wrapped.clear()
                return
            super().erase_in_display(how, *args, **kwargs)

        def set_mode(self, *modes, **kwargs):
            # Entering alternate screen (\x1b[?1049h) → save main screen to history.
            if kwargs.get("private") and self._ALT_SCREEN in modes:
                if self._ALT_SCREEN_FLAG not in self.mode:
                    self._push_visible_to_history()
            super().set_mode(*modes, **kwargs)

except ImportError:
    _PYTE_OK = False

try:
    import paramiko
    _PARAMIKO_OK = True
except ImportError:
    _PARAMIKO_OK = False


# ──────────────────────────────────────── Colour helpers ─────────────────────

_PALETTE_16 = [
    '#1e1e1e', '#cc0000', '#4e9a06', '#c4a000',
    '#3465a4', '#75507b', '#06989a', '#d3d7cf',
    '#555753', '#ef2929', '#8ae234', '#fce94f',
    '#729fcf', '#ad7fa8', '#34e2e2', '#eeeeec',
]
_PYTE_COLORS = {
    'black':          _PALETTE_16[0],  'red':            _PALETTE_16[1],
    'green':          _PALETTE_16[2],  'brown':          _PALETTE_16[3],
    'blue':           _PALETTE_16[4],  'magenta':        _PALETTE_16[5],
    'cyan':           _PALETTE_16[6],  'white':          _PALETTE_16[7],
    'bright black':   _PALETTE_16[8],  'bright red':     _PALETTE_16[9],
    'bright green':   _PALETTE_16[10], 'bright brown':   _PALETTE_16[11],
    'bright blue':    _PALETTE_16[12], 'bright magenta': _PALETTE_16[13],
    'bright cyan':    _PALETTE_16[14], 'bright white':   _PALETTE_16[15],
    # pyte >=0.8 uses no-space names
    'brightblack':    _PALETTE_16[8],  'brightred':      _PALETTE_16[9],
    'brightgreen':    _PALETTE_16[10], 'brightbrown':    _PALETTE_16[11],
    'brightblue':     _PALETTE_16[12], 'brightmagenta':  _PALETTE_16[13],
    'brightcyan':     _PALETTE_16[14], 'brightwhite':    _PALETTE_16[15],
}
_DEFAULT_FG = '#c9d1d9'
_DEFAULT_BG = '#0d1117'
_FLAG_FG    = '#8fe4c4'  # mint — highlight for CLI flags (-ef, --foo)


def _fmt_size(n: int) -> str:
    if n < 1024:          return f"{n} B"
    if n < 1_048_576:     return f"{n/1024:.1f} KB"
    if n < 1_073_741_824: return f"{n/1_048_576:.1f} MB"
    return f"{n/1_073_741_824:.1f} GB"


def _256_to_hex(n: int) -> str:
    if n < 16:
        return _PALETTE_16[n]
    if n < 232:
        n -= 16
        b, g, r = n % 6, (n // 6) % 6, n // 36
        v = lambda x: 0 if x == 0 else 55 + x * 40
        return f'#{v(r):02x}{v(g):02x}{v(b):02x}'
    g = 8 + (n - 232) * 10
    return f'#{g:02x}{g:02x}{g:02x}'


# ──────────────────────────────────────── Terminal widget ─────────────────────

class TerminalWidget(QWidget):
    """VT100 terminal backed by pyte, rendered cell-by-cell with QPainter."""

    char_input     = pyqtSignal(bytes)
    resize_pty     = pyqtSignal(int, int)   # cols, rows → SSH PTY resize
    scroll_changed = pyqtSignal(int, int)   # offset, max_offset

    _SCROLLBACK = 50_000   # ~200 MB worst-case per session; freed on tab close

    _CTRL_MAP = {
        Qt.Key.Key_At:            b'\x00',
        Qt.Key.Key_A:             b'\x01', Qt.Key.Key_B: b'\x02',
        Qt.Key.Key_C:             b'\x03', Qt.Key.Key_D: b'\x04',
        Qt.Key.Key_E:             b'\x05', Qt.Key.Key_F: b'\x06',
        Qt.Key.Key_G:             b'\x07', Qt.Key.Key_H: b'\x08',
        Qt.Key.Key_I:             b'\x09', Qt.Key.Key_J: b'\x0a',
        Qt.Key.Key_K:             b'\x0b', Qt.Key.Key_L: b'\x0c',
        Qt.Key.Key_M:             b'\x0d', Qt.Key.Key_N: b'\x0e',
        Qt.Key.Key_O:             b'\x0f', Qt.Key.Key_P: b'\x10',
        Qt.Key.Key_Q:             b'\x11', Qt.Key.Key_R: b'\x12',
        Qt.Key.Key_S:             b'\x13', Qt.Key.Key_T: b'\x14',
        Qt.Key.Key_U:             b'\x15', Qt.Key.Key_V: b'\x16',
        Qt.Key.Key_W:             b'\x17', Qt.Key.Key_X: b'\x18',
        Qt.Key.Key_Y:             b'\x19', Qt.Key.Key_Z: b'\x1a',
        Qt.Key.Key_BracketLeft:   b'\x1b', Qt.Key.Key_Backslash: b'\x1c',
        Qt.Key.Key_BracketRight:  b'\x1d',
    }
    _SPECIAL_MAP = {
        Qt.Key.Key_Return:    b'\r',
        Qt.Key.Key_Enter:     b'\r',
        Qt.Key.Key_Backspace: b'\x7f',
        Qt.Key.Key_Delete:    b'\x1b[3~',
        Qt.Key.Key_Tab:       b'\t',
        Qt.Key.Key_Escape:    b'\x1b',
        Qt.Key.Key_Up:        b'\x1b[A',
        Qt.Key.Key_Down:      b'\x1b[B',
        Qt.Key.Key_Right:     b'\x1b[C',
        Qt.Key.Key_Left:      b'\x1b[D',
        Qt.Key.Key_Home:      b'\x1b[H',
        Qt.Key.Key_End:       b'\x1b[F',
        Qt.Key.Key_PageUp:    b'\x1b[5~',
        Qt.Key.Key_PageDown:  b'\x1b[6~',
        Qt.Key.Key_F1:  b'\x1bOP',   Qt.Key.Key_F2:  b'\x1bOQ',
        Qt.Key.Key_F3:  b'\x1bOR',   Qt.Key.Key_F4:  b'\x1bOS',
        Qt.Key.Key_F5:  b'\x1b[15~', Qt.Key.Key_F6:  b'\x1b[17~',
        Qt.Key.Key_F7:  b'\x1b[18~', Qt.Key.Key_F8:  b'\x1b[19~',
        Qt.Key.Key_F9:  b'\x1b[20~', Qt.Key.Key_F10: b'\x1b[21~',
        Qt.Key.Key_F11: b'\x1b[23~', Qt.Key.Key_F12: b'\x1b[24~',
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAttribute(Qt.WidgetAttribute.WA_InputMethodEnabled, False)
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent, True)
        self.setCursor(Qt.CursorShape.IBeamCursor)

        font = QFont('Cascadia Code', 11)
        if not QFontInfo(font).exactMatch():
            font = QFont('Consolas', 11)
        font.setFixedPitch(True)
        self._font      = font
        self._font_bold = QFont(font)
        self._font_bold.setBold(True)

        fm = QFontMetricsF(self._font)
        self._cw  = fm.horizontalAdvance('M')
        self._ch  = fm.height()
        self._asc = fm.ascent()

        # Hard lower bound: 80 cols × 24 rows — prevents row loss on aggressive resize
        self.setMinimumSize(int(80 * self._cw), int(24 * self._ch))

        self._cols = 220
        self._rows = 50
        self._screen = _TermScreen(self._cols, self._rows, history=self._SCROLLBACK) if _PYTE_OK else None
        self._stream = pyte.Stream(self._screen) if _PYTE_OK else None

        self._cur_vis = True
        self._blink   = QTimer(self)
        self._blink.timeout.connect(self._toggle_cursor)
        self._blink.start(530)

        # Debounced PTY resize — fires 150 ms after last resize event
        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.setInterval(150)
        self._resize_timer.timeout.connect(self._emit_resize)
        self._pending_resize: tuple | None = None

        # Scrollback
        self._scroll_offset = 0   # 0 = at bottom; positive = scrolled up N lines
        self._prev_hist_len = 0   # track history length for scroll-lock
        # list() snapshot of history.top — rebuilt once per scroll gesture so
        # deque[idx] (O(n)) is replaced with list[idx] (O(1)) during rendering.
        self._hist_cache: list | None = None

        # Mouse selection — coordinates in absolute row space
        # (col, arow) where arow = hist_index for history, hist_len+buf_row for buffer
        self._sel_start: tuple | None = None
        self._sel_end:   tuple | None = None
        self._selecting  = False
        self._sel_mouse_col = 0

        # Auto-scroll timer for drag-selection beyond visible area
        self._sel_scroll_timer = QTimer(self)
        self._sel_scroll_timer.setInterval(50)
        self._sel_scroll_timer.timeout.connect(self._sel_auto_scroll)
        self._sel_scroll_dir = 0  # -1 = up, 1 = down

        # Coalesce timer — batches rapid feed() calls into a single repaint
        self._coalesce_timer = QTimer(self)
        self._coalesce_timer.setSingleShot(True)
        self._coalesce_timer.setInterval(8)   # ~120 fps cap
        self._coalesce_timer.timeout.connect(self._flush_pending)
        self._pending_data: list[str] = []

    # ── Public API ────────────────────────────────────────────────────────

    def feed(self, data: str):
        self._pending_data.append(data)
        if not self._coalesce_timer.isActive():
            self._coalesce_timer.start()

    def _flush_pending(self):
        """Process all buffered data in one batch and repaint once."""
        if not self._pending_data:
            return
        if self._stream:
            for chunk in self._pending_data:
                try:
                    self._stream.feed(chunk)
                except Exception as _e:
                    import traceback; traceback.print_exc()
        self._pending_data.clear()
        # Only auto-scroll to bottom if user is already at the bottom.
        # If user scrolled up to read logs, keep their position stable.
        if self._scroll_offset == 0:
            pass  # already at bottom, stay there
        else:
            # User is scrolled up — keep their view position by compensating
            # for new lines that pushed content into history.
            new_hist_len = len(self._screen.history.top) if self._screen else 0
            added = new_hist_len - getattr(self, '_prev_hist_len', new_hist_len)
            if added > 0:
                self._scroll_offset += added
        self._prev_hist_len = len(self._screen.history.top) if self._screen else 0
        self._hist_cache    = None  # new rows may have scrolled into history
        self._cur_vis = True
        self._blink.start(530)
        self.update()
        self._emit_scroll()

    def clear(self):
        self._pending_data.clear()
        if self._screen:
            self._screen.reset()
            self._screen.history.top.clear()
            self._screen.history.bottom.clear()
            # Suppress the next erase_in_display from re-pushing content
            # to history (server responds to Ctrl+L with \x1b[2J).
            self._screen._suppress_history_push = True
        self._scroll_offset = 0
        self._hist_cache    = None
        self._sel_start = self._sel_end = None
        self.update()
        self._emit_scroll()

    def _emit_scroll(self):
        """Emit current scroll position so the scrollbar can update."""
        if self._screen:
            max_off = len(self._screen.history.top)
            self.scroll_changed.emit(self._scroll_offset, max_off)

    def terminal_size(self):
        """Return current terminal dimensions from actual widget size (always live)."""
        cols = max(80, int(self.width()  / self._cw))
        rows = max(24, int(self.height() / self._ch))
        return cols, rows

    # ── Internal helpers ──────────────────────────────────────────────────

    def _toggle_cursor(self):
        self._cur_vis = not self._cur_vis
        self.update()

    def _color(self, c: str, is_fg: bool) -> str:
        if not c or c == 'default':
            return _DEFAULT_FG if is_fg else _DEFAULT_BG
        named = _PYTE_COLORS.get(c)
        if named:
            return named
        if len(c) == 6:     # pyte 24-bit: 'rrggbb' hex
            return '#' + c
        if len(c) == 3:     # pyte 256-colour: '000'–'255' decimal
            try:
                return _256_to_hex(int(c))
            except ValueError:
                pass
        return _DEFAULT_FG if is_fg else _DEFAULT_BG

    def _cell_at_pos(self, pos) -> tuple:
        """Convert pixel position to (col, vrow) in visual space."""
        col = max(0, min(int(pos.x() / self._cw), self._cols - 1))
        row = max(0, min(int(pos.y() / self._ch), self._rows - 1))
        return col, row

    def _cell_at_pos_unclamped(self, pos) -> tuple:
        """Like _cell_at_pos but row is not clamped (can be <0 or >=rows)."""
        col = max(0, min(int(pos.x() / self._cw), self._cols - 1))
        row = int(pos.y() / self._ch)
        return col, row

    def _vrow_to_arow(self, vrow: int) -> int:
        """Convert visual row to absolute row (history-based)."""
        hist_len = len(self._screen.history.top) if self._screen else 0
        return hist_len - self._scroll_offset + vrow

    def _arow_to_vrow(self, arow: int) -> int:
        """Convert absolute row to visual row."""
        hist_len = len(self._screen.history.top) if self._screen else 0
        return arow - hist_len + self._scroll_offset

    def _get_row_abs(self, arow: int):
        """Return pyte row for absolute row index."""
        if not self._screen:
            return {}
        if self._hist_cache is None:
            self._hist_cache = list(self._screen.history.top)
        hist = self._hist_cache
        hist_len = len(hist)
        if arow < 0:
            return {}
        if arow < hist_len:
            return hist[arow]
        buf_row = arow - hist_len
        if 0 <= buf_row < self._rows:
            return self._screen.buffer[buf_row]
        return {}

    def _get_row(self, vrow: int):
        """Return pyte row for visual row index (0 = top of visible area).

        History is accessed via a list() snapshot so that deque[idx] (O(n))
        is replaced with list[idx] (O(1)) — critical for large scrollback.
        The cache is built once per scroll gesture and invalidated by feed().
        """
        if not self._screen:
            return {}
        offset = self._scroll_offset
        if offset > 0:
            if self._hist_cache is None:
                self._hist_cache = list(self._screen.history.top)
            hist     = self._hist_cache
            hist_len = len(hist)
            if vrow < offset:
                idx = hist_len - offset + vrow
                if 0 <= idx < hist_len:
                    return hist[idx]
                return {}
            buf_row = vrow - offset
            if 0 <= buf_row < self._rows:
                return self._screen.buffer[buf_row]
            return {}
        return self._screen.buffer[vrow]

    def _in_selection(self, x: int, vrow: int) -> bool:
        if not self._sel_start or not self._sel_end:
            return False
        arow = self._vrow_to_arow(vrow)
        (sc, sr), (ec, er) = self._sel_start, self._sel_end
        if (sr, sc) > (er, ec):
            sc, sr, ec, er = ec, er, sc, sr
        if arow < sr or arow > er:
            return False
        if sr == er:
            return sc <= x <= ec
        if arow == sr:
            return x >= sc
        if arow == er:
            return x <= ec
        return True

    def _selected_text(self) -> str:
        if not self._sel_start or not self._sel_end:
            return ''
        (sc, sr), (ec, er) = self._sel_start, self._sel_end
        if (sr, sc) > (er, ec):
            sc, sr, ec, er = ec, er, sc, sr
        lines = []
        for arow in range(sr, er + 1):
            row_data = self._get_row_abs(arow)
            c0 = sc if arow == sr else 0
            c1 = ec if arow == er else self._cols - 1
            chars = []
            for x in range(c0, c1 + 1):
                try:
                    cell = row_data[x]
                    chars.append(cell.data or ' ')
                except (KeyError, AttributeError, TypeError):
                    chars.append(' ')
            lines.append(''.join(chars).rstrip())
        return '\n'.join(lines)

    # ── Painting ──────────────────────────────────────────────────────────

    def _flag_columns(self, row) -> set[int]:
        """Return set of column indices belonging to CLI-flag tokens on this row.

        Recognizes ' -x', ' -abc', ' --foo' — dash preceded by whitespace/start,
        followed by a letter (avoids hitting negative numbers or stdout text
        with hyphens inside words). Stops at space/pipe/redirect/quote chars.
        """
        cols: set[int] = set()
        cw = self._cols
        # Build a plain string view with a simple char accessor
        def _ch(i: int) -> str:
            try:
                c = row[i].data
                return c if c else ' '
            except (KeyError, AttributeError, TypeError):
                return ' '
        _BOUND = set(" \t|;&<>\"'`")
        i = 0
        while i < cw:
            if _ch(i) == '-':
                prev = _ch(i - 1) if i > 0 else ' '
                if prev in _BOUND:
                    nxt = _ch(i + 1)
                    is_flag = nxt.isalpha() or (nxt == '-' and _ch(i + 2).isalpha())
                    if is_flag:
                        j = i
                        while j < cw and _ch(j) not in _BOUND:
                            cols.add(j)
                            j += 1
                        i = j
                        continue
            i += 1
        return cols

    def paintEvent(self, event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(_DEFAULT_BG))

        if not self._screen:
            p.setPen(QColor('#e05555'))
            p.drawText(8, 20, 'Brak biblioteki pyte. Zainstaluj: pip install pyte')
            return

        cx      = self._screen.cursor.x
        cy      = self._screen.cursor.y
        focused = self.hasFocus()
        cw      = self._cw
        lh      = self._ch
        asc     = self._asc
        offset  = self._scroll_offset
        int_cw  = int(cw) + 1
        int_lh  = int(lh) + 1

        # Pre-create frequently used QColor objects
        sel_bg = QColor('#5a80b0')
        sel_fg_c = QColor('#ffffff')
        default_fg_c = QColor(_DEFAULT_FG)

        # Cache QColor objects to avoid re-creating them every cell
        _color_cache: dict[str, QColor] = {}
        def _qcolor(hex_str: str) -> QColor:
            c = _color_cache.get(hex_str)
            if c is None:
                c = QColor(hex_str)
                _color_cache[hex_str] = c
            return c

        has_sel = self._sel_start is not None and self._sel_end is not None

        # Only repaint rows/cols within the dirty/exposed region
        clip = event.rect()
        y_start = max(0, int(clip.top() / lh))
        y_end = min(self._rows, int(clip.bottom() / lh) + 1)
        x_start = max(0, int(clip.left() / cw))
        x_end = min(self._cols, int(clip.right() / cw) + 2)

        for y in range(y_start, y_end):
            row = self._get_row(y)
            py  = int(y * lh)
            is_cursor_row = (offset == 0 and y == cy and focused and self._cur_vis)

            flag_cols = self._flag_columns(row) if row else None

            if not row:
                # Draw cursor on empty row if needed
                if is_cursor_row:
                    rx = int(cx * cw)
                    p.fillRect(rx, py, int_cw, int_lh, default_fg_c)
                continue

            # Batch: collect runs of chars with same style to draw together
            prev_fg = None
            prev_bold = None
            run_chars = []
            run_x_start = 0

            for x in range(x_start, x_end):
                try:
                    cell = row[x]
                    char = cell.data or ' '
                    fg   = self._color(cell.fg, True)
                    bg   = self._color(cell.bg, False)
                    if cell.reverse:
                        fg, bg = bg, fg
                    bold = cell.bold
                except (KeyError, AttributeError, TypeError):
                    char, fg, bg, bold = ' ', _DEFAULT_FG, _DEFAULT_BG, False

                # Flag highlighting (only when cell hasn't been colored by program)
                if flag_cols and x in flag_cols and fg == _DEFAULT_FG and not cell.reverse:
                    fg = _FLAG_FG

                rx     = int(x * cw)
                sel    = has_sel and self._in_selection(x, y)
                is_cur = (is_cursor_row and x == cx)

                # Determine actual fg/bg for this cell
                if sel:
                    p.fillRect(rx, py, int_cw, int_lh, sel_bg)
                    draw_fg = '#ffffff'
                elif is_cur:
                    p.fillRect(rx, py, int_cw, int_lh, _qcolor(fg))
                    draw_fg = bg
                elif bg != _DEFAULT_BG:
                    p.fillRect(rx, py, int_cw, int_lh, _qcolor(bg))
                    draw_fg = fg
                else:
                    draw_fg = fg

                # Check if we can extend the current text run
                if draw_fg == prev_fg and bold == prev_bold and not sel and not is_cur:
                    run_chars.append(char)
                else:
                    # Flush previous run
                    if run_chars:
                        text = ''.join(run_chars)
                        if text.rstrip():
                            p.drawText(int(run_x_start * cw), int(py + asc), text)
                    # Start new run
                    if bold != prev_bold:
                        p.setFont(self._font_bold if bold else self._font)
                        prev_bold = bold
                    if draw_fg != prev_fg:
                        p.setPen(_qcolor(draw_fg))
                        prev_fg = draw_fg
                    run_x_start = x
                    run_chars = [char]

            # Flush last run
            if run_chars:
                text = ''.join(run_chars)
                if text.rstrip():
                    p.drawText(int(run_x_start * cw), int(py + asc), text)


    # ── Resize ────────────────────────────────────────────────────────────

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.width() < 20 or self.height() < 20:
            return   # not yet laid out — ignore spurious resize events
        new_cols = max(80, int(self.width()  / self._cw))
        new_rows = max(24, int(self.height() / self._ch))
        if new_cols != self._cols or new_rows != self._rows:
            # Do NOT touch pyte buffer here — resizing it on every drag pixel
            # causes it to pull scrollback history and produce phantom lines.
            # Schedule both the pyte resize and the PTY SIGWINCH for after
            # the drag settles (debounce 150 ms).
            self._pending_resize = (new_cols, new_rows)
            self._resize_timer.start()

    def _emit_resize(self):
        if self._pending_resize:
            new_cols, new_rows = self._pending_resize
            if self._screen:
                self._screen.resize(new_rows, new_cols)
            self._cols = new_cols
            self._rows = new_rows
            self._scroll_offset = 0
            self._hist_cache    = None
            self._pending_resize = None
            self.resize_pty.emit(new_cols, new_rows)
            self._emit_scroll()
            self.update()

    def sizeHint(self):
        return QSize(int(self._cols * self._cw), int(self._rows * self._ch))

    # ── Qt event override — capture Tab before focus system ───────────────

    def event(self, e):
        if e.type() == QEvent.Type.KeyPress:
            if e.key() in (Qt.Key.Key_Tab, Qt.Key.Key_Backtab):
                self.keyPressEvent(e)
                return True
        return super().event(e)

    # ── Input ─────────────────────────────────────────────────────────────

    def keyPressEvent(self, event):
        key   = event.key()
        mods  = event.modifiers()
        ctrl  = bool(mods & Qt.KeyboardModifier.ControlModifier)
        shift = bool(mods & Qt.KeyboardModifier.ShiftModifier)

        # Ctrl+Shift+C: copy selection to clipboard
        if ctrl and shift and key == Qt.Key.Key_C:
            text = self._selected_text()
            if text.strip():
                QApplication.clipboard().setText(text)
            event.accept()
            return

        # Any key other than copy → clear selection
        if self._sel_start is not None or self._sel_end is not None:
            self._sel_start = self._sel_end = None
            self.update()

        # Ctrl+Shift+V: paste from clipboard
        if ctrl and shift and key == Qt.Key.Key_V:
            text = QApplication.clipboard().text()
            if text:
                self._scroll_offset = 0
                self.char_input.emit(text.encode('utf-8'))
            event.accept()
            return

        # Any input: return to bottom of scrollback
        if self._scroll_offset:
            self._scroll_offset = 0
            self.update()

        if ctrl and not shift:
            data = self._CTRL_MAP.get(key)
        else:
            data = self._SPECIAL_MAP.get(key)
            if data is None and event.text():
                data = event.text().encode('utf-8')

        if data:
            self._cur_vis = True
            self._blink.start(530)
            self.char_input.emit(data)
        event.accept()

    # ── Mouse ─────────────────────────────────────────────────────────────

    def mousePressEvent(self, event):
        self.setFocus()
        if event.button() == Qt.MouseButton.LeftButton:
            col, row = self._cell_at_pos(event.position())
            arow = self._vrow_to_arow(row)
            self._sel_start = (col, arow)
            self._sel_end   = (col, arow)
            self._sel_mouse_col = col
            self._selecting = True
            self.update()
        elif event.button() == Qt.MouseButton.RightButton:
            # Paste from clipboard (PuTTY style)
            text = QApplication.clipboard().text()
            if text:
                self._scroll_offset = 0
                self.char_input.emit(text.encode('utf-8'))

    def mouseMoveEvent(self, event):
        if self._selecting and (event.buttons() & Qt.MouseButton.LeftButton):
            col, vrow_raw = self._cell_at_pos_unclamped(event.position())
            self._sel_mouse_col = col

            if vrow_raw < 0:
                # Mouse above terminal — auto-scroll up
                self._sel_scroll_dir = -1
                if not self._sel_scroll_timer.isActive():
                    self._sel_scroll_timer.start()
                vrow = 0
            elif vrow_raw >= self._rows:
                # Mouse below terminal — auto-scroll down
                self._sel_scroll_dir = 1
                if not self._sel_scroll_timer.isActive():
                    self._sel_scroll_timer.start()
                vrow = self._rows - 1
            else:
                self._sel_scroll_dir = 0
                self._sel_scroll_timer.stop()
                vrow = vrow_raw

            arow = self._vrow_to_arow(vrow)
            self._sel_end = (col, arow)
            self.update()

    def _sel_auto_scroll(self):
        """Timer callback: scroll terminal while dragging outside bounds."""
        try:
            if not self._screen or not self._selecting:
                self._sel_scroll_timer.stop()
                return
            hist_max = len(self._screen.history.top)
            if self._sel_scroll_dir < 0:
                self._scroll_offset = min(self._scroll_offset + 3, hist_max)
                vrow = 0
            else:
                self._scroll_offset = max(self._scroll_offset - 3, 0)
                vrow = self._rows - 1

            arow = self._vrow_to_arow(vrow)
            self._sel_end = (self._sel_mouse_col, arow)
            self._hist_cache = None
            self.update()
            self._emit_scroll()
        except Exception:
            self._sel_scroll_timer.stop()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self._selecting:
            self._sel_scroll_timer.stop()
            self._sel_scroll_dir = 0
            col, vrow_raw = self._cell_at_pos_unclamped(event.position())
            vrow = max(0, min(vrow_raw, self._rows - 1))
            arow = self._vrow_to_arow(vrow)
            self._sel_end   = (col, arow)
            self._selecting = False
            text = self._selected_text()
            if text.strip():
                QApplication.clipboard().setText(text)
            self.update()

    def wheelEvent(self, event):
        if not self._screen:
            return
        steps    = event.angleDelta().y() // 40
        hist_max = len(self._screen.history.top)
        self._scroll_offset = max(0, min(self._scroll_offset + steps, hist_max))
        self.update()
        self._emit_scroll()

    def focusInEvent(self, event):
        self.update()
        super().focusInEvent(event)

    def focusOutEvent(self, event):
        self._sel_scroll_timer.stop()
        self._selecting = False
        self._sel_start = self._sel_end = None
        self.update()
        super().focusOutEvent(event)


# ──────────────────────────────────────── Connection error page ──────────────

# ──────────────────────────────────────── Workers ────────────────────────────

def _x11_handler(channel, info):
    """Proxy an incoming X11 channel to the local X server (Xming, TCP port 6000)."""
    import socket, threading
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 6000))
    except OSError:
        channel.close()
        return

    def _pipe(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.send(data)
        except Exception:
            pass

    threading.Thread(target=_pipe, args=(channel, sock), daemon=True).start()
    threading.Thread(target=_pipe, args=(sock, channel), daemon=True).start()


class _TofuHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Trust-On-First-Use: stores fingerprint on first connect, rejects mismatches."""

    _KEYS_FILE = os.path.join(os.path.expanduser('~'), '.hospitalhub_known_hosts')
    _cache: dict | None = None

    @classmethod
    def _load(cls) -> dict:
        if cls._cache is None:
            try:
                with open(cls._KEYS_FILE, 'r', encoding='utf-8') as f:
                    cls._cache = json.load(f)
            except Exception:
                cls._cache = {}
        return cls._cache

    @classmethod
    def _save(cls) -> None:
        try:
            with open(cls._KEYS_FILE, 'w', encoding='utf-8') as f:
                json.dump(cls._cache, f, indent=2)
        except Exception:
            pass

    def missing_host_key(self, client, hostname: str, key) -> None:
        known    = self._load()
        key_type = key.get_name()
        fp       = hashlib.sha256(key.asbytes()).hexdigest()

        stored = known.get(hostname, {})
        if key_type in stored:
            if stored[key_type] != fp:
                raise paramiko.BadHostKeyException(hostname, key, key)
            # Key matches — allow silently
        else:
            # First connection — store fingerprint (TOFU)
            stored[key_type] = fp
            known[hostname]  = stored
            self._save()


def _make_client(host: str, user: str, password: str, port: int = 22) -> 'paramiko.SSHClient':
    """Connect via SSH, tolerating legacy algorithms and keyboard-interactive auth.

    Paramiko 4.0 disables ssh-rsa (SHA-1) and older key-exchange by default.
    Many hospital Linux boxes still rely on these.  We re-enable them via
    disabled_algorithms={} so the behaviour matches MobaXterm / PuTTY.

    Auth order when password is provided:
      1. Normal password auth
      2. If rejected → keyboard-interactive (some servers only allow this)
    """
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(_TofuHostKeyPolicy())

    # Common transport/connection kwargs
    base = dict(
        hostname=host, port=port, username=user,
        timeout=12, banner_timeout=20,
        disabled_algorithms={},
    )

    if not password:
        c.connect(**base, look_for_keys=True, allow_agent=True)
        return c

    # --- Has password ---
    try:
        c.connect(**base, password=password,
                  look_for_keys=False, allow_agent=False)
        return c
    except paramiko.ssh_exception.AuthenticationException:
        pass   # password method rejected — try keyboard-interactive below
    except Exception:
        raise  # network error, host-key error, etc. — don't retry

    # Keyboard-interactive fallback: open a raw Transport, verify the
    # host key through TOFU, then auth via keyboard-interactive.
    c.close()
    import socket as _sock
    sock = _sock.create_connection((host, port), timeout=12)
    transport = paramiko.Transport(sock)
    transport.start_client()
    # Host-key verification
    host_key = transport.get_remote_server_key()
    _TofuHostKeyPolicy().missing_host_key(None, host, host_key)
    def _kbd_interactive_handler(title, instructions, prompts):
        answers = []
        for prompt_text, _echo in prompts:
            pt = prompt_text.lower()
            # Only respond to password/passcode prompts; refuse others
            if any(kw in pt for kw in ('password', 'passcode', 'hasło')):
                answers.append(password)
            else:
                answers.append('')
        return answers

    transport.auth_interactive(user, _kbd_interactive_handler)
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(_TofuHostKeyPolicy())
    c._transport = transport
    return c


class _SshWorker(QThread):
    output    = pyqtSignal(str)
    connected = pyqtSignal()
    error     = pyqtSignal(str)
    done      = pyqtSignal()

    def __init__(self, host, user, password, cols=220, rows=50, port=22):
        super().__init__()
        self._host, self._user, self._pw = host, user, password
        self._port    = port
        self._cols    = cols
        self._rows    = rows
        self._channel = None
        self._client  = None
        self._running = False
        # Thread-safe queue for outgoing data.  send() puts bytes here so the
        # worker drains it immediately on each loop tick — Ctrl+C reaches the
        # SSH channel within one iteration regardless of Qt event-queue depth.
        self._send_q: _queue.SimpleQueue[bytes] = _queue.SimpleQueue()

    # ── Interactive password input ─────────────────────────────────────

    def _read_interactive_line(self, echo: bool = True) -> str:
        """Read a line from the terminal send queue (blocks until Enter).

        Used during keyboard-interactive auth so the user can type a
        password directly in the terminal instead of a separate dialog.
        """
        buf = bytearray()
        while True:
            try:
                data = self._send_q.get(timeout=120)
            except _queue.Empty:
                return ''
            for b in data:
                if b in (0x0d, 0x0a):           # Enter
                    self.output.emit('\r\n')
                    return buf.decode('utf-8', errors='replace')
                if b == 0x7f or b == 0x08:      # Backspace
                    if buf:
                        buf.pop()
                        self.output.emit('\b \b')
                    continue
                if b == 0x03:                    # Ctrl+C → cancel
                    self.output.emit('\r\n')
                    return ''
                if b >= 0x20:                    # Printable
                    buf.append(b)
                    self.output.emit('*' if not echo else chr(b))
        return buf.decode('utf-8', errors='replace')

    # ── Main loop ──────────────────────────────────────────────────────

    def run(self):
        import time
        try:
            # ── Interactive login prompt (when no user stored) ─────────
            if not self._user:
                self.output.emit(f"Logowanie do {self._host}\r\nLogin: ")
                login = self._read_interactive_line(echo=True)
                if not login:
                    self.error.emit("Anulowano logowanie.")
                    return
                self._user = login.strip()

            # ── Authentication ─────────────────────────────────────────
            if self._pw:
                self._client = _make_client(
                    self._host, self._user, self._pw, self._port)
            else:
                # Try key-based / agent auth first
                key_ok = False
                try:
                    self._client = _make_client(
                        self._host, self._user, '', self._port)
                    key_ok = True
                except OSError:
                    raise   # network error — let outer handler deal with it
                except Exception:
                    pass    # auth failed (any reason) — fall through

                if not key_ok:
                    # No keys worked → ask for password in terminal
                    self.output.emit("Password: ")
                    pw = self._read_interactive_line(echo=False)
                    if not pw:
                        self.error.emit("Anulowano logowanie.")
                        return
                    self._pw = pw
                    self._client = _make_client(
                        self._host, self._user, pw, self._port)

            # Open session manually so we can attempt X11 forwarding before
            # invoking the shell (invoke_shell() doesn't expose this).
            transport     = self._client.get_transport()
            self._channel = transport.open_session()
            try:
                self._channel.request_x11(screen_number=0, single_connection=False,
                                          handler=_x11_handler)
            except Exception:
                # X11 rejected (older servers close the channel on failure).
                # Re-open a fresh session and continue without X11.
                self._channel = transport.open_session()
            self._channel.get_pty(term='xterm-256color',
                                  width=self._cols, height=self._rows)
            self._channel.invoke_shell()
            self.connected.emit()
            self._running = True
            while self._running:
                # ── Drain outgoing queue FIRST ────────────────────────────────
                # send() puts bytes here so Ctrl+C reaches the SSH channel
                # within one loop iteration regardless of Qt event-queue depth.
                got_ctrl_c = False
                while not self._send_q.empty():
                    try:
                        data = self._send_q.get_nowait()
                        self._channel.send(data)
                        if b'\x03' in data:
                            got_ctrl_c = True
                    except Exception:
                        break

                if got_ctrl_c:
                    deadline = time.monotonic() + 0.5
                    while (time.monotonic() < deadline
                           and self._channel.recv_ready()):
                        self._channel.recv(65536)
                    for _ in range(50):
                        time.sleep(0.01)
                        if self._channel.recv_ready():
                            while self._channel.recv_ready():
                                self.output.emit(
                                    self._channel.recv(8192)
                                    .decode('utf-8', errors='replace'))
                            break

                if self._channel.recv_ready():
                    self.output.emit(
                        self._channel.recv(8192).decode('utf-8', errors='replace'))
                if self._channel.closed or self._channel.exit_status_ready():
                    break
                time.sleep(0.02)
        except paramiko.AuthenticationException:
            self.error.emit("Błąd autentykacji — sprawdź login i hasło.")
        except paramiko.BadHostKeyException as e:
            self.error.emit(
                f"Ostrzeżenie: klucz hosta {e.hostname!r} zmienił się!\n"
                "Możliwy atak MitM. Zweryfikuj serwer ręcznie."
            )
        except paramiko.SSHException as e:
            self.error.emit(f"Błąd SSH: {type(e).__name__}")
        except OSError as e:
            self.error.emit(f"Błąd sieci: {e.strerror or type(e).__name__}")
        except Exception as e:
            self.error.emit(f"Błąd połączenia: {type(e).__name__}")
        finally:
            self.done.emit()

    def send(self, data: bytes):
        """Queue bytes for immediate delivery by the worker thread."""
        self._send_q.put(data)

    def exec_one(self, cmd: str) -> str:
        """Run a one-shot command on the SSH client (separate from the PTY channel)."""
        if not self._client:
            return ''
        try:
            _, stdout, _ = self._client.exec_command(cmd, timeout=6)
            return stdout.read().decode('utf-8', errors='replace').strip()
        except Exception:
            return ''

    def stop(self):
        self._running = False
        try:
            if self._channel: self._channel.close()
            if self._client:  self._client.close()
        except Exception:
            pass


class _StatsWorker(QThread):
    """Polls live machine stats via a one-shot exec on the existing SSH client."""
    stats = pyqtSignal(str, str, str, str)   # load, mem used/total MB, uptime, disk pct+usage

    _CMD = (
        "awk '{printf \"%.2f\",$1}' /proc/loadavg 2>/dev/null; echo; "
        "free -m 2>/dev/null | awk '/^Mem:/{printf \"%d/%d\",$3,$2}'; echo; "
        "awk '{t=$1;printf \"%dd %02dh %02dm\","
        "int(t/86400),int(t%86400/3600),int(t%3600/60)}' /proc/uptime 2>/dev/null; echo; "
        "(df -P /u01 2>/dev/null || df -P /) | awk 'NR==2{gsub(/%/,\"\",$5); printf \"%s %s\",$5,$3\"/\"$2}'"
    )

    def __init__(self, ssh_worker: '_SshWorker', interval: int = 5, parent=None):
        super().__init__(parent)
        self._ssh  = ssh_worker
        self._interval = interval
        self._running  = False

    def run(self):
        import time
        self._running = True
        while self._running:
            out   = self._ssh.exec_one(self._CMD)
            lines = [l for l in out.splitlines() if l.strip()]
            if len(lines) >= 4:
                self.stats.emit(lines[0], lines[1], lines[2], lines[3])
            elif len(lines) == 3:
                self.stats.emit(lines[0], lines[1], lines[2], '')
            for _ in range(self._interval * 10):
                if not self._running:
                    return
                time.sleep(0.1)

    def stop(self):
        self._running = False


class _SftpConnectWorker(QThread):
    ready = pyqtSignal(object, object)
    error = pyqtSignal(str)

    def __init__(self, host, user, password, port=22):
        super().__init__()
        self._host, self._user, self._pw = host, user, password
        self._port = port

    def run(self):
        try:
            c = _make_client(self._host, self._user, self._pw, self._port)
            self.ready.emit(c.open_sftp(), c)
        except paramiko.AuthenticationException:
            self.error.emit("Błąd autentykacji — sprawdź login i hasło.")
        except paramiko.BadHostKeyException as e:
            self.error.emit(
                f"Ostrzeżenie: klucz hosta {e.hostname!r} zmienił się!\n"
                "Możliwy atak MitM. Zweryfikuj serwer ręcznie."
            )
        except Exception as e:
            self.error.emit(f"Błąd połączenia: {type(e).__name__}")


class _SftpListWorker(QThread):
    listing = pyqtSignal(str, list)
    error   = pyqtSignal(str)

    def __init__(self, sftp, path):
        super().__init__()
        self._sftp, self._path = sftp, path

    def run(self):
        try:
            path = self._path
            # Resolve symlinks and normalize the path
            try:
                path = self._sftp.normalize(path)
            except Exception:
                pass
            # If target is a file, navigate to its parent directory
            try:
                st = self._sftp.stat(path)
                if not stat.S_ISDIR(st.st_mode):
                    path = '/'.join(path.rstrip('/').split('/')[:-1]) or '/'
            except Exception:
                pass  # stat failed — try listing anyway
            entries = self._sftp.listdir_attr(path)
            result  = []
            for e in sorted(entries, key=lambda x: (
                not stat.S_ISDIR(x.st_mode), x.filename.lower()
            )):
                is_dir = stat.S_ISDIR(e.st_mode)
                mtime  = (datetime.fromtimestamp(e.st_mtime).strftime('%Y-%m-%d %H:%M')
                          if e.st_mtime else '')
                perms  = oct(e.st_mode)[-3:] if e.st_mode else ''
                result.append((e.filename, is_dir,
                               e.st_size if not is_dir else -1, mtime, perms))
            self.listing.emit(path, result)
        except Exception as e:
            self.error.emit(str(e))


class _CancelledError(Exception):
    pass


class _TransferWorker(QThread):
    progress  = pyqtSignal(int)
    done      = pyqtSignal(str)
    error     = pyqtSignal(str)
    cancelled = pyqtSignal()

    def __init__(self, sftp, mode, remote, local, total=0):
        super().__init__()
        self._sftp, self._mode = sftp, mode
        self._remote, self._local, self._total = remote, local, total
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            def cb(done, total):
                if self._cancel:
                    raise _CancelledError()
                t = total or self._total or 1
                self.progress.emit(min(int(done * 100 / t), 100))

            if self._mode == 'get':
                self._sftp.get(self._remote, self._local, callback=cb)
                self.done.emit(f"Pobrano: {os.path.basename(self._local)}")
            else:
                self._sftp.put(self._local, self._remote, callback=cb)
                self.done.emit(f"Wgrano: {os.path.basename(self._local)}")
        except _CancelledError:
            self.cancelled.emit()
        except Exception as e:
            self.error.emit(str(e))


class _SimpleWorker(QThread):
    done      = pyqtSignal()
    error     = pyqtSignal(str)
    progress  = pyqtSignal(int)
    cancelled = pyqtSignal()

    def __init__(self, fn):
        super().__init__()
        self._fn = fn
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            self._fn()
            self.done.emit()
        except _CancelledError:
            self.cancelled.emit()
        except Exception as e:
            self.error.emit(str(e))


# ──────────────────────────────────────── Numeric sort item ──────────────────

class _NumItem(QTableWidgetItem):
    """Table item that sorts numerically using UserRole data."""
    def __lt__(self, other):
        try:
            return (self.data(Qt.ItemDataRole.UserRole) <
                    other.data(Qt.ItemDataRole.UserRole))
        except Exception:
            return super().__lt__(other)


class _DirFirstItem(QTableWidgetItem):
    """Name item that always sorts directories before files."""
    def __lt__(self, other):
        try:
            _, my_dir, _ = self.data(Qt.ItemDataRole.UserRole)
            _, ot_dir, _ = other.data(Qt.ItemDataRole.UserRole)
            # ".." always first
            my_name = self.text()
            ot_name = other.text()
            if my_name == '..':
                return True
            if ot_name == '..':
                return False
            # Dirs before files
            if my_dir != ot_dir:
                return my_dir  # True (dir) < False (file) → dir first
            # Same type: alphabetical (case-insensitive)
            return my_name.lower() < ot_name.lower()
        except Exception:
            return super().__lt__(other)


# ──────────────────────────────────────── SFTP file icons ─────────────────────

_SFTP_ICON_CACHE: dict[str, QIcon] = {}

def _sftp_icon(key: str) -> QIcon:
    """Return a cached QPainter-drawn icon for SFTP file types."""
    if key in _SFTP_ICON_CACHE:
        return _SFTP_ICON_CACHE[key]
    sz = 16
    pix = QPixmap(sz, sz)
    pix.fill(QColor(0, 0, 0, 0))
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    _SFTP_ICON_DRAW[key](p, sz)
    p.end()
    icon = QIcon(pix)
    _SFTP_ICON_CACHE[key] = icon
    return icon


def _draw_folder(p: QPainter, s: int):
    """Yellow folder icon."""
    c = QColor("#e2b340")
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(c))
    # Tab
    path = QPainterPath()
    path.moveTo(1, 4)
    path.lineTo(1, 2.5)
    path.quadTo(1, 1.5, 2, 1.5)
    path.lineTo(5.5, 1.5)
    path.lineTo(7, 3.5)
    path.lineTo(13, 3.5)
    path.quadTo(14.5, 3.5, 14.5, 5)
    path.lineTo(14.5, 12.5)
    path.quadTo(14.5, 14, 13, 14)
    path.lineTo(3, 14)
    path.quadTo(1, 14, 1, 12.5)
    path.closeSubpath()
    p.drawPath(path)
    # Lighter front face
    p.setBrush(QBrush(QColor("#f0c850")))
    front = QPainterPath()
    front.moveTo(1, 6)
    front.lineTo(14.5, 6)
    front.lineTo(14.5, 12.5)
    front.quadTo(14.5, 14, 13, 14)
    front.lineTo(3, 14)
    front.quadTo(1, 14, 1, 12.5)
    front.closeSubpath()
    p.drawPath(front)


def _draw_file_generic(p: QPainter, s: int):
    """White/gray generic file icon."""
    p.setPen(QPen(QColor("#8b949e"), 1.2))
    p.setBrush(QBrush(QColor("#21262d")))
    path = QPainterPath()
    path.moveTo(3, 1)
    path.lineTo(10, 1)
    path.lineTo(13, 4)
    path.lineTo(13, 14)
    path.quadTo(13, 15, 12, 15)
    path.lineTo(4, 15)
    path.quadTo(3, 15, 3, 14)
    path.closeSubpath()
    p.drawPath(path)
    # Dog ear
    p.setPen(QPen(QColor("#8b949e"), 0.8))
    p.drawLine(10, 1, 10, 4)
    p.drawLine(10, 4, 13, 4)


def _draw_file_text(p: QPainter, s: int):
    """Text file — lines inside a doc."""
    _draw_file_generic(p, s)
    p.setPen(QPen(QColor("#7d8590"), 1.0))
    for y in (7, 9.5, 12):
        p.drawLine(5, int(y), 11, int(y))


def _draw_file_script(p: QPainter, s: int):
    """Shell/script file — terminal prompt icon."""
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(QColor("#1a1e24")))
    p.drawRoundedRect(1, 1, 14, 14, 2.5, 2.5)
    # Title bar
    p.setBrush(QBrush(QColor("#30363d")))
    p.drawRoundedRect(1, 1, 14, 4, 2.5, 2.5)
    p.drawRect(1, 3, 14, 2)
    # Prompt >_
    p.setPen(QPen(QColor("#3fb950"), 1.5))
    p.drawLine(4, 9, 7, 11)
    p.drawLine(4, 13, 7, 11)
    p.setPen(QPen(QColor("#8b949e"), 1.3))
    p.drawLine(9, 13, 12, 13)


def _draw_file_code(p: QPainter, s: int):
    """Code file — angle brackets < />."""
    _draw_file_generic(p, s)
    p.setPen(QPen(QColor("#58a6ff"), 1.3))
    # <
    p.drawLine(5, 8, 3, 10)
    p.drawLine(3, 10, 5, 12)
    # />
    p.drawLine(8, 12, 10, 8)
    p.drawLine(11, 8, 13, 10)
    p.drawLine(13, 10, 11, 12)


def _draw_file_config(p: QPainter, s: int):
    """Config file — gear/cog."""
    _draw_file_generic(p, s)
    cx, cy, r = 8, 10.5, 2.2
    p.setPen(QPen(QColor("#e2b340"), 1.2))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(int(cx - r), int(cy - r), int(2 * r), int(2 * r))
    p.setPen(QPen(QColor("#e2b340"), 1.0))
    for i in range(6):
        a = math.radians(i * 60)
        x1, y1 = cx + r * math.cos(a), cy + r * math.sin(a)
        x2, y2 = cx + (r + 1.3) * math.cos(a), cy + (r + 1.3) * math.sin(a)
        p.drawLine(int(x1), int(y1), int(x2), int(y2))


def _draw_file_archive(p: QPainter, s: int):
    """Archive file — zip icon."""
    _draw_file_generic(p, s)
    p.setPen(QPen(QColor("#da8b45"), 1.2))
    # Zigzag
    p.drawLine(7, 6, 9, 8)
    p.drawLine(9, 8, 7, 10)
    p.drawLine(7, 10, 9, 12)


def _draw_file_image(p: QPainter, s: int):
    """Image file — landscape icon."""
    _draw_file_generic(p, s)
    # Mountain
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(QColor("#3fb950")))
    path = QPainterPath()
    path.moveTo(5, 13)
    path.lineTo(8, 8)
    path.lineTo(11, 13)
    path.closeSubpath()
    p.drawPath(path)
    # Sun
    p.setBrush(QBrush(QColor("#e2b340")))
    p.drawEllipse(10, 6, 3, 3)


def _draw_file_log(p: QPainter, s: int):
    """Log file — scroll icon."""
    _draw_file_generic(p, s)
    p.setPen(QPen(QColor("#da8b45"), 1.0))
    for y in (7, 9, 11, 13):
        w = 6 if y < 13 else 4
        p.drawLine(5, y, 5 + w, y)


def _draw_file_data(p: QPainter, s: int):
    """Data/DB file — cylinder."""
    p.setPen(QPen(QColor("#8b949e"), 1.0))
    p.setBrush(QBrush(QColor("#1f3a5f")))
    p.drawEllipse(3, 1, 10, 4)
    p.drawRect(3, 3, 10, 10)
    p.setBrush(QBrush(QColor("#1f3a5f")))
    p.drawEllipse(3, 11, 10, 4)
    p.setPen(QPen(QColor("#58a6ff"), 1.0))
    p.drawEllipse(3, 1, 10, 4)


def _draw_file_pdf(p: QPainter, s: int):
    """PDF file — red document."""
    p.setPen(QPen(QColor("#f85149"), 1.2))
    p.setBrush(QBrush(QColor("#2d1117")))
    path = QPainterPath()
    path.moveTo(3, 1)
    path.lineTo(10, 1)
    path.lineTo(13, 4)
    path.lineTo(13, 14)
    path.quadTo(13, 15, 12, 15)
    path.lineTo(4, 15)
    path.quadTo(3, 15, 3, 14)
    path.closeSubpath()
    p.drawPath(path)
    p.setPen(QPen(QColor("#f85149"), 0.8))
    p.drawLine(10, 1, 10, 4)
    p.drawLine(10, 4, 13, 4)
    # "P" letter
    p.setPen(QPen(QColor("#f85149"), 1.5))
    p.drawLine(6, 7, 6, 13)
    p.drawLine(6, 7, 9, 7)
    p.drawLine(9, 7, 9, 10)
    p.drawLine(6, 10, 9, 10)


def _draw_parent_dir(p: QPainter, s: int):
    """Parent dir (..) — folder with up arrow."""
    _draw_folder(p, s)
    p.setPen(QPen(QColor("#0d1117"), 2.0))
    p.drawLine(8, 12, 8, 8)
    p.drawLine(6, 10, 8, 8)
    p.drawLine(10, 10, 8, 8)


# Extension → icon key mapping
_EXT_ICON_MAP: dict[str, str] = {}
_exts_script = ('.sh', '.bash', '.zsh', '.ksh', '.csh', '.fish', '.bat', '.cmd', '.ps1')
_exts_code = ('.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.hpp', '.go', '.rs',
              '.rb', '.php', '.cs', '.swift', '.kt', '.scala', '.lua', '.pl', '.r')
_exts_text = ('.txt', '.md', '.rst', '.csv', '.tsv', '.rtf', '.tex')
_exts_config = ('.conf', '.cfg', '.ini', '.yaml', '.yml', '.toml', '.json', '.xml',
                '.properties', '.env', '.service', '.desktop')
_exts_archive = ('.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.tgz', '.war',
                 '.jar', '.ear', '.rpm', '.deb')
_exts_image = ('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.ico', '.webp', '.tiff')
_exts_log = ('.log', '.out', '.err')
_exts_data = ('.sql', '.db', '.sqlite', '.mdb', '.ora', '.dump')
_exts_pdf = ('.pdf',)

for _ext in _exts_script:  _EXT_ICON_MAP[_ext] = 'script'
for _ext in _exts_code:    _EXT_ICON_MAP[_ext] = 'code'
for _ext in _exts_text:    _EXT_ICON_MAP[_ext] = 'text'
for _ext in _exts_config:  _EXT_ICON_MAP[_ext] = 'config'
for _ext in _exts_archive: _EXT_ICON_MAP[_ext] = 'archive'
for _ext in _exts_image:   _EXT_ICON_MAP[_ext] = 'image'
for _ext in _exts_log:     _EXT_ICON_MAP[_ext] = 'log'
for _ext in _exts_data:    _EXT_ICON_MAP[_ext] = 'data'
for _ext in _exts_pdf:     _EXT_ICON_MAP[_ext] = 'pdf'

_SFTP_ICON_DRAW = {
    'folder':  _draw_folder,
    'parent':  _draw_parent_dir,
    'file':    _draw_file_generic,
    'text':    _draw_file_text,
    'script':  _draw_file_script,
    'code':    _draw_file_code,
    'config':  _draw_file_config,
    'archive': _draw_file_archive,
    'image':   _draw_file_image,
    'log':     _draw_file_log,
    'data':    _draw_file_data,
    'pdf':     _draw_file_pdf,
}


def _icon_for_entry(name: str, is_dir: bool) -> QIcon:
    """Pick the right icon for a file/directory entry."""
    if is_dir:
        return _sftp_icon('parent' if name == '..' else 'folder')
    ext = os.path.splitext(name)[1].lower()
    key = _EXT_ICON_MAP.get(ext, 'file')
    return _sftp_icon(key)


# ──────────────────────────────────────── SFTP panel ─────────────────────────

class SftpPanel(QWidget):
    status_msg    = pyqtSignal(str, bool)   # text, is_error
    upload_file   = pyqtSignal(str)         # local path
    _open_local   = pyqtSignal(str)         # path → open in main thread
    _watch_file_sig = pyqtSignal(str, str, int)  # local_path, remote_path, orig_size → watch in main thread

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self._open_local.connect(lambda p: QDesktopServices.openUrl(QUrl.fromLocalFile(p)))
        self._sftp:  object = None
        self._ssh_client: object = None
        self._path   = '/'
        self._history: list[str] = []
        self._workers: list[QThread] = []
        self._listing_active = False   # guard against concurrent listdir_attr
        self._rename_editor: QLineEdit | None = None
        self._rename_editor_data: dict | None = None
        self._transfer_queue: list = []
        self._transfer_total_count = 0
        self._transfer_done_count = 0
        self._setup_ui()

        # Slow-double-click rename (click on already-selected row after a pause)
        self._rename_timer = QTimer(self)
        self._rename_timer.setSingleShot(True)
        self._rename_timer.setInterval(700)
        self._rename_timer.timeout.connect(self._do_pending_rename)
        self._pending_rename_item = None
        self._click_was_selected  = False
        self._table.viewport().installEventFilter(self)
        self._table.itemClicked.connect(self._on_item_clicked)

        # Serialize concurrent open_sftp() calls (paramiko transport is not
        # safe for simultaneous channel opens from multiple threads).
        self._sftp_open_lock = threading.Lock()

        # Auto-upload: poll mtime every 2 s instead of QFileSystemWatcher
        # (watcher was unreliable on Windows — fired for its own writes,
        #  editor temp files, etc. — causing freezes and data loss).
        self._watched_files: dict[str, dict] = {}  # path → {remote, orig_size, mtime}
        self._upload_active: set[str] = set()       # paths currently being uploaded
        self._watch_poll = QTimer(self)
        self._watch_poll.setInterval(2000)
        self._watch_poll.timeout.connect(self._poll_watched_files)
        self._watch_file_sig.connect(self._watch_file)

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.setSpacing(4)

        # Navigation bar
        nav = QHBoxLayout()
        self._btn_up  = self._nav_btn("↑", "Katalog wyżej", self._go_up)
        self._btn_home = self._nav_btn("⌂", "Katalog /", lambda: self._list('/'))
        self._btn_ref  = self._nav_btn("↻", "Odśwież", lambda: self._list(self._path))
        for b in (self._btn_up, self._btn_home, self._btn_ref):
            b.setEnabled(False)
            nav.addWidget(b)

        # Path bar: label (click to edit) / line-edit (copy, Enter to navigate)
        self._path_stack = QStackedWidget()
        self._path_stack.setFixedHeight(28)

        self._path_lbl = QLabel("Nie połączono")
        self._path_lbl.setFont(QFont("Consolas", 9))
        self._path_lbl.setStyleSheet("color: #58a6ff; padding-left: 4px;")
        self._path_lbl.setCursor(Qt.CursorShape.IBeamCursor)
        self._path_lbl.mousePressEvent = lambda e: self._start_path_edit()
        self._path_stack.addWidget(self._path_lbl)   # index 0

        self._path_edit = QLineEdit()
        self._path_edit.setFont(QFont("Consolas", 9))
        self._path_edit.setStyleSheet(
            "QLineEdit{background:#0d1117;color:#58a6ff;border:1px solid #1f6feb;"
            "border-radius:4px;padding:0 4px;}"
        )
        self._path_edit.returnPressed.connect(self._navigate_from_edit)
        self._path_stack.addWidget(self._path_edit)   # index 1
        self._path_edit.installEventFilter(self)

        self._path_stack.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        nav.addWidget(self._path_stack, 1)

        # History dropdown button
        self._btn_history = QToolButton()
        self._btn_history.setText("▾")
        self._btn_history.setFixedSize(22, 28)
        self._btn_history.setToolTip("Historia folderów")
        self._btn_history.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._btn_history.setStyleSheet(
            "QToolButton{background:#151b23;color:#8b949e;"
            "border:1px solid #21262d;border-radius:4px;font-size:12px;}"
            "QToolButton:hover{background:#1c2433;color:#c9d1d9;border-color:#30363d;}"
            "QToolButton::menu-indicator{image:none;}"
        )
        self._history_menu = QMenu(self)
        self._history_menu.setStyleSheet(
            "QMenu{background:#161b22;color:#e6edf3;border:1px solid #30363d;"
            "border-radius:6px;padding:4px;}"
            "QMenu::item{padding:4px 16px;border-radius:3px;}"
            "QMenu::item:selected{background:#1f6feb;}"
        )
        self._btn_history.setMenu(self._history_menu)
        nav.addWidget(self._btn_history)

        root.addLayout(nav)

        # File table
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Nazwa", "Rozmiar", "Zmodyfikowano", "Uprawnienia"])
        hh = self._table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        hh.setStretchLastSection(False)
        hh.setMinimumSectionSize(80)
        hh.setDefaultSectionSize(120)
        hh.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._table.setColumnWidth(0, 200)
        self._table.setColumnWidth(1, 90)
        self._table.setColumnWidth(2, 130)
        self._table.setColumnWidth(3, 80)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setShowGrid(False)
        sftp_font = QFont("Consolas", 10)
        self._table.setFont(sftp_font)
        self._table.setIconSize(QSize(16, 16))
        self._table.setSortingEnabled(True)
        self._table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        self._table.doubleClicked.connect(self._on_dbl_click)
        self._table.itemSelectionChanged.connect(self._on_sel_change)
        self._table.setStyleSheet("""
            QTableWidget {
                background: #0d1117;
                alternate-background-color: #111820;
                color: #e6edf3;
                border: 1px solid #21262d;
                border-radius: 6px;
                gridline-color: transparent;
                selection-background-color: #1a2540;
                selection-color: #c0d0f0;
            }
            QTableWidget::item {
                padding: 2px 4px;
                border-bottom: 1px solid #161b22;
            }
            QTableWidget::item:selected {
                background: #1a2540;
                color: #c0d0f0;
                border-radius: 3px;
            }
            QTableWidget::item:hover:!selected {
                background: #131920;
            }
            QHeaderView::section {
                background: #0d1117;
                color: #7d8590;
                border: none;
                border-bottom: 2px solid #21262d;
                padding: 5px 8px;
                font-size: 10px;
                font-weight: 600;
                text-transform: uppercase;
            }
            QScrollBar:vertical {
                background: #0d1117;
                width: 8px;
                margin: 0;
            }
            QScrollBar::handle:vertical {
                background: #30363d;
                border-radius: 4px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover { background: #484f58; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }
        """)
        root.addWidget(self._table, 1)

        # Drag & drop hint
        hint = QLabel("Upuść pliki tutaj aby wgrać  ⬆")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("color:#30363d; font-size:10px; padding:2px;")
        root.addWidget(hint)

        # Transfer buttons + progress
        xfer = QHBoxLayout()
        self._btn_dl = QPushButton("⬇  Pobierz")
        self._btn_dl.setEnabled(False)
        self._btn_dl.setStyleSheet(
            "QPushButton{background:#0d1f0d;color:#3fb950;"
            "border:1px solid #1b3d1b;border-radius:6px;padding:4px 10px;"
            "font-size:11px;}"
            "QPushButton:hover{background:#152b15;border-color:#2d5a2d;}"
            "QPushButton:disabled{color:#30363d;background:#0d1117;"
            "border-color:#1c2128;}")
        self._btn_dl.clicked.connect(self._download)

        self._btn_ul = QPushButton("⬆  Wgraj")
        self._btn_ul.setEnabled(False)
        self._btn_ul.setStyleSheet(
            "QPushButton{background:#0d1525;color:#58a6ff;"
            "border:1px solid #1a3050;border-radius:6px;padding:4px 10px;"
            "font-size:11px;}"
            "QPushButton:hover{background:#152540;border-color:#2a4a6a;}"
            "QPushButton:disabled{color:#333;background:#111;}")
        self._btn_ul.clicked.connect(self._upload_browse)

        self._progress = QProgressBar()
        self._progress.setVisible(False)
        self._progress.setFixedHeight(16)
        self._progress.setTextVisible(True)
        self._progress.setFormat("%p%")
        self._progress.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._progress.setStyleSheet(
            "QProgressBar{border:none;background:#21262d;border-radius:3px;"
            "color:#c9d1d9;font-size:10px;}"
            "QProgressBar::chunk{background:#1f6feb;border-radius:3px;}")

        self._btn_cancel = QPushButton("✕")
        self._btn_cancel.setVisible(False)
        self._btn_cancel.setFixedSize(20, 20)
        self._btn_cancel.setToolTip("Anuluj transfer")
        self._btn_cancel.setStyleSheet(
            "QPushButton{background:#3d1f1f;color:#f85149;"
            "border:1px solid #5a2d2d;border-radius:4px;"
            "font-size:11px;font-weight:bold;padding:0;}"
            "QPushButton:hover{background:#5a2d2d;border-color:#f85149;}")
        self._btn_cancel.clicked.connect(self._cancel_transfer)
        self._active_transfer_worker = None

        xfer.addWidget(self._btn_dl)
        xfer.addWidget(self._btn_ul)
        xfer.addWidget(self._progress, 1)
        xfer.addWidget(self._btn_cancel)
        root.addLayout(xfer)

    def _nav_btn(self, text, tip, slot) -> QPushButton:
        b = QPushButton(text)
        b.setFixedSize(28, 28)
        b.setToolTip(tip)
        b.setStyleSheet(
            "QPushButton{background:#151b23;color:#8b949e;"
            "border:1px solid #21262d;border-radius:6px;font-size:13px;}"
            "QPushButton:hover{background:#1c2433;color:#c9d1d9;"
            "border-color:#30363d;}"
            "QPushButton:disabled{color:#30363d;border-color:#1c2128;}")
        b.clicked.connect(slot)
        return b

    # ── Path bar helpers ─────────────────────────────────────────────────

    def _start_path_edit(self):
        """Switch path bar to editable line-edit for copy / manual navigation."""
        self._path_edit.setText(self._path)
        self._path_stack.setCurrentIndex(1)
        self._path_edit.setFocus()
        self._path_edit.selectAll()

    def _end_path_edit(self):
        """Switch back to label display."""
        self._path_stack.setCurrentIndex(0)

    def _navigate_from_edit(self):
        """Navigate to path typed in the edit field."""
        target = self._path_edit.text().strip()
        self._end_path_edit()
        if not target or not self._sftp or self._listing_active:
            return
        # Normalize: resolve relative paths against current directory
        if not target.startswith('/'):
            target = self._path.rstrip('/') + '/' + target
        # Resolve .. and . components
        parts = target.split('/')
        resolved: list[str] = []
        for p in parts:
            if p == '' or p == '.':
                continue
            elif p == '..':
                if resolved:
                    resolved.pop()
            else:
                resolved.append(p)
        target = '/' + '/'.join(resolved)
        self._history.append(self._path)
        self._list(target)

    def _update_history_menu(self):
        """Rebuild the history dropdown menu from self._history."""
        self._history_menu.clear()
        if not self._history:
            a = self._history_menu.addAction("(brak historii)")
            a.setEnabled(False)
            return
        # Show most recent first, deduplicated, max 20
        seen = set()
        for path in reversed(self._history):
            if path in seen:
                continue
            seen.add(path)
            self._history_menu.addAction(path, lambda p=path: self._jump_history(p))
            if len(seen) >= 20:
                break

    def _jump_history(self, path: str):
        """Navigate directly to a path from the history dropdown."""
        if self._sftp:
            self._list(path)

    # ── Public API ────────────────────────────────────────────────────────

    def set_sftp(self, sftp, ssh_client):
        self._sftp = sftp
        self._ssh_client = ssh_client
        for b in (self._btn_up, self._btn_home, self._btn_ref, self._btn_ul):
            b.setEnabled(True)
        self._list('/')

    # ── Navigation ────────────────────────────────────────────────────────

    def _list(self, path: str):
        if not self._sftp or self._listing_active:
            return
        self._listing_active = True
        self._path_lbl.setText(f"…  {path}")
        self._table.setSortingEnabled(False)
        w = _SftpListWorker(self._sftp, path)
        w.listing.connect(self._on_listing)
        w.error.connect(lambda e: self._on_listing_error(e))
        w.start()
        self._workers.append(w)

    def _on_listing_error(self, msg: str):
        self._listing_active = False
        self._path_lbl.setText(self._path)
        self._end_path_edit()
        self.status_msg.emit(f"SFTP: {msg}", True)

    def _on_listing(self, path: str, entries: list):
        self._listing_active = False
        self._path = path
        self._path_lbl.setText(path)
        self._end_path_edit()
        self._update_history_menu()
        self._table.setRowCount(0)

        for i, (name, is_dir, size, mtime, perms) in enumerate(entries):
            self._table.insertRow(i)

            # Col 0: name with file-type icon (dirs-first sort)
            ni = _DirFirstItem(name)
            ni.setIcon(_icon_for_entry(name, is_dir))
            ni.setData(Qt.ItemDataRole.UserRole, (name, is_dir, size))
            if is_dir:
                ni.setForeground(QColor("#e6edf3"))
            self._table.setItem(i, 0, ni)

            # Col 1: size (numeric sort)
            si = _NumItem("" if is_dir else _fmt_size(size))
            si.setData(Qt.ItemDataRole.UserRole, size)
            si.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._table.setItem(i, 1, si)

            # Col 2: modified date
            self._table.setItem(i, 2, QTableWidgetItem(mtime))

            self._table.setItem(i, 3, QTableWidgetItem(perms))
            self._table.setRowHeight(i, 24)

        self._table.setSortingEnabled(True)
        self._table.sortItems(0, Qt.SortOrder.AscendingOrder)
        self._btn_dl.setEnabled(False)

    def eventFilter(self, obj, event):
        # Path edit: Escape cancels, FocusOut returns to label
        if obj is self._path_edit:
            if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Escape:
                self._end_path_edit()
                return True
            if event.type() == QEvent.Type.FocusOut:
                self._end_path_edit()
        if obj == self._table.viewport() and event.type() == QEvent.Type.ToolTip:
            idx = self._table.indexAt(event.pos())
            if idx.isValid() and idx.column() == 0:
                item = self._table.item(idx.row(), 0)
                if item:
                    fm = self._table.fontMetrics()
                    # available width = column width minus icon/padding (~30px)
                    avail = self._table.columnWidth(0) - 30
                    text_w = fm.horizontalAdvance(item.text())
                    if text_w > avail:
                        from PyQt6.QtWidgets import QToolTip
                        QToolTip.showText(event.globalPos(), item.text(), self._table.viewport())
                    else:
                        from PyQt6.QtWidgets import QToolTip
                        QToolTip.hideText()
                    return True
            from PyQt6.QtWidgets import QToolTip
            QToolTip.hideText()
            return True
        if obj == self._table.viewport() and event.type() == QEvent.Type.MouseButtonPress:
            idx = self._table.indexAt(event.pos())
            self._click_was_selected = (
                idx.isValid() and self._table.selectionModel().isSelected(idx)
            )
            if self._rename_editor:
                self._commit_rename()
        if obj is self._rename_editor:
            if event.type() == QEvent.Type.KeyPress:
                if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                    self._commit_rename()
                    return True
                if event.key() == Qt.Key.Key_Escape:
                    self._close_rename_editor()
                    return True
            elif event.type() == QEvent.Type.FocusOut:
                self._commit_rename()
        return False

    def _on_item_clicked(self, item):
        row_item = self._table.item(item.row(), 0)
        if not row_item or not row_item.data(Qt.ItemDataRole.UserRole):
            return
        if self._click_was_selected:
            self._pending_rename_item = row_item
            self._rename_timer.start()
        else:
            self._rename_timer.stop()
            self._pending_rename_item = None

    def _do_pending_rename(self):
        item, self._pending_rename_item = self._pending_rename_item, None
        if item:
            self._start_inline_rename(item)

    def _start_inline_rename(self, item):
        # Close any existing rename editor first
        self._close_rename_editor()
        name, is_dir, size = item.data(Qt.ItemDataRole.UserRole)
        # Position overlay QLineEdit exactly over the cell — no delegate, no crashes
        rect = self._table.visualItemRect(item)
        ed = QLineEdit(self._table.viewport())
        ed.setText(name)
        ed.selectAll()
        ed.setGeometry(rect)
        ed.setStyleSheet(
            "QLineEdit { background:#2d333b; color:#e6edf3;"
            " border:1px solid #58a6ff; padding:0 4px;"
            " font: 10pt Consolas; }"
        )
        ed.show()
        ed.setFocus()
        ed.installEventFilter(self)
        self._rename_editor      = ed
        self._rename_editor_data = {'item': item, 'name': name,
                                    'is_dir': is_dir, 'size': size}

    def _commit_rename(self):
        ed   = self._rename_editor
        data = self._rename_editor_data
        if not ed or not data:
            return
        new_name = ed.text().strip()
        self._close_rename_editor()
        item     = data['item']
        original = data['name']
        is_dir   = data['is_dir']
        size     = data['size']
        if not new_name or new_name == original:
            return
        self._table.blockSignals(True)
        item.setText(new_name)
        item.setIcon(_icon_for_entry(new_name, is_dir))
        item.setData(Qt.ItemDataRole.UserRole, (new_name, is_dir, size))
        self._table.blockSignals(False)
        old_remote = self._path.rstrip('/') + '/' + original
        new_remote = self._path.rstrip('/') + '/' + new_name

        def do_rename():
            self._sftp.rename(old_remote, new_remote)

        w = _SimpleWorker(do_rename)
        w.done.connect(lambda: self._list(self._path))
        w.error.connect(lambda e: self.status_msg.emit(f"Zmiana nazwy: {e}", True))
        w.start()
        self._workers.append(w)

    def _close_rename_editor(self):
        if self._rename_editor:
            self._rename_editor.hide()
            self._rename_editor.deleteLater()
            self._rename_editor      = None
            self._rename_editor_data = None

    def _on_dbl_click(self, index):
        self._rename_timer.stop()
        self._pending_rename_item = None
        self._close_rename_editor()
        if self._listing_active:
            return

        item = self._table.item(index.row(), 0)
        if not item:
            return
        name, is_dir, _ = item.data(Qt.ItemDataRole.UserRole)
        if is_dir:
            parent = self._path.rstrip('/')
            self._history.append(self._path)
            self._list(f"{parent}/{name}" if parent else f"/{name}")
        else:
            self._open_remote(self._path.rstrip('/') + '/' + name, name)

    def _go_up(self):
        if self._listing_active:
            return
        if self._history:
            target = self._history.pop()
            self._list(target)
        else:
            parts = self._path.rstrip('/').split('/')
            parent = '/'.join(parts[:-1]) or '/'
            if parent != self._path:
                self._history.append(self._path)
                self._list(parent)

    def _on_sel_change(self):
        sel = self._table.selectedItems()
        if not sel:
            self._btn_dl.setEnabled(False)
            return
        # Enable download if at least one selected row is a file
        seen = set()
        has_file = False
        for s in sel:
            r = s.row()
            if r in seen:
                continue
            seen.add(r)
            item = self._table.item(r, 0)
            if item:
                _, is_dir, _ = item.data(Qt.ItemDataRole.UserRole)
                if not is_dir:
                    has_file = True
                    break
        self._btn_dl.setEnabled(has_file)

    # ── Context menu ──────────────────────────────────────────────────────

    def _context_menu(self, pos):
        item = self._table.itemAt(pos)
        if not item:
            return
        row_item = self._table.item(item.row(), 0)
        if not row_item:
            return
        name, is_dir, size = row_item.data(Qt.ItemDataRole.UserRole)
        remote = self._path.rstrip('/') + '/' + name

        menu = QMenu(self)
        if not is_dir:
            menu.addAction("⬇  Pobierz", self._download)
            menu.addAction("📄  Otwórz lokalnie", lambda: self._open_remote(remote, name))
            menu.addAction("📂  Otwórz za pomocą...", lambda: self._open_with(remote, name))
        menu.addSeparator()
        menu.addAction("📋  Kopiuj ścieżkę", lambda r=remote: QApplication.clipboard().setText(r))
        menu.addSeparator()
        menu.addAction("🔒  Uprawnienia...", lambda: self._chmod_dialog(remote, name))
        menu.addAction("✏️  Zmień nazwę", lambda ri=row_item: self._start_inline_rename(ri))
        menu.addAction("🗑️  Usuń", lambda: self._delete(remote, is_dir, name))
        menu.exec(self._table.viewport().mapToGlobal(pos))

    # ── Transfer ──────────────────────────────────────────────────────────

    def _download(self):
        if not self._sftp:
            return
        # Collect unique selected file rows (skip dirs)
        seen_rows = set()
        files = []
        for sel in self._table.selectedItems():
            r = sel.row()
            if r in seen_rows:
                continue
            seen_rows.add(r)
            item = self._table.item(r, 0)
            if not item:
                continue
            name, is_dir, size = item.data(Qt.ItemDataRole.UserRole)
            if is_dir:
                continue
            files.append((name, size))
        if not files:
            return

        if len(files) == 1:
            name, size = files[0]
            remote = self._path.rstrip('/') + '/' + name
            local, _ = QFileDialog.getSaveFileName(self, "Zapisz plik", name)
            if local:
                self._run_transfer('get', remote, local, size)
        else:
            folder = QFileDialog.getExistingDirectory(self, "Wybierz folder do zapisania plików")
            if not folder:
                return
            queue = []
            for name, size in files:
                remote = self._path.rstrip('/') + '/' + name
                local = os.path.join(folder, name)
                queue.append(('get', remote, local, size))
            self._transfer_queue = queue
            self._transfer_total_count = len(queue)
            self._transfer_done_count = 0
            self._run_next_queued_transfer()

    def _upload_browse(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Wybierz pliki do wgrania")
        if not paths or not self._sftp:
            return
        if len(paths) == 1:
            self._upload_file(paths[0])
        else:
            queue = []
            for p in paths:
                if not os.path.isfile(p):
                    continue
                fname = os.path.basename(p)
                remote = self._path.rstrip('/') + '/' + fname
                queue.append(('put', remote, p, os.path.getsize(p)))
            if queue:
                self._transfer_queue = queue
                self._transfer_total_count = len(queue)
                self._transfer_done_count = 0
                self._run_next_queued_transfer()

    def _upload_file(self, local: str):
        if not self._sftp or not os.path.isfile(local):
            return
        fname  = os.path.basename(local)
        remote = self._path.rstrip('/') + '/' + fname
        self._run_transfer('put', remote, local, os.path.getsize(local))

    def _run_transfer(self, mode, remote, local, size):
        self._transfer_queue = []
        self._transfer_total_count = 1
        self._transfer_done_count = 0
        self._start_single_transfer(mode, remote, local, size)

    def _run_next_queued_transfer(self):
        if not self._transfer_queue:
            return
        mode, remote, local, size = self._transfer_queue.pop(0)
        self._start_single_transfer(mode, remote, local, size)

    def _start_single_transfer(self, mode, remote, local, size):
        self._transfer_current_mode = mode
        total = self._transfer_total_count
        done_n = self._transfer_done_count
        if total > 1:
            self._progress.setFormat(f"{done_n+1}/{total}  %p%")
        else:
            self._progress.setFormat("%p%")
        self._progress.setValue(0)
        self._progress.setVisible(True)
        self._btn_cancel.setVisible(True)
        self._btn_dl.setEnabled(False)
        self._btn_ul.setEnabled(False)
        w = _TransferWorker(self._sftp, mode, remote, local, size)
        self._active_transfer_worker = w
        w.progress.connect(self._progress.setValue)
        w.done.connect(self._transfer_done)
        w.cancelled.connect(lambda: self._transfer_cancelled(local if mode == 'get' else None))
        w.error.connect(lambda e: self._transfer_error(e))
        w.start()
        self._workers.append(w)

    def _transfer_done(self, msg: str):
        self._transfer_done_count += 1
        total = self._transfer_total_count
        if self._transfer_queue:
            self.status_msg.emit(msg, False)
            self._run_next_queued_transfer()
        else:
            self._transfer_finished_cleanup()
            if total > 1:
                mode = getattr(self, '_transfer_current_mode', 'get')
                verb = "Pobrano" if mode == 'get' else "Wgrano"
                self.status_msg.emit(f"{verb} {self._transfer_done_count} plików", False)
            else:
                self.status_msg.emit(msg, False)
            self._list(self._path)

    def _transfer_error(self, e: str):
        if self._transfer_queue:
            self.status_msg.emit(f"Transfer: {e}", True)
            self._transfer_done_count += 1
            self._run_next_queued_transfer()
        else:
            self._transfer_finished_cleanup()
            self.status_msg.emit(f"Transfer: {e}", True)

    def _transfer_cancelled(self, partial_file: str = None):
        self._transfer_queue = []
        self._transfer_finished_cleanup()
        if partial_file and os.path.exists(partial_file):
            try:
                os.remove(partial_file)
            except OSError:
                pass
        self.status_msg.emit("Transfer anulowany", False)

    def _transfer_finished_cleanup(self):
        self._progress.setFormat("%p%")
        self._progress.setVisible(False)
        self._btn_cancel.setVisible(False)
        self._btn_ul.setEnabled(True)
        self._active_transfer_worker = None
        self._on_sel_change()  # re-evaluate download button state
        # Prune finished workers to prevent memory leak
        self._workers = [w for w in self._workers if w.isRunning()]

    def _cancel_transfer(self):
        w = self._active_transfer_worker
        if w:
            self._transfer_queue = []
            w.cancel()

    _DANGEROUS_EXT = frozenset({
        '.exe', '.bat', '.cmd', '.com', '.msi', '.scr', '.pif',
        '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1',
        '.jar', '.iso', '.img', '.hta', '.cpl', '.inf', '.reg',
    })

    def _open_remote(self, remote: str, name: str):
        """Download to temp file, open with default app, watch for changes → auto-upload."""
        if not self._ssh_client:
            return
        # Warn about potentially dangerous file types
        ext = os.path.splitext(name)[1].lower()
        if ext in self._DANGEROUS_EXT:
            from PyQt6.QtWidgets import QMessageBox
            r = QMessageBox.warning(
                self, "Ostrzeżenie",
                f"Plik \"{name}\" ma potencjalnie niebezpieczne rozszerzenie "
                f"({ext}).\n\nCzy na pewno chcesz go otworzyć?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if r != QMessageBox.StandardButton.Yes:
                return
        # Use a dedicated subdir so the file keeps its original name (like WinSCP)
        tmp_dir  = os.path.join(tempfile.gettempdir(),
                                f'HospitalHub_{os.getpid()}')
        os.makedirs(tmp_dir, exist_ok=True)
        safe_name = os.path.basename(name) or 'file'   # strip any path components
        tmp_path  = os.path.join(tmp_dir, safe_name)

        # If already open/watched, just re-open in editor without re-downloading
        if tmp_path in self._watched_files:
            QDesktopServices.openUrl(QUrl.fromLocalFile(tmp_path))
            return

        ssh_client = self._ssh_client   # capture — each worker gets its own channel

        lock = self._sftp_open_lock

        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setVisible(True)
        self._btn_cancel.setVisible(True)

        worker_ref = [None]

        def do_open():
            with lock:                          # serialize channel opens
                sftp = ssh_client.open_sftp()
            try:
                try:
                    total = sftp.stat(remote).st_size or 1
                except Exception:
                    total = 1
                def cb(done, t):
                    if worker_ref[0]._cancel:
                        raise _CancelledError()
                    worker_ref[0].progress.emit(min(int(done * 100 / (t or total)), 100))
                sftp.get(remote, tmp_path, callback=cb)
            finally:
                sftp.close()
            self._open_local.emit(tmp_path)
            size = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
            self._watch_file_sig.emit(tmp_path, remote, size)

        w = _SimpleWorker(do_open)
        worker_ref[0] = w
        self._active_transfer_worker = w
        w.progress.connect(self._progress.setValue)
        w.cancelled.connect(lambda: self._transfer_cancelled(tmp_path))
        w.error.connect(lambda e: (
            self._transfer_finished_cleanup(),
            self.status_msg.emit(f"Otwieranie: {e}", True)))
        w.done.connect(lambda: self._transfer_finished_cleanup())
        w.start()
        self._workers.append(w)

    def _open_with(self, remote: str, name: str):
        """Download to temp, then let the user pick an application to open with."""
        if not self._ssh_client:
            return
        tmp_dir = os.path.join(tempfile.gettempdir(), f'HospitalHub_{os.getpid()}')
        os.makedirs(tmp_dir, exist_ok=True)
        safe_name = os.path.basename(name) or 'file'
        tmp_path = os.path.join(tmp_dir, safe_name)
        ssh_client = self._ssh_client
        lock = self._sftp_open_lock

        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setVisible(True)
        self._btn_cancel.setVisible(True)

        worker_ref = [None]

        def do_download():
            with lock:
                sftp = ssh_client.open_sftp()
            try:
                try:
                    total = sftp.stat(remote).st_size or 1
                except Exception:
                    total = 1
                def cb(done, t):
                    if worker_ref[0]._cancel:
                        raise _CancelledError()
                    worker_ref[0].progress.emit(min(int(done * 100 / (t or total)), 100))
                sftp.get(remote, tmp_path, callback=cb)
            finally:
                sftp.close()

        def on_done():
            self._transfer_finished_cleanup()
            if not os.path.exists(tmp_path):
                return
            if sys.platform == 'win32':
                import subprocess
                subprocess.Popen(['rundll32', 'shell32.dll,OpenAs_RunDLL', tmp_path])
            else:
                subprocess.Popen(['xdg-open', tmp_path])
            size = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
            self._watch_file_sig.emit(tmp_path, remote, size)

        w = _SimpleWorker(do_download)
        worker_ref[0] = w
        self._active_transfer_worker = w
        w.progress.connect(self._progress.setValue)
        w.cancelled.connect(lambda: self._transfer_cancelled(tmp_path))
        w.error.connect(lambda e: (
            self._transfer_finished_cleanup(),
            self.status_msg.emit(f"Otwieranie: {e}", True)))
        w.done.connect(on_done)
        w.start()
        self._workers.append(w)

    def _chmod_dialog(self, remote: str, name: str):
        """Show a dialog to change file/directory permissions."""
        if not self._sftp:
            return
        try:
            st = self._sftp.stat(remote)
            current_mode = st.st_mode & 0o7777
        except Exception as e:
            self.status_msg.emit(f"Nie mozna odczytac uprawnien: {e}", True)
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Uprawnienia: {name}")
        dlg.setFixedSize(320, 280)
        dlg.setStyleSheet(
            "QDialog { background:#1a1d28; color:#e1e4eb; }"
            "QGroupBox { border:1px solid #2a2d3a; border-radius:8px;"
            " padding:12px 8px 8px 8px; margin-top:8px; color:#8a90a4; font-size:11px; }"
            "QGroupBox::title { subcontrol-origin:margin; left:12px; padding:0 4px; }"
            "QCheckBox { color:#c8ccd6; spacing:6px; }"
            "QCheckBox::indicator { width:14px; height:14px; border:1px solid #3a3f55;"
            " border-radius:3px; background:#22242e; }"
            "QCheckBox::indicator:checked { background:#4a5adf; border-color:#4a5adf; }"
            "QLineEdit { background:#22242e; border:1px solid #2a2d3a; border-radius:6px;"
            " padding:4px 8px; color:#e1e4eb; font-family:monospace; }"
        )
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(16, 12, 16, 12)

        # Octal input
        oct_row = QHBoxLayout()
        oct_row.addWidget(QLabel("Octal:"))
        oct_edit = QLineEdit(f"{current_mode:04o}")
        oct_edit.setMaximumWidth(80)
        oct_row.addWidget(oct_edit)
        oct_row.addStretch()
        layout.addLayout(oct_row)

        # Permission checkboxes
        labels = [("Odczyt", "Zapis", "Wykonanie")]
        groups = [("Właściciel", 6), ("Grupa", 3), ("Inni", 0)]
        checks = {}
        for group_name, shift in groups:
            grp = QGroupBox(group_name)
            gl = QHBoxLayout(grp)
            for i, perm_name in enumerate(["Odczyt", "Zapis", "Wykonanie"]):
                bit = 1 << (shift + (2 - i))
                cb = QCheckBox(perm_name)
                cb.setChecked(bool(current_mode & bit))
                checks[(shift, i)] = (cb, bit)
                gl.addWidget(cb)
            layout.addWidget(grp)

        # Sync checkboxes → octal
        def sync_to_octal():
            mode = 0
            for (_, _), (cb, bit) in checks.items():
                if cb.isChecked():
                    mode |= bit
            oct_edit.setText(f"{mode:04o}")

        # Sync octal → checkboxes
        def sync_from_octal():
            try:
                mode = int(oct_edit.text(), 8)
            except ValueError:
                return
            for (_, _), (cb, bit) in checks.items():
                cb.blockSignals(True)
                cb.setChecked(bool(mode & bit))
                cb.blockSignals(False)

        for (_, _), (cb, _) in checks.items():
            cb.stateChanged.connect(sync_to_octal)
        oct_edit.textChanged.connect(sync_from_octal)

        # Buttons
        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(dlg.reject)
        btn_row.addWidget(btn_cancel)
        btn_apply = QPushButton("Zastosuj")
        btn_apply.setDefault(True)
        btn_apply.setStyleSheet(
            "QPushButton { background:#4a5adf; color:#fff; border:none;"
            " border-radius:6px; padding:6px 18px; font-weight:bold; }"
            "QPushButton:hover { background:#5a6aef; }"
        )
        btn_apply.clicked.connect(dlg.accept)
        btn_row.addWidget(btn_apply)
        layout.addStretch()
        layout.addLayout(btn_row)

        if dlg.exec():
            try:
                new_mode = int(oct_edit.text(), 8)
                self._sftp.chmod(remote, new_mode)
                self.status_msg.emit(
                    f"Uprawnienia {name}: {oct_edit.text()}", False)
                self._list(self._path)
            except Exception as e:
                self.status_msg.emit(f"chmod: {e}", True)

    # ── Auto-upload (mtime polling) ────────────────────────────────────────

    def _watch_file(self, local_path: str, remote_path: str, orig_size: int = 0):
        try:
            mtime = os.path.getmtime(local_path) if os.path.exists(local_path) else 0
        except OSError:
            mtime = 0
        self._watched_files[local_path] = {
            'remote':    remote_path,
            'orig_size': orig_size,
            'mtime':     mtime,
        }
        if not self._watch_poll.isActive():
            self._watch_poll.start()

    def _poll_watched_files(self):
        if not self._ssh_client:
            return
        for local_path, info in list(self._watched_files.items()):
            if local_path in self._upload_active:
                continue
            if not os.path.exists(local_path):
                continue
            try:
                mtime = os.path.getmtime(local_path)
                size  = os.path.getsize(local_path)
            except OSError:
                continue
            if mtime <= info['mtime']:
                continue                          # file not modified since last check
            orig_size = info['orig_size']
            if size == 0 or (orig_size > 512 and size < orig_size * 0.10):
                self.status_msg.emit(
                    f"Auto-upload pominięty — plik pusty lub uszkodzony "
                    f"({size} B, było {orig_size} B)", True)
                info['mtime'] = mtime             # don't warn again for same write
                continue
            info['mtime']     = mtime
            info['orig_size'] = size
            self._upload_changed_file(local_path, info['remote'])

    def _upload_changed_file(self, local: str, remote: str):
        if not self._ssh_client or local in self._upload_active:
            return
        self._upload_active.add(local)
        ssh_client = self._ssh_client

        lock = self._sftp_open_lock
        try:
            total = os.path.getsize(local) or 1
        except OSError:
            total = 1

        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setVisible(True)
        self._btn_cancel.setVisible(True)

        worker_ref = [None]

        def do_upload():
            with lock:
                sftp = ssh_client.open_sftp()
            try:
                def cb(done, t):
                    if worker_ref[0]._cancel:
                        raise _CancelledError()
                    worker_ref[0].progress.emit(min(int(done * 100 / (t or total)), 100))
                sftp.put(local, remote, callback=cb)
            finally:
                sftp.close()

        def on_done(_=None):
            self._upload_active.discard(local)
            self._transfer_finished_cleanup()
            self.status_msg.emit(f"Zapisano na SFTP: {os.path.basename(remote)}", False)
            self._list(self._path)

        def on_cancelled():
            self._upload_active.discard(local)
            self._transfer_finished_cleanup()
            self.status_msg.emit("Auto-upload anulowany", False)

        def on_error(e):
            self._upload_active.discard(local)
            self._transfer_finished_cleanup()
            self.status_msg.emit(f"Błąd zapisu: {e}", True)

        w = _SimpleWorker(do_upload)
        worker_ref[0] = w
        self._active_transfer_worker = w
        w.progress.connect(self._progress.setValue)
        w.cancelled.connect(on_cancelled)
        w.done.connect(on_done)
        w.error.connect(on_error)
        w.start()
        self._workers.append(w)

    def _delete(self, remote: str, is_dir: bool, name: str):
        ans = QMessageBox.question(
            self, "Usuń",
            f"Usunąć {'katalog' if is_dir else 'plik'} '{name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if ans != QMessageBox.StandardButton.Yes:
            return

        import stat as _stat
        sftp = self._sftp
        worker_ref = [None]

        def do_delete():
            if not is_dir:
                sftp.remove(remote)
                return
            # Recursively collect entries (files first, dirs deepest-first)
            files, dirs = [], []
            def walk(p):
                for a in sftp.listdir_attr(p):
                    sub = p.rstrip('/') + '/' + a.filename
                    if _stat.S_ISDIR(a.st_mode or 0):
                        walk(sub)
                        dirs.append(sub)
                    else:
                        files.append(sub)
            walk(remote)
            total = len(files) + len(dirs) + 1
            done = 0
            for f in files:
                if worker_ref[0]._cancel:
                    raise _CancelledError()
                sftp.remove(f)
                done += 1
                worker_ref[0].progress.emit(int(done * 100 / total))
            for d in dirs:
                if worker_ref[0]._cancel:
                    raise _CancelledError()
                sftp.rmdir(d)
                done += 1
                worker_ref[0].progress.emit(int(done * 100 / total))
            sftp.rmdir(remote)
            worker_ref[0].progress.emit(100)

        self._progress.setFormat(f"Usuwanie: {name}  %p%")
        if is_dir:
            self._progress.setRange(0, 100)
        else:
            self._progress.setRange(0, 0)  # indeterminate for single file
        self._progress.setValue(0)
        self._progress.setVisible(True)

        w = _SimpleWorker(do_delete)
        worker_ref[0] = w

        def _finish():
            self._progress.setRange(0, 100)
            self._progress.setFormat("%p%")
            self._progress.setVisible(False)
            self._list(self._path)

        def _on_err(e):
            self._progress.setRange(0, 100)
            self._progress.setFormat("%p%")
            self._progress.setVisible(False)
            self.status_msg.emit(f"Usuwanie: {e}", True)

        w.progress.connect(self._progress.setValue)
        w.done.connect(_finish)
        w.cancelled.connect(_finish)
        w.error.connect(_on_err)
        w.start()
        self._workers.append(w)

    # ── Drag & drop from Windows Explorer ────────────────────────────────

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        if not self._sftp:
            return
        files = []
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.isfile(path):
                files.append(path)
        if not files:
            return
        if len(files) == 1:
            self._upload_file(files[0])
        else:
            queue = []
            for p in files:
                fname = os.path.basename(p)
                remote = self._path.rstrip('/') + '/' + fname
                queue.append(('put', remote, p, os.path.getsize(p)))
            self._transfer_queue = queue
            self._transfer_total_count = len(queue)
            self._transfer_done_count = 0
            self._run_next_queued_transfer()

    # ── Cleanup ───────────────────────────────────────────────────────────

    def switch_sftp(self, sftp, ssh_client, restore_path: str = '/',
                    restore_history: list[str] | None = None):
        """Swap active SFTP connection and restore the previous browsed path."""
        self._watch_poll.stop()
        self._watched_files.clear()
        self._upload_active.clear()
        self._sftp        = sftp
        self._ssh_client  = ssh_client
        self._history     = restore_history if restore_history is not None else []
        connected = bool(sftp and ssh_client)
        for b in (self._btn_up, self._btn_home, self._btn_ref, self._btn_ul):
            b.setEnabled(connected)
        if connected:
            self._list(restore_path)
        else:
            self._path_lbl.setText("Nie połączono")
            self._table.setRowCount(0)
            self._update_history_menu()

    def stop(self):
        self._close_rename_editor()
        self._watch_poll.stop()
        self._watched_files.clear()
        self._upload_active.clear()
        for w in self._workers:
            if w.isRunning():
                w.wait(800)
        # sftp / ssh_client are owned by _Session objects — closed there


# ──────────────────────────────────────── Environment panel ──────────────────

class _EnvironmentPanel(QWidget):
    """Machine list with hospital dropdown, double-click connect, credential context menu."""
    open_machine = pyqtSignal(object)            # machine (uses first cred)
    open_machine_cred = pyqtSignal(object, object)  # machine, credential

    _STYLE_IDLE = (
        "QFrame#machineCard { background:#1a1d28; border:1px solid #2a2d3a;"
        " border-radius:10px; border-left:3px solid #2a2d3a; }"
        "QFrame#machineCard:hover { background:#1e2233; border-color:#3a3f55;"
        " border-left:3px solid #4a5adf; }"
        "QLabel { border:none; background:transparent; }"
    )
    _STYLE_ACTIVE = (
        "QFrame#machineCard { background:#1c2240; border:1px solid #4a5adf;"
        " border-radius:10px; border-left:3px solid #6382ff; }"
        "QLabel { border:none; background:transparent; }"
    )
    _STYLE_SELECTED = (
        "QFrame#machineCard { background:#1a2830; border:1px solid #2a8a6a;"
        " border-radius:10px; border-left:3px solid #40c090; }"
        "QLabel { border:none; background:transparent; }"
    )

    def __init__(self, hospital=None, all_hospitals=None,
                 initial_ip: str = '', admin_unlocked: bool = False,
                 parent=None):
        super().__init__(parent)
        self._cards: dict[str, QFrame] = {}   # ip → card widget
        self._machines: dict[str, object] = {}  # ip → machine object
        self._active_ip: str = ''
        self._selected_ips: set[str] = set()
        self._all_hospitals = all_hospitals or []
        self._current_hospital = hospital
        self._admin_unlocked = admin_unlocked

        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        # Hospital selector button + dropdown menu
        self._hospital_btn = QPushButton()
        self._hospital_btn.setStyleSheet(
            "QPushButton { background:#1a1d28; color:#e1e4eb; border:1px solid #2a2d3a;"
            " border-radius:10px; padding:8px 14px; font-size:13px; font-weight:bold;"
            " text-align:left; letter-spacing:0.3px; }"
            "QPushButton:hover { border-color:#4a5adf; background:#1e2233; }"
            "QPushButton:pressed { background:#1c2240; }"
            "QPushButton::menu-indicator { width:0; height:0; }"
        )
        self._hospital_btn.setCursor(Qt.CursorShape.PointingHandCursor)

        # Arrow indicator on the right
        self._hospital_btn.clicked.connect(self._show_hospital_menu)

        # Set initial text
        if hospital:
            self._hospital_btn.setText(f"  {hospital.name}" if hospital.name else "  (bez nazwy)")
        else:
            self._hospital_btn.setText("  —")
        root.addWidget(self._hospital_btn)

        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)

        # Machine list area
        self._machine_area = QWidget()
        self._machine_layout = QVBoxLayout(self._machine_area)
        self._machine_layout.setContentsMargins(0, 0, 0, 0)
        self._machine_layout.setSpacing(0)
        root.addWidget(self._machine_area, 1)

        self._build_machine_list(hospital)

        if initial_ip:
            self.set_active(initial_ip)

    def _show_hospital_menu(self):
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background:#1a1d28; color:#e1e4eb; border:1px solid #2a2d3a;"
            " border-radius:10px; padding:6px; }"
            "QMenu::item { padding:8px 16px; border-radius:6px; font-size:12px; }"
            "QMenu::item:selected { background:#4a5adf; color:#fff; }"
            "QMenu::separator { height:1px; background:#2a2d3a; margin:4px 10px; }"
        )
        for h in self._all_hospitals:
            name = h.name if h.name else "(bez nazwy)"
            action = menu.addAction(f"  {name}")
            if h is self._current_hospital:
                action.setEnabled(False)
            action.triggered.connect(lambda _=False, _h=h: self._select_hospital(_h))

        # Show menu below the button
        pos = self._hospital_btn.mapToGlobal(
            self._hospital_btn.rect().bottomLeft())
        menu.exec(pos)

    def _select_hospital(self, h):
        if h is self._current_hospital:
            return
        self._current_hospital = h
        self._hospital_btn.setText(
            f"  {h.name}" if h.name else "  (bez nazwy)")
        old_active = self._active_ip
        self._cards.clear()
        self._machines.clear()
        self._selected_ips.clear()
        self._build_machine_list(h)
        if old_active and old_active in self._cards:
            self.set_active(old_active)

    def _build_machine_list(self, hospital):
        # Clear old content
        layout = self._machine_layout
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

        if not hospital or not hospital.machines:
            empty = QLabel("Brak maszyn")
            empty.setStyleSheet("color:#5a5f72; font-size:11px; padding:16px;")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(empty)
            layout.addStretch()
            return

        section_lbl = QLabel("MASZYNY")
        section_lbl.setStyleSheet(
            "color:#5a5f72; font-size:9px; font-weight:bold;"
            " letter-spacing:2px; padding:6px 4px 4px 4px;"
        )
        layout.addWidget(section_lbl)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet(
            "QScrollArea { background:transparent; border:none; }"
            "QScrollBar:vertical { background:#14161e; width:6px; border:none;"
            " border-radius:3px; margin:2px; }"
            "QScrollBar::handle:vertical { background:#2a2d3a; border-radius:3px;"
            " min-height:20px; }"
            "QScrollBar::handle:vertical:hover { background:#3a3f55; }"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }"
        )

        container = QWidget()
        container.setStyleSheet("background:transparent;")
        cl = QVBoxLayout(container)
        cl.setContentsMargins(0, 0, 2, 0)
        cl.setSpacing(2)

        machines = hospital.machines if self._admin_unlocked else [
            m for m in hospital.machines if not m.admin_only]
        machines = [m for m in machines if getattr(m, "connection_type", "SSH") != "WWW"]
        for m in machines:
            card = self._make_machine_card(m)
            cl.addWidget(card)

        cl.addStretch()
        scroll.setWidget(container)
        layout.addWidget(scroll, 1)

    def _make_machine_card(self, m) -> QFrame:
        card = QFrame()
        card.setObjectName("machineCard")
        card.setFrameShape(QFrame.Shape.NoFrame)
        card.setStyleSheet(self._STYLE_IDLE)
        card.setCursor(Qt.CursorShape.PointingHandCursor)
        card.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._cards[m.ip] = card
        self._machines[m.ip] = m

        # Store machine ref on card for event handling
        card.setProperty('_machine', m)

        rl = QHBoxLayout(card)
        rl.setContentsMargins(10, 4, 8, 4)
        rl.setSpacing(6)

        # IP + name on one line
        if m.name:
            line = (f"<b style='color:#b0c0ff;'>{m.ip}</b>"
                    f"<span style='color:#8a90a4;'>  {m.name}</span>")
        else:
            line = f"<b style='color:#b0c0ff;'>{m.ip}</b>"
        lbl = QLabel(line)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        lbl.setStyleSheet("font-size:11px;")
        rl.addWidget(lbl, 1)

        if getattr(m, 'connection_type', 'SSH') == 'RDP':
            btn = QPushButton("RDP")
            btn.setFixedSize(36, 18)
            btn.setToolTip(
                f"Polacz przez Remote Desktop ({m.ip}:"
                f"{getattr(m, 'rdp_port', '3389') or '3389'})"
            )
            btn.setStyleSheet(
                "QPushButton { background:#2a1a40; color:#c084fc;"
                " border:1px solid #5a3a8a; border-radius:6px;"
                " font-size:9px; font-weight:bold; padding:0; }"
                "QPushButton:hover { background:#7c3aed; color:#fff;"
                " border-color:#7c3aed; }"
            )
            btn.clicked.connect(lambda _=False, _m=m: _connect_rdp(
                _m, self, self._admin_unlocked))
        else:
            btn = QPushButton("SSH")
            btn.setFixedSize(36, 18)
            btn.setToolTip(f"Polacz z {m.ip}")
            btn.setStyleSheet(
                "QPushButton { background:#1a2040; color:#6382ff;"
                " border:1px solid #3a4070; border-radius:6px;"
                " font-size:9px; font-weight:bold; padding:0; }"
                "QPushButton:hover { background:#4a5adf; color:#fff;"
                " border-color:#4a5adf; }"
            )
            btn.clicked.connect(lambda _=False, _m=m: self.open_machine.emit(_m))
        rl.addWidget(btn)

        # Click: normal = connect, Ctrl = toggle selection
        card.mousePressEvent = lambda e, _m=m: self._card_clicked(_m, e)

        # Right-click context menu with credentials
        card.customContextMenuRequested.connect(
            lambda pos, _m=m, _c=card: self._show_cred_menu(_m, _c, pos))

        return card

    def _card_clicked(self, machine, event):
        if event.button() != Qt.MouseButton.LeftButton:
            return
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self._toggle_select(machine.ip)
            self.setFocus()
        else:
            self._clear_selection()
            self._dblclick_connect(machine)

    def _toggle_select(self, ip: str):
        if ip in self._selected_ips:
            self._selected_ips.discard(ip)
        else:
            self._selected_ips.add(ip)
        self._refresh_card_style(ip)

    def _clear_selection(self):
        for ip in list(self._selected_ips):
            self._selected_ips.discard(ip)
            self._refresh_card_style(ip)

    def _refresh_card_style(self, ip: str):
        if ip not in self._cards:
            return
        if ip in self._selected_ips:
            self._cards[ip].setStyleSheet(self._STYLE_SELECTED)
        elif ip == self._active_ip:
            self._cards[ip].setStyleSheet(self._STYLE_ACTIVE)
        else:
            self._cards[ip].setStyleSheet(self._STYLE_IDLE)

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and self._selected_ips:
            machines = [self._machines[ip] for ip in self._selected_ips
                        if ip in self._machines]
            self._clear_selection()
            for m in machines:
                self._dblclick_connect(m)
            return
        super().keyPressEvent(event)

    def _dblclick_connect(self, machine):
        if getattr(machine, 'connection_type', 'SSH') == 'RDP':
            _connect_rdp(machine, self, self._admin_unlocked)
        else:
            self.open_machine.emit(machine)

    def _show_cred_menu(self, machine, card, pos):
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu{background:#1a1d28;color:#e1e4eb;border:1px solid #2a2d3a;"
            "border-radius:10px;padding:6px;}"
            "QMenu::item{padding:6px 18px;border-radius:6px;}"
            "QMenu::item:selected{background:#4a5adf;}"
            "QMenu::separator{height:1px;background:#2a2d3a;margin:4px 10px;}"
        )
        vis_creds = machine.credentials if self._admin_unlocked else [
            c for c in machine.credentials if not c.admin_only]
        if vis_creds:
            header = menu.addAction("Połącz jako:")
            header.setEnabled(False)
            menu.addSeparator()
            for cred in vis_creds:
                label = cred.login
                if cred.note:
                    label += f"  ({cred.note})"
                menu.addAction(label,
                    lambda _c=cred, _m=machine: self.open_machine_cred.emit(_m, _c))
        else:
            a = menu.addAction("Brak poświadczeń — połącz ręcznie")
            a.triggered.connect(lambda: self.open_machine.emit(machine))
        menu.exec(card.mapToGlobal(pos))

    def set_active(self, ip: str):
        """Highlight the card for ip, de-highlight the previous one."""
        if ip == self._active_ip:
            return
        if self._active_ip and self._active_ip in self._cards:
            self._cards[self._active_ip].setStyleSheet(self._STYLE_IDLE)
        self._active_ip = ip
        if ip and ip in self._cards:
            self._cards[ip].setStyleSheet(self._STYLE_ACTIVE)


# ──────────────────────────────────────── Terminal pane & session ─────────────

class _TerminalPane(QWidget):
    """TerminalWidget wrapped with a multi-exec header bar."""

    def __init__(self, term: 'TerminalWidget', label: str, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        self._hdr = QWidget()
        self._hdr.setFixedHeight(26)
        self._hdr.setStyleSheet(
            "background:#0d1117;border-bottom:1px solid #21262d;")
        hl = QHBoxLayout(self._hdr)
        hl.setContentsMargins(6, 0, 6, 0)
        name_lbl = QLabel(f"<b>{label}</b>")
        name_lbl.setTextFormat(Qt.TextFormat.RichText)
        name_lbl.setStyleSheet("color:#58a6ff;font-size:10px;")
        self.exclude_cb = QCheckBox("Wyklucz")
        self.exclude_cb.setStyleSheet("color:#888;font-size:10px;")
        hl.addWidget(name_lbl)
        hl.addStretch()
        hl.addWidget(self.exclude_cb)
        self._hdr.setVisible(False)
        lay.addWidget(self._hdr)

        self.term = term
        self._error_mode = False
        term.installEventFilter(self)

        # Terminal row: term + narrow scrollbar
        term_row = QHBoxLayout()
        term_row.setContentsMargins(0, 0, 0, 0)
        term_row.setSpacing(0)
        term_row.addWidget(term, 1)

        self._scrollbar = QScrollBar(Qt.Orientation.Vertical)
        self._scrollbar.setFixedWidth(10)
        self._scrollbar.setStyleSheet(
            "QScrollBar:vertical{background:#0d1117;width:10px;margin:0;}"
            "QScrollBar::handle:vertical{background:#30363d;border-radius:4px;min-height:20px;}"
            "QScrollBar::handle:vertical:hover{background:#484f58;}"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"
            "QScrollBar::add-page:vertical,QScrollBar::sub-page:vertical{background:none;}")
        self._scrollbar.setRange(0, 0)
        self._scrollbar.setValue(0)
        self._scrollbar.setVisible(False)
        term_row.addWidget(self._scrollbar)
        lay.addLayout(term_row, 1)

        self._sb_updating = False
        term.scroll_changed.connect(self._on_scroll_changed)
        self._scrollbar.valueChanged.connect(self._on_scrollbar_moved)

    def set_multiexec_header(self, visible: bool):
        self._hdr.setVisible(visible)

    def _on_scroll_changed(self, offset: int, max_offset: int):
        """Terminal notified us of a scroll position change — sync scrollbar."""
        self._sb_updating = True
        self._scrollbar.setRange(0, max_offset)
        # scrollbar value 0 = bottom (newest), max_offset = top (oldest)
        self._scrollbar.setValue(max_offset - offset)
        self._scrollbar.setVisible(max_offset > 0)
        self._sb_updating = False

    def _on_scrollbar_moved(self, value: int):
        """User dragged the scrollbar — update terminal scroll offset."""
        if self._sb_updating:
            return
        new_offset = self._scrollbar.maximum() - value
        self.term._scroll_offset = new_offset
        self.term.update()

    def show_error(self, msg: str):
        """Print styled error block into the terminal and enable R/Esc intercept."""
        self._error_mode = True
        self.term.feed(
            f"\r\n"
            f"\x1b[31m  ╔══════════════════════════════════════╗\x1b[0m\r\n"
            f"\x1b[31m  ║   ⚠  POŁĄCZENIE NIEUDANE             ║\x1b[0m\r\n"
            f"\x1b[31m  ╚══════════════════════════════════════╝\x1b[0m\r\n"
            f"\x1b[90m  {msg}\x1b[0m\r\n"
            f"\r\n"
            f"  \x1b[97;44m R \x1b[0m \x1b[97m Połącz ponownie\x1b[0m"
            f"     \x1b[97;100m Esc \x1b[0m \x1b[90m Zamknij\x1b[0m\r\n"
        )

    def show_terminal(self):
        """Disable error intercept (terminal resumes normal input)."""
        self._error_mode = False

    # Intercept R / Esc when connection has failed
    def eventFilter(self, obj, event):
        if obj is self.term and self._error_mode:
            if event.type() == QEvent.Type.KeyPress:
                if event.key() == Qt.Key.Key_R:
                    self.retry_requested.emit()
                    return True
                if event.key() == Qt.Key.Key_Escape:
                    self.close_requested.emit()
                    return True
        return False

    retry_requested = pyqtSignal()
    close_requested = pyqtSignal()


class _Session:
    """One SSH session: terminal pane + worker + optional SFTP connection."""
    __slots__ = ('pane', 'worker', 'label', 'sftp', 'sftp_client', 'sftp_path',
                 'sftp_history', 'stats_worker', 'last_stats')

    def __init__(self, pane: _TerminalPane, worker: '_SshWorker', label: str):
        self.pane         = pane
        self.worker       = worker
        self.label        = label
        self.sftp         = None
        self.sftp_client  = None
        self.sftp_path    = '/'
        self.sftp_history: list[str] = []
        self.stats_worker = None
        self.last_stats: tuple | None = None   # (load, mem, uptime, disk) — last known values

    @property
    def term(self) -> 'TerminalWidget':
        return self.pane.term

    @property
    def excluded(self) -> bool:
        return self.pane.exclude_cb.isChecked()


# ──────────────────────────────────────── Add-session dialog ─────────────────

class _AddSessionDialog(QDialog):
    """Dialog for manually entering SSH connection parameters."""

    def __init__(self, default_ip: str = '', default_user: str = '', parent=None):
        super().__init__(parent)
        self.setWindowTitle("Nowa sesja SSH")
        self.setFixedSize(420, 260)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)
        self.setStyleSheet("""
            _AddSessionDialog {background: #0d1117;}
            QLabel {color: #c9d1d9; font-size: 12px;}
            QLineEdit {
                background: #161b22; color: #e6edf3;
                border: 1px solid #30363d; border-radius: 6px;
                padding: 6px 10px; font-size: 12px;
            }
            QLineEdit:focus {border-color: #1f6feb;}
            QLineEdit::placeholder {color: #484f58;}
            QPushButton {
                background: #21262d; color: #c9d1d9;
                border: 1px solid #30363d; border-radius: 6px;
                padding: 6px 18px; font-size: 12px;
            }
            QPushButton:hover {background: #30363d; color: #e6edf3;}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 18)
        layout.setSpacing(12)

        form = QFormLayout()
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._ip_edit = QLineEdit(default_ip)
        self._ip_edit.setPlaceholderText("np. 192.168.1.100")
        form.addRow("Host / IP:", self._ip_edit)

        self._port_edit = QLineEdit()
        self._port_edit.setPlaceholderText("22 (domyślnie)")
        self._port_edit.setMaximumWidth(80)
        form.addRow("Port:", self._port_edit)

        self._user_edit = QLineEdit(default_user)
        self._user_edit.setPlaceholderText("np. root, admin")
        form.addRow("Login:", self._user_edit)

        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.setPlaceholderText("Opcjonalne — wpisz w terminalu jeśli pusty")
        self._pass_edit.returnPressed.connect(self._accept)
        form.addRow("Hasło:", self._pass_edit)

        layout.addLayout(form)
        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        btn_ok = QPushButton("Połącz")
        btn_ok.setDefault(True)
        btn_ok.setStyleSheet(
            "QPushButton{background:#0d1f0d;color:#3fb950;"
            "border:1px solid #1b3d1b;border-radius:6px;padding:6px 20px;}"
            "QPushButton:hover{background:#152b15;border-color:#2d5a2d;}")
        btn_ok.clicked.connect(self._accept)
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

    def _accept(self):
        if not self._ip_edit.text().strip():
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Błąd", "Podaj adres IP lub hostname.")
            return
        if not self._user_edit.text().strip():
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Błąd", "Podaj login.")
            return
        self.accept()

    def get_values(self) -> tuple:
        port_text = self._port_edit.text().strip()
        port = int(port_text) if port_text.isdigit() else 22
        return (
            self._ip_edit.text().strip(),
            self._user_edit.text().strip(),
            self._pass_edit.text(),
            port,
        )


# ──────────────────────────────────────── Main dialog ────────────────────────

_TAB_STYLE = """
    QTabWidget::pane {
        border: none;
        background: #0d1117;
        border-top: 1px solid #30363d;
    }
    QTabBar {
        background: #010409;
        qproperty-drawBase: 0;
    }
    QTabBar::tab {
        background: #010409;
        color: #7d8590;
        padding: 6px 16px 5px 16px;
        margin-right: 1px;
        border: 1px solid transparent;
        border-bottom: none;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
        font-size: 11px;
        min-width: 80px;
    }
    QTabBar::tab:selected {
        background: #0d1117;
        color: #e6edf3;
        border-color: #30363d;
        border-bottom: 1px solid #0d1117;
    }
    QTabBar::tab:!selected:hover {
        background: #161b22;
        color: #c9d1d9;
    }
    QTabBar::close-button {
        subcontrol-position: right;
        margin: 2px 4px 0 0;
        padding: 2px;
        border-radius: 4px;
    }
    QTabBar::close-button:hover {
        background: rgba(220, 60, 60, 100);
    }
"""

def _ensure_close_icons():
    """Create close-button PNG icons (normal + hover) in temp dir, return paths."""
    d = os.path.join(os.path.realpath(tempfile.gettempdir()), 'hhub_icons')
    os.makedirs(d, exist_ok=True)
    normal = os.path.join(d, 'tab_close.png')
    hover  = os.path.join(d, 'tab_close_h.png')
    if not os.path.exists(normal) or not os.path.exists(hover):
        from PyQt6.QtGui import QPixmap, QPainter, QPen, QColor
        from PyQt6.QtCore import Qt as _Qt
        for path, color in [(normal, '#8b949e'), (hover, '#e6edf3')]:
            px = QPixmap(16, 16)
            px.fill(_Qt.GlobalColor.transparent)
            p = QPainter(px)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.setPen(QPen(QColor(color), 1.8))
            p.drawLine(4, 4, 12, 12)
            p.drawLine(12, 4, 4, 12)
            p.end()
            px.save(path)
    return normal.replace('\\', '/'), hover.replace('\\', '/')

def _session_tab_style():
    n, h = _ensure_close_icons()
    return f"""
    QTabWidget::pane {{
        border: none;
        background: #0d1117;
    }}
    QTabBar {{
        background: #010409;
        qproperty-drawBase: 0;
        padding-left: 4px;
    }}
    QTabBar::tab {{
        background: #0c1018;
        color: #7d8590;
        padding: 5px 14px 4px 10px;
        margin-right: 2px;
        margin-top: 2px;
        border: 1px solid #21262d;
        border-bottom: none;
        border-top-left-radius: 10px;
        border-top-right-radius: 10px;
        font-size: 11px;
        min-width: 100px;
    }}
    QTabBar::tab:selected {{
        background: #0d1117;
        color: #e6edf3;
        border-color: #30363d;
        border-bottom: 1px solid #0d1117;
        margin-top: 0px;
        padding-bottom: 6px;
    }}
    QTabBar::tab:!selected:hover {{
        background: #161b22;
        color: #c9d1d9;
        border-color: #30363d;
    }}
    QTabBar::close-button {{
        image: url({n});
        subcontrol-position: right;
        margin: 2px 4px 0 0;
        padding: 2px;
        border-radius: 4px;
        width: 12px;
        height: 12px;
    }}
    QTabBar::close-button:hover {{
        image: url({h});
        background: rgba(220, 60, 60, 0.65);
    }}
    """


def _make_ssh_window_icon() -> QIcon:
    """QPainter-drawn terminal icon for SSH window taskbar."""
    sz = 32
    pix = QPixmap(sz, sz)
    pix.fill(QColor(0, 0, 0, 0))
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    # Terminal background
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(QColor("#0d1117")))
    p.drawRoundedRect(1, 1, 30, 30, 5, 5)
    # Title bar
    p.setBrush(QBrush(QColor("#30363d")))
    p.drawRoundedRect(1, 1, 30, 8, 5, 5)
    p.drawRect(1, 6, 30, 3)
    # Prompt >_
    p.setPen(QPen(QColor("#3fb950"), 2.5))
    p.drawLine(7, 16, 13, 20)
    p.drawLine(7, 24, 13, 20)
    # Cursor
    p.setPen(QPen(QColor("#58a6ff"), 2.0))
    p.drawLine(16, 24, 24, 24)
    p.end()
    return QIcon(pix)


class SshDialog(QDialog):
    # Class-level list to prevent garbage collection of detached windows
    _alive: list['SshDialog'] = []

    def __init__(self, machine, hospital=None, all_hospitals=None,
                 admin_unlocked=False, parent=None):
        # Pass parent=None so this is a true top-level window with own taskbar icon
        super().__init__(None)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowFlag(Qt.WindowType.Window)
        SshDialog._alive.append(self)
        self._machine  = machine
        self._hospital = hospital
        self._all_hospitals = all_hospitals or []
        self._admin_unlocked = admin_unlocked
        vis_creds = machine.credentials if admin_unlocked else [
            c for c in machine.credentials if not c.admin_only]
        self._cred     = vis_creds[0] if vis_creds else None
        self._sessions: list[_Session] = []
        self._multiexec = False
        self._workers: list[QThread] = []

        self.setWindowTitle("Terminal SSH - HospitalHub")
        self.setWindowIcon(_make_ssh_window_icon())
        self.resize(1200, 700)
        self.setMinimumSize(700, 450)
        self.setStyleSheet("""
            SshDialog { background: #010409; }
        """)
        # Track maximized state for restore-from-minimize on Windows
        self._was_maximized  = False
        self._is_minimized   = False
        self._saved_geometry = None
        self._setup_ui()

        if not _PARAMIKO_OK:
            self._status("Brak biblioteki paramiko. Zainstaluj: pip install paramiko", err=True)
            return

        QTimer.singleShot(0, self._add_first_session)

    # ── UI ────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(4)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet(
            "QSplitter::handle { background: #21262d; border-radius: 2px; }"
            "QSplitter { background: #010409; }"
        )

        # ── Left: SFTP + Environment tabs ──
        left_tabs = QTabWidget()
        left_tabs.setStyleSheet(_TAB_STYLE)

        self._sftp_panel = SftpPanel()
        self._sftp_panel.status_msg.connect(lambda t, e: self._status(t, err=e))
        left_tabs.addTab(self._sftp_panel, "📁  Pliki")

        self._env_panel = _EnvironmentPanel(
            self._hospital, all_hospitals=self._all_hospitals,
            initial_ip=self._machine.ip,
            admin_unlocked=self._admin_unlocked)
        self._env_panel.open_machine.connect(self._open_extra_machine)
        self._env_panel.open_machine_cred.connect(self._open_machine_with_cred)
        left_tabs.addTab(self._env_panel, "🖥  Środowisko")

        self._left_tabs = left_tabs
        from PyQt6.QtWidgets import QSizePolicy
        left_tabs.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        splitter.addWidget(left_tabs)
        splitter.setCollapsible(0, True)

        # ── Right: Terminal area ──
        term_area = QWidget()
        tlay = QVBoxLayout(term_area)
        tlay.setContentsMargins(0, 0, 0, 0)
        tlay.setSpacing(2)

        # Toolbar
        tb = QHBoxLayout()
        tb.setContentsMargins(4, 2, 4, 2)

        self._btn_multiexec = QPushButton("⊞  Multi-exec")
        self._btn_multiexec.setCheckable(True)
        self._btn_multiexec.setStyleSheet(
            "QPushButton{background:#151b23;color:#58a6ff;"
            "border:1px solid #21262d;border-radius:6px;padding:4px 12px;"
            "font-size:11px;}"
            "QPushButton:checked{background:#1f6feb;color:#fff;"
            "border-color:#1f6feb;}"
            "QPushButton:hover{background:#1c2433;border-color:#30363d;}")
        self._btn_multiexec.toggled.connect(self._toggle_multiexec)

        btn_new = QPushButton("＋  Nowa sesja")
        btn_new.setStyleSheet(
            "QPushButton{background:#0d1f0d;color:#3fb950;"
            "border:1px solid #1b3d1b;border-radius:6px;padding:4px 12px;"
            "font-size:11px;}"
            "QPushButton:hover{background:#152b15;border-color:#2d5a2d;}")
        btn_new.clicked.connect(self._prompt_new_session)

        tb.addWidget(self._btn_multiexec)
        tb.addWidget(btn_new)
        tb.addStretch()
        tlay.addLayout(tb)

        # Mode stack: 0 = tabs, 1 = multi-exec grid
        self._mode_stack = QStackedWidget()

        self._tab_widget = QTabWidget()
        self._tab_widget.setStyleSheet(_session_tab_style())
        self._tab_widget.setMovable(True)
        self._tab_widget.setTabsClosable(True)
        self._tab_widget.tabCloseRequested.connect(self._close_session)
        self._tab_widget.currentChanged.connect(self._on_tab_changed)
        self._tab_widget.tabBar().tabMoved.connect(self._on_tab_moved)
        self._mode_stack.addWidget(self._tab_widget)

        self._grid_container = QWidget()
        self._grid_container.setStyleSheet("background:#0d1117;")
        self._grid_layout = QGridLayout(self._grid_container)
        self._grid_layout.setContentsMargins(4, 4, 4, 4)
        self._grid_layout.setSpacing(4)
        self._mode_stack.addWidget(self._grid_container)

        tlay.addWidget(self._mode_stack, 1)
        splitter.addWidget(term_area)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([250, 950])
        self._main_splitter = splitter
        self._left_collapsed = False

        # Custom grip handle with three dots
        handle = splitter.handle(1)
        handle.setCursor(Qt.CursorShape.SplitHCursor)
        handle_layout = QVBoxLayout(handle)
        handle_layout.setContentsMargins(0, 0, 0, 0)
        handle_layout.addStretch()
        dots = QLabel("⋮")
        dots.setStyleSheet(
            "color: #6e7681; font-size: 14px; background: transparent;"
        )
        dots.setAlignment(Qt.AlignmentFlag.AlignCenter)
        handle_layout.addWidget(dots)
        handle_layout.addStretch()

        # Double-click handle to toggle collapse
        handle.mouseDoubleClickEvent = lambda e: self._toggle_left_panel()

        splitter.splitterMoved.connect(self._on_splitter_moved)

        root.addWidget(splitter, 1)

        # Live stats bar
        stats_bar = QWidget()
        stats_bar.setFixedHeight(28)
        stats_bar.setStyleSheet(
            "background:#010409; border-top:1px solid #21262d;")
        sbl = QHBoxLayout(stats_bar)
        sbl.setContentsMargins(10, 0, 12, 0)
        sbl.setSpacing(0)

        _s = "color:#6e7681; font-size:12px; font-family:Consolas; background:transparent;"

        sbl.addStretch()

        # Uptime
        self._stat_up = QLabel("Up: —")
        self._stat_up.setStyleSheet(_s)
        sbl.addWidget(self._stat_up)
        sbl.addSpacing(18)

        # Load
        self._stat_load = QLabel("Load: —")
        self._stat_load.setStyleSheet(_s)
        sbl.addWidget(self._stat_load)
        sbl.addSpacing(18)

        # RAM
        self._stat_mem = QLabel("RAM: —")
        self._stat_mem.setStyleSheet(_s)
        sbl.addWidget(self._stat_mem)
        sbl.addSpacing(18)

        # Disk /u01 with progress bar
        disk_lbl = QLabel("/u01")
        disk_lbl.setStyleSheet(_s)
        sbl.addWidget(disk_lbl)
        sbl.addSpacing(5)

        self._stat_disk_bar = QProgressBar()
        self._stat_disk_bar.setFixedSize(72, 8)
        self._stat_disk_bar.setTextVisible(False)
        self._stat_disk_bar.setRange(0, 100)
        self._stat_disk_bar.setValue(0)
        self._stat_disk_bar.setStyleSheet(
            "QProgressBar{border:none;background:#21262d;border-radius:3px;}"
            "QProgressBar::chunk{background:#1f6feb;border-radius:3px;}")
        sbl.addWidget(self._stat_disk_bar)
        sbl.addSpacing(5)

        self._stat_disk_lbl = QLabel("—")
        self._stat_disk_lbl.setStyleSheet(_s)
        sbl.addWidget(self._stat_disk_lbl)

        self._last_tab_idx: int = -1
        root.addWidget(stats_bar)

    # ── Window geometry persistence ────────────────────────────────────────

    _SFTP_PANEL_WIDTH = 250

    def _on_splitter_moved(self, pos, index):
        self._left_collapsed = (self._main_splitter.sizes()[0] == 0)

    def _toggle_left_panel(self):
        sizes = self._main_splitter.sizes()
        total = sum(sizes)
        if sizes[0] > 0:
            self._left_collapsed = True
            self._main_splitter.setSizes([0, total])
        else:
            self._left_collapsed = False
            self._main_splitter.setSizes(
                [self._SFTP_PANEL_WIDTH, total - self._SFTP_PANEL_WIDTH])

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if not self._left_collapsed:
            total = sum(self._main_splitter.sizes())
            if total > 0:
                self._main_splitter.setSizes(
                    [self._SFTP_PANEL_WIDTH, total - self._SFTP_PANEL_WIDTH])
        state = self.windowState()
        # Save normal geometry only when not minimized/maximized
        if not (state & (Qt.WindowState.WindowMinimized
                         | Qt.WindowState.WindowMaximized)):
            if not self._is_minimized:
                self._saved_geometry = self.saveGeometry()

    def moveEvent(self, event):
        super().moveEvent(event)
        state = self.windowState()
        if not (state & (Qt.WindowState.WindowMinimized
                         | Qt.WindowState.WindowMaximized)):
            if not self._is_minimized:
                self._saved_geometry = self.saveGeometry()

    def showEvent(self, event):
        super().showEvent(event)
        # Capture initial geometry (includes screen position) once laid out
        if self._saved_geometry is None:
            QTimer.singleShot(0, self._snapshot_geometry)

    def _snapshot_geometry(self):
        """Save geometry only when in normal (non-minimized/maximized) state."""
        state = self.windowState()
        if not (state & (Qt.WindowState.WindowMinimized
                         | Qt.WindowState.WindowMaximized)):
            self._saved_geometry = self.saveGeometry()

    def changeEvent(self, event):
        if event.type() == event.Type.WindowStateChange:
            old_state = event.oldState()
            new_state = self.windowState()
            now_minimized = bool(new_state & Qt.WindowState.WindowMinimized)

            if now_minimized and not self._is_minimized:
                # Entering minimized — remember if we WERE maximized
                self._was_maximized = bool(
                    old_state & Qt.WindowState.WindowMaximized)
                # Save the screen the window was on before minimizing
                self._pre_minimize_screen = self.screen()
                # Save geometry so non-maximized windows restore to correct monitor
                if not self._was_maximized:
                    self._saved_geometry = self.saveGeometry()
                    self._saved_geo_rect = self.geometry()
                self._is_minimized = True
            elif self._is_minimized and not now_minimized:
                # Leaving minimized — restore previous window state on the
                # correct monitor (Windows tends to restore to primary screen)
                self._is_minimized = False
                if self._was_maximized:
                    target_screen = getattr(self, '_pre_minimize_screen', None)
                    def _restore_maximized(scr=target_screen):
                        if scr is not None:
                            geo = scr.availableGeometry()
                            self.setGeometry(geo)
                        self.showMaximized()
                    QTimer.singleShot(0, _restore_maximized)
                elif getattr(self, '_saved_geo_rect', None) is not None:
                    QTimer.singleShot(0,
                        lambda g=self._saved_geo_rect: self.setGeometry(g))
        super().changeEvent(event)

    # ── Session management ─────────────────────────────────────────────────

    def _add_first_session(self):
        label = self._machine.ip
        if self._machine.name:
            label += f"  ({self._machine.name})"
        port = getattr(self._machine, '_ssh_port', 22)
        user = self._cred.login if self._cred else ''
        password = self._cred.password if self._cred else ''
        self._add_session(label=label, ip=self._machine.ip,
                          user=user, password=password,
                          is_first=True, port=port)

    def _add_session(self, label: str = '', ip: str = '',
                     user: str = '', password: str = '',
                     is_first: bool = False, port: int = 22):
        if not ip:
            if not self._cred:
                return
            ip, user, password = (self._machine.ip,
                                  self._cred.login, self._cred.password)
        if not label:
            label = f"Sesja {len(self._sessions) + 1}"

        term = TerminalWidget()
        pane = _TerminalPane(term, label)
        pane.set_multiexec_header(self._multiexec)

        cols, rows = term.terminal_size()
        worker = _SshWorker(ip, user, password, cols, rows, port=port)

        # Session created before signal connections so lambdas can capture it.
        # resize_pty uses session.worker so it stays correct after retry.
        session = _Session(pane, worker, label)

        term.char_input.connect(
            lambda data, t=term: self._on_key(data, t))
        term.resize_pty.connect(
            lambda c, r, s=session: self._resize_pty_worker(s.worker, c, r))

        pane.retry_requested.connect(
            lambda s=session: self._retry_session(s))
        pane.close_requested.connect(
            lambda s=session: self._close_session_by_ref(s))

        self._connect_worker(worker, term, pane, ip, user, is_first, session)
        term.feed(f"\x1b[90mŁączenie z {ip}…\x1b[0m\r\n")
        worker.start()

        self._sessions.append(session)
        if self._multiexec:
            self._rebuild_grid()
        else:
            self._tab_widget.addTab(pane, label)
            self._tab_widget.setCurrentIndex(self._tab_widget.count() - 1)

        QTimer.singleShot(150, term.setFocus)

    def _auto_close_session(self, worker: '_SshWorker'):
        """Invoked when a worker's SSH session ends — shows disconnect banner then closes tab."""
        for s in self._sessions:
            if s.worker is worker:
                if s.pane._error_mode:
                    return   # error shown in terminal — user decides with R / Esc
                ts = datetime.now().strftime('%H:%M:%S')
                s.term.feed(
                    f"\r\n\x1b[33m─── Rozłączono [{ts}] ─────────────────────\x1b[0m\r\n")
                QTimer.singleShot(600, lambda ref=s: self._close_session_by_ref(ref))
                return
        self._status("Sesja SSH zakończona.")

    def _on_tab_moved(self, from_idx: int, to_idx: int):
        """Keep _sessions list in sync when user drags tabs."""
        if 0 <= from_idx < len(self._sessions) and 0 <= to_idx < len(self._sessions):
            s = self._sessions.pop(from_idx)
            self._sessions.insert(to_idx, s)
            # Update last_tab_idx to follow the moved tab
            self._last_tab_idx = self._tab_widget.currentIndex()

    def _on_tab_changed(self, idx: int):
        """Update environment panel + SFTP panel when active terminal tab changes."""
        if self._multiexec:
            return
        # Save SFTP state of the tab we're leaving
        prev = self._last_tab_idx
        if 0 <= prev < len(self._sessions):
            self._sessions[prev].sftp_path = self._sftp_panel._path
            self._sessions[prev].sftp_history = list(self._sftp_panel._history)
        self._last_tab_idx = idx

        if idx < 0 or idx >= len(self._sessions):
            self._env_panel.set_active('')
            self._sftp_panel.switch_sftp(None, None)
            return
        s = self._sessions[idx]
        self._env_panel.set_active(s.worker._host)
        self._sftp_panel.switch_sftp(s.sftp, s.sftp_client, s.sftp_path,
                                     s.sftp_history)
        # Immediately show cached stats for this session (no wait for next poll)
        if s.last_stats:
            self._update_stats_display(*s.last_stats)
        else:
            self._clear_stats_display()

    def _prompt_new_session(self):
        """Show dialog to create a new SSH session with custom credentials."""
        dlg = _AddSessionDialog(parent=self)
        if dlg.exec():
            ip, user, password, port = dlg.get_values()
            label = f"{user}@{ip}"
            self._add_session(label=label, ip=ip, user=user, password=password, port=port)

    def _open_extra_machine(self, machine):
        """Connect button in Environment tab → new session tab.

        Missing/empty credentials → open session with blank auth; the SSH
        worker will prompt for Login/Password directly in the terminal.
        """
        vis_creds = machine.credentials if self._admin_unlocked else [
            c for c in machine.credentials if not c.admin_only]
        cred = vis_creds[0] if vis_creds else None
        label = machine.ip + (f"  ({machine.name})" if machine.name else "")
        self._add_session(label=label, ip=machine.ip,
                          user=cred.login if cred else '',
                          password=cred.password if cred else '')

    def _open_machine_with_cred(self, machine, cred):
        """Connect to a machine with a specific credential (from context menu)."""
        label = machine.ip + (f"  ({machine.name})" if machine.name else "")
        label += f"  [{cred.login}]"
        self._add_session(label=label, ip=machine.ip,
                          user=cred.login, password=cred.password)

    def _teardown_session(self, s: '_Session'):
        """Release all memory held by a session (worker + pyte scrollback).

        Used by both single-tab close and full-window close paths so that
        closing the SSH window actually frees scrollback (50k lines × n sessions).
        """
        try:
            s.worker.output.disconnect()
            s.worker.error.disconnect()
            s.worker.connected.disconnect()
            s.worker.done.disconnect()
        except Exception:
            pass
        try:
            if s.sftp:        s.sftp.close()
            if s.sftp_client: s.sftp_client.close()
        except Exception:
            pass
        if s.stats_worker:
            try: s.stats_worker.stats.disconnect()
            except Exception: pass
            s.stats_worker.stop()
        if hasattr(s.worker, '_pw'):
            s.worker._pw = None
        s.worker._channel = None
        s.worker._client = None
        term = s.pane.term
        try: term.char_input.disconnect()
        except Exception: pass
        try: term.resize_pty.disconnect()
        except Exception: pass
        if term._screen:
            try:
                term._screen.buffer.clear()
                term._screen._soft_wrapped.clear()
            except Exception:
                pass
            term._screen.history.top.clear()
            term._screen.history.bottom.clear()
            term._screen.reset()
            term._screen = None
        term._hist_cache = None
        term._stream = None
        term._pending_data.clear()
        s.sftp_history.clear()
        s.last_stats = None

    def _close_session(self, idx: int):
        """Stop and remove one terminal session tab."""
        if idx < 0 or idx >= len(self._sessions):
            return
        s = self._sessions.pop(idx)
        s.worker.stop()
        self._teardown_session(s)
        # Remove from whichever container currently holds it
        if not self._multiexec:
            self._tab_widget.removeTab(idx)
            s.pane.setParent(None)
        else:
            self._rebuild_grid()
        s.pane.deleteLater()
        s.worker.wait(500)
        # Force garbage collection to reclaim memory immediately
        import gc; gc.collect()

    # ── Multi-exec ────────────────────────────────────────────────────────

    def _toggle_multiexec(self, active: bool):
        self._multiexec = active
        for s in self._sessions:
            s.pane.set_multiexec_header(active)
        if active:
            self._rebuild_grid()
            self._mode_stack.setCurrentIndex(1)
        else:
            self._rebuild_tabs()
            self._mode_stack.setCurrentIndex(0)

    def _rebuild_grid(self):
        # Pull panes out of tab widget — removeTab hides them, so we must
        # explicitly reparent to None and then show() after addWidget().
        while self._tab_widget.count():
            w = self._tab_widget.widget(0)
            self._tab_widget.removeTab(0)
            if w:
                w.setParent(None)
        while self._grid_layout.count():
            item = self._grid_layout.takeAt(0)
            if item and item.widget():
                item.widget().setParent(None)

        n = len(self._sessions)
        n_rows = max(1, (n + 1) // 2)

        for i, s in enumerate(self._sessions):
            r, c = divmod(i, 2)
            self._grid_layout.addWidget(s.pane, r, c)
            s.pane.show()

        # Equal stretch — every row and both columns get the same share
        for r in range(n_rows):
            self._grid_layout.setRowStretch(r, 1)
        # Reset any extra rows from previous builds
        for r in range(n_rows, n_rows + 4):
            self._grid_layout.setRowStretch(r, 0)
        self._grid_layout.setColumnStretch(0, 1)
        self._grid_layout.setColumnStretch(1, 1)

    def _rebuild_tabs(self):
        while self._grid_layout.count():
            item = self._grid_layout.takeAt(0)
            if item and item.widget():
                item.widget().setParent(None)
        while self._tab_widget.count():
            self._tab_widget.removeTab(0)
        for s in self._sessions:
            self._tab_widget.addTab(s.pane, s.label)
            s.pane.show()

    # ── Input ─────────────────────────────────────────────────────────────

    def _on_key(self, data: bytes, source_term: TerminalWidget):
        if not self._multiexec:
            for s in self._sessions:
                if s.term is source_term:
                    s.worker.send(data)
                    return
        else:
            for s in self._sessions:
                if not s.excluded:
                    s.worker.send(data)

    def _clear_current(self):
        idx = self._tab_widget.currentIndex()
        if 0 <= idx < len(self._sessions):
            s = self._sessions[idx]
            s.term.clear()
            # Re-display connection banner
            ip   = s.worker._host
            user = s.worker._user
            banner = self._make_connect_banner(ip, user)
            # Replace the "Łączenie…" placeholder with "Połączono"
            banner = banner.replace(
                '\x1b[90mŁączenie…\x1b[0m\r\n',
                f'\x1b[32mPołączono z {ip}\x1b[0m\r\n')
            s.term.feed(banner)
            # Send Ctrl+L so the server redraws the prompt
            s.worker.send(b'\x0c')

    # ── SSH / PTY ─────────────────────────────────────────────────────────

    def _on_ssh_error(self, msg: str):
        if self._sessions:
            self._sessions[0].term.feed(f"\x1b[31mBłąd SSH: {msg}\x1b[0m\r\n")
        self._status(f"Błąd SSH: {msg}", err=True)

    # ── Connection helpers ─────────────────────────────────────────────────

    def _connect_worker(self, worker: _SshWorker, term: TerminalWidget,
                        pane: _TerminalPane, ip: str, user: str,
                        is_first: bool, session: '_Session | None' = None):
        """Wire up all signals for a (new or retried) SSH worker."""
        worker.output.connect(lambda text, t=term: t.feed(_colorize_log(text)))
        worker.done.connect(lambda w=worker: self._auto_close_session(w))
        # Overwrite "Łączenie z ip…" line with success message
        worker.connected.connect(
            lambda t=term, i=ip: t.feed(
                f"\r\x1b[A\x1b[2K\x1b[32mPołączono z {i}\x1b[0m\r\n"))
        if session is not None:
            # Re-send correct PTY size after channel is open — terminal_size()
            # called before layout returns 80x24, which may be dropped if the
            # channel wasn't ready yet.  This guarantees COLUMNS matches display.
            worker.connected.connect(
                lambda s=session: self._resize_pty_worker(
                    s.worker, *s.pane.term.terminal_size()))
            worker.connected.connect(lambda s=session: self._start_session_stats(s))
            worker.connected.connect(lambda s=session: self._connect_sftp_for_session(s))
        worker.error.connect(
            lambda e, p=pane, f=is_first: self._on_session_error(e, p, f))

    def _on_session_error(self, msg: str, pane: _TerminalPane, is_first: bool):
        pane.term.feed(f"\x1b[31m✗ Błąd połączenia: {msg}\x1b[0m\r\n")
        pane.show_error(msg)
        if is_first:
            self._status(f"Błąd połączenia: {msg}", err=True)

    def _make_connect_banner(self, ip: str, user: str) -> str:
        ts = datetime.now().strftime('%H:%M:%S')
        return (
            f"\x1b[36m─── SSH ────────────────────────────────\x1b[0m\r\n"
            f"  \x1b[90mHost: \x1b[0m\x1b[1;97m{ip}\x1b[0m\r\n"
            f"  \x1b[90mLogin:\x1b[0m \x1b[93m{user}\x1b[0m\r\n"
            f"  \x1b[90mTime: \x1b[0m\x1b[90m{ts}\x1b[0m\r\n"
            f"\x1b[36m────────────────────────────────────────\x1b[0m\r\n"
            f"\x1b[90mŁączenie…\x1b[0m\r\n"
        )

    def _retry_session(self, session: '_Session'):
        """Stop the failed worker, create a fresh one, reconnect all signals."""
        old_worker = session.worker
        ip, user, pw, port = old_worker._host, old_worker._user, old_worker._pw, old_worker._port

        old_worker.stop()
        try:
            old_worker.output.disconnect()
            old_worker.error.disconnect()
            old_worker.connected.disconnect()
            old_worker.done.disconnect()
        except Exception:
            pass
        old_worker.wait(500)

        if session.stats_worker:
            session.stats_worker.stop()
            session.stats_worker.wait(300)
            session.stats_worker = None

        term = session.term
        pane = session.pane
        term.clear()
        pane.show_terminal()

        cols, rows = term.terminal_size()
        new_worker = _SshWorker(ip, user, pw, cols, rows, port=port)
        session.worker = new_worker   # resize_pty lambda reads session.worker → stays correct

        is_first = bool(self._sessions) and self._sessions[0] is session
        self._connect_worker(new_worker, term, pane, ip, user, is_first, session)
        term.feed(f"\x1b[90mŁączenie z {ip}…\x1b[0m\r\n")
        new_worker.start()

    def _close_session_by_ref(self, session: '_Session'):
        """Close a session by object reference (safe after index shifts)."""
        try:
            idx = self._sessions.index(session)
        except ValueError:
            return
        self._close_session(idx)

    def _resize_pty_worker(self, worker: _SshWorker, cols: int, rows: int):
        if worker and worker._channel and not worker._channel.closed:
            try:
                worker._channel.resize_pty(width=cols, height=rows)
            except Exception:
                pass

    # ── SFTP ──────────────────────────────────────────────────────────────

    def _connect_sftp_for_session(self, session: '_Session'):
        """Start an SFTP connection for a session; called when SSH connects."""
        w = _SftpConnectWorker(
            session.worker._host, session.worker._user, session.worker._pw,
            session.worker._port)
        w.ready.connect(lambda sftp, client, s=session: self._on_sftp_ready(s, sftp, client))
        w.error.connect(lambda e: self._status(f"Błąd SFTP: {e}", err=True))
        w.start()
        self._workers.append(w)

    def _on_sftp_ready(self, session: '_Session', sftp, client):
        session.sftp        = sftp
        session.sftp_client = client
        # Show in panel only if this session is currently active
        active = self._active_session()
        if active is session:
            self._sftp_panel.switch_sftp(sftp, client, session.sftp_path,
                                             session.sftp_history)

    def _active_session(self) -> '_Session | None':
        if self._multiexec:
            return self._sessions[0] if self._sessions else None
        idx = self._tab_widget.currentIndex()
        if 0 <= idx < len(self._sessions):
            return self._sessions[idx]
        return None

    # ── Live stats ────────────────────────────────────────────────────────

    def _start_session_stats(self, session: '_Session'):
        if session.stats_worker:
            return
        w = _StatsWorker(session.worker, interval=5)
        session.stats_worker = w
        # Each worker is permanently wired to its session — no reconnect on tab switch.
        # The handler caches the value in session.last_stats and updates the UI
        # only when this session is the active one.
        w.stats.connect(
            lambda load, mem, up, disk, s=session:
                self._on_stats_for_session(s, load, mem, up, disk))
        w.start()

    def _on_stats_for_session(self, session: '_Session',
                               load: str, mem: str, uptime: str, disk: str):
        """Receive a stats poll result: cache it in the session, update UI if active."""
        session.last_stats = (load, mem, uptime, disk)
        if self._active_session() is session:
            self._update_stats_display(load, mem, uptime, disk)

    def _clear_stats_display(self):
        _base = "font-size:12px; font-family:Consolas; background:transparent;"
        self._stat_load.setText("Load: —")
        self._stat_load.setStyleSheet(f"color:#6e7681; {_base}")
        self._stat_mem.setText("RAM: —")
        self._stat_mem.setStyleSheet(f"color:#6e7681; {_base}")
        self._stat_up.setText("Up: —")
        self._stat_disk_bar.setValue(0)
        self._stat_disk_bar.setStyleSheet(
            "QProgressBar{border:none;background:#21262d;border-radius:3px;}"
            "QProgressBar::chunk{background:#1f6feb;border-radius:3px;}")
        self._stat_disk_lbl.setText("—")
        self._stat_disk_lbl.setStyleSheet(f"color:#6e7681; {_base}")

    def _update_stats_display(self, load: str, mem: str, uptime: str, disk: str):
        _base = "font-size:12px; font-family:Consolas; background:transparent;"

        # Load
        try:
            val = float(load)
            lc  = "#8ae234" if val < 1.0 else "#fce94f" if val < 3.0 else "#ef2929"
        except ValueError:
            lc  = "#6e7681"
        self._stat_load.setText(f"Load: {load}")
        self._stat_load.setStyleSheet(f"color:{lc}; {_base}")

        # RAM
        parts = mem.split('/')
        if len(parts) == 2:
            try:
                used, total = int(parts[0]), int(parts[1])
                pct = int(used * 100 / total) if total else 0
                mc  = "#8ae234" if pct < 60 else "#fce94f" if pct < 85 else "#ef2929"
            except ValueError:
                mc  = "#6e7681"
            self._stat_mem.setText(f"RAM: {parts[0]}/{parts[1]} MB")
            self._stat_mem.setStyleSheet(f"color:{mc}; {_base}")
        else:
            self._stat_mem.setText(f"RAM: {mem}")

        # Uptime
        self._stat_up.setText(f"Up: {uptime}")

        # Disk
        if disk:
            try:
                dp  = disk.split()
                pct = int(dp[0])
                dc  = "#8ae234" if pct < 60 else "#fce94f" if pct < 85 else "#ef2929"
                self._stat_disk_bar.setValue(pct)
                self._stat_disk_bar.setStyleSheet(
                    f"QProgressBar{{border:none;background:#21262d;border-radius:3px;}}"
                    f"QProgressBar::chunk{{background:{dc};border-radius:3px;}}")
                self._stat_disk_lbl.setText(f"{pct}%")
                self._stat_disk_lbl.setStyleSheet(f"color:{dc}; {_base}")
            except (ValueError, IndexError):
                self._stat_disk_bar.setValue(0)
                self._stat_disk_lbl.setText("n/d")
                self._stat_disk_lbl.setStyleSheet(f"color:#6e7681; {_base}")
        else:
            self._stat_disk_bar.setValue(0)
            self._stat_disk_lbl.setText("n/d")
            self._stat_disk_lbl.setStyleSheet(f"color:#6e7681; {_base}")

    # ── Helpers ───────────────────────────────────────────────────────────

    def _status(self, text: str, err: bool = False):
        pass  # status bar removed — errors visible in terminal

    def closeEvent(self, event):
        for s in self._sessions:
            s.worker.stop()
        for s in self._sessions:
            s.worker.wait(1000)
            self._teardown_session(s)
        self._sessions.clear()
        self._sftp_panel.stop()
        for w in self._workers:
            if w.isRunning():
                w.wait(800)
        # Clean up temp SFTP files
        import shutil
        tmp_dir = os.path.join(tempfile.gettempdir(),
                               f'HospitalHub_{os.getpid()}')
        if os.path.isdir(tmp_dir):
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass
        # Remove from alive list so GC can collect
        try:
            SshDialog._alive.remove(self)
        except ValueError:
            pass
        import gc; gc.collect()
        super().closeEvent(event)
