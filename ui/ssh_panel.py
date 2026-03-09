# Copyright © 2026 Sebastian Bąk. All rights reserved.

import hashlib
import json
import os
import queue as _queue
import re
import stat
import tempfile
import threading
from datetime import datetime

# ──────────────────────────────────────── Log colorizer ──────────────────────

_ANSI_PRESENT   = re.compile(r'\x1b\[')
_STACK_TRACE_RE = re.compile(r'^\s+at\s+[\w$.]+\(')   # Java: "    at pkg.Class.method("

_LOG_RULES = [
    # Errors — red bold
    (re.compile(r'\b(ERROR|FATAL|CRITICAL|FAIL(?:ED)?|EXCEPTION|SEVERE)\b'),
     '\x1b[1;31m'),
    # "Caused by:" (Java stack trace header) — red bold, matched case-sensitively
    (re.compile(r'(Caused by:)'),
     '\x1b[1;31m'),
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
    # Maven/Gradle build result — override with specific color per word
    (re.compile(r'\b(BUILD SUCCESS(?:FUL)?)\b'),
     '\x1b[1;32m'),
    (re.compile(r'\b(BUILD FAIL(?:URE|ED)?)\b'),
     '\x1b[1;31m'),
    # Docker image/container lifecycle
    (re.compile(r'\b(Pulling|Pulled|Pushing|Pushed|Building|Built|Created|Removed)\b'),
     '\x1b[0;36m'),
    # IPv4 addresses — bright cyan
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
     '\x1b[0;96m'),
    # CLI flags: -x  --long-flag  --key=value — bright yellow
    (re.compile(r'(?:(?<=\s)|(?<=^))(--?[a-zA-Z][\w\-=.]*)'),
     '\x1b[0;93m'),
]

def _colorize_log(text: str) -> str:
    """Add ANSI keyword highlighting to plain-text log lines."""
    lines = text.split('\n')
    for i, line in enumerate(lines):
        if _ANSI_PRESENT.search(line):
            continue   # already colored (e.g. shell prompt sequences)
        # Java stack trace lines get the whole line dimmed
        if _STACK_TRACE_RE.match(line):
            lines[i] = f'\x1b[2;37m{line}\x1b[0m'
            continue
        for pat, color in _LOG_RULES:
            line = pat.sub(lambda m, c=color: f'{c}{m.group()}\x1b[0m', line)
        lines[i] = line
    return '\n'.join(lines)

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QSplitter, QWidget,
    QPushButton, QLabel, QApplication,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QFileDialog, QProgressBar, QMenu, QInputDialog, QMessageBox,
    QLineEdit, QTabWidget, QStackedWidget, QScrollArea,
    QCheckBox, QGroupBox, QGridLayout, QFrame, QFormLayout, QSizePolicy,
    QScrollBar,
)
from PyQt6.QtCore import Qt, QThread, QTimer, QSize, QEvent, pyqtSignal, QMimeData, QUrl
from PyQt6.QtGui import QFont, QFontInfo, QFontMetricsF, QColor, QPainter, QKeySequence, QDesktopServices

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
        _ALT_SCREEN = 1049  # DECSET 1049: alternate screen buffer

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
            """xterm/PuTTY cursor-relative resize — no row is ever lost or
            unnecessarily pushed to scrollback.

            Previous attempts failed because they called Screen.resize() which
            always runs delete_lines(N) from row 0 — destroying content
            unconditionally — or saved the top-N rows blindly (causing content
            to accumulate in history on every expand/shrink cycle even when
            the cursor never moved).

            Correct algorithm (verified by automated tests):
              SHRINK — only scroll rows to history if the cursor would fall
                       outside the new viewport.
                       n_scroll = max(0, cursor.y − (new_lines − 1))
                       If cursor fits (typical: cursor near top, lots of empty
                       space below) → zero rows pushed, buffer untouched, only
                       self.lines decremented.  No phantom history accumulation.
              EXPAND — just increase self.lines; existing rows stay in place,
                       new empty rows appear at the bottom.  Shell repaints
                       via SIGWINCH.  History is never touched on expand.
            """
            lines   = lines   or self.lines
            columns = columns or self.columns
            if lines == self.lines and columns == self.columns:
                return

            if lines < self.lines:
                # How many top rows must scroll off to keep cursor in view?
                n_scroll = max(0, self.cursor.y - (lines - 1))
                if n_scroll > 0:
                    # Save to scrollback, then shift buffer up.
                    for y in range(n_scroll):
                        self.history.top.append(self.buffer[y])
                    for y in range(self.lines - n_scroll):
                        self.buffer[y] = self.buffer[y + n_scroll]
                    for y in range(self.lines - n_scroll, self.lines):
                        self.buffer.pop(y, None)
                    self.cursor.y -= n_scroll
                # Clamp cursor to new bounds.
                self.cursor.y = min(self.cursor.y, lines - 1)
                self.cursor.x = min(self.cursor.x, columns - 1)
            # else: expanding — buffer unchanged, new empty rows appear at bottom.

            # Trim columns if narrowing.
            if columns < self.columns:
                for line in self.buffer.values():
                    for x in range(columns, self.columns):
                        line.pop(x, None)

            self.lines   = lines
            self.columns = columns
            self.dirty.update(range(lines))
            self.set_margins()

        def erase_in_display(self, how=0, **kwargs):
            # Full-screen clear (e.g. \x1b[2J from `clear` or first `top` frame)
            # while NOT already inside the alternate screen → save to history first.
            if how in (2, 3) and self._ALT_SCREEN not in self.mode:
                self._push_visible_to_history()
            super().erase_in_display(how, **kwargs)

        def set_mode(self, *modes, **kwargs):
            # Entering alternate screen (\x1b[?1049h) → save main screen to history.
            if kwargs.get("private") and self._ALT_SCREEN in modes:
                if self._ALT_SCREEN not in self.mode:
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
}
_DEFAULT_FG = '#c9d1d9'
_DEFAULT_BG = '#0d1117'


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

    _SCROLLBACK = 50_000   # ~200 MB worst-case; render uses O(1) list cache

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
        # list() snapshot of history.top — rebuilt once per scroll gesture so
        # deque[idx] (O(n)) is replaced with list[idx] (O(1)) during rendering.
        self._hist_cache: list | None = None

        # Mouse selection
        self._sel_start: tuple | None = None   # (col, vrow) in visual space
        self._sel_end:   tuple | None = None
        self._selecting  = False

    # ── Public API ────────────────────────────────────────────────────────

    def feed(self, data: str):
        if self._stream:
            self._stream.feed(data)
        self._scroll_offset = 0   # auto-scroll to bottom on new output
        self._hist_cache    = None  # new rows may have scrolled into history
        self._cur_vis = True
        self._blink.start(530)
        self.update()
        self._emit_scroll()

    def clear(self):
        if self._screen:
            self._screen.reset()
        self._scroll_offset = 0
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
        (sc, sr), (ec, er) = self._sel_start, self._sel_end
        if (sr, sc) > (er, ec):
            sc, sr, ec, er = ec, er, sc, sr
        if vrow < sr or vrow > er:
            return False
        if sr == er:
            return sc <= x <= ec
        if vrow == sr:
            return x >= sc
        if vrow == er:
            return x <= ec
        return True

    def _selected_text(self) -> str:
        if not self._sel_start or not self._sel_end:
            return ''
        (sc, sr), (ec, er) = self._sel_start, self._sel_end
        if (sr, sc) > (er, ec):
            sc, sr, ec, er = ec, er, sc, sr
        lines = []
        for vrow in range(sr, er + 1):
            row_data = self._get_row(vrow)
            c0 = sc if vrow == sr else 0
            c1 = ec if vrow == er else self._cols - 1
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

        for y in range(self._rows):
            row = self._get_row(y)
            py  = int(y * lh)
            for x in range(self._cols):
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

                rx     = int(x * cw)
                rw     = int(cw) + 1
                sel    = self._in_selection(x, y)
                is_cur = (offset == 0 and x == cx and y == cy and focused and self._cur_vis)

                if sel:
                    p.fillRect(rx, py, rw, int(lh) + 1, QColor('#264f78'))
                    draw_fg = '#ffffff'
                elif is_cur:
                    p.fillRect(rx, py, rw, int(lh) + 1, QColor(fg))
                    draw_fg = bg
                elif bg != _DEFAULT_BG:
                    p.fillRect(rx, py, rw, int(lh) + 1, QColor(bg))
                    draw_fg = fg
                else:
                    draw_fg = fg

                if char != ' ':
                    p.setFont(self._font_bold if bold else self._font)
                    p.setPen(QColor(draw_fg))
                    p.drawText(rx, int(py + asc), char)


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
            self._sel_start = (col, row)
            self._sel_end   = (col, row)
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
            col, row = self._cell_at_pos(event.position())
            self._sel_end = (col, row)
            self.update()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self._selecting:
            col, row = self._cell_at_pos(event.position())
            self._sel_end   = (col, row)
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


def _make_client(host: str, user: str, password: str) -> 'paramiko.SSHClient':
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(_TofuHostKeyPolicy())
    c.connect(
        host, port=22,
        username=user, password=password,
        timeout=12, banner_timeout=20,
        look_for_keys=False, allow_agent=False,
    )
    return c


class _SshWorker(QThread):
    output    = pyqtSignal(str)
    connected = pyqtSignal()
    error     = pyqtSignal(str)
    done      = pyqtSignal()

    def __init__(self, host, user, password, cols=220, rows=50):
        super().__init__()
        self._host, self._user, self._pw = host, user, password
        self._cols    = cols
        self._rows    = rows
        self._channel = None
        self._client  = None
        self._running = False
        # Thread-safe queue for outgoing data.  send() puts bytes here so the
        # worker drains it immediately on each loop tick — Ctrl+C reaches the
        # SSH channel within one iteration regardless of Qt event-queue depth.
        self._send_q: _queue.SimpleQueue[bytes] = _queue.SimpleQueue()

    def run(self):
        import time
        try:
            self._client  = _make_client(self._host, self._user, self._pw)
            # Open session manually so we can request X11 forwarding before
            # invoking the shell (invoke_shell() doesn't expose this).
            transport     = self._client.get_transport()
            self._channel = transport.open_session()
            self._channel.request_x11(screen_number=0, single_connection=False,
                                      handler=_x11_handler)
            self._channel.get_pty(term='xterm-256color',
                                  width=self._cols, height=self._rows)
            self._channel.invoke_shell()
            self.connected.emit()
            self._running = True
            while self._running:
                # ── Drain outgoing queue FIRST ────────────────────────────────
                # send() puts bytes here so Ctrl+C reaches the SSH channel
                # within one loop iteration regardless of Qt event-queue depth.
                # After b'\x03' we also fast-drain any recv backlog so the
                # display stops flooding immediately instead of up to seconds
                # later (tail -f / docker logs can buffer megabytes of output
                # that would otherwise keep flooding the screen).
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
                    # Drain recv backlog instantly (no sleep) so the loop
                    # finishes in < 1 ms — before the server's SIGINT response
                    # (^C echo + prompt) has time to arrive over the network.
                    # With sleep(0.002) inside, local-server RTT (~1 ms) meant
                    # the prompt arrived during drain and was discarded.
                    deadline = time.monotonic() + 0.5
                    while (time.monotonic() < deadline
                           and self._channel.recv_ready()):
                        self._channel.recv(65536)   # no sleep — drain fast
                    # Shell sends ^C echo + new prompt after processing SIGINT.
                    # Poll up to 500 ms (covers slow VPN servers) and emit
                    # everything that arrives so the prompt is shown immediately.
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

    def __init__(self, host, user, password):
        super().__init__()
        self._host, self._user, self._pw = host, user, password

    def run(self):
        try:
            c = _make_client(self._host, self._user, self._pw)
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
            entries = self._sftp.listdir_attr(self._path)
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
            self.listing.emit(self._path, result)
        except Exception as e:
            self.error.emit(str(e))


class _TransferWorker(QThread):
    progress = pyqtSignal(int)
    done     = pyqtSignal(str)
    error    = pyqtSignal(str)

    def __init__(self, sftp, mode, remote, local, total=0):
        super().__init__()
        self._sftp, self._mode = sftp, mode
        self._remote, self._local, self._total = remote, local, total

    def run(self):
        try:
            def cb(done, total):
                t = total or self._total or 1
                self.progress.emit(min(int(done * 100 / t), 100))

            if self._mode == 'get':
                self._sftp.get(self._remote, self._local, callback=cb)
                self.done.emit(f"Pobrano: {os.path.basename(self._local)}")
            else:
                self._sftp.put(self._local, self._remote, callback=cb)
                self.done.emit(f"Wgrano: {os.path.basename(self._local)}")
        except Exception as e:
            self.error.emit(str(e))


class _SimpleWorker(QThread):
    done  = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    def run(self):
        try:
            self._fn()
            self.done.emit()
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
        self._setup_ui()

        # Slow-double-click rename (click on already-selected row after a pause)
        self._rename_timer = QTimer(self)
        self._rename_timer.setSingleShot(True)
        self._rename_timer.setInterval(700)
        self._rename_timer.timeout.connect(self._do_pending_rename)
        self._pending_rename_item = None
        self._click_was_selected  = False
        self._rename_editor: QLineEdit | None = None
        self._rename_editor_data: dict | None = None
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

        self._path_lbl = QLabel("Nie połączono")
        self._path_lbl.setFont(QFont("Consolas", 9))
        self._path_lbl.setStyleSheet("color: #58a6ff; padding-left: 4px;")
        self._path_lbl.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        nav.addWidget(self._path_lbl, 1)
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
        self._table.setSortingEnabled(True)
        self._table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        self._table.doubleClicked.connect(self._on_dbl_click)
        self._table.itemSelectionChanged.connect(self._on_sel_change)
        self._table.setStyleSheet("""
            QTableWidget {
                background: #161b22;
                alternate-background-color: #1c2128;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 4px;
                gridline-color: transparent;
            }
            QTableWidget::item { padding: 3px 6px; }
            QTableWidget::item:selected {
                background: #1f6feb;
                color: #ffffff;
            }
            QHeaderView::section {
                background: #21262d;
                color: #8b949e;
                border: none;
                border-bottom: 1px solid #30363d;
                padding: 4px 6px;
                font-weight: bold;
            }
        """)
        root.addWidget(self._table, 1)

        # Drag & drop hint
        hint = QLabel("Upuść pliki tutaj aby wgrać  ⬆")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("color: #444; font-size: 10px; padding: 2px;")
        root.addWidget(hint)

        # Transfer buttons + progress
        xfer = QHBoxLayout()
        self._btn_dl = QPushButton("⬇  Pobierz")
        self._btn_dl.setEnabled(False)
        self._btn_dl.setStyleSheet(
            "QPushButton{background:#1a3a1a;color:#8ae234;border-radius:3px;padding:3px 8px;}"
            "QPushButton:hover{background:#2a4a2a;}"
            "QPushButton:disabled{color:#333;background:#111;}")
        self._btn_dl.clicked.connect(self._download)

        self._btn_ul = QPushButton("⬆  Wgraj")
        self._btn_ul.setEnabled(False)
        self._btn_ul.setStyleSheet(
            "QPushButton{background:#1a2a3a;color:#58a6ff;border-radius:3px;padding:3px 8px;}"
            "QPushButton:hover{background:#2a3a4a;}"
            "QPushButton:disabled{color:#333;background:#111;}")
        self._btn_ul.clicked.connect(self._upload_browse)

        self._progress = QProgressBar()
        self._progress.setVisible(False)
        self._progress.setFixedHeight(12)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet(
            "QProgressBar{border:none;background:#21262d;border-radius:3px;}"
            "QProgressBar::chunk{background:#1f6feb;border-radius:3px;}")

        xfer.addWidget(self._btn_dl)
        xfer.addWidget(self._btn_ul)
        xfer.addWidget(self._progress, 1)
        root.addLayout(xfer)

    def _nav_btn(self, text, tip, slot) -> QPushButton:
        b = QPushButton(text)
        b.setFixedSize(28, 28)
        b.setToolTip(tip)
        b.clicked.connect(slot)
        return b

    # ── Public API ────────────────────────────────────────────────────────

    def set_sftp(self, sftp, ssh_client):
        self._sftp = sftp
        self._ssh_client = ssh_client
        for b in (self._btn_up, self._btn_home, self._btn_ref, self._btn_ul):
            b.setEnabled(True)
        self._list('/')

    # ── Navigation ────────────────────────────────────────────────────────

    def _list(self, path: str):
        if not self._sftp:
            return
        self._path_lbl.setText(f"…  {path}")
        self._table.setSortingEnabled(False)
        w = _SftpListWorker(self._sftp, path)
        w.listing.connect(self._on_listing)
        w.error.connect(lambda e: self.status_msg.emit(f"SFTP: {e}", True))
        w.start()
        self._workers.append(w)

    def _on_listing(self, path: str, entries: list):
        self._path = path
        self._path_lbl.setText(path)
        self._table.setRowCount(0)

        for i, (name, is_dir, size, mtime, perms) in enumerate(entries):
            self._table.insertRow(i)

            # Col 0: name
            ni = QTableWidgetItem(("📁  " if is_dir else "📄  ") + name)
            ni.setData(Qt.ItemDataRole.UserRole, (name, is_dir, size))
            if is_dir:
                ni.setForeground(QColor("#58a6ff"))
            self._table.setItem(i, 0, ni)

            # Col 1: size (numeric sort)
            si = _NumItem("" if is_dir else _fmt_size(size))
            si.setData(Qt.ItemDataRole.UserRole, size)
            si.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._table.setItem(i, 1, si)

            self._table.setItem(i, 2, QTableWidgetItem(mtime))
            self._table.setItem(i, 3, QTableWidgetItem(perms))
            self._table.setRowHeight(i, 28)

        self._table.setSortingEnabled(True)
        self._table.sortItems(0, Qt.SortOrder.AscendingOrder)
        self._btn_dl.setEnabled(False)

    def eventFilter(self, obj, event):
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
        icon = "📁  " if is_dir else "📄  "
        self._table.blockSignals(True)
        item.setText(icon + new_name)
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
        if self._history:
            self._list(self._history.pop())
        else:
            parts = self._path.rstrip('/').split('/')
            parent = '/'.join(parts[:-1]) or '/'
            if parent != self._path:
                self._list(parent)

    def _on_sel_change(self):
        rows = self._table.selectedItems()
        if not rows:
            self._btn_dl.setEnabled(False)
            return
        item = self._table.item(rows[0].row(), 0)
        if item:
            _, is_dir, _ = item.data(Qt.ItemDataRole.UserRole)
            self._btn_dl.setEnabled(not is_dir)

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
        menu.addSeparator()
        menu.addAction("📋  Kopiuj ścieżkę", lambda r=remote: QApplication.clipboard().setText(r))
        menu.addSeparator()
        menu.addAction("✏️  Zmień nazwę", lambda ri=row_item: self._start_inline_rename(ri))
        menu.addAction("🗑️  Usuń", lambda: self._delete(remote, is_dir, name))
        menu.exec(self._table.viewport().mapToGlobal(pos))

    # ── Transfer ──────────────────────────────────────────────────────────

    def _download(self):
        rows = self._table.selectedItems()
        if not rows or not self._sftp:
            return
        item = self._table.item(rows[0].row(), 0)
        if not item:
            return
        name, _, size = item.data(Qt.ItemDataRole.UserRole)
        remote = self._path.rstrip('/') + '/' + name
        local, _ = QFileDialog.getSaveFileName(self, "Zapisz plik", name)
        if local:
            self._run_transfer('get', remote, local, size)

    def _upload_browse(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Wybierz pliki do wgrania")
        for p in paths:
            self._upload_file(p)

    def _upload_file(self, local: str):
        if not self._sftp or not os.path.isfile(local):
            return
        fname  = os.path.basename(local)
        remote = self._path.rstrip('/') + '/' + fname
        self._run_transfer('put', remote, local, os.path.getsize(local))

    def _run_transfer(self, mode, remote, local, size):
        self._progress.setValue(0)
        self._progress.setVisible(True)
        self._btn_dl.setEnabled(False)
        self._btn_ul.setEnabled(False)
        w = _TransferWorker(self._sftp, mode, remote, local, size)
        w.progress.connect(self._progress.setValue)
        w.done.connect(self._transfer_done)
        w.error.connect(lambda e: self.status_msg.emit(f"Transfer: {e}", True))
        w.done.connect(lambda _: self._list(self._path))
        w.start()
        self._workers.append(w)

    def _transfer_done(self, msg: str):
        self._progress.setVisible(False)
        self._btn_ul.setEnabled(True)
        self.status_msg.emit(msg, False)

    def _open_remote(self, remote: str, name: str):
        """Download to temp file, open with default app, watch for changes → auto-upload."""
        if not self._ssh_client:
            return
        # Use a dedicated subdir so the file keeps its original name (like WinSCP)
        tmp_dir  = os.path.join(tempfile.gettempdir(),
                                f'HospitalHub_{os.getpid()}')
        os.makedirs(tmp_dir, exist_ok=True)
        safe_name = os.path.basename(name) or 'file'   # strip any path components
        tmp_path  = os.path.join(tmp_dir, safe_name)
        ssh_client = self._ssh_client   # capture — each worker gets its own channel

        lock = self._sftp_open_lock

        def do_open():
            with lock:                          # serialize channel opens
                sftp = ssh_client.open_sftp()
            try:
                sftp.get(remote, tmp_path)
            finally:
                sftp.close()
            self._open_local.emit(tmp_path)
            size = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
            self._watch_file_sig.emit(tmp_path, remote, size)

        w = _SimpleWorker(do_open)
        w.error.connect(lambda e: self.status_msg.emit(f"Otwieranie: {e}", True))
        w.start()
        self._workers.append(w)

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

        def do_upload():
            with lock:
                sftp = ssh_client.open_sftp()
            try:
                sftp.put(local, remote)
            finally:
                sftp.close()

        def on_done(_=None):
            self._upload_active.discard(local)
            self.status_msg.emit(f"Zapisano na SFTP: {os.path.basename(remote)}", False)
            self._list(self._path)   # odśwież listę — pokaż aktualny rozmiar

        def on_error(e):
            self._upload_active.discard(local)
            self.status_msg.emit(f"Błąd zapisu: {e}", True)

        w = _SimpleWorker(do_upload)
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

        def do_delete():
            if is_dir:
                self._sftp.rmdir(remote)
            else:
                self._sftp.remove(remote)

        w = _SimpleWorker(do_delete)
        w.done.connect(lambda: self._list(self._path))
        w.error.connect(lambda e: self.status_msg.emit(f"Usuwanie: {e}", True))
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
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.isfile(path):
                self._upload_file(path)

    # ── Cleanup ───────────────────────────────────────────────────────────

    def switch_sftp(self, sftp, ssh_client, restore_path: str = '/'):
        """Swap active SFTP connection and restore the previous browsed path."""
        self._watch_poll.stop()
        self._watched_files.clear()
        self._upload_active.clear()
        self._sftp        = sftp
        self._ssh_client  = ssh_client
        connected = bool(sftp and ssh_client)
        for b in (self._btn_up, self._btn_home, self._btn_ref, self._btn_ul):
            b.setEnabled(connected)
        if connected:
            self._list(restore_path)
        else:
            self._path_lbl.setText("Nie połączono")
            self._table.setRowCount(0)

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
    """Minimalist machine list with dynamic highlight based on active terminal tab."""
    open_machine = pyqtSignal(object)

    _STYLE_IDLE = (
        "QFrame { background:#161b22; border:1px solid #30363d; border-radius:6px; }"
        "QLabel { border:none; background:transparent; }"
    )
    _STYLE_ACTIVE = (
        "QFrame { background:#1a2535; border:1px solid #1f6feb; border-radius:6px; }"
        "QLabel { border:none; background:transparent; }"
    )

    def __init__(self, hospital=None, initial_ip: str = '', parent=None):
        super().__init__(parent)
        self._cards: dict[str, QFrame] = {}   # ip → card widget
        self._active_ip: str = ''

        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        # Hospital badge
        badge = QLabel(f"🏥  <b>{hospital.name if hospital else '—'}</b>")
        badge.setTextFormat(Qt.TextFormat.RichText)
        badge.setStyleSheet(
            "color:#58a6ff; font-size:13px; padding:6px 4px 8px 4px;"
            "border-bottom:1px solid #30363d;"
        )
        root.addWidget(badge)

        if hospital and hospital.machines:
            section_lbl = QLabel("MASZYNY")
            section_lbl.setStyleSheet(
                "color:#6e7681; font-size:9px; letter-spacing:1px; padding:2px 2px 4px 2px;"
            )
            root.addWidget(section_lbl)

            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            scroll.setStyleSheet("background:transparent; border:none;")

            container = QWidget()
            container.setStyleSheet("background:transparent;")
            cl = QVBoxLayout(container)
            cl.setContentsMargins(0, 0, 4, 0)
            cl.setSpacing(2)

            for m in hospital.machines:
                card = QFrame()
                card.setFrameShape(QFrame.Shape.NoFrame)
                card.setStyleSheet(self._STYLE_IDLE)
                self._cards[m.ip] = card

                rl = QHBoxLayout(card)
                rl.setContentsMargins(8, 3, 6, 3)
                rl.setSpacing(6)

                # IP + name on one line
                if m.name:
                    line = (f"<span style='color:#58a6ff; font-size:10px;'>"
                            f"<b>{m.ip}</b></span>"
                            f"<span style='color:#c9d1d9; font-size:9px;'>"
                            f"  {m.name}</span>")
                else:
                    line = (f"<span style='color:#58a6ff; font-size:10px;'>"
                            f"<b>{m.ip}</b></span>")
                lbl = QLabel(line)
                lbl.setTextFormat(Qt.TextFormat.RichText)
                rl.addWidget(lbl, 1)

                if getattr(m, 'connection_type', 'SSH') == 'RDP':
                    btn = QPushButton("RDP")
                    btn.setFixedSize(34, 18)
                    btn.setToolTip(
                        f"Połącz przez Remote Desktop ({m.ip}:"
                        f"{getattr(m, 'rdp_port', '3389') or '3389'})"
                    )
                    btn.setStyleSheet(
                        "QPushButton { background:#2a1a35; color:#c084fc;"
                        " border:1px solid #6b3fa0; border-radius:3px;"
                        " font-size:9px; font-weight:bold; padding:0; }"
                        "QPushButton:hover { background:#7c3aed; color:#fff; }"
                    )
                    btn.clicked.connect(lambda _=False, _m=m: _connect_rdp(_m))
                else:
                    btn = QPushButton("⇆")
                    btn.setFixedSize(24, 18)
                    btn.setToolTip(f"Połącz z {m.ip}")
                    btn.setStyleSheet(
                        "QPushButton { background:#0f2535; color:#58a6ff;"
                        " border:1px solid #1f4a70; border-radius:3px;"
                        " font-size:11px; padding:0; }"
                        "QPushButton:hover { background:#1f6feb; color:#fff; }"
                    )
                    btn.clicked.connect(lambda _=False, _m=m: self.open_machine.emit(_m))
                rl.addWidget(btn)

                cl.addWidget(card)

            cl.addStretch()
            scroll.setWidget(container)
            root.addWidget(scroll, 1)
        else:
            root.addStretch()

        if initial_ip:
            self.set_active(initial_ip)

    def set_active(self, ip: str):
        """Highlight the card for ip, de-highlight the previous one.
        Pass empty string to clear all highlights."""
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
        self._hdr.setFixedHeight(22)
        self._hdr.setStyleSheet(
            "background:#161b22;border-bottom:1px solid #30363d;")
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
                 'stats_worker', 'last_stats')

    def __init__(self, pane: _TerminalPane, worker: '_SshWorker', label: str):
        self.pane         = pane
        self.worker       = worker
        self.label        = label
        self.sftp         = None
        self.sftp_client  = None
        self.sftp_path    = '/'
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
        self.setFixedSize(400, 210)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._ip_edit = QLineEdit(default_ip)
        self._ip_edit.setPlaceholderText("np. 192.168.1.100")
        form.addRow("Host / IP:", self._ip_edit)

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
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        btn_ok = QPushButton("Połącz")
        btn_ok.setDefault(True)
        btn_ok.setStyleSheet(
            "QPushButton { background:#1a3a1a; color:#8ae234;"
            " border:1px solid #2d5a1a; border-radius:4px; padding:4px 16px; }"
            "QPushButton:hover { background:#253d1a; color:#a0de4a; }"
        )
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
        return (
            self._ip_edit.text().strip(),
            self._user_edit.text().strip(),
            self._pass_edit.text(),
        )


# ──────────────────────────────────────── Main dialog ────────────────────────

_TAB_STYLE = """
    QTabWidget::pane  { border:1px solid #30363d; }
    QTabBar::tab      { background:#0d1117; color:#8b949e; padding:4px 12px;
                        border:1px solid #30363d; border-bottom:none;
                        font-size:11px; }
    QTabBar::tab:selected { background:#161b22; color:#c9d1d9; }
    QTabBar::tab:hover    { background:#161b22; }
    QTabBar::close-button { subcontrol-position: right; margin: 2px; }
    QTabBar::close-button:hover { background: rgba(220,60,60,80);
                                   border-radius: 2px; }
"""


class SshDialog(QDialog):
    def __init__(self, machine, hospital=None, parent=None):
        super().__init__(parent)
        self._machine  = machine
        self._hospital = hospital
        self._cred     = machine.credentials[0] if machine.credentials else None
        self._sessions: list[_Session] = []
        self._multiexec = False
        self._workers: list[QThread] = []

        title = f"Połączenie — {machine.ip}"
        if machine.name:
            title += f"  ({machine.name})"
        self.setWindowTitle(title)
        self.resize(1200, 700)
        self.setMinimumSize(1150, 640)

        self._setup_ui()

        if not _PARAMIKO_OK:
            self._status("Brak biblioteki paramiko. Zainstaluj: pip install paramiko", err=True)
            return
        if not self._cred:
            self._status("Brak poświadczeń dla tej maszyny.", err=True)
            return

        QTimer.singleShot(0, self._add_first_session)

    # ── UI ────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(4)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(4)
        splitter.setStyleSheet("QSplitter::handle { background: #30363d; }")

        # ── Left: SFTP + Environment tabs ──
        left_tabs = QTabWidget()
        left_tabs.setStyleSheet(_TAB_STYLE)

        self._sftp_panel = SftpPanel()
        self._sftp_panel.status_msg.connect(lambda t, e: self._status(t, err=e))
        left_tabs.addTab(self._sftp_panel, "📁  Pliki")

        self._env_panel = _EnvironmentPanel(
            self._hospital, initial_ip=self._machine.ip)
        self._env_panel.open_machine.connect(self._open_extra_machine)
        left_tabs.addTab(self._env_panel, "🖥  Środowisko")

        splitter.addWidget(left_tabs)

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
            "QPushButton{background:#1a2a3a;color:#58a6ff;"
            "border-radius:3px;padding:3px 8px;}"
            "QPushButton:checked{background:#1f6feb;color:#fff;}"
            "QPushButton:hover{background:#2a3a4a;}")
        self._btn_multiexec.toggled.connect(self._toggle_multiexec)

        btn_new = QPushButton("＋  Nowa sesja")
        btn_new.setStyleSheet(
            "QPushButton{background:#1a2a1a;color:#8ae234;"
            "border-radius:3px;padding:3px 8px;}"
            "QPushButton:hover{background:#2a3a2a;}")
        btn_new.clicked.connect(self._prompt_new_session)

        tb.addWidget(self._btn_multiexec)
        tb.addWidget(btn_new)
        tb.addStretch()
        tlay.addLayout(tb)

        # Mode stack: 0 = tabs, 1 = multi-exec grid
        self._mode_stack = QStackedWidget()

        self._tab_widget = QTabWidget()
        self._tab_widget.setStyleSheet(_TAB_STYLE)
        self._tab_widget.setTabsClosable(True)
        self._tab_widget.tabCloseRequested.connect(self._close_session)
        self._tab_widget.currentChanged.connect(self._on_tab_changed)
        self._mode_stack.addWidget(self._tab_widget)

        self._grid_container = QWidget()
        self._grid_container.setStyleSheet("background:#0d1117;")
        self._grid_layout = QGridLayout(self._grid_container)
        self._grid_layout.setContentsMargins(4, 4, 4, 4)
        self._grid_layout.setSpacing(4)
        self._mode_stack.addWidget(self._grid_container)

        tlay.addWidget(self._mode_stack, 1)
        splitter.addWidget(term_area)
        splitter.setSizes([320, 880])
        root.addWidget(splitter, 1)

        # Live stats bar
        stats_bar = QWidget()
        stats_bar.setFixedHeight(34)
        stats_bar.setStyleSheet(
            "background:#0d1117; border-top:1px solid #21262d;")
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

    # ── Session management ─────────────────────────────────────────────────

    def _add_first_session(self):
        label = self._machine.ip
        if self._machine.name:
            label += f"  ({self._machine.name})"
        self._add_session(label=label, ip=self._machine.ip,
                          user=self._cred.login, password=self._cred.password,
                          is_first=True)

    def _add_session(self, label: str = '', ip: str = '',
                     user: str = '', password: str = '',
                     is_first: bool = False):
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
        worker = _SshWorker(ip, user, password, cols, rows)

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

    def _on_tab_changed(self, idx: int):
        """Update environment panel + SFTP panel when active terminal tab changes."""
        if self._multiexec:
            return
        # Save SFTP path of the tab we're leaving
        prev = self._last_tab_idx
        if 0 <= prev < len(self._sessions):
            self._sessions[prev].sftp_path = self._sftp_panel._path
        self._last_tab_idx = idx

        if idx < 0 or idx >= len(self._sessions):
            self._env_panel.set_active('')
            self._sftp_panel.switch_sftp(None, None)
            return
        s = self._sessions[idx]
        self._env_panel.set_active(s.worker._host)
        self._sftp_panel.switch_sftp(s.sftp, s.sftp_client, s.sftp_path)
        # Immediately show cached stats for this session (no wait for next poll)
        if s.last_stats:
            self._update_stats_display(*s.last_stats)
        else:
            self._clear_stats_display()

    def _prompt_new_session(self):
        """Show dialog to create a new SSH session with custom credentials."""
        dlg = _AddSessionDialog(parent=self)
        if dlg.exec():
            ip, user, password = dlg.get_values()
            label = f"{user}@{ip}"
            self._add_session(label=label, ip=ip, user=user, password=password)

    def _open_extra_machine(self, machine):
        """Connect button in Environment tab → new session tab."""
        if machine.credentials:
            cred  = machine.credentials[0]
            label = machine.ip + (f"  ({machine.name})" if machine.name else "")
            self._add_session(label=label, ip=machine.ip,
                              user=cred.login, password=cred.password)
        else:
            # No stored credentials — ask user
            dlg = _AddSessionDialog(default_ip=machine.ip, parent=self)
            if dlg.exec():
                ip, user, password = dlg.get_values()
                label = ip + (f"  ({machine.name})" if machine.name else "")
                self._add_session(label=label, ip=ip, user=user, password=password)

    def _close_session(self, idx: int):
        """Stop and remove one terminal session tab."""
        if idx < 0 or idx >= len(self._sessions):
            return
        s = self._sessions.pop(idx)
        s.worker.stop()
        # Disconnect all worker signals before deleting the pane.
        # The worker thread may still emit signals for a moment after stop(),
        # and those queued signals must not fire against an already-deleted widget.
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
        # Remove from whichever container currently holds it
        if not self._multiexec:
            self._tab_widget.removeTab(idx)
            s.pane.setParent(None)
        else:
            self._rebuild_grid()
        s.pane.deleteLater()
        s.worker.wait(500)

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
            self._sessions[idx].term.clear()

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
        ip, user, pw = old_worker._host, old_worker._user, old_worker._pw

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
        new_worker = _SshWorker(ip, user, pw, cols, rows)
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
        if not self._sessions:
            self.close()

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
            session.worker._host, session.worker._user, session.worker._pw)
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
            self._sftp_panel.switch_sftp(sftp, client, session.sftp_path)

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
                s.stats_worker.stop()
            s.worker.wait(1000)
        self._sftp_panel.stop()
        for w in self._workers:
            if w.isRunning():
                w.wait(800)
        super().closeEvent(event)
