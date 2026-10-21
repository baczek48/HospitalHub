# Copyright © 2026 Sebastian Bąk. All rights reserved.

import base64
import codecs
import hashlib
import itertools
import json
import math
import os
import posixpath
import queue as _queue
import re
import shutil
import stat
import struct
import sys
import tempfile
import threading
import weakref
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

_LEVEL_RULES = [
    # Log-level keywords — aplikowane ZAWSZE (nawet gdy linia ma już ANSI
    # z własnego kolorowania aplikacji / Dockera), bo użytkownik chce widzieć
    # wyróżnione levele również w logach kontenerów.
    # Errors — soft red (bez bold, case-insensitive dla Docker "level=error").
    (re.compile(r'\b(ERROR|FATAL|CRITICAL|FAIL(?:ED)?|EXCEPTION|SEVERE)\b', re.IGNORECASE),
     '\x1b[0;31m'),
    # Warnings — soft yellow.
    (re.compile(r'\b(WARN(?:ING)?)\b', re.IGNORECASE),
     '\x1b[0;33m'),
    # Info — soft green.
    (re.compile(r'\b(INFO(?:RMATION)?)\b', re.IGNORECASE),
     '\x1b[0;32m'),
    # Debug/trace — dim gray.
    (re.compile(r'\b(DEBUG|TRACE|VERBOSE|FINE(?:R|ST)?)\b', re.IGNORECASE),
     '\x1b[2;37m'),
]

_LOG_RULES = [
    # "Caused by:" (Java stack trace header) — red bold, matched case-sensitively
    (re.compile(r'(Caused by:)'),
     '\x1b[1;31m'),
    # Denial / negative — red (lookbehind (?<!=) avoids =false in Java args)
    (re.compile(r'(?<!=)\b(no|NO|denied|DENIED|disabled|DISABLED|rejected|REJECTED'
                r'|refused|REFUSED|unreachable|UNREACHABLE|inactive|INACTIVE'
                r'|stopped|STOPPED|down|DOWN|dead|DEAD|false|FALSE|off|OFF)\b'),
     '\x1b[0;31m'),
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
    (re.compile(r'(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}(?::(?:\d{1,3}\.){3}\d{1,3})?'),
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

#: A line that places the cursor (tmux/ncurses redraw) is a screen update,
#: not a log line — highlighting it would cut the app's own colours (T-03).
_CURSOR_ADDRESSING_RE = re.compile(r'\x1b\[[\d;]*[HfdGrJ]')
#: A chunk that switches to an alternate screen: a full-screen app starts.
_FULLSCREEN_ENTER_RE = re.compile(r'\x1b\[\?(?:1049|1047|47)h')

_COLORIZE_MAX_LINE = 4096   # skip per-line regex pass on >4 KB lines
                            # (prevents pathological backtracking on JSON
                            #  blobs / minified output from `docker logs`)


def _colorize_log(text: str) -> str:
    """Add ANSI keyword highlighting to plain-text log lines.

    Uses placeholder markers (\x00idx\x00) so that text already colored by an
    earlier rule is invisible to later regexes — prevents e.g. HTTP-status
    rules from re-coloring octets inside an already-highlighted IPv4 address.
    """
    lines = text.split('\n')
    last = len(lines) - 1
    for i, line in enumerate(lines):
        # Long lines (JSON dumps, minified output) get colorize skipped —
        # the regex passes are O(rules × len) and trigger backtracking on
        # input with many delimiter chars (`:`, `.`, `=`).
        if len(line) > _COLORIZE_MAX_LINE:
            continue
        if _CURSOR_ADDRESSING_RE.search(line):
            continue            # a screen update, not a log line (T-03)
        has_ansi = bool(_ANSI_PRESENT.search(line))

        # Stash: list of colored fragments; replaced by \x00idx\x00 in `line`
        stash: list[str] = []
        def _stash(fragment: str, _s=stash) -> str:
            idx = len(_s)
            _s.append(fragment)
            return f'\x00{idx}\x00'

        # Level keywords (INFO/WARN/ERROR/DEBUG) — ZAWSZE, nawet gdy linia
        # ma już własne ANSI (np. Docker/framework colored logs).
        for pat, color in _LEVEL_RULES:
            line = pat.sub(
                lambda m, c=color: _stash(f'{c}{m.group()}\x1b[0m'), line)

        if has_ansi:
            # Linia była pokolorowana przez aplikację — tylko leveli dokładamy,
            # reszty reguł nie ruszamy, żeby nie psuć własnych kolorów.
            if stash:
                line = _PLACEHOLDER_RE.sub(lambda m: stash[int(m.group(1))], line)
            lines[i] = line
            continue

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
                # Odtwórz level-highlighty przed dalszym formatowaniem
                if stash:
                    cmd_part = _PLACEHOLDER_RE.sub(
                        lambda m: stash[int(m.group(1))], cmd_part)
                lines[i] = f'{prompt_part}\x1b[1;97m{cmd_part}\x1b[0m'
                continue

        for pat, color in _LOG_RULES:
            if color == '_IPV4_PORT':
                line = pat.sub(lambda m: _stash(_ipv4_port_sub(m)), line)
            else:
                line = pat.sub(
                    lambda m, c=color: _stash(f'{c}{m.group()}\x1b[0m'), line)
        # Restore stashed fragments
        if stash:
            line = _PLACEHOLDER_RE.sub(lambda m: stash[int(m.group(1))], line)
        # Reset at the end of a whole plain-text line so pyte never carries
        # a stale foreground color across visual line-wrap boundaries — not
        # after a piece of one: typed characters arrive one per chunk and the
        # reset wiped the background they were typed on (T-03).
        if i < last:
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
    QScrollBar, QToolButton, QToolTip, QSplitterHandle,
)
from PyQt6.QtCore import (
    Qt, QThread, QTimer, QSize, QEvent, QObject, pyqtSignal, QMimeData, QUrl,
    QBuffer, QByteArray, QIODevice, QPoint,
)
from PyQt6.QtGui import (
    QFont, QFontInfo, QFontMetricsF, QColor, QPainter, QKeySequence,
    QDesktopServices, QIcon, QPixmap, QPen, QBrush, QPainterPath, QDrag,
)

from html import escape as _esc

from ui.rdp import connect_rdp as _connect_rdp
from ui import theme
from ui.icons import icon, painter_icon, set_icon

try:
    import pyte
    _PYTE_OK = True

    # ── Compact scrollback history ──────────────────────────────────────
    # Instead of dict[int, pyte.Char] per row (~57 KB worst-case for 220
    # columns), store rows as (text, runs_bytes) backed by a shared color
    # pool. Each style run is packed as 6 bytes (start_col, fg_idx, bg_idx,
    # attrs) instead of a Python tuple-of-tuples (~120 B / run + tuple
    # headers). For a typical 50k-line scrollback this saves roughly 4-5×
    # the RAM compared to the previous tuple-based layout, while keeping
    # the row[x] read interface unchanged.
    #
    # Rows in history.top are frozen — never modified after being appended —
    # so the packed representation is read-only.

    _ATTR_BOLD          = 1
    _ATTR_REVERSE       = 2
    _ATTR_ITALIC        = 4
    _ATTR_UNDERSCORE    = 8
    _ATTR_STRIKETHROUGH = 16
    _ATTR_BLINK         = 32

    # Shared color pool: any color string ever seen gets one slot. Lookup is
    # O(1) by dict; reverse lookup is O(1) by list index. In practice fewer
    # than ~50 unique colors appear across a session (default + 16 ANSI +
    # any 256/24-bit shades the app uses), so the pool stays tiny.
    _COLOR_POOL: list = ['default']
    _COLOR_INDEX: dict = {'default': 0}

    def _color_id(c) -> int:
        """Get the pool index for color string `c`, adding it if new."""
        if c is None:
            return 0
        idx = _COLOR_INDEX.get(c)
        if idx is None:
            idx = len(_COLOR_POOL)
            if idx > 65535:
                # uint16 overflow — extremely unlikely (would need 65k unique
                # colors). Fall back to default so we never raise.
                return 0
            _COLOR_POOL.append(c)
            _COLOR_INDEX[c] = idx
        return idx

    # Format per run: start_col (uint16, supports ultrawide windows),
    # fg_idx (uint16), bg_idx (uint16), attrs (uint8) = 7 bytes.
    # Little-endian for consistency.
    _RUN_FMT = '<HHHB'
    _RUN_SIZE = 7   # struct.calcsize(_RUN_FMT)

    class _HistCell:
        __slots__ = ('data', 'fg', 'bg', 'bold', 'reverse',
                     'italic', 'underscore', 'strikethrough', 'blink')
        def __init__(self, data, fg='default', bg='default', attrs=0):
            self.data          = data
            self.fg            = fg
            self.bg            = bg
            self.bold          = bool(attrs & _ATTR_BOLD)
            self.reverse       = bool(attrs & _ATTR_REVERSE)
            self.italic        = bool(attrs & _ATTR_ITALIC)
            self.underscore    = bool(attrs & _ATTR_UNDERSCORE)
            self.strikethrough = bool(attrs & _ATTR_STRIKETHROUGH)
            self.blink         = bool(attrs & _ATTR_BLINK)

    class _HistRow:
        """Compact read-only scrollback row. Interface-compatible with the
        subset of dict[int, pyte.Char] used by the renderer: row[x] returns
        a _HistCell, out-of-range raises KeyError (caught by caller).

        `runs` is a `bytes` buffer of packed (start_col, fg_idx, bg_idx,
        attrs) records — 6 bytes each — backed by _COLOR_POOL. Empty `runs`
        means the entire row uses default fg/bg/attrs (the common case for
        plain log lines), which lets us skip even the bytes object.
        """
        __slots__ = ('text', 'runs')

        def __init__(self, text: str, runs: bytes = b''):
            self.text = text      # no trailing spaces
            self.runs = runs      # packed bytes, see _RUN_FMT

        def __bool__(self):
            return bool(self.text)

        def __len__(self):
            return len(self.text)

        def __getitem__(self, x: int) -> '_HistCell':
            if not isinstance(x, int) or x < 0 or x >= len(self.text):
                raise KeyError(x)
            ch = self.text[x]
            r = self.runs
            if not r:
                # Plain line — every cell uses defaults.
                return _HistCell(ch, 'default', 'default', 0)
            # Linear scan — runs typically have 1-3 entries for log lines.
            fg_idx = bg_idx = 0
            attrs = 0
            n = len(r) // _RUN_SIZE
            for i in range(n):
                start, f, b, a = struct.unpack_from(_RUN_FMT, r, i * _RUN_SIZE)
                if start > x:
                    break
                fg_idx, bg_idx, attrs = f, b, a
            return _HistCell(ch, _COLOR_POOL[fg_idx], _COLOR_POOL[bg_idx], attrs)

    _PyteChar = pyte.screens.Char

    def _row_to_hist(row) -> '_HistRow':
        """Convert a pyte buffer row (dict[int, Char]) into a compact _HistRow."""
        if not row:
            return _HistRow('')
        # Find last column with meaningful content (non-space or non-default bg).
        last_col = -1
        for x, cell in row.items():
            if not isinstance(x, int):
                continue
            d = getattr(cell, 'data', ' ')
            bg = getattr(cell, 'bg', 'default')
            if (d not in (' ', '')) or (bg not in ('default', None)):
                if x > last_col:
                    last_col = x
        if last_col < 0:
            return _HistRow('')
        chars = []
        run_records = []   # list of (start, fg_idx, bg_idx, attrs)
        prev_style = None
        all_default = True
        get = row.get if hasattr(row, 'get') else (lambda _x: None)
        for x in range(last_col + 1):
            cell = get(x)
            if cell is None:
                chars.append(' ')
                style = (0, 0, 0)   # default fg, default bg, no attrs
            elif type(cell) is _PyteChar:
                # Fast path (2026-10-16): a pyte Char is a namedtuple — one
                # unpack instead of ten getattr calls per cell.
                d, fg, bg, bold, italics, under, strike, rev, blink = cell
                chars.append(d or ' ')
                if (fg == 'default' and bg == 'default' and not (
                        bold or italics or under or strike or rev or blink)):
                    style = (0, 0, 0)
                else:
                    attrs = ((_ATTR_BOLD if bold else 0)
                             | (_ATTR_REVERSE if rev else 0)
                             | (_ATTR_ITALIC if italics else 0)
                             | (_ATTR_UNDERSCORE if under else 0)
                             | (_ATTR_STRIKETHROUGH if strike else 0)
                             | (_ATTR_BLINK if blink else 0))
                    style = (_color_id(fg or 'default'),
                             _color_id(bg or 'default'), attrs)
                    if style != (0, 0, 0):
                        all_default = False
            else:
                chars.append(cell.data or ' ')
                attrs = 0
                if getattr(cell, 'bold', False):          attrs |= _ATTR_BOLD
                if getattr(cell, 'reverse', False):       attrs |= _ATTR_REVERSE
                if getattr(cell, 'italic', False):        attrs |= _ATTR_ITALIC
                if getattr(cell, 'underscore', False):    attrs |= _ATTR_UNDERSCORE
                if getattr(cell, 'strikethrough', False): attrs |= _ATTR_STRIKETHROUGH
                if getattr(cell, 'blink', False):         attrs |= _ATTR_BLINK
                fg_idx = _color_id(cell.fg or 'default')
                bg_idx = _color_id(cell.bg or 'default')
                style = (fg_idx, bg_idx, attrs)
                if style != (0, 0, 0):
                    all_default = False
            if style != prev_style:
                run_records.append((x,) + style)
                prev_style = style
        text = ''.join(chars)
        if all_default:
            # Skip the bytes allocation entirely for plain log lines.
            return _HistRow(text)
        # Pack runs into a single bytes buffer.
        packed = b''.join(
            struct.pack(_RUN_FMT, start, fg_i, bg_i, attrs)
            for (start, fg_i, bg_i, attrs) in run_records
        )
        return _HistRow(text, packed)


    # ── Parser: what tmux, ncurses and vim send that pyte 0.8.2 does not
    # parse (UX audit 2026-10-16, T-01/T-09/T-10/T-11/T-22) ───────────────

    from collections import defaultdict as _defaultdict

    #: Zero-width code points that are not combining marks.  pyte's draw()
    #: stops at the first one and drops the REST of the text it was given
    #: (T-15: "✔️ Container started" showed as "✔").
    _ZERO_WIDTH_RE = re.compile('[\u200b\u200c\u200d\u2060\ufe0e\ufe0f\ufeff]')

    def _flatten_csi_params(groups, final):
        """CSI parameters with ':' sub-parameters (``38:2::r:g:b``,
        ``4:3``) as the flat list pyte understands, or None to ignore the
        sequence (T-22).  Underline colour (58) is dropped: not rendered."""
        if all(len(g) == 1 for g in groups):
            flat = [g[0] for g in groups]
        elif final != 'm':
            return None             # sub-parameters only mean something in SGR
        else:
            flat = []
            for g in groups:
                head = g[0]
                if len(g) == 1:
                    flat.append(head)
                elif head in (38, 48):
                    if len(g) >= 3 and g[1] == 5:
                        flat.extend((head, 5, g[2]))
                    elif len(g) >= 5 and g[1] == 2:
                        flat.extend((head, 2, g[-3], g[-2], g[-1]))
                elif head == 4:
                    flat.append(24 if g[1] == 0 else 4)   # 4:0 off, 4:3 curly → on
                elif head != 58:
                    flat.append(head)
        if final == 'm' and 58 in flat:
            # Drop the underline-colour attribute (58;5;n / 58;2;r;g;b) by
            # position — a 58 that is a colour VALUE (38;5;58) stays (R-05).
            out, i = [], 0
            while i < len(flat):
                v = flat[i]
                if v in (38, 48, 58):
                    kind = flat[i + 1] if i + 1 < len(flat) else None
                    size = 3 if kind == 5 else 5 if kind == 2 else 1
                    if v != 58:
                        out.extend(flat[i:i + size])
                    i += size
                    continue
                out.append(v)
                i += 1
            flat = out
        return flat

    class _TermStream(pyte.Stream):
        """pyte.Stream plus SU/SD, REP, SCOSC/SCORC, secondary DA and
        ``>``/``=``-prefixed or intermediate-byte sequences, which pyte
        either ignores or — worse — runs as their plain form (vim's
        ``CSI > 4;2 m`` became SGR 4;2: underline + dim)."""

        csi = dict(pyte.Stream.csi)
        csi.update({'S': 'scroll_up', 'T': 'scroll_down',
                    'b': 'repeat_last',
                    's': 'save_cursor_sco', 'u': 'restore_cursor_sco'})

        def _parser_fsm(self):
            """pyte 0.8.2's FSM; only the CSI branch differs."""
            ctrl = pyte.control
            basic = self.basic
            listener = self.listener
            draw = listener.draw
            debug = listener.debug
            ESC, CSI_C1 = ctrl.ESC, ctrl.CSI_C1
            OSC_C1 = ctrl.OSC_C1
            NUL_OR_DEL = ctrl.NUL + ctrl.DEL
            CAN_OR_SUB = ctrl.CAN + ctrl.SUB
            ALLOWED_IN_CSI = "".join([ctrl.BEL, ctrl.BS, ctrl.HT, ctrl.LF,
                                      ctrl.VT, ctrl.FF, ctrl.CR])
            OSC_TERMINATORS = set([ctrl.ST_C0, ctrl.ST_C1, ctrl.BEL])

            def create_dispatcher(mapping):
                return _defaultdict(lambda: debug, dict(
                    (event, getattr(listener, attr))
                    for event, attr in mapping.items()))

            basic_dispatch = create_dispatcher(basic)
            sharp_dispatch = create_dispatcher(self.sharp)
            escape_dispatch = create_dispatcher(self.escape)
            csi_dispatch = create_dispatcher(self.csi)

            while True:
                char = yield True
                if char == ESC:
                    char = yield None
                    if char == "[":
                        char = CSI_C1
                    elif char == "]":
                        char = OSC_C1
                    else:
                        if char == "#":
                            sharp_dispatch[(yield None)]()
                        elif char == "%":
                            self.select_other_charset((yield None))
                        elif char in "()":
                            code = yield None
                            if self.use_utf8:
                                continue
                            listener.define_charset(code, mode=char)
                        else:
                            escape_dispatch[char]()
                        continue
                if char in basic:
                    if (char == ctrl.SI or char == ctrl.SO) and self.use_utf8:
                        continue
                    basic_dispatch[char]()
                elif char == CSI_C1:
                    groups = [[]]
                    current = ""
                    private = False
                    prefix = ""            # '>', '=', '<'
                    intermediate = ""      # 0x20-0x2F before the final byte
                    while True:
                        char = yield None
                        if char == "?":
                            private = True
                        elif char in "<=>":
                            prefix = char
                        elif char in ALLOWED_IN_CSI:
                            basic_dispatch[char]()
                        elif char in CAN_OR_SUB:
                            break          # sequence aborted, nothing shown
                        elif char.isdigit():
                            current += char
                        elif char == ":":
                            groups[-1].append(min(int(current or 0), 9999))
                            current = ""
                        elif " " <= char <= "/":
                            intermediate += char
                        else:
                            groups[-1].append(min(int(current or 0), 9999))
                            if char == ";":
                                groups.append([])
                                current = ""
                                continue
                            if intermediate or prefix in ("<", "="):
                                pass       # DECSCUSR, DECRQM, … — unsupported
                            elif prefix == ">":
                                if char == "c":
                                    listener.report_secondary_device_attributes()
                                # >m (modifyOtherKeys), >q (XTVERSION), >u: no
                            else:
                                params = _flatten_csi_params(groups, char)
                                if params is not None:
                                    if private:
                                        csi_dispatch[char](*params, private=True)
                                    else:
                                        csi_dispatch[char](*params)
                            break
                elif char == OSC_C1:
                    code = yield None
                    if code == "R":
                        continue
                    elif code == "P":
                        continue
                    param = ""
                    while True:
                        char = yield None
                        if char == ESC:
                            char += yield None
                        if char in OSC_TERMINATORS:
                            break
                        else:
                            param += char
                    param = param[1:]
                    if code in "01":
                        listener.set_icon_name(param)
                    if code in "02":
                        listener.set_title(param)
                elif char not in NUL_OR_DEL:
                    draw(char)

    class _TermScreen(pyte.HistoryScreen):
        """HistoryScreen with a real alternate screen and xterm's scrolling.

        Full-screen apps (less, vim, htop, tmux) run in their own buffer: the
        shell's screen comes back when they exit and nothing of theirs reaches
        the scrollback (UX audit 2026-10-16, T-04/T-05).
        """
        _ALT_SCREEN = 1049          # DECSET 1049: alternate screen buffer
        _ALT_SCREEN_FLAG = 1049 << 5  # pyte stores private modes shifted by 5
        # All three private-mode codes that switch to an alternate screen:
        # 47 (legacy), 1047 (clear-on-entry), 1049 (save cursor + alt). Some
        # builds of top/htop/less still use the older variants.
        _ALT_SCREEN_MODES = (47, 1047, 1049)
        _ALT_SCREEN_FLAGS = frozenset(m << 5 for m in (47, 1047, 1049))

        # Track which rows are continuations of the previous row (soft-wrap).
        # A row number in this set means it continues the line from the row above.
        _soft_wrapped: set
        _in_draw: bool = False

        def __init__(self, *args, **kwargs):
            self._soft_wrapped = set()
            self._just_homed = False
            # Set by TerminalWidget when the user explicitly invokes a
            # scrollback-wiping command (`clear`, `cls`, `reset`, Ctrl+L).
            # Consumed by the next CSI 2 J on the main screen.
            self._user_clear_pending = False
            #: Main screen while an alternate screen is shown (T-04).
            self._alt_saved = None
            #: Last printed character, for REP (T-10).
            self._last_drawn = ''
            super().__init__(*args, **kwargs)

        def reset(self):
            super().reset()
            self._soft_wrapped = set()
            self._in_draw = False
            self._just_homed = False
            self._user_clear_pending = False
            self._alt_saved = None
            self._last_drawn = ''

        def before_event(self, event):
            # The `clear` command emits CSI H immediately followed by
            # CSI 2 J with no other event between. Keep _just_homed alive
            # across exactly that pair; clear it on anything else so that
            # leftover cursor-at-home state (e.g. after `top` exited the
            # alt screen leaving the cursor there) cannot retroactively
            # turn an unrelated 2 J into a scrollback wipe.
            super().before_event(event)
            if event not in ('cursor_position', 'erase_in_display'):
                self._just_homed = False

        def cursor_position(self, line=None, column=None):
            super().cursor_position(line, column)
            self._just_homed = (self.cursor.x == 0 and self.cursor.y == 0)

        def draw(self, data):
            if _ZERO_WIDTH_RE.search(data):
                data = _ZERO_WIDTH_RE.sub('', data)          # T-15
                if not data:
                    return
            self._last_drawn = data[-1]
            self._in_draw = True
            try:
                super().draw(data)
            finally:
                self._in_draw = False

        # ── sequences pyte lacks (see _TermStream) ───────────────────────

        def scroll_up(self, count=None, *args, **kwargs):
            """CSI n S: scroll the region up n lines, cursor stays (T-01).
            tmux 3.2+ batches a pane's scroll into one of these."""
            if kwargs.get('private'):
                return
            top, bottom = self.margins or (0, self.lines - 1)
            n = max(1, min(count or 1, bottom - top + 1))
            buf = self.buffer
            for y in range(top, bottom + 1 - n):
                buf[y] = buf[y + n]
            for y in range(bottom + 1 - n, bottom + 1):
                buf.pop(y, None)
            self._soft_wrapped = {
                (r - n if top <= r <= bottom else r) for r in self._soft_wrapped
                if not (top <= r <= bottom) or r - n >= top}
            self.dirty.update(range(top, bottom + 1))

        def scroll_down(self, count=None, *args, **kwargs):
            """CSI n T: scroll the region down n lines, cursor stays."""
            if kwargs.get('private'):
                return
            top, bottom = self.margins or (0, self.lines - 1)
            n = max(1, min(count or 1, bottom - top + 1))
            buf = self.buffer
            for y in range(bottom, top + n - 1, -1):
                buf[y] = buf[y - n]
            for y in range(top, top + n):
                buf.pop(y, None)
            self._soft_wrapped = {
                (r + n if top <= r <= bottom else r) for r in self._soft_wrapped
                if not (top <= r <= bottom) or r + n <= bottom}
            self.dirty.update(range(top, bottom + 1))

        def repeat_last(self, count=None, *args, **kwargs):
            """CSI n b (REP): print the last character n more times (T-10)."""
            if self._last_drawn and not kwargs.get('private'):
                self.draw(self._last_drawn
                          * max(1, min(count or 1, self.columns * self.lines)))

        def save_cursor_sco(self, *args, **kwargs):
            """CSI s — not CSI ? s (XTSAVE) nor DECSLRM with parameters."""
            if not kwargs.get('private') and not any(args):
                self.save_cursor()

        def restore_cursor_sco(self, *args, **kwargs):
            if not kwargs.get('private') and not any(args):
                self.restore_cursor()

        def report_secondary_device_attributes(self):
            """CSI > c: answer like a VT100-class terminal, as Windows
            Terminal does (T-09)."""
            self.write_process_input("\x1b[>0;10;1c")

        # ── alternate screen (T-04/T-05) ─────────────────────────────────

        def _enter_alt(self, save_cursor: bool):
            self._alt_saved = dict(
                buffer=self.buffer, soft=self._soft_wrapped,
                cursor=(self.cursor.x, self.cursor.y, self.cursor.attrs)
                if save_cursor else None,
                lines=self.lines, columns=self.columns)
            dc = self.default_char
            self.buffer = _defaultdict(lambda: _defaultdict(lambda: dc))
            self._soft_wrapped = set()
            self.dirty.update(range(self.lines))

        def _leave_alt(self):
            saved, self._alt_saved = self._alt_saved, None
            if saved is None:
                return
            lines, columns = self.lines, self.columns
            self.buffer = saved['buffer']
            self._soft_wrapped = saved['soft']
            if saved['cursor'] is not None:
                self.cursor.x, self.cursor.y, self.cursor.attrs = saved['cursor']
            if (saved['lines'], saved['columns']) != (lines, columns):
                # Resized while the app ran: reflow the shell's screen now.
                self.lines, self.columns = saved['lines'], saved['columns']
                self.resize(lines, columns)
            self.cursor.x = min(self.cursor.x, self.columns - 1)
            self.cursor.y = min(self.cursor.y, self.lines - 1)
            self.dirty.update(range(self.lines))

        def index(self):
            top, bottom = self.margins or (0, self.lines - 1)
            will_scroll = self.cursor.y == bottom
            # Scroll off the top row into history as a compact _HistRow,
            # then delegate the buffer scroll to plain Screen.index() so
            # HistoryScreen.index() does NOT also push its dict copy.
            if will_scroll:
                # Only a line leaving the top of the MAIN screen is history;
                # a tmux pane or a full-screen app scrolling its region is
                # not (T-05).
                if top == 0 and self._alt_saved is None:
                    self.history.top.append(_row_to_hist(self.buffer[top]))
                pyte.Screen.index(self)
            else:
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
                        if self._alt_saved is None:      # never the alt screen (T-05)
                            for y in range(n_scroll):
                                self.history.top.append(_row_to_hist(self.buffer[y]))
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
                    self.history.top.append(_row_to_hist(new_rows[y]))
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

        def _in_alt_screen(self):
            return not self._ALT_SCREEN_FLAGS.isdisjoint(self.mode)

        def erase_in_display(self, how=0, *args, **kwargs):
            if how == 3:
                # CSI 3 J — programs like top/htop send this on startup
                # (terminfo E3 capability). Keep scrollback intact; only
                # `clear` / Ctrl+L is allowed to wipe it.
                return
            if how == 2:
                # CSI 2 J — by default this only wipes the visible buffer.
                # The shell `clear` command and Ctrl+L both go through this
                # path, but so do top/htop/vim/etc. — escape-sequence-based
                # heuristics cannot reliably tell them apart on every distro.
                # Instead we trust the actual user signal: TerminalWidget
                # sets _user_clear_pending when it observes the user typing
                # `clear`/`cls`/`reset`<Enter> or pressing Ctrl+L. Anything
                # else that emits CSI 2 J (full-screen apps repainting) sees
                # the flag still False and leaves scrollback intact.
                consume = self._user_clear_pending and not self._in_alt_screen()
                self._user_clear_pending = False
                self._just_homed = False
                if consume:
                    self.history.top.clear()
                    self.history.bottom.clear()
                    self._soft_wrapped.clear()
                    self._suppress_history_push = False
            super().erase_in_display(how, *args, **kwargs)
            self._fill_erased_background(how)

        def _fill_erased_background(self, how):
            """BCE (T-07): an erase paints the current background on every
            cell, not only on cells that held something — xterm-256color
            promises it, and mc/vim/htop draw their backgrounds that way."""
            blank = self.cursor.attrs
            if blank.bg == 'default':
                return
            blank = blank._replace(data=' ')
            cols, y = self.columns, self.cursor.y
            if how == 0:
                spans = [(y, range(self.cursor.x, cols))] + [
                    (r, range(cols)) for r in range(y + 1, self.lines)]
            elif how == 1:
                spans = [(r, range(cols)) for r in range(y)] + [
                    (y, range(0, min(self.cursor.x + 1, cols)))]
            elif how == 2:
                spans = [(r, range(cols)) for r in range(self.lines)]
            else:
                return
            for r, xs in spans:
                line = self.buffer[r]
                for x in xs:
                    line[x] = blank

        def set_mode(self, *modes, **kwargs):
            # Entering an alternate screen (47 / 1047 / 1049): the shell's
            # screen is put aside whole and comes back on exit; 1049 also
            # saves the cursor (T-04).
            if (kwargs.get("private") and self._alt_saved is None
                    and any(m in self._ALT_SCREEN_MODES for m in modes)):
                self._enter_alt(save_cursor=1049 in modes)
            super().set_mode(*modes, **kwargs)

        def reset_mode(self, *modes, **kwargs):
            super().reset_mode(*modes, **kwargs)
            if (kwargs.get("private") and self._alt_saved is not None
                    and any(m in self._ALT_SCREEN_MODES for m in modes)
                    and not self._in_alt_screen()):
                self._leave_alt()

    def _wrap_history_events(cls):
        """Terminal speed (2026-10-16): pyte's HistoryScreen routes EVERY
        attribute read (self.cursor, self.buffer, self.columns …) through a
        Python-level __getattribute__ that wraps event methods in
        before_event/after_event — ~950 calls per printed line, the largest
        cost of a long `cat`.  Same wrapping, done once on the class: each
        event method (ours where we override it) is replaced by a wrapper
        and the plain attribute lookup is restored."""
        for name in pyte.HistoryScreen._wrapped:
            impl = getattr(cls, name, None)
            if impl is None:
                continue

            def wrapper(self, *args, _impl=impl, _name=name, **kwargs):
                self.before_event(_name)
                result = _impl(self, *args, **kwargs)
                self.after_event(_name)
                return result

            wrapper.__name__ = name
            wrapper.__doc__ = impl.__doc__
            setattr(cls, name, wrapper)
        cls.__getattribute__ = object.__getattribute__

    _wrap_history_events(_TermScreen)

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
    #: Bytes for THIS session only — answers to terminal queries and mouse
    #: reports; never broadcast by multi-exec like typed input (T-09/T-24).
    term_reply     = pyqtSignal(bytes)
    #: Ctrl+Shift+F — open the search bar (E-03).
    search_requested = pyqtSignal()

    _SCROLLBACK = 250_000   # 25 MB - 250 MB per session (lines × ~100-1000 B);
                            # freed on tab close. Still 2.5× MobaXterm's max
                            # (99 999) so heavy `docker logs -f` runs aren't
                            # truncated. CPU cost is negligible — append is O(1)
                            # and the renderer only looks at visible rows. Only
                            # first scroll after a flush rebuilds the lookup
                            # cache (~30-50 ms).

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
    # DECCKM (application cursor keys) — vim/less/mc set private mode 1
    # after entering alt-screen and then expect \x1bOA-D for arrow keys
    # instead of the default \x1b[A-D. Without this map vim's normal-mode
    # navigation via arrows does nothing.
    _APP_CURSOR_MAP = {
        Qt.Key.Key_Up:    b'\x1bOA',
        Qt.Key.Key_Down:  b'\x1bOB',
        Qt.Key.Key_Right: b'\x1bOC',
        Qt.Key.Key_Left:  b'\x1bOD',
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

        # Lower bound 40×10.  It used to be 80×24, but the SSH window's
        # splitter squeezed the widget below that anyway, and the PTY was
        # still told 80 columns: the rightmost ones were written off-screen
        # (UX audit V-01).  The size sent is now always what is visible.
        self.setMinimumSize(int(40 * self._cw), int(10 * self._ch))

        self._cols = 220
        self._rows = 50
        self._screen = _TermScreen(self._cols, self._rows, history=self._SCROLLBACK) if _PYTE_OK else None
        self._stream = _TermStream(self._screen) if _PYTE_OK else None
        if self._stream is not None:
            # Text arrives already decoded, so UTF-8 stays intact; switching
            # pyte's UTF-8 mode off lets ESC ( 0 / SO-SI line drawing work
            # (T-08: frames drawn as "lqqk").
            self._stream.use_utf8 = False
            self._screen.write_process_input = (
                lambda s: self.term_reply.emit(s.encode('utf-8')))
        #: Read by the SSH worker thread (a plain bool): a full-screen app
        #: is showing — no log highlighting, no output dropped on Ctrl+C.
        self.alt_screen = False
        #: How many sessions a paste reaches (multi-exec); set by SshDialog.
        self.paste_targets = lambda: 1
        #: In multi-exec: did EVERY receiving session ask for bracketed
        #: paste?  Otherwise the text goes unwrapped, with the warning that
        #: each line runs at once (review 71, R-06).
        self.paste_bracketed_everywhere = lambda: True
        #: The last command line sent with Enter, and Ctrl+D (R-07).
        self.last_command = b''
        self._mouse_button = None

        # Buffer of bytes typed on the current input line. Used by
        # _emit_input to detect when the user invokes a scrollback-wiping
        # command so the next CSI 2 J is allowed to clear scrollback.
        self._typed_line = bytearray()

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

        # Search state — populated by set_search_term(). Matches stored as
        # (arow, col_start, col_end). _search_current_idx == -1 means no match yet.
        self._search_term: str = ''
        self._search_matches: list[tuple[int, int, int]] = []
        self._search_current_idx: int = -1

    # ── Public API ────────────────────────────────────────────────────────

    def feed(self, data: str):
        self._pending_data.append(data)
        if not self._coalesce_timer.isActive():
            # Hidden tabs: throttle pyte parse to ~4 Hz instead of 120 Hz.
            # Without this, a heavy stream on a background tab (e.g. docker
            # logs -f) keeps eating UI-thread CPU on pyte feed and starves
            # keystroke handling on the *visible* tab. Repaint already short-
            # circuits for hidden widgets, but parse does not.
            self._coalesce_timer.setInterval(8 if self.isVisible() else 250)
            self._coalesce_timer.start()

    def feed_discontinuity(self):
        """The worker dropped received bytes (Ctrl+C on the shell screen)."""
        self._pending_data.append(None)
        if not self._coalesce_timer.isActive():
            self._coalesce_timer.start()

    def flush_now(self):
        """Process any buffered chunks immediately (used when a hidden tab
        becomes visible so the user sees fresh content right away)."""
        if self._coalesce_timer.isActive():
            self._coalesce_timer.stop()
        if self._pending_data:
            self._flush_pending()

    def pending_chunks(self) -> int:
        """How many received chunks are queued for pyte parsing.

        Used by the SSH worker for back-pressure: when this grows past a
        threshold, the worker pauses recv() so the OS-level SSH receive
        buffer fills up and TCP signals the upstream server to slow down.
        Nothing gets dropped — data is throttled at the network layer.
        """
        return len(self._pending_data)

    def _flush_pending(self):
        """Process buffered data with a UI-thread timeslice and repaint once.

        Pyte stream parsing is CPU-bound and blocks the UI thread. With heavy
        output (e.g. `docker compose logs -f` over many services) a single
        batch can take 50-200 ms, freezing typing/scrolling on every other
        widget. We cap one flush at ~12 ms and reschedule the rest — UI gets
        regular breathing room, no data is lost (chunks stay queued).
        """
        if not self._pending_data:
            return
        import time as _t
        if self._stream:
            # Tight timeslice — keeps the UI thread returning to its event
            # loop fast enough that key presses (esp. Ctrl+C) don't get
            # stuck behind a long flush of buffered chunks.
            # In alt-screen mode (top/htop/vim/less/mc) a full-screen app
            # emits a complete frame every cycle. If we tear that frame by
            # breaking mid-flush, the user sees half the previous frame and
            # half the new one for ~8 ms (visible as duplicated/jumping rows
            # in `top`). Frames are small (~5-10 KB across a handful of
            # chunks), so a 30 ms budget lets them land atomically while
            # still leaving the UI responsive to Ctrl+C on pathological
            # alt-screen streams (`yes | less`).
            in_alt = self._screen._in_alt_screen() if self._screen else False
            deadline = _t.monotonic() + (0.030 if in_alt else 0.010)
            n = len(self._pending_data)
            i = 0
            while i < n:
                item = self._pending_data[i]
                try:
                    if item is None:
                        # Bytes were dropped here (Ctrl+C): any escape
                        # sequence in progress is gone — start clean (T-02).
                        self._stream._initialize_parser()
                        self._stream.feed('\x1b[0m')
                    else:
                        self._stream.feed(item)
                except Exception as _e:
                    import traceback; traceback.print_exc()
                i += 1
                # Always process at least one chunk before checking the clock.
                if i < n and _t.monotonic() >= deadline:
                    break
            del self._pending_data[:i]
            self.alt_screen = self._screen._in_alt_screen()
        else:
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
        # Frame skip during a backlog: heavy log streams (docker logs -f, tail -f)
        # emit dozens of chunks back-to-back. Each flush would otherwise repaint
        # the full visible buffer (~10k cells), but the next flush 8 ms later
        # overwrites that paint immediately — pure wasted work. Skip the paint
        # if data is still queued, except we force one every 50 ms so the user
        # still sees live progress (~20 fps minimum during sustained streams).
        now = _t.monotonic()
        last_paint = getattr(self, '_last_paint_t', 0.0)
        if not self._pending_data or (now - last_paint) > 0.050:
            self.update()
            self._last_paint_t = now
        self._emit_scroll()
        # If the timeslice expired with leftover work, schedule another pass —
        # at once (after the event loop has run, so keys still get through):
        # waiting the usual 8 ms left the parser idle half the time and a
        # long `cat` took twice as long (2026-10-16).  Hidden tabs keep
        # their slow pace.
        if self._pending_data and not self._coalesce_timer.isActive():
            self._coalesce_timer.setInterval(1 if self.isVisible() else 250)
            self._coalesce_timer.start()

    _CLEAR_COMMANDS = frozenset([b'clear', b'cls', b'reset', b'tput'])

    def _emit_input(self, data: bytes):
        """Forward typed bytes to the SSH worker, but first sniff for the
        user invoking an explicit scrollback-wipe command. Sets a flag on
        the screen so the next CSI 2 J on the main screen actually wipes
        scrollback. Anything else (top/htop/vim/...) emits CSI 2 J without
        the flag and scrollback is preserved."""
        screen = self._screen
        if screen is not None and data:
            for b in data:
                if b == 0x0c:  # Ctrl+L — shell turns this into a clear sequence
                    screen._user_clear_pending = True
                    self._typed_line.clear()
                elif b == 0x04:  # Ctrl+D — the shell may end
                    self.last_command = b'^d'
                elif b in (0x0d, 0x0a):  # Enter
                    line = bytes(self._typed_line).strip().lower()
                    self.last_command = line
                    for sep in (b';', b'&', b'|', b'`'):
                        line = line.replace(sep, b' ')
                    tokens = line.split()
                    if tokens and (tokens[-1] in self._CLEAR_COMMANDS
                                   or tokens[0] in self._CLEAR_COMMANDS):
                        screen._user_clear_pending = True
                    self._typed_line.clear()
                elif b == 0x15:  # Ctrl+U — kill line
                    self._typed_line.clear()
                    screen._user_clear_pending = False
                elif b == 0x03:  # Ctrl+C — abort current input
                    self._typed_line.clear()
                    screen._user_clear_pending = False
                elif b in (0x08, 0x7f):  # backspace
                    if self._typed_line:
                        self._typed_line.pop()
                elif 0x20 <= b <= 0x7e:  # printable ASCII
                    self._typed_line.append(b)
                    # User still typing — invalidate any stale pending flag
                    screen._user_clear_pending = False
                # Other bytes (escape sequences, arrow keys, tabs) leave the
                # buffer alone — we can't track shell-side line edits, but a
                # mistracked buffer just means no auto-wipe, which is the
                # safe failure mode (user can still hit Ctrl+Shift+L).
        self.char_input.emit(data)

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

    def clear_scrollback(self):
        """Wipe scrollback only (leave the visible buffer alone). Bound to
        Ctrl+Shift+L — matches iTerm2 / gnome-terminal / Windows Terminal
        convention for explicit history wipe."""
        if self._screen:
            self._screen.history.top.clear()
            self._screen.history.bottom.clear()
            self._screen._soft_wrapped = {
                r for r in self._screen._soft_wrapped if r < self._screen.lines
            }
        self._scroll_offset = 0
        self._hist_cache    = None
        self.update()
        self._emit_scroll()

    def _emit_scroll(self):
        """Emit current scroll position so the scrollbar can update."""
        if self._screen:
            max_off = len(self._screen.history.top)
            self.scroll_changed.emit(self._scroll_offset, max_off)

    def terminal_size(self):
        """Return current terminal dimensions from actual widget size (always live)."""
        cols = max(20, int(self.width()  / self._cw))
        rows = max(5, int(self.height() / self._ch))
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
                    if cell.data == '':
                        continue        # right half of a wide character
                    chars.append(cell.data)
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

        # Pending wrap leaves x == columns: draw in the last cell (T-23).
        cx      = min(self._screen.cursor.x, max(0, self._cols - 1))
        cy      = self._screen.cursor.y
        focused = self.hasFocus()
        # Hidden (DECTCEM ?25l) means hidden (T-12); without focus the
        # cursor is an outline instead of nothing (T-23).
        show_cursor = (not self._screen.cursor.hidden
                       and (self._cur_vis or not focused))
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
            is_cursor_row = (offset == 0 and y == cy and show_cursor)

            flag_cols = self._flag_columns(row) if row else None

            if not row:
                # Draw cursor on empty row if needed
                if is_cursor_row:
                    rx = int(cx * cw)
                    if focused:
                        p.fillRect(rx, py, int_cw, int_lh, default_fg_c)
                    else:
                        p.setPen(default_fg_c)
                        p.drawRect(rx, py, int_cw - 2, int_lh - 2)
                continue

            # Batch: collect runs of chars with same style to draw together
            prev_fg = None
            prev_bold = None
            run_chars = []
            run_x_start = 0

            for x in range(x_start, x_end):
                cell = None
                try:
                    cell = row[x]
                    if cell.data == '':
                        # Right half of a wide character: its glyph was drawn
                        # with the left half; end the run so the next text
                        # starts at its own column (T-14).
                        if run_chars:
                            text = ''.join(run_chars)
                            if text.rstrip():
                                p.drawText(int(run_x_start * cw), int(py + asc), text)
                            run_chars = []
                        bg = self._color(cell.bg, False)
                        if bg != _DEFAULT_BG:
                            p.fillRect(int(x * cw), py, int_cw, int_lh, _qcolor(bg))
                        continue
                    char = cell.data or ' '
                    fg   = self._color(cell.fg, True)
                    bg   = self._color(cell.bg, False)
                    if cell.reverse:
                        fg, bg = bg, fg
                    style = (cell.bold,
                             getattr(cell, 'italics', False) or getattr(cell, 'italic', False),
                             bool(getattr(cell, 'underscore', False)),
                             bool(getattr(cell, 'strikethrough', False)))
                except (KeyError, AttributeError, TypeError):
                    char, fg, bg = ' ', _DEFAULT_FG, _DEFAULT_BG
                    style = (False, False, False, False)
                bold = style

                # Flag highlighting (only when cell hasn't been colored by program)
                if (flag_cols and x in flag_cols and fg == _DEFAULT_FG
                        and not (cell is not None and cell.reverse)):
                    fg = _FLAG_FG

                rx     = int(x * cw)
                sel    = has_sel and self._in_selection(x, y)
                is_cur = (is_cursor_row and focused and x == cx)

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
                if (run_chars and draw_fg == prev_fg and bold == prev_bold
                        and not sel and not is_cur):
                    run_chars.append(char)
                else:
                    # Flush previous run
                    if run_chars:
                        text = ''.join(run_chars)
                        if text.rstrip():
                            p.drawText(int(run_x_start * cw), int(py + asc), text)
                    # Start new run
                    if bold != prev_bold:
                        p.setFont(self._styled_font(bold))
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
            if is_cursor_row and not focused:
                p.setPen(default_fg_c)
                p.drawRect(int(cx * cw), py, int_cw - 2, int_lh - 2)

        # Search highlights — drawn on top of text. Current match uses a stronger
        # orange; others a softer yellow.
        if self._search_matches:
            hist_len = len(self._screen.history.top)
            cur_idx = self._search_current_idx
            match_bg  = QColor(255, 220, 70, 90)
            current_bg = QColor(255, 140, 0, 170)
            for i, (arow, c0, c1) in enumerate(self._search_matches):
                vrow = arow - hist_len + offset
                if vrow < y_start or vrow >= y_end:
                    continue
                py = int(vrow * lh)
                rx = int(c0 * cw)
                rw = int((c1 - c0) * cw) + 1
                p.fillRect(rx, py, rw, int_lh, current_bg if i == cur_idx else match_bg)
                # Re-draw the text on top so it stays legible.
                row = self._get_row(vrow)
                if row:
                    chars = []
                    for x in range(c0, c1):
                        try:
                            chars.append(row[x].data or ' ')
                        except (KeyError, AttributeError, TypeError):
                            chars.append(' ')
                    p.setFont(self._font)
                    p.setPen(QColor('#1c1f26'))
                    p.drawText(rx, int(py + asc), ''.join(chars))


    def _styled_font(self, style) -> QFont:
        """(bold, italic, underline, strike) → font, cached (T-13)."""
        cache = self.__dict__.setdefault('_font_cache', {})
        f = cache.get(style)
        if f is None:
            f = QFont(self._font)
            f.setBold(style[0])
            f.setItalic(style[1])
            f.setUnderline(style[2])
            f.setStrikeOut(style[3])
            cache[style] = f
        return f

    # ── Resize ────────────────────────────────────────────────────────────

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.width() < 20 or self.height() < 20:
            return   # not yet laid out — ignore spurious resize events
        new_cols = max(20, int(self.width()  / self._cw))
        new_rows = max(5, int(self.height() / self._ch))
        # A pending resize is replaced even when the size came back to the
        # current one: A→B→A within the debounce used to apply B (T-19).
        if ((new_cols, new_rows) != (self._cols, self._rows)
                or self._pending_resize is not None):
            # Do NOT touch pyte buffer here — resizing it on every drag pixel
            # causes it to pull scrollback history and produce phantom lines.
            # Schedule both the pyte resize and the PTY SIGWINCH for after
            # the drag settles (debounce 150 ms).
            self._pending_resize = (new_cols, new_rows)
            self._resize_timer.start()

    def _emit_resize(self):
        if self._pending_resize == (self._cols, self._rows):
            self._pending_resize = None
            return
        if self._pending_resize:
            new_cols, new_rows = self._pending_resize
            if self._screen:
                self._screen.resize(new_rows, new_cols)
            self._cols = new_cols
            self._rows = new_rows
            # Keep the user's scroll position when they resize (e.g. drag the
            # SFTP/terminal splitter while reading logs). Clamp to new history
            # length — pyte.resize may have shifted the buffer.
            if self._scroll_offset and self._screen:
                self._scroll_offset = min(self._scroll_offset,
                                          len(self._screen.history.top))
            self._hist_cache    = None
            self._pending_resize = None
            self.resize_pty.emit(new_cols, new_rows)
            # Geometry changed — old match rects point to stale (line, col)
            # positions. Recompute on the new buffer so highlights line up
            # with the reflowed text.
            if self._search_term:
                self._rebuild_search_matches()
                if self._search_matches:
                    if self._search_current_idx >= len(self._search_matches):
                        self._search_current_idx = 0
                else:
                    self._search_current_idx = -1
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

        # Ctrl+Tab / Ctrl+Shift+Tab: defer to the dialog so it can cycle
        # session tabs. Without ignore() the event would be swallowed here.
        if ctrl and key in (Qt.Key.Key_Tab, Qt.Key.Key_Backtab):
            event.ignore()
            return

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
            self.paste(QApplication.clipboard().text())
            event.accept()
            return

        # Ctrl+Shift+F: search (E-03) — Ctrl+F itself belongs to the shell.
        if ctrl and shift and key == Qt.Key.Key_F:
            self.search_requested.emit()
            event.accept()
            return

        # Shift+PgUp / Shift+PgDn: page through the local scrollback.
        if (shift and not ctrl and self._screen
                and key in (Qt.Key.Key_PageUp, Qt.Key.Key_PageDown)):
            step = max(1, self._rows - 1)
            hist_max = len(self._screen.history.top)
            delta = step if key == Qt.Key.Key_PageUp else -step
            self._scroll_offset = max(0, min(self._scroll_offset + delta, hist_max))
            self._hist_cache = None
            self.update()
            self._emit_scroll()
            event.accept()
            return

        # Ctrl+Shift+L: wipe scrollback (visible buffer untouched). The
        # shell `clear` command no longer eats scrollback (it would mis-fire
        # for top/htop/vim too) — this shortcut is the explicit override.
        if ctrl and shift and key == Qt.Key.Key_L:
            self.clear_scrollback()
            event.accept()
            return

        # Any input: return to bottom of scrollback
        if self._scroll_offset:
            self._scroll_offset = 0
            self.update()

        alt = bool(mods & Qt.KeyboardModifier.AltModifier)
        data = self._encode_key(key, event.text(), ctrl, shift, alt)

        if data:
            self._cur_vis = True
            self._blink.start(530)
            self._emit_input(data)
        event.accept()

    # xterm key encoding (UX audit T-16/T-17): a modifier is the parameter
    # 1 + Shift + 2·Alt + 4·Ctrl; DECCKM switches cursor keys to SS3.
    _CSI_LETTER_KEYS = {
        Qt.Key.Key_Up: 'A', Qt.Key.Key_Down: 'B', Qt.Key.Key_Right: 'C',
        Qt.Key.Key_Left: 'D', Qt.Key.Key_Home: 'H', Qt.Key.Key_End: 'F',
    }
    _SS3_FKEYS = {Qt.Key.Key_F1: 'P', Qt.Key.Key_F2: 'Q',
                  Qt.Key.Key_F3: 'R', Qt.Key.Key_F4: 'S'}
    _TILDE_KEYS = {
        Qt.Key.Key_Insert: 2, Qt.Key.Key_Delete: 3, Qt.Key.Key_PageUp: 5,
        Qt.Key.Key_PageDown: 6, Qt.Key.Key_F5: 15, Qt.Key.Key_F6: 17,
        Qt.Key.Key_F7: 18, Qt.Key.Key_F8: 19, Qt.Key.Key_F9: 20,
        Qt.Key.Key_F10: 21, Qt.Key.Key_F11: 23, Qt.Key.Key_F12: 24,
    }
    _CTRL_SYMBOLS = {
        Qt.Key.Key_Space: b'\x00', Qt.Key.Key_2: b'\x00',
        Qt.Key.Key_3: b'\x1b', Qt.Key.Key_4: b'\x1c', Qt.Key.Key_5: b'\x1d',
        Qt.Key.Key_6: b'\x1e', Qt.Key.Key_AsciiCircum: b'\x1e',
        Qt.Key.Key_7: b'\x1f', Qt.Key.Key_Slash: b'\x1f',
        Qt.Key.Key_Minus: b'\x1f', Qt.Key.Key_Underscore: b'\x1f',
        Qt.Key.Key_8: b'\x7f', Qt.Key.Key_Question: b'\x7f',
    }

    def _encode_key(self, key, text: str, ctrl: bool, shift: bool,
                    alt: bool) -> bytes | None:
        """The bytes xterm sends for this key, or None."""
        mod = 1 + shift + 2 * alt + 4 * ctrl
        app_cursor = self._screen is not None and 32 in self._screen.mode
        letter = self._CSI_LETTER_KEYS.get(key)
        if letter:
            if mod > 1:
                return f'\x1b[1;{mod}{letter}'.encode()
            return (b'\x1bO' if app_cursor else b'\x1b[') + letter.encode()
        letter = self._SS3_FKEYS.get(key)
        if letter:
            if mod > 1:
                return f'\x1b[1;{mod}{letter}'.encode()
            return b'\x1bO' + letter.encode()
        num = self._TILDE_KEYS.get(key)
        if num:
            return (f'\x1b[{num};{mod}~' if mod > 1 else f'\x1b[{num}~').encode()
        if key == Qt.Key.Key_Backtab or (key == Qt.Key.Key_Tab and shift):
            return b'\x1b[Z'
        if key == Qt.Key.Key_Tab:
            return b'\t'
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            return b'\x1b\r' if alt else b'\r'
        if key == Qt.Key.Key_Backspace:
            if ctrl:
                return b'\x08'
            return b'\x1b\x7f' if alt else b'\x7f'
        if key == Qt.Key.Key_Escape:
            return b'\x1b'
        # AltGr on Windows arrives as Ctrl+Alt carrying the character it
        # produced (ą, ę, @, {): that is text, not a control combination.
        if ctrl and alt and text and text.isprintable():
            return text.encode('utf-8')
        if ctrl:
            data = self._CTRL_MAP.get(key) or self._CTRL_SYMBOLS.get(key)
            if data:
                return b'\x1b' + data if alt else data
            if text and len(text) == 1 and ord(text) < 0x20:
                return text.encode()
            return None
        if text:
            data = text.encode('utf-8')
            return b'\x1b' + data if alt else data
        return None

    # ── Paste ─────────────────────────────────────────────────────────────

    def paste(self, text: str) -> None:
        """Send clipboard text the way xterm does (UX audit T-18/E-05).

        Line breaks become CR (what the Enter key sends).  When the program
        asked for bracketed paste (?2004 — bash 5.1+, zsh, vim) the text is
        wrapped so nothing runs until the user presses Enter.  Without it,
        several lines — each run the moment it lands — or a paste into more
        than one session (multi-exec) need a confirmation first.
        """
        if not text:
            return
        text = text.replace('\r\n', '\r').replace('\n', '\r')
        bracketed = (self._screen is not None
                     and (2004 << 5) in self._screen.mode
                     and self.paste_bracketed_everywhere())
        lines = text.rstrip('\r').count('\r') + 1
        targets = max(1, int(self.paste_targets() or 1))
        if (lines > 1 and not bracketed) or targets > 1:
            if not self._confirm_paste(text, lines, targets, bracketed):
                return
        if bracketed:
            text = '\x1b[200~' + text.replace('\x1b[201~', '') + '\x1b[201~'
        self._scroll_offset = 0
        self._emit_input(text.encode('utf-8'))

    def _confirm_paste(self, text: str, lines: int, targets: int,
                       bracketed: bool) -> bool:
        from ui.utils import plural
        what = "Wklejasz " + plural(lines, "linię", "linie", "linii")
        if targets > 1:
            what += f" do {plural(targets, 'sesji', 'sesji', 'sesji')} naraz (Multi-exec)"
        what += "."
        if lines > 1 and not bracketed:
            what += "\nKażda linia zostanie wykonana od razu po wklejeniu."
        preview = text.replace('\r', '\n').strip('\n')
        shown = preview.split('\n')[:6]
        preview = '\n'.join(s if len(s) <= 100 else s[:100] + '…' for s in shown)
        if lines > len(shown):
            preview += '\n…'
        box = QMessageBox(QMessageBox.Icon.Warning, "Wklejanie do terminala",
                          what, parent=self)
        box.setInformativeText(preview)
        paste_btn = box.addButton("Wklej", QMessageBox.ButtonRole.AcceptRole)
        cancel_btn = box.addButton("Anuluj", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(cancel_btn)
        box.setEscapeButton(cancel_btn)
        box.exec()
        return box.clickedButton() is paste_btn

    # ── Mouse ─────────────────────────────────────────────────────────────

    def _mouse_report(self, button: int, col: int, row: int,
                      release: bool = False, motion: bool = False) -> bool:
        """Report a mouse event to a program that asked for it (?1000/1002/
        1003, SGR 1006) — tmux `mouse on`, htop, mc, vim mouse=a (T-24).
        Returns False when nobody asked: the click stays local."""
        mode = self._screen.mode if self._screen else ()
        if not any((m << 5) in mode for m in (1000, 1002, 1003)):
            return False
        code = button + (32 if motion else 0)
        if (1006 << 5) in mode:
            data = f'\x1b[<{code};{col + 1};{row + 1}{"m" if release else "M"}'.encode()
        else:
            if col > 222 or row > 222:
                return True               # beyond the X10 encoding: dropped
            data = b'\x1b[M' + bytes((32 + (3 if release else code),
                                      33 + col, 33 + row))
        self.term_reply.emit(data)
        return True

    _MOUSE_BUTTONS = {Qt.MouseButton.LeftButton: 0,
                      Qt.MouseButton.MiddleButton: 1,
                      Qt.MouseButton.RightButton: 2}

    def _mouse_reportable(self, event) -> bool:
        """Shift keeps the mouse local (selection, paste), as in xterm."""
        return (self._scroll_offset == 0
                and not (event.modifiers() & Qt.KeyboardModifier.ShiftModifier))

    def mousePressEvent(self, event):
        self.setFocus()
        button = self._MOUSE_BUTTONS.get(event.button())
        if button is not None and self._mouse_reportable(event):
            col, row = self._cell_at_pos(event.position())
            if self._mouse_report(button, col, row):
                self._mouse_button = button
                return
        if event.button() == Qt.MouseButton.LeftButton:
            col, row = self._cell_at_pos(event.position())
            arow = self._vrow_to_arow(row)
            # A plain click only clears the old selection; a selection (and
            # the copy to the clipboard) starts once the mouse is dragged,
            # as in MobaXterm — clicking to type must not replace what the
            # clipboard holds (owner's request 2026-10-16).
            self._sel_start = (col, arow)
            self._sel_end   = None
            self._sel_press_pos = event.position()
            self._sel_mouse_col = col
            self._selecting = True
            self.update()
        elif event.button() == Qt.MouseButton.RightButton:
            # Paste from clipboard (PuTTY style) — through paste(): several
            # lines or several sessions ask first (E-05).
            self.paste(QApplication.clipboard().text())

    def mouseMoveEvent(self, event):
        if self._mouse_button is not None:
            mode = self._screen.mode if self._screen else ()
            if (1002 << 5) in mode or (1003 << 5) in mode:
                col, row = self._cell_at_pos(event.position())
                self._mouse_report(self._mouse_button, col, row, motion=True)
            return
        if self._selecting and (event.buttons() & Qt.MouseButton.LeftButton):
            if self._sel_end is None and not self._dragged_far(event.position()):
                return
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

    def _dragged_far(self, pos) -> bool:
        """Has the mouse left the pressed cell by a real drag?"""
        start = getattr(self, '_sel_press_pos', None)
        if start is None:
            return True
        d = pos - start
        return (abs(d.x()) + abs(d.y())) >= max(
            QApplication.startDragDistance() // 2, min(self._cw, self._ch) / 2)

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
        if self._mouse_button is not None:
            col, row = self._cell_at_pos(event.position())
            self._mouse_report(self._mouse_button, col, row, release=True)
            self._mouse_button = None
            return
        if event.button() == Qt.MouseButton.LeftButton and self._selecting:
            self._sel_scroll_timer.stop()
            self._sel_scroll_dir = 0
            if self._sel_end is None:           # a click, not a drag
                self._selecting = False
                self._sel_start = None
                self.update()
                return
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
        if self._mouse_reportable(event):
            notches = event.angleDelta().y() // 120
            if notches:
                col, row = self._cell_at_pos(event.position())
                button = 64 if notches > 0 else 65
                if self._mouse_report(button, col, row):
                    for _ in range(abs(notches) - 1):
                        self._mouse_report(button, col, row)
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

    # ── Terminal search ───────────────────────────────────────────────────

    def _row_plain_text(self, arow: int) -> str:
        """Plain text for absolute row (history as stored, buffer rendered to str)."""
        row = self._get_row_abs(arow)
        # _HistRow: already has .text
        text = getattr(row, 'text', None)
        if text is not None:
            return text
        if not row:
            return ''
        chars = []
        last_nonspace = -1
        for x in range(self._cols):
            try:
                ch = row[x].data or ' '
            except (KeyError, AttributeError, TypeError):
                ch = ' '
            chars.append(ch)
            if ch != ' ':
                last_nonspace = x
        if last_nonspace < 0:
            return ''
        return ''.join(chars[:last_nonspace + 1])

    def set_search_term(self, term: str):
        """Replace the current search term. Jumps to the first match from the top.
        Passing '' clears the search."""
        self._search_term = term or ''
        self._hist_cache = None
        self._rebuild_search_matches()
        if self._search_matches:
            self._search_current_idx = 0
            self._scroll_to_match(0)
        else:
            self._search_current_idx = -1
        self.update()

    def search_next(self):
        if not self._search_matches:
            return
        self._search_current_idx = (self._search_current_idx + 1) % len(self._search_matches)
        self._scroll_to_match(self._search_current_idx)
        self.update()

    def search_prev(self):
        if not self._search_matches:
            return
        self._search_current_idx = (self._search_current_idx - 1) % len(self._search_matches)
        self._scroll_to_match(self._search_current_idx)
        self.update()

    def clear_search(self):
        self._search_term = ''
        self._search_matches = []
        self._search_current_idx = -1
        self.update()

    def search_status(self) -> tuple[int, int]:
        """Returns (current_1_based, total) — (0, 0) when nothing is active."""
        if not self._search_matches:
            return (0, 0)
        return (self._search_current_idx + 1, len(self._search_matches))

    def _rebuild_search_matches(self):
        self._search_matches = []
        if not self._search_term or not self._screen:
            return
        needle = self._search_term.lower()
        nlen = len(needle)
        if nlen == 0:
            return
        hist_len = len(self._screen.history.top)
        total_rows = hist_len + self._rows
        for arow in range(total_rows):
            text = self._row_plain_text(arow)
            if not text:
                continue
            hay = text.lower()
            start = 0
            while True:
                idx = hay.find(needle, start)
                if idx < 0:
                    break
                self._search_matches.append((arow, idx, idx + nlen))
                # Allow overlapping matches: advance by 1 (common expectation
                # when searching single characters).
                start = idx + 1

    def _scroll_to_match(self, idx: int):
        if not (0 <= idx < len(self._search_matches)) or not self._screen:
            return
        arow = self._search_matches[idx][0]
        hist_len = len(self._screen.history.top)
        # Put the match in the middle of the visible area.
        target_vrow = max(1, self._rows // 2)
        new_offset = target_vrow - (arow - hist_len)
        new_offset = max(0, min(new_offset, hist_len))
        if new_offset != self._scroll_offset:
            self._scroll_offset = new_offset
            self.scroll_changed.emit(new_offset, hist_len)


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


def _count_dir_with_cap(listdir_attr_fn, root: str, cap: int) -> dict:
    """Iteratively count files & subdirs below `root`, stopping early when
    the total exceeds `cap`.

    Pulled out as a pure function (taking a listdir-attr callable, not a
    paramiko client) so it can be unit-tested without an SSH server. The
    real call site passes `sftp.listdir_attr`; tests pass a closure over
    a fixture tree. Iterative on purpose — recursion would hit Python's
    default 1000-frame limit on the kind of pathological tree that makes
    this scan worth doing in the first place.

    Returns a dict {'files': int, 'dirs': int, 'capped': bool,
    'error': str|None}. `error` is set when the root itself cannot be
    listed — subdir read failures are silently skipped because partial
    counts are still informative.
    """
    result = {'files': 0, 'dirs': 0, 'capped': False, 'error': None}
    stack = [root]
    is_root = True
    while stack:
        if result['files'] + result['dirs'] > cap:
            result['capped'] = True
            return result
        p = stack.pop()
        try:
            entries = listdir_attr_fn(p)
        except IOError as e:
            if is_root:
                result['error'] = str(e)
                return result
            is_root = False
            continue
        is_root = False
        for a in entries:
            sub = p.rstrip('/') + '/' + a.filename
            if stat.S_ISDIR(a.st_mode or 0):
                result['dirs'] += 1
                stack.append(sub)
            else:
                result['files'] += 1
            if result['files'] + result['dirs'] > cap:
                result['capped'] = True
                return result
    return result


def _pl_pl(n: int, sg: str, pl_few: str, pl_many: str) -> str:
    """Render '{n} {noun}' with correct Polish declension (ui.utils.plural)."""
    from ui.utils import plural
    return plural(n, sg, pl_few, pl_many)


def _ssh_fingerprint(key) -> tuple[str, str]:
    """Return (storage_hex, display_openssh) fingerprints for a paramiko key.

    storage_hex is what we persist (back-compat with the old format).
    display_openssh matches `ssh-keygen -lf` so the user can copy-verify it
    against the server admin's known good value (`SHA256:abc...XYZ`).
    """
    raw = key.asbytes()
    h = hashlib.sha256(raw).digest()
    return (
        hashlib.sha256(raw).hexdigest(),
        "SHA256:" + base64.b64encode(h).decode('ascii').rstrip('='),
    )


class _HostKeyPrompt(QObject):
    """Bridge between paramiko's blocking missing_host_key() callback (worker
    thread) and the Qt modal dialog (GUI thread).

    paramiko invokes the policy synchronously during connect, so we have
    to block the worker until the user picks. Qt signals are queued
    cross-thread, so we emit and wait on a threading.Event the GUI
    handler sets when it's done.

    Must be instantiated on the GUI thread (do it from SshDialog.__init__
    before any worker is started) so the slot runs on that thread.
    """
    _ask_first   = pyqtSignal(str, str, str, object)         # host, key_type, fp, ev
    _ask_changed = pyqtSignal(str, str, str, str, object)    # host, key_type, old_fp, new_fp, ev

    def __init__(self):
        super().__init__()
        self._results: dict[int, bool] = {}
        self._ask_first.connect(self._on_first, Qt.ConnectionType.QueuedConnection)
        self._ask_changed.connect(self._on_changed, Qt.ConnectionType.QueuedConnection)

    def _on_first(self, host, key_type, fp, ev):
        try:
            box = QMessageBox()
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle("Nieznany host SSH")
            box.setText(f"Łączysz się po raz pierwszy z hostem '{host}'.")
            box.setInformativeText(
                f"Typ klucza:   {key_type}\n"
                f"Fingerprint:  {fp}\n\n"
                "Sprawdź ten fingerprint u administratora serwera. "
                "Zaakceptuj tylko jeśli się zgadza — w przeciwnym razie "
                "możesz paść ofiarą ataku MitM."
            )
            btn_y = box.addButton("Zaufaj i połącz", QMessageBox.ButtonRole.AcceptRole)
            btn_n = box.addButton("Anuluj", QMessageBox.ButtonRole.RejectRole)
            box.setDefaultButton(btn_n)
            box.exec()
            self._results[id(ev)] = (box.clickedButton() is btn_y)
        finally:
            ev.set()

    def _on_changed(self, host, key_type, old_fp, new_fp, ev):
        try:
            box = QMessageBox()
            box.setIcon(QMessageBox.Icon.Critical)
            box.setWindowTitle("UWAGA: zmienił się klucz hosta")
            box.setText(
                f"Klucz hosta '{host}' jest INNY niż zapamiętany.\n\n"
                "To może oznaczać atak MitM lub reinstalację serwera. "
                "Zweryfikuj zanim klikniesz cokolwiek."
            )
            box.setInformativeText(
                f"Typ klucza:        {key_type}\n"
                f"Zapamiętany:       SHA256(hex)={old_fp[:16]}…\n"
                f"Nowy fingerprint:  {new_fp}"
            )
            btn_cancel = box.addButton("Anuluj (zalecane)", QMessageBox.ButtonRole.RejectRole)
            btn_accept = box.addButton(
                "Zaakceptuj nowy klucz", QMessageBox.ButtonRole.DestructiveRole)
            box.setDefaultButton(btn_cancel)
            box.exec()
            self._results[id(ev)] = (box.clickedButton() is btn_accept)
        finally:
            ev.set()

    def ask_first(self, host: str, key_type: str, fp: str) -> bool:
        ev = threading.Event()
        self._ask_first.emit(host, key_type, fp, ev)
        ev.wait()
        return self._results.pop(id(ev), False)

    def ask_changed(self, host: str, key_type: str, old_fp: str, new_fp: str) -> bool:
        ev = threading.Event()
        self._ask_changed.emit(host, key_type, old_fp, new_fp, ev)
        ev.wait()
        return self._results.pop(id(ev), False)


_host_key_prompt: '_HostKeyPrompt | None' = None


def _get_host_key_prompt() -> '_HostKeyPrompt | None':
    """Return the GUI bridge for host-key prompts (lazy singleton).

    Must be called from the GUI thread the first time so the QObject
    binds its signals to that thread's event loop. Subsequent calls
    return the existing instance. Returns None if no QApplication is
    running yet — caller should fall back to legacy silent TOFU.
    """
    global _host_key_prompt
    if _host_key_prompt is None:
        from PyQt6.QtWidgets import QApplication
        app = QApplication.instance()
        if app is None:
            return None
        _host_key_prompt = _HostKeyPrompt()
        # Defensive: if a worker thread accidentally created us, snap
        # affinity back to the GUI thread so queued signals dispatch there.
        if _host_key_prompt.thread() is not app.thread():
            _host_key_prompt.moveToThread(app.thread())
    return _host_key_prompt


class _TofuHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Trust-On-First-Use with a real user prompt.

    Old behaviour: silently stored whatever fingerprint the server presented
    on the first connect — the user had no chance to verify and was
    vulnerable to a first-time MitM. Old mismatch behaviour: hard-raise
    BadHostKeyException with no escape hatch, so a legitimate server-key
    rotation required hand-editing ~/.hospitalhub_v2_known_hosts.

    New behaviour:
      • First connect → modal showing the OpenSSH-style fingerprint
        (SHA256:base64). User accepts → stored; rejects → SSHException.
      • Mismatch → loud security modal with both fingerprints. User
        either cancels (raise BadHostKeyException) or explicitly
        accepts the new key (store + proceed).

    Falls back to legacy silent-TOFU only when no GUI is available
    (running headless or before QApplication exists). Don't depend on
    that path in production — it's a footgun.
    """

    _KEYS_FILE = os.path.join(os.path.expanduser('~'), '.hospitalhub_v2_known_hosts')
    _cache: dict | None = None
    #: Several connects can verify at once (each in its own worker thread).
    _lock = threading.Lock()

    @classmethod
    def _load(cls) -> dict:
        if cls._cache is None:
            try:
                with open(cls._KEYS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                cls._cache = data if isinstance(data, dict) else None
                if cls._cache is None:
                    raise ValueError("not an object")
            except FileNotFoundError:
                cls._cache = {}
            except OSError as e:
                # Locked by an antivirus, no permission… — the file may be
                # fine.  Treating it as empty would let the next save replace
                # every remembered key with one host (review 68).  Refuse
                # this connect instead; the next one reads again.
                cls._cache = None
                raise paramiko.SSHException(
                    f"Nie można odczytać pliku zaufanych kluczy hostów: {e}")
            except Exception:
                # A damaged file is set aside, not silently replaced by an
                # empty one on the next save (2026-10-14, C1-09): the keys in
                # it may be the only record of what each server presented.
                try:
                    os.replace(cls._KEYS_FILE, cls._KEYS_FILE
                               + datetime.now().strftime('.corrupt-%Y%m%d-%H%M%S'))
                except OSError:
                    pass
                cls._cache = {}
        return cls._cache

    @classmethod
    def _save(cls) -> None:
        # Temporary file + replace: a crash mid-write must not leave half a
        # known-hosts file (C1-09).
        try:
            tmp = cls._KEYS_FILE + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(cls._cache, f, indent=2)
            os.replace(tmp, cls._KEYS_FILE)
        except Exception:
            pass

    def missing_host_key(self, client, hostname: str, key) -> None:
        with self._lock:
            self._verify(hostname, key)

    def _verify(self, hostname: str, key) -> None:
        known    = self._load()
        key_type = key.get_name()
        fp_hex, fp_display = _ssh_fingerprint(key)

        stored = known.get(hostname, {})
        if not isinstance(stored, dict):
            stored = {}
        if stored and key_type not in stored:
            # Known host, but a key of a type it never showed before
            # (C1-09).  That is what an attacker in the middle presents —
            # any type but the remembered one — so it is a *changed* key,
            # not a first connection, and never accepted without asking.
            prompt = _get_host_key_prompt()
            remembered = ", ".join(sorted(stored))
            if prompt is None or not prompt.ask_changed(
                    hostname, key_type,
                    f"(zapamiętany inny typ klucza: {remembered})", fp_display):
                raise paramiko.BadHostKeyException(hostname, key, key)
            stored[key_type] = fp_hex
            known[hostname]  = stored
            self._save()
            return
        if key_type in stored:
            if stored[key_type] == fp_hex:
                return                 # known good — silent allow
            # Mismatch — possible MitM or legit rotation.
            prompt = _get_host_key_prompt()
            if prompt is None or not prompt.ask_changed(
                    hostname, key_type, stored[key_type], fp_display):
                raise paramiko.BadHostKeyException(hostname, key, key)
            # User accepted — record new key and continue.
            stored[key_type] = fp_hex
            known[hostname]  = stored
            self._save()
            return

        # First connection — ask before trusting.
        prompt = _get_host_key_prompt()
        if prompt is None:
            # No GUI available (headless / very early startup). Legacy
            # silent-TOFU keeps the app usable; not a security claim.
            stored[key_type] = fp_hex
            known[hostname]  = stored
            self._save()
            return
        if not prompt.ask_first(hostname, key_type, fp_display):
            raise paramiko.SSHException(
                f"Klucz hosta {hostname} odrzucony przez użytkownika")
        stored[key_type] = fp_hex
        known[hostname]  = stored
        self._save()


def _enable_keepalive(c, interval: int = 30):
    """Send SSH keepalives so idle terminals/SFTP survive NAT/firewall idle
    timeouts. Hospital networks silently drop quiet TCP after a few minutes,
    leaving a half-open socket: the terminal tab "falls off" and the next
    listdir/read hangs forever (which also wedged the SFTP _listing_active
    guard, killing double-click). A 30 s keepalive both holds the NAT mapping
    open and lets paramiko notice a genuinely dead peer instead of blocking."""
    try:
        t = c.get_transport()
        if t is not None:
            t.set_keepalive(interval)
    except Exception:
        pass


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
        _enable_keepalive(c)
        return c

    # --- Has password ---
    try:
        c.connect(**base, password=password,
                  look_for_keys=False, allow_agent=False)
        _enable_keepalive(c)
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
    try:
        return _kbd_interactive_client(transport, host, port, user, password)
    except BaseException:
        # A refused key or a failed login must not leave the transport — and
        # its server login slot — open until LoginGraceTime (C1-14).
        try:
            transport.close()
        except Exception:
            pass
        raise


def _known_hosts_name(host: str, port: int) -> str:
    """The name paramiko's own connect() verifies a host key under — the same
    name the fallback must use, or one server gets two TOFU records (C1-14)."""
    return host if port == 22 else f"[{host}]:{port}"


def _kbd_interactive_client(transport, host, port, user, password):
    transport.start_client()
    # Host-key verification
    host_key = transport.get_remote_server_key()
    _TofuHostKeyPolicy().missing_host_key(None, _known_hosts_name(host, port),
                                          host_key)
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
    _enable_keepalive(c)
    return c


class _SshWorker(QThread):
    output    = pyqtSignal(str)
    connected = pyqtSignal()
    error     = pyqtSignal(str)
    done      = pyqtSignal()
    dropped   = pyqtSignal()   # connection lost unexpectedly → trigger auto-reconnect
    #: Received bytes were dropped (fast Ctrl+C): the terminal restarts its
    #: parser there (T-02).
    discontinuity = pyqtSignal()

    def __init__(self, host, user, password, cols=220, rows=50, port=22):
        super().__init__()
        self._host, self._user, self._pw = host, user, password
        self._port    = port
        self._cols    = cols
        self._rows    = rows
        self._channel = None
        self._client  = None
        self._running = False
        #: Set by stop() from the UI thread (2026-10-14, C1-05).  stop() during
        #: the connect has no client or channel to close yet, so run() checks
        #: this after authenticating and after opening the shell, and leaves.
        self._stop_requested = False
        # Thread-safe queue for outgoing data.  send() puts bytes here so the
        # worker drains it immediately on each loop tick — Ctrl+C reaches the
        # SSH channel within one iteration regardless of Qt event-queue depth.
        self._send_q: _queue.SimpleQueue[bytes] = _queue.SimpleQueue()
        # Wakeup event: set by send() so the worker exits its 20 ms idle wait
        # *immediately* when keystrokes arrive. Without this, Ctrl+C could be
        # delayed by up to 20 ms on heavy log streams (and longer if the prior
        # iteration's drain happened to land mid-sleep).
        self._wake = threading.Event()
        # Set by the UI thread when it has already written Ctrl+C straight
        # to the channel. Worker treats it as got_ctrl_c (drains recv buffer)
        # *without* re-sending — avoids the server seeing Ctrl+C twice and
        # the shell echoing a second '^C'.
        self._direct_ctrl_c_pending = False
        # Back-pressure: set by UI before .start() so the worker can check
        # how many chunks are queued in the terminal widget. When the queue
        # grows past _BP_HIGH, we pause recv() so the TCP receive buffer
        # fills up and the server slows down. Resumes when it drops below
        # _BP_LOW. No data is ever dropped — only throttled upstream.
        self._term_ref = None  # set externally; safe to read across threads
                               # (len(list) and a bool — GIL-atomic reads)
        # One decoder for the whole stream: a character cut between two
        # reads is completed by the next one instead of becoming U+FFFD
        # (T-06 — tmux pane borders are 3 bytes each).
        self._decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')

    # ── Interactive password input ─────────────────────────────────────

    def _read_interactive_line(self, echo: bool = True) -> str:
        """Read a line from the terminal send queue (blocks until Enter).

        Used during keyboard-interactive auth so the user can type a
        password directly in the terminal instead of a separate dialog.
        """
        buf = bytearray()
        while True:
            if self._stop_requested:
                return ''
            try:
                data = self._send_q.get(timeout=120)
            except _queue.Empty:
                return ''
            if self._stop_requested:
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

            # ── Authentication (re-prompt for password on failure) ─────
            # Like MobaXterm: when credentials are wrong we DON'T kill the
            # session and make the user press 'R' (which would just retry the
            # same bad password). Instead we ask for the password again right
            # here in the terminal and try once more with the new value.
            _MAX_PW_ATTEMPTS = 5
            _pw_attempt = 0
            while True:
                try:
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
                                self._host, self._user, self._pw, self._port)
                    break   # authenticated successfully
                except paramiko.AuthenticationException:
                    _pw_attempt += 1
                    if _pw_attempt >= _MAX_PW_ATTEMPTS:
                        self.error.emit("Błąd autentykacji — sprawdź login i hasło.")
                        return
                    # Wrong login/password → re-prompt for the password in the
                    # terminal and retry with the freshly typed value.
                    self.output.emit(
                        "\r\n\x1b[91mBłędny login lub hasło.\x1b[0m "
                        f"Wpisz hasło ponownie (login: {self._user}).\r\nPassword: ")
                    pw = self._read_interactive_line(echo=False)
                    if not pw:
                        self.error.emit("Anulowano logowanie.")
                        return
                    self._pw = pw   # retry loop picks this up via `if self._pw`

            if self._stop_requested:
                # The tab was closed while we were logging in (C1-05).
                self._close_quietly()
                return

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
            if self._stop_requested:
                self._close_quietly()
                return
            self.connected.emit()
            self._running = True
            while self._running and not self._stop_requested:
                # ── Drain outgoing queue FIRST ────────────────────────────────
                # send() puts bytes here so Ctrl+C reaches the SSH channel
                # within one loop iteration regardless of Qt event-queue depth.
                got_ctrl_c = False
                if self._direct_ctrl_c_pending:
                    # UI thread already wrote Ctrl+C straight to the channel.
                    # Don't re-send (would duplicate the cancel and produce a
                    # second '^C' echo from the shell). Just enter the same
                    # post-Ctrl+C drain path used for queued cancels.
                    self._direct_ctrl_c_pending = False
                    got_ctrl_c = True
                while not self._send_q.empty():
                    try:
                        data = self._send_q.get_nowait()
                        self._channel.send(data)
                        if b'\x03' in data:
                            got_ctrl_c = True
                    except Exception:
                        break

                if got_ctrl_c:
                    self._quiet_after_ctrl_c()
                    for _ in range(50):
                        time.sleep(0.01)
                        if self._channel.recv_ready():
                            self._drain_and_emit(max_total=262144)
                            break

                if self._channel.recv_ready():
                    # Aggressive back-pressure for MobaXterm-like instant
                    # Ctrl+C: only drain when the UI's pyte queue is fully
                    # empty, and emit at most ~2 chunks per drain. This
                    # caps the Qt event queue at 1-2 QMetaCallEvents ahead
                    # of any user keystroke, so Ctrl+C surfaces within
                    # ~20 ms instead of waiting behind a flush.
                    #
                    # Trade-off: throughput drops from ~3 MB/s to ~1 MB/s
                    # for very heavy log streams. TCP back-pressure handles
                    # the upstream — no data is dropped, server just slows.
                    t = self._term_ref
                    if t is None or t.pending_chunks() < 1:
                        self._drain_and_emit(max_total=32768)
                    # else: UI is behind; let the kernel buffer absorb it.
                    # We loop back, drain _send_q again (so Ctrl+C still goes
                    # out without delay), then re-check back-pressure.
                if (self._channel.exit_status != -1
                        and not self._channel.recv_ready()):
                    # The server sent an exit status: the shell ended
                    # (exit, Ctrl+D, a script finished).  Not
                    # exit_status_ready() nor status_event — paramiko sets
                    # both for ANY closed channel, so a dropped link looked
                    # like a logout and auto-reconnect never ran (UX audit
                    # S-01).  exit_status stays -1 until the message arrives.
                    break
                if self._channel.closed:
                    if self._session_dropped():
                        self.dropped.emit()
                    break
                # Idle wait — but wake immediately when send() pushes a
                # keystroke (e.g. Ctrl+C). Without this we could spend 20 ms
                # asleep while a Ctrl+C sits in _send_q.
                self._wake.wait(0.02)
                self._wake.clear()
        except paramiko.AuthenticationException:
            self.error.emit("Błąd autentykacji — sprawdź login i hasło.")
        except paramiko.BadHostKeyException as e:
            # The TOFU policy now handles mismatches with an explicit modal
            # and a user-driven accept-or-cancel choice. Reaching this
            # except means the user cancelled or no GUI prompt was
            # available — surface the rejection plainly.
            self.error.emit(
                f"Połączenie odrzucone — klucz hosta {e.hostname!r} nie zgadza się "
                "z zapisanym. Możliwy atak MitM."
            )
        except paramiko.SSHException as e:
            # Preserve the original message (was hidden behind type name —
            # the TOFU prompt's user-rejected message would otherwise look
            # like a generic "Błąd SSH: SSHException").
            msg = str(e) or type(e).__name__
            self.error.emit(f"Błąd SSH: {msg}")
        except OSError as e:
            self.error.emit(f"Błąd sieci: {e.strerror or type(e).__name__}")
        except Exception as e:
            self.error.emit(f"Błąd połączenia: {type(e).__name__}")
        finally:
            self.done.emit()

    def _quiet_after_ctrl_c(self) -> None:
        """Instant quiet after Ctrl+C on the shell screen: output already
        received is dropped.  Never inside a full-screen app — tmux, vim or
        less would be left believing the screen was updated when it was
        not (UX audit T-02)."""
        import time
        t = self._term_ref
        if t is not None and getattr(t, 'alt_screen', False):
            return
        dropped = False
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline and self._channel.recv_ready():
            self._channel.recv(65536)
            dropped = True
        if dropped:
            self._decoder.reset()
            self.discontinuity.emit()

    def _session_dropped(self) -> bool:
        """The channel closed without an exit status: did the link drop
        (idle NAT / firewall timeout, network change, server gone) or did
        the server close only this channel?

        paramiko unlinks the channel *before* it marks the transport dead,
        so a dead link can read "transport active" for a moment — wait for
        it briefly before calling it a clean close.
        """
        import time
        if self._channel.exit_status != -1:
            return False
        transport = self._client.get_transport() if self._client else None
        deadline = time.monotonic() + 0.5
        while (transport is not None and transport.is_active()
               and time.monotonic() < deadline):
            time.sleep(0.02)
        return transport is None or not transport.is_active()

    def _drain_and_emit(self, max_total: int = 131072):
        """Drain up to `max_total` bytes from the channel, decode once, and
        emit as multiple small ANSI-colorized chunks (~16 KB) split at line
        boundaries.

        Why split: pyte stream parsing in the UI thread cannot be interrupted
        mid-chunk. A single 1 MB chunk takes >100 ms, blocking Ctrl+C and
        typing. ~16 KB chunks let _flush_pending's 12 ms timeslice yield the
        UI thread between chunks. Splitting at '\\n' keeps log records intact
        for the colorize regexes (which match line-by-line).
        """
        chunks = []
        total = 0
        while self._channel.recv_ready() and total < max_total:
            buf = self._channel.recv(32768)
            if not buf:
                break
            chunks.append(buf)
            total += len(buf)
        if not chunks:
            return
        text = self._decoder.decode(b''.join(chunks))
        if not text:
            return
        EMIT_SIZE = 16384
        n = len(text)
        if n <= EMIT_SIZE:
            self.output.emit(self._highlight(text))
            return
        pos = 0
        while pos < n:
            end = min(pos + EMIT_SIZE, n)
            if end < n:
                nl = text.rfind('\n', pos, end)
                if nl > pos:
                    end = nl + 1
            self.output.emit(self._highlight(text[pos:end]))
            pos = end

    def _highlight(self, text: str) -> str:
        """Log highlighting — but not into a full-screen app (T-03)."""
        t = self._term_ref
        if ((t is not None and getattr(t, 'alt_screen', False))
                or _FULLSCREEN_ENTER_RE.search(text)):
            return text
        return _colorize_log(text)

    def send(self, data: bytes):
        """Queue bytes for immediate delivery by the worker thread."""
        self._send_q.put(data)
        self._wake.set()   # wake the run loop now — don't wait out the idle

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
        self._stop_requested = True
        self._running = False
        self._wake.set()   # break out of the idle wait so the loop exits now
        # Wake a login prompt that is waiting for typed input (C1-17): without
        # this the thread sat in a 120 s queue wait after its tab was closed.
        try:
            self._send_q.put(b'')
        except Exception:
            pass
        self._close_quietly()

    def _close_quietly(self):
        try:
            if self._channel: self._channel.close()
        except Exception:
            pass
        try:
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
            # The navigation channel: used from the UI thread (C1-11).
            try:
                sftp = open_sftp_bounded(c)
            except Exception:
                _close_sftp_pair(None, c)      # do not leave it logged in
                raise
            self.ready.emit(sftp, c)
        except paramiko.AuthenticationException:
            self.error.emit("Błąd autentykacji — sprawdź login i hasło.")
        except paramiko.BadHostKeyException as e:
            # TOFU policy already showed the security modal; reaching
            # here means the user picked Cancel (or no GUI was up).
            self.error.emit(
                f"Połączenie odrzucone — klucz hosta {e.hostname!r} nie zgadza się "
                "z zapisanym. Możliwy atak MitM."
            )
        except paramiko.SSHException as e:
            msg = str(e) or type(e).__name__
            self.error.emit(f"Błąd SSH: {msg}")
        except Exception as e:
            self.error.emit(f"Błąd połączenia: {type(e).__name__}")


def _friendly_sftp_error(text: str) -> str:
    """What a paramiko/OS error means for the user (UX audit E-15, S-06)."""
    low = (text or '').lower()
    if any(s in low for s in ('socket is closed', 'connection dropped',
                              'session not active', "has no attribute 'open_sftp'",
                              'eof during negotiation', 'connection reset')):
        return "połączenie z serwerem zostało przerwane"
    if 'permission denied' in low or 'errno 13' in low:
        return "brak uprawnień na serwerze"
    if 'no such file' in low or 'errno 2' in low:
        return "plik lub katalog nie istnieje"
    if 'no space left' in low:
        return "brak miejsca na dysku serwera"
    return text


def _listdir_attr_lenient(sftp, path: str):
    """listdir_attr that survives file names which are not UTF-8.

    paramiko decodes every name strictly, so ONE name written in CP1250 /
    ISO-8859-2 on an older server made the whole directory unlistable (UX
    audit S-04).  Same protocol exchange as paramiko's listdir_attr; a name
    that does not decode is shown with U+FFFD.  Returns (entries, bad).
    """
    from paramiko.sftp import (CMD_OPENDIR, CMD_READDIR, CMD_HANDLE,
                               CMD_NAME, CMD_CLOSE)
    from paramiko.sftp_attr import SFTPAttributes
    t, msg = sftp._request(CMD_OPENDIR, path)
    if t != CMD_HANDLE:
        raise IOError("Nie można otworzyć katalogu")
    handle = msg.get_binary()
    entries, bad = [], 0
    try:
        while True:
            try:
                t, msg = sftp._request(CMD_READDIR, handle)
            except EOFError:
                break
            if t != CMD_NAME:
                raise IOError("Nieoczekiwana odpowiedź serwera SFTP")
            for _ in range(msg.get_int()):
                raw = msg.get_string()
                longname = msg.get_string()
                try:
                    name = raw.decode('utf-8')
                except UnicodeDecodeError:
                    name = raw.decode('utf-8', errors='replace')
                    bad += 1
                attr = SFTPAttributes._from_msg(
                    msg, name, longname.decode('utf-8', errors='replace'))
                if name not in ('.', '..'):
                    entries.append(attr)
    finally:
        try:
            sftp._request(CMD_CLOSE, handle)
        except Exception:
            pass
    return entries, bad


class _SftpListWorker(QThread):
    listing = pyqtSignal(str, list)
    error   = pyqtSignal(str)
    #: Something the user should know about a listing that worked.
    note    = pyqtSignal(str)

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
            try:
                entries = self._sftp.listdir_attr(path)
            except UnicodeDecodeError:
                entries, bad = _listdir_attr_lenient(self._sftp, path)
                from ui.utils import plural
                self.note.emit(
                    f"Katalog zawiera {plural(bad, 'nazwę', 'nazwy', 'nazw')} "
                    "w kodowaniu innym niż UTF-8 — pokazane z „�”; operacje "
                    "na tych plikach mogą się nie udać.")
            result  = []
            from ui.utils import polish_key
            for e in sorted(entries, key=lambda x: (
                not stat.S_ISDIR(x.st_mode), polish_key(x.filename)
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


#: Leaves whatever a dead session switched on: alternate screen, scroll
#: region, application cursor keys, hidden cursor, attributes, bracketed
#: paste, mouse reporting, autowrap off (T-20).
_TERM_SOFT_RESET = ('\x0f\x1b[?1049l\x1b[?1047l\x1b[?47l\x1b[r\x1b[?1l'
                    '\x1b[?25h\x1b(B\x1b[0m\x1b[?2004l\x1b[?1000l'
                    '\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?7h')


def _own_signals(obj) -> list:
    """The signals `obj` declares in this module's classes — not the ones
    QThread itself has (``finished`` keeps :func:`retire_thread` working)."""
    out = []
    for cls in type(obj).__mro__:
        if cls.__module__ != __name__:
            continue
        for name, value in vars(cls).items():
            if isinstance(value, pyqtSignal):
                out.append(getattr(obj, name))
    return out


def _remove_partial_download(path: str, tries: int = 10) -> None:
    """Delete a cut download; while the retired worker still holds the file
    open (Windows locks it), try again a little later."""
    try:
        if os.path.exists(path):
            os.remove(path)
        return
    except OSError:
        pass
    if tries > 0:
        QTimer.singleShot(500, lambda: _remove_partial_download(path, tries - 1))


def _unplug_and_retire(workers, budget_ms: int = 1000) -> None:
    """Closing a window: cut every worker's signals, then give the running
    ones one shared `budget_ms` and keep the rest alive until they end.

    UX audit 2026-10-16, S-02/S-08: the windows waited 0.8–1 s per thread in
    turn and left the signals plugged in.  A transfer or listing that outlived
    the wait then reported into the deleted window — a QMessageBox on a
    destroyed parent took the whole process down (0xC0000374), unsaved vaults
    included.  Signals go first, for finished threads too: what they emitted
    last may still be queued.
    """
    import time
    from ui.thread_retire import retire_thread
    alive = []
    for w in workers:
        if w is None:
            continue
        for signal in _own_signals(w):
            try:
                signal.disconnect()
            except Exception:
                pass
        try:
            if w.isRunning():
                alive.append(w)
        except RuntimeError:
            pass                    # the C++ object is already gone
    deadline = time.monotonic() + budget_ms / 1000.0
    for w in alive:
        left = int((deadline - time.monotonic()) * 1000)
        try:
            if left > 0:
                w.wait(left)
            retire_thread(w)
        except RuntimeError:
            pass


class _TransferWorker(QThread):
    progress  = pyqtSignal(int)
    done      = pyqtSignal(str)
    error     = pyqtSignal(str)
    cancelled = pyqtSignal()

    def __init__(self, ssh_client, mode, remote, local, total=0, open_lock=None):
        super().__init__()
        self._ssh_client = ssh_client
        self._mode = mode
        self._remote, self._local, self._total = remote, local, total
        self._open_lock = open_lock or threading.Lock()
        self._cancel = False
        self._sftp = None   # private SFTP channel — safe to close on cancel

    def cancel(self):
        self._cancel = True
        # Hard cancel: close the private SFTP channel so paramiko's blocking
        # read/write raises immediately instead of waiting for the next chunk.
        s = self._sftp
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    def run(self):
        try:
            with self._open_lock:
                self._sftp = self._ssh_client.open_sftp()
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
                    # Not sftp.put: its pipelined writes hide a block the
                    # server refused (G10, 2026-10-15) — see upload_direct.
                    upload_direct(self._sftp, self._local, self._remote, callback=cb)
                    self.done.emit(f"Wgrano: {os.path.basename(self._local)}")
            finally:
                try:
                    self._sftp.close()
                except Exception:
                    pass
        except _CancelledError:
            self.cancelled.emit()
        except Exception as e:
            # If hard-cancel closed the channel mid-transfer, paramiko
            # surfaces a generic exception — surface it as cancellation,
            # not an error.
            if self._cancel:
                self.cancelled.emit()
            else:
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
        self._cancel_hook = None

    def set_cancel_hook(self, hook):
        """Register a callable invoked from cancel() — typically used to
        close an open SFTP channel so a blocking transfer raises promptly."""
        self._cancel_hook = hook

    def cancel(self):
        self._cancel = True
        h = self._cancel_hook
        if h is not None:
            try:
                h()
            except Exception:
                pass

    def run(self):
        try:
            self._fn()
            self.done.emit()
        except _CancelledError:
            self.cancelled.emit()
        except Exception as e:
            # Hard-cancelled transfers surface as generic exceptions —
            # report them as cancellation instead of an error.
            if self._cancel:
                self.cancelled.emit()
            else:
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
            # Same type: Polish alphabetical order (case-insensitive)
            from ui.utils import polish_key
            return polish_key(my_name) < polish_key(ot_name)
        except Exception:
            return super().__lt__(other)


# ──────────────────────────────────────── SFTP file icons ─────────────────────

_SFTP_ICON_CACHE: dict[str, QIcon] = {}

def _sftp_icon(key: str) -> QIcon:
    """Return a cached QPainter-drawn icon for SFTP file types."""
    if key in _SFTP_ICON_CACHE:
        return _SFTP_ICON_CACHE[key]
    # The 16-px drawings run scaled to the real pixel size (150 %, 200 %, a
    # 4K TV) instead of a 16×16 bitmap being stretched.
    ic = painter_icon(_SFTP_ICON_DRAW[key], base=16)
    _SFTP_ICON_CACHE[key] = ic
    return ic


#: Dark fills of the file icons and what they become in the light theme —
#: QPainter colours never pass through the stylesheet remap (UX audit V-11).
_LIGHT_ICON_FILLS = {
    "#21262d": "#ffffff", "#1a1e24": "#f6f8fa", "#30363d": "#d0d7de",
    "#1f3a5f": "#ddf4ff", "#2d1117": "#ffebe9", "#0d1117": "#ffffff",
}


def _ic(hex_color: str) -> QColor:
    """An icon colour for the active theme."""
    if theme.is_light():
        return QColor(_LIGHT_ICON_FILLS.get(hex_color.lower(), hex_color))
    return QColor(hex_color)


def _draw_folder(p: QPainter, s: int):
    """Yellow folder icon."""
    c = _ic("#e2b340")
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
    p.setBrush(QBrush(_ic("#f0c850")))
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
    p.setPen(QPen(_ic("#8b949e"), 1.2))
    p.setBrush(QBrush(_ic("#21262d")))
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
    p.setPen(QPen(_ic("#8b949e"), 0.8))
    p.drawLine(10, 1, 10, 4)
    p.drawLine(10, 4, 13, 4)


def _draw_file_text(p: QPainter, s: int):
    """Text file — lines inside a doc."""
    _draw_file_generic(p, s)
    p.setPen(QPen(_ic("#7d8590"), 1.0))
    for y in (7, 9.5, 12):
        p.drawLine(5, int(y), 11, int(y))


def _draw_file_script(p: QPainter, s: int):
    """Shell/script file — terminal prompt icon."""
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(_ic("#1a1e24")))
    p.drawRoundedRect(1, 1, 14, 14, 2.5, 2.5)
    # Title bar
    p.setBrush(QBrush(_ic("#30363d")))
    p.drawRoundedRect(1, 1, 14, 4, 2.5, 2.5)
    p.drawRect(1, 3, 14, 2)
    # Prompt >_
    p.setPen(QPen(_ic("#3fb950"), 1.5))
    p.drawLine(4, 9, 7, 11)
    p.drawLine(4, 13, 7, 11)
    p.setPen(QPen(_ic("#8b949e"), 1.3))
    p.drawLine(9, 13, 12, 13)


def _draw_file_code(p: QPainter, s: int):
    """Code file — angle brackets < />."""
    _draw_file_generic(p, s)
    p.setPen(QPen(_ic("#58a6ff"), 1.3))
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
    p.setPen(QPen(_ic("#e2b340"), 1.2))
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawEllipse(int(cx - r), int(cy - r), int(2 * r), int(2 * r))
    p.setPen(QPen(_ic("#e2b340"), 1.0))
    for i in range(6):
        a = math.radians(i * 60)
        x1, y1 = cx + r * math.cos(a), cy + r * math.sin(a)
        x2, y2 = cx + (r + 1.3) * math.cos(a), cy + (r + 1.3) * math.sin(a)
        p.drawLine(int(x1), int(y1), int(x2), int(y2))


def _draw_file_archive(p: QPainter, s: int):
    """Archive file — zip icon."""
    _draw_file_generic(p, s)
    p.setPen(QPen(_ic("#da8b45"), 1.2))
    # Zigzag
    p.drawLine(7, 6, 9, 8)
    p.drawLine(9, 8, 7, 10)
    p.drawLine(7, 10, 9, 12)


def _draw_file_image(p: QPainter, s: int):
    """Image file — landscape icon."""
    _draw_file_generic(p, s)
    # Mountain
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(_ic("#3fb950")))
    path = QPainterPath()
    path.moveTo(5, 13)
    path.lineTo(8, 8)
    path.lineTo(11, 13)
    path.closeSubpath()
    p.drawPath(path)
    # Sun
    p.setBrush(QBrush(_ic("#e2b340")))
    p.drawEllipse(10, 6, 3, 3)


def _draw_file_log(p: QPainter, s: int):
    """Log file — scroll icon."""
    _draw_file_generic(p, s)
    p.setPen(QPen(_ic("#da8b45"), 1.0))
    for y in (7, 9, 11, 13):
        w = 6 if y < 13 else 4
        p.drawLine(5, y, 5 + w, y)


def _draw_file_data(p: QPainter, s: int):
    """Data/DB file — cylinder."""
    p.setPen(QPen(_ic("#8b949e"), 1.0))
    p.setBrush(QBrush(_ic("#1f3a5f")))
    p.drawEllipse(3, 1, 10, 4)
    p.drawRect(3, 3, 10, 10)
    p.setBrush(QBrush(_ic("#1f3a5f")))
    p.drawEllipse(3, 11, 10, 4)
    p.setPen(QPen(_ic("#58a6ff"), 1.0))
    p.drawEllipse(3, 1, 10, 4)


def _draw_file_pdf(p: QPainter, s: int):
    """PDF file — red document."""
    p.setPen(QPen(_ic("#f85149"), 1.2))
    p.setBrush(QBrush(_ic("#2d1117")))
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
    p.setPen(QPen(_ic("#f85149"), 0.8))
    p.drawLine(10, 1, 10, 4)
    p.drawLine(10, 4, 13, 4)
    # "P" letter
    p.setPen(QPen(_ic("#f85149"), 1.5))
    p.drawLine(6, 7, 6, 13)
    p.drawLine(6, 7, 9, 7)
    p.drawLine(9, 7, 9, 10)
    p.drawLine(6, 10, 9, 10)


def _draw_parent_dir(p: QPainter, s: int):
    """Parent dir (..) — folder with up arrow."""
    _draw_folder(p, s)
    p.setPen(QPen(_ic("#0d1117"), 2.0))
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


class _SftpFileTable(QTableWidget):
    """QTableWidget with internal drag-and-drop so users can move files between
    folders by dragging a row onto a folder row.

    External drops (files from Explorer) bubble up to SftpPanel.dropEvent for
    upload — we only accept our own mime type here and ignore everything else.
    """

    sftp_move = pyqtSignal(list, str)  # source names, destination folder name
    _MIME = 'application/x-hh-sftp-paths'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        # Use DragOnly for outgoing + override dropEvent for incoming, so we
        # don't get Qt's default in-table reordering behaviour (which would
        # try to rewrite cell text on drop).
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)
        self._drag_start_pos = None
        self._drop_target_row = -1

    # ── Drag start ────────────────────────────────────────────────────────

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._drag_start_pos = e.position().toPoint()
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e):
        if (self._drag_start_pos is None
                or not (e.buttons() & Qt.MouseButton.LeftButton)):
            return super().mouseMoveEvent(e)
        dist = (e.position().toPoint() - self._drag_start_pos).manhattanLength()
        if dist < QApplication.startDragDistance():
            return super().mouseMoveEvent(e)
        # Collect distinct names from selected rows (skip the .. entry).
        names: list[str] = []
        seen = set()
        for it in self.selectedItems():
            if it.column() != 0:
                continue
            data = it.data(Qt.ItemDataRole.UserRole)
            if not data:
                continue
            name = data[0]
            if name in seen or name == '..':
                continue
            seen.add(name)
            names.append(name)
        self._drag_start_pos = None
        if not names:
            return
        mime = QMimeData()
        mime.setData(self._MIME, '\n'.join(names).encode('utf-8'))
        drag = QDrag(self)
        drag.setMimeData(mime)
        drag.exec(Qt.DropAction.MoveAction)

    # ── Drop highlighting ─────────────────────────────────────────────────

    def _set_drop_target(self, row: int):
        if row == self._drop_target_row:
            return
        highlight = QBrush(QColor('#1a3050'))
        clear = QBrush()
        if self._drop_target_row >= 0:
            for col in range(self.columnCount()):
                cell = self.item(self._drop_target_row, col)
                if cell:
                    cell.setBackground(clear)
        if row >= 0:
            for col in range(self.columnCount()):
                cell = self.item(row, col)
                if cell:
                    cell.setBackground(highlight)
        self._drop_target_row = row

    # ── Drop acceptance ───────────────────────────────────────────────────

    def dragEnterEvent(self, e):
        if e.mimeData().hasFormat(self._MIME):
            e.acceptProposedAction()
        else:
            e.ignore()   # let SftpPanel handle external file drops

    def dragMoveEvent(self, e):
        if not e.mimeData().hasFormat(self._MIME):
            e.ignore()
            return
        row = self.indexAt(e.position().toPoint()).row()
        target_ok = False
        if row >= 0:
            it = self.item(row, 0)
            if it:
                data = it.data(Qt.ItemDataRole.UserRole)
                if data and data[1]:   # is_dir
                    src = (e.mimeData().data(self._MIME)
                           .data().decode('utf-8').split('\n'))
                    if data[0] not in src:
                        target_ok = True
        self._set_drop_target(row if target_ok else -1)
        if target_ok:
            e.acceptProposedAction()
        else:
            e.ignore()

    def dragLeaveEvent(self, e):
        self._set_drop_target(-1)
        super().dragLeaveEvent(e)

    def dropEvent(self, e):
        if not e.mimeData().hasFormat(self._MIME):
            e.ignore()
            return
        row = self.indexAt(e.position().toPoint()).row()
        self._set_drop_target(-1)
        if row < 0:
            e.ignore()
            return
        it = self.item(row, 0)
        data = it.data(Qt.ItemDataRole.UserRole) if it else None
        if not data or not data[1]:
            e.ignore()
            return
        target = data[0]
        src = (e.mimeData().data(self._MIME)
               .data().decode('utf-8').split('\n'))
        src = [n for n in src if n and n != target]
        if not src:
            e.ignore()
            return
        self.sftp_move.emit(src, target)
        e.acceptProposedAction()


_SFTP_PANEL_SEQ = iter(range(1, 1 << 62))

#: Device names Windows reserves in any directory, with or without extension.
_WINDOWS_RESERVED = frozenset(
    ["CON", "PRN", "AUX", "NUL"] + [f"COM{i}" for i in range(1, 10)]
    + [f"LPT{i}" for i in range(1, 10)])


def safe_local_name(name: str) -> str | None:
    r"""`name` as a plain Windows file name, or ``None`` if it cannot be one.

    2026-10-14 (audit C1-06): a Linux file name may legally contain a
    backslash and a colon, so a remote name such as ``..\..\Startup\x.bat``
    or ``C:\x`` joined to the chosen folder wrote outside it.  Refused here:
    separators, drive and stream colons, ``.``/``..``, control characters,
    reserved device names and a trailing dot or space (which Windows strips).
    """
    if not isinstance(name, str) or not name or len(name) > 255:
        return None
    if any(c in name for c in '\\/:*?"<>|') or any(ord(c) < 32 for c in name):
        return None
    if name in (".", "..") or name[-1] in ". ":
        return None
    if name.split(".")[0].upper() in _WINDOWS_RESERVED:
        return None
    return name


#: client object -> a number never handed out twice in this process.
_CONNECTION_TOKENS: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()
_CONNECTION_SEQ = iter(range(1, 1 << 62))


def connection_token(client) -> str:
    """A name for one SSH connection that no other connection ever gets."""
    if client is None:
        return "none"
    try:
        token = _CONNECTION_TOKENS.get(client)
        if token is None:
            token = f"c{next(_CONNECTION_SEQ)}"
            _CONNECTION_TOKENS[client] = token
        return token
    except TypeError:           # not weak-referenceable: unique but uncached
        return f"u{next(_CONNECTION_SEQ)}"


def mode_allows_write(mode, uid, gid, identity) -> bool:
    """Do POSIX mode bits let `identity` = (uid, gids) write the file?

    ``None`` anywhere means "cannot tell" and answers True (C1-12)."""
    if not isinstance(mode, int):
        return True
    if identity is not None and identity[0] == 0:
        return True                     # root writes regardless of mode bits
    if not mode & 0o222:
        return False                    # nobody else may write
    if identity is None:
        return True
    my_uid, my_gids = identity
    if uid is not None and uid == my_uid:
        return bool(mode & 0o200)
    if gid is not None and gid in my_gids:
        return bool(mode & 0o020)
    return bool(mode & 0o002)


#: For SFTP channels the UI thread waits on (2026-10-14, C1-11): opening the
#: channel and every reply after that.  Without it a half-open socket froze
#: the window for paramiko's default hour on a stat(), a flush or a close.
_UI_SFTP_TIMEOUT_S = 20


def open_sftp_bounded(client, timeout: float = _UI_SFTP_TIMEOUT_S):
    """An SFTP client over `client` whose channel open and replies time out."""
    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise paramiko.SSHException("Połączenie SSH jest zamknięte")
    channel = transport.open_session(timeout=timeout)
    channel.settimeout(timeout)
    channel.invoke_subsystem("sftp")
    return paramiko.SFTPClient(channel)


def _close_sftp_pair(sftp, client) -> None:
    """Close an SFTP channel and its SSH client.  Never raises."""
    for obj in (sftp, client):
        try:
            if obj is not None:
                obj.close()
        except Exception:
            pass


def sftp_temp_root() -> str:
    """This process's directory for files opened from SFTP."""
    return os.path.join(tempfile.gettempdir(), f'HospitalHubV2_{os.getpid()}')


def sftp_temp_path(panel_dir: str, server: str, remote: str, name: str) -> str:
    """Where the local copy of `remote` on `server` lives for one panel.

    2026-10-14 (audit C1-01/C1-02): the path used to be the process temp
    directory plus the bare file name.  Two SSH windows — or two directories
    of one server — opening ``config.xml`` shared one local file, and the
    edit watcher of one window uploaded the other server's content to its
    own server, unasked.  Now every panel has its own directory, and every
    (server, remote path) pair its own subdirectory, so the file keeps its
    original name (for the editor) and nothing is shared.
    """
    safe_name = safe_local_name(os.path.basename(name or '')) or 'file'
    key = f"{server}\0{remote}".encode('utf-8', 'surrogatepass')
    return os.path.join(panel_dir, hashlib.sha1(key).hexdigest()[:12], safe_name)


def local_part_path(local: str) -> str:
    """A private file next to `local` that a download is written into first.

    2026-10-15 (F1): downloads wrote straight into the watched local copy.
    "Otwórz za pomocą…" of a file that was already open re-downloaded into
    it while the watch was live, so the poll could upload a half-written
    download — and a cancel deleted the copy the editor was working on.
    The download now lands here and replaces the copy only when complete.
    """
    return f"{local}.{os.urandom(4).hex()}.part"


def unsent_copies_dir() -> str:
    """Where edits that could not reach the server are kept at a close."""
    return os.path.join(os.path.expanduser('~'), 'Documents',
                        'HospitalHub - niewysłane zmiany')


def preserve_unsent_copy(local: str) -> str | None:
    """Copy `local` out of the panel's temp directory, which the window's
    close deletes (2026-10-21): an edit the close could not upload — the
    server file changed, the link was gone — used to vanish with it.
    Returns the copy's path, or None."""
    try:
        folder = unsent_copies_dir()
        os.makedirs(folder, exist_ok=True)
        target = os.path.join(
            folder, f"{datetime.now():%Y%m%d-%H%M%S} {os.path.basename(local)}")
        shutil.copy2(local, target)
        return target
    except OSError:
        return None


def _mtime_or_none(path: str):
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def replace_local_copy(part: str, local: str, expect_mtime=None) -> None:
    """Put a finished download in place of the local copy, or fail clearly.

    `expect_mtime` is the copy's mtime when the download started: if the
    editor saved it meanwhile (review 2026-10-15 M2), the copy is kept and
    the download dropped — its unsent edit is uploaded by the poll later."""
    if _mtime_or_none(local) != expect_mtime:
        try:
            os.remove(part)
        except OSError:
            pass
        raise IOError(
            f"'{os.path.basename(local)}' został zapisany w edytorze podczas "
            "pobierania — lokalnej kopii nie nadpisano")
    try:
        os.replace(part, local)
    except OSError as e:
        try:
            os.remove(part)
        except OSError:
            pass
        raise IOError(
            f"nie można podmienić lokalnej kopii '{os.path.basename(local)}' "
            f"— zamknij ją w edytorze i otwórz ponownie ({e.strerror or e})") from e


#: 2026-10-15 (P1, RELEASE_READINESS "auto-upload nieatomowy"): an edit saved
#: in the external editor goes back through a temp file next to the original
#: and an atomic posix-rename over it, so a broken transfer never leaves the
#: server file truncated.  OFF until the SFTP write safety and compatibility
#: test (gate G10): the replace is a new file — owner, mode bits and ACLs
#: are not all carried over, and a temp file briefly appears in the
#: directory.  Off = the old direct put.
#: 2026-10-21 (owner): ON.  Where the server does not allow it (no write
#: access to the directory, a file owned by someone else, no posix-rename,
#: the file gone) the edit is written in place as before instead of being
#: refused — see ``upload_edit(fallback_direct=True)``.
SFTP_SAFE_REPLACE_ENABLED = True


class SafeReplaceError(IOError):
    """The safe replace cannot be done; the server file is untouched."""


class SafeReplaceUnsupported(SafeReplaceError):
    """The server does not allow the safe replace for this file (directory
    permissions, owner, posix-rename, ...).  Nothing has been written that
    could fail the same way in place, so the direct write may still go."""


def remote_part_path(target: str) -> str:
    """Hidden temp name next to `target`: a leading dot and a ``.part``
    suffix, so a directory listing or a process that skips dot files or
    filters on the extension does not take it for the real file."""
    import posixpath
    head, base = posixpath.split(target)
    return posixpath.join(head, f".{base}.hhv2-{os.urandom(4).hex()}.part")


#: One SFTP write request: paramiko's own cap per request.
_ACK_WRITE_CHUNK = 32768


def _write_acknowledged(sftp, local: str, remote: str, mode: str, total: int,
                        callback, before_data=None) -> None:
    """Write `local` to `remote`, every block confirmed by the server.

    2026-10-15 (G10 protocol test): paramiko pipelines writes — ``put`` turns
    it on by itself — and reads the server's answers only every ~100
    requests; answers still pending when the file is closed are dropped
    unread.  A write the server refused in the middle (disk full, quota, an
    I/O error) was therefore never reported, and when a later block landed
    the file even had the right size.  Here the handle is unbuffered and not
    pipelined: each ``write`` sends one request and waits for its status, so
    the first refused block raises at once.  Slower on a high-latency link —
    one round trip per 32 kB — which edited files do not notice.

    `mode` is ``'wb'`` (truncate and write in place: a broken transfer can
    still leave the file cut short) or ``'wbx'`` (a new file only).
    `before_data` runs on the open handle before the first byte.
    """
    with open(local, 'rb') as src:
        f = sftp.open(remote, mode, bufsize=0)
        try:
            if before_data is not None:
                before_data(f)
            done = 0
            while True:
                chunk = src.read(_ACK_WRITE_CHUNK)
                if not chunk:
                    break
                f.write(chunk)              # waits for the server's status
                done += len(chunk)
                if callback is not None:
                    callback(done, total)
        except BaseException:
            try:
                f.close()
            except Exception:
                pass                        # the first error is the one to report
            raise
        f.close()


def upload_direct(sftp, local: str, remote: str, callback=None):
    """Create or overwrite `remote` in place with `local`, every block
    acknowledged, then compare sizes; return the final stat (None when the
    server cannot be asked after a successful write).  Used by plain uploads
    and by `upload_edit` in direct mode.  A broken transfer leaves `remote`
    cut short — that is what the safe-replace mode is for."""
    local_size = os.path.getsize(local)
    _write_acknowledged(sftp, local, remote, 'wb', local_size, callback)
    try:
        final = sftp.stat(remote)
    except Exception:
        return None                     # as before: unverifiable is not failure
    if (final.st_size or 0) != local_size:
        raise IOError(
            f"weryfikacja po zapisie: rozmiar zdalny {final.st_size} B "
            f"!= lokalny {local_size} B")
    return final


def _remote_state(sftp, path: str):
    """True / False = `path` exists / does not; None = cannot tell."""
    try:
        sftp.stat(path)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return None


class RemoteChangedError(IOError):
    """The server file is no longer the one the edit started from; nothing
    was written.  `mtime`/`size` describe it now; `deleted` = it is gone."""

    def __init__(self, remote: str, mtime: int = 0, size: int = 0,
                 deleted: bool = False):
        self.remote, self.mtime, self.size, self.deleted = remote, mtime, size, deleted
        what = ("został usunięty z serwera" if deleted
                else "zmienił się na serwerze od chwili otwarcia")
        super().__init__(f"'{posixpath.basename(remote)}' {what} — "
                         "nic nie wgrano")


def check_remote_unchanged(sftp, remote: str, server_mtime: int,
                           server_size: int) -> None:
    """Raise RemoteChangedError when `remote` differs from what was downloaded.

    2026-10-21 (owner: "as safe as MobaXterm"): a save in the editor wrote the
    whole local copy over the server file without looking at it, so a change
    made meanwhile — the same file saved from a second tab or window, ``vim``
    in the terminal, a colleague, a program — was lost without a word.  Now
    the file's mtime and size are compared with the ones recorded at the
    download first.  An unknown baseline (mtime 0) or a server that cannot be
    asked is not a conflict: the write goes as before.
    """
    if not server_mtime:
        return
    try:
        st = sftp.stat(remote)
    except FileNotFoundError:
        raise RemoteChangedError(remote, deleted=True) from None
    except Exception:
        return
    mtime, size = int(st.st_mtime or 0), st.st_size or 0
    if mtime != int(server_mtime) or size != (server_size or 0):
        raise RemoteChangedError(remote, mtime, size)


def upload_edit(sftp, local: str, remote: str, callback=None,
                safe_replace: bool | None = None, before_commit=None,
                leftovers: list | None = None, fallback_direct: bool = False,
                in_place: list | None = None):
    """Send an edited local copy back to `remote`; return the final stat
    (None when the server cannot be asked after a successful write).
    The callers check first that the server file is still the one the edit
    started from (:func:`check_remote_unchanged`, 2026-10-21).

    Direct mode (``safe_replace`` False) writes over the file in
    place — every block acknowledged by the server (no pipelining, so a
    refused write is reported, not hidden), then the size is compared.  It
    does NOT protect the original: a transfer that breaks or is cancelled
    leaves the server file truncated.  Safe mode writes a
    new, owner-only temp file in the same directory, checks its size, gives
    it the original's owner and permissions, and posix-renames it over the
    original.  Anything it cannot do raises SafeReplaceError with the
    original untouched.

    `fallback_direct` (2026-10-21, the panel's saves): when the server does
    not allow the safe replace for this file (SafeReplaceUnsupported — no
    write access to the directory, an owner it may not set, no posix-rename,
    not a regular file, the file gone) the edit is written in place, as
    before the safe mode existed, instead of being refused.  A temp write
    that broke (disk full, the link dropped), a cancel or an unconfirmed
    rename never fall back — the original stays as it was.
    `in_place`, when given, gets one entry as an in-place write starts: ''
    in direct mode, the reason the safe replace was not possible otherwise.
    `before_commit` runs just before the rename or the fallback write (the
    last point where a cancel still leaves the original as it was).  A temp
    file that could not be removed afterwards (the link is gone) is appended
    to `leftovers`.
    """
    if safe_replace is None:
        safe_replace = SFTP_SAFE_REPLACE_ENABLED
    if not safe_replace:
        if in_place is not None:
            in_place.append('')
        return upload_direct(sftp, local, remote, callback)
    try:
        return _replace_via_temp(sftp, local, remote, callback,
                                 before_commit, leftovers)
    except SafeReplaceUnsupported as e:
        if not fallback_direct:
            raise
        reason = str(e)
    if before_commit is not None:
        before_commit()
    if in_place is not None:
        in_place.append(reason)
    return upload_direct(sftp, local, remote, callback)


def _in_place_note(in_place: list) -> str:
    """Status-line suffix when a save had to be written in place although the
    safe replace is on."""
    if not in_place or not in_place[0]:
        return ''
    return " (zapis bezpośredni — serwer nie pozwala tu na bezpieczną podmianę)"


def _replace_via_temp(sftp, local: str, remote: str, callback, before_commit,
                      leftovers: list | None):
    """The safe mode of :func:`upload_edit`."""
    local_size = os.path.getsize(local)
    untouched = "plik na serwerze nie został zmieniony."
    try:
        target = remote
        orig = sftp.lstat(remote)
        if stat.S_ISLNK(orig.st_mode or 0):
            # Replace the file the link points at and keep the link itself.
            target = sftp.normalize(remote)
            orig = sftp.lstat(target)
    except FileNotFoundError as e:
        raise SafeReplaceUnsupported(
            f"'{remote}' nie istnieje już na serwerze — bezpieczna podmiana "
            "nie tworzy pliku od nowa.") from e
    except Exception as e:
        raise SafeReplaceUnsupported(
            f"Nie można odczytać '{remote}' ({e}) — {untouched}") from e
    if not stat.S_ISREG(orig.st_mode or 0):
        raise SafeReplaceUnsupported(
            f"'{remote}' nie jest zwykłym plikiem — bezpieczna podmiana "
            f"niemożliwa, {untouched}")
    want_mode = (orig.st_mode or 0) & 0o7777
    want_owner = (orig.st_uid, orig.st_gid)

    tmp = remote_part_path(target)
    committed = False
    opened = [False]        # the temp exists and is private: data goes next

    def private(f):
        f.chmod(0o600)
        opened[0] = True
    try:
        try:
            # Created (never an existing file) readable by its owner only,
            # so the edited content is never readable by other users, not
            # even for the length of the transfer (review 2026-10-15 L5).
            _write_acknowledged(sftp, local, tmp, 'wbx', local_size, callback,
                                before_data=private)
        except _CancelledError:
            raise
        except Exception as e:
            if not opened[0]:
                # No temp file allowed here (directory permissions, a quota
                # on new files, an extension the server lacks).
                raise SafeReplaceUnsupported(
                    f"Nie można utworzyć pliku tymczasowego obok '{target}' "
                    f"({e}) — {untouched}") from e
            raise SafeReplaceError(
                f"Nie można przygotować pliku tymczasowego obok '{target}' ({e}) "
                f"— {untouched}") from e
        try:
            st = sftp.stat(tmp)
            if (st.st_size or 0) != local_size:
                raise SafeReplaceError(
                    f"Plik tymczasowy ma {st.st_size} B zamiast {local_size} B "
                    f"— przerwano, {untouched}")
            if (st.st_uid, st.st_gid) != want_owner:
                try:
                    sftp.chown(tmp, *want_owner)
                except Exception as e:
                    raise SafeReplaceUnsupported(
                        f"Podmiana zmieniłaby właściciela '{target}' "
                        f"({want_owner[0]}:{want_owner[1]}) — przerwano, "
                        f"{untouched}") from e
            sftp.chmod(tmp, want_mode)      # after chown, which may clear bits
            st = sftp.stat(tmp)
            if (((st.st_mode or 0) & 0o7777) != want_mode
                    or (st.st_uid, st.st_gid) != want_owner):
                raise SafeReplaceUnsupported(
                    f"Nie udało się odtworzyć uprawnień '{target}' — przerwano, "
                    f"{untouched}")
        except (_CancelledError, SafeReplaceError):
            raise
        except Exception as e:
            raise SafeReplaceError(
                f"Nie można przygotować pliku tymczasowego obok '{target}' ({e}) "
                f"— {untouched}") from e
        if before_commit is not None:
            before_commit()
        try:
            sftp.posix_rename(tmp, target)
        except Exception as e:
            if _remote_state(sftp, tmp) is True:
                raise SafeReplaceUnsupported(
                    f"Serwer nie wykonał bezpiecznej podmiany (posix-rename): "
                    f"{e} — {untouched}") from e
            # The reply is lost (link down, cancel): the rename may have run.
            raise SafeReplaceError(
                f"Podmiana '{target}' przerwana bez potwierdzenia ({e}) — stan "
                "pliku na serwerze NIEZNANY, sprawdź go przed ponownym zapisem.") from e
        committed = True
    finally:
        if not committed:
            try:
                sftp.remove(tmp)
            except FileNotFoundError:
                pass
            except Exception:
                if leftovers is not None:
                    leftovers.append(tmp)
    try:
        final = sftp.stat(target)
    except Exception:
        # Replaced, but the server cannot be asked (a receiver already took
        # the file, or the link dropped) — not a failure (review M4).
        return None
    if (final.st_size or 0) != local_size:
        raise IOError(
            f"weryfikacja po zapisie: rozmiar zdalny {final.st_size} B "
            f"!= lokalny {local_size} B")
    return final


class SftpPanel(QWidget):
    status_msg    = pyqtSignal(str, bool)   # text, is_error
    upload_file   = pyqtSignal(str)         # local path
    _open_local   = pyqtSignal(str)         # path → open in main thread
    # local_path, remote_path, orig_size, readonly, server_mtime, server_size,
    # and the client the file was downloaded through (review 67/S2).
    _watch_file_sig = pyqtSignal(str, str, int, bool, int, int, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self._open_local.connect(lambda p: QDesktopServices.openUrl(QUrl.fromLocalFile(p)))
        self._sftp:  object = None
        self._ssh_client: object = None
        #: This panel's own temp directory (C1-01): never shared with
        #: another SSH window, removed when this window closes.
        self._temp_dir = os.path.join(sftp_temp_root(),
                                      f'p{next(_SFTP_PANEL_SEQ)}')
        self._path   = '/'
        self._history: list[str] = []
        self._workers: list[QThread] = []
        self._listing_active = False   # guard against concurrent listdir_attr
        #: Bumped by every listing and every connection switch; a result that
        #: arrives for an older one is dropped (2026-10-14, C1-10) — a slow
        #: listing of server A must not repaint the table, and set the path
        #: later deletes and downloads use, while the panel is on server B.
        self._listing_gen = 0
        self._rename_editor: QLineEdit | None = None
        self._rename_editor_data: dict | None = None
        # Re-entry guard: when the conflict dialog opens it steals focus from
        # the inline editor, which would otherwise fire FocusOut → close →
        # the editor disappears mid-dialog and a second commit on the click
        # that dismissed the dialog raised the warning a second time.
        self._in_conflict_dialog = False
        # When a rename triggers a re-list, hold (h_scroll, v_scroll) here so
        # _on_listing can restore the view to where the user was looking.
        self._preserve_scroll_on_next_list: tuple[int, int] | None = None
        self._transfer_queue: list = []
        # (name, reason) of failed transfers in the current queue, names not
        # sent, and why (UX audit S-06): one summary at the end, not a
        # modal per file.
        self._transfer_failures: list = []
        self._transfer_skipped: list = []
        self._transfer_skip_reason = ''
        self._transfer_last_msg = ''
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
        #: Local copies a download is about to replace (F1): never uploaded
        #: until the download has finished and the watch is renewed.
        self._download_active: set[str] = set()
        self._watch_poll = QTimer(self)
        self._watch_poll.setInterval(2000)
        #: connection token -> (uid, gids) of its SSH user (C1-12).
        self._identity_cache: dict[str, tuple | None] = {}
        #: id(ssh client) -> (weak reference to that client, its watched
        #: files) while another tab is active (C1-03).  The weak reference is
        #: the identity check: an id() is reused once its object is freed,
        #: and a new connection — to another hospital — must never inherit
        #: the watches, and the uploads, of a dead one (review 66/S1).
        self._watch_store: dict[int, tuple] = {}
        self._watch_poll.timeout.connect(self._poll_watched_files)
        self._watch_file_sig.connect(self._watch_file)

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.setSpacing(4)

        # Navigation bar
        nav = QHBoxLayout()
        self._btn_up  = self._nav_btn("up", "Katalog wyżej", self._go_up)
        self._btn_home = self._nav_btn("home", "Katalog /", lambda: self._list('/'))
        self._btn_ref  = self._nav_btn("refresh", "Odśwież", lambda: self._list(self._path))
        self._btn_mkdir = self._nav_btn("folder-plus", "Nowy folder", self._mkdir_dialog)
        for b in (self._btn_up, self._btn_home, self._btn_ref, self._btn_mkdir):
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
        set_icon(self._btn_history, "chevron-down", "#8b949e", active="#c9d1d9", size=12)
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
        self._table = _SftpFileTable(0, 4)
        self._table.sftp_move.connect(self._handle_drag_move)
        self._table.setHorizontalHeaderLabels(["Nazwa", "Rozmiar", "Zmodyfikowano", "Prawa"])
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
        # Set row height once on the vertical header instead of per-row in
        # _on_listing — saves O(n) layout passes for large directories.
        vh = self._table.verticalHeader()
        vh.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        vh.setDefaultSectionSize(24)
        self._table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._context_menu)
        self._table.doubleClicked.connect(self._on_dbl_click)
        self._table.installEventFilter(self)
        self._table.itemSelectionChanged.connect(self._on_sel_change)
        self._table.setStyleSheet("""
            QTableWidget {
                background: #161b22;
                alternate-background-color: #1c2128;
                color: #e6edf3;
                border: 1px solid #30363d;
                border-radius: 6px;
                gridline-color: transparent;
                outline: none;
                selection-background-color: #1a2540;
                selection-color: #c0d0f0;
            }
            QTableWidget::item {
                padding: 5px 6px;
                border: none;
            }
            QTableWidget::item:selected {
                background: #1a2540;
                color: #c0d0f0;
            }
            QTableWidget::item:hover:!selected {
                background: #1c2433;
            }
            QHeaderView::section {
                background: #161b22;
                color: #7d8590;
                border: none;
                border-bottom: 1px solid #30363d;
                padding: 6px 8px;
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
        hint = QLabel("Upuść tu pliki lub foldery, aby wgrać")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("color:#30363d; font-size:10px; padding:2px;")
        root.addWidget(hint)

        # Transfer buttons + progress
        xfer = QHBoxLayout()
        self._btn_dl = QPushButton("Pobierz")
        set_icon(self._btn_dl, "download", "#3fb950", size=14)
        self._btn_dl.setEnabled(False)
        self._btn_dl.setStyleSheet(
            "QPushButton{background:#0d1f0d;color:#3fb950;"
            "border:1px solid #1b3d1b;border-radius:6px;padding:4px 10px;"
            "font-size:11px;}"
            "QPushButton:hover{background:#152b15;border-color:#2d5a2d;}"
            "QPushButton:disabled{color:#30363d;background:#0d1117;"
            "border-color:#1c2128;}")
        self._btn_dl.clicked.connect(self._download)

        self._btn_ul = QPushButton("Wgraj")
        set_icon(self._btn_ul, "upload", "#58a6ff", size=14)
        self._btn_ul.setEnabled(False)
        self._btn_ul.setStyleSheet(
            "QPushButton{background:#0d1525;color:#58a6ff;"
            "border:1px solid #1a3050;border-radius:6px;padding:4px 10px;"
            "font-size:11px;}"
            "QPushButton:hover{background:#152540;border-color:#2a4a6a;}"
            "QPushButton:disabled{color:#484f58;background:#1c2128;}")
        # Files or a whole folder (owner's request 2026-10-16).
        ul_menu = QMenu(self._btn_ul)
        ul_menu.setStyleSheet(
            "QMenu{background:#161b22;color:#e6edf3;border:1px solid #30363d;"
            "padding:4px;font-size:11px;}"
            "QMenu::item{padding:4px 16px;border-radius:3px;}"
            "QMenu::item:selected{background:#1f6feb;}")
        ul_menu.addAction(icon("file", "#c9d1d9"), "Pliki…", self._upload_browse)
        ul_menu.addAction(icon("folder", "#c9d1d9"), "Folder…", self._upload_browse_folder)
        self._btn_ul.setMenu(ul_menu)

        self._progress = QProgressBar()
        self._progress.setFixedHeight(16)
        self._progress.setTextVisible(True)
        self._progress.setFormat("%p%")
        self._progress.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._progress.setStyleSheet(
            "QProgressBar{border:none;background:#21262d;border-radius:3px;"
            "color:#c9d1d9;font-size:10px;}"
            "QProgressBar::chunk{background:#1f6feb;border-radius:3px;}")
        # Reserve the space in the layout even while the bar is hidden — opening
        # a remote file briefly shows/hides this row, which used to make the
        # whole SFTP panel reflow (the visible-grow-and-shrink the user saw).
        _sp = self._progress.sizePolicy()
        _sp.setRetainSizeWhenHidden(True)
        self._progress.setSizePolicy(_sp)
        self._progress.setVisible(False)

        self._btn_cancel = QPushButton()
        set_icon(self._btn_cancel, "close", "#f85149", size=12)
        self._btn_cancel.setFixedSize(20, 20)
        self._btn_cancel.setToolTip("Anuluj transfer")
        self._btn_cancel.setStyleSheet(
            "QPushButton{background:#3d1f1f;color:#f85149;"
            "border:1px solid #5a2d2d;border-radius:4px;"
            "font-size:11px;font-weight:bold;padding:0;}"
            "QPushButton:hover{background:#5a2d2d;border-color:#f85149;}")
        _sp = self._btn_cancel.sizePolicy()
        _sp.setRetainSizeWhenHidden(True)
        self._btn_cancel.setSizePolicy(_sp)
        self._btn_cancel.setVisible(False)
        self._btn_cancel.clicked.connect(self._cancel_transfer)
        self._active_transfer_worker = None

        xfer.addWidget(self._btn_dl)
        xfer.addWidget(self._btn_ul)
        xfer.addWidget(self._progress, 1)
        xfer.addWidget(self._btn_cancel)
        root.addLayout(xfer)

    def _nav_btn(self, icon_name, tip, slot) -> QPushButton:
        b = QPushButton()
        set_icon(b, icon_name, "#8b949e", active="#c9d1d9", size=15)
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
        self._listing_gen += 1
        gen = self._listing_gen
        self._path_lbl.setText(f"…  {path}")
        self._table.setSortingEnabled(False)
        w = _SftpListWorker(self._sftp, path)
        w.listing.connect(lambda p, e, g=gen: self._on_listing(p, e, g))
        w.error.connect(lambda e, g=gen: self._on_listing_error(e, g))
        w.note.connect(lambda text: self.status_msg.emit(text, False))
        w.start()
        self._workers.append(w)

    def _on_listing_error(self, msg: str, gen: int | None = None):
        if gen is not None and gen != self._listing_gen:
            return                      # an older listing — not ours any more
        self._listing_active = False
        self._path_lbl.setText(self._path)
        self._end_path_edit()
        self.status_msg.emit(
            f"Nie udało się wyświetlić katalogu: {_friendly_sftp_error(msg)}", True)

    def _on_listing(self, path: str, entries: list, gen: int | None = None):
        if gen is not None and gen != self._listing_gen:
            return                      # an older listing — not ours any more
        self._listing_active = False
        self._path = path
        self._path_lbl.setText(path)
        self._end_path_edit()
        self._update_history_menu()

        # Bulk-fill the table: pre-allocate row count and freeze repaints
        # so 500-row listings don't trigger a layout pass per cell.
        # Sorting is already disabled by _list() before the worker starts.
        # Prepend ".." entry so the user can click their way up — same UX as
        # WinSCP/FileZilla. `_DirFirstItem` already pins ".." to the top of any
        # sort order, but we still need to actually inject the row.
        show_parent = path not in ('', '/')
        rows = entries[:]
        if show_parent:
            rows.insert(0, ('..', True, 0, '', ''))

        table = self._table
        table.setUpdatesEnabled(False)
        table.blockSignals(True)
        try:
            table.clearContents()
            table.setRowCount(len(rows))

            for i, (name, is_dir, size, mtime, perms) in enumerate(rows):
                # Col 0: name with file-type icon (dirs-first sort)
                ni = _DirFirstItem(name)
                ni.setIcon(_icon_for_entry(name, is_dir))
                ni.setData(Qt.ItemDataRole.UserRole, (name, is_dir, size))
                if is_dir:
                    # Folders blue for clear distinction; strong blue on the
                    # light theme's white list, original bright on dark.
                    dir_c = "#0a52c0" if theme.is_light() else "#e6edf3"
                    ni.setForeground(QColor(dir_c))
                table.setItem(i, 0, ni)

                # Col 1: size (numeric sort)
                si = _NumItem("" if is_dir else _fmt_size(size))
                si.setData(Qt.ItemDataRole.UserRole, size)
                si.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                table.setItem(i, 1, si)

                # Col 2: modified date
                table.setItem(i, 2, QTableWidgetItem(mtime))

                table.setItem(i, 3, QTableWidgetItem(perms))
        finally:
            table.blockSignals(False)
            table.setUpdatesEnabled(True)

        # Worker already returned entries in dirs-first / name-asc order.
        # Reset the sort indicator to that order before re-enabling sorting,
        # otherwise Qt re-sorts using whatever indicator the user last set
        # (e.g. descending date) — which would silently flip the new listing.
        table.horizontalHeader().setSortIndicator(0, Qt.SortOrder.AscendingOrder)
        table.setSortingEnabled(True)
        self._btn_dl.setEnabled(False)

        # If this re-list was triggered by a rename, put the viewport back
        # where the user was — Qt otherwise scrolls horizontally to the
        # re-sorted/refocused row.
        preserve = self._preserve_scroll_on_next_list
        if preserve is not None:
            self._preserve_scroll_on_next_list = None
            h_pos, v_pos = preserve
            def _restore_scroll():
                table.horizontalScrollBar().setValue(h_pos)
                table.verticalScrollBar().setValue(v_pos)
            # Defer one tick — Qt is still finalizing layout/scroll after
            # setSortingEnabled(True).
            QTimer.singleShot(0, _restore_scroll)

    def eventFilter(self, obj, event):
        # Path edit: Escape cancels, FocusOut returns to label
        if self._table_keys(obj, event):
            return True
        if obj is self._path_edit:
            if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Escape:
                self._end_path_edit()
                return True
            if event.type() == QEvent.Type.FocusOut:
                self._end_path_edit()
        if obj == self._table.viewport() and event.type() == QEvent.Type.ToolTip:
            idx = self._table.indexAt(event.pos())
            if idx.isValid():
                row = idx.row()
                name_item = self._table.item(row, 0)
                size_item = self._table.item(row, 1)
                date_item = self._table.item(row, 2)
                perm_item = self._table.item(row, 3)
                if name_item:
                    name = name_item.text()
                    size_txt = (size_item.text() if size_item else '') or '—'
                    date_txt = (date_item.text() if date_item else '') or '—'
                    perm_txt = (perm_item.text() if perm_item else '') or '—'
                    data = name_item.data(Qt.ItemDataRole.UserRole)
                    is_dir = bool(data[1]) if data else False
                    icon = _icon_for_entry(name, is_dir)
                    pix = icon.pixmap(QSize(16, 16))
                    ba = QByteArray()
                    buf = QBuffer(ba)
                    buf.open(QIODevice.OpenModeFlag.WriteOnly)
                    pix.save(buf, "PNG")
                    buf.close()
                    b64 = bytes(ba.toBase64()).decode('ascii')
                    img_tag = (
                        f"<img src='data:image/png;base64,{b64}' "
                        f"width='16' height='16' style='vertical-align:middle;'/>"
                    )
                    sep = "&nbsp;&nbsp;&nbsp;&nbsp;"
                    html = (
                        "<div style='font-family:Consolas; white-space:nowrap;'>"
                        f"{img_tag}&nbsp;<b>{_esc(name)}</b>"
                        f"{sep}{_esc(size_txt)}"
                        f"{sep}{_esc(date_txt)}"
                        f"{sep}{_esc(perm_txt)}"
                        "</div>"
                    )
                    QToolTip.showText(event.globalPos(), html, self._table.viewport())
                    return True
            QToolTip.hideText()
            return True
        if obj == self._table.viewport() and event.type() == QEvent.Type.MouseButtonPress:
            idx = self._table.indexAt(event.pos())
            self._click_was_selected = (
                idx.isValid() and self._table.selectionModel().isSelected(idx)
            )
            if self._rename_editor and not self._in_conflict_dialog:
                # Click anywhere else inside the table viewport cancels the
                # in-place rename — matches Explorer/Finder behaviour. Avoids
                # the warning dialog firing as a side effect of clicking away.
                self._close_rename_editor()
        if obj is self._rename_editor:
            if event.type() == QEvent.Type.KeyPress:
                if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                    self._commit_rename()
                    return True
                if event.key() == Qt.Key.Key_Escape:
                    self._close_rename_editor()
                    return True
            elif event.type() == QEvent.Type.FocusOut:
                # Focus left the field (clicked outside, switched windows).
                # Treat that as cancel — only Enter commits. The
                # _in_conflict_dialog flag keeps us from closing the editor
                # while the warning dialog is briefly stealing focus.
                if not self._in_conflict_dialog:
                    self._close_rename_editor()
        return False

    def _on_item_clicked(self, item):
        row_item = self._table.item(item.row(), 0)
        if not row_item or not row_item.data(Qt.ItemDataRole.UserRole):
            return
        name, _, _ = row_item.data(Qt.ItemDataRole.UserRole)
        if name == '..':
            # ".." is a navigation shortcut, not a real file — never rename it.
            self._rename_timer.stop()
            self._pending_rename_item = None
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
        # Snapshot scroll BEFORE moving current cell / placing the editor —
        # Qt auto-scrolls to keep the current item / focused child visible,
        # which nudges the horizontal scrollbar a few pixels right every time
        # the user enters rename mode.
        hbar = self._table.horizontalScrollBar()
        vbar = self._table.verticalScrollBar()
        h_pos, v_pos = hbar.value(), vbar.value()
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
        hbar.setValue(h_pos)
        vbar.setValue(v_pos)
        self._rename_editor      = ed
        self._rename_editor_data = {'item': item, 'name': name,
                                    'is_dir': is_dir, 'size': size}

    def _commit_rename(self):
        ed   = self._rename_editor
        data = self._rename_editor_data
        if not ed or not data:
            return
        new_name = ed.text().strip()
        item     = data['item']
        original = data['name']
        is_dir   = data['is_dir']
        size     = data['size']
        if not new_name or new_name == original:
            self._close_rename_editor()
            return
        if '/' in new_name or new_name in ('.', '..'):
            # "a/b" or "../x" would MOVE the file elsewhere (UX audit S-07).
            self._close_rename_editor()
            QMessageBox.warning(
                self, "Zmiana nazwy",
                "Nazwa nie może zawierać „/” ani być „.” lub „..”.\n"
                "Do przenoszenia plików służy przeciąganie do katalogu.")
            return
        # Pre-check name collision (case-sensitive — POSIX SFTP servers are too).
        # The previous code optimistically renamed the row in the table and only
        # discovered the conflict on the SFTP error, leaving the wrong label
        # visible until the next directory refresh.
        new_remote = self._path.rstrip('/') + '/' + new_name
        conflict_found = False
        for r in range(self._table.rowCount()):
            it = self._table.item(r, 0)
            if not it or it is item:
                continue
            ex_name, _, _ = it.data(Qt.ItemDataRole.UserRole)
            if ex_name == new_name:
                conflict_found = True
                break
        # Belt + suspenders: the in-memory check above only sees the rows
        # we listed. Hidden entries (the listing filtered out) and races
        # with another client (a parallel SFTP session creating the file
        # between our listdir and our rename) would slip past. On
        # OpenSSH-style servers sftp.rename uses POSIX rename(2)
        # semantics → silent clobber. One extra stat() roundtrip closes
        # the window in the common case.
        if not conflict_found and self._sftp:
            try:
                self._sftp.stat(new_remote)
                conflict_found = True
            except IOError:
                pass        # doesn't exist on server — proceed
            except Exception:
                pass        # stat failed for unrelated reason — let rename try
        if conflict_found:
            self._in_conflict_dialog = True
            try:
                QMessageBox.warning(
                    self, "Zmiana nazwy",
                    f"Plik lub folder o nazwie '{new_name}' już istnieje "
                    f"w tym katalogu.\n\nWybierz inną nazwę.",
                )
            finally:
                self._in_conflict_dialog = False
            if self._rename_editor is ed:
                ed.setFocus()
                ed.selectAll()
            return
        # Snapshot scroll BEFORE closing the editor — focus moving back from
        # the QLineEdit to the table triggers Qt's "scroll to current cell"
        # behaviour. If the current column is e.g. "Rozmiar" (because the
        # user clicked that header to sort), the horizontal bar jumps right.
        hbar = self._table.horizontalScrollBar()
        vbar = self._table.verticalScrollBar()
        h_pos, v_pos = hbar.value(), vbar.value()
        # Disable sorting while we mutate the row — setText with sorting on
        # re-sorts the table, which scrolls to the moved current cell.
        sort_was_on = self._table.isSortingEnabled()
        self._table.setSortingEnabled(False)
        self._close_rename_editor()
        self._table.blockSignals(True)
        item.setText(new_name)
        item.setIcon(_icon_for_entry(new_name, is_dir))
        item.setData(Qt.ItemDataRole.UserRole, (new_name, is_dir, size))
        self._table.blockSignals(False)
        if sort_was_on:
            self._table.setSortingEnabled(True)
        hbar.setValue(h_pos)
        vbar.setValue(v_pos)
        # Defer one tick: focus moves and any pending ensureVisible() fire on
        # the next event-loop pass — pin the scrollbar back then too.
        QTimer.singleShot(0, lambda: (hbar.setValue(h_pos), vbar.setValue(v_pos)))
        old_remote = self._path.rstrip('/') + '/' + original
        new_remote = self._path.rstrip('/') + '/' + new_name
        # Mark the next listing so _on_listing restores the same scroll.
        self._preserve_scroll_on_next_list = (h_pos, v_pos)

        def do_rename():
            self._sftp.rename(old_remote, new_remote)

        def on_error(e):
            self.status_msg.emit(f"Zmiana nazwy: {e}", True)
            # Re-list to revert the optimistic in-place update — the server
            # rejected the rename, so the old name is still authoritative.
            self._list(self._path)

        w = _SimpleWorker(do_rename)
        w.done.connect(lambda: self._list(self._path))
        w.error.connect(on_error)
        w.start()
        self._workers.append(w)

    def _handle_drag_move(self, src_names: list, target_folder: str):
        """Move dragged entries into `target_folder` (relative to current dir).

        sftp.rename() on POSIX-like servers silently clobbers an existing
        destination — drag-dropping a file into a folder that already
        has one of the same name used to wipe the target. We now stat()
        each destination first and ask before overwriting.
        """
        if not self._sftp or self._listing_active or not src_names:
            return
        base = self._path.rstrip('/')
        if target_folder == '..':
            parts = base.split('/')
            target_dir = '/'.join(parts[:-1]) or '/'
        else:
            target_dir = (base + '/' + target_folder).rstrip('/') or '/'

        moves = [((base + '/' + n) if base else '/' + n,
                  (target_dir.rstrip('/') + '/' + n)) for n in src_names]

        # Filter out trivial moves where source == destination (e.g.
        # dropping a row onto itself). Server would error out anyway.
        moves = [(old, new) for (old, new) in moves if old != new]
        if not moves:
            return

        def after_scan(conflicts: list[str]):
            chosen = moves
            overwrite_set: set[str] = set()
            if conflicts:
                action = self._ask_overwrite(conflicts)
                if action == 'cancel':
                    return
                if action == 'skip':
                    skip_set = set(conflicts)
                    chosen = [m for m in moves if m[1] not in skip_set]
                    if not chosen:
                        self.status_msg.emit(
                            "Wszystkie cele istnieją — przeniesienie pominięte", False)
                        return
                else:
                    overwrite_set = set(conflicts)
            self._start_moves(chosen, overwrite_set)

        self._scan_move_conflicts_async(moves, after_scan)

    def _scan_move_conflicts_async(self, moves, on_done):
        """Find destinations that already exist; same channel-discipline
        as the upload scan (fresh open_sftp under lock, dedicated channel
        per scan)."""
        ssh_client = self._ssh_client
        lock = self._sftp_open_lock
        conflicts: list[str] = []

        def scan():
            with lock:
                sftp = ssh_client.open_sftp()
            try:
                for old, new in moves:
                    try:
                        sftp.stat(new)
                        conflicts.append(new)
                    except IOError:
                        continue
                    except Exception:
                        continue
            finally:
                try:
                    sftp.close()
                except Exception:
                    pass

        w = _SimpleWorker(scan)
        w.done.connect(lambda: on_done(conflicts))
        w.error.connect(lambda e: self.status_msg.emit(
            f"Skan kolizji: {e}", True))
        w.start()
        self._workers.append(w)

    def _start_moves(self, moves: list[tuple[str, str]],
                     overwrite_set: set[str]):
        """Execute the (old, new) renames; for items in overwrite_set, remove
        the destination first so sftp.rename() can complete cleanly."""
        sftp = self._sftp

        def do_move():
            for old, new in moves:
                if new in overwrite_set:
                    try:
                        sftp.remove(new)
                    except IOError:
                        pass            # gone in the meantime — rename will decide
                    except Exception:
                        pass
                sftp.rename(old, new)

        def on_error(e):
            self.status_msg.emit(f"Przenoszenie: {e}", True)
            self._list(self._path)

        w = _SimpleWorker(do_move)
        w.done.connect(lambda: self._list(self._path))
        w.error.connect(on_error)
        w.start()
        self._workers.append(w)

    def _mkdir_dialog(self):
        """Prompt for a new folder name and create it via SFTP.mkdir."""
        if not self._sftp or self._listing_active:
            return
        name, ok = QInputDialog.getText(self, "Nowy folder", "Nazwa folderu:")
        if not ok:
            return
        name = name.strip()
        if not name:
            return
        if '/' in name or name in ('.', '..'):
            QMessageBox.warning(self, "Nowy folder", "Nieprawidłowa nazwa folderu.")
            return
        conflict = False
        for r in range(self._table.rowCount()):
            it = self._table.item(r, 0)
            if not it:
                continue
            ex_name, _, _ = it.data(Qt.ItemDataRole.UserRole)
            if ex_name == name:
                conflict = True
                break
        remote = self._path.rstrip('/') + '/' + name
        # Belt + suspenders — see _commit_rename for the same pattern.
        if not conflict and self._sftp:
            try:
                self._sftp.stat(remote)
                conflict = True
            except IOError:
                pass
            except Exception:
                pass
        if conflict:
            QMessageBox.warning(
                self, "Nowy folder",
                f"Element o nazwie '{name}' już istnieje w tym katalogu.",
            )
            return

        def do_mkdir():
            self._sftp.mkdir(remote)

        w = _SimpleWorker(do_mkdir)
        w.done.connect(lambda: self._list(self._path))
        w.error.connect(lambda e: self.status_msg.emit(
            f"Tworzenie folderu: {e}", True))
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
        if name == '..':
            self._go_up()
            return
        if is_dir:
            parent = self._path.rstrip('/')
            self._history.append(self._path)
            self._list(f"{parent}/{name}" if parent else f"/{name}")
        else:
            self._open_remote(self._path.rstrip('/') + '/' + name, name)

    def _table_keys(self, obj, event) -> bool:
        """Keys in the file table (UX audit E-11): Enter opens, Backspace goes
        up, F2 renames, Delete deletes, F5 refreshes."""
        if obj is self._table and event.type() == QEvent.Type.KeyPress:
            key = event.key()
            row = self._table.currentRow()
            item = self._table.item(row, 0) if row >= 0 else None
            if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and item is not None:
                self._on_dbl_click(self._table.model().index(row, 0))
                return True
            if key == Qt.Key.Key_Backspace:
                self._go_up()
                return True
            if key == Qt.Key.Key_F5 and self._sftp is not None:
                self._list(self._path)
                return True
            if item is not None and key in (Qt.Key.Key_F2, Qt.Key.Key_Delete):
                name, is_dir, _ = item.data(Qt.ItemDataRole.UserRole)
                if name != '..':
                    if key == Qt.Key.Key_F2:
                        self._start_inline_rename(item)
                    else:
                        self._delete(self._path.rstrip('/') + '/' + name, is_dir, name)
                    return True
        return False

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
        menu = QMenu(self)
        if not item:
            # Empty area — only the directory-wide action.
            if self._sftp:
                menu.addAction(icon("folder-plus", "#c9d1d9"), "Nowy folder", self._mkdir_dialog)
                menu.exec(self._table.viewport().mapToGlobal(pos))
            return
        row_item = self._table.item(item.row(), 0)
        if not row_item:
            return
        name, is_dir, size = row_item.data(Qt.ItemDataRole.UserRole)
        if name == '..':
            # Treat ".." like an empty area — only the directory-wide action.
            if self._sftp:
                menu.addAction(icon("folder-plus", "#c9d1d9"), "Nowy folder", self._mkdir_dialog)
                menu.exec(self._table.viewport().mapToGlobal(pos))
            return
        remote = self._path.rstrip('/') + '/' + name

        if not is_dir:
            menu.addAction(icon("download", "#c9d1d9"), "Pobierz", self._download)
            menu.addAction(icon("file", "#c9d1d9"), "Otwórz lokalnie",
                           lambda: self._open_remote(remote, name))
            menu.addAction(icon("folder-open", "#c9d1d9"), "Otwórz za pomocą...",
                           lambda: self._open_with(remote, name))
        menu.addSeparator()
        menu.addAction(icon("clipboard", "#c9d1d9"), "Kopiuj ścieżkę",
                       lambda r=remote: QApplication.clipboard().setText(r))
        menu.addSeparator()
        menu.addAction(icon("lock", "#c9d1d9"), "Uprawnienia...",
                       lambda: self._chmod_dialog(remote, name))
        menu.addAction(icon("pencil", "#c9d1d9"), "Zmień nazwę",
                       lambda ri=row_item: self._start_inline_rename(ri))
        menu.addAction(icon("folder-plus", "#c9d1d9"), "Nowy folder", self._mkdir_dialog)
        menu.addAction(icon("trash", "#f85149"), f"Usuń „{name}”",
                       lambda: self._delete(remote, is_dir, name))
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
            skipped = []
            for name, size in files:
                remote = self._path.rstrip('/') + '/' + name
                # A remote name is not trusted as a Windows path (C1-06).
                local_name = safe_local_name(name)
                if local_name is None:
                    skipped.append(name)
                    continue
                local = os.path.join(folder, local_name)
                queue.append(('get', remote, local, size))
            if skipped:
                QMessageBox.warning(
                    self, "Pominięte pliki",
                    "Tych plików nie da się bezpiecznie zapisać pod tą nazwą "
                    "w Windows i zostały pominięte:\n\n"
                    + "\n".join(repr(n) for n in skipped[:20]))
            # Files already in the folder are not replaced unasked
            # (2026-10-21) — a single download asks through the save dialog.
            existing = [q[2] for q in queue if os.path.exists(q[2])]
            if existing:
                action = self._ask_overwrite(existing, "w wybranym folderze")
                if action == 'cancel':
                    return
                if action == 'skip':
                    queue = [q for q in queue if q[2] not in existing]
            if not queue:
                return
            self._enqueue_transfers(queue)

    def _upload_browse(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Wybierz pliki do wgrania")
        if not paths or not self._sftp:
            return
        self._begin_uploads(paths)

    def _upload_browse_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Wybierz folder do wgrania")
        if not path or not self._sftp:
            return
        self._begin_uploads([path])

    #: A folder this big asks before anything is sent.
    _FOLDER_CONFIRM_FILES = 200
    _FOLDER_CONFIRM_BYTES = 500 * 1024 * 1024
    #: Walking stops here — a dropped drive or home folder must not freeze.
    _FOLDER_MAX_FILES = 20000

    def _expand_upload_sources(self, locals_list: list[str]):
        """Files and folders → ((remote, local, size) files, remote dirs).

        A folder keeps its name and structure under the current directory;
        the directories come parents first, so creating them in order works.
        Symbolic links to folders are not followed.  Returns None when the
        folder holds more than _FOLDER_MAX_FILES files.
        """
        base = self._path.rstrip('/')
        items: list[tuple[str, str, int]] = []
        dirs: list[str] = []
        seen: set[str] = set()

        def add(remote, local):
            if remote in seen:
                return
            try:
                size = os.path.getsize(local)
            except OSError:
                return
            seen.add(remote)
            items.append((remote, local, size))

        for p in locals_list:
            p = os.path.normpath(p)
            name = os.path.basename(p)
            if not name:
                continue
            if os.path.isdir(p) and not os.path.islink(p):
                top = base + '/' + name
                if top not in dirs:
                    dirs.append(top)
                for root, dnames, fnames in os.walk(p):
                    dnames[:] = sorted(
                        d for d in dnames
                        if not os.path.islink(os.path.join(root, d)))
                    rel = os.path.relpath(root, p)
                    rbase = top if rel == '.' else (
                        top + '/' + rel.replace(os.sep, '/'))
                    dirs.extend(rbase + '/' + d for d in dnames)
                    for f in sorted(fnames):
                        lp = os.path.join(root, f)
                        if os.path.isfile(lp):
                            add(rbase + '/' + f, lp)
                    if len(items) > self._FOLDER_MAX_FILES:
                        return None
            elif os.path.isfile(p):
                add(base + '/' + name, p)
        return items, dirs

    def _upload_file(self, local: str):
        # Kept as a compat shim — every caller (drag-drop, single-file
        # upload) now flows through _begin_uploads so the same overwrite
        # check runs regardless of entry point.
        if not self._sftp or not os.path.isfile(local):
            return
        self._begin_uploads([local])

    def _begin_uploads(self, locals_list: list[str]):
        """Pre-scan target dir for name conflicts, ask the user, then start.

        Plain sftp.put() always clobbers an existing remote file with no
        warning — drag-dropping a file whose name matches one on the
        server silently destroys the original. We stat() each target on
        a fresh SFTP channel (so concurrent listings/transfers on the
        nav channel aren't perturbed), then surface a single dialog with
        the conflicting names and let the user choose: overwrite / skip
        existing / cancel.
        """
        if not self._sftp or not self._ssh_client or not locals_list:
            return
        expanded = self._expand_upload_sources(locals_list)
        if expanded is None:
            QMessageBox.warning(
                self, "Za dużo plików",
                f"Folder ma ponad {self._FOLDER_MAX_FILES} plików — nie wgrano "
                "niczego. Spakuj go (np. do ZIP) albo wgraj mniejsze części.")
            return
        items, dirs = expanded
        if not items and not dirs:
            return
        if dirs:
            from ui.utils import confirm
            total = sum(it[2] for it in items)
            if (len(items) > self._FOLDER_CONFIRM_FILES
                    or total > self._FOLDER_CONFIRM_BYTES):
                if not confirm(
                        self, "Wgrać folder?",
                        f"Do {self._path} trafi {len(items)} plików "
                        f"({total / 1024 / 1024:.0f} MB) w {len(dirs)} folderach.",
                        "Wgraj"):
                    return

        def after_scan(conflicts: list[tuple[str, str, int]]):
            chosen = items
            if conflicts:
                action = self._ask_overwrite([c[0] for c in conflicts])
                if action == 'cancel':
                    return
                if action == 'skip':
                    skip_set = {c[0] for c in conflicts}
                    chosen = [it for it in items if it[0] not in skip_set]
                    if not chosen and not dirs:
                        self.status_msg.emit(
                            "Wszystkie pliki istnieją — pominięto", False)
                        return
            if dirs:
                self._make_remote_dirs(
                    dirs, lambda: bool(chosen) and (self._start_uploads(chosen) or True))
            else:
                self._start_uploads(chosen)

        self._scan_conflicts_async(items, after_scan)

    def _scan_conflicts_async(self, items, on_done):
        """Stat() each remote on a fresh channel; report which already exist.

        paramiko's SFTPClient is not safe for concurrent calls on one
        channel — this avoids racing the nav channel against an
        in-flight listdir/edit. The open is serialised through
        _sftp_open_lock to match the rest of the codebase.
        """
        ssh_client = self._ssh_client
        lock = self._sftp_open_lock
        conflicts: list[tuple] = []

        def scan():
            with lock:
                sftp = ssh_client.open_sftp()
            try:
                for it in items:
                    try:
                        sftp.stat(it[0])
                        conflicts.append(it)
                    except IOError:
                        continue          # not-exists is the happy case
                    except Exception:
                        continue          # treat unknown errors as "no conflict"
            finally:
                try:
                    sftp.close()
                except Exception:
                    pass

        w = _SimpleWorker(scan)
        w.done.connect(lambda: on_done(conflicts))
        w.error.connect(lambda e: self.status_msg.emit(
            f"Skan kolizji: {e}", True))
        w.start()
        self._workers.append(w)

    def _make_remote_dirs(self, dirs: list[str], then) -> None:
        """Create the folders of a folder upload (parents first), then go on.

        An existing folder is used as it is (its files are compared like any
        others); a FILE where a folder should be stops the upload.
        """
        ssh_client = self._ssh_client
        lock = self._sftp_open_lock
        created = [0]

        def work():
            import stat as _stat
            with lock:
                sftp = ssh_client.open_sftp()
            try:
                for d in dirs:
                    try:
                        st = sftp.stat(d)
                    except IOError:
                        sftp.mkdir(d)
                        created[0] += 1
                        continue
                    if not _stat.S_ISDIR(st.st_mode or 0):
                        raise IOError(
                            f"Na serwerze jest plik „{d}”, a ma tam być folder.")
            finally:
                try:
                    sftp.close()
                except Exception:
                    pass

        def done():
            # No listing here: it would share the navigation channel with
            # the transfer that starts now (paramiko is not thread-safe —
            # it hung).  The queue refreshes the listing when it ends; with
            # nothing to send, refresh now.
            if not then() and created[0]:
                self._list(self._path)

        w = _SimpleWorker(work)
        w.done.connect(done)
        w.error.connect(lambda e: QMessageBox.warning(
            self, "Wgrywanie folderu", f"Nie udało się utworzyć folderów:\n{e}"))
        w.start()
        self._workers.append(w)

    def _start_uploads(self, items: list[tuple[str, str, int]]):
        """Kick off transfer(s) once conflicts are resolved."""
        if not items:
            return
        if len(items) == 1:
            remote, local, size = items[0]
            self._run_transfer('put', remote, local, size)
        else:
            self._enqueue_transfers([('put', r, l, s) for (r, l, s) in items])

    def _shown_name(self, remote: str) -> str:
        """A remote path as the user knows it: relative to the folder open."""
        base = self._path.rstrip('/') + '/'
        return remote[len(base):] if remote.startswith(base) else os.path.basename(remote)

    def _ask_overwrite(self, conflict_paths: list[str],
                       where: str = "na serwerze") -> str:
        """Modal for name conflicts (upload or move). Returns
        'overwrite'/'skip'/'cancel'. Shared by uploads, drag-moves and
        any future op that lands on an existing remote path."""
        n = len(conflict_paths)
        # Polish noun declension: 1 → plik, 2-4 → pliki, 5+ → plików;
        # teens (11-14) take the genitive plural too.
        last = n % 100
        if 11 <= last <= 14:
            word = "plików"
        elif n == 1:
            word = "plik"
        elif 2 <= last % 10 <= 4:
            word = "pliki"
        else:
            word = "plików"
        preview_n = 10
        names = "\n".join(f"  • {self._shown_name(p)}" for p in conflict_paths[:preview_n])
        if n > preview_n:
            names += f"\n  …+{n - preview_n} więcej"
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Pliki już istnieją")
        box.setText(f"{n} {word} już istnieje {where}:")
        box.setInformativeText(names + "\n\nCo zrobić?")
        btn_ow = box.addButton("Nadpisz wszystkie", QMessageBox.ButtonRole.AcceptRole)
        btn_sk = box.addButton("Pomiń istniejące", QMessageBox.ButtonRole.DestructiveRole)
        btn_ca = box.addButton("Anuluj", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(btn_ca)
        box.exec()
        clicked = box.clickedButton()
        if clicked is btn_ow:
            return 'overwrite'
        if clicked is btn_sk:
            return 'skip'
        return 'cancel'

    def _run_transfer(self, mode, remote, local, size):
        self._enqueue_transfers([(mode, remote, local, size)])

    def _transfer_busy(self) -> bool:
        if getattr(self, '_transfer_in_progress', False):
            return True
        w = self._active_transfer_worker
        try:
            return w is not None and w.isRunning()
        except RuntimeError:
            return False

    def _enqueue_transfers(self, items) -> None:
        """Queue (mode, remote, local, size) transfers on the CURRENT
        connection.

        Each item keeps the connection it was queued on: after a tab switch
        the rest of a queue used to run through the new tab's connection —
        another server.  A transfer requested while one runs joins the queue
        (a dropped file used to wipe it silently, UX audit S-05).
        """
        owner = self._ssh_client
        queued = [tuple(it) + (owner,) for it in items]
        if self._transfer_busy():
            self._transfer_queue.extend(queued)
            self._transfer_total_count += len(queued)
            from ui.utils import plural
            self.status_msg.emit(
                "Dodano do kolejki: " + plural(len(queued), 'plik', 'pliki', 'plików'),
                False)
            return
        self._transfer_queue = queued
        self._transfer_total_count = len(queued)
        self._transfer_done_count = 0
        self._transfer_failures = []
        self._transfer_skipped = []
        self._transfer_skip_reason = ''
        self._run_next_queued_transfer()

    def _run_next_queued_transfer(self):
        while self._transfer_queue:
            mode, remote, local, size, owner = self._transfer_queue.pop(0)
            if owner is not self._ssh_client:
                self._transfer_skipped.append(posixpath.basename(remote))
                self._transfer_skip_reason = (
                    "widok przełączono na inne połączenie")
                continue
            self._start_single_transfer(mode, remote, local, size)
            return
        self._finish_queue()

    def _connection_lost(self) -> bool:
        client = self._ssh_client
        if client is None:
            return True
        try:
            transport = client.get_transport()
            return transport is None or not transport.is_active()
        except Exception:
            return True

    def _finish_queue(self) -> None:
        """One message for the whole queue (UX audit S-06)."""
        from ui.utils import plural
        self._transfer_finished_cleanup()
        total, done = self._transfer_total_count, self._transfer_done_count
        fails, skipped = self._transfer_failures, self._transfer_skipped
        get = getattr(self, '_transfer_current_mode', 'get') == 'get'
        if not fails and not skipped:
            if total > 1:
                verb = "Pobrano" if get else "Wgrano"
                self.status_msg.emit(
                    f"{verb} {plural(done, 'plik', 'pliki', 'plików')}", False)
            elif self._transfer_last_msg:
                self.status_msg.emit(self._transfer_last_msg, False)
        else:
            if total > 1:
                lines = [f"Przesłano {done} z {plural(total, 'pliku', 'plików', 'plików')}."]
            else:
                lines = ["Transfer nie powiódł się."]
            for name, why in fails[:10]:
                lines.append(f"  • {name}: {why}")
            if len(fails) > 10:
                lines.append(f"  …+{len(fails) - 10} więcej")
            if skipped:
                names = ", ".join(skipped[:10]) + (
                    f" …+{len(skipped) - 10}" if len(skipped) > 10 else "")
                lines.append(f"Nie przesłano ({self._transfer_skip_reason}): {names}")
            self.status_msg.emit("\n".join(lines), True)
        self._transfer_failures, self._transfer_skipped = [], []
        self._transfer_skip_reason = ''
        self._transfer_last_msg = ''
        if self._sftp is not None and not self._connection_lost():
            self._list(self._path)

    def _start_single_transfer(self, mode, remote, local, size):
        # Set until the queue ends or is cancelled: a request arriving
        # between a worker's end and its queued "done" joins the queue
        # instead of starting a second transfer (review 71, R-08).
        self._transfer_in_progress = True
        self._transfer_current_mode   = mode
        self._transfer_current_remote = remote
        self._transfer_current_owner  = self._ssh_client
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
        # Did the target already exist?  A cancel may only delete what this
        # transfer created (2026-10-14, C1-07): cancelling an upload that
        # overwrote a server file used to delete that file outright, and a
        # cancelled download deleted the user's existing local file.
        if mode == 'put':
            target_existed = self._remote_exists(remote)
        else:
            target_existed = os.path.exists(local)
        # What stop() must clean up if the window closes mid-transfer (R-04).
        self._transfer_partial = (local if mode == 'get' and not target_existed
                                  else None)
        w = _TransferWorker(self._ssh_client, mode, remote, local, size,
                            open_lock=self._sftp_open_lock)
        self._active_transfer_worker = w
        w.progress.connect(self._progress.setValue)
        w.done.connect(self._transfer_done)
        owner = self._ssh_client
        w.cancelled.connect(lambda: self._transfer_cancelled(
            local if mode == 'get' and not target_existed else None,
            remote_partial=remote if mode == 'put' and not target_existed else None,
            overwritten=(local if mode == 'get' else remote) if target_existed else None,
            owner=owner))
        w.error.connect(lambda e: self._transfer_error(e))
        w.start()
        self._workers.append(w)

    def _transfer_done(self, msg: str):
        # Po udanym uploadzie unieważnij cache tmp-pliku dla tego remote,
        # żeby kolejny double-click pobrał świeżą zawartość zamiast pokazywać
        # starą lokalną kopię (np. po podmianie certyfikatu o tej samej nazwie).
        if self._transfer_current_mode == 'put':
            self._invalidate_open_remote_cache(
                self._transfer_current_remote,
                getattr(self, '_transfer_current_owner', None))
        self._transfer_done_count += 1
        self._transfer_last_msg = msg
        self._run_next_queued_transfer()

    def _transfer_error(self, e: str):
        name = posixpath.basename(getattr(self, '_transfer_current_remote', '') or '')
        self._transfer_failures.append((name, _friendly_sftp_error(e)))
        if self._transfer_queue and self._connection_lost():
            # The link is gone: the rest cannot succeed — stop here instead
            # of one error window per file (UX audit S-06).
            self._transfer_skipped.extend(
                posixpath.basename(it[1]) for it in self._transfer_queue)
            self._transfer_skip_reason = "połączenie z serwerem zostało przerwane"
            self._transfer_queue = []
        self._run_next_queued_transfer()

    def _remote_exists(self, remote: str) -> bool:
        """Does `remote` exist?  Unknown counts as yes — the safe answer for
        "may a cancel delete it" is no."""
        if not self._sftp:
            return True
        try:
            self._sftp.stat(remote)
            return True
        except IOError as e:
            return getattr(e, 'errno', None) != 2       # ENOENT → it did not
        except Exception:
            return True

    def _transfer_cancelled(self, partial_file: str = None, remote_partial: str = None,
                            overwritten: str = None, owner=None):
        self._transfer_queue = []
        self._transfer_failures, self._transfer_skipped = [], []
        self._transfer_finished_cleanup()
        if remote_partial and owner is not None and not self.bound_to(owner):
            # The panel is on another connection now (tab switched or the
            # session reconnected): deleting through it would remove a file
            # of the same name on ANOTHER server (review 68).  Leave the
            # fragment and say so.
            self.status_msg.emit(
                f"Anulowano. Fragment '{os.path.basename(remote_partial)}' został "
                f"na serwerze, z którego przełączono widok — usuń go ręcznie.", True)
            remote_partial = None
        elif remote_partial and not self._sftp:
            self.status_msg.emit(
                f"Anulowano. Fragment '{os.path.basename(remote_partial)}' został "
                f"na serwerze (połączenie zamknięte) — usuń go ręcznie.", True)
            remote_partial = None
        if overwritten:
            # Not deleted — it existed before.  But the transfer had started
            # writing over it, so it may now be incomplete (C1-07).
            self.status_msg.emit(
                f"Anulowano. Plik {os.path.basename(overwritten)} istniał wcześniej "
                f"i nie został usunięty, ale mógł zostać częściowo nadpisany — sprawdź go.",
                True)
        local_cleanup_err: str | None = None
        if partial_file and os.path.exists(partial_file):
            try:
                os.remove(partial_file)
            except OSError as e:
                local_cleanup_err = str(e)
        remote_cleanup_err: str | None = None
        if remote_partial and self._sftp:
            # Upload was hard-cancelled — its private SFTP channel is gone.
            # Reuse the navigation channel (self._sftp) to drop the partial
            # file. One round-trip, runs synchronously here; opening a new
            # channel from a side thread proved fragile under rapid cancel.
            try:
                self._sftp.remove(remote_partial)
            except Exception as e:
                # Previously this was a bare 'except: pass' — a partial
                # upload that we couldn't clean up was indistinguishable
                # from a clean cancel, so the user had no idea half a
                # gigabyte sat on the server. Surface it.
                remote_cleanup_err = str(e)
            if self._path:
                self._list(self._path)
        if local_cleanup_err or remote_cleanup_err:
            bits = ["Transfer anulowany, ale cleanup się nie powiódł:"]
            if remote_cleanup_err:
                bits.append(
                    f"  • plik fragmentu na serwerze "
                    f"'{os.path.basename(remote_partial)}': {remote_cleanup_err}")
            if local_cleanup_err:
                bits.append(
                    f"  • lokalny fragment "
                    f"'{os.path.basename(partial_file)}': {local_cleanup_err}")
            self.status_msg.emit("\n".join(bits), True)
        elif not overwritten:
            self.status_msg.emit("Transfer anulowany", False)

    def _transfer_finished_cleanup(self):
        self._transfer_in_progress = False
        self._progress.setRange(0, 100)
        self._progress.setFormat("%p%")
        self._progress.setVisible(False)
        self._btn_cancel.setVisible(False)
        self._btn_cancel.setEnabled(True)
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
            # The worker may take several seconds to unwind — paramiko
            # only checks _cancel between chunk reads, and slow networks
            # mean long gaps. Give the user immediate visual feedback so
            # they know the cancel was registered (not a hang).
            self._btn_cancel.setEnabled(False)
            self._progress.setRange(0, 0)   # indeterminate / animated
            self._progress.setFormat("Anulowanie…")
            self.status_msg.emit("Anulowanie transferu…", False)

    _DANGEROUS_EXT = frozenset({
        '.exe', '.bat', '.cmd', '.com', '.msi', '.scr', '.pif',
        '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1',
        '.jar', '.iso', '.img', '.hta', '.cpl', '.inf', '.reg',
        # 2026-10-14 (C1-15): also run code when opened on Windows.
        '.py', '.pyw', '.lnk', '.url', '.chm', '.msc', '.msp', '.psm1',
        '.psd1', '.appref-ms', '.application', '.gadget', '.xll', '.docm',
        '.xlsm', '.pptm', '.dotm', '.xlam', '.scf', '.settingcontent-ms',
        '.vhd', '.vhdx', '.library-ms', '.search-ms', '.diagcab',
    })

    def _server_identity(self) -> str:
        """Which connection the local copies belong to — for the temp path.

        A token unique to the client object for the life of the process
        (review 67/S3): a peer address is not enough — two tabs to one
        ip:port (two accounts, a load-balanced VIP, a bastion) shared one
        local copy, and a watch of one uploaded what the other downloaded.
        """
        return connection_token(self._ssh_client)

    def _local_copy_path(self, remote: str, name: str) -> str:
        return sftp_temp_path(self._temp_dir, self._server_identity(),
                              remote, name)

    def temp_dir(self) -> str:
        return self._temp_dir

    def bound_to(self, ssh_client) -> bool:
        """Is this panel currently working over `ssh_client`?"""
        return ssh_client is not None and self._ssh_client is ssh_client

    def _remember_watches(self, ssh_client, files: dict) -> None:
        try:
            ref = weakref.ref(ssh_client)
        except TypeError:
            return            # cannot be tracked safely: do not keep them
        self._watch_store[id(ssh_client)] = (ref, dict(files))

    def _recall_watches(self, ssh_client) -> dict:
        if ssh_client is None:
            return {}
        entry = self._watch_store.pop(id(ssh_client), None)
        if entry is None:
            return {}
        ref, files = entry
        return files if ref() is ssh_client else {}

    def forget_connection(self, ssh_client) -> None:
        """A connection is gone (tab closed, reconnected): drop its watches —
        kept or active — so nothing is ever uploaded through another one."""
        if ssh_client is None:
            return
        self._watch_store.pop(id(ssh_client), None)
        if self.bound_to(ssh_client):
            self._watch_poll.stop()
            self._watched_files = {}
            self._upload_active.clear()
            self._ssh_client = None
            # Nothing may run over the closed connection afterwards — in
            # multiexec no tab change follows to do this (review 67/N1).
            self._sftp = None
            for b in (self._btn_up, self._btn_home, self._btn_ref,
                      self._btn_mkdir, self._btn_ul):
                b.setEnabled(False)

    def rebind_connection(self, old_client, new_client) -> None:
        """One session reconnected to the same server: move its watched edits
        to the new connection instead of dropping them (UX audit S-01).

        Only for the reconnect of a single session — same host, port and
        user, the host key checked again by the new connection — so a watch
        still never reaches another server.  Without this an editor left open
        across a dropped link lost every later save without a word.  The
        entries wait under the new connection; the panel picks them up when
        it switches to it (switch_sftp), as for any inactive tab.
        """
        if old_client is None or new_client is None or old_client is new_client:
            return
        try:
            new_ref = weakref.ref(new_client)
        except TypeError:
            self.forget_connection(old_client)
            return
        moved = self._recall_watches(old_client)
        if self.bound_to(old_client):
            moved.update(self._watched_files)
            self._watch_poll.stop()
            self._watched_files = {}
            self._ssh_client = None
            self._sftp = None       # nothing may run over the dead connection
        for entry in moved.values():
            entry['owner'] = new_ref
        if moved:
            kept = self._watch_store.get(id(new_client))
            if kept is not None and kept[0]() is new_client:
                kept[1].update(moved)
            else:
                self._watch_store[id(new_client)] = (new_ref, moved)

    def _invalidate_open_remote_cache(self, remote: str, owner=None):
        """Drop the watch of `remote` on the connection `owner` (default: the
        current one) so the next _open_remote re-downloads instead of opening
        the stale local copy.

        The local path depends on the connection, not only on the name
        (C1-01, review 2026-10-15 L7): a manual upload through A that ends
        after a switch to B must drop A's watch, never B's file of the same
        path.  The copy on disk stays; the next download replaces it.
        """
        owner = owner if owner is not None else self._ssh_client
        path = sftp_temp_path(self._temp_dir, connection_token(owner),
                              remote, remote)
        if self.bound_to(owner):
            self._watched_files.pop(path, None)
            return
        kept = self._watch_store.get(id(owner))
        if kept is not None and kept[0]() is owner:
            kept[1].pop(path, None)

    # Files larger than this trigger a "do you really want to download?"
    # prompt before "Otwórz lokalnie" / "Otwórz za pomocą…" pulls them
    # into %TEMP%. Stops accidental clicks on multi-gig logs from
    # filling the disk.
    _LARGE_FILE_THRESHOLD = 500 * 1024 * 1024     # 500 MB

    def _confirm_large_file(self, name: str, size_bytes: int) -> bool:
        """Ask before downloading files above _LARGE_FILE_THRESHOLD.

        Returns True if the user wants to proceed. Sizes are shown in
        MB/GB rather than raw bytes because the threshold makes "MB"
        the natural unit and humans recognise it faster than 10-digit
        byte counts.
        """
        if size_bytes < 1024 * 1024 * 1024:
            human = f"{size_bytes / (1024 * 1024):.0f} MB"
        else:
            human = f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
        ans = QMessageBox.question(
            self, "Duży plik",
            f"Plik '{name}' ma {human}.\n\n"
            "Pobranie zajmie miejsce w %TEMP% i może chwilę potrwać.\n"
            "Kontynuować?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return ans == QMessageBox.StandardButton.Yes

    def _probe_writable(self, remote: str) -> bool:
        """Can the SFTP user write `remote`?  Decided from permissions only.

        2026-10-14 (C1-12): this used to open the file for writing ('r+') and
        close it.  Nothing was written, but closing a handle opened for
        writing raises IN_CLOSE_WRITE on the server — the event incron/inotify
        watchers on the server react to.  Now the mode
        bits from ``stat`` are compared with the user's uid and groups (one
        ``id`` per connection, cached).  Anything unknown answers True, as
        before, so a transient failure never blocks the user; an ACL that
        grants more than the mode bits shows the read-only question needlessly
        — the cautious side.
        """
        if not self._sftp:
            return True
        try:
            st = self._sftp.stat(remote)
        except Exception:
            return True
        return mode_allows_write(getattr(st, 'st_mode', None),
                                 getattr(st, 'st_uid', None),
                                 getattr(st, 'st_gid', None),
                                 self._remote_identity())

    def _remote_identity(self):
        """(uid, gids) of the SSH user on the current connection, or None."""
        client = self._ssh_client
        if client is None:
            return None
        key = connection_token(client)
        if key in self._identity_cache:
            return self._identity_cache[key]
        ident = None
        try:
            _, out, _ = client.exec_command('id -u; id -G', timeout=5)
            lines = out.read().decode('ascii', 'replace').split('\n')
            uid = int(lines[0].strip())
            gids = {int(g) for g in lines[1].split()} if len(lines) > 1 else set()
            ident = (uid, gids)
        except Exception:
            ident = None
        self._identity_cache[key] = ident
        return ident

    def _confirm_readonly_open(self, name: str) -> bool:
        """Modal: file is read-only on the server. Open in view-only mode?

        Returning True opens the file without registering a watcher, so the
        local edit never triggers an auto-upload that would silently fail.
        Returning False cancels the open entirely.
        """
        ans = QMessageBox.warning(
            self, "Plik tylko do odczytu",
            f"Brak praw zapisu do '{name}' na serwerze.\n\n"
            "Zmiany zapisane w edytorze NIE zostaną wgrane.\n"
            "Otworzyć w trybie podglądu?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return ans == QMessageBox.StandardButton.Yes

    def _open_remote(self, remote: str, name: str):
        """Download to temp file, open with default app, watch for changes → auto-upload."""
        if not self._ssh_client:
            return
        # Warn about potentially dangerous file types
        ext = os.path.splitext(name)[1].lower()
        if ext in self._DANGEROUS_EXT:
            r = QMessageBox.warning(
                self, "Ostrzeżenie",
                f"Plik \"{name}\" ma potencjalnie niebezpieczne rozszerzenie "
                f"({ext}).\n\nCzy na pewno chcesz go otworzyć?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if r != QMessageBox.StandardButton.Yes:
                return
        # A dedicated subdir per panel and per (server, remote path), so the
        # file keeps its original name (like WinSCP) and is never shared
        # with another window or another directory (C1-01/C1-02).
        tmp_path = self._local_copy_path(remote, name)
        os.makedirs(os.path.dirname(tmp_path), exist_ok=True)

        # If already open/watched, check if the server-side file has
        # changed since our last download (e.g. user vim'd it in the
        # terminal) — if so, drop the stale temp and re-download.
        # Otherwise just open the cached local copy.
        if tmp_path in self._download_active:
            self.status_msg.emit(f"'{name}' jest właśnie pobierany.", False)
            return
        if tmp_path in self._upload_active:
            # Review 2026-10-15 M1: a direct put truncates the server file
            # first — reading it now could bring back a cut copy.
            self.status_msg.emit(
                f"'{name}' jest właśnie wysyłany — otwórz go ponownie za chwilę.",
                False)
            return
        if tmp_path in self._watched_files:
            info = self._watched_files[tmp_path]
            server_changed = False
            if self._sftp:
                try:
                    st = self._sftp.stat(remote)
                    srv_mtime = int(st.st_mtime or 0)
                    srv_size  = st.st_size or 0
                    last_mtime = int(info.get('server_mtime', 0))
                    last_size  = info.get('server_size', None)
                    if last_mtime and srv_mtime > last_mtime:
                        server_changed = True
                    elif last_size is not None and srv_size != last_size:
                        server_changed = True
                except Exception:
                    pass    # probe failure → fall back to cache
            if not server_changed:
                QDesktopServices.openUrl(QUrl.fromLocalFile(tmp_path))
                return
            if self._has_unsent_edits(tmp_path):
                # Review 2026-10-15 M2: the copy holds edits the server has
                # not got — never replace them with the newer server file.
                self.status_msg.emit(
                    f"'{name}' zmienił się na serwerze, a lokalna kopia ma "
                    "niewysłane zmiany — nie pobrano nowej wersji.", True)
                return
            # Server has newer content — download again below.  The watch
            # stays (re-review 2026-10-15): _download_active holds it during
            # the download and _watch_file renews it on success; a failed,
            # cancelled or refused download leaves the editor's saves still
            # going to the server instead of silently nowhere.

        # Size guard — bail before any download if the file is huge.
        # The stat is one nav-channel roundtrip; tolerable to do on the
        # UI thread because anything past ~100 MB is going to be a
        # multi-second download anyway.
        if self._sftp:
            try:
                sz = self._sftp.stat(remote).st_size or 0
                if sz >= self._LARGE_FILE_THRESHOLD:
                    if not self._confirm_large_file(name, sz):
                        return
            except Exception:
                pass    # stat failure → just attempt the download

        # Probe write access BEFORE downloading. If the file is read-only,
        # the auto-upload watcher would later fail silently — by asking up
        # front we either skip the watcher (view-only) or cancel cleanly.
        watch_for_upload = True
        if not self._probe_writable(remote):
            if not self._confirm_readonly_open(name):
                return
            watch_for_upload = False

        ssh_client = self._ssh_client   # capture — each worker gets its own channel

        lock = self._sftp_open_lock

        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setVisible(True)
        self._btn_cancel.setVisible(True)

        worker_ref = [None]
        sftp_ref = [None]
        part_path = local_part_path(tmp_path)
        start_mtime = _mtime_or_none(tmp_path)
        self._download_active.add(tmp_path)

        def do_open():
            with lock:                          # serialize channel opens
                sftp = ssh_client.open_sftp()
            sftp_ref[0] = sftp
            srv_mtime = 0
            srv_size  = 0
            try:
                try:
                    st = sftp.stat(remote)
                    srv_mtime = int(st.st_mtime or 0)
                    srv_size  = st.st_size or 0
                    total     = srv_size or 1
                except Exception:
                    total = 1
                def cb(done, t):
                    if worker_ref[0]._cancel:
                        raise _CancelledError()
                    worker_ref[0].progress.emit(min(int(done * 100 / (t or total)), 100))
                sftp.get(remote, part_path, callback=cb)
            finally:
                sftp_ref[0] = None
                try:
                    sftp.close()
                except Exception:
                    pass
            replace_local_copy(part_path, tmp_path, start_mtime)
            self._open_local.emit(tmp_path)
            size = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
            # Always register the watcher — even in view-only mode — so a
            # write to a read-only file produces an explicit "permission
            # denied" status instead of silence (the editor's own
            # confirmation can look indistinguishable from a real save).
            self._watch_file_sig.emit(tmp_path, remote, size,
                                       not watch_for_upload,
                                       srv_mtime, srv_size, ssh_client)

        def hard_cancel():
            s = sftp_ref[0]
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

        w = _SimpleWorker(do_open)
        w.set_cancel_hook(hard_cancel)
        worker_ref[0] = w
        self._active_transfer_worker = w
        w.progress.connect(self._progress.setValue)
        w.cancelled.connect(lambda: (
            self._download_ended(tmp_path, part_path),
            self._transfer_cancelled(part_path)))
        w.error.connect(lambda e: (
            self._download_ended(tmp_path, part_path),
            self._transfer_finished_cleanup(),
            self.status_msg.emit(f"Otwieranie: {e}", True)))
        w.done.connect(lambda: self._transfer_finished_cleanup())
        w.start()
        self._workers.append(w)

    def _open_with(self, remote: str, name: str):
        """Download to temp, then let the user pick an application to open with."""
        if not self._ssh_client:
            return
        tmp_path = self._local_copy_path(remote, name)
        os.makedirs(os.path.dirname(tmp_path), exist_ok=True)

        # Same size guard as _open_remote — large files routinely show
        # up in /var/log; one wrong click would otherwise dump a 5 GB
        # journal into %TEMP%.
        if self._sftp:
            try:
                sz = self._sftp.stat(remote).st_size or 0
                if sz >= self._LARGE_FILE_THRESHOLD:
                    if not self._confirm_large_file(name, sz):
                        return
            except Exception:
                pass

        # See _open_remote — same read-only probe so we don't pretend an
        # edit made via "Open with…" will round-trip back to the server.
        watch_for_upload = True
        if not self._probe_writable(remote):
            if not self._confirm_readonly_open(name):
                return
            watch_for_upload = False

        if tmp_path in self._download_active:
            self.status_msg.emit(f"'{name}' jest właśnie pobierany.", False)
            return
        if tmp_path in self._upload_active:
            self.status_msg.emit(
                f"'{name}' jest właśnie wysyłany — otwórz go ponownie za chwilę.",
                False)
            return
        if self._has_unsent_edits(tmp_path):
            self.status_msg.emit(
                f"Lokalna kopia '{name}' ma niewysłane zmiany — nie pobrano jej "
                "ponownie. Zapisz ją jeszcze raz albo zamknij edytor.", True)
            return

        ssh_client = self._ssh_client
        lock = self._sftp_open_lock

        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setVisible(True)
        self._btn_cancel.setVisible(True)

        worker_ref = [None]
        sftp_ref = [None]
        # F1: a file already open is downloaded again here — into a private
        # part file, with the watch held, never into the copy being edited.
        part_path = local_part_path(tmp_path)
        start_mtime = _mtime_or_none(tmp_path)
        self._download_active.add(tmp_path)

        srv_meta = {'mtime': 0, 'size': 0}

        def do_download():
            with lock:
                sftp = ssh_client.open_sftp()
            sftp_ref[0] = sftp
            try:
                try:
                    st = sftp.stat(remote)
                    srv_meta['mtime'] = int(st.st_mtime or 0)
                    srv_meta['size']  = st.st_size or 0
                    total = srv_meta['size'] or 1
                except Exception:
                    total = 1
                def cb(done, t):
                    if worker_ref[0]._cancel:
                        raise _CancelledError()
                    worker_ref[0].progress.emit(min(int(done * 100 / (t or total)), 100))
                sftp.get(remote, part_path, callback=cb)
            finally:
                sftp_ref[0] = None
                try:
                    sftp.close()
                except Exception:
                    pass
            replace_local_copy(part_path, tmp_path, start_mtime)

        def hard_cancel():
            s = sftp_ref[0]
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

        def on_done():
            self._transfer_finished_cleanup()
            if not os.path.exists(tmp_path):
                self._download_ended(tmp_path, part_path)
                return
            if sys.platform == 'win32':
                import subprocess
                subprocess.Popen(['rundll32', 'shell32.dll,OpenAs_RunDLL', tmp_path])
            else:
                subprocess.Popen(['xdg-open', tmp_path])
            size = os.path.getsize(tmp_path) if os.path.exists(tmp_path) else 0
            # Same reasoning as _open_remote — always watch, flag
            # readonly so the poller surfaces "permission denied"
            # instead of attempting (and silently dropping) an upload.
            self._watch_file_sig.emit(tmp_path, remote, size,
                                       not watch_for_upload,
                                       srv_meta['mtime'], srv_meta['size'],
                                       ssh_client)

        w = _SimpleWorker(do_download)
        w.set_cancel_hook(hard_cancel)
        worker_ref[0] = w
        self._active_transfer_worker = w
        w.progress.connect(self._progress.setValue)
        w.cancelled.connect(lambda: (
            self._download_ended(tmp_path, part_path),
            self._transfer_cancelled(part_path)))
        w.error.connect(lambda e: (
            self._download_ended(tmp_path, part_path),
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
            self.status_msg.emit(f"Nie można odczytać uprawnień: {e}", True)
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

    def _watch_file(self, local_path: str, remote_path: str,
                    orig_size: int = 0, readonly: bool = False,
                    server_mtime: int = 0, server_size: int = 0,
                    owner=None):
        try:
            mtime = os.path.getmtime(local_path) if os.path.exists(local_path) else 0
        except OSError:
            mtime = 0
        entry = {
            'remote':       remote_path,
            'orig_size':    orig_size,
            'mtime':        mtime,
            'dirty':        False,   # last upload failed → local is ahead of remote
            'readonly':     readonly,  # remote rejected the write probe — no upload attempts
            'server_mtime': server_mtime,  # for stale-cache detection on re-open
            'server_size':  server_size,
        }
        self._download_active.discard(local_path)
        # The connection the file came through, fixed for the life of the
        # watch (2026-10-15, F3): an upload goes only through this one, never
        # through whatever tab happens to be active.
        bind_to = owner if owner is not None else self._ssh_client
        try:
            entry['owner'] = weakref.ref(bind_to) if bind_to is not None else None
        except TypeError:
            entry['owner'] = None
        # The download finished on the worker thread; the user may have
        # switched tabs (or the session reconnected) meanwhile.  The file
        # belongs to the connection it came through — watching it under the
        # current one would upload it to another server (review 67/S2).
        if owner is not None and not self.bound_to(owner):
            self._watch_for_other(owner, local_path, entry)
            return
        self._watched_files[local_path] = entry
        if not self._watch_poll.isActive():
            self._watch_poll.start()

    def _has_unsent_edits(self, local_path: str) -> bool:
        """Has the editor saved `local_path` since its last upload, or did
        that upload fail?  (Read-only copies never upload — not counted.)"""
        info = self._watched_files.get(local_path)
        if info is None or info.get('readonly'):
            return False
        if info.get('dirty'):
            return True
        mtime = _mtime_or_none(local_path)
        return mtime is not None and mtime > info['mtime']

    def _report_leftovers(self, leftovers: list) -> None:
        """Safe replace could not delete its temp file (review 2026-10-15
        M3): say where it is, so it does not sit unnoticed in a receiver's
        directory."""
        for path in leftovers:
            self.status_msg.emit(
                f"Plik tymczasowy '{path}' mógł zostać na serwerze — "
                "sprawdź katalog i usuń go ręcznie.", True)

    def _download_ended(self, local_path: str, part_path: str) -> None:
        """A download into `local_path` is over without a new watch."""
        self._download_active.discard(local_path)
        if os.path.exists(part_path):
            try:
                os.remove(part_path)
            except OSError:
                pass

    def _upload_target_ok(self, info: dict) -> bool:
        """Does this watch belong to the connection the panel is on now?

        The watch list is swapped with the tab, so this always holds — it is
        the second lock on the door (F3): an entry without a live owner, or
        with another one, is never uploaded."""
        ref = info.get('owner')
        client = ref() if ref is not None else None
        return client is not None and client is self._ssh_client

    def _watch_for_other(self, owner, local_path: str, entry: dict) -> None:
        """File a watch under a connection that is not the active one."""
        kept = self._watch_store.get(id(owner))
        if kept is not None and kept[0]() is owner:
            kept[1][local_path] = entry
            return
        try:
            self._watch_store[id(owner)] = (weakref.ref(owner), {local_path: entry})
        except TypeError:
            pass

    def _poll_watched_files(self):
        if not self._ssh_client:
            return
        for local_path, info in list(self._watched_files.items()):
            if (local_path in self._upload_active
                    or local_path in self._download_active
                    or info.get('conflict_open')):
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
            if not self._upload_target_ok(info):
                continue
            orig_size = info['orig_size']
            # Defence against editor crashes / antivirus quarantine
            # truncating the temp file to 0 B or a sliver of its
            # original size. Originally a silent skip — but legitimate
            # cases (user emptying a small config file) were getting
            # blocked too. Now we ask. The mtime is bumped before the
            # prompt so a "No" doesn't loop on the same write.
            suspicious_empty  = size == 0 and orig_size > 0
            suspicious_shrink = orig_size > 512 and size < orig_size * 0.10
            if suspicious_empty or suspicious_shrink:
                info['mtime'] = mtime
                name = os.path.basename(local_path)
                if suspicious_empty:
                    q = (f"Plik '{name}' jest pusty (poprzednio {orig_size} B).\n\n"
                         "Czy na pewno wgrać pusty plik na serwer?\n"
                         "(„Nie” jeśli to był wypadek — np. crash edytora.)")
                else:
                    q = (f"Plik '{name}' skurczył się drastycznie: "
                         f"{size} B zamiast {orig_size} B.\n\n"
                         "Czy na pewno wgrać tak okrojoną wersję?\n"
                         "(„Nie” jeśli to nie była zamierzona zmiana.)")
                ans = QMessageBox.question(
                    self, "Podejrzanie mały plik", q,
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if ans != QMessageBox.StandardButton.Yes:
                    self.status_msg.emit(
                        f"Auto-upload pominięty — '{name}' "
                        f"({size} B, było {orig_size} B)", False)
                    continue
                info['orig_size'] = size           # accept new baseline
            info['mtime']     = mtime
            info['orig_size'] = size
            if info.get('readonly'):
                # Read-only mode: pre-flight write probe already said the
                # server will reject this. Surface "permission denied"
                # explicitly so the user gets the same feedback they'd
                # get from any normal editor → SFTP combo, without
                # actually round-tripping a doomed upload. Refresh the
                # listing so the user can see the server-side mtime is
                # unchanged — confirms visually that the save didn't take.
                info['dirty'] = True
                name = os.path.basename(local_path)
                self.status_msg.emit(
                    f"Permission denied: '{name}' tylko do odczytu — "
                    "zmiany NIE zostały wgrane na serwer.", True)
                self._list(self._path)
                continue
            self._upload_changed_file(local_path, info['remote'])

    def _upload_changed_file(self, local: str, remote: str):
        if not self._ssh_client or local in self._upload_active:
            return
        # The watch, not the active tab, says where the file goes (F3).
        info = self._watched_files.get(local)
        if info is None or info.get('remote') != remote \
                or not self._upload_target_ok(info):
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
        sftp_ref = [None]
        final_stat = [None]
        leftovers: list[str] = []
        unknown = [None]     # "stan NIEZNANY" must survive a cancel
        changed = [None]     # RemoteChangedError: the user decides
        started = [False]    # the write began: the server file may be ours now
        in_place: list[str] = []   # an in-place write began (and why)

        def forget_baseline_if_written():
            # A direct write that broke (or an unknown safe replace) has
            # already changed the server file itself: the next save must not
            # call our own half-write "changed by someone else".
            if started[0] and (in_place or unknown[0]):
                info['server_mtime'] = 0
                info['server_size'] = 0

        def do_upload():
            with lock:
                sftp = ssh_client.open_sftp()
            sftp_ref[0] = sftp
            try:
                def cb(done, t):
                    if worker_ref[0]._cancel:
                        raise _CancelledError()
                    worker_ref[0].progress.emit(min(int(done * 100 / (t or total)), 100))

                def before_commit():
                    if worker_ref[0]._cancel:
                        raise _CancelledError()
                # Size re-verified after the write so a quota/permission quirk
                # that silently drops bytes can't masquerade as success.
                try:
                    check_remote_unchanged(sftp, remote,
                                           info.get('server_mtime', 0),
                                           info.get('server_size', 0))
                except RemoteChangedError as e:
                    changed[0] = e
                    raise
                started[0] = True
                try:
                    final_stat[0] = upload_edit(sftp, local, remote, callback=cb,
                                                before_commit=before_commit,
                                                leftovers=leftovers,
                                                fallback_direct=True,
                                                in_place=in_place)
                except SafeReplaceError as e:
                    if 'NIEZNANY' in str(e):
                        unknown[0] = str(e)
                    raise
            finally:
                sftp_ref[0] = None
                try:
                    sftp.close()
                except Exception:
                    pass

        def hard_cancel():
            s = sftp_ref[0]
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

        def on_done(_=None):
            self._upload_active.discard(local)
            self._transfer_finished_cleanup()
            # Local is now in sync with server — clear any dirty flag
            # set by a previous failed upload of the same file. Also
            # refresh the stored server metadata so the next re-open
            # doesn't see our own upload as "someone vim'd it externally".
            # The stat comes from the upload's own channel — the panel may
            # be on another server by now (F3).
            info['dirty'] = False
            st = final_stat[0]
            # Without a stat the baseline is unknown (0): the next save is
            # not checked, rather than reported as someone else's change.
            info['server_mtime'] = int(st.st_mtime or 0) if st is not None else 0
            info['server_size']  = (st.st_size or 0) if st is not None else 0
            self.status_msg.emit(f"Zapisano na SFTP: {os.path.basename(remote)}"
                                 + _in_place_note(in_place), False)
            self._list(self._path)

        def on_cancelled():
            self._upload_active.discard(local)
            self._transfer_finished_cleanup()
            self.status_msg.emit("Auto-upload anulowany", False)
            forget_baseline_if_written()
            if unknown[0]:
                info['dirty'] = True
                self.status_msg.emit(f"Błąd zapisu: {unknown[0]}", True)
            self._report_leftovers(leftovers)

        def on_error(e):
            self._upload_active.discard(local)
            self._transfer_finished_cleanup()
            # Keep the dirty bit around so internal state stays honest
            # (used by anything else that inspects _watched_files), but
            # the visible signal is now: modal error + listing refresh.
            # The listing's server-side mtime tells the user whether the
            # save took, replacing the dirty-reopen prompt we removed.
            info['dirty'] = True
            if changed[0] is not None:
                self._resolve_remote_change(local, remote, info, changed[0])
                return
            forget_baseline_if_written()
            self.status_msg.emit(f"Błąd zapisu: {e}", True)
            self._report_leftovers(leftovers)
            self._list(self._path)

        w = _SimpleWorker(do_upload)
        w.set_cancel_hook(hard_cancel)
        worker_ref[0] = w
        self._active_transfer_worker = w
        w.progress.connect(self._progress.setValue)
        w.cancelled.connect(on_cancelled)
        w.done.connect(on_done)
        w.error.connect(on_error)
        w.start()
        self._workers.append(w)

    # ── A server file changed under an open edit (2026-10-21) ─────────────

    def _ask_remote_changed(self, name: str, info: dict, err: 'RemoteChangedError',
                            allow_show: bool = True) -> str:
        """'overwrite' / 'show' / 'skip' — what to do with an edit whose
        server file is no longer the one it was opened from."""
        def when(t):
            try:
                return datetime.fromtimestamp(int(t)).strftime('%d.%m %H:%M:%S')
            except (OverflowError, OSError, ValueError):
                return "?"
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        if err.deleted:
            box.setWindowTitle("Plik usunięty na serwerze")
            box.setText(f"'{name}' został usunięty z serwera, odkąd go otworzono.")
            box.setInformativeText(
                f"Ścieżka: {err.remote}\n\nWgranie Twojej wersji utworzy go ponownie.")
            btn_ow = box.addButton("Utwórz ponownie moją wersją",
                                   QMessageBox.ButtonRole.AcceptRole)
            btn_show = None
        else:
            box.setWindowTitle("Plik zmienił się na serwerze")
            box.setText(f"'{name}' na serwerze jest inny niż w chwili otwarcia.")
            box.setInformativeText(
                f"Ścieżka: {err.remote}\n"
                f"Przy otwarciu: {when(info.get('server_mtime', 0))}, "
                f"{info.get('server_size', 0)} B\n"
                f"Teraz na serwerze: {when(err.mtime)}, {err.size} B\n\n"
                "Ktoś go zmienił — inna karta lub okno, terminal, inna osoba "
                "albo program. Wgranie Twojej wersji usunie tamte zmiany.\n"
                "Twoja wersja nie została jeszcze wgrana.")
            btn_ow = box.addButton("Nadpisz moją wersją",
                                   QMessageBox.ButtonRole.DestructiveRole)
            btn_show = (box.addButton("Pokaż wersję z serwera",
                                      QMessageBox.ButtonRole.ActionRole)
                        if allow_show else None)
        btn_skip = box.addButton("Nie wgrywaj", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(btn_skip)
        box.exec()
        clicked = box.clickedButton()
        if clicked is btn_ow:
            return 'overwrite'
        if btn_show is not None and clicked is btn_show:
            return 'show'
        return 'skip'

    def _resolve_remote_change(self, local: str, remote: str, info: dict,
                               err: 'RemoteChangedError') -> None:
        """The upload found the server file changed: nothing was written,
        the user chooses.  The local copy is never touched here."""
        name = os.path.basename(local)
        info['conflict_open'] = True
        try:
            choice = self._ask_remote_changed(name, info, err)
        finally:
            info['conflict_open'] = False
        if choice == 'overwrite':
            # The server file as it is now becomes the baseline; if it changes
            # again before the write, the user is asked again.
            info['server_mtime'] = 0 if err.deleted else err.mtime
            info['server_size']  = 0 if err.deleted else err.size
            self._upload_changed_file(local, remote)
            return
        if choice == 'show':
            self._show_server_version(local, remote, info)
        self.status_msg.emit(
            f"NIE wgrano '{name}' — plik zmienił się na serwerze. Twoja wersja "
            "jest w edytorze; przy następnym zapisie zapytam ponownie.", True)

    def _show_server_version(self, local: str, remote: str, info: dict) -> None:
        """Download the server's version next to the local copy, under its
        own name, and open it — for comparing.  It is not watched: saving it
        uploads nothing."""
        ref = info.get('owner')
        client = ref() if ref is not None else None
        if client is None:
            return
        stem, ext = os.path.splitext(os.path.basename(local))
        target = os.path.join(
            os.path.dirname(local),
            f"{stem} (wersja z serwera {datetime.now():%H-%M-%S}){ext}")
        lock = self._sftp_open_lock

        def do_get():
            with lock:
                sftp = client.open_sftp()
            try:
                sftp.get(remote, target)
            finally:
                try:
                    sftp.close()
                except Exception:
                    pass

        def on_done(_=None):
            self._open_local.emit(target)

        def on_error(e):
            self.status_msg.emit(f"Nie można pobrać wersji z serwera: {e}", True)

        w = _SimpleWorker(do_get)
        w.done.connect(on_done)
        w.error.connect(on_error)
        w.start()
        self._workers.append(w)

    def _flush_pending_edits(self, final: bool = False):
        """Synchronously upload any watched temp file whose local copy is newer
        than what we last sent to the server — BEFORE the watch list is torn
        down (tab switch / reconnect / panel close).

        Without this, a save made in the external editor inside the ~2 s poll
        window — or any save followed by leaving the tab — is silently dropped:
        switch_sftp()/stop() stop the poll and clear _watched_files, so the
        change never uploads and the next re-open re-downloads the stale server
        copy. (That is why edits only "stuck" while staying on the same tab.)

        Best-effort and bounded: uses the connection that is still current at
        call time (correct for tab-switch and graceful close); a dead
        connection — the reconnect case — fails fast (open_sftp() raises on a
        closed transport) and we surface a warning instead of hanging the UI.
        Huge edits are skipped with a warning so a multi-MB synchronous put
        can't freeze the close path.
        """
        client = self._ssh_client
        if not client or not self._watched_files:
            return
        unsent: list[str] = []
        for local_path, info in list(self._watched_files.items()):
            if (info.get('readonly') or local_path in self._upload_active
                    or local_path in self._download_active
                    or not self._upload_target_ok(info)):
                continue
            if not os.path.exists(local_path):
                continue
            try:
                mtime = os.path.getmtime(local_path)
                size  = os.path.getsize(local_path)
            except OSError:
                continue
            if mtime <= info['mtime']:
                continue                      # nothing new since last upload
            remote = info['remote']
            name = os.path.basename(local_path)
            if size > self._SYNC_FLUSH_MAX_BYTES:
                unsent.append(
                    f"Niewysłane zmiany w '{name}' ({size} B) — plik za duży "
                    "na zapis przy przełączeniu; wgraj ponownie ręcznie."
                    + self._keep_unsent(local_path, final))
                self.status_msg.emit(unsent[-1], True)
                continue
            started = False
            in_place: list[str] = []
            try:
                # Synchronous, on the UI thread, often while closing: bounded
                # so a dead connection fails instead of freezing (C1-11).
                sftp = open_sftp_bounded(client)
                leftovers: list[str] = []
                try:
                    try:
                        check_remote_unchanged(sftp, remote,
                                               info.get('server_mtime', 0),
                                               info.get('server_size', 0))
                    except RemoteChangedError as e:
                        # A tab switch leaves the question for the return to
                        # the tab (the poll asks); a close asks now.
                        if not final or self._ask_remote_changed(
                                name, info, e, allow_show=False) != 'overwrite':
                            raise
                    started = True
                    st = upload_edit(sftp, local_path, remote, leftovers=leftovers,
                                     fallback_direct=True, in_place=in_place)
                finally:
                    self._report_leftovers(leftovers)
                    try:
                        sftp.close()
                    except Exception:
                        pass
                info['mtime'] = mtime
                info['dirty'] = False
                info['server_mtime'] = int(st.st_mtime or 0) if st is not None else 0
                info['server_size']  = (st.st_size or 0) if st is not None else 0
                self.status_msg.emit(
                    f"Zapisano na SFTP przed przełączeniem: "
                    f"{os.path.basename(remote)}" + _in_place_note(in_place), False)
            except Exception as e:
                if started and (in_place or 'NIEZNANY' in str(e)):
                    # Our own broken write changed the server file (see
                    # _upload_changed_file): not someone else's change.
                    info['server_mtime'] = 0
                    info['server_size'] = 0
                unsent.append(f"Niewysłane zmiany w '{name}': {e}"
                              + self._keep_unsent(local_path, final))
                self.status_msg.emit(unsent[-1], True)
        if final and unsent:
            # The window is closing: a status line would never be read.
            self._notify_unsent(unsent)

    def _notify_unsent(self, lines: list) -> None:
        QMessageBox.warning(self, "Zmiany niewgrane na serwer", "\n\n".join(lines))

    def _keep_unsent(self, local_path: str, final: bool) -> str:
        """On a close, copy an edit that did not reach the server out of the
        temp directory (which the close deletes) — the sentence to append to
        the message.  On a tab switch the copy stays where it is."""
        if not final:
            return ""
        kept = preserve_unsent_copy(local_path)
        if kept:
            return f"  Twoja wersja zachowana: {kept}"
        return "  Nie udało się zachować kopii — zmiany przepadną."

    # Above this size, _flush_pending_edits refuses the synchronous put so the
    # teardown path can't block the UI thread. Edited config files are tiny;
    # anything this large is unlikely to be a live edit anyway.
    _SYNC_FLUSH_MAX_BYTES = 16 * 1024 * 1024     # 16 MB

    # Cap on the recursive-count scan that precedes a directory delete.
    # We don't need an exact number — "5000+" is enough for the user to
    # realise the scope. Stops a pathological tree (e.g. accidentally
    # pointing at /var/log) from spending 30 s scanning before the
    # confirmation dialog even appears.
    _DELETE_COUNT_CAP = 5000

    def _delete(self, remote: str, is_dir: bool, name: str):
        """Delete a remote file/directory after an informed confirm.

        Plain file → short confirm and go. Directory → first scan its
        contents on a worker thread (with a cap) and surface a confirm
        that names how many files and subdirs are about to vanish.
        Previously the prompt was a one-liner that hid the blast radius
        of recursive deletes.
        """
        if not is_dir:
            from ui.utils import confirm
            # "Anuluj" by default (E-07): the file goes from the server for good.
            if not confirm(self, "Usuń plik",
                           f"Usunąć plik '{name}' z serwera?\n\n"
                           "Tej operacji nie można cofnąć.",
                           yes="Usuń", no="Anuluj"):
                return
            self._run_delete(remote, is_dir=False, name=name)
            return

        # Directory — scan first to show count in the confirm dialog.
        if not self._ssh_client:
            return
        ssh_client = self._ssh_client
        lock = self._sftp_open_lock
        cap = self._DELETE_COUNT_CAP
        scan_result: dict = {}

        self._progress.setFormat(f"Liczenie zawartości: {name}")
        self._progress.setRange(0, 0)         # indeterminate
        self._progress.setValue(0)
        self._progress.setVisible(True)

        def scan():
            with lock:
                sftp = ssh_client.open_sftp()
            try:
                scan_result.update(
                    _count_dir_with_cap(sftp.listdir_attr, remote, cap))
            finally:
                try:
                    sftp.close()
                except Exception:
                    pass

        def reset_progress():
            self._progress.setRange(0, 100)
            self._progress.setFormat("%p%")
            self._progress.setVisible(False)

        def after_scan():
            reset_progress()
            if scan_result.get('error'):
                self.status_msg.emit(
                    f"Nie można odczytać katalogu: {scan_result['error']}", True)
                return
            f = scan_result.get('files', 0)
            d = scan_result.get('dirs', 0)
            capped = scan_result.get('capped', False)
            if capped:
                details = (f"co najmniej {_pl_pl(f, 'plik', 'pliki', 'plików')} "
                           f"i {_pl_pl(d, 'podkatalog', 'podkatalogi', 'podkatalogów')} "
                           f"(zawartość większa niż {cap})")
            elif f == 0 and d == 0:
                details = "katalog jest pusty"
            else:
                details = (f"{_pl_pl(f, 'plik', 'pliki', 'plików')}, "
                           f"{_pl_pl(d, 'podkatalog', 'podkatalogi', 'podkatalogów')}")
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle("Usuń katalog")
            box.setText(f"Czy na pewno usunąć katalog '{name}'?")
            box.setInformativeText(
                f"Zawiera: {details}\n\nOperacja jest nieodwracalna."
            )
            btn_yes = box.addButton("Usuń", QMessageBox.ButtonRole.DestructiveRole)
            btn_no  = box.addButton("Anuluj", QMessageBox.ButtonRole.RejectRole)
            box.setDefaultButton(btn_no)
            box.exec()
            if box.clickedButton() is btn_yes:
                self._run_delete(remote, is_dir=True, name=name)

        def on_err(e):
            reset_progress()
            self.status_msg.emit(f"Liczenie zawartości: {e}", True)

        w = _SimpleWorker(scan)
        w.done.connect(after_scan)
        w.error.connect(on_err)
        w.start()
        self._workers.append(w)

    def _run_delete(self, remote: str, is_dir: bool, name: str):
        """Actually perform the delete after the user confirmed."""
        sftp = self._sftp
        worker_ref = [None]

        def do_delete():
            if not is_dir:
                sftp.remove(remote)
                return
            files, dirs = [], []
            def walk(p):
                for a in sftp.listdir_attr(p):
                    sub = p.rstrip('/') + '/' + a.filename
                    if stat.S_ISDIR(a.st_mode or 0):
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
            self._progress.setRange(0, 0)        # indeterminate for single file
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
            if os.path.isfile(path) or os.path.isdir(path):
                files.append(path)
        if files:
            self._begin_uploads(files)

    # ── Cleanup ───────────────────────────────────────────────────────────

    def switch_sftp(self, sftp, ssh_client, restore_path: str = '/',
                    restore_history: list[str] | None = None):
        """Swap active SFTP connection and restore the previous browsed path."""
        # Push any unsaved edits to the OUTGOING connection before we drop the
        # watch list — otherwise leaving the tab loses edits made in the last
        # poll window (see _flush_pending_edits).
        self._flush_pending_edits()
        self._watch_poll.stop()
        # Keep the outgoing connection's watched files and bring back the
        # incoming one's (2026-10-14, C1-03): an editor left open on a file
        # from another tab used to lose every later save without a word.
        # Now those saves upload when that tab is active again.
        if self._ssh_client is not None and self._watched_files:
            self._remember_watches(self._ssh_client, self._watched_files)
        self._watched_files = self._recall_watches(ssh_client)
        # _upload_active is NOT cleared (2026-10-15, F2): its paths are unique
        # per connection, and an upload of A still running when the user
        # comes back to A must keep the poll from starting a second, parallel
        # write of the same file.  Each upload removes its own entry.
        self._sftp        = sftp
        self._ssh_client  = ssh_client
        if self._watched_files and sftp is not None:
            self._watch_poll.start()
        self._history     = restore_history if restore_history is not None else []
        # Abandon any in-flight listing guard from the connection we just left.
        # If that listing hung (half-open socket), the flag would otherwise stay
        # True forever and silently block every _list()/double-click on the new
        # connection — exactly the "double-click does nothing after returning to
        # the tab" symptom. A stale worker that later fires just repaints.
        self._listing_active = False
        self._listing_gen += 1          # results of the left connection are stale
        connected = bool(sftp and ssh_client)
        for b in (self._btn_up, self._btn_home, self._btn_ref,
                  self._btn_mkdir, self._btn_ul):
            b.setEnabled(connected)
        if connected:
            self._list(restore_path)
        else:
            self._path_lbl.setText("Nie połączono")
            self._table.setRowCount(0)
            self._update_history_menu()

    def stop(self):
        self._close_rename_editor()
        # Last chance to push edits still sitting in temp before teardown.
        self._flush_pending_edits(final=True)
        self._watch_poll.stop()
        self._watched_files.clear()
        self._upload_active.clear()
        w = self._active_transfer_worker
        partial = None
        if w is not None:
            try:
                if w.isRunning():
                    w.cancel()      # stops at the next block, closes its channel
                    partial = getattr(self, '_transfer_partial', None)
            except RuntimeError:
                pass
        _unplug_and_retire(self._workers)
        self._workers = []
        if partial:
            # The cancelled download's slot no longer runs (signals cut): a
            # file that did not exist before must not stay behind looking
            # complete (review 71, R-04).
            _remove_partial_download(partial)
        # sftp / ssh_client are owned by _Session objects — closed there

    def transfer_running(self) -> bool:
        """Is a file going to or from the server right now?"""
        if self._upload_active:
            return True
        w = self._active_transfer_worker
        try:
            return w is not None and w.isRunning()
        except RuntimeError:
            return False


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
                 parent=None, initial_machine=None):
        super().__init__(parent)
        # Keyed by the machine itself (id), not by its IP: two machines of
        # a hospital may share an address (e.g. SSH and RDP entries, or two
        # logins) and the second card used to replace the first — a click
        # on one lit up the other (owner's report 2026-10-16).
        self._cards: dict[int, QFrame] = {}     # machine key → card widget
        self._machines: dict[int, object] = {}  # machine key → machine
        self._active_key: int | None = None
        self._selected: set[int] = set()
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
            self.set_active(initial_ip, initial_machine)

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

    def set_admin_mode(self, unlocked: bool) -> None:
        """Admin locked or unlocked in the vault this window came from: show
        or hide the admin-only machines (UX audit S-03)."""
        if unlocked == self._admin_unlocked:
            return
        self._admin_unlocked = unlocked
        old_active = self._machines.get(self._active_key)
        self._cards.clear()
        self._machines.clear()
        self._selected.clear()
        self._active_key = None
        self._build_machine_list(self._current_hospital)
        if old_active is not None:
            self.set_active(old_active.ip, old_active)

    def _select_hospital(self, h):
        if h is self._current_hospital:
            return
        self._current_hospital = h
        self._hospital_btn.setText(
            f"  {h.name}" if h.name else "  (bez nazwy)")
        old_active = self._machines.get(self._active_key)
        self._cards.clear()
        self._machines.clear()
        self._selected.clear()
        self._active_key = None
        self._build_machine_list(h)
        if old_active is not None:
            self.set_active(old_active.ip, old_active)

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
        self._cards[id(m)] = card
        self._machines[id(m)] = m

        # Store machine ref on card for event handling
        card.setProperty('_machine', m)

        rl = QHBoxLayout(card)
        rl.setContentsMargins(10, 4, 8, 4)
        rl.setSpacing(6)

        # IP + name on one line. HTML colours don't pass through the theme
        # remap (that only touches setStyleSheet), so pick them per-theme: a
        # strong dark blue on the light card (the periwinkle was too pale),
        # the original light periwinkle on dark.
        if theme.is_light():
            ip_c, name_c = "#0a4db0", "#525861"
        else:
            ip_c, name_c = "#b0c0ff", "#8a90a4"
        if m.name:
            line = (f"<b style='color:{ip_c};'>{m.ip}</b>"
                    f"<span style='color:{name_c};'>  {m.name}</span>")
        else:
            line = f"<b style='color:{ip_c};'>{m.ip}</b>"
        lbl = QLabel(line)
        lbl.setTextFormat(Qt.TextFormat.RichText)
        lbl.setStyleSheet("font-size:11px;")
        rl.addWidget(lbl, 1)

        if getattr(m, 'connection_type', 'SSH') == 'RDP':
            btn = QPushButton("RDP")
            btn.setFixedSize(36, 18)
            btn.setToolTip(
                f"Połącz przez Remote Desktop ({m.ip}:"
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
            btn.setToolTip(f"Połącz z {m.ip}")
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
        card.mouseDoubleClickEvent = lambda e, _m=m: self._card_double_clicked(_m, e)
        card.setToolTip("Dwuklik lub Enter — połącz;  Ctrl+klik — zaznacz kilka")

        # Right-click context menu with credentials
        card.customContextMenuRequested.connect(
            lambda pos, _m=m, _c=card: self._show_cred_menu(_m, _c, pos))

        return card

    def _card_clicked(self, machine, event):
        if event.button() != Qt.MouseButton.LeftButton:
            return
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self._toggle_select(id(machine))
        else:
            # Selects only.  A single click used to log in at once — and
            # every further click opened another session or mstsc window on
            # a hospital server (UX audit E-04).
            self._clear_selection()
            self._toggle_select(id(machine))
        self.setFocus()

    def _card_double_clicked(self, machine, event):
        if event.button() != Qt.MouseButton.LeftButton:
            return
        self._clear_selection()
        self._dblclick_connect(machine)

    def _toggle_select(self, key: int):
        if key in self._selected:
            self._selected.discard(key)
        else:
            self._selected.add(key)
        self._refresh_card_style(key)

    def _clear_selection(self):
        for key in list(self._selected):
            self._selected.discard(key)
            self._refresh_card_style(key)

    def _refresh_card_style(self, key: int):
        if key not in self._cards:
            return
        if key in self._selected:
            self._cards[key].setStyleSheet(self._STYLE_SELECTED)
        elif key == self._active_key:
            self._cards[key].setStyleSheet(self._STYLE_ACTIVE)
        else:
            self._cards[key].setStyleSheet(self._STYLE_IDLE)

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and self._selected:
            machines = [self._machines[k] for k in self._selected
                        if k in self._machines]
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

    def _key_for(self, ip: str, machine=None):
        """The card of `machine` if it is listed, else the first card with
        this IP (a session opened by hand), else None."""
        if machine is not None and id(machine) in self._cards:
            return id(machine)
        if ip:
            for key, m in self._machines.items():
                if m.ip == ip:
                    return key
        return None

    def set_active(self, ip: str, machine=None):
        """Highlight the card of the active session, de-highlight the
        previous one."""
        key = self._key_for(ip, machine)
        if key == self._active_key:
            return
        old, self._active_key = self._active_key, key
        if old is not None:
            self._refresh_card_style(old)
        if key is not None:
            self._refresh_card_style(key)


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
        # rgb(), not #hex: theme.remap swaps #hex colours, and this bar is
        # part of the terminal, which stays dark in every theme — remapped,
        # it was a light stripe inside the terminal and, beside "Wsparcie
        # Claude", made the dark handle look like a line (2026-10-21).
        self._scrollbar.setStyleSheet(
            "QScrollBar:vertical{background:rgb(13,17,23);width:10px;margin:0;}"
            "QScrollBar::handle:vertical{background:rgb(48,54,61);border-radius:4px;min-height:20px;}"
            "QScrollBar::handle:vertical:hover{background:rgb(72,79,88);}"
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

    def show_error(self, msg: str, title: str = "Połączenie nieudane",
                   hint: str = "") -> None:
        """Print the error card into the terminal and enable the R/Esc
        intercept.  Remembers how many lines it took (`_error_lines`), so a
        retry can take it off the screen again."""
        self._error_mode = True
        self.term.feed(_error_card(title, msg, hint, self.term.terminal_size()[0]))

    def clear_error(self) -> None:
        """Remove the card printed by show_error — from the blank row above
        its top border to the end of the screen — and leave the intercept."""
        if self._error_mode:
            y = _find_row(self.term, lambda t: t.lstrip().startswith("╭"))
            if y is not None:
                if y > 0 and not _screen_row_text(self.term, y - 1).strip():
                    y -= 1
                self.term.feed(f"\x1b[{y + 1};1H\x1b[J")
        self._error_mode = False

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


def _screen_row_text(term, y: int) -> str:
    row = term._screen.buffer[y]
    return "".join(row[x].data for x in range(term._screen.columns))


def _find_row(term, match) -> 'int | None':
    """The lowest visible row whose text satisfies `match` (None: gone —
    scrolled off or overwritten).  Rows are found by what they say, not by
    counting back from the cursor: a resize or a scroll in between would
    otherwise make the rewrite land on someone else's line."""
    term.flush_now()
    for y in range(term._screen.lines - 1, -1, -1):
        if match(_screen_row_text(term, y)):
            return y
    return None


def _fit(text: str, cols: int) -> str:
    """One terminal row: lines that wrapped would throw off the in-place
    rewrites (cursor-up counts rows, not lines)."""
    limit = max(8, cols - 1)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _error_card(title: str, msg: str, hint: str, cols: int) -> str:
    """The "connection failed" card: a rounded frame with the title, the
    error and a hint, then the two keys as caps.  Width follows the
    terminal (up to 72 columns) and every row fits in it — a wrapped row
    would break clear_error(), which counts rows."""
    import textwrap
    indent = 2 if cols >= 40 else 0
    width = max(16, min(72, cols - indent - 1))
    inner = width - 4
    pad = " " * indent
    border, reset = "\x1b[38;5;167m", "\x1b[0m"
    lines = [("\x1b[1;38;5;210m", part)
             for part in textwrap.wrap("●  " + title, inner) or [""]]
    lines.append(("", ""))
    for para in msg.split("\n"):
        for part in textwrap.wrap(para, inner) or [""]:
            lines.append(("\x1b[38;5;250m", part))
    if hint:
        for part in textwrap.wrap(hint, inner):
            lines.append(("\x1b[38;5;244m", part))
    out = ["\r\n", f"{pad}{border}╭{'─' * (width - 2)}╮{reset}\r\n"]
    for color, text in lines:
        out.append(f"{pad}{border}│{reset} {color}{text.ljust(inner)}{reset} "
                   f"{border}│{reset}\r\n")
    out.append(f"{pad}{border}╰{'─' * (width - 2)}╯{reset}\r\n")
    key_r = f"\x1b[1;38;5;231;48;5;25m  R  {reset} \x1b[38;5;252mPołącz ponownie{reset}"
    key_esc = f"\x1b[1;38;5;231;48;5;240m Esc {reset} \x1b[38;5;246mZamknij kartę{reset}"
    out.append("\r\n")
    if cols >= 52:          # both keys on one row: 3 + 21 + 6 + 19 columns
        out.append(f" {pad}{key_r}      {key_esc}\r\n")
    else:
        out.append(f" {pad}{key_r}\r\n {pad}{key_esc}\r\n")
    return "".join(out)


#: Automatic reconnect attempts after a dropped link before the tab stops
#: and offers R (try again) / Esc (close) — a VPN that is gone stays gone.
_AUTO_RECONNECT_TRIES = 3


class _Session:
    """One SSH session: terminal pane + worker + optional SFTP connection."""
    __slots__ = ('pane', 'worker', 'label', 'sftp', 'sftp_client', 'sftp_path',
                 'sftp_history', 'stats_worker', 'last_stats', 'has_unread',
                 'reconnecting', 'reconnect_attempts', 'reconnect_exhausted',
                 'reconnect_line', 'dropped_at', 'machine', 'claude_panel')

    def __init__(self, pane: _TerminalPane, worker: '_SshWorker', label: str,
                 machine=None):
        self.pane         = pane
        self.worker       = worker
        self.label        = label
        #: The vault machine this tab was opened for (None: typed by hand) —
        #: which card of the Environment tab to light up.
        self.machine      = machine
        self.sftp         = None
        self.sftp_client  = None
        self.sftp_path    = '/'
        self.sftp_history: list[str] = []
        self.stats_worker = None
        self.last_stats: tuple | None = None   # (load, mem, uptime, disk) — last known values
        self.has_unread   = False              # set when output arrives on inactive tab
        self.reconnecting = False              # auto-reconnect loop active after a drop
        self.reconnect_attempts = 0            # consecutive failed reconnects (backoff)
        self.reconnect_exhausted = False       # gave up after _AUTO_RECONNECT_TRIES; R restarts
        self.reconnect_line = False            # the one-line attempt status is on screen
        self.dropped_at = ''                   # HH:MM:SS of the drop, for the banner
        #: This tab's "Wsparcie Claude" panel (running, or ended and kept for
        #: reading) — shown only while this tab is on screen (2026-10-21).
        self.claude_panel = None

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
        self._port_edit.setPlaceholderText("22")
        self._port_edit.setToolTip("Puste = 22")
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
        from ui.utils import parse_port, split_host_port
        host, port_in_host = split_host_port(self._ip_edit.text())
        if port_in_host and not self._port_edit.text().strip():
            # "10.0.0.1:2222" pasted into the host field (S-11).
            self._ip_edit.setText(host)
            self._port_edit.setText(port_in_host)
        if not self._ip_edit.text().strip():
            QMessageBox.warning(self, "Błąd", "Podaj adres IP lub hostname.")
            return
        if parse_port(self._port_edit.text(), 22) is None:
            QMessageBox.warning(self, "Błąd", "Port musi być liczbą od 1 do 65535.")
            self._port_edit.setFocus()
            return
        if not self._user_edit.text().strip():
            QMessageBox.warning(self, "Błąd", "Podaj login.")
            return
        self.accept()

    def get_values(self) -> tuple:
        from ui.utils import parse_port
        port = parse_port(self._port_edit.text(), 22) or 22
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
    variants = [(normal, '#8b949e', 1), (hover, '#e6edf3', 1),
                (normal[:-4] + '@2x.png', '#8b949e', 2),
                (hover[:-4] + '@2x.png', '#e6edf3', 2)]
    if not all(os.path.exists(v[0]) for v in variants):
        from PyQt6.QtCore import QPointF
        for path, color, k in variants:
            # Qt's stylesheet url() takes the @2x file on a 2x screen.
            px = QPixmap(16 * k, 16 * k)
            px.fill(Qt.GlobalColor.transparent)
            p = QPainter(px)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.scale(k, k)
            p.setPen(QPen(QColor(color), 1.8))
            p.drawLine(QPointF(4, 4), QPointF(12, 12))
            p.drawLine(QPointF(12, 4), QPointF(4, 12))
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


class _TermSupportHandle(QSplitterHandle):
    """The handle between the terminal and "Wsparcie Claude" (2026-10-21).

    The splitter's grey handle was a white stripe beside the dark terminal in
    the light themes (owner: "biała linia").  This one has the window's
    colour beside the toolbar and the tab bar, and the terminal's own
    background from the terminal's top down — the terminal reaches the
    panel's frame in every theme."""

    def __init__(self, orientation, parent, terminal_top):
        super().__init__(orientation, parent)
        self._terminal_top = terminal_top     # -> y in the splitter, or None

    def paintEvent(self, event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(theme.paint('#010409')))
        top = self._terminal_top()
        if top is not None:
            y = max(0, top - self.y())
            p.fillRect(0, y, self.width(), self.height() - y, QColor(_DEFAULT_BG))
        p.end()


class _TermSupportSplitter(QSplitter):
    def __init__(self, terminal_top):
        super().__init__(Qt.Orientation.Horizontal)
        self._terminal_top = terminal_top

    def createHandle(self):
        return _TermSupportHandle(self.orientation(), self, self._terminal_top)


class _SupportTarget:
    """One SSH tab as "Wsparcie Claude" sees it (ui.claude_panel): its screen
    and scrollback, read only.  It cannot type, and sees nothing else."""

    def __init__(self, dialog: 'SshDialog', session: '_Session'):
        self._dialog = dialog
        self._session = session

    def label(self) -> str:
        return self._session.label

    def alive(self) -> bool:
        s = self._session
        if s not in self._dialog._sessions:
            return False
        channel = getattr(s.worker, "_channel", None)
        return channel is not None and not getattr(channel, "closed", True)

    def read(self, lines: int) -> str:
        """The last `lines` rows: the end of the scrollback, then the screen."""
        term = self._session.term
        term.flush_now()
        screen = term._screen
        visible = [line.rstrip() for line in screen.display]
        top = screen.history.top            # up to 250 000 rows: take the end only
        start = max(0, len(top) - lines)
        rows = [top[i].text.rstrip() for i in range(start, len(top))] + visible
        while rows and not rows[-1]:
            rows.pop()
        return "\n".join(rows[-lines:])



class SshDialog(QDialog):
    # Class-level list to prevent garbage collection of detached windows
    _alive: list['SshDialog'] = []
    # Activation order: the window last used gets the next machine.
    _activations = itertools.count(1)

    def __init__(self, machine, hospital=None, all_hospitals=None,
                 admin_unlocked=False, parent=None):
        # Pass parent=None so this is a true top-level window with own taskbar icon
        super().__init__(None)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        # QDialog defaults strip Min/Max button hints on Windows; restore them
        # so the user can minimize/maximize the SSH window (especially when
        # opened with showMaximized() via the "open in big window" option).
        self.setWindowFlags(
            Qt.WindowType.Window
            | Qt.WindowType.WindowTitleHint
            | Qt.WindowType.WindowSystemMenuHint
            | Qt.WindowType.WindowMinimizeButtonHint
            | Qt.WindowType.WindowMaximizeButtonHint
            | Qt.WindowType.WindowCloseButtonHint
        )
        SshDialog._alive.append(self)
        self._activated_seq = next(SshDialog._activations)
        # The vault window it was opened from (UX audit S-03): its admin lock
        # and its closing reach this window too.
        try:
            owner = parent.window() if parent is not None else None
            self._owner_ref = weakref.ref(owner) if owner is not None else None
        except (TypeError, RuntimeError):
            self._owner_ref = None
        # Eagerly bind the host-key prompt bridge to the GUI thread. The
        # worker threads call into this from missing_host_key() during
        # connect — if the singleton were created from a worker, its
        # queued signal would deliver to that worker's (dead) event loop.
        _get_host_key_prompt()
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
        from ui.utils import resize_within_screen
        resize_within_screen(self, 1200, 700)
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

    def keyPressEvent(self, event):
        """Cycle session tabs with Ctrl+Tab / Ctrl+Shift+Tab.

        Reaches us because TerminalWidget.keyPressEvent ignores these keys
        (event.ignore() bubbles up to the parent dialog).
        """
        key = event.key()
        mods = event.modifiers()
        ctrl = bool(mods & Qt.KeyboardModifier.ControlModifier)
        shift = bool(mods & Qt.KeyboardModifier.ShiftModifier)
        if ctrl and key in (Qt.Key.Key_Tab, Qt.Key.Key_Backtab):
            cnt = self._tab_widget.count()
            if cnt > 1:
                cur = self._tab_widget.currentIndex()
                step = -1 if (shift or key == Qt.Key.Key_Backtab) else 1
                self._tab_widget.setCurrentIndex((cur + step) % cnt)
            event.accept()
            return
        if key == Qt.Key.Key_Escape:
            # A QDialog closes on Escape — here that ended every session at
            # once when the focus sat outside the terminal (SFTP table, tab
            # bar).  The window closes only by its title-bar button
            # (UX audit E-01).
            event.accept()
            return
        super().keyPressEvent(event)

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
        left_tabs.addTab(self._sftp_panel, icon("folder", "#e2b340"), "Pliki")

        self._env_panel = _EnvironmentPanel(
            self._hospital, all_hospitals=self._all_hospitals,
            initial_ip=self._machine.ip, initial_machine=self._machine,
            admin_unlocked=self._admin_unlocked)
        self._env_panel.open_machine.connect(self._open_extra_machine)
        self._env_panel.open_machine_cred.connect(self._open_machine_with_cred)
        left_tabs.addTab(self._env_panel, icon("monitor", "#58a6ff"), "Środowisko")

        self._left_tabs = left_tabs
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

        self._btn_multiexec = QPushButton("Multi-exec")
        set_icon(self._btn_multiexec, "grid", "#58a6ff", on="#ffffff", size=14)
        self._btn_multiexec.setCheckable(True)
        self._btn_multiexec.setStyleSheet(
            "QPushButton{background:#151b23;color:#58a6ff;"
            "border:1px solid #21262d;border-radius:6px;padding:4px 12px;"
            "font-size:11px;}"
            "QPushButton:checked{background:#1f6feb;color:#fff;"
            "border-color:#1f6feb;}"
            "QPushButton:hover{background:#1c2433;border-color:#30363d;}")
        self._btn_multiexec.toggled.connect(self._toggle_multiexec)

        btn_new = QPushButton("Nowa sesja")
        set_icon(btn_new, "plus", "#3fb950", size=14)
        btn_new.setStyleSheet(
            "QPushButton{background:#0d1f0d;color:#3fb950;"
            "border:1px solid #1b3d1b;border-radius:6px;padding:4px 12px;"
            "font-size:11px;}"
            "QPushButton:hover{background:#152b15;border-color:#2d5a2d;}")
        btn_new.clicked.connect(self._prompt_new_session)

        # Wsparcie Claude (2026-10-20): a conversation about the current tab.
        self._btn_claude = QPushButton("Wsparcie Claude")
        set_icon(self._btn_claude, "chat", "#d97757", on="#ffffff", size=14)
        self._btn_claude.setCheckable(True)
        self._btn_claude.setToolTip(
            "Rozmowa z Claude o bieżącej karcie terminala — Claude tylko czyta "
            "ekran i podpowiada komendy, wpisujesz je sam")
        # Claude's orange, as the panel's frame (ui.claude_panel.ACCENT).
        self._btn_claude.setStyleSheet(
            "QPushButton{background:#24150f;color:#e88a6b;"
            "border:1px solid #5c3322;border-radius:6px;padding:4px 12px;"
            "font-size:11px;}"
            "QPushButton:checked{background:#d97757;color:#fff;border-color:#d97757;}"
            "QPushButton:hover{background:#33200f;border-color:#d97757;}")
        self._btn_claude.toggled.connect(self._toggle_claude_support)

        tb.addWidget(self._btn_multiexec)
        tb.addWidget(btn_new)
        tb.addWidget(self._btn_claude)
        tb.addStretch()
        tlay.addLayout(tb)

        # Mode stack: 0 = tabs, 1 = multi-exec grid
        self._mode_stack = QStackedWidget()

        self._tab_widget = QTabWidget()
        self._tab_widget.setStyleSheet(_session_tab_style())
        self._tab_widget.setMovable(True)
        self._tab_widget.setTabsClosable(True)
        # Compact icon size — used for the teal "unread" dot. Default is 16x16
        # which would push the label sideways and make the tab wider whenever
        # activity arrives.
        self._tab_widget.setIconSize(QSize(10, 10))
        self._tab_widget.tabCloseRequested.connect(self._close_session)
        self._tab_widget.currentChanged.connect(self._on_tab_changed)
        self._tab_widget.tabBar().tabMoved.connect(self._on_tab_moved)
        # Right-click on a tab → context menu with "Duplikuj" / "Zamknij".
        tab_bar = self._tab_widget.tabBar()
        tab_bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tab_bar.customContextMenuRequested.connect(self._on_tab_context_menu)
        self._mode_stack.addWidget(self._tab_widget)

        self._grid_container = QWidget()
        self._grid_container.setStyleSheet("background:#0d1117;")
        self._grid_layout = QGridLayout(self._grid_container)
        self._grid_layout.setContentsMargins(4, 4, 4, 4)
        self._grid_layout.setSpacing(4)
        self._mode_stack.addWidget(self._grid_container)

        tlay.addWidget(self._mode_stack, 1)
        # The terminal and "Wsparcie Claude" share an inner splitter with a
        # handle of its own (_TermSupportHandle): the outer splitter's grey
        # handle was a white stripe beside the dark terminal in the light
        # themes (owner, 2026-10-21: "biała linia"), and one handle of a
        # QSplitter cannot be styled apart from the others.
        self._term_splitter = _TermSupportSplitter(self._terminal_top)
        self._term_splitter.setHandleWidth(6)
        self._term_splitter.setChildrenCollapsible(False)
        self._term_splitter.addWidget(term_area)
        # One "Wsparcie Claude" panel per tab: the stack shows the one of the
        # tab on screen and is hidden for a tab without it (2026-10-21).
        self._claude_stack = QStackedWidget()
        self._term_splitter.addWidget(self._claude_stack)
        self._term_splitter.setStretchFactor(0, 1)
        self._term_splitter.setStretchFactor(1, 0)
        self._claude_stack.hide()
        self._claude_width = 380
        splitter.addWidget(self._term_splitter)
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
        from ui.icons import pixmap as _icon_pixmap
        dots = QLabel()
        dots.setFixedSize(6, 18)                 # the handle is 6 px wide
        dots.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dots.setStyleSheet("background: transparent;")
        dots.setPixmap(_icon_pixmap("more", "#8b949e", 18, splitter))
        handle_layout.addWidget(dots, 0, Qt.AlignmentFlag.AlignHCenter)
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

        # ── Terminal search: lupa + find field ──────────────────────────────
        self._search_btn = QToolButton()
        set_icon(self._search_btn, "search", "#6e7681", active="#c9d1d9",
                 on="#58a6ff", size=14)
        self._search_btn.setCheckable(True)
        self._search_btn.setToolTip("Szukaj w terminalu (Ctrl+Shift+F)")
        self._search_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._search_btn.setFixedSize(22, 22)
        self._search_btn.setStyleSheet(
            "QToolButton { background: transparent; color: #6e7681; border: none;"
            " font-size: 13px; padding: 0; }"
            "QToolButton:hover { color: #c9d1d9; }"
            "QToolButton:checked { color: #58a6ff; }"
        )
        self._search_btn.clicked.connect(self._toggle_search)
        sbl.addWidget(self._search_btn)
        sbl.addSpacing(6)

        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Wyszukaj frazę...")
        self._search_edit.setFixedWidth(220)
        self._search_edit.setFixedHeight(20)
        self._search_edit.setStyleSheet(
            "QLineEdit { background: #0d1117; color: #c9d1d9; border: 1px solid #30363d;"
            " border-radius: 3px; padding: 0 6px; font-size: 11px; }"
            "QLineEdit:focus { border-color: #1f6feb; }"
        )
        self._search_edit.textChanged.connect(self._on_search_text_changed)
        self._search_edit.returnPressed.connect(self._on_search_next)
        self._search_edit.installEventFilter(self)
        self._search_edit.setVisible(False)
        sbl.addWidget(self._search_edit)
        sbl.addSpacing(4)

        self._search_prev_btn = QToolButton()
        self._search_prev_btn.setText("▲")
        self._search_prev_btn.setToolTip("Poprzedni wynik (Shift+Enter)")
        self._search_prev_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._search_prev_btn.setFixedSize(20, 20)
        self._search_prev_btn.setStyleSheet(
            "QToolButton { background: transparent; color: #6e7681; border: none;"
            " font-size: 10px; padding: 0; }"
            "QToolButton:hover { color: #c9d1d9; }"
        )
        self._search_prev_btn.clicked.connect(self._on_search_prev)
        self._search_prev_btn.setVisible(False)
        sbl.addWidget(self._search_prev_btn)
        sbl.addSpacing(6)

        self._search_count_lbl = QLabel("")
        self._search_count_lbl.setStyleSheet(
            "color: #6e7681; font-size: 10px; background: transparent;")
        self._search_count_lbl.setVisible(False)
        sbl.addWidget(self._search_count_lbl)
        sbl.addSpacing(12)

        # Short confirmations ("Zapisano na SFTP: …", "Pobrano 3 pliki") —
        # they used to vanish unseen; errors still get a dialog (E-15).
        self._notice_lbl = QLabel("")
        self._notice_lbl.setStyleSheet(
            "color: #3fb950; font-size: 11px; background: transparent;")
        self._notice_timer = QTimer(self)
        self._notice_timer.setSingleShot(True)
        self._notice_timer.timeout.connect(lambda: self._notice_lbl.setText(""))
        sbl.addWidget(self._notice_lbl)

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
        width = self._main_splitter.sizes()[0]
        self._left_collapsed = (width == 0)
        if width > 0:
            self._sftp_width = width     # kept across resizes (S-12)

    def _toggle_left_panel(self):
        sizes = self._main_splitter.sizes()
        total = sum(sizes)
        if sizes[0] > 0:
            self._left_collapsed = True
            self._main_splitter.setSizes([0, total])
        else:
            self._left_collapsed = False
            w = getattr(self, '_sftp_width', self._SFTP_PANEL_WIDTH)
            self._main_splitter.setSizes([w, total - w])

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if not self._left_collapsed:
            total = sum(self._main_splitter.sizes())
            if total > 0:
                w = min(getattr(self, '_sftp_width', self._SFTP_PANEL_WIDTH),
                        max(0, total - 300))
                self._main_splitter.setSizes([w, total - w])
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

    def _restore_maximized(self, scr) -> None:
        """Back from minimized, it was maximized before.

        Windows itself brings such a window back maximized.  setGeometry() on
        that window desynced Qt from the real client area (measured: Qt
        0…1032, real 23…1032 below the title bar), so the bottom of the
        content sat under the screen edge.  Only a window that came back
        un-maximized or on another monitor is moved — while normal."""
        if self.isMaximized() and (scr is None or self.screen() is scr):
            return
        if self.isMaximized():
            self.showNormal()
        if scr is not None:
            self.move(scr.availableGeometry().topLeft())
        self.showMaximized()

    def changeEvent(self, event):
        if event.type() == event.Type.ActivationChange and self.isActiveWindow():
            self._activated_seq = next(SshDialog._activations)
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
                    QTimer.singleShot(
                        0, lambda scr=target_screen: self._restore_maximized(scr))
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
                          is_first=True, port=port, machine=self._machine)

    def _add_session(self, label: str = '', ip: str = '',
                     user: str = '', password: str = '',
                     is_first: bool = False, port: int = 22, machine=None):
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
        session = _Session(pane, worker, label, machine)

        term.char_input.connect(
            lambda data, t=term: self._on_key(data, t))
        # Answers to terminal queries and mouse reports: this session only.
        term.term_reply.connect(lambda data, s=session: s.worker.send(data))
        term.search_requested.connect(self._open_search)
        term.paste_targets = lambda t=term: self._paste_target_count(t)
        term.paste_bracketed_everywhere = lambda t=term: self._paste_bracketed_everywhere(t)
        term.resize_pty.connect(
            lambda c, r, s=session: self._resize_pty_worker(s.worker, c, r))

        pane.retry_requested.connect(
            lambda s=session: self._on_retry_key(s))
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
                if s.reconnecting:
                    return   # auto-reconnect in progress — keep the tab alive
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
            self._sync_claude_panel()   # the index now names another session

    def _on_tab_context_menu(self, pos):
        """Right-click on a tab — show actions for that tab."""
        tab_bar = self._tab_widget.tabBar()
        idx = tab_bar.tabAt(pos)
        if idx < 0 or idx >= len(self._sessions):
            return
        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background:#1a1d28; color:#e1e4eb; border:1px solid #2a2d3a;"
            " border-radius:10px; padding:6px; }"
            "QMenu::item { padding:8px 16px; border-radius:6px; font-size:12px; }"
            "QMenu::item:selected { background:#4a5adf; color:#fff; }"
            "QMenu::separator { height:1px; background:#2a2d3a; margin:4px 10px; }"
        )
        act_dup = menu.addAction("Duplikuj")
        if self._multiexec:
            # Not available in multi-exec — greyed out, not silently ignored (E-25).
            act_dup.setEnabled(False)
            act_dup.setText("Duplikuj (niedostępne w trybie Multi-exec)")
        menu.addSeparator()
        act_close = menu.addAction("Zamknij")
        chosen = menu.exec(tab_bar.mapToGlobal(pos))
        if chosen is act_dup:
            self._duplicate_session(idx)
        elif chosen is act_close:
            self._close_session(idx)

    def _duplicate_session(self, idx: int):
        """Open a new tab using the same host/user/password/port as session `idx`.

        Creates a fully independent SSH connection; the original tab is
        untouched. Credentials are read from the source session's worker.
        """
        if idx < 0 or idx >= len(self._sessions):
            return
        if self._multiexec:
            return
        src = self._sessions[idx]
        w = src.worker
        host = getattr(w, '_host', '')
        user = getattr(w, '_user', '')
        pw = getattr(w, '_pw', '')
        port = getattr(w, '_port', 22)
        if not host:
            return
        # Match the original label and tag the copy so duplicated tabs
        # don't all share an identical name.
        base = src.label or host
        # Strip an existing "(kopia N)" suffix when re-duplicating a copy
        # so we don't accumulate "(kopia) (kopia) (kopia)" chains.
        import re as _re
        m = _re.match(r"^(.*?)\s*\(kopia(?:\s+(\d+))?\)\s*$", base)
        root = m.group(1) if m else base
        # Find an unused suffix
        existing = {s.label for s in self._sessions}
        candidate = f"{root} (kopia)"
        n = 2
        while candidate in existing:
            candidate = f"{root} (kopia {n})"
            n += 1
        self._add_session(label=candidate, ip=host, user=user,
                          password=pw, port=port)

    # Color used to mark inactive tabs that received new output.
    _UNREAD_TAB_COLOR = QColor('#1abc9c')   # morski (teal)

    @classmethod
    def _unread_icon(cls) -> QIcon:
        """Cached teal-dot icon shown next to a tab label when it has unread output.

        We use an icon (rather than setTabTextColor) because the tab stylesheet
        defines an explicit `color:` on QTabBar::tab, which overrides any
        per-tab text color set programmatically. Icons are not subject to that.
        """
        cached = getattr(cls, '_unread_icon_cached', None)
        if cached is not None:
            return cached
        # Small icon (10x10) with a 6x6 dot — keeps the tab from growing
        # noticeably wider when the dot appears.
        pix = QPixmap(10, 10)
        pix.fill(QColor(0, 0, 0, 0))
        p = QPainter(pix)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setBrush(QBrush(cls._UNREAD_TAB_COLOR))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawEllipse(2, 2, 6, 6)
        p.end()
        ico = QIcon(pix)
        cls._unread_icon_cached = ico
        return ico

    def _mark_session_activity(self, session: '_Session'):
        """Show a teal dot on the tab when output arrives on a non-current tab.

        Cleared when the user switches to that tab (see _on_tab_changed).
        """
        idx = self._tab_widget.indexOf(session.pane)
        if idx < 0:
            return
        if idx == self._tab_widget.currentIndex():
            return   # user is looking at this tab — nothing to flag
        if session.has_unread:
            return   # already flagged — avoid hammering on every chunk
        session.has_unread = True
        self._tab_widget.setTabIcon(idx, self._unread_icon())

    def _update_window_title(self) -> None:
        """"SSH · user@host · hospital" — windows told apart on the taskbar
        and in Alt+Tab (UX audit E-18)."""
        parts = ["SSH"]
        s = self._active_session()
        if s is not None:
            w = s.worker
            parts.append(f"{w._user}@{w._host}" if w._user else w._host)
        hospital = getattr(self._hospital, 'name', '') if self._hospital else ''
        if hospital:
            parts.append(hospital)
        self.setWindowTitle("  ·  ".join(parts) + "  —  HospitalHub")

    def _on_tab_changed(self, idx: int):
        """Update environment panel + SFTP panel when active terminal tab changes."""
        try:
            self._update_window_title()
        except (AttributeError, RuntimeError):
            pass
        # Clear unread highlight on the tab we're entering (regardless of mode).
        if 0 <= idx < len(self._sessions):
            s_new = self._sessions[idx]
            if s_new.has_unread:
                s_new.has_unread = False
                self._tab_widget.setTabIcon(idx, QIcon())
        self._sync_claude_panel()
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
        # Drain anything that buffered while this tab was hidden (throttled
        # feed in TerminalWidget) so the user sees current state immediately.
        s.pane.term.flush_now()
        self._env_panel.set_active(s.worker._host, s.machine)
        self._sftp_panel.switch_sftp(s.sftp, s.sftp_client, s.sftp_path,
                                     s.sftp_history)
        # Immediately show cached stats for this session (no wait for next poll)
        if s.last_stats:
            self._update_stats_display(*s.last_stats)
        else:
            self._clear_stats_display()
        # Pole wyszukiwania pokazuje zapytanie tej sesji (per-session state).
        self._sync_search_ui_to_active()

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
                          password=cred.password if cred else '',
                          machine=machine)
        self._left_tabs.setCurrentWidget(self._sftp_panel)

    def _open_machine_with_cred(self, machine, cred):
        """Connect to a machine with a specific credential (from context menu)."""
        label = machine.ip + (f"  ({machine.name})" if machine.name else "")
        label += f"  [{cred.login}]"
        self._add_session(label=label, ip=machine.ip,
                          user=cred.login, password=cred.password,
                          machine=machine)
        self._left_tabs.setCurrentWidget(self._sftp_panel)

    def _teardown_session(self, s: '_Session'):
        """Release all memory held by a session (worker + pyte scrollback).

        Used by both single-tab close and full-window close paths so that
        closing the SSH window actually frees scrollback (50k lines × n sessions).
        """
        # Stop any pending auto-reconnect loop so a queued timer can't revive
        # a tab the user just closed.
        s.reconnecting = False
        try:
            s.worker.output.disconnect()
            s.worker.error.disconnect()
            s.worker.connected.disconnect()
            s.worker.done.disconnect()
            s.worker.dropped.disconnect()
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
        try: term.term_reply.disconnect()
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

    # ── Wsparcie Claude: one conversation per tab (2026-10-21) ────────────
    #
    # Owner: "the support window appears in the terminal where I switched it
    # on" — with three tabs, support on the first, nothing on the second and
    # another conversation on the third.  Each tab keeps its own panel
    # (session.claude_panel); the stack beside the terminal shows the one of
    # the tab on screen.  An ended conversation stays for reading until the
    # button is clicked again on that tab, or the tab closes.

    def _terminal_top(self):
        """Where the terminal of the tab on screen starts, in the inner
        splitter's coordinates (None: no terminal)."""
        pane = self._tab_widget.currentWidget()
        splitter = getattr(self, '_term_splitter', None)
        if pane is None or splitter is None or not pane.isVisible():
            return None
        return pane.mapTo(splitter, QPoint(0, 0)).y()

    def _current_session(self):
        """The tab on screen, or None (no tab, or Multi-exec)."""
        idx = self._tab_widget.currentIndex()
        if self._multiexec or not 0 <= idx < len(self._sessions):
            return None
        return self._sessions[idx]

    @staticmethod
    def _claude_live(s) -> bool:
        p = getattr(s, 'claude_panel', None)
        return p is not None and not p.ended()

    def _tab_title(self, s) -> str:
        """A tab's text: "●" marks a running conversation."""
        return ("● " + s.label) if self._claude_live(s) else s.label

    def _refresh_tab_title(self, s) -> None:
        tab = self._tab_widget.indexOf(s.pane)
        if tab >= 0:
            self._tab_widget.setTabText(tab, self._tab_title(s))

    def _sync_claude_panel(self) -> None:
        """Show the panel of the tab on screen (or none) and set the button."""
        s = self._current_session()
        panel = s.claude_panel if s is not None else None
        stack = self._claude_stack
        if panel is not None:
            stack.setCurrentWidget(panel)
            if stack.isHidden():
                stack.show()
                total = sum(self._term_splitter.sizes())
                w = self._claude_width
                self._term_splitter.setSizes([max(400, total - w), w])
        elif not stack.isHidden():
            # The width the user dragged it to comes back with the next panel.
            width = self._term_splitter.sizes()[1]
            if width > 0:
                self._claude_width = max(260, width)
            stack.hide()
        self._btn_claude.blockSignals(True)
        self._btn_claude.setChecked(s is not None and self._claude_live(s))
        self._btn_claude.blockSignals(False)

    def _toggle_claude_support(self, on: bool) -> None:
        s = self._current_session()
        if not on:
            if s is not None and s.claude_panel is not None:
                s.claude_panel.end()
            self._sync_claude_panel()
            return
        if s is None:
            self._status("Wsparcie Claude dotyczy jednej karty — wyłącz Multi-exec."
                         if self._multiexec else
                         "Otwórz kartę terminala, której ma dotyczyć wsparcie.",
                         err=True)
            self._sync_claude_panel()
            return
        if self._claude_live(s):
            self._sync_claude_panel()
            return
        from ui.claude_panel import ClaudeSupportPanel
        # This tab's last conversation, kept for reading, goes now.
        self._drop_claude_panel(s)
        panel = ClaudeSupportPanel(_SupportTarget(self, s), self)
        panel.closed.connect(
            lambda s=s, p=panel: self._on_claude_support_closed(s, p))
        panel.dismissed.connect(
            lambda s=s, p=panel: self._drop_claude_panel(s)
            if s.claude_panel is p else None)
        s.claude_panel = panel
        self._claude_stack.addWidget(panel)
        panel.start()
        self._refresh_tab_title(s)
        self._sync_claude_panel()

    def _on_claude_support_closed(self, s, panel) -> None:
        # The panel stays in its tab, so the last answer can still be read.
        if s.claude_panel is panel:
            self._refresh_tab_title(s)
        self._sync_claude_panel()

    def _drop_claude_panel(self, s) -> None:
        """Remove a tab's panel for good (ending the conversation first)."""
        panel, s.claude_panel = s.claude_panel, None
        if panel is None:
            return
        panel.end()
        self._claude_stack.removeWidget(panel)
        panel.setParent(None)
        panel.deleteLater()
        self._sync_claude_panel()

    def _close_session(self, idx: int):
        """Stop and remove one terminal session tab."""
        if idx < 0 or idx >= len(self._sessions):
            return
        s = self._sessions.pop(idx)
        if s.claude_panel is not None:
            s.claude_panel.target_gone()
            self._drop_claude_panel(s)
        # Push edits still waiting in temp while this session's SFTP is open
        # (C1-04): the teardown below closes it, and a flush after that met a
        # closed transport — the last ~2 s of edits were lost.
        if getattr(s, 'sftp_client', None) is not None:
            if self._sftp_panel.bound_to(s.sftp_client):
                self._sftp_panel._flush_pending_edits(final=True)
            self._sftp_panel.forget_connection(s.sftp_client)
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
        # Każda sesja zachowuje własne wyszukiwanie; po relayoucie terminal
        # sam przeliczy pozycje trafień w _emit_resize (po debounce). UI
        # synchronizujemy do nowej aktywnej sesji.
        QTimer.singleShot(0, self._sync_search_ui_to_active)
        self._sync_claude_panel()    # Multi-exec: no panel; back: the tab's

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
            self._tab_widget.addTab(s.pane, self._tab_title(s))
            s.pane.show()

    # ── Input ─────────────────────────────────────────────────────────────

    def _on_key(self, data: bytes, source_term: TerminalWidget):
        # Ctrl+C fast-path: write straight to the channel from the UI
        # thread, bypassing the worker's send_q drain (which can sit
        # asleep for up to ~20 ms under heavy output). Paramiko Channel
        # is thread-safe. Then signal the worker via _direct_ctrl_c_pending
        # so it still triggers the post-Ctrl+C recv drain — without
        # re-sending '\x03' (which would otherwise duplicate the cancel
        # and produce a second '^C' echo).
        is_ctrl_c = b'\x03' in data
        if not self._multiexec:
            for s in self._sessions:
                if s.term is source_term:
                    self._send_one(s, data, is_ctrl_c)
                    return
        else:
            for s in self._sessions:
                if not s.excluded:
                    self._send_one(s, data, is_ctrl_c)

    def _send_one(self, s: '_Session', data: bytes, is_ctrl_c: bool):
        """Route a keystroke to one session via the fast direct path
        when possible, falling back to the worker's send_q on error."""
        if is_ctrl_c and s.worker._channel:
            try:
                s.worker._channel.send(data)
            except Exception:
                # Direct write failed — fall back to the queue.
                s.worker.send(data)
                return
            s.worker._direct_ctrl_c_pending = True
            s.worker._wake.set()
            return
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
        # Colorization already happens on the worker thread before emit,
        # so the UI thread only does the pyte feed + repaint here.
        worker.output.connect(lambda text, t=term: t.feed(text))
        worker.discontinuity.connect(lambda t=term: t.feed_discontinuity())
        # Hand the worker a back-reference to the terminal so it can read
        # pending_chunks() for back-pressure (see _SshWorker.run).
        worker._term_ref = term
        # Activity highlight: tint the tab text teal when output arrives on
        # an inactive tab so the user notices background sessions changing.
        if session is not None:
            worker.output.connect(
                lambda _text, s=session: self._mark_session_activity(s))
        worker.done.connect(lambda w=worker: self._auto_close_session(w))
        # Overwrite "Łączenie z ip…" line with success message
        worker.connected.connect(
            lambda t=term, i=ip, s=session: self._show_connected(t, i, s))
        if session is not None:
            # Re-send correct PTY size after channel is open — terminal_size()
            # called before layout returns 80x24, which may be dropped if the
            # channel wasn't ready yet.  This guarantees COLUMNS matches display.
            worker.connected.connect(
                lambda s=session: self._resize_pty_worker(
                    s.worker, *s.pane.term.terminal_size()))
            worker.connected.connect(lambda s=session: self._start_session_stats(s))
            worker.connected.connect(lambda s=session: self._connect_sftp_for_session(s))
            worker.connected.connect(lambda s=session: self._on_reconnect_success(s))
            worker.dropped.connect(lambda s=session: self._on_session_dropped(s))
        worker.error.connect(
            lambda e, p=pane, f=is_first, s=session: self._on_session_error(e, p, f, s))

    def _show_connected(self, term, ip: str, session) -> None:
        """Turn the "Łączenie…" line into "Połączono z …".  After a drop it
        is the attempt line under the banner, found by its text."""
        done = f"\x1b[32mPołączono z {ip}\x1b[0m"
        if session is not None and session.reconnecting and session.reconnect_line:
            if self._replace_status_row(session, done):
                return
        term.feed(f"\r\x1b[A\x1b[2K{done}\r\n")

    def _on_session_error(self, msg: str, pane: _TerminalPane, is_first: bool,
                          session: '_Session | None' = None):
        # If this fired while auto-reconnecting after a drop, don't show the
        # manual-retry prompt: an auth failure won't fix itself (stop and let
        # the user decide), but anything transient (host down, timeout) just
        # means "try again" — keep looping until the user closes the tab.
        if session is not None and session.reconnecting:
            low = msg.lower()
            if ('autentykacj' in low or 'hasł' in low
                    or ('host' in low and 'klucz' in low)):
                session.reconnecting = False
                self._reconnect_status(session, None)
                pane.show_error(msg, title="Logowanie odrzucone")
                return
            if session.reconnect_attempts >= _AUTO_RECONNECT_TRIES:
                # VPN gone or host down for good: stop knocking and let the
                # user choose — R starts another round, Esc closes the tab.
                session.reconnecting = False
                session.reconnect_exhausted = True
                self._reconnect_status(session, None)
                from ui.utils import plural
                tries = plural(_AUTO_RECONNECT_TRIES, 'próba', 'próby', 'prób')
                pane.show_error(
                    f"{tries} ponownego połączenia bez powodzenia.\n"
                    f"Ostatni błąd: {msg}",
                    title=f"Brak połączenia z {session.worker._host}",
                    hint="Sprawdź, czy VPN i sieć działają.")
                return
            self._reconnect_status(
                session, f"Próba {session.reconnect_attempts}/"
                f"{_AUTO_RECONNECT_TRIES} nieudana — ponawiam…")
            self._schedule_reconnect(session)
            return
        pane.show_error(msg, title=f"Nie udało się połączyć z "
                                   f"{session.worker._host if session else ''}".strip())
        # The terminal already shows it, with R / Esc: no second, modal copy
        # titled "SFTP" on top of that (UX audit V-12, E-15).
        if is_first:
            self._notice(f"Błąd połączenia: {msg}")

    # ── Auto-reconnect after an unexpected drop ───────────────────────────
    #
    # Goal: a connection that dies on its own (idle NAT/firewall timeout,
    # network blip, VPN flap) must NOT kill the tab or demand a manual retry.
    # The tab reconnects by itself — _AUTO_RECONNECT_TRIES times, then it
    # stops and offers R (another round) / Esc (close the tab).

    def _on_session_dropped(self, session: '_Session'):
        if session not in self._sessions or session.reconnecting:
            return
        last = getattr(session.term, 'last_command', b'')
        if last in (b'exit', b'logout', b'^d') or last.endswith((b' exit', b';exit')):
            # The user logged out; some servers (network devices) close
            # without an exit status — not a dropped link (review 71, R-07).
            return
        session.reconnecting = True
        session.reconnect_attempts = 0
        ts = datetime.now().strftime('%H:%M:%S')
        # Whatever the dead session left switched on (tmux's alternate
        # screen and scroll region, hidden cursor, app keypad, mouse
        # reporting) must not carry over into the new shell (T-20).
        session.term.feed_discontinuity()
        session.dropped_at = ts
        session.reconnect_line = False
        banner = _fit(f"─── Połączenie utracone [{ts}]", session.term.terminal_size()[0])
        session.term.feed(
            _TERM_SOFT_RESET + f"\r\n\x1b[33m{banner}\x1b[0m\r\n")
        self._schedule_reconnect(session)

    def _reconnect_status(self, session: '_Session', text) -> None:
        """The single line under the drop banner that says which attempt is
        running — rewritten in place, never a growing list; None removes it."""
        if text is None:
            self._replace_status_row(session, None)
            session.reconnect_line = False
            return
        line = f"\x1b[38;5;244m{_fit(text, session.term.terminal_size()[0])}\x1b[0m"
        if not (session.reconnect_line and self._replace_status_row(session, line)):
            session.term.feed(line + "\r\n")
        session.reconnect_line = True

    @staticmethod
    def _replace_status_row(session: '_Session', ansi_text) -> bool:
        """Rewrite (or, with None, blank) the attempt line and leave the
        cursor at the start of the row after it.  False: not on screen."""
        y = _find_row(session.term, lambda t: t.startswith(
            ("Ponowne łączenie z ", "Próba ")))
        if y is None:
            return False
        if ansi_text is None:
            session.term.feed(f"\x1b[{y + 1};1H\x1b[2K")
        else:
            session.term.feed(f"\x1b[{y + 1};1H\x1b[2K{ansi_text}\r\n")
        return True

    def _on_retry_key(self, session: '_Session'):
        """R on the error block.  After a dropped link gave up: another round
        of automatic attempts, keeping the scrollback; otherwise the plain
        manual retry (fresh screen)."""
        if session.reconnect_exhausted:
            session.reconnect_exhausted = False
            session.reconnecting = True
            session.reconnect_attempts = 0
            session.pane.clear_error()          # back to the drop banner
            session.reconnect_line = False
            self._do_auto_reconnect(session)
            return
        self._retry_session(session)

    def _schedule_reconnect(self, session: '_Session'):
        if session not in self._sessions or not session.reconnecting:
            return
        # Backoff so a server that's down for a while isn't hammered: 2 s, 4 s,
        # 6 s … capped at 15 s. Resets to 2 s on the next successful connect.
        delay = min(2000 + session.reconnect_attempts * 2000, 15000)
        QTimer.singleShot(delay, lambda: self._do_auto_reconnect(session))

    def _do_auto_reconnect(self, session: '_Session'):
        # Bail if the user closed the tab or it already came back while we waited.
        if session not in self._sessions or not session.reconnecting:
            return
        session.reconnect_attempts += 1
        self._retry_session(session, auto=True)

    def _on_reconnect_success(self, session: '_Session'):
        # The connected handler already prints the green "Połączono z {ip}";
        # we only need to leave the reconnect loop and reset the backoff.
        session.reconnect_exhausted = False
        if session.reconnecting:
            session.reconnecting = False
            session.reconnect_attempts = 0
            # The connected handler has just turned the attempt line into
            # "Połączono z …"; the banner above it now says when it came back.
            if session.reconnect_line and session.dropped_at:
                back = datetime.now().strftime('%H:%M:%S')
                banner = _fit(f"─── Przerwa w połączeniu {session.dropped_at}–{back}",
                              session.term.terminal_size()[0])
                lost = f"utracone [{session.dropped_at}]"
                y = _find_row(session.term, lambda t: lost in t)
                if y is not None:
                    # ESC 7 / ESC 8: the cursor stays where the shell needs it.
                    session.term.feed(
                        f"\x1b7\x1b[{y + 1};1H\x1b[2K\x1b[38;5;108m{banner}"
                        f"\x1b[0m\x1b8")
            session.reconnect_line = False

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

    def _retry_session(self, session: '_Session', auto: bool = False):
        """Stop the failed worker, create a fresh one, reconnect all signals.

        `auto=True` is the silent post-drop reconnect: it preserves the
        existing scrollback (the user's logs stay on screen) and the
        `reconnecting` flag, where the manual R-retry clears the screen and
        starts a clean session.
        """
        old_worker = session.worker
        ip, user, pw, port = old_worker._host, old_worker._user, old_worker._pw, old_worker._port

        old_worker.stop()
        try:
            old_worker.output.disconnect()
            old_worker.error.disconnect()
            old_worker.connected.disconnect()
            old_worker.done.disconnect()
            old_worker.dropped.disconnect()
            old_worker.discontinuity.disconnect()
        except Exception:
            pass
        old_worker.wait(500)

        if session.stats_worker:
            session.stats_worker.stop()
            session.stats_worker.wait(300)
            session.stats_worker = None

        term = session.term
        pane = session.pane
        if not auto:
            term.clear()           # manual retry → fresh screen
        pane.show_terminal()

        cols, rows = term.terminal_size()
        new_worker = _SshWorker(ip, user, pw, cols, rows, port=port)
        session.worker = new_worker   # resize_pty lambda reads session.worker → stays correct

        is_first = bool(self._sessions) and self._sessions[0] is session
        self._connect_worker(new_worker, term, pane, ip, user, is_first, session)
        # Always print the "Łączenie…" line: the connected handler overwrites it
        # in place (\r ↑ erase) with the green "Połączono z {ip}", so on an
        # auto-reconnect it must exist or that overwrite would eat a log line.
        if auto:
            self._reconnect_status(
                session, f"Ponowne łączenie z {ip} — próba "
                f"{session.reconnect_attempts}/{_AUTO_RECONNECT_TRIES}…")
        else:
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
        if session not in self._sessions:
            # The tab was closed while SFTP was connecting: nobody will ever
            # use or close this logged-in connection (2026-10-14, C1-08).
            _close_sftp_pair(sftp, client)
            return
        old, old_sftp = session.sftp_client, session.sftp
        if old is not None and old is not client:
            # The same session reconnected (same host, port, user): its
            # watched edits move to the new connection — an editor open
            # across the drop keeps uploading (UX audit S-01).  Keyed by the
            # new client, so a recycled id of the old one finds nothing
            # (review 66/S1).
            self._sftp_panel.rebind_connection(old, client)
            # A reconnect replaced it; close it rather than leave it logged
            # in with keepalives until the app exits (C1-08).
            _close_sftp_pair(old_sftp, old)
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
        # Stats workers can fire after the SSH panel has been torn down
        # (e.g. user closed the window before the QThread drained); the
        # underlying QTabWidget C++ object is gone but the Python proxy
        # is still alive in the lambda holding `self`. Guard so we don't
        # crash with "wrapped C/C++ object … has been deleted".
        try:
            idx = self._tab_widget.currentIndex()
        except RuntimeError:
            return None
        if 0 <= idx < len(self._sessions):
            return self._sessions[idx]
        return None

    # ── Terminal search ───────────────────────────────────────────────────

    def _open_search(self):
        """Ctrl+Shift+F in a terminal (E-03)."""
        if not self._search_btn.isChecked():
            self._search_btn.click()
        else:
            self._search_edit.setFocus()
            self._search_edit.selectAll()

    def _paste_bracketed_everywhere(self, term) -> bool:
        if not self._multiexec:
            return True
        for s in self._sessions:
            if s.excluded:
                continue
            scr = s.term._screen
            if scr is None or (2004 << 5) not in scr.mode:
                return False
        return True

    def _paste_target_count(self, term) -> int:
        """Sessions a paste from `term` reaches: all non-excluded ones in
        multi-exec, otherwise one."""
        if not self._multiexec:
            return 1
        return sum(1 for s in self._sessions if not s.excluded)

    def _toggle_search(self):
        show = self._search_btn.isChecked()
        self._search_edit.setVisible(show)
        self._search_prev_btn.setVisible(show)
        self._search_count_lbl.setVisible(show)
        if show:
            # Pokaż w polu to, czego szuka aktualna sesja (każda trzyma własne zapytanie).
            self._sync_search_ui_to_active()
            self._search_edit.setFocus()
            self._search_edit.selectAll()
        else:
            # Zamknięcie paska czyści wyszukiwanie tylko tam, gdzie jesteśmy
            # — pozostałe sesje zachowują swoje podświetlenia.
            self._apply_search_to_active('')
            self._search_count_lbl.setText('')

    def _sync_search_ui_to_active(self):
        """Dostosuj zawartość pola i licznik do stanu aktywnej sesji bez
        ponownego uruchamiania wyszukiwania."""
        if not self._search_btn.isChecked():
            return
        active = self._active_session()
        term = active.term._search_term if active else ''
        self._search_edit.blockSignals(True)
        self._search_edit.setText(term)
        self._search_edit.blockSignals(False)
        self._update_search_count()

    def _apply_search_to_active(self, term: str):
        active = self._active_session()
        if active is None:
            self._search_count_lbl.setText('')
            return
        if term:
            active.term.set_search_term(term)
        else:
            active.term.clear_search()
        self._update_search_count()

    def _on_search_text_changed(self, text: str):
        self._apply_search_to_active(text)

    def _on_search_next(self):
        active = self._active_session()
        if active is None:
            return
        active.term.search_next()
        self._update_search_count()

    def _on_search_prev(self):
        active = self._active_session()
        if active is None:
            return
        active.term.search_prev()
        self._update_search_count()

    def _update_search_count(self):
        active = self._active_session()
        if active is None:
            self._search_count_lbl.setText('')
            return
        cur, total = active.term.search_status()
        if total == 0:
            txt = 'brak' if self._search_edit.text() else ''
            self._search_count_lbl.setText(txt)
        else:
            self._search_count_lbl.setText(f'{cur}/{total}')

    def eventFilter(self, obj, event):
        if obj is self._search_edit and event.type() == QEvent.Type.KeyPress:
            if event.key() == Qt.Key.Key_Escape:
                self._search_btn.setChecked(False)
                self._toggle_search()
                return True
            if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) \
                    and event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                self._on_search_prev()
                return True
        return super().eventFilter(obj, event)

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
        # Critical: SFTP errors used to vanish here (no-op). A read-only
        # remote file or permission-denied upload would silently fail, and
        # the user kept editing convinced everything was saved — until the
        # next session re-downloaded the original. Surface real failures
        # as a modal so the user can react; ignore success notifications.
        from PyQt6 import sip
        if sip.isdeleted(self):
            return              # a late report into a closed window (S-02)
        if not text:
            return
        if err:
            QMessageBox.warning(self, "Pliki (SFTP)", text)
        else:
            self._notice(text)

    def _notice(self, text: str) -> None:
        """A short non-modal message in the status bar, gone after 6 s."""
        first = text.splitlines()[0] if text else ""
        self._notice_lbl.setText(first)
        self._notice_lbl.setToolTip(text)
        self._notice_timer.start(6000)

    def owner_window(self):
        ref = getattr(self, '_owner_ref', None)
        return ref() if ref is not None else None

    @classmethod
    def windows_of(cls, owner) -> list:
        return [d for d in list(cls._alive) if d.owner_window() is owner]

    @classmethod
    def window_for(cls, owner, hospital) -> 'SshDialog | None':
        """The open SSH window of this vault window and hospital — the one
        used last when there are several.  Connecting another machine of
        the same hospital adds a tab there instead of a new window."""
        wins = [d for d in cls.windows_of(owner)
                if d._hospital is hospital and d.isVisible()]
        return max(wins, key=lambda d: d._activated_seq, default=None)

    def open_machine(self, machine) -> None:
        """Connect `machine` in a new tab of this window and bring it up
        (restored if minimized).  The first visible account is used, as for
        a new window."""
        self._open_extra_machine(machine)
        if self.isMinimized():
            if self._was_maximized:
                self.showMaximized()
            else:
                self.showNormal()
        self.raise_()
        self.activateWindow()

    def set_admin_mode(self, unlocked: bool) -> None:
        """Follow the vault's admin lock (UX audit S-03): admin-only machines
        and credentials leave the Environment panel and new connections.
        Sessions already open stay — closing a working shell is the user's
        call, not a side effect of the lock."""
        self._admin_unlocked = unlocked
        if not unlocked and self._cred is not None and self._cred.admin_only:
            vis = [c for c in self._machine.credentials if not c.admin_only]
            self._cred = vis[0] if vis else None
        self._env_panel.set_admin_mode(unlocked)

    def close_for_vault(self) -> bool:
        """The vault this window came from is closing.  A running transfer
        still gets its question; otherwise the window simply goes.  False
        when the user kept the window — the vault must then stay open too,
        or the window would outlive it with its passwords (review 71, R-03)."""
        if self._sftp_panel.transfer_running():
            self.close()
            return not self.isVisible()
        self.close_without_asking()
        return True

    def close_without_asking(self) -> None:
        """Close for the application (quit, vault closed): no questions."""
        self._close_confirmed = True
        self.close()

    def _confirm_close(self) -> bool:
        """Ask before ending a transfer or several live sessions (UX audit
        S-02, E-02).  One open session closes without a question."""
        if getattr(self, '_close_confirmed', False):
            return True
        transfer = self._sftp_panel.transfer_running()
        live = sum(1 for s in self._sessions
                   if getattr(s.worker, '_running', False))
        if not transfer and live < 2:
            return True
        if transfer:
            uploading = (bool(self._sftp_panel._upload_active) or getattr(
                self._sftp_panel, '_transfer_current_mode', 'put') == 'put')
            text = ("Trwa przesyłanie pliku.\n\nZamknięcie okna przerwie "
                    "transfer — " + (
                        "plik na serwerze może zostać niepełny."
                        if uploading else
                        "pobierany plik nie zostanie zapisany w całości."))
        else:
            text = (f"Otwarte sesje SSH: {live}.\n\nZamknięcie okna "
                    "rozłączy wszystkie.")
        return self._ask_close(text)

    def _ask_close(self, text: str) -> bool:
        """The question itself; "Nie zamykaj" is the default and Escape."""
        box = QMessageBox(QMessageBox.Icon.Warning, "Zamknąć okno SSH?",
                          text, parent=self)
        close_btn = box.addButton("Zamknij okno",
                                  QMessageBox.ButtonRole.DestructiveRole)
        keep_btn = box.addButton("Nie zamykaj",
                                 QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(keep_btn)
        box.setEscapeButton(keep_btn)
        box.exec()
        return box.clickedButton() is close_btn

    def closeEvent(self, event):
        if not self._confirm_close():
            event.ignore()
            return
        for s in self._sessions:
            if s.claude_panel is not None:
                s.claude_panel.end()
        # The SFTP panel first: its last flush needs the connections the loop
        # below closes (C1-04).
        self._sftp_panel.stop()
        for s in self._sessions:
            s.worker.stop()
        # One shared wait for every thread, the rest retired (S-02, S-08).
        _unplug_and_retire(
            [s.worker for s in self._sessions]
            + [s.stats_worker for s in self._sessions]
            + list(self._workers))
        for s in self._sessions:
            self._teardown_session(s)
        self._sessions.clear()
        self._workers = []
        # Clean up this window's temp SFTP files — and only this window's:
        # another SSH window may still be editing its own (C1-01).  The
        # process directory goes when the application exits (main.py).
        import shutil
        tmp_dir = self._sftp_panel.temp_dir()
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
