"""TerminalWidget against what tmux, ncurses, vim and less send (UX audit
2026-10-16, A1 findings T-01…T-24).  Offscreen, no network."""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

ESC = "\x1b"


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def sp(app):
    from ui import ssh_panel
    return ssh_panel


@pytest.fixture
def term(sp):
    t = sp.TerminalWidget()
    t._screen.resize(24, 80)
    t._cols, t._rows = 80, 24
    t.sent, t.replies = [], []
    t.char_input.connect(t.sent.append)
    t.term_reply.connect(t.replies.append)
    return t


def feed(t, text):
    t.feed(text)
    t.flush_now()
    while t._pending_data:
        t._flush_pending()


def rows(t):
    return [line.rstrip() for line in t._screen.display]


def history(t):
    return [r.text for r in t._screen.history.top]


# ── T-01 scroll up/down inside a region (tmux 3.2+ pane scroll) ──────────

def test_su_scrolls_the_region_and_keeps_the_status_line(term):
    feed(term, f"{ESC}[?1049h")
    for i in range(23):
        feed(term, f"{ESC}[{i + 1};1Hline{i:02d}")
    feed(term, f"{ESC}[24;1H[0] 0:bash*")
    feed(term, f"{ESC}[1;23r{ESC}[3S{ESC}[r"
               f"{ESC}[21;1Hnew-A{ESC}[22;1Hnew-B{ESC}[23;1Hnew-C")
    r = rows(term)
    assert r[0] == "line03" and r[19] == "line22"
    assert r[20:23] == ["new-A", "new-B", "new-C"] and r[23] == "[0] 0:bash*"


def test_sd_scrolls_the_region_down(term):
    feed(term, "row0\r\nrow1\r\nrow2")
    feed(term, f"{ESC}[1;5r{ESC}[2T{ESC}[r")
    assert rows(term)[:5] == ["", "", "row0", "row1", "row2"]


# ── T-04/T-05 alternate screen ──────────────────────────────────────────

def test_leaving_less_brings_back_the_shell_screen_and_cursor(term):
    feed(term, "$ ls\r\nplik1 plik2\r\n$ less x\r\n")
    feed(term, f"{ESC}[?1049h{ESC}[H{ESC}[2J")
    for i in range(23):
        feed(term, f"LESS {i}\r\n")
    feed(term, f"{ESC}[?1049l$ ")
    assert rows(term)[:4] == ["$ ls", "plik1 plik2", "$ less x", "$"]
    assert history(term) == [], "klatka less nie trafia do historii"


def test_tmux_pane_scrolling_never_reaches_the_scrollback(term):
    feed(term, f"{ESC}[?1049h{ESC}[1;23r{ESC}[23;1H")
    for i in range(60):
        feed(term, f"pane-line-{i}\n")
    assert history(term) == []


def test_resizing_inside_an_app_restores_a_reflowed_shell(term):
    feed(term, "x" * 100 + "\r\n$ vim\r\n")
    feed(term, f"{ESC}[?1049h")
    term._screen.resize(20, 60)
    feed(term, f"{ESC}[?1049l")
    assert term._screen.columns == 60 and term._screen.lines == 20
    assert "x" * 60 in rows(term)[0]


def test_the_main_screen_still_scrolls_into_history(term):
    for i in range(30):
        feed(term, f"log {i}\r\n")
    assert history(term)[:3] == ["log 0", "log 1", "log 2"]


# ── T-07 BCE, T-08 ACS, T-10 REP, T-11 SCOSC, T-15 zero width, T-22 ──────

def test_erase_paints_the_background_on_every_cell(term):
    feed(term, f"{ESC}[44m{ESC}[2J")
    assert term._screen.buffer[10][10].bg == "blue"


def test_line_drawing_charset(term):
    feed(term, f"{ESC}(0lqqk{ESC}(B zażółć")
    assert rows(term)[0] == "┌──┐ zażółć"


def test_rep_repeats_the_last_character(term):
    feed(term, f"-{ESC}[9b|")
    assert rows(term)[0] == "-" * 10 + "|"


def test_csi_s_and_u_save_and_restore_the_cursor(term):
    feed(term, f"{ESC}[5;10H{ESC}[sXX{ESC}[1;1HYY{ESC}[uZZ")
    assert rows(term)[4][9:11] == "ZZ" and rows(term)[0] == "YY"


def test_variation_selector_does_not_eat_the_rest_of_the_line(term):
    feed(term, "✔️ Container started|end")
    assert rows(term)[0] == "✔ Container started|end"


def test_colon_sgr_is_a_colour_not_text(term):
    feed(term, f"{ESC}[38:2::255:0:0mRED{ESC}[4:3mU{ESC}[0m end")
    assert rows(term)[0] == "REDU end"
    assert term._screen.buffer[0][0].fg == "ff0000"


def test_vim_modify_other_keys_is_not_an_underline(term):
    feed(term, f"{ESC}[>4;2mtext")
    assert term._screen.buffer[0][0].underscore is False


# ── T-09 replies go to this session only ──────────────────────────────────

def test_queries_are_answered_through_term_reply(term):
    feed(term, f"{ESC}[c{ESC}[>c{ESC}[5n{ESC}[3;4H{ESC}[6n")
    assert term.replies == [b"\x1b[?6c", b"\x1b[>0;10;1c", b"\x1b[0n", b"\x1b[3;4R"]
    assert term.sent == [], "odpowiedź nie idzie jak klawisze (multi-exec)"


# ── T-12 hidden cursor, T-19 resize debounce ─────────────────────────────

def test_a_hidden_cursor_is_not_painted(term):
    from PyQt6.QtGui import QColor
    term.resize(660, 440)
    term.setFocus()
    feed(term, f"{ESC}[?25l{ESC}[5;10H")
    img = term.grab().toImage()
    x, y = int(9 * term._cw + 2), int(4 * term._ch + 4)
    assert QColor(img.pixel(x, y)).name() != "#c9d1d9"


def test_a_resize_and_back_within_the_debounce_keeps_the_size(term):
    from PyQt6.QtWidgets import QApplication
    size80 = (int(80 * term._cw) + 1, int(24 * term._ch) + 1)
    term.resize(*size80)
    term.show()
    QApplication.processEvents()
    term._emit_resize()
    assert (term._cols, term._rows) == (80, 24)
    term.resize(int(90 * term._cw) + 1, size80[1])      # 90 columns …
    QApplication.processEvents()
    term.resize(*size80)                                 # … and back
    QApplication.processEvents()
    term._emit_resize()                                  # the timer fires
    assert (term._cols, term._rows) == (80, 24)
    assert term._screen.columns == 80


def test_the_pty_gets_the_visible_width_even_below_80_columns(term):
    term.resize(int(60 * term._cw) + 1, int(20 * term._ch) + 1)
    assert term.terminal_size() == (60, 20)


# ── T-16/T-17 keys ───────────────────────────────────────────────────────

@pytest.mark.parametrize("key, text, mods, want", [
    ("Key_Left", "", ("Control",), b"\x1b[1;5D"),
    ("Key_Up", "", ("Shift",), b"\x1b[1;2A"),
    ("Key_Backtab", "", ("Shift",), b"\x1b[Z"),
    ("Key_B", "b", ("Alt",), b"\x1bb"),
    ("Key_Delete", "", ("Control",), b"\x1b[3;5~"),
    ("Key_Insert", "", (), b"\x1b[2~"),
    ("Key_F5", "", ("Shift",), b"\x1b[15;2~"),
    ("Key_Space", " ", ("Control",), b"\x00"),
    ("Key_A", "ą", ("Control", "Alt"), "ą".encode()),   # AltGr+a, Polish layout
    ("Key_C", "\x03", ("Control",), b"\x03"),
])
def test_keys(term, key, text, mods, want):
    from PyQt6.QtCore import Qt, QEvent
    from PyQt6.QtGui import QKeyEvent
    m = Qt.KeyboardModifier.NoModifier
    for name in mods:
        m |= getattr(Qt.KeyboardModifier, name + "Modifier")
    term.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, getattr(Qt.Key, key), m, text))
    assert term.sent[-1] == want


def test_home_and_end_follow_application_cursor_mode(term):
    from PyQt6.QtCore import Qt, QEvent
    from PyQt6.QtGui import QKeyEvent
    feed(term, f"{ESC}[?1h")
    for key, want in ((Qt.Key.Key_Home, b"\x1bOH"), (Qt.Key.Key_End, b"\x1bOF")):
        term.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, key,
                                     Qt.KeyboardModifier.NoModifier, ""))
        assert term.sent[-1] == want


# ── T-18 paste ───────────────────────────────────────────────────────────

def test_bracketed_paste_wraps_and_runs_nothing(term, monkeypatch):
    asked = []
    monkeypatch.setattr(term, "_confirm_paste", lambda *a: asked.append(a) or False)
    feed(term, f"{ESC}[?2004h")
    term.paste("echo 1\necho 2\n")
    assert term.sent == [b"\x1b[200~echo 1\recho 2\r\x1b[201~"] and asked == []


def test_several_lines_without_bracketed_paste_ask_first(term, monkeypatch):
    monkeypatch.setattr(term, "_confirm_paste", lambda *a: False)
    term.paste("uptime\nrm -rf /tmp/x\n")
    assert term.sent == []
    monkeypatch.setattr(term, "_confirm_paste", lambda *a: True)
    term.paste("uptime\nrm -rf /tmp/x\n")
    assert term.sent == [b"uptime\rrm -rf /tmp/x\r"]


def test_one_line_pastes_without_a_question(term, monkeypatch):
    monkeypatch.setattr(term, "_confirm_paste",
                        lambda *a: pytest.fail("pytanie przy jednej linii"))
    term.paste("ls -la")
    assert term.sent == [b"ls -la"]


def test_multi_exec_paste_asks_even_for_one_line(term, monkeypatch):
    asked = []
    monkeypatch.setattr(term, "_confirm_paste",
                        lambda text, lines, targets, br: asked.append(targets) or False)
    term.paste_targets = lambda: 4
    term.paste("reboot")
    assert asked == [4] and term.sent == []


def test_a_paste_cannot_close_the_bracket_itself(term, monkeypatch):
    feed(term, f"{ESC}[?2004h")
    term.paste(f"a{ESC}[201~rm -rf /\n")
    assert term.sent == [b"\x1b[200~arm -rf /\r\x1b[201~"]


# ── T-24 mouse reporting ─────────────────────────────────────────────────

def test_mouse_reports_only_when_the_program_asked(term):
    from PyQt6.QtCore import Qt, QPointF, QEvent
    from PyQt6.QtGui import QMouseEvent
    pos = QPointF(2 * term._cw + 1, 3 * term._ch + 1)

    def click():
        for t in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonRelease):
            ev = QMouseEvent(t, pos, pos, Qt.MouseButton.LeftButton,
                             Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
            (term.mousePressEvent if t == QEvent.Type.MouseButtonPress
             else term.mouseReleaseEvent)(ev)
    click()
    assert term.replies == []
    feed(term, f"{ESC}[?1000h{ESC}[?1006h")
    click()
    assert term.replies == [b"\x1b[<0;3;4M", b"\x1b[<0;3;4m"]


# ── worker: T-02/T-03/T-06 ───────────────────────────────────────────────

class _Chan:
    def __init__(self, parts):
        self.parts = list(parts)

    def recv_ready(self):
        return bool(self.parts)

    def recv(self, n):
        return self.parts.pop(0)


def test_a_character_cut_between_reads_survives(sp):
    w = sp._SshWorker("h", "u", "p")
    out = []
    w.output.connect(out.append)
    data = "ramka │ łódź".encode()
    cut = data.index("│".encode()) + 1
    w._channel = _Chan([data[:cut]])
    w._drain_and_emit()
    w._channel = _Chan([data[cut:]])
    w._drain_and_emit()
    assert "�" not in "".join(out) and "│" in "".join(out)


def test_no_log_highlighting_inside_a_full_screen_app(sp, term):
    w = sp._SshWorker("h", "u", "p")
    w._term_ref = term
    line = "listen no\r\n"
    assert w._highlight(line) != line, "zwykły ekran: podświetlanie zostaje"
    feed(term, f"{ESC}[?1049h")
    assert w._highlight(line) == line
    assert w._highlight(f"{ESC}[?1049h{line}") == f"{ESC}[?1049h{line}"


def test_highlighting_resets_after_whole_lines_only(sp):
    out = sp._colorize_log("typed")
    assert not out.endswith("\x1b[0m")
    assert sp._colorize_log("done\nnext").startswith("done\x1b[0m")
    redraw = f"{ESC}[24;1H{ESC}[30;42m1:error-log*"
    assert sp._colorize_log(redraw) == redraw


def test_ctrl_c_keeps_the_output_of_a_full_screen_app(sp, term):
    """T-02: the post-Ctrl+C drop happens on the shell screen only."""
    w = sp._SshWorker("h", "u", "p")
    w._term_ref = term
    dropped = []
    w.discontinuity.connect(lambda: dropped.append(True))
    feed(term, f"{ESC}[?1049h")
    w._channel = _Chan([b"frame-1", b"frame-2"])
    w._quiet_after_ctrl_c()
    assert w._channel.parts == [b"frame-1", b"frame-2"] and dropped == []
    feed(term, f"{ESC}[?1049l")
    w._quiet_after_ctrl_c()
    assert w._channel.parts == [] and dropped == [True]


def test_a_discontinuity_restarts_the_parser(term):
    feed(term, f"{ESC}[3")              # a CSI cut in the middle
    term.feed_discontinuity()
    feed(term, "ok")
    assert rows(term)[0] == "ok"


# ── T-20 after a drop the shell starts clean ────────────────────────────

def test_the_soft_reset_leaves_what_tmux_switched_on(sp, term):
    feed(term, "$ tmux\r\n")
    feed(term, f"{ESC}[?1049h{ESC}[?1h{ESC}[?25l{ESC}[1;23r{ESC}[?1000h")
    feed(term, sp._TERM_SOFT_RESET)
    s = term._screen
    assert not s._in_alt_screen() and s.margins is None
    assert 32 not in s.mode and not s.cursor.hidden and (1000 << 5) not in s.mode
    assert rows(term)[0] == "$ tmux"
