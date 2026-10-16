"""2026-10-16: the terminal speed-ups keep what is shown — pyte's event
wrapping still runs (now once per call, not per attribute read) and lines
that scroll into history keep their text, colours and attributes."""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

sp = pytest.importorskip("ui.ssh_panel")


def _screen():
    scr = sp._TermScreen(40, 3, history=100)
    stream = sp._TermStream(scr)
    stream.use_utf8 = False
    return scr, stream


def test_attribute_reads_no_longer_go_through_pyte_wrapper():
    assert sp._TermScreen.__getattribute__ is object.__getattribute__


def test_events_still_run_before_and_after_hooks(monkeypatch):
    scr, stream = _screen()
    seen = []
    monkeypatch.setattr(scr, "before_event", lambda e: seen.append(("b", e)))
    monkeypatch.setattr(scr, "after_event", lambda e: seen.append(("a", e)))
    stream.feed("x\r\n")
    assert ("b", "draw") in seen and ("a", "draw") in seen
    assert ("b", "linefeed") in seen


def test_hidden_cursor_mode_still_hides_the_cursor():
    scr, stream = _screen()
    stream.feed("\x1b[?25l")
    assert scr.cursor.hidden
    stream.feed("\x1b[?25h")
    assert not scr.cursor.hidden


def test_lines_in_history_keep_text_colour_and_attributes():
    scr, stream = _screen()
    stream.feed("plain line\r\n\x1b[31mred\x1b[0m \x1b[1;3;4mbold it ul\x1b[0m\r\n"
                "a\r\nb\r\nc\r\n")
    top = list(scr.history.top)
    assert top[0].text == "plain line" and top[0].runs == b""
    row = top[1]
    assert row.text == "red bold it ul"
    assert row[0].fg == "red" and row[3].fg == "default"
    c = row[4]
    assert c.bold and c.italic and c.underscore and c.fg == "default"
