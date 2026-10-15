"""Seam for talking to a monitored client process (CLI 2FA).

The EMS/ZTNA edition can be driven from the command line, and when it is
started with pipes its stdout asks for the second factor in plain text while
its stdin accepts the answer.  That is a second way a token leaves this
application, so it gets the same treatment as the keyboard and the window
messages: one small, injectable object, and nothing else in ``vpn/`` may reach
for a pipe.

What this seam deliberately does **not** do is decide anything.  It reads a
line and writes a line; whether a line is a 2FA challenge, and whether the
process may be given a token at all, is decided in
:mod:`vpn.providers.forticlient_2fa`.

Note on the output: a challenge line is read to be *classified*, never to be
stored.  Callers get a yes/no answer and an index, and the line itself is
dropped — the client echoes what it is doing, and on some editions that
includes the credentials it was started with.
"""

from __future__ import annotations

__all__ = ["ProcessChannel", "PopenProcessChannel"]


class ProcessChannel:
    """A line-oriented pipe to a running client process."""

    @property
    def pid(self) -> int | None:
        """The process id, so the caller can verify *who* is being answered."""
        raise NotImplementedError

    def read_line(self) -> str | None:
        """The next stdout line, or None at end of stream."""
        raise NotImplementedError

    def write_line(self, text: str) -> None:
        """Write one line to stdin.  Raises when the pipe is gone."""
        raise NotImplementedError


class PopenProcessChannel(ProcessChannel):
    """Wraps the ``Popen`` that ``connect_monitored`` hands to the UI today.

    Byte handling mirrors the legacy monitor exactly: read bytes and decode as
    UTF-8 with ``errors="replace"``, write the token plus ``"\\n"`` encoded as
    UTF-8, then flush.  Unlike the legacy it does *not* swallow write errors —
    the caller turns them into a result, because "the token was not delivered"
    is something a connect has to know.
    """

    def __init__(self, process):
        self._process = process

    @property
    def pid(self) -> int | None:
        return getattr(self._process, "pid", None)

    def read_line(self) -> str | None:
        stream = getattr(self._process, "stdout", None)
        if stream is None:
            return None
        raw = stream.readline()
        if not raw:
            return None
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return raw

    def write_line(self, text: str) -> None:
        stream = self._process.stdin
        stream.write((text + "\n").encode("utf-8"))
        stream.flush()
