"""Letting a running QThread outlive the window that started it — safely.

2026-10-14 (audit D-01/D-02).  A panel's worker threads were children of the
panel and stopped with ``quit()`` + ``wait(500)``.  Workers that block — the
2FA window waiter (up to 20 s), the VPN monitor reading a client's stdout,
the status poll — have no event loop, so ``quit()`` does nothing and the wait
times out.  Closing one vault window while others stayed open then deleted the
panel, and with it a *running* QThread: Qt aborts the whole process
("QThread: Destroyed while thread is still running").  ``terminate()``, used
to replace a monitor, kills a Python thread mid-bytecode and can leave the GIL
or a lock held.

:func:`retire_thread` instead detaches the thread from its Qt parent, cuts the
signals that lead into the window being discarded, and keeps a reference here
until the thread finishes on its own.
"""

from __future__ import annotations

__all__ = ["retire_thread", "wait_for_retired", "RETIRED"]

#: Threads kept alive until their ``finished``.
RETIRED: set = set()


def wait_for_retired(total_ms: int = 3000) -> None:
    """At exit: give retired threads up to `total_ms` in all to finish, so
    none is still running while the interpreter tears its objects down
    (review 69/N4).  Never raises."""
    import time
    deadline = time.monotonic() + total_ms / 1000.0
    for thread in list(RETIRED):
        left = int((deadline - time.monotonic()) * 1000)
        if left <= 0:
            break
        try:
            thread.wait(left)
        except Exception:
            pass


def retire_thread(thread, *, disconnect=()) -> bool:
    """Keep `thread` alive, parentless and unplugged, until it finishes.

    `disconnect` lists the signals of the thread that reach the discarded
    window.  Returns True when the thread was still running (and is now
    held), False when there was nothing to do.  Never raises.
    """
    if thread is None:
        return False
    try:
        running = thread.isRunning()
    except Exception:              # the C++ object is already gone
        return False
    if not running:
        return False
    for signal in disconnect:
        try:
            signal.disconnect()
        except Exception:
            pass
    try:
        thread.setParent(None)     # its parent's deletion must not take it
    except Exception:
        pass
    RETIRED.add(thread)
    try:
        thread.finished.connect(lambda t=thread: RETIRED.discard(t))
    except Exception:
        pass
    return True
