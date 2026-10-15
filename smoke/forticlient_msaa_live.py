"""Gate G1 — what does MSAA say about the ``VPN Name`` combo, live?  Read-only.

Stage 63 decides every key of the profile step from three ``accState`` bits of
the FortiClient ``VPN Name`` combo — FOCUSED (Space only then), EXPANDED (the
name and the committing Enter only then), COLLAPSED (a confirmation only then)
— and from ``accValue`` read back after the commit.  Stage 61 measured that
MSAA answers on FortiClient VPN 7.4.3, but only in one state: closed, not
focused.  Whether Electron reports the other states is the open question, and
until it is answered the profile step can only refuse.

This watcher answers it.  It finds the verified FortiClient window the same
way the fill does, and reads the combo with the production reader
(:func:`forticlient_profile.read_profile_control` over
:class:`Win32MsaaSystem`) a few times a second, printing a line whenever the
reading changes.  **The person at the keyboard** does the interacting —
clicks the list open, moves the highlight with the arrow keys, closes it with
Escape — and the transcript shows what each state looks like to MSAA.

What it never does
------------------
No key, no click, no focus change, no window activation, no clipboard, no
credentials, no ``accDoDefaultAction``/``accSelect``, no connect.  The only
calls into the client are ``AccessibleObjectFromWindow`` and the MSAA property
reads of :class:`Win32MsaaSystem` — the same reads Stages 61 and 62 made.

The displayed value names a hospital, so it is not printed: the transcript
says which configured tunnel it matches (by position in the registry list) or
why it matches none.

Usage::

    py -3.13 -m smoke.forticlient_msaa_live watch [--seconds 60] [--interval 0.25]
    py -3.13 -m smoke.forticlient_msaa_live once
"""

from __future__ import annotations

import argparse
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import vpn                                                       # noqa: E402
from vpn.providers import forticlient_profile as fp              # noqa: E402
from vpn.providers.msaa_system import (                          # noqa: E402
    STATE_SYSTEM_COLLAPSED, STATE_SYSTEM_EXPANDED, STATE_SYSTEM_FOCUSED,
    Win32MsaaSystem,
)

#: Other accState bits worth naming in the transcript.
_NAMED_BITS = (
    (STATE_SYSTEM_FOCUSED, "FOCUSED"),
    (STATE_SYSTEM_EXPANDED, "EXPANDED"),
    (STATE_SYSTEM_COLLAPSED, "COLLAPSED"),
    (0x1, "UNAVAILABLE"),
    (0x2, "SELECTED"),
    (0x8000, "INVISIBLE"),
    (0x100000, "FOCUSABLE"),
    (0x200000, "SELECTABLE"),
    (0x40, "READONLY"),
    (0x80, "HOTTRACKED"),
)


def describe_state(state) -> str:
    if not isinstance(state, int):
        return "state=?"
    names = [name for bit, name in _NAMED_BITS if state & bit]
    return f"state=0x{state:08x} [{' '.join(names) or '-'}]"


def describe_value(value, catalog: fp.TunnelCatalog) -> str:
    """Where the displayed value sits — never the value itself."""
    if not isinstance(value, str) or not value:
        return "value=unreadable"
    labels = [label for label in fp.GROUP_LABELS if value.startswith(label + " ")]
    if not labels:
        return f"value=unknown-format (len={len(value)})"
    name = value[len(labels[0]) + 1:]
    for kind in (fp.TUNNEL_KIND_SSL, fp.TUNNEL_KIND_IPSEC):
        tunnels = catalog.of_kind(kind)
        if name in tunnels:
            return f"value='{labels[0]}' + {kind} tunnel #{tunnels.index(name) + 1}/{len(tunnels)}"
    return f"value='{labels[0]}' + not-a-configured-tunnel (len={len(name)})"


def reading_line(target, msaa, catalog) -> str:
    hit = target.first_verified_candidate()
    if hit is None:
        return "no verified FortiClient window"
    hwnd, _owner = hit
    started = time.perf_counter()
    reading = fp.read_profile_control(target, msaa, hwnd=hwnd)
    took_ms = (time.perf_counter() - started) * 1000
    if not reading.ok:
        return f"hwnd=0x{hwnd:x} refused={reading.reason} ({took_ms:.0f} ms)"
    return (f"hwnd=0x{hwnd:x} {describe_state(reading.state)} "
            f"{describe_value(reading.value, catalog)} ({took_ms:.0f} ms)")


def _setup():
    provider = vpn.default_registry.get("forticlient")
    return (provider.secure_window_target(), Win32MsaaSystem(),
            provider.configured_tunnels())


def cmd_once(_args) -> int:
    target, msaa, catalog = _setup()
    print(f"catalog: ssl={len(catalog.ssl)} ipsec={len(catalog.ipsec)}")
    print(reading_line(target, msaa, catalog))
    return 0


def cmd_watch(args) -> int:
    target, msaa, catalog = _setup()
    print(f"catalog: ssl={len(catalog.ssl)} ipsec={len(catalog.ipsec)}")
    print(f"watching for {args.seconds:.0f} s — open the VPN Name list, move the "
          "highlight, close it; this tool only reads")
    end = time.monotonic() + args.seconds
    last = None
    start = time.monotonic()
    while time.monotonic() < end:
        line = reading_line(target, msaa, catalog)
        key = line.rsplit(" (", 1)[0]          # ignore timing when comparing
        if key != last:
            print(f"+{time.monotonic() - start:6.2f}s  {line}", flush=True)
            last = key
        time.sleep(args.interval)
    print("done")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("once", help="one reading").set_defaults(func=cmd_once)
    watch = sub.add_parser("watch", help="print every change of the reading")
    watch.add_argument("--seconds", type=float, default=60.0)
    watch.add_argument("--interval", type=float, default=0.25)
    watch.set_defaults(func=cmd_watch)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
