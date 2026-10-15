"""Read-only probe for the Barracuda Network Access Client — measures, never acts.

Stage 48.  Barracuda is not installed on the machine this was written on, and
its login window has never been measured, so the V2 provider stops before any
keystroke.  This probe is what a later autofill stage needs: run it on a machine
that *has* Barracuda and it reports, without touching anything, the facts the
autofill decision depends on — the executable, the window's title and class, its
owning process and whether that process passes the trusted-image test, and the
shape of its controls (how many Edit fields, which buttons).

It is exhaustively read-only.  It never sends a key, never clicks, never sets
focus, never types, never touches the clipboard, and never starts a login.  It
uses the **production** ``BarracudaProvider`` and ``SecureWindowTarget`` for
verification, and reads control captions through the same
``Win32WindowMessageSystem`` seam the other providers use — enumeration only.

Edit-control contents are never printed (a login may already be typed): edits
show as ``<hidden>``.

Commands
--------
``detect``   (default) executable + trusted dirs + candidate windows + owner
             verification + require_visible reading.
``controls`` additionally enumerate the verified window's child controls
             (count of Edit/Button, button captions) — still read-only.
"""

from __future__ import annotations

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import secure_window as sw                                       # noqa: E402
from vpn.providers.barracuda import (                           # noqa: E402
    BarracudaProvider, GUI_PATHS, INSTALL_DIRS, WINDOW_TITLE_HINT,
)
from vpn.providers.window_message_system import (                # noqa: E402
    BUTTON, EDIT, Win32WindowMessageSystem, is_connect_button,
)

OK, WARN, BAD, INFO = "  OK  ", " WARN ", " FAIL ", " ..   "


def line(status: str, text: str) -> None:
    print(f"[{status}] {text}")


def head(text: str) -> None:
    print(f"\n=== {text} " + "=" * max(0, 64 - len(text)))


def _forti_style_titles():
    """Every visible top-level window whose title mentions Barracuda.

    Titles only, for the report — never trusted for anything.  Verification is
    done by the provider's secure target, below.
    """
    import win32gui
    found: list[tuple[int, str]] = []

    def _cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if title and WINDOW_TITLE_HINT.lower() in title.lower():
                found.append((hwnd, title))
        return True

    win32gui.EnumWindows(_cb, None)
    return found


def _describe_window(hwnd, api):
    import win32gui
    try:
        cls = win32gui.GetClassName(hwnd)
    except Exception:
        cls = "?"
    pid = api.window_pid(hwnd)
    image = api.process_image_path(pid) if pid else None
    return cls, pid, image


def cmd_detect(args) -> int:
    provider = BarracudaProvider()
    api = sw.Win32WindowApi()

    head("Barracuda — wykrycie executable")
    detection = provider.detect()
    line(OK if detection.path else WARN,
         f"detect -> state={detection.state.value} path={detection.path} "
         f"source={detection.source}")
    line(INFO, "znane ścieżki (CONTRACT-ONLY — potwierdzić na maszynie):")
    for path in GUI_PATHS:
        line(INFO if not os.path.isfile(path) else OK,
             f"  {'JEST' if os.path.isfile(path) else 'brak'}: {path}")
    line(INFO, f"zaufane katalogi: {list(provider.trusted_window_dirs())}")

    head("Barracuda — okna kandydujące (tytuł zawiera 'Barracuda')")
    titles = _forti_style_titles()
    if not titles:
        line(WARN, "brak widocznych okien z 'Barracuda' w tytule")
    for hwnd, title in titles:
        cls, pid, image = _describe_window(hwnd, api)
        line(INFO, f"okno {hex(hwnd)} title={title!r} class={cls!r} pid={pid} "
                   f"image={image}")

    head("Barracuda — weryfikacja właściciela (produkcyjny SecureWindowTarget)")
    target = provider.secure_window_target(api=api)
    verified = target.first_verified_candidate()
    if verified is None:
        line(WARN, "brak ZWERYFIKOWANEGO okna Barracudy "
                   "(HWND→PID→zaufany obraz)")
        _summary(installed=bool(detection.path), window=False)
        return 0
    hwnd, owner = verified
    line(OK, f"zweryfikowane okno: {hex(hwnd)} pid={owner.pid} "
             f"image={owner.image_name}")
    strict = target.strict_foreground_check(hwnd)
    line(OK if strict.ok else WARN,
         f"require_visible (strict_foreground_check) -> ok={strict.ok} "
         f"reason={strict.reason} iconic={strict.iconic}")

    if args.command == "controls":
        _report_controls(hwnd, api, provider)

    _summary(installed=bool(detection.path), window=True)
    return 0


def _report_controls(hwnd, api, provider):
    head("Barracuda — struktura kontrolek (enumeracja, BEZ wpisywania)")
    messages = Win32WindowMessageSystem()
    controls = messages.enumerate_controls(hwnd)
    edits = [c for c in controls if c.kind == EDIT]
    buttons = [c for c in controls if c.kind == BUTTON]
    line(INFO, f"kontrolek: {len(controls)} (Edit={len(edits)}, "
               f"Button={len(buttons)})")
    for control in controls:
        # NEVER print an edit's text — it may hold a login already typed.
        shown = "<hidden>" if control.kind == EDIT else repr(control.text[:32])
        line(INFO, f"  {control.kind:<6} {hex(control.hwnd)} text={shown}")
    line(INFO, f"pól Edit ≥ 2 (możliwa ścieżka WM_SETTEXT): {len(edits) >= 2}")
    if len(edits) < 2:
        line(INFO, "mało pól Edit → prawdopodobnie UI modern (Electron/WPF) → "
                   "ścieżka SendInput; wymaga pomiaru kolejności pól")
    connect_buttons = [b for b in buttons if is_connect_button(b.text)]
    line(INFO, f"przyciski typu Connect/OK: {[b.text for b in connect_buttons]}")
    trusted = provider.trusted_window_dirs()
    check = sw.controls_belong_to(hwnd, [c.hwnd for c in controls],
                                  trusted, sw.Win32WindowApi())
    line(OK if check.ok else BAD,
         f"controls_belong_to -> ok={check.ok} reason={check.reason}")


def _summary(*, installed: bool, window: bool):
    head("podsumowanie Barracuda")
    if window:
        line(OK, "Okno wykryte i zweryfikowane — można zebrać strukturę "
                 "kontrolek (uruchom `controls`).")
    else:
        line(WARN, "Barracuda: CONTRACT-ONLY na tej maszynie "
                   f"(zainstalowany={installed}, okno=False).")
    line(INFO, "Do implementacji autofillu potrzeba (z tej maszyny): dokładny "
               "tytuł + klasa okna logowania, liczba i kolejność pól Edit, "
               "czy Win32 (WM_SETTEXT) czy modern (SendInput), tekst przycisku "
               "submit, oraz czy pojawia się okno MFA/token.")
    line(INFO, "Kod produkcyjny NIEZMIENIONY; provider zatrzymuje się przed "
               "autofillem (ui_contract_verified=False).")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only probe Barracuda (bez klawiszy/kliknięć).")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("detect", help="wykryj exe + okna + weryfikacja właściciela")
    sub.add_parser("controls", help="dodatkowo: enumeruj kontrolki (read-only)")
    args = parser.parse_args(argv)
    args.command = args.command or "detect"
    return cmd_detect(args)


if __name__ == "__main__":
    raise SystemExit(main())
