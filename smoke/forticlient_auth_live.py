"""Live smoke for the migrated EMS AUTH_WINDOW credentials fill (Stage 48/49).

Read-only by default: it looks for the real FortiClient **authentication**
window (the EMS/ZTNA WinForms dialog, title "FortiClient" + "Authentication"),
verifies it through the *production* V2 objects, and prints its structure —
never a field value.  Only with the explicit opt-in flags does it perform a
controlled live fill through the real ``submit_credentials_to_window``.

Everything here uses the shipping code:

* ``vpn.default_registry.get("forticlient")`` — the registered provider;
* ``provider.auth_credentials_target()`` — the Stage-48 target
  (``require_visible=True``, ``raise_window=False``);
* ``vpn.providers.forticlient_auth_window.submit_credentials_to_window`` — the
  real fill;
* ``Win32WindowMessageSystem`` — real ``WM_SETTEXT`` / ``BM_CLICK``.

There are **no fake HWNDs and no fake controls** in this file: if the window is
not on screen, the tool reports that and stops.  It never fabricates a window
to make the path "runnable".

Commands
--------
``detect``     (default) read-only: is the auth window present, verified, and
               visible?  What controls does it have?  No secret is read or
               printed — edit-control contents are shown as ``<hidden>``.
``fill-live``  opt-in (``--i-am-at-the-keyboard --overwrite-my-fields``): fill
               login + password with the agreed DRY values through the real V2
               path.  ``--allow-connect`` additionally lets the real Connect
               (``BM_CLICK``) fire; without it the click is held.  If the window
               has a third edit (a token field), the fill still never touches it
               — credentials go to ``edits[0]``/``edits[1]`` only — and the tool
               says so.

Why this may print "no window" on this machine: the FortiClient **Free /
VPN-only** edition (``FA_FCM installed == 0``) authenticates inside the main
Electron GUI and does not raise a separate WinForms authentication window; that
dialog belongs to the EMS/ZTNA managed edition.  On Free the AUTH_WINDOW path is
CONTRACT-ONLY — the fake suite ``tests/test_vpn_forticlient_auth_window.py`` is
its safety contract.  See the printed summary.
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
import vpn                                                       # noqa: E402
from vpn import ErrorCode, VpnRequest                            # noqa: E402
from vpn.providers.activation_gate import CancellationToken      # noqa: E402
from vpn.providers.forticlient_auth_window import (              # noqa: E402
    submit_credentials_to_window,
)
from vpn.providers.window_message_system import (                # noqa: E402
    BUTTON, EDIT, Win32WindowMessageSystem, is_connect_button,
)

#: Never a real credential — recognisable in a recording, obviously not a secret.
DRY_LOGIN = "DRY-RUN-LOGIN-NOT-REAL"
DRY_PASSWORD = "DRY-RUN-PASSWORD-NOT-REAL"

OK, WARN, BAD, INFO = "  OK  ", " WARN ", " FAIL ", " ..   "


def line(status: str, text: str, detail: str = "") -> None:
    print(f"[{status}] {text}" + (f"\n         {detail}" if detail else ""))


def head(text: str) -> None:
    print(f"\n=== {text} " + "=" * max(0, 64 - len(text)))


# --------------------------------------------------------------------------- #
# Environment facts (read-only)                                               #
# --------------------------------------------------------------------------- #

def _registry_value(subkey: str, name: str):
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey)
    except OSError:
        return None
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None
    finally:
        winreg.CloseKey(key)


def _is_free_edition() -> bool:
    return _registry_value(r"SOFTWARE\Fortinet\FortiClient\FA_FCM",
                           "installed") == 0


def _forti_titles() -> list[tuple[int, str]]:
    """Every visible top-level window whose title mentions FortiClient.

    Titles only — used to explain what *is* on screen when the auth window is
    not.  A title is not trusted for anything: verification is done by the
    provider's secure target, below.
    """
    import win32gui
    found: list[tuple[int, str]] = []

    def _cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if title and "forticlient" in title.lower():
                found.append((hwnd, title))
        return True

    win32gui.EnumWindows(_cb, None)
    return found


# --------------------------------------------------------------------------- #
# detect — read-only                                                          #
# --------------------------------------------------------------------------- #

def _locate_and_verify(provider, api):
    """Return ``(hwnd, owner)`` for a verified auth window, or ``None``.

    Uses the production credentials target — the same HWND → PID → trusted
    ``forticlient.exe`` verification the fill would use.  No focus is taken.
    """
    target = provider.auth_credentials_target(api=api)
    return target.first_verified_candidate()


def cmd_detect(_args) -> int:
    provider = vpn.default_registry.get("forticlient")
    api = sw.Win32WindowApi()
    trusted = provider.trusted_window_dirs()
    messages = Win32WindowMessageSystem()

    head("edycja i okna FortiClienta")
    free = _is_free_edition()
    line(INFO if not free else WARN,
         f"edycja: {'Free / VPN-only (FA_FCM installed=0)' if free else 'EMS/managed'}")
    line(INFO, f"zaufane katalogi: {list(trusted) or '(brak — klient nieznaleziony)'}")
    titles = _forti_titles()
    if titles:
        for hwnd, title in titles:
            line(INFO, f"okno {hex(hwnd)}: {title!r}")
    else:
        line(INFO, "brak widocznych okien FortiClienta")

    head("okno EMS Authentication — wykrycie i weryfikacja")
    verified = _locate_and_verify(provider, api)
    if verified is None:
        line(WARN, "brak zweryfikowanego okna 'FortiClient Authentication'")
        if free:
            line(INFO, "Free/VPN-only loguje w głównym GUI Electron — to okno "
                       "NIE powstaje na tej instalacji (patrz podsumowanie).")
        else:
            line(INFO, "Uruchom logowanie EMS/SAML, aż pojawi się okno auth, "
                       "i powtórz.")
        _summary(free, window_present=False)
        return 0

    hwnd, owner = verified
    line(OK, f"zweryfikowane okno: {hex(hwnd)} pid={owner.pid} "
             f"image={owner.image_name}")

    controls = messages.enumerate_controls(hwnd)
    edits = [c for c in controls if c.kind == EDIT]
    buttons = [c for c in controls if c.kind == BUTTON]
    line(INFO, f"kontrolek: {len(controls)} (Edit={len(edits)}, "
               f"Button={len(buttons)})")
    for control in controls:
        # NEVER print an edit control's text — it can hold a login already typed.
        shown = "<hidden>" if control.kind == EDIT else repr(control.text[:32])
        line(INFO, f"  {control.kind:<6} {hex(control.hwnd)} text={shown}")

    enough = len(edits) >= 2
    line(OK if enough else BAD,
         f"pól Edit >= 2 (wymóg okna poświadczeń): {enough}")
    if len(edits) >= 3:
        line(WARN, "trzecie pole Edit obecne — okno ma pole tokenu; fill "
                   "poświadczeń NIE dotyka go (wypełnia tylko edits[0]/edits[1])")
    connect_buttons = [b for b in buttons if is_connect_button(b.text)]
    line(OK if connect_buttons else WARN,
         f"przycisk Connect rozpoznany: {[b.text for b in connect_buttons]}")

    if controls:
        check = sw.controls_belong_to(hwnd, [c.hwnd for c in controls],
                                      trusted, api)
        line(OK if check.ok else BAD,
             f"controls_belong_to -> ok={check.ok} reason={check.reason}")

    # require_visible: does the real window satisfy the strict reading?
    strict = provider.auth_credentials_target(api=api).strict_foreground_check(hwnd)
    line(OK if strict.ok else WARN,
         f"require_visible (strict_foreground_check) -> ok={strict.ok} "
         f"reason={strict.reason} iconic={strict.iconic}")

    line(OK, "Okno gotowe do live fill: uruchom komendę fill-live z flagami.")
    _summary(free, window_present=True)
    return 0


# --------------------------------------------------------------------------- #
# fill-live — opt-in, real WM_SETTEXT                                          #
# --------------------------------------------------------------------------- #

def cmd_fill_live(args) -> int:
    if not (args.i_am_at_the_keyboard and args.overwrite_my_fields):
        line(WARN, "fill-live wymaga --i-am-at-the-keyboard --overwrite-my-fields")
        return 2

    provider = vpn.default_registry.get("forticlient")
    api = sw.Win32WindowApi()
    verified = _locate_and_verify(provider, api)
    if verified is None:
        line(WARN, "brak okna EMS Authentication — nie ma czego wypełniać")
        line(INFO, "Ta instalacja nie generuje okna (patrz `detect`). "
                   "Kontrakt bezpieczeństwa: tests/test_vpn_forticlient_auth_window.py")
        return 0

    hwnd, owner = verified
    head("fill-live — prawdziwy WM_SETTEXT, atrapy poświadczeń")
    line(WARN, f"okno {hex(hwnd)} pid={owner.pid} image={owner.image_name}")
    line(INFO, f"login/hasło: atrapy ({len(DRY_LOGIN)}/{len(DRY_PASSWORD)} znaków)")
    line(WARN if args.allow_connect else INFO,
         f"Connect (BM_CLICK): {'ZOSTANIE KLIKNIĘTY' if args.allow_connect else 'wstrzymany'}")

    # A message system that honours --allow-connect: the credentials fill always
    # calls click_button for a Connect button, so without permission we swallow
    # the click here (the WM_SETTEXT of login/password still goes out for real).
    messages = _LiveMessages(allow_connect=args.allow_connect)
    request = VpnRequest(provider_id="forticlient", login=DRY_LOGIN,
                         password=DRY_PASSWORD)
    result = submit_credentials_to_window(
        provider, request,
        target=provider.auth_credentials_target(api=api),
        message_system=messages, api=api,
        cancellation=CancellationToken(), trace=None)

    head("wynik")
    line(OK if result.ok else WARN,
         f"located={result.located} login_sent={result.login_sent} "
         f"password_sent={result.password_sent} submitted={result.submitted}")
    line(INFO, f"blocked={result.blocked} cancelled={result.cancelled} "
               f"blocked_at={result.blocked_at} error={result.error_code}")
    line(INFO, f"WM_SETTEXT wysłanych: {messages.set_count} "
               f"(atrapy — popraw pola ręcznie)")
    line(INFO, f"BM_CLICK: wykonanych {messages.click_count}, "
               f"wstrzymanych {messages.click_held}")
    if result.manual_submit_required:
        line(INFO, "Connect nie został kliknięty przez nas — kliknij ręcznie.")
    return 0


class _LiveMessages(Win32WindowMessageSystem):
    """The real message seam, counting sends and optionally holding the click."""

    def __init__(self, *, allow_connect: bool):
        self.allow_connect = allow_connect
        self.set_count = 0
        self.click_count = 0
        self.click_held = 0

    def set_control_text(self, hwnd, text):
        self.set_count += 1
        super().set_control_text(hwnd, text)      # real WM_SETTEXT

    def click_button(self, hwnd):
        if not self.allow_connect:
            self.click_held += 1
            return
        self.click_count += 1
        super().click_button(hwnd)                # real BM_CLICK


# --------------------------------------------------------------------------- #
# Summary                                                                     #
# --------------------------------------------------------------------------- #

def _summary(free: bool, *, window_present: bool) -> None:
    head("podsumowanie AUTH_WINDOW")
    if window_present:
        line(OK, "AUTH_WINDOW: LIVE-DOSTĘPNE na tej maszynie — uruchom fill-live.")
        return
    line(WARN, "AUTH_WINDOW: CONTRACT-ONLY na tej instalacji.")
    if free:
        line(INFO, "Powód: FortiClient Free / VPN-only (FA_FCM installed=0) "
                   "uwierzytelnia w głównym GUI Electron; okno WinForms "
                   "'FortiClient Authentication' powstaje tylko w edycji EMS/ZTNA.")
    line(INFO, "Bezpieczeństwo ścieżki potwierdzone kontraktem fake: "
               "tests/test_vpn_forticlient_auth_window.py (29 testów): poprawny "
               "fill, brak okna, niezweryfikowany HWND, zmiana PID, exe poza "
               "trusted, obca kontrolka, utrata okna login-haslo, minimalizacja, "
               "cancellation ×3, brak Connect po blokadzie, brak sekretów w trace.")
    line(INFO, "Kod produkcyjny NIEZMIENIONY, żeby wymusić okno; CONNECT_ENABLED=False.")


# --------------------------------------------------------------------------- #
# Entry                                                                       #
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Live smoke dla EMS AUTH_WINDOW (login+hasło) FortiClienta.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("detect", help="read-only: wykryj i zweryfikuj okno auth")

    p_fill = sub.add_parser("fill-live", help="opt-in: prawdziwy WM_SETTEXT atrap")
    p_fill.add_argument("--i-am-at-the-keyboard", action="store_true")
    p_fill.add_argument("--overwrite-my-fields", action="store_true")
    p_fill.add_argument("--allow-connect", action="store_true",
                        help="pozwól na prawdziwy BM_CLICK w Connect")

    args = parser.parse_args(argv)
    command = args.command or "detect"
    return {"detect": cmd_detect, "fill-live": cmd_fill_live}[command](args)


if __name__ == "__main__":
    raise SystemExit(main())
