"""Stage 17 — does the real FortiClient match what the mocks assume?

Every previous stage proved its component against a fake machine.  This one
asks the only question a fake cannot answer: *is the real client shaped the way
we think it is?*  It is a set of observations, not a migration step — nothing
here switches production, arms ``connect()``, or touches the UI.

Commands
--------
Read-only, safe to run at any time, never take focus and never send anything::

    py -3.13 -m smoke.forticlient_live inspect
    py -3.13 -m smoke.forticlient_live controls

Starts a process (a status query — no credentials on the command line)::

    py -3.13 -m smoke.forticlient_live cli-probe --i-am-at-the-keyboard

Takes the foreground away from whatever you are doing::

    py -3.13 -m smoke.forticlient_live focus --i-am-at-the-keyboard
    py -3.13 -m smoke.forticlient_live autofill-dry --i-am-at-the-keyboard
    py -3.13 -m smoke.forticlient_live autofill-dry --i-am-at-the-keyboard \
            --steal-focus-at 12
    py -3.13 -m smoke.forticlient_live tab-order --i-am-at-the-keyboard

The flag is not ceremony: these disturb the desktop, so they must be a
deliberate act of somebody sitting in front of it.

What none of this does
----------------------
No password, no token, no clipboard *write* into the client, no typed
character, no ``WM_SETTEXT``, no ``BM_CLICK``, **no Enter**, no connect.

* ``autofill-dry`` runs the *real* Stage-14 autofill against the *real* window
  with the sending seam replaced by a recorder: it proves the flow reaches the
  guarded send with a genuine HWND and that nothing leaves the process.  The
  credentials it carries are literal placeholders.  ``--steal-focus-at N``
  yanks the foreground away mid-sequence to show the guard refusing.
* ``tab-order`` answers the one question the mocks cannot: where the Tab
  sequence actually lands.  It types **nothing**.  It walks the tab stops and
  at each one presses Ctrl+A, Ctrl+C and looks at what the clipboard received
  — a read, not a write, so the client's fields are never modified and no
  connection can be attempted.  Whatever it reads is classified and dropped:
  this tool prints "empty" or "not empty", never a character of it.  The
  user's clipboard is saved first and restored at the end.

Why not simply type into the fields: the real sequence ends in Enter, and
Enter on the FortiClient login form starts an authentication attempt against a
real gateway.  A test must not do that, so this one never presses it.
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

import secure_window as sw                                       # noqa: E402
import vpn                                                       # noqa: E402
from vpn import AutofillStatus, VpnRequest                       # noqa: E402
from vpn.providers import forticlient as fc                      # noqa: E402
from vpn.providers import forticlient_2fa as f2                  # noqa: E402
from vpn.providers.input_system import InputSystem               # noqa: E402
from vpn.providers.launch_system import (                        # noqa: E402
    CLI_PROBE_TIMEOUT_S, WindowsLaunchSystem,
)
from vpn.providers.input_system import (                         # noqa: E402
    VK_CONTROL, VK_RETURN, VK_SHIFT, VK_TAB, Win32InputSystem,
)
from vpn.providers.window_message_system import (                # noqa: E402
    BUTTON, EDIT, Win32WindowMessageSystem,
)

#: Never a real credential.  Long enough to be recognisable in a recording,
#: obviously not a secret to anyone reading a screen over your shoulder.
DRY_LOGIN = "DRY-RUN-LOGIN-NOT-REAL"
DRY_PASSWORD = "DRY-RUN-PASSWORD-NOT-REAL"

OK, WARN, BAD, INFO = "  OK  ", " WARN ", " FAIL ", " ..   "


def line(status: str, text: str, detail: str = "") -> None:
    print(f"[{status}] {text}" + (f"\n         {detail}" if detail else ""))


def head(text: str) -> None:
    print(f"\n=== {text} " + "=" * max(0, 64 - len(text)))


# --------------------------------------------------------------------------- #
# Recording seams — the point is that they cannot send                         #
# --------------------------------------------------------------------------- #

class BlockedInput(InputSystem):
    """Everything the autofill would do, recorded instead of done.

    The clipboard is never read or written: ``read_clipboard`` answers with a
    placeholder so the sequence can continue without the real clipboard being
    touched, let alone overwritten with a password.
    """

    PLACEHOLDER_CLIPBOARD = "DRY-RUN-CLIPBOARD-UNTOUCHED"

    def __init__(self, steal_focus_at: int | None = None, target_hwnd=None):
        self.events: list[tuple] = []
        self.steal_focus_at = steal_focus_at
        self.target_hwnd = target_hwnd
        self.stolen_at: int | None = None

    def _record(self, event) -> None:
        self.events.append(event)
        if self.steal_focus_at is not None and len(self.events) == self.steal_focus_at:
            if steal_foreground(self.target_hwnd):
                self.stolen_at = len(self.events)
                self.events.append(("FOREGROUND-STOLEN",))

    def press_key(self, vk):
        self._record(("key", vk))

    def press_combo(self, modifier_vk, key):
        self._record(("combo", modifier_vk, key))

    def type_text(self, text):
        self._record(("type", len(text)))                # length, never content

    def copy_to_clipboard(self, text):
        self._record(("clipboard-write-blocked", len(text)))
        return True

    def read_clipboard(self):
        self._record(("clipboard-read-skipped",))
        return self.PLACEHOLDER_CLIPBOARD

    def sleep(self, seconds):
        self._record(("sleep", seconds))


def steal_foreground(target_hwnd=None) -> bool:
    """Make the target stop being the foreground — to prove the guard closes.

    First choice is to bring our own console forward.  When there is no console
    (this script is often run from a tool, not a terminal) the honest fallback
    is to minimise the client's own window: it is no longer the foreground, it
    is reversible, and it needs no fight with Windows' foreground lock.
    """
    import win32gui
    try:
        import ctypes
        console = ctypes.windll.kernel32.GetConsoleWindow()
        if console:
            win32gui.ShowWindow(console, 9)              # SW_RESTORE
            if win32gui.SetForegroundWindow(console):
                return True
    except Exception:
        pass
    if target_hwnd:
        try:
            win32gui.ShowWindow(target_hwnd, 6)          # SW_MINIMIZE
        except Exception:
            return False
        # Windows hands the foreground to the next window a moment later; until
        # it does, the minimised window is still reported as the foreground.
        # Measured on this machine: the switch lands within a few hundred ms.
        import time
        for _ in range(15):
            if win32gui.GetForegroundWindow() != target_hwnd:
                return True
            time.sleep(0.1)
        return False
    return False


# --------------------------------------------------------------------------- #
# 1. Read-only inspection                                                      #
# --------------------------------------------------------------------------- #

def cmd_inspect(_args) -> int:
    """Detection, trusted directories, processes, windows — nothing touched."""
    provider = vpn.default_registry.get("forticlient")
    request = VpnRequest(provider_id="forticlient")
    problems = 0

    head("detection (new provider)")
    detection = provider.detect(request)
    line(OK if detection.installed else BAD,
         f"state={detection.state.value} edition={detection.edition}")
    line(INFO, f"exe    = {detection.path}")
    line(INFO, f"source = {detection.source}")
    for key, value in sorted(detection.metadata.items()):
        line(INFO, f"{key} = {value!r}")
    problems += 0 if detection.installed else 1

    head("detection (legacy, for comparison)")
    import vpn_connect
    legacy_installed = vpn_connect.is_forticlient_installed()
    legacy_gui = vpn_connect._find_forticlient_gui()
    legacy_dir = vpn_connect._forti_install_dir()
    legacy_free = vpn_connect._is_forti_free_edition()
    line(OK if legacy_installed == detection.installed else BAD,
         f"installed: legacy={legacy_installed} new={detection.installed}")
    same_exe = _same_path(legacy_gui, detection.path)
    line(OK if same_exe else BAD, f"exe: legacy={legacy_gui}")
    line(OK if legacy_free == (detection.edition == "free") else WARN,
         f"free edition: legacy={legacy_free} new={detection.edition!r}")
    line(INFO, f"install dir: legacy={legacy_dir!r}")
    problems += 0 if same_exe else 1

    head("trusted directories (SecureWindowTarget)")
    trusted_new = provider.trusted_window_dirs()
    trusted_legacy = vpn_connect._trusted_forti_dirs()
    line(OK if trusted_new else BAD, f"new    = {trusted_new}")
    line(OK if set(trusted_legacy) == set(trusted_new) else WARN,
         f"legacy = {tuple(trusted_legacy)}")
    if detection.path:
        inside = any(sw.is_inside(detection.path, directory)
                     for directory in trusted_new)
        line(OK if inside else BAD,
             f"wykryty exe leży w zaufanym katalogu: {inside}")
        problems += 0 if inside else 1
    problems += 0 if trusted_new else 1

    head("process image lookup (QueryFullProcessImageNameW)")
    api = sw.Win32WindowApi()
    our_session = _session_of(os.getpid())
    for image in ("FortiTray.exe", "FortiVPN.exe", "FortiClient.exe",
                  "FortiSSLVPNdaemon.exe"):
        pid = _pid_of(image)
        if pid is None:
            line(INFO, f"{image}: nie działa")
            continue
        session = _session_of(pid)
        path = api.process_image_path(pid)
        readable = isinstance(path, str) and bool(path)
        # A Fortinet *service* runs as SYSTEM in session 0; an unelevated
        # process cannot open it even for PROCESS_QUERY_LIMITED_INFORMATION.
        # That is expected and harmless here — the guard only ever verifies
        # processes that own a window on this desktop — and it fails closed.
        ours = session == our_session
        if readable:
            line(OK, f"{image} pid={pid} sesja={session} -> {path!r}")
        elif ours:
            line(BAD, f"{image} pid={pid} sesja={session}: obraz NIECZYTELNY "
                      f"mimo tej samej sesji")
            problems += 1
        else:
            line(INFO, f"{image} pid={pid} sesja={session}: obraz nieczytelny "
                       f"(usługa SYSTEM, ACCESS_DENIED) — guard odmówi, "
                       f"czyli zachowanie fail-closed")
        if readable:
            inside = any(sw.is_inside(path, d) for d in trusted_new)
            line(OK if inside else WARN,
                 f"{image}: w zaufanym katalogu = {inside}")

    head("window discovery (title candidates, nothing verified yet)")
    main_finder = sw.Win32TitleWindowFinder(fc.WINDOW_TITLE_MUST_CONTAIN,
                                            fc.WINDOW_TITLE_MUST_NOT_CONTAIN)
    auth_finder = sw.Win32TitleWindowFinder(fc.AUTH_WINDOW_TITLE_MUST_CONTAIN)
    main_candidates = main_finder.candidates()
    auth_candidates = auth_finder.candidates()
    line(INFO, f"kandydaci okna głównego: {[hex(h) for h in main_candidates]}")
    line(INFO, f"kandydaci okna EMS     : {[hex(h) for h in auth_candidates]}")
    _describe_windows(main_candidates + auth_candidates, api, trusted_new)

    head("owner verification (read-only, no focus)")
    target = provider.secure_window_target()
    verified = target.first_verified_candidate()
    if verified is None:
        line(INFO if not main_candidates else BAD,
             "brak zweryfikowanego okna głównego"
             + (" (GUI klienta nie jest uruchomione)" if not main_candidates
                else " — kandydat istnieje, ale właściciel odrzucony"))
        problems += 0 if not main_candidates else 1
    else:
        hwnd, owner = verified
        line(OK, f"zweryfikowane okno {hex(hwnd)} pid={owner.pid} "
                 f"image={owner.image_name}")

    head("false positives")
    strangers = _stranger_windows(api, trusted_new)
    line(OK if not strangers else BAD,
         f"okien spoza FortiClienta uznanych za kandydatów: {len(strangers)}")
    for row in strangers:
        line(BAD, row)
    problems += len(strangers)

    head("legacy window probe (read-only)")
    # The legacy loop is `while time.time() < deadline`, so timeout=0 can never
    # run an iteration: use the value connect()'s fast path really passes.
    from vpn.providers.forticlient_connect import FAST_PATH_WINDOW_TIMEOUT_S
    legacy_hwnd = vpn_connect._wait_forticlient_window(
        timeout=FAST_PATH_WINDOW_TIMEOUT_S)
    new_hwnd = verified[0] if verified else None
    line(INFO, f"legacy _wait_forticlient_window({FAST_PATH_WINDOW_TIMEOUT_S}) "
               f"-> {legacy_hwnd!r}")
    agree = bool(legacy_hwnd) == bool(new_hwnd) and (
        legacy_hwnd == new_hwnd or new_hwnd is None)
    line(OK if agree else WARN,
         f"zgodność legacy/new: legacy={legacy_hwnd!r} new={new_hwnd!r}")
    line(INFO, "legacy ufa NAZWIE procesu z tasklist (prefiks 'Forti'); nowy "
               "sprawdza pełną ścieżkę obrazu w zaufanym katalogu")
    problems += 0 if agree else 1

    print()
    line(OK if not problems else BAD, f"zakończono, problemów: {problems}")
    return 0 if not problems else 1


def _same_path(left, right) -> bool:
    if not left or not right:
        return left == right
    return os.path.normcase(os.path.normpath(left)) == \
        os.path.normcase(os.path.normpath(right))


def _session_of(pid: int):
    """Which Windows session a pid lives in (0 = services).  None if unknown."""
    import ctypes
    session = ctypes.c_ulong()
    try:
        ok = ctypes.windll.kernel32.ProcessIdToSessionId(
            ctypes.c_ulong(pid), ctypes.byref(session))
    except Exception:
        return None
    return session.value if ok else None


def _pid_of(image_name: str):
    import subprocess
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {image_name}", "/NH", "/FO", "CSV"],
            capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return None
    for row in out.splitlines():
        parts = [p.strip('"') for p in row.split('","')]
        if len(parts) >= 2 and parts[0].lower() == image_name.lower():
            try:
                return int(parts[1])
            except ValueError:
                return None
    return None


def _describe_windows(handles, api, trusted) -> None:
    import win32gui
    for hwnd in handles:
        try:
            title = win32gui.GetWindowText(hwnd)
            cls = win32gui.GetClassName(hwnd)
        except Exception:
            title = cls = "?"
        owner = sw.verify_window_owner(hwnd, trusted, api)
        line(OK if owner.verified else WARN,
             f"{hex(hwnd)} class={cls!r} title={title[:48]!r}",
             f"owner: verified={owner.verified} reason={owner.reason} "
             f"pid={owner.pid} image={owner.image_name}")


def _stranger_windows(api, trusted) -> list[str]:
    """Visible windows that pass the title filter but are not FortiClient."""
    import win32gui
    strangers = []
    for finder in (sw.Win32TitleWindowFinder(fc.WINDOW_TITLE_MUST_CONTAIN,
                                             fc.WINDOW_TITLE_MUST_NOT_CONTAIN),
                   sw.Win32TitleWindowFinder(fc.AUTH_WINDOW_TITLE_MUST_CONTAIN)):
        for hwnd in finder.candidates():
            owner = sw.verify_window_owner(hwnd, trusted, api)
            if not owner.verified:
                try:
                    title = win32gui.GetWindowText(hwnd)[:48]
                except Exception:
                    title = "?"
                strangers.append(f"{hex(hwnd)} {title!r} -> {owner.reason}")
    return strangers


# --------------------------------------------------------------------------- #
# 3. GUI structure — read-only                                                 #
# --------------------------------------------------------------------------- #

def cmd_controls(_args) -> int:
    """Enumerate the controls of any verified FortiClient window.  Read-only."""
    provider = vpn.default_registry.get("forticlient")
    api = sw.Win32WindowApi()
    trusted = provider.trusted_window_dirs()
    messages = Win32WindowMessageSystem()
    found_any = False

    for label, target in (("okno główne", provider.secure_window_target()),
                          ("okno EMS", provider.auth_window_target())):
        head(f"{label}: struktura kontrolek")
        verified = target.first_verified_candidate()
        if verified is None:
            line(INFO, "brak zweryfikowanego okna — nic do obejrzenia")
            continue
        found_any = True
        hwnd, owner = verified
        line(OK, f"{hex(hwnd)} pid={owner.pid} image={owner.image_name}")

        controls = messages.enumerate_controls(hwnd)
        edits = [c for c in controls if c.kind == EDIT]
        buttons = [c for c in controls if c.kind == BUTTON]
        line(INFO, f"kontrolek: {len(controls)} (Edit={len(edits)}, "
                   f"Button={len(buttons)})")
        for control in controls:
            line(INFO, f"  {control.kind:<6} {hex(control.hwnd)} "
                       f"text={control.text[:32]!r}")

        if controls:
            check = sw.controls_belong_to(hwnd, [c.hwnd for c in controls],
                                          trusted, api)
            line(OK if check.ok else BAD,
                 f"controls_belong_to -> ok={check.ok} reason={check.reason}")

        if label == "okno EMS":
            enough = len(edits) >= f2.MIN_TOKEN_EDITS
            line(OK if enough else WARN,
                 f"pól Edit >= {f2.MIN_TOKEN_EDITS} (wymóg tokenu): {enough}")
            connect_buttons = [b for b in buttons
                               if f2.is_connect_button(b.text)]
            line(OK if connect_buttons else WARN,
                 f"przycisk Connect rozpoznany: "
                 f"{[b.text for b in connect_buttons]}")

    if not found_any:
        line(INFO, "Uruchom GUI FortiClienta i powtórz, aby zobaczyć strukturę.")
    return 0


# --------------------------------------------------------------------------- #
# 2. Focus — opt-in                                                            #
# --------------------------------------------------------------------------- #

def cmd_focus(_args) -> int:
    """Acquire, confirm, re-verify, release.  No keystroke is sent."""
    provider = vpn.default_registry.get("forticlient")
    head("focus na prawdziwym oknie FortiClienta")
    target = provider.secure_window_target()
    acquired = target.acquire_any()

    if not getattr(acquired, "ok", False):
        line(WARN, f"focus odmówiony: reason={getattr(acquired, 'reason', '?')}",
             "to jest poprawny wynik: BLOCKED/NO_FOCUS, nie sukces")
        return 2

    try:
        line(OK, f"przejęto: pid={acquired.pid} image={acquired.image_name}")
        confirm = acquired.confirm()
        line(OK if confirm.ok else BAD,
             f"foreground potwierdzony: ok={confirm.ok} reason={confirm.reason}")
        again = acquired.confirm()
        line(OK if again.ok else BAD,
             f"ponowna weryfikacja właściciela: ok={again.ok} reason={again.reason}")
        guard = acquired.run_guarded("smoke-noop", lambda: "nic-nie-wysłano")
        line(OK if guard.performed else WARN,
             f"guard bez wysyłki: performed={guard.performed} "
             f"reason={guard.reason} value={guard.value!r}")
        return 0 if confirm.ok and again.ok else 1
    finally:
        acquired.release()
        line(OK, "target zwolniony (attach thread input odpięty)")


# --------------------------------------------------------------------------- #
# 5. Autofill dry run — opt-in, real window, blocked sender                    #
# --------------------------------------------------------------------------- #

def cmd_autofill_dry(args) -> int:
    """The real Stage-14 autofill on the real window, with nothing sent."""
    provider = vpn.default_registry.get("forticlient")
    head("autofill dry-run (prawdziwe okno, zablokowany szew wysyłający)")
    line(INFO, "poświadczenia to jawne atrapy — żadne prawdziwe hasło nie jest "
               "używane ani nie trafia do schowka")
    steal_at = getattr(args, "steal_focus_at", None)
    if steal_at:
        line(INFO, f"po {steal_at}. zdarzeniu odbiorę oknu foreground — guard "
                   f"powinien ODMÓWIĆ dalszej sekwencji")

    live = provider.secure_window_target().first_verified_candidate()
    recorder = BlockedInput(steal_focus_at=steal_at,
                            target_hwnd=live[0] if live else None)
    if live:
        line(INFO, f"prawdziwe okno: hwnd={hex(live[0])} pid={live[1].pid} "
                   f"image={live[1].image_name}")
    profile = getattr(args, "profile", "") or ""
    if profile:
        line(INFO, f"profil tunelu: {profile!r} — sekwencja cofnie się "
                   f"Shift+Tab x2 do combo i wpisze nazwę (type-ahead, bez "
                   f"Spacji i bez Enter); wszystko rejestrowane, nic nie "
                   f"wysyłane")
    request = VpnRequest(provider_id="forticlient", login=DRY_LOGIN,
                         password=DRY_PASSWORD, profile_name=profile)
    result = provider.autofill_login_password(request, input_system=recorder)

    line(OK if result.status is AutofillStatus.DONE else WARN,
         f"status={result.status.value} blocked_at={result.blocked_at} "
         f"error={result.error_code}")
    line(INFO, f"login_entered={result.login_entered} "
               f"password_entered={result.password_entered}")
    head("co szew ZAREJESTROWAŁ zamiast wysłać")
    for event in recorder.events:
        line(INFO, f"  {event}")
    sent = [e for e in recorder.events if e[0] == "clipboard-write-blocked"]
    line(OK, f"zapisów do schowka wykonanych naprawdę: 0 "
             f"(zarejestrowanych prób: {len(sent)})")
    blob = repr(recorder.events) + repr(result)
    leaked = [s for s in (DRY_LOGIN, DRY_PASSWORD) if s in blob]
    line(OK if not leaked else BAD,
         f"atrapy poświadczeń w rejestrze/wyniku: {leaked or 'brak'}")

    if steal_at:
        head("czy guard zamknął się po utracie foreground?")
        if recorder.stolen_at is None:
            line(WARN, "nie udało się odebrać foreground — wynik nierozstrzygający")
            return 2
        blocked = result.status is not AutofillStatus.DONE
        line(OK if blocked else BAD,
             f"foreground odebrany po zdarzeniu {recorder.stolen_at}; "
             f"status={result.status.value} blocked_at={result.blocked_at}")
        after = recorder.events[recorder.stolen_at:]
        sends = [e for e in after
                 if e[0] in ("clipboard-write-blocked", "combo", "type")]
        line(OK if not sends else BAD,
             f"prób wysyłki PO utracie foreground: {len(sends)} {sends}")
        return 0 if blocked and not sends else 1
    return 0 if result.status is AutofillStatus.DONE else 2


# --------------------------------------------------------------------------- #
# E. The real Tab order — observed, never typed into                           #
# --------------------------------------------------------------------------- #

#: How many tab stops to walk.  The autofill assumes the username is three Tabs
#: in (profile combo, then two more), so a handful past that is plenty.
TAB_STOPS = 7

#: Above this many characters, Ctrl+A/Ctrl+C copied the document rather than a
#: field — the signature of a tab stop that is not a text input.
PAGE_SELECTION_CHARS = 60


def cmd_tab_order(_args) -> int:
    """Where does Tab actually land?  Read the fields, never write them.

    At every tab stop: Ctrl+A, Ctrl+C, look at what arrived in the clipboard.
    Nothing is typed, nothing is deleted, Enter is never pressed — so the form
    cannot be submitted and no authentication can be attempted.  The content
    read back is classified and thrown away; it is never printed.
    """
    provider = vpn.default_registry.get("forticlient")
    head("rzeczywista kolejność Tab (odczyt, bez wpisywania)")
    line(INFO, "nic nie jest wpisywane, nic nie jest kasowane, Enter NIE jest "
               "wysyłany — formularz nie może zostać zatwierdzony")

    inputs = Win32InputSystem()
    original_clipboard = None
    try:
        original_clipboard = inputs.read_clipboard()
    except Exception:
        pass
    line(INFO, f"schowek zapamiętany: "
               f"{'tak' if original_clipboard is not None else 'nie (pusty/niedostępny)'}")

    target = provider.secure_window_target()
    acquired = target.acquire_any()
    if not getattr(acquired, "ok", False):
        line(WARN, f"nie przejęto okna: {getattr(acquired, 'reason', '?')}")
        return 2

    observations = []
    try:
        line(OK, f"okno: pid={acquired.pid} image={acquired.image_name}")
        inputs.sleep(1.5)                     # the same settle the autofill uses
        for stop in range(TAB_STOPS + 1):
            if stop:
                moved = acquired.run_guarded(
                    f"tab-{stop}", lambda: (inputs.press_key(VK_TAB),
                                            inputs.sleep(0.3)))
                if not moved.performed:
                    line(BAD, f"guard odmówił przy Tab {stop}: {moved.reason}")
                    break
            probe = acquired.run_guarded(
                f"read-{stop}", lambda: _copy_focused_field(inputs))
            if not probe.performed:
                line(BAD, f"guard odmówił przy odczycie {stop}: {probe.reason}")
                break
            observations.append((stop, probe.value))
    finally:
        acquired.release()
        if original_clipboard is not None:
            try:
                inputs.copy_to_clipboard(original_clipboard)
                line(OK, "schowek przywrócony")
            except Exception:
                line(WARN, "nie udało się przywrócić schowka")

    head("obserwacja")
    line(INFO, "'kopiowalne' = pole tekstowe oddało zawartość; 'nic' = pole "
               "hasła albo element bez tekstu (przeglądarki blokują kopiowanie "
               "z pól typu password)")
    for stop, verdict in observations:
        line(INFO, f"  Tab x{stop}: {verdict}")

    head("czego autofill oczekuje (Stage 45)")
    line(INFO, "  szuka pola tekstowego sondujac kolejne Tab-y (bez liczenia)")
    line(INFO, "  z pola username: Shift+Tab x2 -> combo profilu, type-ahead")
    line(INFO, "  Tab x2 -> z powrotem username, potem Tab x1 -> password")
    line(INFO, "Zestaw to z powyższym: pole username powinno być 'kopiowalne', "
               "pole password 'nic'.")
    return 0


def _copy_focused_field(inputs) -> str:
    """Ctrl+A, Ctrl+C, then classify what the clipboard received.

    Returns a verdict, never the text.  A field that refuses to be copied is
    the signature of a password input.
    """
    inputs.copy_to_clipboard("")                 # clear, so a stale value cannot lie
    inputs.sleep(0.15)
    inputs.press_combo(VK_CONTROL, ord("A"))
    inputs.sleep(0.15)
    inputs.press_combo(VK_CONTROL, ord("C"))
    inputs.sleep(0.25)
    try:
        got = inputs.read_clipboard()
    except Exception:
        return "odczyt schowka nieudany"
    if not got:
        return "NIC — pole hasła albo element nietekstowy"
    # Never print the text, and never print its exact length either: the length
    # of a saved username is still something about the user.  Two buckets are
    # all the diagnosis needs — a whole-page select-all (no text field has
    # focus, so Ctrl+A grabbed the document) versus a real form field.
    if len(got) >= PAGE_SELECTION_CHARS:
        return "zaznaczenie CAŁEJ STRONY — w tym miejscu nie ma pola tekstowego"
    return "POLE TEKSTOWE, niepuste (treść i długość nie są pokazywane)"


# --------------------------------------------------------------------------- #
# 4. CLI probe — opt-in, no credentials                                        #
# --------------------------------------------------------------------------- #

def cmd_cli_probe(_args) -> int:
    """``FortiVPN.exe --cli --status`` — a status query, no credentials."""
    provider = vpn.default_registry.get("forticlient")
    head("sonda CLI")
    fortivpn = provider._fortivpn_executable("")
    line(OK if fortivpn else WARN, f"FortiVPN.exe = {fortivpn!r}")
    if not fortivpn:
        return 2

    free = provider._free_edition()
    line(INFO, f"wersja darmowa wg rejestru: {free} "
               f"({'legacy NIGDY tu nie sonduje' if free else 'legacy sonduje'})")

    from vpn.providers.forticlient_runtime import (
        CLI_PROBE_ARGS, CLI_UNSUPPORTED_MARKERS,
    )
    cmd = [fortivpn, *CLI_PROBE_ARGS]
    line(INFO, f"uruchamiam: {cmd} (timeout {CLI_PROBE_TIMEOUT_S}s)")
    import time
    started = time.monotonic()
    rc, output = WindowsLaunchSystem().run_capture(cmd, CLI_PROBE_TIMEOUT_S)
    elapsed = time.monotonic() - started

    line(INFO, f"returncode={rc} czas={elapsed:.2f}s")
    line(INFO, "stdout+stderr (pierwsze 600 znaków):")
    print("---------8<---------")
    print((output or "")[:600])
    print("--------->8---------")
    low = (output or "").lower()
    markers = [m for m in CLI_UNSUPPORTED_MARKERS if m in low]
    supported = not markers
    line(INFO, f"markery 'nieobsługiwane' znalezione: {markers or 'brak'}")
    line(OK, f"cli_supported wg nowej logiki = {supported}")

    import vpn_connect
    legacy = vpn_connect._is_fortivpn_cli_supported()
    line(OK if legacy == (supported and not free) else WARN,
         f"legacy _is_fortivpn_cli_supported() = {legacy}")
    return 0


# --------------------------------------------------------------------------- #
# Stage 19: why does Windows refuse the foreground?                            #
# --------------------------------------------------------------------------- #
#
# Measurement only.  Every probe either reads state or performs one documented
# Win32 call whose effect is a window activation — never a keystroke, never a
# character, never Enter.  Whatever a probe attaches, it detaches.

SPI_GETFOREGROUNDLOCKTIMEOUT = 0x2000
ASFW_ANY = -1
SW_RESTORE, SW_SHOW, SW_MINIMIZE = 9, 5, 6


def _user32():
    import ctypes
    return ctypes.WinDLL("user32", use_last_error=True)


class _GuiThreadInfo:
    """GetGUIThreadInfo, unpacked into the three fields that matter here."""

    def __init__(self, tid):
        import ctypes
        from ctypes import wintypes

        class GUITHREADINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD), ("flags", wintypes.DWORD),
                        ("hwndActive", wintypes.HWND), ("hwndFocus", wintypes.HWND),
                        ("hwndCapture", wintypes.HWND),
                        ("hwndMenuOwner", wintypes.HWND),
                        ("hwndMoveSize", wintypes.HWND),
                        ("hwndCaret", wintypes.HWND), ("rcCaret", wintypes.RECT)]

        info = GUITHREADINFO()
        info.cbSize = ctypes.sizeof(GUITHREADINFO)
        self.ok = bool(_user32().GetGUIThreadInfo(tid, ctypes.byref(info)))
        self.active = info.hwndActive if self.ok else None
        self.focus = info.hwndFocus if self.ok else None


def _describe(hwnd, api):
    import win32gui
    if not hwnd:
        return "(brak)"
    try:
        pid = api.window_pid(hwnd)
        image = api.process_image_path(pid) if pid else None
        name = os.path.basename(image) if image else "?"
        return (f"{hex(hwnd)} class={win32gui.GetClassName(hwnd)!r} "
                f"pid={pid} image={name}")
    except Exception:
        return f"{hex(hwnd)} (nieczytelne)"


def _user_idle_seconds():
    """Seconds since the last *real* keyboard/mouse input from the user.

    The variable that decides everything here: while somebody is working, the
    application they touched holds the right to set the foreground, and a
    background process is refused.  On an idle desktop nobody holds it and the
    same call succeeds.  Any focus measurement without this number next to it
    is not reproducible.
    """
    import ctypes
    from ctypes import wintypes

    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]

    info = LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(info)
    if not _user32().GetLastInputInfo(ctypes.byref(info)):
        return None
    ticks = ctypes.WinDLL("kernel32").GetTickCount()
    return max(0.0, (ticks - info.dwTime) / 1000.0)


def _foreground_lock_timeout():
    import ctypes
    from ctypes import wintypes
    value = wintypes.DWORD()
    ok = _user32().SystemParametersInfoW(SPI_GETFOREGROUNDLOCKTIMEOUT, 0,
                                         ctypes.byref(value), 0)
    return value.value if ok else None


def _probe(name, action, *, target, api, expect):
    """Run one mechanism, report what the desktop looked like afterwards."""
    import ctypes
    import time
    import win32gui

    ctypes.set_last_error(0)
    try:
        returned = action()
        error = ctypes.get_last_error()
    except Exception as exc:
        line(WARN, f"{name}: wyjątek {type(exc).__name__}")
        return False
    time.sleep(0.25)
    foreground = win32gui.GetForegroundWindow()
    won = foreground == target
    line(OK if won else INFO,
         f"{name}: zwrócono {returned!r} last_error={error} -> foreground "
         f"{'= CEL' if won else 'nadal ' + _describe(foreground, api)}")
    if not won and expect:
        line(INFO, f"         oczekiwane: {expect}")
    return won


def cmd_focus_diagnose(args) -> int:
    """Why is the foreground refused, and which mechanism could change that?"""
    import ctypes
    import time
    import win32gui

    provider = vpn.default_registry.get("forticlient")
    api = sw.Win32WindowApi()
    user32 = _user32()

    found = provider.secure_window_target().first_verified_candidate()
    if found is None:
        line(WARN, "brak zweryfikowanego okna FortiClienta — uruchom klienta")
        return 2
    target, owner = found

    head("stan wyjściowy")
    our_pid, our_tid = os.getpid(), api.current_thread_id()
    foreground = win32gui.GetForegroundWindow()
    fg_tid = api.window_thread_id(foreground) if foreground else None
    fg_pid = api.window_pid(foreground) if foreground else None
    target_tid = api.window_thread_id(target)

    line(INFO, f"my           : pid={our_pid} tid={our_tid}")
    line(INFO, f"cel          : {_describe(target, api)} tid={target_tid}")
    line(INFO, f"               iconic={win32gui.IsIconic(target)} "
               f"visible={win32gui.IsWindowVisible(target)} "
               f"enabled={win32gui.IsWindowEnabled(target)}")
    line(INFO, f"foreground   : {_describe(foreground, api)} tid={fg_tid}")
    we_are_foreground = fg_pid == our_pid
    line(OK if we_are_foreground else INFO,
         f"czy MY jesteśmy procesem foreground: {we_are_foreground}")
    timeout = _foreground_lock_timeout()
    line(INFO, f"SPI_GETFOREGROUNDLOCKTIMEOUT = {timeout} ms "
               f"({'blokada aktywna' if timeout else 'blokada wyłączona'})")
    idle = _user_idle_seconds()
    line(INFO if idle is None else (WARN if idle > 30 else OK),
         f"od ostatniego PRAWDZIWEGO wejścia użytkownika: "
         f"{'nieznane' if idle is None else f'{idle:.1f} s'}")
    if idle is not None and idle > 30:
        line(WARN, "pulpit bezczynny — żaden proces nie trzyma prawa do "
                   "foreground, więc poniższe próby są ŁATWIEJSZE niż w realnym "
                   "użyciu; wynik NIE jest reprezentatywny dla pracującego "
                   "użytkownika")

    head("warunki, w których SetForegroundWindow JEST dozwolone (dokumentacja)")
    conditions = [
        ("proces wywołujący jest procesem foreground", we_are_foreground),
        ("nie ma żadnego okna foreground", not foreground),
        ("proces wywołujący jest debugowany",
         bool(ctypes.windll.kernel32.IsDebuggerPresent())),
        ("cel należy do procesu foreground", fg_pid == owner.pid),
    ]
    for text, holds in conditions:
        line(OK if holds else INFO, f"{'SPEŁNIONY ' if holds else 'niespełniony'}: {text}")
    line(INFO, "pozostałe warunki (proces otrzymał ostatnie zdarzenie wejścia, "
               "został uruchomiony przez proces foreground, blokada wygasła) nie "
               "dają się odczytać z API — wnioskujemy je z wyniku prób poniżej")

    if args.minimize_first:
        head("scenariusz B: minimalizuję okno klienta")
        win32gui.ShowWindow(target, SW_MINIMIZE)
        time.sleep(0.6)
        line(INFO, f"iconic={win32gui.IsIconic(target)} foreground="
                   f"{_describe(win32gui.GetForegroundWindow(), api)}")

    head("próby mechanizmów (żadna nie wysyła znaku)")
    attached = []

    def attach(tid, label):
        ok = api.attach_thread_input(our_tid, tid, True)
        line(INFO, f"AttachThreadInput(nasz -> {label} tid={tid}) = {ok}")
        if ok:
            attached.append(tid)
        return ok

    def detach_all():
        for tid in list(attached):
            api.attach_thread_input(our_tid, tid, False)
            attached.remove(tid)

    results = {}
    try:
        # 1 — the bare call, exactly what the production code ends up doing.
        results["SetForegroundWindow"] = _probe(
            "1. SetForegroundWindow (bez attach)",
            lambda: user32.SetForegroundWindow(target), target=target, api=api,
            expect="blokada foreground odrzuca wywołanie z procesu w tle")

        # 2 — what acquire_focus() does today.
        if attach(target_tid, "wątek CELU"):
            results["attach(target)+SFW"] = _probe(
                "2. attach(cel) + SetForegroundWindow  [obecna implementacja]",
                lambda: user32.SetForegroundWindow(target), target=target,
                api=api, expect="attach do celu nie nadaje prawa do foreground")
            detach_all()

        # 3 — the folklore fix: attach to the *foreground* thread.
        if fg_tid and fg_tid != target_tid and attach(fg_tid, "wątek FOREGROUND"):
            results["attach(foreground)+SFW"] = _probe(
                "3. attach(foreground) + SetForegroundWindow",
                lambda: user32.SetForegroundWindow(target), target=target,
                api=api, expect="najczęściej cytowane obejście")
            results["attach(foreground)+BringWindowToTop"] = _probe(
                "4. attach(foreground) + BringWindowToTop",
                lambda: user32.BringWindowToTop(target), target=target, api=api,
                expect="zmienia kolejność Z, nie nadaje foreground")
            detach_all()

        # 5 — AllowSetForegroundWindow, called by a process that has no right
        #     to give away (the API is meant for the foreground process).
        results["AllowSetForegroundWindow"] = _probe(
            "5. AllowSetForegroundWindow(ASFW_ANY) + SetForegroundWindow",
            lambda: (user32.AllowSetForegroundWindow(ASFW_ANY),
                     user32.SetForegroundWindow(target))[1],
            target=target, api=api,
            expect="ma je wołać proces, KTÓRY MA prawo — nie my")

        # 6 — activation without foreground rights.
        results["ShowWindowAsync"] = _probe(
            "6. ShowWindowAsync(SW_SHOW)",
            lambda: user32.ShowWindowAsync(target, SW_SHOW), target=target,
            api=api, expect="pokazuje okno, nie nadaje foreground")

        # 7 — keyboard focus inside a merged input queue: a different question
        #     from "which window is the foreground one".
        head("7. SetFocus w połączonej kolejce wejścia (attach do wątku celu)")
        if attach(target_tid, "wątek CELU"):
            before = _GuiThreadInfo(target_tid)
            line(INFO, f"GetGUIThreadInfo(cel) przed: active="
                       f"{_describe(before.active, api)} focus="
                       f"{_describe(before.focus, api)}")
            previous = user32.GetFocus()
            ctypes.set_last_error(0)
            returned = user32.SetFocus(target)
            error = ctypes.get_last_error()
            time.sleep(0.2)
            after = _GuiThreadInfo(target_tid)
            got_focus = user32.GetFocus()
            line(INFO, f"SetFocus(cel) = {returned!r} last_error={error}")
            line(INFO, f"GetFocus() w naszej (połączonej) kolejce: "
                       f"{_describe(got_focus, api)}")
            line(INFO, f"GetGUIThreadInfo(cel) po: active="
                       f"{_describe(after.active, api)} focus="
                       f"{_describe(after.focus, api)}")
            line(INFO, f"foreground nadal: "
                       f"{_describe(win32gui.GetForegroundWindow(), api)}")
            results["SetFocus(attached)"] = got_focus == target
            if previous:
                user32.SetFocus(previous)
            detach_all()
    finally:
        detach_all()
        if args.minimize_first:
            win32gui.ShowWindow(target, SW_RESTORE)
            line(OK, "okno klienta przywrócone")

    head("wątki procesu klienta (scenariusz E)")
    _thread_map(owner.pid, target, api)

    head("podsumowanie")
    for name, won in results.items():
        line(OK if won else INFO,
             f"{name}: {'PRZEJĘŁO foreground' if won else 'nie przejęło'}")
    any_worked = any(results.values())
    line(OK if any_worked else WARN,
         "któryś mechanizm zadziałał" if any_worked
         else "żaden mechanizm nie przejął foreground w tym stanie pulpitu")
    return 0


def _thread_map(pid, target, api) -> None:
    """Which threads of the client own windows, and which one owns the target."""
    import win32gui
    import win32process
    by_thread = {}

    def _cb(hwnd, _):
        try:
            tid, window_pid = win32process.GetWindowThreadProcessId(hwnd)
        except Exception:
            return True
        if window_pid == pid:
            by_thread.setdefault(tid, []).append(hwnd)
        return True

    try:
        win32gui.EnumWindows(_cb, None)
    except Exception:
        pass
    target_tid = api.window_thread_id(target)
    for tid, handles in sorted(by_thread.items()):
        mark = "  <- wątek okna docelowego" if tid == target_tid else ""
        line(INFO, f"tid={tid}: {[hex(h) for h in handles]}{mark}")
    if not by_thread:
        line(INFO, "brak okien najwyższego poziomu tego procesu")


# --------------------------------------------------------------------------- #
# Stage 20: one measurement of the production mechanism, with its reasons      #
# --------------------------------------------------------------------------- #

def cmd_focus_sample(args) -> int:
    """Take ONE sample of the real `acquire_focus`, labelled by input state.

    The point is the comparison: the same target and the same mechanism, once
    while somebody is working (``--wait-active``) and once on an idle desktop
    (``--wait-idle``).  Nothing is typed; the attempt either wins the
    foreground or is refused, and either way the window is released again.
    """
    import time
    import win32gui

    provider = vpn.default_registry.get("forticlient")
    api = sw.Win32WindowApi()
    user32 = _user32()

    found = provider.secure_window_target().first_verified_candidate()
    if found is None:
        line(WARN, "brak zweryfikowanego okna FortiClienta — uruchom klienta")
        return 2
    target = found[0]

    if args.wait_active:
        head("czekam na AKTYWNEGO użytkownika")
        line(INFO, f"RUSZ MYSZKĄ albo pisz w innym oknie — próba wystrzeli, gdy "
                   f"od ostatniego wejścia minie mniej niż {args.active_below} s")
        if not _wait_until(lambda: (api.user_idle_seconds() or 999) < args.active_below,
                           args.wait_seconds):
            line(WARN, "nie doczekałem się aktywności — próbka nieważna")
            return 2
    if args.wait_idle:
        head("czekam na BEZCZYNNY pulpit")
        line(INFO, f"nie dotykaj klawiatury ani myszy — próba wystrzeli po "
                   f"{args.idle_above} s bezczynności")
        if not _wait_until(lambda: (api.user_idle_seconds() or 0) > args.idle_above,
                           args.wait_seconds):
            line(WARN, "pulpit nie stał się bezczynny — próbka nieważna")
            return 2

    label = args.label or ("A-aktywny" if args.wait_active
                           else "B-bezczynny" if args.wait_idle else "bez-etykiety")
    head(f"PRÓBKA {label}")
    foreground = win32gui.GetForegroundWindow()
    line(INFO, f"foreground przed : {_describe(foreground, api)}")
    line(INFO, f"cel              : {_describe(target, api)}")
    line(INFO, f"idle             : {api.user_idle_seconds()} s")
    line(INFO, f"iconic(cel)      : {api.is_iconic(target)}")

    # The production mechanism, unchanged — only asked to explain itself.
    # One target instance, because that is where a *successful* attempt leaves
    # its notes (a VerifiedWindow deliberately carries none of its own).
    secure_target = provider.secure_window_target()
    started = time.monotonic()
    result = secure_target.acquire_any(diagnose=True)
    elapsed = time.monotonic() - started
    won = getattr(result, "ok", False)
    notes = dict(secure_target.last_focus_diagnostics)
    if not notes:
        notes = dict(getattr(result, "diagnostics", {}) or {})
    line(OK if won else WARN,
         f"acquire_any -> {'PRZEJĘTO' if won else 'ODMOWA: ' + getattr(result, 'reason', '?')}"
         f"  ({elapsed * 1000:.0f} ms)")
    if won:
        result.release()

    head("FocusResult.diagnostics (wyłącznie liczby i uchwyty)")
    for key in sw.FOCUS_DIAGNOSTIC_KEYS:
        if key in notes:
            value = notes[key]
            is_handle = key in ("foreground_before", "foreground_after")
            shown = hex(value) if is_handle and isinstance(value, int) else value
            line(INFO, f"  {key:<22} = {shown}")
    missing = [k for k in sw.FOCUS_DIAGNOSTIC_KEYS if k not in notes]
    line(INFO, f"  (nieobecne: {', '.join(missing) or 'brak'})")

    if not won:
        head("ta sama chwila, mechanizm BEZ AttachThreadInput")
        line(INFO, "porównanie ma sens tylko po odmowie — po sukcesie foreground "
                   "jest już nasz i każda kolejna próba wygrywa trywialnie")
        _probe("SetForegroundWindow (bez attach)",
               lambda: user32.SetForegroundWindow(target), target=target,
               api=api, expect="")

    head("stan po próbie")
    after = win32gui.GetForegroundWindow()
    line(INFO, f"foreground po    : {_describe(after, api)}")
    line(INFO, f"idle po          : {api.user_idle_seconds()} s")
    return 0 if won else 1


def _wait_until(predicate, seconds) -> bool:
    import time
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


# --------------------------------------------------------------------------- #
# autofill-live — the real sequence, actually sent, minus the submit           #
# --------------------------------------------------------------------------- #

class LiveInputNoEnter(Win32InputSystem):
    """Sends everything for real except Enter, which it counts and swallows.

    FortiClient's autofill ends in a submit, and a submit here is not a
    keystroke — it is an authentication attempt against the real gateway of a
    real hospital, with placeholder credentials.  Filling the form is what was
    asked for; connecting was not.  So Enter stops at this seam, and the tool
    reports that it did.

    The clipboard is genuinely used, because the migrated autofill pastes
    rather than types; the autofill restores the operator's clipboard itself
    once the sequence ends.
    """

    def __init__(self, allow_enter: bool = False):
        self.steps = []
        self.enters_withheld = 0
        self.enters_sent = 0
        self._allow_enter = allow_enter

    def press_key(self, vk):
        if vk == VK_RETURN and not self._allow_enter:
            self.enters_withheld += 1
            self.steps.append("ENTER — ZATRZYMANY (brak proby polaczenia)")
            return
        if vk == VK_RETURN:
            self.enters_sent += 1
            self.steps.append("ENTER — WYSLANY (klient sprobuje sie polaczyc)")
            super().press_key(vk)
            return
        name = {0x09: "TAB", 0x20: "SPACE", 0x2E: "DELETE"}.get(vk, vk)
        self.steps.append("klawisz {}".format(name))
        super().press_key(vk)

    NAMES = {0x09: "TAB", 0x10: "SHIFT", 0x0D: "ENTER", 0x11: "CONTROL",
             0x20: "SPACE", 0x2E: "DELETE"}

    def press_combo(self, modifier_vk, key):
        # Both halves get named: the modifier is not always Ctrl (Shift+Tab
        # walks backwards), and a hard-coded "CONTROL+9" in the log reads as a
        # different keystroke than the one actually sent.
        modifier = self.NAMES.get(modifier_vk, modifier_vk)
        name = self.NAMES.get(key, chr(key) if 32 < key < 127 else key)
        self.steps.append("skrot {}+{}".format(modifier, name))
        super().press_combo(modifier_vk, key)

    def type_text(self, text):
        self.steps.append("wpisanie tekstu (tresc nie jest logowana)")
        super().type_text(text)

    def copy_to_clipboard(self, text):
        self.steps.append("zapis do schowka (tresc nie jest logowana)")
        return super().copy_to_clipboard(text)

    def read_clipboard(self):
        self.steps.append("odczyt schowka operatora (do przywrocenia)")
        return super().read_clipboard()


def cmd_autofill_live(args) -> int:
    """The migrated Stage-14 autofill on the real window, sending for real.

    Production code throughout — window verification, the guards, the paste
    sequence — with two deliberate limits: the credentials are obvious
    placeholders, and **Enter never leaves the process**, so the client fills
    in but never tries to connect.

    Runs without a profile name on purpose.  With one, the sequence opens the
    VPN-name combo and presses Enter to pick from it, and that Enter is
    indistinguishable at this seam from the submit.  Without it the navigation
    is three Tabs to the username — the order measured live in Stage 18 — and
    the only Enter in the whole run is the submit, which is the one to stop.
    """
    if not args.overwrite_my_fields:
        head("odmowa — to polecenie NADPISZE pola klienta")
        line(WARN, "Username i Password zostana zastapione atrapami")
        line(INFO, "jesli sie zgadzasz, dodaj --overwrite-my-fields")
        line(INFO, "ENTER domyslnie NIE jest wysylany; --allow-enter to zmienia")
        return 2

    provider = vpn.default_registry.get("forticlient")
    target = provider.secure_window_target()
    live = target.first_verified_candidate()
    if live is None:
        line(WARN, "brak zweryfikowanego okna FortiClienta — otworz klienta")
        return 2

    head("autofill NA ZYWO (prawdziwy SendInput, atrapy, ENTER zatrzymany)")
    line(INFO, "prawdziwe okno: hwnd={} pid={} image={}".format(
        hex(live[0]), live[1].pid, live[1].image_name))
    line(INFO, "profil: {}".format(args.profile or
                                    "bez zmian — combo nie jest ruszane"))
    line(INFO if not args.allow_enter else WARN,
         "ENTER: {}".format("zatrzymany na szwie" if not args.allow_enter
                            else "ZOSTANIE WYSLANY — klient sprobuje sie "
                                 "polaczyc atrapami (odrzucenie po stronie bramy)"))
    line(INFO, "")
    line(INFO, "  >>> KLIKNIJ TERAZ w okno FortiClienta i NIE RUSZAJ MYSZA.")
    line(INFO, "")

    from vpn.providers.activation_gate import ActivationGate, CancellationToken

    activation = ActivationGate(
        target=provider.secure_window_target(),
        cancellation=CancellationToken(), timeout_s=args.timeout,
        observer=lambda st: line(INFO, "stan -> " + st.value)).wait()
    if not activation.ok:
        line(WARN, "bez ACTIVATION_OBSERVED nic nie wysylam: {}".format(
            activation.state.value))
        return 2
    line(OK, "ACTIVATION_OBSERVED: hwnd={} pid={} image={}".format(
        hex(activation.hwnd), activation.pid, activation.image_name))

    inputs = LiveInputNoEnter(allow_enter=args.allow_enter)

    head("sekwencja — profil i poswiadczenia w jednym przebiegu")
    # Since Stage 45 the profile is the production autofill's own first step,
    # so this passes the name through instead of running its own calibration
    # beforehand — which is what made the run take twice as long as it needed.
    request = VpnRequest(provider_id="forticlient", login=DRY_LOGIN,
                         password=DRY_PASSWORD, profile_name=args.profile)
    started = time.monotonic()
    result = provider.autofill_login_password(request, input_system=inputs)
    elapsed = time.monotonic() - started

    for index, step in enumerate(inputs.steps, 1):
        line(INFO, "  {:>2}. {}".format(index, step))

    head("wynik")
    line(OK if result.status is AutofillStatus.DONE else WARN,
         "status={} blocked_at={} error={}".format(
             result.status.value, result.blocked_at, result.error_code))
    line(INFO, "czas calej sekwencji: {:.1f} s".format(elapsed))
    line(INFO, "login_entered={} password_entered={}".format(
        result.login_entered, result.password_entered))

    head("co sie stalo z maszyna")
    line(OK, "ENTER zatrzymanych na szwie: {}".format(inputs.enters_withheld))
    line(WARN if inputs.enters_sent else OK,
         "ENTER wyslanych: {}".format(inputs.enters_sent))
    line(WARN if inputs.enters_sent else OK,
         "proba polaczenia z brama: {}".format(
             "TAK, atrapami — spodziewane odrzucenie" if inputs.enters_sent
             else "NIE"))
    line(INFO, "pola Username i Password sa nadpisane atrapami — popraw je")
    line(INFO, "schowek zostal przywrocony przez sam autofill")
    blob = repr(result)
    leaked = [x for x in (DRY_LOGIN, DRY_PASSWORD) if x in blob]
    line(OK if not leaked else BAD, "atrapy w wyniku: {}".format(leaked or "brak"))
    return 0 if result.status is AutofillStatus.DONE else 1


# --------------------------------------------------------------------------- #
# profile-select — reach the profile combo, set it, and prove it visually      #
# --------------------------------------------------------------------------- #

def cmd_profile_select(args) -> int:
    """Walk back to the profile combo and type a profile name.  Nothing else.

    Split out from the autofill on purpose: choosing a profile may clear the
    credential fields, so it has to happen first — and before it can happen in
    production, it has to be shown to land on the combo rather than on the
    hamburger beside it.  This command exists to be photographed.
    """
    if not args.profile:
        line(WARN, "podaj --profile NAZWA (np. --profile 1SZP)")
        return 2

    provider = vpn.default_registry.get("forticlient")
    if provider.secure_window_target().first_verified_candidate() is None:
        line(WARN, "brak zweryfikowanego okna FortiClienta")
        return 2

    head("Etap 44 — wybor profilu (bez Space, bez Enter)")
    line(INFO, "profil docelowy: {}".format(args.profile))
    line(INFO, "jesli trafimy w hamburger zamiast w combo, wpisany tekst nic "
               "nie zrobi — przycisk ignoruje znaki")
    line(INFO, "")
    line(INFO, "  >>> KLIKNIJ TERAZ w okno FortiClienta i NIE RUSZAJ MYSZA.")
    line(INFO, "")

    from vpn.providers.activation_gate import ActivationGate, CancellationToken
    from vpn.providers.forticlient_autofill import (
        _locate_text_field, _read_selection,
    )
    from vpn.providers.secure_target import VerifiedWindow

    activation = ActivationGate(
        target=provider.secure_window_target(),
        cancellation=CancellationToken(), timeout_s=args.timeout,
        observer=lambda st: line(INFO, "stan -> " + st.value)).wait()
    if not activation.ok:
        line(WARN, "bez ACTIVATION_OBSERVED nic nie robie: {}".format(
            activation.state.value))
        return 2
    line(OK, "ACTIVATION_OBSERVED: hwnd={}".format(hex(activation.hwnd)))

    inputs = LiveInputNoEnter(allow_enter=False)   # Enter is never wanted here
    acquired = provider.secure_window_target().acquire_any()
    if not isinstance(acquired, VerifiedWindow):
        line(BAD, "acquire odmowil: {}".format(getattr(acquired, "reason", "?")))
        return 1

    state = {"clip_dirty": False}

    def guard(win, purpose, operation):
        result = win.run_guarded(purpose, operation)
        return result.performed, result.reason

    with acquired as win:
        head("1. kalibracja do pola tekstowego (Username)")
        found, reason = _locate_text_field(win, inputs, guard, state)
        line(OK if found else BAD, "znaleziono pole: {} ({})".format(found, reason))
        if not found:
            return 1

        head("2. Shift+Tab x2 — wstecz przez hamburger do comba")
        for step in (1, 2):
            performed, reason = guard(win, "back-{}".format(step), lambda: (
                inputs.press_combo(VK_SHIFT, VK_TAB), inputs.sleep(0.3)))
            line(OK if performed else BAD,
                 "Shift+Tab #{}: {}".format(step, reason))
            if not performed:
                return 1

        head("3. wpisanie nazwy profilu (type-ahead, bez Space i bez Enter)")
        performed, reason = guard(win, "profile-type", lambda: (
            inputs.type_text(args.profile), inputs.sleep(0.6)))
        line(OK if performed else BAD, "wpisano: {}".format(performed))

    head("co zostalo wyslane")
    for index, step in enumerate(inputs.steps, 1):
        line(INFO, "  {:>2}. {}".format(index, step))
    line(OK, "ENTER: 0 (wstrzymany na szwie)")
    line(INFO, "")
    line(INFO, "OBEJRZYJ TERAZ OKNO: czy lista profili pokazuje {}?".format(
        args.profile))
    line(INFO, "jesli otworzylo sie menu przy hamburgerze — wcisnij Escape")
    return 0


COMMANDS = {
    "focus-sample": (cmd_focus_sample, True),
    "focus-diagnose": (cmd_focus_diagnose, True),
    "inspect": (cmd_inspect, False),
    "controls": (cmd_controls, False),
    "focus": (cmd_focus, True),
    "autofill-dry": (cmd_autofill_dry, True),
    "autofill-live": (cmd_autofill_live, True),
    "profile-select": (cmd_profile_select, True),
    "tab-order": (cmd_tab_order, True),
    "cli-probe": (cmd_cli_probe, True),
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="smoke.forticlient_live", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--i-am-at-the-keyboard", action="store_true",
                        help="wymagane dla poleceń, które ruszają pulpit lub "
                             "uruchamiają proces")
    parser.add_argument("--label", default=None,
                        help="focus-sample: etykieta próbki w raporcie")
    parser.add_argument("--wait-active", action="store_true",
                        help="focus-sample: poczekaj, aż użytkownik będzie "
                             "aktywny, i dopiero wtedy próbuj (próbka A)")
    parser.add_argument("--wait-idle", action="store_true",
                        help="focus-sample: poczekaj na bezczynny pulpit "
                             "(próbka B)")
    parser.add_argument("--active-below", type=float, default=5.0, metavar="S")
    parser.add_argument("--idle-above", type=float, default=30.0, metavar="S")
    parser.add_argument("--wait-seconds", type=float, default=60.0, metavar="S")
    parser.add_argument("--minimize-first", action="store_true",
                        help="focus-diagnose: zminimalizuj okno klienta przed "
                             "pomiarem (scenariusz B), potem przywróć")
    parser.add_argument("--profile", default="",
                        help="nazwa profilu: tunel dla `autofill-dry`, "
                             "profil do wybrania dla `profile-select`")
    parser.add_argument("--overwrite-my-fields", action="store_true",
                        help="`autofill-live`: zgoda na nadpisanie pol atrapami")
    parser.add_argument("--allow-enter", action="store_true",
                        help="`autofill-live`: wypusc ENTER (klient sprobuje "
                             "sie polaczyc atrapami)")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="`autofill-live`: ile sekund czekac na aktywacje")
    parser.add_argument("--steal-focus-at", type=int, default=None, metavar="N",
                        help="autofill-dry: po N-tym zarejestrowanym zdarzeniu "
                             "odbierz oknu foreground, żeby pokazać, że guard "
                             "zamyka się i nie wysyła dalej")
    args = parser.parse_args(argv)

    handler, needs_consent = COMMANDS[args.command]
    if needs_consent and not args.i_am_at_the_keyboard:
        print(f"'{args.command}' rusza pulpit albo uruchamia proces.\n"
              f"Uruchom ponownie z --i-am-at-the-keyboard, jeżeli siedzisz "
              f"przy tym komputerze.")
        return 3
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
