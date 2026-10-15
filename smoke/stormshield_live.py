"""Stage 39 — does the real Stormshield client match what Stage 39 assumes?

Three commands, no credentials, no typing, no connect.  The same question the
FortiClient smoke tools ask, pointed at the second provider::

    py -3.13 -m smoke.stormshield_live inspect
    py -3.13 -m smoke.stormshield_live window-probe
    py -3.13 -m smoke.stormshield_live launch --i-am-at-the-keyboard

`inspect` and `window-probe` read only.  `launch` starts the client and stops —
it does not raise the window, click the tray, or wait for anything to come
forward, because none of that is this provider's to do.

What none of this does
----------------------
No login, no password, no keystroke, no clipboard, no `SecureWindowTarget.
acquire_any()`.  The autofill is not migrated yet; when it is, it will get its
own dry-run tool with a blocked sending seam, exactly as FortiClient did.
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
from vpn import VpnRequest                                       # noqa: E402
from vpn.providers.stormshield import (                          # noqa: E402
    GUI_EXE_NAME, GUI_PATHS, StormshieldProvider,
)
from smoke.forticlient_live import (                             # noqa: E402
    BAD, INFO, OK, WARN, BlockedInput, _copy_focused_field, head, line,
)
from smoke.activation_live import beep, live_gate                # noqa: E402
from vpn.providers.input_system import Win32InputSystem           # noqa: E402


def provider(app_path: str = "") -> StormshieldProvider:
    prov = StormshieldProvider()
    return prov.with_app_path(app_path) if app_path else prov


def cmd_inspect(args) -> int:
    """Detection, trusted directories and the executable's manifest."""
    prov = provider(args.app_path)

    head("detekcja")
    result = prov.detect(VpnRequest(provider_id="stormshield",
                                    app_path=args.app_path or ""))
    line(OK if result.installed else WARN,
         "state={} source={}".format(result.state.value, result.source))
    line(INFO, "exe = {}".format(result.path))

    head("znane sciezki")
    for path in GUI_PATHS:
        line(OK if os.path.isfile(path) else INFO,
             "{} {}".format("jest    " if os.path.isfile(path) else "brak    ",
                            path))

    head("zaufane katalogi")
    for directory in prov.trusted_window_dirs():
        line(OK if os.path.isdir(directory) else INFO, directory)

    head("manifest — czy klient zada podniesienia uprawnien")
    if result.path and os.path.isfile(result.path):
        import re
        data = open(result.path, "rb").read()
        levels = {m.decode() for m in re.findall(
            rb'requestedExecutionLevel[^>]*level="(\w+)"', data)}
        line(OK if levels == {"asInvoker"} else WARN,
             "requestedExecutionLevel = {}".format(sorted(levels) or "BRAK"))
        line(INFO, "asInvoker => spawn_detached wystarczy, UAC niepotrzebny")
    else:
        line(WARN, "brak pliku — nie mozna sprawdzic manifestu")

    head("kontrakt okna")
    target = prov.secure_window_target()
    line(OK, "require_visible={} raise_window={}".format(
        target._require_visible, target._raise_window))
    line(OK, "CONNECT_ENABLED={}".format(prov.CONNECT_ENABLED))
    return 0 if result.installed else 2


def cmd_window_probe(args) -> int:
    """Which windows the title proposes, and which of them verify.  Read-only."""
    prov = provider(args.app_path)
    head("kandydaci wg tytulu (sama heurystyka, nic nie znaczy)")
    finder = prov.window_finder()
    candidates = finder.candidates()
    line(INFO, "znaleziono kandydatow: {}".format(len(candidates)))

    api = sw.Win32WindowApi()
    trusted = prov.trusted_window_dirs()
    for hwnd in candidates:
        owner = sw.verify_window_owner(hwnd, trusted, api)
        line(OK if owner.verified else WARN,
             "{} pid={} image={} -> {}".format(
                 hex(hwnd), owner.pid, owner.image_name,
                 "ZWERYFIKOWANY" if owner.verified else owner.reason))

    head("pierwszy zweryfikowany kandydat")
    target = prov.secure_window_target(api=api)
    found = target.first_verified_candidate()
    if found is None:
        line(WARN, "brak zweryfikowanego okna",
             "klient nie dziala albo okno jest ukryte w zasobniku — "
             "to poprawna odmowa, nie awaria")
        return 2
    hwnd, owner = found
    line(OK, "hwnd={} pid={} image={}".format(hex(hwnd), owner.pid,
                                              owner.image_name))

    head("odczyt stanu (bez zadnego dzialania)")
    check = target.foreground_check(hwnd)
    line(INFO, "foreground_check: ok={} reason={} foreground={} iconic={}".format(
        check.ok, check.reason, check.foreground, check.iconic))
    strict = target.strict_foreground_check(hwnd)
    line(INFO, "strict_foreground_check: ok={} reason={}".format(
        strict.ok, strict.reason))
    return 0


def cmd_launch(args) -> int:
    """Start the client.  Nothing else — no raise, no tray, no waiting."""
    prov = provider(args.app_path)
    head("launch (spawn_detached, czyste srodowisko)")
    result = prov.launch(VpnRequest(provider_id="stormshield",
                                    app_path=args.app_path or ""))
    line(OK if result.success else BAD,
         "success={} started={} strategy={} pid={} error={}".format(
             result.success, result.started, result.strategy, result.pid,
             result.error_code))
    line(INFO, "observation_failed={}".format(result.observation_failed))
    line(INFO, "proces {} {}".format(
        GUI_EXE_NAME,
        "widziany" if result.started else "niewidziany w oknie czasu"))
    line(OK, "okno NIE bylo podnoszone ani aktywowane — to rola uzytkownika")
    return 0 if result.success else 1


# --------------------------------------------------------------------------- #
# Stage 40 — the window itself                                                 #
# --------------------------------------------------------------------------- #

def _process_windows(pids):
    """Top-level windows of the given pids, with the facts that matter."""
    import win32gui
    import win32process

    rows = []

    def _cb(hwnd, _):
        try:
            _tid, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid not in pids:
                return True
            rows.append({
                "hwnd": hwnd, "pid": pid,
                "class": win32gui.GetClassName(hwnd),
                "visible": bool(win32gui.IsWindowVisible(hwnd)),
                "iconic": bool(win32gui.IsIconic(hwnd)),
                "title_len": len(win32gui.GetWindowText(hwnd)),
            })
        except Exception:
            pass
        return True

    win32gui.EnumWindows(_cb, None)
    return rows


def _client_pids():
    import subprocess
    out = subprocess.run(["tasklist", "/fo", "csv", "/nh"],
                         capture_output=True, text=True, errors="replace").stdout
    pids = set()
    for row in out.splitlines():
        parts = row.split('","')
        if len(parts) >= 2 and GUI_EXE_NAME.lower() in parts[0].lower():
            try:
                pids.add(int(parts[1]))
            except ValueError:
                pass
    return pids


def cmd_window_inspect(args) -> int:
    """Everything about the client's windows, without touching any of them.

    Deliberately prints the *length* of a window title rather than the title:
    a VPN client's caption can carry a gateway name, and none of the questions
    here need it.
    """
    import win32gui

    prov = provider(args.app_path)
    pids = _client_pids()
    head("procesy klienta")
    line(OK if pids else WARN, "pid: {}".format(sorted(pids) or "klient nie dziala"))
    if not pids:
        line(INFO, "uruchom klienta (`launch --i-am-at-the-keyboard`) i powtorz")
        return 2

    head("okna top-level tego procesu")
    rows = _process_windows(pids)
    for row in rows:
        line(OK if row["visible"] else INFO,
             "{} class={!r} visible={} iconic={} dlugosc_tytulu={}".format(
                 hex(row["hwnd"]), row["class"], row["visible"], row["iconic"],
                 row["title_len"]))
    visible = [r for r in rows if r["visible"]]
    line(OK if visible else WARN,
         "widocznych okien: {}".format(len(visible)))
    if not visible:
        line(INFO, "klient startuje do ZASOBNIKA — otworz okno dwuklikiem na "
                   "ikonie w tray, potem powtorz to polecenie")

    head("struktura dzieci (czy Qt5 daje natywne kontrolki Win32)")
    for row in rows:
        kids = []
        try:
            win32gui.EnumChildWindows(row["hwnd"], lambda k, a: a.append(k), kids)
        except Exception:
            kids = []
        classes = []
        for kid in kids[:12]:
            try:
                classes.append(win32gui.GetClassName(kid))
            except Exception:
                classes.append("?")
        line(INFO, "{}: dzieci={} {}".format(hex(row["hwnd"]), len(kids),
                                             classes or ""))
    edits = sum(1 for row in rows for cls in [row["class"]] if "EDIT" in cls.upper())
    line(OK if edits == 0 else WARN,
         "natywnych kontrolek Edit/Button: {} — Qt5 rysuje pola sam, wiec "
         "WM_SETTEXT nie ma do czego trafic".format(edits))

    head("weryfikacja wlasciciela (model V2)")
    api = sw.Win32WindowApi()
    trusted = prov.trusted_window_dirs()
    target = prov.secure_window_target(api=api)
    found = target.first_verified_candidate()
    if found is None:
        line(WARN, "brak zweryfikowanego kandydata")
        line(INFO, "kandydaci wg tytulu: {}".format(
            len(prov.window_finder().candidates())))
        return 2
    hwnd, owner = found
    line(OK, "hwnd={} pid={} image={}".format(hex(hwnd), owner.pid,
                                              owner.image_name))
    line(INFO, "zaufane katalogi: {}".format(len(trusted)))

    head("stan wzgledem kontraktu V2 (same odczyty)")
    line(INFO, "GetForegroundWindow: {}".format(hex(win32gui.GetForegroundWindow())))
    check = target.foreground_check(hwnd)
    line(INFO, "foreground_check : ok={} reason={} foreground={} iconic={}".format(
        check.ok, check.reason, check.foreground, check.iconic))
    strict = target.strict_foreground_check(hwnd)
    line(OK if strict.ok else INFO,
         "strict_foreground_check: ok={} reason={}".format(strict.ok, strict.reason))
    return 0


def cmd_gate_live(args) -> int:
    """The real activation gate, on the real Stormshield window.

    Nothing here restores, raises or focuses: the operator opens and activates
    the window, the gate watches.  Exactly the machinery FortiClient uses —
    reused, not reimplemented.
    """
    prov = provider(args.app_path)
    if prov.secure_window_target().first_verified_candidate() is None:
        line(WARN, "brak zweryfikowanego okna — otworz okno klienta z zasobnika")
        return 2

    head("bramka aktywacji na zywym oknie Stormshielda")
    line(INFO, "")
    beep("act")
    line(INFO, "  >>> KLIKNIJ TERAZ w okno Stormshielda.")
    line(INFO, "")

    from smoke.activation_live import IconicCountingApi

    api = IconicCountingApi()
    target = prov.secure_window_target(api=api)
    from vpn.providers.activation_gate import (
        ActivationGate, CancellationToken,
    )
    gate = ActivationGate(target=target, cancellation=CancellationToken(),
                          timeout_s=args.timeout,
                          observer=lambda st: line(INFO, "stan -> " + st.value))
    result = gate.wait()

    head("wynik bramki")
    line(OK if result.ok else WARN,
         "state={} reason={}".format(result.state.value, result.reason))
    line(INFO, "polls={} waited_s={:.2f} repins={}".format(
        result.polls, result.waited_s, result.repins))
    line(INFO, "pinned: hwnd={} pid={} image={}".format(
        hex(result.hwnd) if result.hwnd else None, result.pid, result.image_name))
    if not result.ok:
        line(WARN, "bez ACTIVATION_OBSERVED dalsza czesc nie ma sensu")
        return 2

    head("activation_still_holds (drugi odczyt)")
    still = target.strict_foreground_check(result.hwnd)
    line(OK if still.ok else WARN,
         "ok={} reason={}".format(still.ok, still.reason))

    head("co dotknelo pulpitu")
    writes = api.writes()
    for name, count in writes.items():
        line(OK if count == 0 else BAD, "{} = {}".format(name, count))
    line(INFO, "odczytow is_iconic={} foreground={}".format(
        api.iconic_reads, api.fg_checks))
    line(OK, "require_visible={} raise_window={}".format(
        target._require_visible, target._raise_window))
    line(OK, "InputSystem: nieutworzony, zero zdarzen")
    return 0 if sum(writes.values()) == 0 else 1


#: How many tab stops to walk.  The legacy sequence is Shift+Tab x2 then three
#: forward steps, so a couple past that is enough to see where it wraps.
TAB_STOPS = 6


def cmd_tab_probe(args) -> int:
    """Where do Tab and Shift+Tab actually land?  Reads fields, never writes.

    This is the one command that sends keystrokes, and it sends only Tab,
    Shift+Tab, Ctrl+A and Ctrl+C.  **Never Enter**, never a character.  At each
    stop it classifies what Ctrl+C received into one of three buckets and
    throws the value away — the content is never printed, and neither is its
    length, because the length of a saved username is still something about
    the user.  The operator's clipboard is saved first and restored at the end.

    ``--fields-may-contain-data`` is required to run it against a form that is
    not empty.  Without it the command refuses, because reading a field that
    holds a real password into this process is a decision the operator has to
    make, not one this tool should make for them.
    """
    import time

    import win32gui

    from vpn.providers.input_system import (
        VK_CONTROL, VK_TAB, Win32InputSystem,
    )

    # Shift is not among the constants the migrated autofill needed so far, so
    # it lives here rather than in the shared module: a smoke tool must not be
    # the reason the common layer grows.  When the Stormshield autofill is
    # implemented it will need Shift+Tab for real, and *that* is the change
    # which earns a `VK_SHIFT` in `input_system`.
    VK_SHIFT = 0x10

    prov = provider(args.app_path)
    api = sw.Win32WindowApi()
    target = prov.secure_window_target(api=api)
    found = target.first_verified_candidate()
    if found is None:
        line(WARN, "brak zweryfikowanego okna — otworz i aktywuj okno klienta")
        return 2
    hwnd, owner = found

    # The operator cannot both start this command and be holding the client in
    # front at the same moment — typing the command takes the foreground away.
    # So the tool waits, exactly as `gate-live` does: the real gate, read-only,
    # until the window is genuinely active and visible.
    from vpn.providers.activation_gate import ActivationGate, CancellationToken

    head("czekam, az aktywujesz okno Stormshielda")
    line(INFO, "")
    beep("act")
    line(INFO, "  >>> KLIKNIJ TERAZ w okno Stormshielda.")
    line(INFO, "")
    activation = ActivationGate(
        target=target, cancellation=CancellationToken(),
        timeout_s=args.timeout,
        observer=lambda st: line(INFO, "stan -> " + st.value)).wait()
    if not activation.ok:
        line(WARN, "bez aktywacji nie ma czego mierzyc: {}".format(
            activation.state.value))
        return 2
    hwnd = activation.hwnd

    strict = target.strict_foreground_check(hwnd)
    if not strict.ok:
        line(WARN, "okno przestalo byc aktywnym celem: {}".format(strict.reason))
        return 2
    line(OK, "okno aktywne i zweryfikowane: hwnd={}".format(hex(hwnd)))

    if not args.fields_may_contain_data:
        head("odmowa — potrzebna jawna zgoda")
        line(WARN, "to polecenie odczytuje zawartosc pol (Ctrl+A/Ctrl+C), zeby "
                   "je sklasyfikowac")
        line(INFO, "jesli formularz jest PUSTY, uruchom ponownie z flaga "
                   "--fields-may-contain-data")
        line(INFO, "jesli sa w nim Twoje prawdziwe dane — wyczysc je najpierw "
                   "albo nie uruchamiaj tego polecenia")
        return 2

    inputs = Win32InputSystem()
    head("zapamietuje schowek operatora")
    try:
        previous = inputs.read_clipboard()
        line(OK, "schowek zapamietany (tresc nie jest pokazywana)")
    except Exception:
        previous = None
        line(WARN, "nie udalo sie odczytac schowka — zostanie wyczyszczony")

    verdicts = []
    try:
        head("krok 0 — pole aktywne zaraz po aktywacji okna")
        verdicts.append(("start", _copy_focused_field(inputs)))
        line(INFO, "  {}".format(verdicts[-1][1]))

        head("Shift+Tab x2 (legacy twierdzi: Password -> Login -> Server)")
        for step in range(1, 3):
            inputs.press_combo(VK_SHIFT, VK_TAB)
            inputs.sleep(0.25)
            verdict = _copy_focused_field(inputs)
            verdicts.append(("shift-tab-{}".format(step), verdict))
            line(INFO, "  po Shift+Tab #{}: {}".format(step, verdict))

        head("Tab do przodu (legacy: Server -> Login -> Password)")
        for step in range(1, TAB_STOPS + 1):
            inputs.press_key(VK_TAB)
            inputs.sleep(0.25)
            verdict = _copy_focused_field(inputs)
            verdicts.append(("tab-{}".format(step), verdict))
            line(INFO, "  po Tab #{}: {}".format(step, verdict))
    finally:
        head("przywracam schowek")
        try:
            inputs.copy_to_clipboard(previous if previous is not None else "")
            line(OK, "schowek przywrocony")
        except Exception:
            line(WARN, "nie udalo sie przywrocic schowka")

    head("podsumowanie sekwencji")
    for name, verdict in verdicts:
        line(INFO, "  {:<14} {}".format(name, verdict))
    line(OK, "wyslano wylacznie: Tab, Shift+Tab, Ctrl+A, Ctrl+C")
    line(OK, "ENTER: 0   znakow wpisanych: 0   sekretow: 0")
    return 0


# --------------------------------------------------------------------------- #
# Stage 41 — the real autofill, with the sending seam blocked                  #
# --------------------------------------------------------------------------- #

#: Never a real credential.  Long, obviously fake, and recognisable in a log.
DRY_LOGIN = "DRY-RUN-LOGIN-NOT-REAL"
DRY_PASSWORD = "DRY-RUN-PASSWORD-NOT-REAL"
DRY_SERVER = "dry-run.invalid"
DRY_PORT = "4433"


class RecordingInput(BlockedInput):
    """Records the *kind* of each operation and sends nothing.

    Inherits the Stage-17 recorder, so the guarantee is the same one already
    reviewed: ``type_text`` stores a length, never the text, and the clipboard
    is neither read nor written.  This subclass adds one thing — a readable
    name for each step — because the question here is the order of operations,
    not their contents.
    """

    NAMES = {0x09: "TAB", 0x10: "SHIFT", 0x0D: "ENTER",
             0x2E: "DELETE", 0x11: "CONTROL"}

    def __init__(self):
        super().__init__()
        self.steps = []

    def _record(self, event) -> None:
        super()._record(event)
        kind = event[0]
        if kind == "type":
            self.steps.append("wpisanie tekstu (dlugosc nie jest pokazywana)")
        elif kind == "key":
            self.steps.append("klawisz {}".format(self.NAMES.get(event[1], event[1])))
        elif kind == "combo":
            modifier = self.NAMES.get(event[1], event[1])
            key = self.NAMES.get(event[2], chr(event[2]) if 32 < event[2] < 127
                                 else event[2])
            self.steps.append("skrot {}+{}".format(modifier, key))


def cmd_autofill_dry(args) -> int:
    """The migrated Stormshield autofill on the real window, sending nothing.

    Everything is real except the last inch: the activation gate, the window
    verification, the guards and the sequence are production code, and only
    ``InputSystem`` is swapped for a recorder.  The credentials are visible
    placeholders, and **Log in is never clicked** — this stage does not submit.

    The report says which kind of operation happened and in what order.  It
    never says what was typed, nor how long it was.
    """
    prov = provider(args.app_path)
    api = sw.Win32WindowApi()
    target = prov.secure_window_target(api=api)
    if target.first_verified_candidate() is None:
        line(WARN, "brak zweryfikowanego okna — otworz okno klienta z zasobnika")
        return 2

    head("Etap 41 — autofill dry-run (prawdziwa sekwencja, zablokowany szew)")
    line(INFO, "poswiadczenia to jawne atrapy; Log in NIE zostanie klikniety")
    line(INFO, "")
    beep("act")
    line(INFO, "  >>> KLIKNIJ TERAZ w okno Stormshielda.")
    line(INFO, "")

    from vpn.providers.activation_gate import ActivationGate, CancellationToken

    activation = ActivationGate(
        target=target, cancellation=CancellationToken(),
        timeout_s=args.timeout,
        observer=lambda st: line(INFO, "stan -> " + st.value)).wait()
    if not activation.ok:
        line(WARN, "bez ACTIVATION_OBSERVED nie ma czego mierzyc: {}".format(
            activation.state.value))
        return 2
    line(OK, "ACTIVATION_OBSERVED: hwnd={} pid={} image={}".format(
        hex(activation.hwnd), activation.pid, activation.image_name))

    head("sekwencja")
    recorder = RecordingInput()
    request = VpnRequest(provider_id="stormshield", login=DRY_LOGIN,
                         password=DRY_PASSWORD, server=DRY_SERVER,
                         port=DRY_PORT)
    result = prov.autofill_login_password(
        request, target=prov.secure_window_target(api=api),
        input_system=recorder)

    for index, step in enumerate(recorder.steps, 1):
        line(INFO, "  {}. {}".format(index, step))

    head("wynik")
    line(OK if result.success else WARN,
         "status={} blocked_at={} error={}".format(
             result.status.value, result.blocked_at, result.error_code))
    line(INFO, "login_entered={} password_entered={}".format(
        result.login_entered, result.password_entered))
    line(INFO, "requires_user_action={} submitted={}".format(
        (result.metadata or {}).get("requires_user_action"),
        (result.metadata or {}).get("submitted")))

    head("co naprawde opuscilo proces")
    enters = [e for e in recorder.events if e[0] == "key" and e[1] == 0x0D]
    clips = [e for e in recorder.events if e[0].startswith("clipboard")]
    line(OK, "realnych znakow wyslanych: 0 (szew rejestruje, nie wysyla)")
    line(OK if not enters else BAD, "ENTER: {}".format(len(enters)))
    line(OK, "operacji na schowku: {} (zadna nie dotarla do systemu)".format(
        len(clips)))
    blob = repr(recorder.events) + repr(result)
    leaked = [x for x in (DRY_LOGIN, DRY_PASSWORD) if x in blob]
    line(OK if not leaked else BAD, "atrapy w rejestrze/wyniku: {}".format(
        leaked or "brak"))
    line(OK, "Log in NIE byl klikniety — to zadanie uzytkownika")

    head("werdykt")
    expected = ["wpisanie tekstu (dlugosc nie jest pokazywana)",
                "skrot SHIFT+TAB",
                "skrot CONTROL+A", "wpisanie tekstu (dlugosc nie jest pokazywana)",
                "skrot SHIFT+TAB",
                "skrot CONTROL+A", "wpisanie tekstu (dlugosc nie jest pokazywana)"]
    matches = recorder.steps == expected
    line(OK if matches else WARN,
         "sekwencja zgodna z projektem Etapu 40: {}".format(matches))
    if not matches:
        line(INFO, "oczekiwano: {}".format(expected))
    return 0 if (result.success and matches and not enters and not leaked) else 1


class WatchingWin32Input(Win32InputSystem):
    """The real input system, with a record of what it was asked to do.

    Unlike :class:`RecordingInput` this one **does** send — that is the entire
    point of ``autofill-live``.  It still refuses to log a value: the operator
    can see what landed in the fields by looking at the window, and a keystroke
    log is a keystroke log regardless of whether today's payload is a
    placeholder.
    """

    NAMES = {0x09: "TAB", 0x10: "SHIFT", 0x0D: "ENTER", 0x2E: "DELETE",
             0x11: "CONTROL"}

    def __init__(self):
        self.steps = []
        self.enters = 0

    def _note(self, text):
        self.steps.append(text)

    def press_key(self, vk):
        if vk == 0x0D:
            self.enters += 1
        self._note("klawisz {}".format(self.NAMES.get(vk, vk)))
        super().press_key(vk)

    def press_combo(self, modifier_vk, key):
        name = self.NAMES.get(key, chr(key) if 32 < key < 127 else key)
        self._note("skrot {}+{}".format(self.NAMES.get(modifier_vk, modifier_vk),
                                        name))
        super().press_combo(modifier_vk, key)

    def type_text(self, text):
        self._note("wpisanie tekstu (tresc nie jest logowana)")
        super().type_text(text)


def cmd_autofill_live(args) -> int:
    """The migrated autofill, sending for real, with placeholder credentials.

    Everything is production code, including ``SendInput``.  What is *not*
    real is the data: an obvious placeholder goes into each field, and **Log in
    is never clicked** — the sequence has no Enter in it at all, so nothing is
    submitted and no connection is attempted.

    It overwrites whatever is in Login and Firewall address, which is why it
    needs ``--overwrite-my-fields`` on top of the usual flag.
    """
    if not args.overwrite_my_fields:
        head("odmowa — to polecenie NADPISZE Twoje pola")
        line(WARN, "Login i Firewall address zostana zastapione atrapami")
        line(INFO, "jesli sie zgadzasz, dodaj --overwrite-my-fields")
        line(INFO, "Log in i tak NIE zostanie klikniety — polaczenie nie ruszy")
        return 2

    prov = provider(args.app_path)
    api = sw.Win32WindowApi()
    if prov.secure_window_target(api=api).first_verified_candidate() is None:
        line(WARN, "brak zweryfikowanego okna — otworz okno klienta z zasobnika")
        return 2

    head("Etap 41b — autofill NA ZYWO (prawdziwy SendInput, atrapy danych)")
    line(INFO, "do pol trafia: {} / {} / {}:{}".format(
        DRY_SERVER, DRY_LOGIN, DRY_SERVER, DRY_PORT))
    line(INFO, "ENTER nie wystepuje w tej sekwencji — Log in zostaje Tobie")
    line(INFO, "")
    beep("act")
    line(INFO, "  >>> KLIKNIJ TERAZ w okno Stormshielda i NIE RUSZAJ MYSZA.")
    line(INFO, "")

    from vpn.providers.activation_gate import ActivationGate, CancellationToken

    target = prov.secure_window_target(api=api)
    activation = ActivationGate(
        target=target, cancellation=CancellationToken(),
        timeout_s=args.timeout,
        observer=lambda st: line(INFO, "stan -> " + st.value)).wait()
    if not activation.ok:
        line(WARN, "bez ACTIVATION_OBSERVED nic nie wysylam: {}".format(
            activation.state.value))
        return 2
    line(OK, "ACTIVATION_OBSERVED: hwnd={} pid={} image={}".format(
        hex(activation.hwnd), activation.pid, activation.image_name))

    head("sekwencja — teraz naprawde")
    inputs = WatchingWin32Input()
    request = VpnRequest(provider_id="stormshield", login=DRY_LOGIN,
                         password=DRY_PASSWORD, server=DRY_SERVER,
                         port=DRY_PORT)
    result = prov.autofill_login_password(
        request, target=prov.secure_window_target(api=api),
        input_system=inputs)

    for index, step in enumerate(inputs.steps, 1):
        line(INFO, "  {}. {}".format(index, step))

    head("wynik")
    line(OK if result.success else WARN,
         "status={} blocked_at={} error={}".format(
             result.status.value, result.blocked_at, result.error_code))
    line(INFO, "login_entered={} password_entered={}".format(
        result.login_entered, result.password_entered))
    line(INFO, "requires_user_action={} submitted={}".format(
        (result.metadata or {}).get("requires_user_action"),
        (result.metadata or {}).get("submitted")))

    head("co sie stalo z maszyna")
    line(OK if inputs.enters == 0 else BAD, "ENTER: {}".format(inputs.enters))
    line(OK, "Log in NIE byl klikniety — polaczenie nie zostalo podjete")
    line(INFO, "pola Login i Firewall address sa teraz nadpisane atrapami "
               "— wpisz swoje wartosci z powrotem")
    blob = repr(result)
    leaked = [x for x in (DRY_LOGIN, DRY_PASSWORD) if x in blob]
    line(OK if not leaked else BAD, "atrapy w wyniku: {}".format(leaked or "brak"))
    return 0 if (result.success and inputs.enters == 0) else 1


COMMANDS = {
    "inspect": (cmd_inspect, False),
    "window-probe": (cmd_window_probe, False),
    "window-inspect": (cmd_window_inspect, False),
    "gate-live": (cmd_gate_live, True),
    "tab-probe": (cmd_tab_probe, True),
    "autofill-dry": (cmd_autofill_dry, True),
    "autofill-live": (cmd_autofill_live, True),
    "launch": (cmd_launch, True),
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m smoke.stormshield_live", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--i-am-at-the-keyboard", action="store_true",
                        help="wymagane dla polecen, ktore uruchamiaja proces")
    parser.add_argument("--app-path", default="",
                        help="sciezka klienta, gdy detekcja jej nie poda")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="`gate-live`: ile sekund czekac na aktywacje")
    parser.add_argument("--fields-may-contain-data", action="store_true",
                        help="`tab-probe`: zgoda na odczyt zawartosci pol")
    parser.add_argument("--overwrite-my-fields", action="store_true",
                        help="`autofill-live`: zgoda na nadpisanie pol atrapami")
    args = parser.parse_args(argv)

    handler, disturbs = COMMANDS[args.command]
    if disturbs and not args.i_am_at_the_keyboard:
        line(WARN, "`{}` uruchamia proces — dodaj --i-am-at-the-keyboard".format(
            args.command))
        return 2
    return handler(args)


if __name__ == "__main__":                                # pragma: no cover
    raise SystemExit(main())
