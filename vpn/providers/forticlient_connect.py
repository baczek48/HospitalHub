"""FortiClient connect — the legacy flow split into phases.  NOT wired up.

Reference: `vpn_connect.connect_monitored` (what both UI panels call) and
`vpn_connect.connect` (where it falls through).  This module restates that
flow as a sequence of small phases over explicit seams, so the migration of
connect can later happen phase by phase instead of as one rewrite.

Nothing here runs in the application:

* the provider only runs this flow when a :class:`FortiConnectSystem` is
  injected, and there is deliberately **no real implementation** of that seam
  yet — the registered provider has none and answers ``unsupported``;
* the legacy module stays the only production connect.

Phases, in legacy order
-----------------------
Entry ``connect_monitored`` (vpn_connect.py:3615)::

    cli_probe ──(autofill and CLI supported)──> cli_connect(monitored) ──> END
       │ otherwise: continue as ``connect``

Entry ``connect`` (vpn_connect.py:2715)::

    session_record → credential_copy (autofill off, password) → window_probe(0.5 s)
      ├ window found → await_activation → autofill_start | manual        ──> END
      ├ autofill: auth_window_fill(0.1 s) → found                         ──> END
      ├ cli_probe; autofill + CLI + profile: cli_connect → ok             ──> END
      ├ autofill + FortiSSLVPNclient.exe: legacy_client_connect → ok      ──> END
      └ launch (FortiClientProvider.launch) → autofill_start | manual     ──> END

What the legacy does *not* have, and this module does not invent: detection of
the login state, waiting for/confirming the tunnel (success = initiated; the
UI polls status afterwards), retries.  Autofill and the auth-window fill are
seams here — their implementations (SendInput, WM_SETTEXT) stay in the legacy
module until they are migrated in their own stages.

Legacy behaviour that is odd, duplicated, dead or unsafe is catalogued in
:data:`LEGACY_BEHAVIOR` and **not** fixed here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..types import (
    AutofillResult, AutofillStatus, AutomationMode, ConnectResult, ConnectStep,
    DetectionState, ErrorCode, LaunchResult, TwoFactorMode, TwoFactorStatus,
    VpnRequest, VpnState,
)

__all__ = [
    "FortiConnectSystem", "FortiConnectFlow", "AuthWindowFill", "plan_two_factor",
    "ENTRY_CONNECT", "ENTRY_CONNECT_MONITORED", "LEGACY_BEHAVIOR", "CONNECT_PARITY",
]

#: Legacy public entry points; the UI uses ``connect_monitored``.
ENTRY_CONNECT = "connect"
ENTRY_CONNECT_MONITORED = "connect_monitored"
ENTRIES = (ENTRY_CONNECT, ENTRY_CONNECT_MONITORED)

#: Routes — which way a connect went (``ConnectResult.route``).
ROUTE_CLI_MONITORED = "cli_monitored"
ROUTE_WINDOW_RESTORE = "window_restore"
ROUTE_EMS_AUTH_WINDOW = "ems_auth_window"
ROUTE_CLI = "cli"
ROUTE_LEGACY_CLIENT = "legacy_sslvpn_client"
ROUTE_GUI_LAUNCH = "gui_launch"

#: Phases (``ConnectStep.phase``).
PHASE_DETECT = "detect"
PHASE_CLI_PROBE = "cli_probe"
PHASE_CLI_CONNECT = "cli_connect"
PHASE_SESSION_RECORD = "session_record"
PHASE_CREDENTIAL_COPY = "credential_copy"
PHASE_WINDOW_PROBE = "window_probe"
PHASE_WINDOW_RESTORE = "window_restore"
PHASE_AUTH_WINDOW = "auth_window_fill"
PHASE_LEGACY_CLIENT = "legacy_client_connect"
PHASE_LAUNCH = "launch"
PHASE_AWAIT_ACTIVATION = "await_activation"
PHASE_AUTOFILL = "autofill_start"
PHASE_TWO_FACTOR = "two_factor"

STEP_OK = "ok"
STEP_NONE = "none"
STEP_FAILED = "failed"

#: `_wait_forticlient_window(timeout=0.5)` — the fast path.
FAST_PATH_WINDOW_TIMEOUT_S = 0.5
#: `_fill_forti_auth_window(..., timeout=0.1)` — the instant EMS check.
AUTH_WINDOW_TIMEOUT_S = 0.1


# --------------------------------------------------------------------------- #
# Legacy behaviour catalogue — recorded, not fixed                             #
# --------------------------------------------------------------------------- #

#: (id, kind, description).  kind: "security" | "bug" | "dead-code" |
#: "duplication" | "legacy" | "ui".  Pinned by tests; the new flow keeps the
#: *observable* behaviour of every item unless the item says otherwise.
LEGACY_BEHAVIOR: tuple[tuple[str, str, str], ...] = (
    ("autofill-types-without-focus", "security",
     "NAPRAWIONE w legacy w Stage 12 (secure_window: właściciel + potwierdzony "
     "fokus przed każdą operacją na sekrecie). Było: "
     "_autofill_forticlient: gdy SetForegroundWindow/AttachThreadInput zawiedzie, "
     "sekwencja idzie dalej — Ctrl+V z hasłem i Enter trafiają do okna, które "
     "akurat ma fokus (np. komunikator); fokus nie jest też sprawdzany przed "
     "wklejeniem, więc kliknięcie gdzie indziej w trakcie ~5 s ma ten sam skutek"),
    ("auth-window-matched-by-title-only", "security",
     "NAPRAWIONE w legacy w Stage 12 (secure_window: HWND → PID → obraz procesu "
     "w katalogu FortiClient, także dla tokenu). Było: "
     "_find_forti_auth_window dopasowuje okno wyłącznie po tytule 'FortiClient' + "
     "'Authentication' i ≥2 kontrolkach Edit, bez sprawdzenia, że należy do procesu "
     "Fortinet (w odróżnieniu od _wait_forticlient_window) — login i hasło "
     "(_fill_forti_auth_window) oraz token (fill_forticlient_token) idą WM_SETTEXT "
     "do dowolnego takiego okna"),
    ("password-on-command-line", "security",
     "ścieżki CLI przekazują hasło w argumentach procesu (FortiVPN.exe --password, "
     "FortiSSLVPNclient.exe -p) — widoczne dla innych procesów użytkownika; "
     "--savecredentials utrwala dane w FortiClient"),
    ("clipboard-keeps-password", "security",
     "autofill wyłączony: hasło zostaje w schowku bez czyszczenia; autofill: hasło "
     "jest w schowku ~4 s — historia schowka Windows może je zachować"),
    ("connect-cli-branch-unreachable-from-ui", "dead-code",
     "gałąź CLI w connect() (vpn_connect.py:2794) jest nieosiągalna z UI: "
     "connect_monitored przejmuje autofill+CLI wcześniej, a bez autofill warunek "
     "jest fałszywy"),
    ("cli-probe-twice", "duplication",
     "connect_monitored sonduje CLI, potem connect() sonduje ponownie (drugi wynik "
     "z cache) — nowy flow sonduje raz"),
    ("cli-probe-without-autofill", "legacy",
     "connect() sonduje CLI (może uruchomić FortiVPN.exe --cli --status, timeout 5 s, "
     "w wątku UI) także przy wyłączonym autofill, choć wyniku wtedy nie używa"),
    ("cli-monitored-no-fallback", "legacy",
     "błąd Popen w connect_monitored kończy się porażką bez próby GUI; ten sam błąd "
     "w connect() przechodzi dalej do klienta legacy/GUI"),
    ("cli-monitored-empty-profile", "bug",
     "connect_monitored nie wymaga profile_name: uruchamia --tunnel '' i zgłasza "
     "sukces 'Łączenie z '''"),
    ("token-never-passed", "dead-code",
     "parametr token connect_monitored (--token) — oba panele UI przekazują pusty"),
    ("session-recorded-before-success", "legacy",
     "_last_connected jest ustawiane na początku connect(), także gdy połączenie "
     "potem się nie uda; ścieżka CLI monitorowana go nie ustawia wcale"),
    ("fast-path-double-thread", "duplication",
     "connect() uruchamia wątek, którego celem jest _autofill_forticlient, a ta "
     "sama uruchamia własny wątek"),
    ("no-login-state-detection", "legacy",
     "fast path nie rozpoznaje, czy klient jest już zalogowany/połączony — "
     "przywraca okno i uruchamia autofill niezależnie od stanu"),
    ("manual-message-without-password", "bug",
     "komunikat 'hasło w schowku' także gdy hasło jest puste i nic nie skopiowano"),
    ("success-means-initiated", "legacy",
     "sukces connect() = rozpoczęto (CLI/automatyzacja/okno); potwierdzenia brak, "
     "UI odpytuje status po 2 s / 15 s; brak retry"),
    ("gui-failure-trace-code", "legacy",
     "porażka GUI kończy trace connect kodem client-not-found niezależnie od "
     "rzeczywistego błędu launch (np. process-start-failed)"),
    ("legacy-client-empty-login", "legacy",
     "FortiSSLVPNclient.exe dostaje -u '' przy pustym loginie"),
    ("exceptions-reach-the-ui", "legacy",
     "wyjątki z sondy okna, wypełniania okna EMS i startu wątku autofill nie są "
     "łapane w connect() — nowy flow zwraca je jako connect-failed"),
    ("detail-panel-drops-monitor", "ui",
     "detail_panel ignoruje proces z connect_monitored — prośba o 2FA na stdout CLI "
     "nie jest tam obsługiwana; zamiast tego czeka 20 s na okno EMS nawet po CLI"),
    ("vpn-panel-no-auth-window-2fa", "ui",
     "vpn_panel obsługuje 2FA tylko przez stdout procesu — dla GUI/EMS nie pyta o token"),
    ("autofill-is-synchronous-here", "legacy",
     "legacy uruchamia autofill w wątku i zwraca sukces, zanim cokolwiek "
     "zostanie wpisane; złożony connect czeka na wynik, żeby móc go zgłosić — "
     "connect trwa wtedy tyle, co wypełnianie formularza (NIEZMIENIONE w legacy)"),
    ("ems-credentials-not-migrated", "legacy",
     "ZMIGROWANE w Stage 48 (forticlient_auth_window.submit_credentials_to_window): "
     "runtime wypełnia login i hasło w oknie EMS przez WM_SETTEXT za guardem, z "
     "rewalidacją właściciela i kontrolek przed każdym sekretem oraz obsługą "
     "cancellation. Było (Stage 15-47): faza auth_window_fill istniała w "
     "kolejności, ale runtime jej nie wykonywał — flow przechodził do kolejnej "
     "trasy, tak jak na maszynie bez tego okna"),
    ("two-factor-inline-when-token-known", "legacy",
     "legacy pyta o token po powrocie connectu (wątek UI); złożony connect "
     "podaje token w trakcie, gdy request już go niesie — czekanie na okno EMS "
     "(15 s) dzieje się wtedy wewnątrz connectu"),
    ("cli-challenge-not-read-by-connect", "legacy",
     "connect nie czyta stdout monitorowanego procesu — oddaje monitor w "
     "ConnectResult, a czytaniem zajmuje się answer_two_factor_challenge, bo "
     "blokujący odczyt potoku należy do wątku wywołującego, nie do connectu"),
    ("window-restore-dropped", "legacy",
     "legacy podnosi okno klienta (ShowWindow + SetForegroundWindow) na "
     "początku connectu; nowy flow tego NIE robi — to kradzież foregroundu, "
     "której Windows odmawia procesowi w tle (Etapy 18-20) — i zamiast tego "
     "czeka, aż użytkownik sam aktywuje okno (bramka aktywacji, Etap 22)"),
)


# --------------------------------------------------------------------------- #
# Parity table — legacy vs. the assembled provider (Stage 16)                  #
# --------------------------------------------------------------------------- #

#: ``(id, input, legacy behaviour, new behaviour, difference, kind)``.
#:
#: ``kind`` is the whole point of the table:
#:
#: * ``same`` — no difference; the new flow reproduces the legacy outcome.
#: * ``security`` — a difference that comes straight out of Stages 12–15.  It
#:   is intended, it is the reason those stages happened, and it is never
#:   "fixed" back towards the legacy.
#: * ``information`` — the same outcome, but the new result *says* more (the
#:   legacy threw the fact away).  Nothing behaves differently.
#: * ``not-migrated`` — a legacy capability the new flow does not have yet, so
#:   it falls through to the next route instead.
#:
#: Pinned by tests so a later stage cannot quietly change one.
CONNECT_PARITY: tuple[tuple[str, str, str, str, str, str], ...] = (
    ("client-already-open",
     "okno klienta otwarte, autofill on",
     "fast path: ShowWindow + SetForegroundWindow na oknie znalezionym po "
     "tytule, potem wątek autofillu; brak launchu",
     "to samo, ale okno przechodzi przez SecureWindowTarget (HWND → PID → "
     "obraz w zaufanym katalogu) zanim zostanie podniesione; brak launchu",
     "okno o pasującym tytule, którego nie posiada proces FortiClienta, nie "
     "jest podnoszone ani wypełniane — legacy je podnosił",
     "security"),
    ("client-not-running",
     "brak okna, klient zainstalowany, autofill on",
     "sonda CLI → klient legacy → _open_forticlient_gui → wątek autofillu",
     "identyczna kolejność faz; launch to zmigrowany FortiClientProvider.launch",
     "brak (kolejność i wynik zachowane)",
     "same"),
    ("gui-autofill",
     "GUI + autofill",
     "wątek pisze SendInput/Ctrl+V na ślepo; connect() zwraca sukces zanim "
     "cokolwiek zostanie wpisane, wynik wypełniania jest tracony",
     "autofill jest synchroniczny i zwraca AutofillResult; connect nadal "
     "kończy się sukcesem („rozpoczęto”), ale wynik jest w ConnectResult",
     "wynik wypełniania jest znany i propagowany; sam connect nie zmienia "
     "znaczenia",
     "information"),
    ("gui-autofill-blocked",
     "GUI + autofill, okno traci fokus / zmienia właściciela",
     "sekwencja szła dalej — hasło i Enter trafiały tam, gdzie akurat był "
     "fokus (naprawione w legacy w Stage 12)",
     "guard odmawia, hasło nie wychodzi, connect zwraca sukces z "
     "automation=MANUAL, requires_user_action i error_code autofillu",
     "brak wpisania zamiast wpisania w obce okno",
     "security"),
    ("gui-manual",
     "GUI, autofill off",
     "hasło do schowka, okno otwarte, nic nie jest wpisywane, 2FA pomijane",
     "to samo",
     "brak",
     "same"),
    ("gui-two-factor",
     "GUI + profil z 2FA + token podany",
     "connect wraca, a UI osobnym wątkiem czeka 20 s na okno EMS i dopiero "
     "wtedy pyta użytkownika o kod",
     "po udanym autofillu connect oddaje token do komponentu 2FA (okno EMS, "
     "WM_SETTEXT za guardem) i zwraca TwoFactorResult",
     "podanie tokenu dzieje się w obrębie connectu, jeżeli token jest znany; "
     "bez tokenu wynik mówi TOKEN_REQUIRED i decyzja wraca do wywołującego",
     "security"),
    ("gui-two-factor-no-token",
     "GUI + profil z 2FA, brak tokenu",
     "UI pyta użytkownika po powrocie connectu",
     "ConnectResult: two_factor=AUTH_WINDOW, status TOKEN_REQUIRED, "
     "requires_user_action=True — nic nie jest wysyłane",
     "brak (ta sama decyzja, tylko wyrażona w wyniku)",
     "information"),
    ("ems-credentials-window",
     "okno EMS z loginem i hasłem już na ekranie, autofill on",
     "_fill_forti_auth_window wpisuje login i hasło przez WM_SETTEXT bez fokusu "
     "i klika Connect; przed wysyłką jeden controls_belong_to",
     "submit_credentials_to_window: okno przez SecureWindowTarget, fokus wzięty "
     "(require_visible), a każdy WM_SETTEXT idzie przez run_guarded z listą "
     "kontrolek — foreground, właściciel i własność kontrolek potwierdzane w tej "
     "samej instrukcji co wysyłka; cancellation przed loginem, hasłem i Connect",
     "login przed hasłem, więc utrata okna między nimi zostawia hasło w "
     "procesie; brak wpisania w obce/zminimalizowane okno tam, gdzie legacy "
     "wpisywał; bez schowka",
     "security"),
    ("cli",
     "EMS/ZTNA, autofill on, profil ustawiony",
     "FortiVPN.exe --cli --connect --tunnel ... --username ... --password ... "
     "--savecredentials, Popen z potokami, sukces = uruchomiono",
     "identyczny wiersz poleceń i identyczne znaczenie sukcesu; proces "
     "startuje przez LaunchSystem",
     "brak",
     "same"),
    ("cli-two-factor",
     "CLI + profil z 2FA",
     "UI czyta stdout w wątku, dopasowuje regex, pyta użytkownika, pisze na "
     "stdin; błąd zapisu jest połykany",
     "ten sam regex i ten sam zapis, ale przez komponent 2FA: proces musi być "
     "zaufanym FortiClientem, a błąd zapisu to wynik FAILED",
     "token nie idzie do nieznanego procesu; nieudany zapis przestaje udawać "
     "sukces",
     "security"),
    ("cli-failure",
     "Popen CLI rzuca",
     "connect_monitored: porażka bez próby GUI; connect(): przechodzi dalej",
     "to samo, osobno dla obu wejść",
     "brak (zachowana asymetria legacy)",
     "same"),
    ("launch-failure",
     "klienta nie da się uruchomić",
     "(False, „Nie znaleziono FortiClient…”), trace kończy się "
     "client-not-found niezależnie od prawdziwego błędu",
     "ConnectResult.success=False z error_code launchu i LaunchResult w "
     "wyniku",
     "wynik niesie prawdziwy kod błędu launchu",
     "information"),
    ("detection",
     "dowolne wejście",
     "brak osobnego kroku — klient jest odkrywany przez próbowanie",
     "detect() jest pierwszą fazą, zapisaną w steps, i NIGDY nie jest "
     "rozstrzygająca: działający klient nadal zostaje znaleziony przez sondę "
     "okna, a maszyna bez klienta nadal kończy na client-not-found",
     "brak wpływu na wynik",
     "information"),
    ("no-profile",
     "connect_monitored bez profile_name, CLI dostępne",
     "uruchamia --tunnel '' i zgłasza sukces",
     "to samo (LEGACY_BEHAVIOR 'cli-monitored-empty-profile')",
     "brak — błąd legacy zachowany celowo",
     "same"),
    ("window-already-open-not-raised",
     "okno klienta otwarte, autofill on",
     "connect() podnosi okno: ShowWindow(SW_RESTORE) + SetForegroundWindow",
     "okno NIE jest podnoszone; flow czeka, aż użytkownik sam je aktywuje, i "
     "dopiero wtedy uruchamia autofill",
     "rezygnacja z przejmowania foregroundu — Windows i tak odmawia procesowi "
     "w tle, a wymuszanie tego maskowało warunek, który mają łapać guardy",
     "security"),
    ("user-never-activates",
     "autofill on, użytkownik nie przełącza się do klienta",
     "wątek autofillu odpala się od razu i kończy niepowodzeniem fokusu, a "
     "connect i tak zgłasza sukces",
     "bramka czeka do budżetu, po czym connect kończy się sukcesem z "
     "automation=MANUAL i requires_user_action — bez ani jednego znaku",
     "ta sama liczba wysłanych znaków (zero), ale wynik mówi wprost, że "
     "potrzebna jest ręczna akcja",
     "information"),
    ("no-credentials",
     "pusty login/hasło",
     "CLI pomija --username/--password, klient legacy dostaje -u ''",
     "to samo",
     "brak",
     "same"),
    ("gui-autofill-empty-field",
     "GUI + autofill, pusty login albo puste hasło",
     "_autofill_forticlient pomija puste pole (`if login:` / `if password:`) — "
     "bez Ctrl+A/Delete i bez wklejania; zostaje wartość zapisana w FortiClient",
     "to samo: puste pole nie jest czyszczone ani wklejane (Stage 60; w "
     "Etapie 59 V2 czyściło je i wklejało pusty schowek)",
     "brak",
     "same"),
    ("gui-profile-select",
     "GUI + autofill, profile_name ustawiony",
     "Tab z początku okna → Space → nazwa → Enter na ślepo; wynik wyboru nie "
     "jest sprawdzany, login i hasło idą dalej w każdym przypadku",
     "nazwa musi być tunelem z rejestru (przed pierwszym klawiszem); MSAA "
     "czyta combo 'VPN Name' zweryfikowanego okna — już ten profil = zero "
     "klawiszy; inaczej Shift+Tab×2, Space tylko gdy combo FOCUSED i zwinięte, "
     "nazwa i Enter tylko gdy lista EXPANDED (odczyt + confirm() + klawisz w "
     "jednym kroku guarda); potem 2 odczyty z rzędu: dokładnie ten profil, "
     "zwinięte; ponowny odczyt przed każdym sekretem w schowku i przed Enterem",
     "niepotwierdzony wybór profilu kończy autofill BLOCKED przed loginem — "
     "bez hasła i bez Entera; legacy w tej sytuacji wpisywał dane do "
     "profilu, który akurat był wybrany",
     "security"),
    ("gui-profile-unspecified",
     "GUI + autofill, profile_name PUSTY",
     "brak kroku profilu: login i hasło wpisywane do profilu, który akurat "
     "jest wyświetlony, potem Enter",
     "tylko gdy w rejestrze jest DOKŁADNIE jeden tunel (mierzonego rodzaju) i "
     "MSAA potwierdza, że to on jest wyświetlony — zero klawiszy profilu; w "
     "każdym innym przypadku BLOCKED profile-not-specified przed pierwszym "
     "klawiszem (2026-10-14, L1; decyzja produktowa G5 otwarta)",
     "dane szpitala nie trafiają na bramę innego profilu; karta bez nazwy "
     "profilu przy kilku tunelach wymaga uzupełnienia pola",
     "security"),
)


# --------------------------------------------------------------------------- #
# Seam                                                                         #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class AuthWindowFill:
    """What filling the EMS authentication window achieved.

    The legacy returns ``(ok, message)``; ``submitted`` is the difference
    between "Łączenie przez FortiClient..." (Connect clicked) and "Dane wpisane —
    kliknij Connect ręcznie." (no Connect button found).

    ``found`` means the flow committed to this route: a verified credentials
    window was located and at least the login was sent, or the whole fill
    completed.  A window that could not be located, or a pre-send refusal that
    left nothing typed, reports ``found=False`` so the flow falls through to the
    other routes exactly as the legacy does on a ``(False, "")`` (Stage 48).

    ``blocked`` / ``cancelled`` carry the Stage 47/48 distinction the legacy
    could not: a guard refused mid-fill (``blocked``) versus the caller called
    it off (``cancelled``).  Both stop the flow rather than launching the GUI on
    top of a window that already has the login in it.
    """

    found: bool
    submitted: bool = False
    blocked: bool = False
    cancelled: bool = False
    error_code: str | None = None
    reason: str | None = None


class FortiConnectSystem:
    """Everything a FortiClient connect does besides launching and detection.

    One method per legacy side effect.  Credentials pass *through* these calls
    (they must reach the client) but never come back into a result.  There is
    no real implementation yet — see the module docstring.

    Security contract for a future implementation (Stage 12): `start_autofill`,
    `fill_auth_window` and any token fill must apply the ``secure_window``
    guard — verified owner process and confirmed foreground immediately
    before every operation on a secret — exactly as the legacy now does.
    """

    def record_session(self, profile_name: str, server: str) -> None:
        """Legacy ``_last_connected`` / ``_last_connected_meta`` (feeds status)."""
        raise NotImplementedError

    def copy_to_clipboard(self, text: str) -> bool:
        raise NotImplementedError

    def find_main_window(self, timeout: float) -> Any:
        """FortiClient main window handle or None (``_wait_forticlient_window``)."""
        raise NotImplementedError

    def restore_window(self, handle: Any) -> None:
        """Legacy ``ShowWindow`` + ``SetForegroundWindow`` on the client window.

        **No longer called by the flow** (Stage 22).  Bringing the client
        forward is a foreground steal, which Windows refuses from a background
        process in exactly the situations that matter (Stages 18-20) — so the
        flow waits for the user to do it instead.  Kept because the seam is
        part of the published contract and the legacy module still does this.
        """
        raise NotImplementedError

    def activation_still_holds(self, hwnd):
        """Does the observed activation still hold, right now?  **Read only.**

        Stage 24 measured the gap this closes: the gate answers at one instant,
        and the first secret moves whole seconds later — long enough for the
        user to click somewhere else, which Stage 26 reproduced on the real
        desktop with a foreign window taking the foreground.  Until now nothing
        looked again in between, and the first thing that did look was
        ``acquire_focus``, which *restores and raises* the window before
        confirming it — undoing the very decision the user had just made.

        So the flow asks once more, and asks the strict question: the pinned
        handle, the verified owner, really in front, and not minimised.  It
        does not act on the answer beyond stopping.

        Returning ``None`` means "this system cannot tell", and the flow
        carries on exactly as it did before — every existing fake keeps working
        and the legacy shape is unchanged.
        """
        return None

    def cancel_requested(self) -> bool:
        """Has the caller called this connect off?  **Read only.**

        Stage 47.  The flow asks before each phase that would change something
        outside this process — putting the password on the clipboard, starting
        the CLI or the legacy client, launching the GUI — so a Cancel pressed
        before any of those means none of them happens.  The activation gate
        and the autofill honour the same token on their own.

        ``False`` is the legacy shape: a system that cannot be cancelled.
        """
        return False

    def await_activation(self):
        """Wait until the user has brought the client's window to the front.

        Returns an :class:`~vpn.providers.activation_gate.ActivationResult`, or
        ``None`` for the legacy shape — a system that does not gate at all, in
        which case the flow proceeds straight to the autofill exactly as it did
        before.  Takes no credentials: nothing about waiting could need one.
        """
        return None

    def start_autofill(self, login: str, password: str, profile_name: str):
        """Fill the client's login form.

        Returns an :class:`~vpn.types.AutofillResult` when the fill ran to a
        known outcome, or ``None`` for the legacy shape — a background thread
        whose result nobody waits for.  The flow treats ``None`` as
        "automation pending" and a result as an answer it can report.
        """
        raise NotImplementedError

    def supply_two_factor(self, request: VpnRequest, mode: TwoFactorMode,
                          monitor):
        """Deliver the second factor, or say what the caller must do.

        Returns a :class:`~vpn.types.TwoFactorResult`, or ``None`` when this
        system does not handle 2FA at all — which is the legacy shape: there,
        the UI asks the user for a code after connect has already returned.
        """
        return None

    def fill_auth_window(self, login: str, password: str,
                         timeout: float) -> AuthWindowFill:
        raise NotImplementedError

    def cli_supported(self, app_path: str) -> bool:
        """``_is_fortivpn_cli_supported`` (EMS/ZTNA editions)."""
        raise NotImplementedError

    def start_cli(self, fortivpn: str, profile_name: str, login: str,
                  password: str, token: str, monitored: bool) -> Any:
        """Start ``FortiVPN.exe --cli --connect``; the process when monitored.

        Raises when the process cannot be started.
        """
        raise NotImplementedError

    def start_legacy_client(self, exe: str, address: str, login: str,
                            password: str) -> None:
        """Start ``FortiSSLVPNclient.exe connect``.  Raises on failure."""
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Decisions                                                                    #
# --------------------------------------------------------------------------- #

def plan_two_factor(*, route: str | None, monitor_available: bool,
                    autofill: bool, requires_2fa: bool) -> TwoFactorMode:
    """How a second factor can be supplied after a successful connect.

    * a monitored CLI process → its stdout (vpn_panel starts the monitor for
      every returned process, whether or not the profile asks for 2FA);
    * otherwise only profiles flagged ``requires_2fa``: with autofill the
      token goes into the EMS auth window (detail_panel), without it the user
      types it into the client (both panels skip 2FA when autofill is off).
    """
    if route == ROUTE_CLI_MONITORED and monitor_available:
        return TwoFactorMode.PROCESS_STDOUT
    if not requires_2fa:
        return TwoFactorMode.NONE
    return TwoFactorMode.AUTH_WINDOW if autofill else TwoFactorMode.IN_CLIENT


# --------------------------------------------------------------------------- #
# Flow                                                                         #
# --------------------------------------------------------------------------- #

def _needs_user(two_factor) -> bool:
    """A second factor that was not delivered is the user's move."""
    return two_factor is not None and two_factor.status in (
        TwoFactorStatus.TOKEN_REQUIRED, TwoFactorStatus.MANUAL_REQUIRED,
        TwoFactorStatus.BLOCKED, TwoFactorStatus.FAILED)


class _Phase:
    """Remembers which phase is running, so an unexpected exception lands on it."""

    def __init__(self):
        self.current: str | None = None


class FortiConnectFlow:
    """Runs the legacy connect sequence over seams.  Never raises.

    `provider` supplies detection (``_fortivpn_executable``,
    ``_sslvpn_client_executable``) and :meth:`launch`; `system` everything else.
    """

    def __init__(self, provider, system: FortiConnectSystem):
        self._provider = provider
        self._system = system

    def run(self, request: VpnRequest,
            entry: str = ENTRY_CONNECT_MONITORED) -> ConnectResult:
        steps: list[ConnectStep] = []
        if entry not in ENTRIES:
            return self._failure(request, steps, None, ErrorCode.CONNECT_FAILED,
                                 reason_code="unknown-entry")
        phase = _Phase()
        try:
            return self._run(request, entry, steps, phase)
        except Exception as exc:
            # Legacy lets these escape to the UI (see LEGACY_BEHAVIOR).
            steps.append(ConnectStep(phase.current or "unknown", STEP_FAILED,
                                     ErrorCode.CONNECT_FAILED.value,
                                     type(exc).__name__))
            return self._failure(request, steps, None, ErrorCode.CONNECT_FAILED,
                                 reason_code=type(exc).__name__)

    # -- the sequence ------------------------------------------------------ #

    def _run(self, request, entry, steps, phase) -> ConnectResult:
        system = self._system
        autofill = bool(request.autofill)
        cli_ok: bool | None = None

        # Detection first — the legacy has no such step (it discovers the
        # client by trying), so this one is *recorded and never fatal*: a
        # client that is already running is still found by the window probe
        # below, exactly as before, and a machine with nothing installed still
        # ends at `client-not-found` after the launch fails.
        phase.current = PHASE_DETECT
        detection = self._provider.detect(request)
        steps.append(ConnectStep(
            PHASE_DETECT,
            STEP_OK if detection.installed else STEP_NONE,
            detection.error_code if detection.state is DetectionState.ERROR else None,
            detection.state.value))

        # connect_monitored: the CLI goes first (vpn_connect.py:3628).
        if entry == ENTRY_CONNECT_MONITORED and autofill:
            cli_ok = self._probe_cli(request, steps, phase)
            if cli_ok:
                return self._cli(request, steps, phase, monitored=True)

        # connect() from here on (vpn_connect.py:2729).
        phase.current = PHASE_SESSION_RECORD
        system.record_session(request.profile_name or "", request.server or "")
        steps.append(ConnectStep(PHASE_SESSION_RECORD, STEP_OK))

        if not autofill and request.password:
            phase.current = PHASE_CREDENTIAL_COPY
            cancelled = self._cancelled(request, steps, PHASE_CREDENTIAL_COPY, None)
            if cancelled is not None:
                return cancelled
            copied = system.copy_to_clipboard(request.password)
            steps.append(ConnectStep(PHASE_CREDENTIAL_COPY,
                                     STEP_OK if copied else STEP_FAILED))

        # Fast path: the client window is already open.
        phase.current = PHASE_WINDOW_PROBE
        handle = system.find_main_window(FAST_PATH_WINDOW_TIMEOUT_S)
        steps.append(ConnectStep(PHASE_WINDOW_PROBE, STEP_OK if handle else STEP_NONE))
        if handle:
            # The legacy restores and raises the window here.  We do not: that
            # is the foreground steal Windows refuses from a background process
            # (Stages 18-20), and the activation gate below waits for the user
            # to do it instead.  The phase stays in the record so a trace still
            # shows the route the connect took.
            steps.append(ConnectStep(PHASE_WINDOW_RESTORE, STEP_NONE,
                                     reason_code="superseded-by-activation-gate"))
            return self._gui_outcome(request, steps, phase, ROUTE_WINDOW_RESTORE)

        # EMS authentication window already on screen (autofill only).
        if autofill:
            phase.current = PHASE_AUTH_WINDOW
            cancelled = self._cancelled(request, steps, PHASE_AUTH_WINDOW,
                                        ROUTE_EMS_AUTH_WINDOW)
            if cancelled is not None:
                return cancelled
            fill = system.fill_auth_window(request.login, request.password,
                                           AUTH_WINDOW_TIMEOUT_S)
            # The user called it off while the window was being filled (Stage
            # 48): stop here rather than launch the GUI on top of it.
            if getattr(fill, "cancelled", False):
                steps.append(ConnectStep(PHASE_AUTH_WINDOW, STEP_NONE,
                                         ErrorCode.CANCELLED.value,
                                         getattr(fill, "reason", None)))
                return self._failure(request, steps, ROUTE_EMS_AUTH_WINDOW,
                                     ErrorCode.CANCELLED,
                                     reason_code=ErrorCode.CANCELLED.value)
            # A guard refused after the login had already been sent: the window
            # is committed to, so do not fall through to a second attempt.
            if getattr(fill, "blocked", False) and fill.found:
                steps.append(ConnectStep(PHASE_AUTH_WINDOW, STEP_FAILED,
                                         fill.error_code,
                                         getattr(fill, "reason", None)))
                return self._failure(
                    request, steps, ROUTE_EMS_AUTH_WINDOW,
                    fill.error_code or ErrorCode.SECRET_INPUT_BLOCKED.value,
                    reason_code=getattr(fill, "reason", None))
            steps.append(ConnectStep(PHASE_AUTH_WINDOW,
                                     STEP_OK if fill.found else STEP_NONE))
            if fill.found:
                return self._success(
                    request, steps, ROUTE_EMS_AUTH_WINDOW,
                    state=VpnState.CONNECTING if fill.submitted else VpnState.UNKNOWN,
                    automation=AutomationMode.WM_SETTEXT,
                    requires_user_action=not fill.submitted)

        # Non-monitored CLI (reachable only through the `connect` entry).
        if cli_ok is None:
            cli_ok = self._probe_cli(request, steps, phase)
        if autofill and cli_ok and request.profile_name:
            result = self._cli(request, steps, phase, monitored=False)
            if result is not None:
                return result

        # Legacy FortiSSLVPNclient.exe (autofill only).
        if autofill:
            exe = self._provider._sslvpn_client_executable()
            if exe:
                phase.current = PHASE_LEGACY_CLIENT
                cancelled = self._cancelled(request, steps, PHASE_LEGACY_CLIENT,
                                            ROUTE_LEGACY_CLIENT)
                if cancelled is not None:
                    return cancelled
                address = (f"{request.server}:{request.port}" if request.port
                           else request.server)
                try:
                    system.start_legacy_client(exe, address, request.login,
                                               request.password)
                except Exception as exc:
                    steps.append(ConnectStep(PHASE_LEGACY_CLIENT, STEP_FAILED,
                                             ErrorCode.LAUNCH_FAILED.value,
                                             type(exc).__name__))
                else:
                    steps.append(ConnectStep(PHASE_LEGACY_CLIENT, STEP_OK))
                    return self._success(request, steps, ROUTE_LEGACY_CLIENT,
                                         state=VpnState.CONNECTING,
                                         automation=AutomationMode.CLI)

        # Open the client (Stage 8/9 launch) and hand over to autofill or user.
        phase.current = PHASE_LAUNCH
        cancelled = self._cancelled(request, steps, PHASE_LAUNCH, ROUTE_GUI_LAUNCH)
        if cancelled is not None:
            return cancelled
        launch: LaunchResult = self._provider.launch(request)
        steps.append(ConnectStep(PHASE_LAUNCH, STEP_OK if launch.success else STEP_FAILED,
                                 None if launch.success else launch.error_code))
        if not launch.success:
            return self._failure(request, steps, ROUTE_GUI_LAUNCH,
                                 launch.error_code or ErrorCode.CLIENT_NOT_FOUND.value,
                                 launch=launch)
        return self._gui_outcome(request, steps, phase, ROUTE_GUI_LAUNCH, launch=launch)

    # -- phases shared by several branches ---------------------------------- #

    def _probe_cli(self, request, steps, phase) -> bool:
        phase.current = PHASE_CLI_PROBE
        supported = bool(self._system.cli_supported(request.app_path))
        steps.append(ConnectStep(PHASE_CLI_PROBE, STEP_OK if supported else STEP_NONE))
        return supported

    def _cli(self, request, steps, phase, *, monitored: bool):
        phase.current = PHASE_CLI_CONNECT
        fortivpn = self._provider._fortivpn_executable(request.app_path)
        route = ROUTE_CLI_MONITORED if monitored else ROUTE_CLI
        cancelled = self._cancelled(request, steps, PHASE_CLI_CONNECT, route)
        if cancelled is not None:
            return cancelled
        try:
            monitor = self._system.start_cli(
                fortivpn, request.profile_name, request.login, request.password,
                request.token if monitored else "", monitored)
        except Exception as exc:
            steps.append(ConnectStep(PHASE_CLI_CONNECT, STEP_FAILED,
                                     ErrorCode.LAUNCH_FAILED.value, type(exc).__name__))
            if monitored:                         # legacy: no fallback here
                return self._failure(request, steps, route, ErrorCode.LAUNCH_FAILED,
                                     reason_code=type(exc).__name__)
            return None                           # connect(): fall through
        steps.append(ConnectStep(PHASE_CLI_CONNECT, STEP_OK))
        monitor = monitor if monitored else None
        two_factor = self._two_factor(request, steps, phase, route, monitor=monitor)
        return self._success(request, steps, route, state=VpnState.CONNECTING,
                             automation=AutomationMode.CLI, monitor=monitor,
                             two_factor_result=two_factor,
                             requires_user_action=_needs_user(two_factor))

    def _gui_outcome(self, request, steps, phase, route, launch=None) -> ConnectResult:
        """The client window is there: fill the form, or leave it to the user."""
        if not request.autofill:
            # Manual: the password is already on the clipboard, the window is
            # up, and nothing is typed.  2FA is skipped here exactly as both UI
            # panels skip it when autofill is off.
            return self._success(request, steps, route, state=VpnState.UNKNOWN,
                                 automation=AutomationMode.MANUAL,
                                 requires_user_action=True, launch=launch)

        # The client's window has to be the one the user is looking at before
        # a single key is sent.  The gate only decides *whether to start*; the
        # guards inside the autofill remain the authority on every secret.
        phase.current = PHASE_AWAIT_ACTIVATION
        activation = self._system.await_activation()
        if activation is not None:
            steps.append(ConnectStep(
                PHASE_AWAIT_ACTIVATION,
                STEP_OK if activation.ok else STEP_FAILED,
                None if activation.ok else ErrorCode.FOCUS_FAILED.value,
                activation.state.value))
            if not activation.ok:
                # Nothing was typed and nothing was blocked mid-way: the user
                # simply never brought the client forward.  The connect itself
                # still started — the client is open and they can type.
                return self._success(
                    request, steps, route, state=VpnState.UNKNOWN,
                    automation=AutomationMode.MANUAL, requires_user_action=True,
                    launch=launch, error_code=ErrorCode.FOCUS_FAILED.value)

            # The gate spoke at one instant; the first secret moves seconds
            # later.  Ask the desktop once more, and ask it strictly — in
            # front, owned, not minimised — before anything reaches for the
            # window.  This is a reading: it never restores, raises or types,
            # and `acquire_focus` (which would) is still further down.
            still = self._system.activation_still_holds(activation.hwnd)
            if still is not None and not still.ok:
                steps.append(ConnectStep(PHASE_AWAIT_ACTIVATION, STEP_FAILED,
                                         ErrorCode.FOCUS_FAILED.value,
                                         still.reason))
                return self._success(
                    request, steps, route, state=VpnState.UNKNOWN,
                    automation=AutomationMode.MANUAL, requires_user_action=True,
                    launch=launch, error_code=ErrorCode.FOCUS_FAILED.value,
                    autofill=AutofillResult(
                        provider_id=self._provider.id, success=False,
                        status=AutofillStatus.BLOCKED,
                        blocked_at=PHASE_AWAIT_ACTIVATION,
                        error_code=ErrorCode.FOCUS_FAILED.value))

        phase.current = PHASE_AUTOFILL
        filled = self._system.start_autofill(request.login, request.password,
                                             request.profile_name)
        if filled is None:
            # Legacy shape: a thread was started and nobody waits for it.
            steps.append(ConnectStep(PHASE_AUTOFILL, STEP_OK))
            return self._success(request, steps, route, state=VpnState.CONNECTING,
                                 automation=AutomationMode.TAB_SEQUENCE,
                                 automation_pending=True, launch=launch)

        if filled.status is AutofillStatus.CANCELLED:
            # The user called it off mid-fill.  Not a security block and not a
            # success: nothing further was typed, no Enter, clipboard restored
            # (Stage 47).  A finished, unsuccessful, unambiguously CANCELLED
            # result — the flow does not pretend the connect started.
            steps.append(ConnectStep(PHASE_AUTOFILL, STEP_NONE,
                                     ErrorCode.CANCELLED.value, filled.blocked_at))
            return self._failure(request, steps, route, ErrorCode.CANCELLED,
                                 reason_code=ErrorCode.CANCELLED.value,
                                 launch=launch, autofill=filled)

        done = filled.status is AutofillStatus.DONE
        steps.append(ConnectStep(PHASE_AUTOFILL, STEP_OK if done else STEP_FAILED,
                                 None if done else filled.error_code,
                                 None if done else filled.blocked_at))
        if not done:
            # The client is open and the user can still type: the connect was
            # started, it just automated nothing.  Refusing to say so would
            # hide a security block from the caller.
            return self._success(
                request, steps, route, state=VpnState.UNKNOWN,
                automation=AutomationMode.MANUAL, requires_user_action=True,
                launch=launch, autofill=filled, error_code=filled.error_code)

        two_factor = self._two_factor(request, steps, phase, route, monitor=None)
        return self._success(request, steps, route, state=VpnState.CONNECTING,
                             automation=AutomationMode.TAB_SEQUENCE,
                             launch=launch, autofill=filled,
                             two_factor_result=two_factor,
                             requires_user_action=_needs_user(two_factor))

    def _two_factor(self, request, steps, phase, route, *, monitor):
        """Hand the second factor to the migrated component, if there is one.

        Returns ``None`` when the system does not do 2FA (the legacy shape, in
        which the UI asks the user after connect has returned) — the mode in
        :class:`ConnectResult` still says how it could be supplied.
        """
        mode = plan_two_factor(route=route, monitor_available=monitor is not None,
                               autofill=bool(request.autofill),
                               requires_2fa=bool(request.requires_2fa))
        if mode is TwoFactorMode.NONE:
            return None
        phase.current = PHASE_TWO_FACTOR
        result = self._system.supply_two_factor(request, mode, monitor)
        if result is None:
            return None
        ok = result.status in (TwoFactorStatus.SUBMITTED,
                               TwoFactorStatus.NOT_REQUIRED)
        steps.append(ConnectStep(PHASE_TWO_FACTOR,
                                 STEP_OK if ok else STEP_FAILED,
                                 None if ok else result.error_code,
                                 result.status.value))
        return result

    # -- cancellation (Stage 47) ------------------------------------------- #

    def _cancelled(self, request, steps, phase_name, route):
        """A finished, unsuccessful result if the caller has called it off.

        Recorded as the phase that did **not** run, so a trace shows exactly
        which side effect the Cancel prevented.  ``getattr`` because a system
        written before Stage 47 need not know the question.
        """
        ask = getattr(self._system, "cancel_requested", None)
        if ask is None or not ask():
            return None
        steps.append(ConnectStep(phase_name, STEP_NONE, ErrorCode.CANCELLED.value,
                                 ErrorCode.CANCELLED.value))
        return self._failure(request, steps, route, ErrorCode.CANCELLED,
                             reason_code=ErrorCode.CANCELLED.value)

    # -- results ------------------------------------------------------------ #

    def _success(self, request, steps, route, *, state, automation,
                 requires_user_action=False, automation_pending=False,
                 monitor=None, launch=None, autofill=None,
                 two_factor_result=None, error_code=None) -> ConnectResult:
        return ConnectResult(
            provider_id=self._provider.id, success=True, state=state,
            automation=automation, requires_user_action=requires_user_action,
            monitor=monitor, route=route, automation_pending=automation_pending,
            two_factor=plan_two_factor(route=route, monitor_available=monitor is not None,
                                       autofill=bool(request.autofill),
                                       requires_2fa=bool(request.requires_2fa)),
            steps=tuple(steps), launch=launch, autofill=autofill,
            two_factor_result=two_factor_result, error_code=error_code)

    def _failure(self, request, steps, route, error_code, *, reason_code=None,
                 launch=None, autofill=None) -> ConnectResult:
        code = error_code.value if isinstance(error_code, ErrorCode) else error_code
        return ConnectResult(
            provider_id=self._provider.id, success=False, state=VpnState.UNKNOWN,
            automation=AutomationMode.NONE, route=route, error_code=code,
            steps=tuple(steps), launch=launch, autofill=autofill,
            metadata={"reason_code": reason_code} if reason_code else {})
