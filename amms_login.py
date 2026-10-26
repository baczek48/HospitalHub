"""AMMS button (2026-10-26): open a hospital's web AMMS and sign in.

The AMMS login page is an Angular app (``an-login-form``) inside a
same-origin frame of ``index.html``.  Its password field is a text input
masked by CSS (``axDisplayAsPassword``), so a password manager does not see a
login form there.  Both fields take their value from the ``input`` event, so
the form is filled from inside the page:

* Chrome (or Edge when there is no Chrome) is started with a profile of its
  own and ``--remote-debugging-port=0``.  Chrome 136+ refuses remote
  debugging on the user's default profile, and a profile of its own keeps
  AMMS away from the user's browsing.  The port is read from
  ``DevToolsActivePort`` in that profile and listens on 127.0.0.1 only.
* Every click starts the browser with the URL, as opening a link does: the
  first click starts it, later ones become a new tab of the running one.
  The tab is the page target that was not there before.
* Over the DevTools protocol the page is asked, every 0.3 s, for a visible
  login form in any of its frames; the login and the password are put in
  with the input's own value setter and an ``input`` event, read back, and
  "Zaloguj" (``#btnLogIn``) is clicked once it is enabled.

Nothing goes through the clipboard or the keyboard.  The credentials go only
to the browser's DevTools socket on 127.0.0.1, never into a URL.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# -- outcomes ------------------------------------------------------------- #

LOGGED_IN = "logged-in"            # the form went away after "Zaloguj"
NEEDS_2FA = "needs-2fa"            # AMMS asks for a 2FA code — the user types it
SUBMITTED = "submitted"            # clicked; the form is still there, nothing said why
REJECTED = "rejected"              # AMMS answered with a message box (e.g. a wrong password)
OPENED = "opened"                  # no login saved: the page is only opened
NO_BROWSER = "no-browser"          # neither Chrome nor Edge found
BROWSER_FAILED = "browser-failed"  # the browser did not start or gave no DevTools
FORM_NOT_FOUND = "form-not-found"  # no login form on the page in time
FILL_MISMATCH = "fill-mismatch"    # the fields did not take the values
CANCELLED = "cancelled"
ERROR = "error"


@dataclass
class AmmsResult:
    outcome: str
    detail: str = ""


class CdpError(Exception):
    """The browser's DevTools endpoint failed or answered with an error."""


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if url and not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    return url


# -- browser -------------------------------------------------------------- #

def _app_path(exe: str) -> str | None:
    try:
        import winreg
    except ImportError:
        return None
    key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" + "\\" + exe
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, key) as k:
                value = winreg.QueryValue(k, None)
        except OSError:
            continue
        if value and os.path.isfile(value.strip('"')):
            return value.strip('"')
    return None


def find_browser() -> str | None:
    """Chrome, else Edge; None when neither is installed."""
    found = _app_path("chrome.exe")
    if found:
        return found
    env = os.environ
    candidates = [
        Path(env.get("ProgramFiles", r"C:\Program Files")) / "Google/Chrome/Application/chrome.exe",
        Path(env.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
        Path(env.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    found = _app_path("msedge.exe")
    if found:
        return found
    for base in (env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                 env.get("ProgramFiles", r"C:\Program Files")):
        c = Path(base) / "Microsoft/Edge/Application/msedge.exe"
        if c.is_file():
            return str(c)
    return None


def profile_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
    return Path(base) / "HospitalHubV2" / "amms_browser"


# No proxy for 127.0.0.1, whatever the environment says.
_LOCAL = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _http_json(port: int, path: str, timeout: float = 2.0):
    with _LOCAL.open(f"http://127.0.0.1:{port}{path}", timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


class Browser:
    """The AMMS browser: one profile, its DevTools port, its page targets."""

    def __init__(self, exe: str, profile: Path):
        self.exe = exe
        self.profile = Path(profile)

    def port(self) -> int | None:
        """The DevTools port of the running browser of this profile, or None."""
        try:
            first = (self.profile / "DevToolsActivePort").read_text(
                encoding="ascii").splitlines()[0]
            port = int(first)
            _http_json(port, "/json/version", timeout=1.0)
            return port
        except (OSError, ValueError, IndexError):
            return None

    def pages(self, port: int) -> list[dict]:
        return [t for t in _http_json(port, "/json/list")
                if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]

    def launch(self, url: str) -> None:
        self.profile.mkdir(parents=True, exist_ok=True)
        flags = 0
        if os.name == "nt":
            flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        subprocess.Popen(
            [self.exe, f"--user-data-dir={self.profile}",
             "--remote-debugging-port=0", "--no-first-run",
             "--no-default-browser-check", url],
            close_fds=True, creationflags=flags,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)

    def open(self, url: str, *, timeout: float = 20.0, sleep=time.sleep,
             clock=time.monotonic, should_stop=lambda: False) -> dict | None:
        """Open url in a new tab; the tab's target, or None."""
        port = self.port()
        before = {t["id"] for t in self.pages(port)} if port else set()
        self.launch(url)
        deadline = clock() + timeout
        while clock() < deadline and not should_stop():
            port = self.port()
            if port:
                try:
                    fresh = [t for t in self.pages(port) if t["id"] not in before]
                except (OSError, ValueError):
                    fresh = []
                if fresh:
                    return fresh[0]
            sleep(0.25)
        return None


# -- DevTools protocol ---------------------------------------------------- #

class _WebSocket:
    """The little of RFC 6455 a DevTools socket needs: text frames, ping."""

    _GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    def __init__(self, url: str, timeout: float = 10.0):
        u = urllib.parse.urlsplit(url)
        self._sock = socket.create_connection((u.hostname, u.port), timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        self._sock.sendall((
            f"GET {u.path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii"))
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self._sock.recv(1024)
            if not chunk:
                raise CdpError("websocket handshake: connection closed")
            head += chunk
        head, self._buf = head.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        if " 101 " not in lines[0] + " ":
            raise CdpError(f"websocket handshake: {lines[0]}")
        accept = base64.b64encode(
            hashlib.sha1((key + self._GUID).encode("ascii")).digest()).decode("ascii")
        if not any(l.lower().startswith("sec-websocket-accept:")
                   and l.split(":", 1)[1].strip() == accept for l in lines[1:]):
            raise CdpError("websocket handshake: bad accept key")

    def _exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise CdpError("websocket closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        head = bytes([0x80 | opcode])
        n = len(payload)
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(head + mask + body)

    def send(self, text: str) -> None:
        self._send_frame(0x1, text.encode("utf-8"))

    def recv(self) -> str:
        parts = []
        while True:
            b0, b1 = self._exact(2)
            opcode, n = b0 & 0x0F, b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._exact(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._exact(8))[0]
            mask = self._exact(4) if b1 & 0x80 else None
            payload = self._exact(n)
            if mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                raise CdpError("websocket closed by the browser")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode in (0x0, 0x1):
                parts.append(payload)
                if b0 & 0x80:
                    return b"".join(parts).decode("utf-8")

    def close(self) -> None:
        try:
            self._send_frame(0x8, b"")
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


class Page:
    """One tab, driven over its DevTools websocket."""

    def __init__(self, ws_url: str, timeout: float = 10.0):
        self._ws = _WebSocket(ws_url, timeout)
        self._id = 0

    def call(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        self._ws.send(json.dumps({"id": self._id, "method": method,
                                  "params": params or {}}))
        while True:
            msg = json.loads(self._ws.recv())
            if msg.get("id") == self._id:
                if "error" in msg:
                    raise CdpError(msg["error"].get("message", "error"))
                return msg.get("result", {})

    def evaluate(self, expression: str):
        res = self.call("Runtime.evaluate",
                        {"expression": expression, "returnByValue": True})
        if "exceptionDetails" in res:
            raise CdpError(res["exceptionDetails"].get("text", "exception"))
        return res.get("result", {}).get("value")

    def close(self) -> None:
        self._ws.close()


# -- the login form ------------------------------------------------------- #

#: One function for every step; ``mode`` is "probe", "fill" or "submit".
#: Arguments come in as JSON literals, so no value can break out of them.
_FORM_JS = r"""
(function (mode, login, password) {
  function shown(el) { return !!el && el.getClientRects().length > 0; }
  function collect(w, out) {
    var d;
    try { d = w.document; } catch (e) { return out; }
    if (!d) { return out; }
    out.push(d);
    for (var i = 0; i < w.frames.length; i++) { collect(w.frames[i], out); }
    return out;
  }
  var docs = collect(window, []);
  for (var i = 0; i < docs.length; i++) {
    if (shown(docs[i].querySelector('input.mfa-code-input'))) {
      return {state: 'mfa'};
    }
  }
  var form = null;
  for (var j = 0; j < docs.length; j++) {
    var user = docs[j].querySelector('input[aria-labelledby="lblUser"]');
    if (shown(user)) {
      form = {user: user,
              pass: docs[j].querySelector('input[aria-labelledby="lblPassword"]'),
              button: docs[j].getElementById('btnLogIn')};
      break;
    }
  }
  if (!form) { return {state: 'none', frames: docs.length}; }
  if (mode === 'probe') {
    // "Próba logowania nie powiodła się" comes as a message box over the form.
    var message = '';
    for (var k = 0; k < docs.length; k++) {
      var box = docs[k].querySelector('.messagebox-dialog');
      if (shown(box)) {
        var body = box.querySelector('.ax-text-wrap') || box;
        message = body.textContent.replace(/\s+/g, ' ').trim().slice(0, 200);
        break;
      }
    }
    return {state: 'form', hasPassword: shown(form.pass), message: message};
  }
  function put(el, value) {
    var view = el.ownerDocument.defaultView;
    var setter = Object.getOwnPropertyDescriptor(
      view.HTMLInputElement.prototype, 'value').set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new view.Event('input', {bubbles: true}));
    el.dispatchEvent(new view.Event('change', {bubbles: true}));
    el.blur();
  }
  if (mode === 'fill') {
    if (!shown(form.pass)) { return {state: 'no-password'}; }
    put(form.user, login);
    put(form.pass, password);
    return {state: 'filled', user: form.user.value,
            passLength: form.pass.value.length};
  }
  if (mode === 'submit') {
    var b = form.button;
    if (shown(b)) {
      if (b.disabled || b.classList.contains('ax-disabled')
          || b.getAttribute('aria-disabled') === 'true') {
        return {state: 'button-disabled'};
      }
      b.click();
      return {state: 'clicked'};
    }
    var view = form.pass.ownerDocument.defaultView;
    form.pass.dispatchEvent(new view.KeyboardEvent('keydown',
      {key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true}));
    return {state: 'entered'};
  }
  return {state: 'unknown-mode'};
})
"""


def form_call(mode: str, login: str = "", password: str = "") -> str:
    return (_FORM_JS.strip() + "(" + json.dumps(mode) + ", "
            + json.dumps(login) + ", " + json.dumps(password) + ")")


def _ask(page, mode, login="", password="") -> dict:
    """One step on the page; a page between navigations reads as no form."""
    try:
        value = page.evaluate(form_call(mode, login, password))
    except CdpError as e:
        return {"state": "none", "error": str(e)}
    return value if isinstance(value, dict) else {"state": "none"}


def fill_and_submit(page, login: str, password: str, *, progress=lambda s: None,
                    should_stop=lambda: False, sleep=time.sleep,
                    clock=time.monotonic, form_timeout: float = 60.0,
                    result_timeout: float = 15.0) -> AmmsResult:
    """Wait for the login form, fill it, click "Zaloguj", watch what follows."""
    progress("Czekam na stronę logowania AMMS…")
    deadline = clock() + form_timeout
    while True:
        if should_stop():
            return AmmsResult(CANCELLED)
        state = _ask(page, "probe")
        if state["state"] == "mfa":
            return AmmsResult(NEEDS_2FA)
        if state["state"] == "form" and state.get("hasPassword"):
            break
        if clock() >= deadline:
            return AmmsResult(FORM_NOT_FOUND)
        sleep(0.3)

    # The page settles after the form shows (the login field's blur handler
    # asks the server about the user); two tries, the second after a pause.
    for attempt in range(2):
        if should_stop():
            return AmmsResult(CANCELLED)
        progress("Wpisuję login i hasło…")
        filled = _ask(page, "fill", login, password)
        ok = (filled.get("state") == "filled"
              and str(filled.get("user", "")).lower() == login.lower()
              and filled.get("passLength") == len(password))
        if ok:
            break
        if attempt == 0:
            sleep(0.7)
    else:
        return AmmsResult(FILL_MISMATCH, str(filled.get("state", "")))

    progress("Loguję…")
    deadline = clock() + 5.0
    while True:
        if should_stop():
            return AmmsResult(CANCELLED)
        sent = _ask(page, "submit")
        if sent.get("state") in ("clicked", "entered"):
            break
        if sent.get("state") == "mfa":
            return AmmsResult(NEEDS_2FA)
        if clock() >= deadline:
            return AmmsResult(SUBMITTED, "button-disabled")
        sleep(0.3)

    deadline = clock() + result_timeout
    while clock() < deadline:
        sleep(0.5)
        state = _ask(page, "probe")
        if state["state"] == "mfa":
            return AmmsResult(NEEDS_2FA)
        if state["state"] == "none" and not state.get("error"):
            return AmmsResult(LOGGED_IN)
        if state.get("message"):
            return AmmsResult(REJECTED, state["message"])
    return AmmsResult(SUBMITTED)


def sign_in(url: str, login: str, password: str, *, progress=lambda s: None,
            should_stop=lambda: False, browser: Browser | None = None,
            page_factory=Page) -> AmmsResult:
    """Open url in the AMMS browser and, with a login, sign in there."""
    url = normalize_url(url)
    if browser is None:
        exe = find_browser()
        if not exe:
            return AmmsResult(NO_BROWSER)
        browser = Browser(exe, profile_dir())
    progress("Otwieram przeglądarkę…")
    try:
        target = browser.open(url, should_stop=should_stop)
    except OSError as e:
        return AmmsResult(BROWSER_FAILED, str(e))
    if should_stop():
        return AmmsResult(CANCELLED)
    if target is None:
        return AmmsResult(BROWSER_FAILED, "no-devtools-target")
    if not login:
        return AmmsResult(OPENED)
    try:
        page = page_factory(target["webSocketDebuggerUrl"])
    except (OSError, CdpError) as e:
        return AmmsResult(BROWSER_FAILED, str(e))
    try:
        try:
            # A tab behind another window still runs focus/blur handlers.
            page.call("Emulation.setFocusEmulationEnabled", {"enabled": True})
        except CdpError:
            pass
        return fill_and_submit(page, login, password, progress=progress,
                               should_stop=should_stop)
    except (OSError, CdpError) as e:
        return AmmsResult(ERROR, str(e))
    finally:
        page.close()
