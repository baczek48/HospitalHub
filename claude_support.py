"""Wsparcie Claude: a Claude Code conversation about one SSH terminal tab.

2026-10-20 (owner): "I have a terminal open and you work on that terminal
while I talk to you — find an error, verify something", with the
conversation held inside HospitalHub.  Two pieces, no Qt here:

* :class:`ToolServer` — a Model Context Protocol server over HTTP, bound to
  127.0.0.1 on a random port, with a random bearer token per support
  session.  It offers one tool — read the shared terminal — and hands every
  call to a handler supplied by the UI.  Read only, by the owner's choice of
  2026-10-20: Claude reads and advises, the owner types every command.
* :class:`ClaudeProcess` — Claude Code started in the background
  (``claude -p`` with stream-json in and out), with **no built-in tools at
  all** (``--tools ""``: no file access, no shell on this computer, no web),
  only this server (``--strict-mcp-config``), only its one tool allowed,
  and ``--permission-mode dontAsk`` refusing anything else.  It runs on the
  user's own Claude Code login; nothing here holds a key.

What the model sees is what the terminal shows.  Passwords and the vault
never pass through here: the SSH session is already logged in, and the tool
can only read the screen of that one tab — it cannot type.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = ["ToolServer", "ClaudeProcess", "find_claude", "TOOLS", "SERVER_NAME",
           "TOOL_READ", "allowed_tool_names"]

SERVER_NAME = "hospitalhub"
TOOL_READ = "terminal_read"

TOOLS = [
    {
        "name": TOOL_READ,
        "description": (
            "Read what the shared SSH terminal shows: the last lines of its "
            "scrollback and the visible screen. Use it before proposing a "
            "command and whenever you need to see the current state."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "lines": {"type": "integer", "minimum": 10, "maximum": 2000,
                          "description": "How many lines from the end (default 150)."},
            },
            "additionalProperties": False,
        },
    }
]


def allowed_tool_names() -> list[str]:
    return [f"mcp__{SERVER_NAME}__{t['name']}" for t in TOOLS]


# ══════════════════════════════════════════════════════════════════════════
# The tool server
# ══════════════════════════════════════════════════════════════════════════

class ToolServer:
    """A minimal MCP server (Streamable HTTP, JSON responses) on 127.0.0.1.

    `handler(name, arguments) -> (text, is_error)` runs in the server's
    request thread and may block (an approval waits for the user).
    """

    def __init__(self, handler):
        self._handler = handler
        self.token = secrets.token_urlsafe(32)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        if self._server is None:
            return ""
        return f"http://127.0.0.1:{self._server.server_address[1]}/mcp"

    def start(self) -> str:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):        # no console output
                pass

            def _send(self, code, obj=None):
                body = b"" if obj is None else json.dumps(obj).encode("utf-8")
                self.send_response(code)
                if obj is not None:
                    self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._send(405)

            def do_DELETE(self):
                self._send(405)

            def do_POST(self):
                # The body first, then the token: answering before reading
                # makes Windows reset the connection under the client.
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    raw = self.rfile.read(size) if size > 0 else b""
                except Exception:
                    return self._send(400)
                if self.headers.get("Authorization") != "Bearer " + outer.token:
                    return self._send(401)
                try:
                    message = json.loads(raw or b"{}")
                except Exception:
                    return self._send(400)
                reply = outer.handle(message)
                if reply is None:
                    return self._send(202)
                self._send(200, reply)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="claude-tools", daemon=True)
        self._thread.start()
        return self.url

    def stop(self) -> None:
        """Returns at once; the server winds down in the background
        (``shutdown`` waits for the serve loop — it froze "Zakończ")."""
        server, self._server = self._server, None
        if server is None:
            return

        def close():
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass

        threading.Thread(target=close, name="claude-tools-stop", daemon=True).start()

    # -- JSON-RPC ------------------------------------------------------------ #

    def handle(self, message: dict):
        """One JSON-RPC message → the reply object, or None for a notification."""
        method = message.get("method")
        mid = message.get("id")
        if mid is None:
            return None
        if method == "initialize":
            params = message.get("params") or {}
            result = {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": SERVER_NAME, "version": "1"}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = message.get("params") or {}
            name = params.get("name", "")
            if name not in {t["name"] for t in TOOLS}:
                return _error(mid, -32602, f"unknown tool: {name}")
            try:
                text, is_error = self._handler(name, params.get("arguments") or {})
            except Exception as exc:
                text, is_error = f"HospitalHub: błąd narzędzia ({type(exc).__name__})", True
            result = {"content": [{"type": "text", "text": text}],
                      "isError": bool(is_error)}
        else:
            return _error(mid, -32601, f"method not found: {method}")
        return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid, code, text):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": text}}


# ══════════════════════════════════════════════════════════════════════════
# Claude Code in the background
# ══════════════════════════════════════════════════════════════════════════

def find_claude() -> str | None:
    """Claude Code's executable: the native one if present, else the npm shim."""
    for name in ("claude.exe", "claude.cmd", "claude"):
        path = shutil.which(name)
        if path:
            return path
    home = os.path.expanduser("~")
    for candidate in (os.path.join(home, ".local", "bin", "claude.exe"),
                      os.path.join(os.environ.get("APPDATA", ""), "npm", "claude.cmd")):
        if os.path.isfile(candidate):
            return candidate
    return None


def _clean_environment() -> dict:
    """Our environment without the PyInstaller keys (a child should not see them)."""
    return {k: v for k, v in os.environ.items()
            if not (k.startswith("_MEI") or k.startswith("_PYI"))}


class ClaudeProcess:
    """One Claude Code conversation over stream-json.

    `on_event(kind, payload)` is called from a reader thread:

    * ``("ready", {"connected": bool})`` — the session started; whether the
      HospitalHub tool server is connected;
    * ``("text", str)`` — a piece of Claude's answer;
    * ``("tool", name)`` — Claude is using one of the tools;
    * ``("turn_end", {"is_error": bool, "text": str})`` — the answer is complete;
    * ``("exit", {"code": int, "stderr": str})`` — the process ended.
    """

    def __init__(self, server_url: str, token: str, system_prompt: str, on_event,
                 *, executable: str | None = None, spawn=subprocess.Popen):
        self._url = server_url
        self._token = token
        self._prompt = system_prompt
        self._on_event = on_event
        self._executable = executable
        self._spawn = spawn
        self._proc = None
        self._dir: str | None = None
        self._stderr: list[str] = []
        self._lock = threading.Lock()

    def command(self, executable: str, workdir: str) -> list[str]:
        config = os.path.join(workdir, "mcp.json")
        prompt = os.path.join(workdir, "prompt.txt")
        return [executable, "-p",
                "--input-format", "stream-json", "--output-format", "stream-json",
                "--verbose",
                "--tools", "",
                "--mcp-config", config, "--strict-mcp-config",
                "--allowedTools", *allowed_tool_names(),
                "--permission-mode", "dontAsk",
                "--setting-sources", "",
                "--no-session-persistence",
                "--append-system-prompt-file", prompt]

    def start(self) -> None:
        executable = self._executable or find_claude()
        if not executable:
            raise FileNotFoundError("claude")
        self._dir = tempfile.mkdtemp(prefix="hh-claude-")
        with open(os.path.join(self._dir, "mcp.json"), "w", encoding="utf-8") as f:
            json.dump({"mcpServers": {SERVER_NAME: {
                "type": "http", "url": self._url,
                "headers": {"Authorization": "Bearer " + self._token}}}}, f)
        with open(os.path.join(self._dir, "prompt.txt"), "w", encoding="utf-8") as f:
            f.write(self._prompt)
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._proc = self._spawn(
            self.command(executable, self._dir), cwd=self._dir,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
            env=_clean_environment(), creationflags=flags)
        threading.Thread(target=self._read_stdout, name="claude-out", daemon=True).start()
        threading.Thread(target=self._read_stderr, name="claude-err", daemon=True).start()

    def send(self, text: str) -> None:
        with self._lock:
            proc = self._proc
            if proc is None or proc.stdin is None:
                raise RuntimeError("claude is not running")
            proc.stdin.write(json.dumps({"type": "user", "message": {
                "role": "user", "content": text}}, ensure_ascii=False) + "\n")
            proc.stdin.flush()

    def stop(self) -> None:
        """Returns at once: closing stdin ends Claude Code (measured ~0.5 s);
        a process still there after 2 s is killed — in the background, the
        UI thread waited for it before (owner: "wyłączenie trwało chwilę")."""
        with self._lock:
            proc, self._proc = self._proc, None
        workdir, self._dir = self._dir, None
        if proc is not None:
            try:
                proc.stdin.close()
            except Exception:
                pass

        def finish():
            if proc is not None:
                try:
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            if workdir:
                shutil.rmtree(workdir, ignore_errors=True)

        threading.Thread(target=finish, name="claude-stop", daemon=True).start()

    # -- readers ------------------------------------------------------------- #

    def _emit(self, kind, payload) -> None:
        try:
            self._on_event(kind, payload)
        except Exception:
            pass

    def _read_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        for line in proc.stderr:
            self._stderr.append(line.rstrip())
            del self._stderr[:-40]

    def _read_stdout(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            self.handle_event(event)
        code = proc.wait() if proc else -1
        self._emit("exit", {"code": code, "stderr": "\n".join(self._stderr[-15:])})

    def handle_event(self, event: dict) -> None:
        kind = event.get("type")
        if kind == "system" and event.get("subtype") == "init":
            servers = event.get("mcp_servers") or []
            connected = any(s.get("name") == SERVER_NAME and s.get("status") == "connected"
                            for s in servers if isinstance(s, dict))
            self._emit("ready", {"connected": connected})
        elif kind == "assistant":
            for block in (event.get("message") or {}).get("content") or []:
                if block.get("type") == "text" and block.get("text"):
                    self._emit("text", block["text"])
                elif block.get("type") == "tool_use":
                    self._emit("tool", str(block.get("name", "")))
        elif kind == "result":
            self._emit("turn_end", {"is_error": bool(event.get("is_error")),
                                    "text": str(event.get("result") or "")})
