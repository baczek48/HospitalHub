"""The system seam for launching a VPN client.

The only module under ``vpn/`` allowed to start processes, and deliberately
tiny: each operation is a line-for-line mirror of what the legacy does at that
point in `vpn_connect.py`.  Providers receive a :class:`LaunchSystem` and never
call `subprocess` themselves, so every launch path can be exercised with a fake
machine and no real client.

Three of the operations open the client's window (Stage 8/9); the other three
were added for connect (Stage 16) and start the client's *command line*
instead.  They live here rather than in a second module for one reason: there
should be exactly one place in ``vpn/`` that can create a process.

Detection never receives this object — it reads the registry and the disk
through :class:`vpn.providers.forticlient.DetectionEnvironment` only.

What is mirrored (constants are pinned by tests against the legacy source):

=====================  =====================================================
``open_with_explorer``  ``subprocess.Popen(["explorer.exe", lnk])``
``spawn_detached``      ``Popen([exe], env=_clean_pyinstaller_env(), cwd=cwd,
                        creationflags=DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP,
                        close_fds=True)``
``wait_for_process``    ``_wait_for_process`` — ``tasklist`` every 0.25 s
                        until the image appears or the timeout elapses
``run_capture``         ``subprocess.run(cmd, capture_output=True, text=True,
                        timeout=…, hidden)`` — the ``--cli --status`` probe of
                        ``_is_fortivpn_cli_supported``
``spawn_hidden``        ``Popen(cmd, startupinfo=hidden, CREATE_NO_WINDOW)`` —
                        the unmonitored CLI connect and the legacy
                        ``FortiSSLVPNclient.exe``
``spawn_monitored``     the same with ``stdin=PIPE, stdout=PIPE,
                        stderr=STDOUT`` — ``connect_monitored``
=====================  =====================================================

The wait is part of launching, not a status check: the legacy decides whether
the ``.lnk`` strategy worked by looking for ``FortiClient.exe`` right after it,
and nowhere else.  Nothing here polls on its own.

``subprocess`` and ``time`` are imported inside the methods, so ``import vpn``
(which registers the providers) still loads no process machinery at all.
"""

from __future__ import annotations

import os

__all__ = ["LaunchSystem", "WindowsLaunchSystem", "clean_pyinstaller_env"]

EXPLORER_EXE = "explorer.exe"
#: ``_wait_for_process``: sleep between probes.
POLL_INTERVAL_S = 0.25
#: ``_is_process_running``: timeout of one ``tasklist`` call.
TASKLIST_TIMEOUT_S = 5
#: ``_is_fortivpn_cli_supported``: timeout of the ``--cli --status`` probe.
CLI_PROBE_TIMEOUT_S = 5


class LaunchSystem:
    """What launching may do to the machine.  Tests substitute a fake."""

    def open_with_explorer(self, path: str) -> None:
        """Hand `path` to ``explorer.exe``.  Raises when the spawn fails."""
        raise NotImplementedError

    def spawn_detached(self, exe: str, cwd) -> int | None:
        """Start `exe` detached with a PyInstaller-free environment; its pid."""
        raise NotImplementedError

    def wait_for_process(self, image_name: str, timeout: float) -> bool:
        """True as soon as a process with `image_name` exists, else False."""
        raise NotImplementedError

    # -- connect (Stage 16): the client's command line --------------------- #

    def run_capture(self, cmd: list[str], timeout: float) -> tuple[int, str]:
        """Run `cmd` to completion hidden; return ``(returncode, stdout+stderr)``.

        Only for probes whose *output* is the answer.  A caller must not put a
        credential in `cmd` — the command line of a running process is
        readable by every process of the same user.
        """
        raise NotImplementedError

    def spawn_hidden(self, cmd: list[str]) -> int | None:
        """Start `cmd` with no window and no pipes; its pid."""
        raise NotImplementedError

    def spawn_monitored(self, cmd: list[str]):
        """Start `cmd` with stdin/stdout pipes; the process object.

        The handle is what the legacy ``connect_monitored`` hands to the UI so
        a 2FA challenge on stdout can be answered on stdin.
        """
        raise NotImplementedError


def _hidden_startupinfo():
    """Mirror of legacy ``_hidden_startupinfo`` — no console window."""
    import subprocess
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    info.wShowWindow = 0
    return info


def clean_pyinstaller_env(environ=None) -> dict:
    """Mirror of legacy ``_clean_pyinstaller_env``: drop ``_MEI*``/``_PYI*``.

    FortiClient (Electron) crashes on a ``_MEIPASS``-tainted environment.
    """
    env = dict(os.environ if environ is None else environ)
    for key in list(env):
        if key.startswith("_MEI") or key.startswith("_PYI"):
            env.pop(key, None)
    return env


class WindowsLaunchSystem(LaunchSystem):
    """The real machine, using exactly the calls the legacy uses."""

    def open_with_explorer(self, path: str) -> None:
        import subprocess
        subprocess.Popen([EXPLORER_EXE, path])

    def spawn_detached(self, exe: str, cwd) -> int | None:
        import subprocess
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen([exe], env=clean_pyinstaller_env(), cwd=cwd,
                                creationflags=flags, close_fds=True)
        return proc.pid

    def wait_for_process(self, image_name: str, timeout: float) -> bool:
        import time
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_process_running(image_name):
                return True
            time.sleep(POLL_INTERVAL_S)
        return False

    def run_capture(self, cmd, timeout):
        import subprocess
        try:
            completed = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
                startupinfo=_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception:
            return -1, ""
        return completed.returncode, (completed.stdout or "") + (completed.stderr or "")

    def spawn_hidden(self, cmd):
        import subprocess
        proc = subprocess.Popen(cmd, startupinfo=_hidden_startupinfo(),
                                creationflags=subprocess.CREATE_NO_WINDOW)
        return proc.pid

    def spawn_monitored(self, cmd):
        import subprocess
        return subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, startupinfo=_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW)

    def is_process_running(self, image_name: str) -> bool:
        """Mirror of legacy ``_is_process_running`` (tasklist, CSV, no window)."""
        import subprocess
        try:
            result = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {image_name}", "/NH", "/FO", "CSV"],
                capture_output=True, text=True, timeout=TASKLIST_TIMEOUT_S,
                startupinfo=_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW)
            return image_name.lower() in (result.stdout or "").lower()
        except Exception:
            return False
