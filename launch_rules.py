"""Small launch rules shared by the legacy VPN launcher and migrated providers.

One rule lives here because both `vpn_connect._open_forticlient_gui` and the
migrated FortiClient launcher under ``vpn/providers/`` must apply it the same
way — and neither may import the other (the legacy never imports the new
package; the migrated provider never imports the legacy module).

`choose_launch_cwd` has no I/O of its own: the caller passes the ``is_dir`` it trusts (the real
``os.path.isdir`` in production, a described machine in tests).
"""

import os

__all__ = ["choose_launch_cwd", "CWD_INSTALL_DIR", "CWD_EXE_DIR", "CWD_INHERITED",
           "user_environment", "desktop_shell_execute"]

#: Where the chosen working directory came from — reported in traces.
CWD_INSTALL_DIR = "install_dir"
CWD_EXE_DIR = "exe_dir"
CWD_INHERITED = "inherited"


def choose_launch_cwd(install_dir, exe_path, is_dir=os.path.isdir):
    """Working directory for starting a client executable.

    Same preference order as before — the installation directory first, then
    the executable's own directory — with one fix: a candidate is used only if
    it is non-empty text naming an **existing** directory.  Previously the
    registry ``INSTALLDIR`` was used as-is, so a stale value (uninstalled or
    moved client) or a non-text value made ``Popen`` fail with WinError 267 /
    TypeError even though the executable itself had been found and was fine.

    Returns ``(cwd, source)``; ``cwd`` is None when neither candidate is a
    directory, meaning "inherit the caller's working directory".
    """
    if isinstance(install_dir, str) and install_dir and is_dir(install_dir):
        return install_dir, CWD_INSTALL_DIR
    exe_dir = os.path.dirname(exe_path) if isinstance(exe_path, str) else ""
    if exe_dir and is_dir(exe_dir):
        return exe_dir, CWD_EXE_DIR
    return None, CWD_INHERITED


def _clean_pyinstaller_env(environ=None) -> dict:
    """``os.environ`` (or `environ`) without PyInstaller's ``_MEI*``/``_PYI*``."""
    env = dict(os.environ if environ is None else environ)
    for key in list(env):
        if key.startswith("_MEI") or key.startswith("_PYI"):
            env.pop(key, None)
    return env


#: Token access rights (winnt.h) — numbers, so this seam needs no win32con.
_TOKEN_DUPLICATE = 0x0002
_TOKEN_QUERY = 0x0008


def user_environment(environ=None) -> dict:
    """The user's own environment, as Windows builds it for a fresh logon.

    2026-10-19: a client started with *our* environment — even with the
    ``_MEI*``/``_PYI*`` keys removed — could still come up broken on some
    machines: FortiClient's Electron main process failed with "Cannot read
    properties of null (reading 'TraceLog')", or started with a hidden
    window.  ``explorer.exe <lnk>`` was meant to avoid that and does not
    (started from our process it carries our environment too) — and on a
    machine with a hijacked ``.lnk`` association it opens "Dokumenty".
    ``CreateEnvironmentBlock(token, inherit=False)`` asks Windows for the
    environment from the user's registry profile, the same one the desktop
    gives a program started from the Start menu; nothing of this process
    leaks into it.  Falls back to a PyInstaller-stripped copy of ours when the call
    is unavailable.
    """
    if environ is None:
        try:
            import win32api
            import win32profile
            import win32security
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                _TOKEN_QUERY | _TOKEN_DUPLICATE)
            env = dict(win32profile.CreateEnvironmentBlock(token, False))
            if env.get("SystemRoot") or env.get("SYSTEMROOT"):
                return env
        except Exception:
            pass
    return _clean_pyinstaller_env(environ)


#: ShellWindows.FindWindowSW arguments for "the desktop" (shlobj.h / exdisp.h).
_CSIDL_DESKTOP = 0
_SWC_DESKTOP = 8
_SWFO_NEEDDISPATCH = 1


def desktop_shell_execute(exe: str, cwd) -> bool:
    """Have the running desktop shell (``explorer.exe``) start `exe`.

    2026-10-19, owner's field test: started by this process — directly with a
    cleaned or a freshly built environment, or through a new ``explorer.exe
    <lnk>`` — FortiClient still failed on some machines with its Electron
    "Cannot read properties of null (reading 'TraceLog')" error.  Started by
    the user from the desktop it works.  ``ShellWindows`` hands us the
    desktop's own ``IShellDispatch2``; its ``ShellExecute`` runs *in the shell
    process*, so the client's parent is explorer and its environment is the
    session's — the same start as a double-click on the shortcut (measured:
    parent ``explorer.exe``, window shown, a second start reuses the first
    instance).  Returns False when there is no desktop shell to ask.
    """
    import pythoncom
    import win32com.client

    pythoncom.CoInitialize()
    try:
        windows = win32com.client.Dispatch("Shell.Application").Windows()
        desktop = windows.FindWindowSW(_CSIDL_DESKTOP, None, _SWC_DESKTOP, 0,
                                       _SWFO_NEEDDISPATCH)
        if desktop is None:
            return False
        desktop.Document.Application.ShellExecute(exe, "", cwd or "", "open", 1)
        return True
    finally:
        windows = desktop = None
        pythoncom.CoUninitialize()
