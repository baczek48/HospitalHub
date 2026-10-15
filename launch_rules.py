"""Small launch rules shared by the legacy VPN launcher and migrated providers.

One rule lives here because both `vpn_connect._open_forticlient_gui` and the
migrated FortiClient launcher under ``vpn/providers/`` must apply it the same
way — and neither may import the other (the legacy never imports the new
package; the migrated provider never imports the legacy module).

No I/O of its own: the caller passes the ``is_dir`` it trusts (the real
``os.path.isdir`` in production, a described machine in tests).
"""

import os

__all__ = ["choose_launch_cwd", "CWD_INSTALL_DIR", "CWD_EXE_DIR", "CWD_INHERITED"]

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
