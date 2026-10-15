"""Writing a vault file, and checking that a decrypted vault is the expected kind.

Pure functions, no Qt — the window code calls them and shows the errors.

Writing (``write_vault_atomic``) keeps what the window code already did —
temporary file in the same directory, ``fsync``, ``os.replace`` — and adds
two things the 2026-10-14 audit (C4-05) found missing:

* the previous file is kept as ``<vault>.bak`` before it is replaced — one
  generation only: it holds the state before the *latest* save, so a save that
  wrote the wrong thing can be undone by hand until the next one.  After a
  master-password change the backup is deleted (it is the old password's
  file), see :func:`discard_backup`;
* ``os.replace`` is retried a few times on ``PermissionError``: antivirus and
  sync clients (OneDrive) hold a just-written file for a moment, and one such
  collision used to be a failed save.

Checking (``vault_kind_error``) closes C4-02: the vault type is chosen in the
login dialog, not stored in the file, so a VPN vault opened as "Ogólny" decoded
to an empty list — and the first save wrote that empty list over the profiles.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time

__all__ = ["write_vault_atomic", "vault_kind_error", "backup_path",
           "discard_backup", "REPLACE_ATTEMPTS"]

#: How many times ``os.replace`` is tried before a PermissionError is final.
REPLACE_ATTEMPTS = 4
_REPLACE_PAUSE_S = 0.25

#: Top-level key each vault type stores its items under.
_KEY_BY_TYPE = {"vpn": "vpn_profiles", "global": "hospitals", "private": "hospitals"}


def backup_path(path: str) -> str:
    return path + ".bak"


def discard_backup(path: str) -> None:
    """Remove ``<vault>.bak`` if it exists.  Never raises."""
    try:
        os.remove(backup_path(os.path.abspath(path)))
    except OSError:
        pass


def write_vault_atomic(path: str, content: bytes, *, backup: bool = True,
                       sleep=time.sleep) -> None:
    """Write `content` to `path` so that a crash never leaves a half file.

    Raises on failure; the original file is then untouched and no temporary
    file is left behind.  A backup that cannot be made does not stop the save
    — it is a second line of defence, not the save itself.
    """
    target = os.path.abspath(path)
    dir_name = os.path.dirname(target)
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        if backup and os.path.isfile(target):
            try:
                shutil.copy2(target, backup_path(target))
            except OSError:
                pass
        for attempt in range(REPLACE_ATTEMPTS):
            try:
                os.replace(tmp_path, target)        # atomic on one filesystem
                break
            except PermissionError:
                if attempt == REPLACE_ATTEMPTS - 1:
                    raise
                sleep(_REPLACE_PAUSE_S)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def vault_kind_error(data, vault_type: str) -> str | None:
    """Why `data` is not a vault of `vault_type`, or ``None`` if it is.

    Only a *contradiction* is refused: the key of the other type present and
    the expected one absent.  A vault holding neither (a hand-made or empty
    file) is accepted as before.
    """
    if not isinstance(data, dict):
        return "Plik nie zawiera danych vaulta."
    expected = _KEY_BY_TYPE.get(vault_type, "hospitals")
    other = "hospitals" if expected == "vpn_profiles" else "vpn_profiles"
    if expected not in data and other in data:
        if expected == "vpn_profiles":
            return ("To jest vault ogólny/prywatny (szpitale), a wybrano typ VPN.\n"
                    "Wybierz właściwy typ vaulta.")
        return ("To jest vault VPN, a wybrano typ ogólny/prywatny.\n"
                "Wybierz typ VPN.")
    return None
