"""One hospital out to its own vault file (2026-10-26, owner).

For a remote machine at a client: the file holds that one hospital only and
opens under a password of its own, never the master one.  Pure functions, no
Qt — the window code asks for the passwords and writes the file.

Items marked ``admin_only`` (machines, databases, logins) stay out unless the
export says to take them; then the file gets an admin password of its own too,
so the admin items are not visible there without it.
"""

from __future__ import annotations

import copy

import models

__all__ = ["admin_item_count", "export_hospital_data", "export_file_name"]


def admin_item_count(hospital: models.Hospital) -> int:
    """How many admin-only machines, databases and logins the hospital has
    (logins inside an admin-only machine or database are not counted again)."""
    n = 0
    for item in list(hospital.machines) + list(hospital.databases):
        if item.admin_only:
            n += 1
        else:
            n += sum(1 for c in item.credentials if c.admin_only)
    return n


def _without_admin(hospital: models.Hospital) -> models.Hospital:
    h = copy.deepcopy(hospital)
    h.machines = [m for m in h.machines if not m.admin_only]
    h.databases = [d for d in h.databases if not d.admin_only]
    for item in h.machines + h.databases:
        item.credentials = [c for c in item.credentials if not c.admin_only]
    return h


def export_hospital_data(hospital: models.Hospital, *, include_admin: bool = False,
                         admin_hash: str = "", admin_salt: str = "") -> dict:
    """The vault content (before encryption) holding only `hospital`.

    With `include_admin` every item is kept and the admin hash/salt — of the
    export's own admin password — are required.
    """
    if include_admin:
        if not (admin_hash and admin_salt):
            raise ValueError("include_admin needs the export's admin password")
        data = models.to_dict([copy.deepcopy(hospital)])
        data["admin_hash"] = admin_hash
        data["admin_salt"] = admin_salt
        return data
    return models.to_dict([_without_admin(hospital)])


_BAD_CHARS = '<>:"/\\|?*'


def export_file_name(hospital_name: str) -> str:
    """A file name for the export: the hospital's name without the characters
    Windows does not allow, ``.vault`` at the end."""
    name = "".join("_" if ch in _BAD_CHARS or ord(ch) < 32 else ch
                   for ch in hospital_name).strip().rstrip(".")
    return (name or "szpital") + ".vault"
