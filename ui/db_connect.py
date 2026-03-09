"""Database tool launcher — SQL Developer with auto-injected connection.

Strategy:
  1. Auto-detect SQL Developer in common install paths (or ask user once).
  2. Inject/update a named connection entry into SQL Developer's connections.xml
     so the connection appears in the Connections tree on next start.
  3. Launch SQL Developer.
  4. Copy first credential's password to clipboard (30 s auto-clear).
"""

import glob
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

from PyQt6.QtWidgets import QFileDialog, QMessageBox

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import models
from config import load_sqldeveloper_path, save_sqldeveloper_path
from ui.dialogs import _clipboard_copy

_NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_SQLDEVELOPER_SEARCH = [
    r"C:\Program Files\Oracle\SQL Developer\sqldeveloper.exe",
    r"C:\Program Files (x86)\Oracle\SQL Developer\sqldeveloper.exe",
    r"C:\sqldeveloper\sqldeveloper.exe",
    r"C:\Oracle\sqldeveloper\sqldeveloper.exe",
    r"C:\app\sqldeveloper\sqldeveloper.exe",
]

_SQLD_NS = "http://xmlns.oracle.com/adf/jndi"
_CONN_REL_PATH = r"o.jdeveloper.db.connection\connections.xml"


# ──────────────────────────────────────────────────────────────────────────────
# Path helpers
# ──────────────────────────────────────────────────────────────────────────────

def _find_sqldeveloper() -> str | None:
    saved = load_sqldeveloper_path()
    if saved and os.path.exists(saved):
        return saved
    for p in _SQLDEVELOPER_SEARCH:
        if os.path.exists(p):
            save_sqldeveloper_path(p)
            return p
    return None


def _find_connections_xml() -> str | None:
    """Return path to SQL Developer's connections.xml (newest system* folder)."""
    app_data = os.environ.get("APPDATA", "")
    pattern = os.path.join(app_data, "SQL Developer", "system*", _CONN_REL_PATH)
    matches = sorted(glob.glob(pattern))
    return matches[-1] if matches else None


def _parse_host(raw: str) -> str:
    """Strip JDBC prefix — return bare hostname/IP."""
    s = raw.strip()
    at = s.rfind("@")
    if at != -1:
        s = s[at + 1:].lstrip("/")
    for ch in (":", "/"):
        idx = s.find(ch)
        if idx != -1:
            s = s[:idx]
            break
    return s or raw.strip()


# ──────────────────────────────────────────────────────────────────────────────
# XML injection
# ──────────────────────────────────────────────────────────────────────────────

def _make_string_addr(addr_type: str, contents: str) -> ET.Element:
    el = ET.Element("StringRefAddr", attrib={"addrType": addr_type})
    c = ET.SubElement(el, "Contents")
    c.text = contents
    return el


def _build_reference(db: models.Database, cred: "models.Credential | None") -> ET.Element:
    """Build a <Reference> element for the given database."""
    conn_name = f"HospitalHub \u2014 {db.name}"
    ref = ET.Element(
        "Reference",
        attrib={
            "name": conn_name,
            "className": "oracle.jdeveloper.db.adapter.DatabaseProvider",
            "xmlns": "",
        },
    )
    factory = ET.SubElement(ref, "Factory")
    factory.set("className", "oracle.jdeveloper.db.adapter.DatabaseProviderFactory")

    addrs = ET.SubElement(ref, "RefAddresses")
    db_type = (db.db_type or "").upper()

    if db_type == "MSSQL":
        addrs.append(_make_string_addr("hostname", _parse_host(db.host)))
        addrs.append(_make_string_addr("port", db.port or "1433"))
        addrs.append(_make_string_addr("dbname", db.name))
        addrs.append(_make_string_addr("RaptorConnectionType", "SqlServer"))
    else:
        # Oracle (and fallback)
        if db.host.strip().lower().startswith("jdbc:"):
            url = db.host.strip()
        else:
            url = f"jdbc:oracle:thin:@{db.host}:{db.port}:{db.name}"
        addrs.append(_make_string_addr("customUrl", url))
        addrs.append(_make_string_addr("driver", "thin"))
        addrs.append(_make_string_addr("RaptorConnectionType", "Oracle (JDBC)"))

    if cred:
        addrs.append(_make_string_addr("user", cred.login))
    addrs.append(_make_string_addr("SavePassword", "false"))
    addrs.append(_make_string_addr(
        "subtype", "oracle.jdeveloper.db.adapter.DefaultDatabaseProvider"))
    return ref


def _inject_connection(db: models.Database, cred: "models.Credential | None") -> bool:
    """Add/update the connection entry in SQL Developer's connections.xml.
    Returns True on success."""
    try:
        conn_name = f"HospitalHub \u2014 {db.name}"
        xml_path = _find_connections_xml()

        ET.register_namespace("", _SQLD_NS)

        if xml_path and os.path.exists(xml_path):
            try:
                tree = ET.parse(xml_path)
                root = tree.getroot()
            except ET.ParseError:
                root = ET.Element(f"{{{_SQLD_NS}}}References")
                tree = ET.ElementTree(root)
            # Remove old entry with same name
            for existing in list(root):
                tag = existing.tag.split("}")[-1] if "}" in existing.tag else existing.tag
                if tag == "Reference" and existing.get("name") == conn_name:
                    root.remove(existing)
        else:
            if xml_path is None:
                app_data = os.environ.get("APPDATA", "")
                xml_path = os.path.join(
                    app_data, "SQL Developer", "system", _CONN_REL_PATH)
            os.makedirs(os.path.dirname(xml_path), exist_ok=True)
            root = ET.Element(f"{{{_SQLD_NS}}}References")
            tree = ET.ElementTree(root)

        root.append(_build_reference(db, cred))
        ET.indent(tree, space="  ")
        tree.write(xml_path, xml_declaration=True, encoding="UTF-8")
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────

def connect_db(db: models.Database, parent=None) -> None:
    """Inject connection into SQL Developer, launch it, copy password to clipboard."""
    path = _find_sqldeveloper()

    if path is None:
        path, _ = QFileDialog.getOpenFileName(
            parent,
            "Zlokalizuj SQL Developer",
            r"C:\Program Files",
            "SQL Developer (sqldeveloper.exe);;Wszystkie pliki (*.*)",
        )
        if not path:
            return
        save_sqldeveloper_path(path)

    cred = db.credentials[0] if db.credentials else None
    injected = _inject_connection(db, cred)

    try:
        subprocess.Popen([path], creationflags=_NO_WIN)
    except Exception as exc:
        QMessageBox.critical(
            parent, "Błąd SQL Developer",
            f"Nie można uruchomić SQL Developer:\n{exc}",
        )
        return

    if cred and cred.password:
        _clipboard_copy(cred.password)

    host_clean = _parse_host(db.host)
    conn_name = f"HospitalHub \u2014 {db.name}"
    lines = [
        f"Połączenie:  {conn_name}",
        f"Host:        {host_clean}",
        f"Port:        {db.port}",
        f"Baza:        {db.name}",
        f"Login:       {cred.login if cred else '—'}",
    ]
    if cred and cred.password:
        lines.append("Hasło:       skopiowane do schowka (wyczyszczone po 30 s)")

    lines.append("")
    if injected:
        lines.append(f"Połączenie '{conn_name}' dodane do drzewa Connections.")
        lines.append("Jeśli SQL Developer był już otwarty — uruchom go ponownie.")
    else:
        lines.append("(Nie udało się auto-dodać połączenia — dodaj ręcznie.)")

    QMessageBox.information(parent, "SQL Developer uruchomiony", "\n".join(lines))
