"""The HL7 package register of AMMS — the logic behind the "Rejestr HL7"
window of HospitalHub Portable (owner, 2026-11-19), in the spirit of the old
wymdMonitor: every package of one order, from the order to the result, with
its status, times and acknowledgement.

The data (owner's notes, schema SYSADM):

* ``WYMD_PACZKA`` — one row per package (message), ACKs too.  ``TRESC`` is a
  LONG: never in a WHERE, read one package at a time by ``GIDK_PACZKI``.
* ``WYMD_PACZKA_OBIEKT`` — the package ↔ AMMS object link.  The packages of
  an order are found by ``ID_OBIEKTU`` (``ZLEC`` the order sent, ``OZZW`` /
  ``WYNZ`` the answer / result).  An ACK has an ``OZID`` row whose
  ``ID_OBIEKTU`` is the ``GIDK_PACZKI`` of the package it acknowledges (and a
  ``POTZ`` row with the order id).

Read only, by construction: the statements below are the only SQL this
module runs, all SELECTs with bind variables, inside ``SET TRANSACTION READ
ONLY`` — Oracle itself refuses any write in that transaction.
"""

from __future__ import annotations

import datetime as _dt
import glob
import os
import re
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass, field

__all__ = [
    "Package", "MAX_ROWS", "ORDER_SQL", "PACKAGE_SQL", "ACK_SQL",
    "CONTENT_SQL", "connect", "begin_read_only", "find_chain",
    "fetch_content", "status_words", "clean_list", "direction",
]

MAX_ROWS = 2000

_COLS = ("p.gidk_paczki, o.r_obiektu, o.id_obiektu, p.czy_wyjsc,"
         " p.postac_przesylki, p.system_gener, p.system_docel_l, p.status,"
         " p.r_zawartosci_l, p.dt_gener, p.dt_wyslania, p.dt_odbioru,"
         " p.dt_przetw, o.potw_status, o.potw_kod, o.potw_info_ttwd,"
         " o.status_wymd")

ORDER_SQL = (
    f"select {_COLS} from sysadm.wymd_paczka_obiekt o"
    " join sysadm.wymd_paczka p on p.gidk_paczki = o.gidk_paczki"
    " where o.id_obiektu = :id order by p.dt_gener, p.gidk_paczki")

#: The objects a package belongs to — to go from one package to its order.
PACKAGE_SQL = (
    "select o.r_obiektu, o.id_obiektu from sysadm.wymd_paczka_obiekt o"
    " where o.gidk_paczki = :g")

#: The ACKs of some packages (``:g0``, ``:g1``… filled in by find_chain).
ACK_SQL = (
    f"select o.id_obiektu as dla, {_COLS} from sysadm.wymd_paczka_obiekt o"
    " join sysadm.wymd_paczka p on p.gidk_paczki = o.gidk_paczki"
    " where o.r_obiektu = 'OZID' and o.id_obiektu in ({binds})"
    " order by p.dt_gener")

CONTENT_SQL = (
    "select p.tresc, p.r_kompr_tresci, p.r_kodow_bt_tresci, p.plik_przesylki,"
    " p.plik_zewn, p.katalog from sysadm.wymd_paczka p"
    " where p.gidk_paczki = :g")

#: Object types that point at an order (a package → its order's chain).
_ORDER_KINDS = ("ZLEC", "OZZW", "WYNZ", "POTZ")

# Owner, 2026-11-19: Z = zatwierdzona, O = do przetworzenia, B = błędna.
_STATUS_OUT = {"N": "nowa", "W": "wysłana", "Z": "zatwierdzona"}
_STATUS_IN = {"O": "do przetworzenia", "P": "przetworzona", "B": "błędna"}


@dataclass
class Package:
    gidk: str
    kinds: list = field(default_factory=list)      # R_OBIEKTU of the rows
    object_id: str = ""
    outgoing: bool | None = None
    via: str = ""                                  # POSTAC_PRZESYLKI
    sender: str = ""
    receivers: str = ""
    status: str = ""
    msg_type: str = ""
    dt_gener: object = None
    dt_sent: object = None
    dt_received: object = None
    dt_processed: object = None
    ack_status: str = ""
    ack_code: str = ""
    ack_info: str = ""
    status_wymd: str = ""
    acks: list = field(default_factory=list)       # Package, the ACKs of it
    ack_for: str = ""                              # this ACK confirms gidk

    @property
    def is_ack(self) -> bool:
        return self.msg_type.upper() == "ACK" or bool(self.ack_for)

    @property
    def via_si(self) -> bool:
        return self.via.upper() == "CPIHL7"


def clean_list(value) -> str:
    """``'^ORU_R01^'`` → ``ORU_R01``; ``'^A^B^'`` → ``A, B``."""
    parts = [p for p in str(value or "").split("^") if p.strip()]
    return ", ".join(p.strip() for p in parts)


def direction(czy_wyjsc) -> bool | None:
    v = str(czy_wyjsc or "").strip().upper()
    if v in ("T", "1", "Y", "TAK"):
        return True
    if v in ("N", "0", "NIE"):
        return False
    return None


def status_words(p: Package) -> str:
    s = (p.status or "").strip().upper()
    if p.outgoing is True:
        word = _STATUS_OUT.get(s)
    elif p.outgoing is False:
        word = _STATUS_IN.get(s)
    else:
        word = _STATUS_OUT.get(s) or _STATUS_IN.get(s)
    return f"{s} {word}" if word else s


def _text(v) -> str:
    return "" if v is None else str(v).strip()


def _row_package(r) -> Package:
    (gidk, kind, oid, czy, via, sender, recv, status, typ, dg, dw, do, dp,
     ps, pk, pi, sw) = r
    return Package(
        gidk=_text(gidk), kinds=[_text(kind)] if kind else [],
        object_id=_text(oid), outgoing=direction(czy), via=_text(via),
        sender=_text(sender), receivers=clean_list(recv), status=_text(status),
        msg_type=clean_list(typ), dt_gener=dg, dt_sent=dw, dt_received=do,
        dt_processed=dp, ack_status=_text(ps), ack_code=_text(pk),
        ack_info=_text(pi), status_wymd=_text(sw))


# ── Oracle ───────────────────────────────────────────────────────────────

_JDBC_PREFIX = re.compile(r"^\s*jdbc:oracle:(thin|oci):[^@]*@", re.I)


def parse_target(host: str, port, name: str) -> dict:
    """Where the database is, from what the vault holds.  The host field may
    be a plain host, ``host:port``, or a whole JDBC URL as copied from AMMS
    (owner's vault, 2026-11-19: ``jdbc:oracle:thin:@10.20.30.40:1521:amms01``)
    — ``@host:port:SID``, ``@host:port/service``, ``@//host:port/service`` —
    or a TNS descriptor ``(DESCRIPTION=…)``.

    → {"host", "port", "service", "sid", "descriptor"}; ``sid`` set when the
    address says SID (``:`` after the port), ``service`` otherwise."""
    h = (host or "").strip()
    out = {"host": "", "port": 1521, "service": "", "sid": "",
           "descriptor": ""}
    try:
        out["port"] = int(str(port).strip() or 1521)
    except ValueError:
        pass
    h = _JDBC_PREFIX.sub("", h)
    if h.startswith("("):
        out["descriptor"] = h
        return out
    h = h.lstrip("/")
    sid = service = ""
    if "/" in h:
        h, service = h.split("/", 1)
    parts = h.split(":")
    out["host"] = parts[0]
    if len(parts) >= 2 and parts[1].strip().isdigit():
        out["port"] = int(parts[1])
    if len(parts) >= 3 and parts[2].strip():
        sid = parts[2].strip()
    name = (name or "").strip()
    if sid:
        out["sid"] = sid
    else:
        out["service"] = service.strip() or name
    return out


#: Errors of the thin driver that the thick one (Oracle Instant Client) gets
#: past — DPY-3015: an account whose password has only the old 10G verifier
#: (owner's sysadm, 2026-11-19: "password verifier type 0x939").
THICK_ONLY = ("DPY-3015", "DPY-3010")

_thick = {"lib": ""}


class NeedsInstantClient(RuntimeError):
    """The database needs the thick driver and no Instant Client is here."""


def _program_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def find_instant_client(base: str | None = None) -> str:
    """A folder with ``oci.dll``: an ``instantclient*`` folder next to the
    program (newest name first), then ORACLE_HOME, then PATH.  "" if none."""
    base = base or _program_dir()
    dirs = sorted(glob.glob(os.path.join(base, "instantclient*")), reverse=True)
    home = os.environ.get("ORACLE_HOME", "")
    if home:
        dirs += [home, os.path.join(home, "bin")]
    dirs += os.environ.get("PATH", "").split(os.pathsep)
    for d in dirs:
        if d and os.path.isfile(os.path.join(d, "oci.dll")):
            return d
    return ""


def _enable_thick(lib: str) -> None:
    """Switch the driver to thick mode once.  The client is told it may log
    in with the old verifiers (sqlnet.ora in a folder of our own)."""
    if _thick["lib"]:
        return
    import oracledb
    cfg = os.path.join(tempfile.gettempdir(), "hh_portable_oracle")
    os.makedirs(cfg, exist_ok=True)
    with open(os.path.join(cfg, "sqlnet.ora"), "w", encoding="ascii") as f:
        f.write("SQLNET.ALLOWED_LOGON_VERSION_CLIENT=10\n")
    # oci.dll loads its siblings (oraociicus19.dll…) by name.  In the frozen
    # exe PyInstaller has set its own DLL directory, so they were not found
    # and the client reported DPI-1072 (2.0.42 self-test).  Let Windows look
    # in the client's folder too.
    os.environ["PATH"] = lib + os.pathsep + os.environ.get("PATH", "")
    if hasattr(os, "add_dll_directory"):
        try:
            _thick["dll_dir"] = os.add_dll_directory(lib)
        except OSError:
            pass
    previous = None
    if sys.platform == "win32":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            buf = ctypes.create_unicode_buffer(32768)
            n = k32.GetDllDirectoryW(len(buf), buf)
            previous = buf.value if n else ""
            k32.SetDllDirectoryW(lib)
        except Exception:
            previous = None
    try:
        oracledb.init_oracle_client(lib_dir=lib, config_dir=cfg)
    finally:
        # Back to PyInstaller's own folder: Qt and the rest load from there.
        if previous is not None:
            try:
                import ctypes
                ctypes.windll.kernel32.SetDllDirectoryW(previous or None)
            except Exception:
                pass
    _thick["lib"] = lib


def connect(host: str, port, service: str, user: str, password: str):
    """A python-oracledb connection: thin (no Oracle client needed) first;
    when the database needs the thick driver (an old 10G password), the
    Instant Client found by find_instant_client.  The address goes through
    parse_target; a service name the listener does not know is tried once
    more as a SID."""
    import oracledb
    t = parse_target(host, port, service)
    if t["descriptor"]:
        dsn = t["descriptor"]
    elif t["sid"]:
        dsn = oracledb.makedsn(t["host"], t["port"], sid=t["sid"])
    else:
        dsn = oracledb.makedsn(t["host"], t["port"], service_name=t["service"])

    def attempt():
        try:
            return oracledb.connect(user=user, password=password, dsn=dsn)
        except oracledb.Error as e:
            if (t["descriptor"] or t["sid"]
                    or ("ORA-12514" not in str(e) and "DPY-6001" not in str(e))):
                raise
            return oracledb.connect(user=user, password=password,
                                    dsn=oracledb.makedsn(t["host"], t["port"],
                                                         sid=t["service"]))

    try:
        conn = attempt()
    except oracledb.Error as e:
        if not any(code in str(e) for code in THICK_ONLY) or _thick["lib"]:
            raise
        lib = find_instant_client()
        if not lib:
            raise NeedsInstantClient(
                "Konto bazy ma hasło w starym formacie Oracle 10G — tryb bez "
                "klienta Oracle go nie obsługuje. Potrzebny Oracle Instant "
                "Client 19 (Basic Light, 64-bit): rozpakuj go do folderu "
                "„instantclient_19_…” obok HospitalHubRemote.exe.") from e
        _enable_thick(lib)
        conn = attempt()
    conn.call_timeout = 60000
    return conn


def selftest() -> str:
    """For the frozen exe (``--selftest-oracledb``): the thin driver and the
    cryptography it needs load — a refused connection is the good answer,
    DPY-3016 means a module was left out of the build.  Then the thick one
    from the Instant Client beside the program: ORA-12541 (no listener) is
    the good answer there."""
    lines = []
    try:
        connect("127.0.0.1", 1, "X", "u", "p")
        lines.append("thin: OK connected?")
    except Exception as e:  # noqa: BLE001
        msg = str(e).splitlines()[0]
        lines.append(("thin: FAIL " if "DPY-3016" in msg else "thin: OK ") + msg)
    lib = find_instant_client()
    if not lib:
        lines.append("thick: brak Instant Client")
        return "\n".join(lines)
    try:
        import oracledb
        _enable_thick(lib)
        oracledb.connect(user="u", password="p", dsn="127.0.0.1:1/X")
        lines.append("thick: OK connected?")
    except Exception as e:  # noqa: BLE001
        msg = str(e).splitlines()[0]
        lines.append(("thick: OK " if "ORA-12541" in msg else "thick: FAIL ")
                     + f"{msg} [{lib}]")
    return "\n".join(lines)


def begin_read_only(conn) -> None:
    """Every query of a search runs in a read-only transaction."""
    try:
        conn.rollback()
    except Exception:
        pass
    cur = conn.cursor()
    try:
        cur.execute("set transaction read only")
    finally:
        cur.close()


def _rows(conn, sql: str, params: dict, limit: int = MAX_ROWS) -> list:
    cur = conn.cursor()
    try:
        cur.execute(sql, params)
        return cur.fetchmany(limit)
    finally:
        cur.close()


def _merge(rows) -> dict:
    """gidk → Package; one package may come in several object rows."""
    out: dict[str, Package] = {}
    for r in rows:
        p = _row_package(r)
        have = out.get(p.gidk)
        if have is None:
            out[p.gidk] = p
            continue
        for k in p.kinds:
            if k not in have.kinds:
                have.kinds.append(k)
        for attr in ("ack_status", "ack_code", "ack_info"):
            if not getattr(have, attr) and getattr(p, attr):
                setattr(have, attr, getattr(p, attr))
    return out


def find_chain(conn, mode: str, value: str) -> tuple[str, list]:
    """(order id, packages of the order in time order with their ACKs
    nested).  ``mode``: ``order`` (ID_OBIEKTU) or ``package`` (GIDK_PACZKI —
    its order is looked up first)."""
    value = (value or "").strip()
    if not value:
        return "", []
    begin_read_only(conn)
    try:
        order_id = value
        if mode == "package":
            objs = _rows(conn, PACKAGE_SQL, {"g": value}, 50)
            ids = [(_text(k), _text(i)) for k, i in objs]
            found = next((i for k, i in ids if k in _ORDER_KINDS), "")
            if not found:
                # An ACK: the package it confirms, then that one's order.
                target = next((i for k, i in ids if k == "OZID"), "")
                if target:
                    objs = _rows(conn, PACKAGE_SQL, {"g": target}, 50)
                    found = next((_text(i) for k, i in objs
                                  if _text(k) in _ORDER_KINDS), "")
            if not found:
                return "", []
            order_id = found
        pkgs = _merge(_rows(conn, ORDER_SQL, {"id": order_id}))
        if not pkgs:
            return order_id, []
        main = [p for p in pkgs.values() if not p.is_ack]
        acks_seen = {g for g, p in pkgs.items() if p.is_ack}
        if main:
            gids = [p.gidk for p in main][:900]       # Oracle IN list limit
            binds = ", ".join(f":g{i}" for i in range(len(gids)))
            params = {f"g{i}": g for i, g in enumerate(gids)}
            by = {p.gidk: p for p in main}
            for r in _rows(conn, ACK_SQL.format(binds=binds), params):
                ack = _row_package(r[1:])
                ack.ack_for = _text(r[0])
                parent = by.get(ack.ack_for)
                if parent is None or any(a.gidk == ack.gidk for a in parent.acks):
                    continue
                parent.acks.append(ack)
                acks_seen.discard(ack.gidk)
        # ACKs of the order not tied to a package by OZID stay in the list.
        loose = [pkgs[g] for g in acks_seen]
        out = sorted(main + loose, key=lambda p: (_sort_time(p.dt_gener), p.gidk))
        return order_id, out
    finally:
        try:
            conn.rollback()
        except Exception:
            pass


def _sort_time(v):
    if isinstance(v, _dt.datetime):
        return v
    return _dt.datetime.min


def _read_lob(v) -> str:
    if v is None:
        return ""
    if hasattr(v, "read"):
        v = v.read()
    if isinstance(v, (bytes, bytearray)):
        for enc in ("utf-8", "cp1250"):
            try:
                return bytes(v).decode(enc)
            except UnicodeDecodeError:
                continue
        return bytes(v).decode("latin-1")
    return str(v)


_PCT = re.compile(r"%[0-9A-Fa-f]{2}")


def decode_content(text: str) -> tuple[str, bool]:
    """TRESC as AMMS keeps it is URL-encoded — ``%0D`` between the segments,
    ``%C5%82`` for "ł" (owner's srv-si, 2026-11-19: the message showed as one
    MSH line).  → (the message, whether it was decoded).  A message with
    real segment breaks and no ``%0D`` is left as it is."""
    if not text or not _PCT.search(text):
        return text, False
    upper = text.upper()
    if "%0D" not in upper and "%0A" not in upper and "\r" in text:
        return text, False
    raw = urllib.parse.unquote_to_bytes(text)
    for enc in ("utf-8", "cp1250"):
        try:
            return raw.decode(enc), True
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1"), True


def fetch_content(conn, gidk: str) -> dict:
    """The raw message of one package and how it is stored."""
    begin_read_only(conn)
    try:
        rows = _rows(conn, CONTENT_SQL, {"g": gidk}, 1)
    finally:
        try:
            conn.rollback()
        except Exception:
            pass
    if not rows:
        return {"text": "", "found": False}
    tresc, kompr, kod, plik, plik_zewn, katalog = rows[0]
    stored = _read_lob(tresc)
    text, decoded = decode_content(stored)
    return {"text": text, "stored": stored, "url_decoded": decoded,
            "found": True,
            "compression": _text(kompr), "encoding": _text(kod),
            "file": _text(plik), "external_file": _text(plik_zewn),
            "folder": _text(katalog)}
