import uuid
from dataclasses import dataclass, field
from typing import List


@dataclass
class Credential:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    login: str = ""
    password: str = ""
    note: str = ""
    admin_only: bool = False


@dataclass
class Machine:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ip: str = ""
    name: str = ""
    description: str = ""
    credentials: List[Credential] = field(default_factory=list)
    connection_type: str = "SSH"   # "SSH" | "RDP"
    rdp_port: str = "3389"
    rdp_drives: List[str] = field(default_factory=list)  # e.g. ["C:", "D:"]
    admin_only: bool = False


@dataclass
class Database:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    host: str = ""
    port: str = "1433"
    name: str = ""
    db_type: str = "MSSQL"
    credentials: List[Credential] = field(default_factory=list)
    note: str = ""
    admin_only: bool = False


@dataclass
class Hospital:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    machines: List[Machine] = field(default_factory=list)
    databases: List[Database] = field(default_factory=list)
    notes: str = ""


def to_dict(hospitals: List[Hospital]) -> dict:
    return {"hospitals": [_hospital_to_dict(h) for h in hospitals]}


def from_dict(data: dict) -> List[Hospital]:
    return [_hospital_from_dict(h) for h in data.get("hospitals", [])]


def _hospital_to_dict(h: Hospital) -> dict:
    return {
        "id": h.id,
        "name": h.name,
        "notes": h.notes,
        "machines": [_machine_to_dict(m) for m in h.machines],
        "databases": [_database_to_dict(d) for d in h.databases],
    }


def _machine_to_dict(m: Machine) -> dict:
    return {
        "id": m.id,
        "ip": m.ip,
        "name": m.name,
        "description": m.description,
        "connection_type": m.connection_type,
        "rdp_port": m.rdp_port,
        "rdp_drives": m.rdp_drives,
        "admin_only": m.admin_only,
        "credentials": [
            {"id": c.id, "login": c.login, "password": c.password,
             "note": c.note, "admin_only": c.admin_only}
            for c in m.credentials
        ],
    }


def _database_to_dict(d: Database) -> dict:
    return {
        "id": d.id,
        "host": d.host,
        "port": d.port,
        "name": d.name,
        "db_type": d.db_type,
        "credentials": [
            {"id": c.id, "login": c.login, "password": c.password,
             "note": c.note, "admin_only": c.admin_only}
            for c in d.credentials
        ],
        "note": d.note,
        "admin_only": d.admin_only,
    }


def _hospital_from_dict(d: dict) -> Hospital:
    return Hospital(
        id=d.get("id", str(uuid.uuid4())),
        name=d.get("name", ""),
        notes=d.get("notes", ""),
        machines=[_machine_from_dict(m) for m in d.get("machines", [])],
        databases=[_database_from_dict(db) for db in d.get("databases", [])],
    )


def _machine_from_dict(d: dict) -> Machine:
    return Machine(
        id=d.get("id", str(uuid.uuid4())),
        ip=d.get("ip", ""),
        name=d.get("name", ""),
        description=d.get("description", ""),
        connection_type=d.get("connection_type", "SSH"),
        rdp_port=d.get("rdp_port", "3389"),
        rdp_drives=d.get("rdp_drives", []),
        admin_only=d.get("admin_only", False),
        credentials=[
            Credential(
                id=c.get("id", str(uuid.uuid4())),
                login=c.get("login", ""),
                password=c.get("password", ""),
                note=c.get("note", ""),
                admin_only=c.get("admin_only", False),
            )
            for c in d.get("credentials", [])
        ],
    )


def _database_from_dict(d: dict) -> Database:
    # Migrate legacy single-credential format (login/password fields)
    raw_creds = d.get("credentials")
    if raw_creds is not None:
        credentials = [
            Credential(
                id=c.get("id", str(uuid.uuid4())),
                login=c.get("login", ""),
                password=c.get("password", ""),
                note=c.get("note", ""),
                admin_only=c.get("admin_only", False),
            )
            for c in raw_creds
        ]
    elif d.get("login"):
        credentials = [Credential(login=d["login"],
                                  password=d.get("password", ""),
                                  note="")]
    else:
        credentials = []
    return Database(
        id=d.get("id", str(uuid.uuid4())),
        host=d.get("host", ""),
        port=d.get("port", "1433"),
        name=d.get("name", ""),
        db_type=d.get("db_type", "MSSQL"),
        credentials=credentials,
        note=d.get("note", ""),
        admin_only=d.get("admin_only", False),
    )
