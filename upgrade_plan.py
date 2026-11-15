"""The upgrade plan of a hospital (2026-11-15, owner) — the data behind the
"Aktualizacja" tab of HospitalHub Portable.

A plan is plain data kept in the vault with the hospital (``Hospital.upgrade``):

* ``order`` — the SSH machines of the upgrade, in the order their tabs open;
* ``groups`` — AMMS (WildFly), Platforma (Tomcat), Zdarzenia medyczne… each
  with its machines, the process pattern of its service and its command
  buttons;
* ``version`` — the version typed in once, put into the commands as
  ``{WERSJA}``; ``{DATA}`` is today (YYYYMMDD).

A command button is a few shell lines.  It is typed into the terminal of
every machine of its group at once, so each terminal shows what happens;
the lines are joined with ``&&`` (a failing line stops the rest) and end in
a marker line whose exit code the window reads back as ✓ / ✗.

"Needs the service stopped" prefixes a check of the group's own process
pattern — not "is any java running", since WildFly and Tomcat may share one
machine and one of them may still run on purpose.
"""

from __future__ import annotations

import copy
import datetime as _dt
import re
import uuid

__all__ = [
    "default_plan", "normalize_plan", "new_id", "expand", "build_line",
    "marker_re", "strip_ansi", "today_stamp", "plan_machines",
]


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def today_stamp(day: _dt.date | None = None) -> str:
    return (day or _dt.date.today()).strftime("%Y%m%d")


def _cmd(label: str, text: str, confirm: bool = False,
         requires_stopped: bool = False) -> dict:
    return {"id": new_id(), "label": label, "text": text,
            "confirm": confirm, "requires_stopped": requires_stopped}


_JAVA = "pgrep -af java || echo 'brak procesów java'"


def default_plan() -> dict:
    """The plan from the owner's own upgrade notes; machines unassigned."""
    return {
        "version": "",
        "order": [],
        "hd": default_hd(),
        "groups": [
            {"id": new_id(), "name": "AMMS (WildFly)",
             "process": "java.*WildflyAMMS", "machines": [],
             "commands": [
                 _cmd("Stop", "systemctl stop amms", confirm=True),
                 _cmd("Procesy java", _JAVA),
                 _cmd("Instaluj",
                      "java -DdisableCheckVersion=true -jar "
                      "/wymiana/upgrade/AMMS_{WERSJA}-standard.jar /u01/upgrade.xml",
                      confirm=True, requires_stopped=True),
                 _cmd("Start + log",
                      "systemctl start amms; tail -f "
                      "/u01/WildflyAMMS/wildfly-26.0.1.Final/standalone/log/server.log"),
             ]},
            {"id": new_id(), "name": "Platforma (Tomcat)",
             "process": "java.*integrationPlatform", "machines": [],
             "commands": [
                 _cmd("Stop", "systemctl stop tomcat", confirm=True),
                 _cmd("Procesy java", _JAVA),
                 _cmd("Przenieś do old",
                      "test ! -e /u01/old/integrationPlatform{DATA}\n"
                      "mv /u01/integrationPlatform/ /u01/old/integrationPlatform{DATA}",
                      confirm=True, requires_stopped=True),
                 _cmd("Instaluj + chmod",
                      "java -jar /wymiana/upgrade/platform-installer_{WERSJA}-standard.jar "
                      "/u01/PIupgrade.xml\n"
                      "chmod 777 /u01/integrationPlatform/ -R",
                      confirm=True, requires_stopped=True),
                 _cmd("Start + log",
                      "systemctl start tomcat; tail -f "
                      "/u01/integrationPlatform/apache-tomcat/logs/catalina.out"),
             ]},
            {"id": new_id(), "name": "Zdarzenia medyczne (Tomcat + docker)",
             "process": "java.*integrationPlatform", "machines": [],
             "commands": [
                 _cmd("Stop + docker down",
                      "systemctl stop tomcat\n"
                      "cd /u01/start_docker\n"
                      "docker compose down", confirm=True),
                 _cmd("Procesy java", _JAVA),
                 _cmd("Przenieś do old",
                      "test ! -e /u01/old/integrationPlatform{DATA}\n"
                      "mv /u01/integrationPlatform/ /u01/old/integrationPlatform{DATA}",
                      confirm=True, requires_stopped=True),
                 _cmd("Instaluj + chmod",
                      "java -jar /wymiana/upgrade/platform-installer_{WERSJA}-standard.jar "
                      "/u01/PIupgrade.xml\n"
                      "chmod 777 /u01/integrationPlatform/ -R",
                      confirm=True, requires_stopped=True),
                 _cmd("Start + docker up",
                      "systemctl start tomcat\n"
                      "cd /u01/start_docker\n"
                      "docker compose pull\n"
                      "docker compose up -d"),
             ]},
            {"id": new_id(), "name": "Balancer",
             "process": "", "machines": [],
             "commands": [
                 _cmd("Wyczyść cache",
                      "/usr/sbin/htcacheclean -v -t -p /var/cache/httpd/proxy -l1M"),
             ]},
        ],
    }


def default_hd() -> dict:
    """hd.asseco.pl: the account, where the packages go, what is skipped."""
    return {"login": "", "password": "", "folder": r"C:\app\upgrade",
            "delete_zip": True, "skip": "PACZKI-KONFIGURACYJNE"}


def normalize_hd(raw) -> dict:
    hd = default_hd()
    if isinstance(raw, dict):
        for k, v in hd.items():
            if k in raw:
                hd[k] = bool(raw[k]) if isinstance(v, bool) else str(raw[k] or "")
    return hd


def normalize_plan(raw) -> dict:
    """A plan read from the vault, with every key present.  An empty or
    missing plan is the default one."""
    if not isinstance(raw, dict) or not raw.get("groups"):
        plan = default_plan()
        if isinstance(raw, dict):
            plan["version"] = str(raw.get("version", "") or "")
            plan["order"] = [str(x) for x in raw.get("order", []) or []]
            plan["hd"] = normalize_hd(raw.get("hd"))
        return plan
    plan = {"version": str(raw.get("version", "") or ""),
            "order": [str(x) for x in raw.get("order", []) or []],
            "hd": normalize_hd(raw.get("hd")),
            "groups": []}
    for g in raw.get("groups", []):
        if not isinstance(g, dict):
            continue
        plan["groups"].append({
            "id": str(g.get("id") or new_id()),
            "name": str(g.get("name", "") or "Grupa"),
            "process": str(g.get("process", "") or ""),
            "machines": [str(x) for x in g.get("machines", []) or []],
            "commands": [{
                "id": str(c.get("id") or new_id()),
                "label": str(c.get("label", "") or "Komenda"),
                "text": str(c.get("text", "") or ""),
                "confirm": bool(c.get("confirm", False)),
                "requires_stopped": bool(c.get("requires_stopped", False)),
            } for c in g.get("commands", []) or [] if isinstance(c, dict)],
        })
    return plan


def plan_machines(plan: dict, machines: list) -> list:
    """The SSH machines of the plan in its order (ids no longer in the vault
    are left out)."""
    by_id = {m.id: m for m in machines}
    return [by_id[i] for i in plan.get("order", []) if i in by_id]


def expand(text: str, version: str, day: str | None = None) -> str:
    return (text.replace("{WERSJA}", version.strip())
                .replace("{DATA}", day or today_stamp()))


def _sq(text: str) -> str:
    """Single-quote for the shell."""
    return "'" + text.replace("'", "'\\''") + "'"


def build_line(cmd: dict, group: dict, version: str, token: str,
               day: str | None = None) -> str:
    """The one shell line typed into a terminal for `cmd`.

    Lines are joined with ``&&``; empty lines and ``#`` comments are left
    out.  The marker after it prints "[HH <token>] kod <exit code>".
    """
    lines = [ln.strip() for ln in expand(cmd.get("text", ""), version, day).splitlines()]
    lines = [ln for ln in lines if ln and not ln.startswith("#")]
    pattern = (group.get("process") or "").strip()
    if cmd.get("requires_stopped") and pattern:
        msg = f"[HH] PRZERWANO: usługa nadal działa ({pattern})"
        # No pgrep must not read as "not running".
        lines.insert(0, "if ! command -v pgrep >/dev/null; then "
                        "echo '[HH] PRZERWANO: brak pgrep — nie da się sprawdzić usługi'; "
                        f"false; elif pgrep -f {_sq(pattern)} >/dev/null; then "
                        f"echo {_sq(msg)}; false; fi")
    body = " && ".join(f"{{ {ln}; }}" if ";" in ln else ln for ln in lines) or "true"
    return (f"{body}; __hh=$?; printf '\\n\\033[90m[HH %s] kod %s\\033[0m\\n' "
            f"{token} $__hh")


def marker_re(token: str) -> re.Pattern:
    return re.compile(r"\[HH " + re.escape(token) + r"\] kod (\d+)")


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-Za-z]|\x1b[=>]")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def copy_plan(plan: dict) -> dict:
    return copy.deepcopy(plan)
