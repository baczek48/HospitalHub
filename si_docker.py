"""Serwer Integracji (Asseco) on a hospital machine — the logic behind the
"SI" tab of HospitalHub Portable (owner, 2026-11-19).

The modules live one per folder under ``/opt/asseco`` (``si-aism``,
``cpi-hl7-services``…), each with the ``docker-compose.yml`` and the env
files the Kreator instalacji generated.  ``old`` holds the owner's own
copies and is never a module.

Everything here is plain text in, plain text out: the shell scripts that run
on the server over one SSH exec channel and the parsers of what they print.
The tab (ui/si_panel.py) only connects, runs and shows.

Privileges: the owner logs in as root; on a machine where he does not,
the whole script runs under ``sudo`` — ``sudo -n`` when it needs no
password, otherwise ``sudo -S`` with the password written to stdin (never on
the command line, never in the shell history).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field

__all__ = [
    "DEFAULT_ROOT", "SKIP_DIRS", "ACTIONS", "Container", "Module",
    "privilege_probe", "parse_privilege", "wrap", "scan_script",
    "parse_scan", "start_order", "stop_order", "action_script",
    "parse_action_markers", "module_state",
]

DEFAULT_ROOT = "/opt/asseco"
SKIP_DIRS = frozenset({"old"})

#: Start order from "Serwer Integracji - przewodnik wdrożeniowy" (3 Kroki
#: instalacji): Elastic server, the base modules (db → keycloak → aism),
#: nginx, the integration modules, Filebeat last.  Stopping goes backwards.
_FIRST = ["si-elastic-server", "si-aism-db", "si-aism-keycloak", "si-aism",
          "si-aism-reverse-proxy"]
_LAST = ["si-elastic-client"]

#: action → (button label, docker compose arguments)
ACTIONS = {
    "start":   ("Uruchom", "up -d"),
    "stop":    ("Zatrzymaj", "stop"),
    "restart": ("Restart", "restart"),
    "pull":    ("Pobierz obrazy", "pull"),
    "logs":    ("Logi", "logs --no-color --timestamps --tail {tail}"),
    "ps":      ("Status", "ps -a"),
    # Before an upgrade (owner, 2026-11-19): stop the modules, then copy
    # their folders to old/ — the owner puts the Kreator's new files in by
    # hand afterwards, then Odśwież → Pobierz → Uruchom.
    "stop_archive": ("Zatrzymaj i zarchiwizuj", "stop"),
}

#: Seconds a base module may take to be ready before the start gives up.
WAIT_MAX = 300

#: Exit codes the start script gives a module beyond docker compose's own.
SKIPPED = 4            # an earlier base module did not come up
WAIT_CODES = {11: "brak kontenerów po starcie",
              12: "kontener zakończył się błędem",
              13: f"nie wstał w {WAIT_MAX} s"}
#: Running but unhealthy after the grace time — a warning, the start goes on
#: (owner's asi-keycloak works while "unhealthy", 2026-11-19).
UNHEALTHY_GRACE = 60
RUNNING_UNHEALTHY = 14

# Owner, 2026-11-19: a base module starts only once the one before it is up.
# "Up" as the AISM guide checks it (5.5.1): every container running, healthy
# where it has a health check, the one-off ones (asi-liquibase,
# asi-keycloak-config-cli, elasticsearch-before…) "Exited (0)".
_WAIT_FN = r'''si_wait() {
  t=0
  while [ "$t" -lt "$SI_WAIT_MAX" ]; do
    ids=$(cd "$1" && $DC ps -a -q 2>/dev/null)
    if [ -z "$ids" ]; then echo "  brak kontenerów"; return 1; fi
    bad=0; pending=0; unh=0
    for s in $(docker inspect -f '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}/{{.State.ExitCode}}' $ids); do
      case "$s" in
        running/healthy/*|running/none/*) ;;
        running/unhealthy/*) unh=1 ;;
        exited/*/0) ;;
        exited/*|dead/*) bad=1 ;;
        *) pending=1 ;;
      esac
    done
    if [ "$bad" = 1 ]; then echo "  kontener zakończył się błędem"; return 2; fi
    if [ "$pending" = 0 ] && [ "$unh" = 0 ]; then echo "  gotowy po ${t} s"; return 0; fi
    if [ "$pending" = 0 ] && [ "$t" -ge "$SI_UNHEALTHY_GRACE" ]; then
      echo "  działa, ale unhealthy po ${t} s — uruchamiam dalej"; return 4
    fi
    if [ $((t % 15)) = 0 ]; then echo "  czekam na gotowość… ${t} s"; fi
    sleep 3; t=$((t + 3))
  done
  echo "  nie wstał w ${SI_WAIT_MAX} s"; return 3
}'''

#: Where "Zatrzymaj i zarchiwizuj" copies the folders — outside the modules'
#: folder, which keeps only the production modules (owner, 2026-11-19).
ARCHIVE_ROOT = "/opt/old"
#: The marker name of a module's archive step: ``si-aism@old``.
ARCHIVE_SUFFIX = "@old"

_MOD = "@@SI-MOD"
_ENV = "@@SI-ENV"
_PS = "@@SI-PS"
_BEGIN = "@@SI-BEGIN"
_END = "@@SI-END"

_COMPOSE_FILES = ("docker-compose.yml", "docker-compose.yaml",
                  "compose.yml", "compose.yaml")

_DC = ('if docker compose version >/dev/null 2>&1; then DC="docker compose"; '
       'else DC="docker-compose"; fi')


@dataclass
class Container:
    name: str
    image: str = ""
    state: str = ""          # running / exited / restarting / created …
    status: str = ""         # "Up 3 days (healthy)"
    workdir: str = ""
    project: str = ""

    @property
    def exit_code(self) -> int | None:
        """``Exited (0) 5 months ago`` → 0; None when not exited."""
        m = re.match(r"\s*Exited \((-?\d+)\)", self.status or "")
        return int(m.group(1)) if m else None

    @property
    def finished_ok(self) -> bool:
        """A one-off job that did its work and ended with 0 — the Kreator's
        ``asi-liquibase``, ``elasticsearch-before``, ``kibana-after``…
        (owner, 2026-11-19: "dlaczego to traktuje jako uwagę?")."""
        return self.state == "exited" and self.exit_code == 0

    @property
    def healthy(self) -> bool | None:
        s = self.status.lower()
        if "(unhealthy)" in s:
            return False
        if "(healthy)" in s:
            return True
        return None

    @property
    def tag(self) -> str:
        """The image tag — the running version (``1.4.55``)."""
        image = self.image.rsplit("/", 1)[-1]
        return image.split(":", 1)[1] if ":" in image else ""


@dataclass
class Module:
    name: str
    compose_file: str = "docker-compose.yml"
    env: dict = field(default_factory=dict)       # *VERSION* and the project
    containers: list = field(default_factory=list)

    @property
    def project(self) -> str:
        return self.env.get("COMPOSE_PROJECT_NAME", "") or self.name

    @property
    def versions(self) -> dict:
        return {k: v for k, v in self.env.items() if "VERSION" in k}

    def version_text(self) -> str:
        """What the tab shows: the env version(s), else the running tag."""
        vals = []
        for v in self.versions.values():
            if v and v not in vals and not v.startswith("$"):
                vals.append(v)
        if vals:
            return ", ".join(vals)
        tags = []
        for c in self.containers:
            if c.tag and c.tag not in tags:
                tags.append(c.tag)
        return ", ".join(tags)


# ── Privileges ───────────────────────────────────────────────────────────

def privilege_probe() -> str:
    """One line each: the uid, whether docker answers us, whether sudo needs
    no password."""
    return ("id -u; "
            "if docker info >/dev/null 2>&1; then echo DOCKER_OK; fi; "
            "if sudo -n true 2>/dev/null; then echo SUDO_N; fi")


def parse_privilege(text: str) -> str:
    """``root`` | ``docker`` (in the docker group) | ``sudo-n`` | ``sudo-pw``."""
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    if lines and lines[0] == "0":
        return "root"
    if "SUDO_N" in lines:
        return "sudo-n"
    if "DOCKER_OK" in lines:
        return "docker"
    return "sudo-pw"


def wrap(script: str, mode: str) -> str:
    """The command that runs ``script`` with the rights the mode needs."""
    q = shlex.quote(script)
    if mode == "sudo-n":
        return f"sudo -n sh -c {q}"
    if mode == "sudo-pw":
        # -p '' : no prompt text in the output; the password comes on stdin.
        return f"sudo -S -p '' sh -c {q}"
    return f"sh -c {q}"


# ── Scan: modules, their env versions, the containers ────────────────────

def scan_script(root: str = DEFAULT_ROOT) -> str:
    r = shlex.quote(root.rstrip("/") or "/")
    skip = " ".join(shlex.quote(s) for s in sorted(SKIP_DIRS))
    files = " ".join(_COMPOSE_FILES)
    return (
        f"for d in {r}/*/; do\n"
        '  [ -d "$d" ] || continue\n'
        '  n=$(basename "$d")\n'
        f'  case " {skip} " in *" $n "*) continue;; esac\n'
        '  f=""\n'
        f'  for c in {files}; do [ -f "$d$c" ] && f=$c && break; done\n'
        '  [ -z "$f" ] && continue\n'
        f"  printf '{_MOD}\\t%s\\t%s\\n' \"$n\" \"$f\"\n"
        '  for e in .env common.env installer.env; do\n'
        '    [ -f "$d$e" ] || continue\n'
        "    grep -E '^[A-Za-z0-9_]*(VERSION|COMPOSE_PROJECT_NAME)[A-Za-z0-9_]*=' \"$d$e\""
        f" | sed 's/^/{_ENV}\\t'\"$n\"'\\t/'\n"
        '  done\n'
        "done\n"
        f"echo {_PS}\n"
        "docker ps -a --format "
        "'{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t"
        '{{.Label "com.docker.compose.project.working_dir"}}\t'
        '{{.Label "com.docker.compose.project"}}\''
    )


def _clean_value(v: str) -> str:
    v = v.strip().split(" #", 1)[0].strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def parse_scan(text: str, root: str = DEFAULT_ROOT) -> tuple[list, list]:
    """(modules in start order, containers of no module)."""
    root = root.rstrip("/")
    mods: dict[str, Module] = {}
    containers: list[Container] = []
    in_ps = False
    for raw in (text or "").splitlines():
        line = raw.rstrip("\r")
        if line == _PS:
            in_ps = True
            continue
        if not in_ps:
            parts = line.split("\t")
            if parts[0] == _MOD and len(parts) >= 3:
                mods[parts[1]] = Module(parts[1], parts[2])
            elif parts[0] == _ENV and len(parts) >= 3:
                m = mods.get(parts[1])
                kv = "\t".join(parts[2:])
                if m is not None and "=" in kv:
                    k, v = kv.split("=", 1)
                    # .env first, then common.env / installer.env: the first
                    # file that sets a key wins, as docker compose reads .env.
                    m.env.setdefault(k.strip(), _clean_value(v))
            continue
        if not line.strip():
            continue
        p = line.split("\t") + [""] * 6
        containers.append(Container(name=p[0], image=p[1], state=p[2],
                                    status=p[3], workdir=p[4].rstrip("/"),
                                    project=p[5]))
    other = []
    by_project = {}
    for m in mods.values():
        by_project.setdefault(m.project, m)
        by_project.setdefault(m.name, m)
    for c in containers:
        m = None
        if c.workdir:
            base = c.workdir.rsplit("/", 1)
            if len(base) == 2 and base[0] == root:
                m = mods.get(base[1])
        if m is None and c.project:
            m = by_project.get(c.project)
        if m is None:
            other.append(c)
        else:
            m.containers.append(c)
    return start_order(list(mods.values())), other


# ── Order ────────────────────────────────────────────────────────────────

def _rank(name: str) -> tuple:
    if name in _FIRST:
        return (0, _FIRST.index(name), name)
    if name in _LAST:
        return (2, _LAST.index(name), name)
    return (1, 0, name)


def start_order(items: list) -> list:
    """Modules (or names) in the order they start."""
    return sorted(items, key=lambda x: _rank(getattr(x, "name", x)))


def stop_order(items: list) -> list:
    return list(reversed(start_order(items)))


# ── Actions ──────────────────────────────────────────────────────────────

def action_script(root: str, names: list, action: str, tail: int = 300) -> str:
    """Run one docker compose action in each module's folder, in the right
    order; every module is framed by markers with its exit code, and a
    failing module does not stop the others (the tab shows each one)."""
    if action not in ACTIONS:
        raise ValueError(action)
    args = ACTIONS[action][1].format(tail=int(tail))
    stopping = action in ("stop", "stop_archive")
    ordered = stop_order(names) if stopping else start_order(names)
    r = root.rstrip("/") or "/"
    lines = [_DC]
    if action in ("start", "restart"):
        return "\n".join(lines + _start_lines(r, ordered, args))
    for n in ordered:
        d = shlex.quote(f"{r}/{n}")
        qn = shlex.quote(n)
        lines.append(f"echo {_BEGIN} {qn}")
        lines.append(f'( cd {d} && $DC {args} ) 2>&1; '
                     f'echo "{_END} {n} $?"')
    if action == "stop_archive":
        lines += archive_lines(r, ordered)
    return "\n".join(lines)


def is_base(name: str) -> bool:
    """Elastic server, db, keycloak, aism, nginx — the ones others need."""
    return name in _FIRST


def _start_lines(root: str, ordered: list, args: str) -> list:
    """Start (or restart) in order.  After a base module, wait until it is
    up before the next one; a base module that does not come up stops the
    rest (they report SKIPPED).  Service modules start one after another
    without waiting — nothing depends on them."""
    out = [_WAIT_FN, f"SI_WAIT_MAX={WAIT_MAX}",
           f"SI_UNHEALTHY_GRACE={UNHEALTHY_GRACE}", "SI_SKIP=0"]
    for i, n in enumerate(ordered):
        d = shlex.quote(f"{root}/{n}")
        out.append(f"echo {_BEGIN} {shlex.quote(n)}")
        skip = (f'if [ "$SI_SKIP" = 1 ]; then '
                f'echo "  pominięty — wcześniejszy moduł bazowy nie wstał"; '
                f'echo "{_END} {n} {SKIPPED}"; else ')
        waits = is_base(n) and i < len(ordered) - 1
        if waits:
            body = (f'( cd {d} && $DC {args} ) 2>&1; rc=$?; '
                    f'if [ "$rc" = 0 ]; then si_wait {d}; w=$?; '
                    f'if [ "$w" = 4 ]; then rc={RUNNING_UNHEALTHY}; '
                    f'elif [ "$w" != 0 ]; then rc=$((10 + w)); SI_SKIP=1; fi; '
                    f'else SI_SKIP=1; fi; echo "{_END} {n} $rc"')
        elif is_base(n):
            body = (f'( cd {d} && $DC {args} ) 2>&1; rc=$?; '
                    f'if [ "$rc" != 0 ]; then SI_SKIP=1; fi; '
                    f'echo "{_END} {n} $rc"')
        else:
            body = f'( cd {d} && $DC {args} ) 2>&1; echo "{_END} {n} $?"'
        out.append(skip + body + "; fi")
    return out


def archive_target(name: str, stamp: str) -> str:
    return f"{ARCHIVE_ROOT}/{name}_{stamp}"


def archive_lines(root: str, names: list) -> list:
    """Copy each module's folder to ``/opt/old/<module>_<YYYYMMDD-HHMM>``.  A copy,
    not a move: the folders hold the containers' own data too (keycloak's
    ``data``, pi-hl7-provider's messages…), which must stay where the new
    compose files expect them.  An existing target is never overwritten."""
    r = root.rstrip("/") or "/"
    out = ['STAMP=$(date +%Y%m%d-%H%M)',
           f"mkdir -p {shlex.quote(ARCHIVE_ROOT)}"]
    for n in names:
        src = shlex.quote(f"{r}/{n}")
        dst = f'{shlex.quote(f"{ARCHIVE_ROOT}/{n}_")}"$STAMP"'
        mark = n + ARCHIVE_SUFFIX
        out.append(f"echo {_BEGIN} {shlex.quote(mark)}")
        out.append(f'( if [ -e {dst} ]; then echo "już istnieje: "{dst}; exit 3; fi; '
                   f'cp -a {src} {dst} && echo "kopia: "{dst} ) 2>&1; '
                   f'echo "{_END} {mark} $?"')
    return out


_END_RE = re.compile(rf"^{_END} (\S+) (\d+)\s*$")
_BEGIN_RE = re.compile(rf"^{_BEGIN} (\S+)\s*$")


def parse_action_markers(line: str):
    """("begin", name) | ("end", name, code) | None for an output line."""
    s = line.rstrip("\r\n")
    m = _END_RE.match(s)
    if m:
        return ("end", m.group(1), int(m.group(2)))
    m = _BEGIN_RE.match(s)
    if m:
        return ("begin", m.group(1))
    return None


def module_state(m: Module) -> str:
    """``ok`` every service up (none unhealthy) | ``warn`` something failed,
    unhealthy or restarting next to what runs | ``down`` nothing running |
    ``none`` no container at all.  A one-off job that ended with 0 is done,
    not down: it never makes a module ``warn``."""
    if not m.containers:
        return "none"
    running = [c for c in m.containers if c.state == "running"]
    if not running:
        return "down"
    bad = [c for c in m.containers
           if c.state != "running" and not c.finished_ok]
    if bad or any(c.healthy is False for c in running):
        return "warn"
    return "ok"
