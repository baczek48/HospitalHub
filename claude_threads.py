"""Saved "Wsparcie Claude" conversations — threads to come back to.

2026-11-13 (owner): "if I want, remember a conversation as a thread — a click
'zapamiętaj', it gets a name from what it was about, and I can return to it
from a list".

How it works, no Qt here:

* every conversation runs as a Claude Code session with an id of ours
  (``--session-id``) in one working folder (:func:`workdir`), so Claude
  Code keeps its record and ``--resume <id>`` brings the whole context back
  — Claude remembers, not just the panel;
* only the threads the owner saved stay: the record of a conversation that
  ends unsaved is deleted (:func:`forget_record`), and records still pending
  after a crash are dealt with at the next login (:meth:`ThreadStore.maintain`).

Encrypted (2026-11-13, owner chose "variant 2" after the security review):
threads hold what Claude saw — terminal text (PESEL masked) and screenshots of
hospital screens (not masked) — so nothing of them stays readable on disk:

* the list (names, tabs, messages) is ``claude_threads.enc`` and the record of
  every saved conversation ``claude_records/<id>.enc`` — AES-256-GCM under a
  random *thread key*;
* the thread key is kept wrapped by the password of the vault (Argon2id, as the
  vault itself) in ``claude_threads.key.json``.  The vault's login unlocks it
  (:func:`unlock`) into memory only; the list is read into memory from then on;
* a record goes back to Claude Code's folder, readable, only while its
  conversation runs (:meth:`ThreadStore.open_record`), and is sealed again —
  encrypted, the plain file deleted — when it ends (:meth:`ThreadStore.seal`);
* sealing takes the screenshots out of the record (``strip_screens``, on by
  default): Claude keeps what was said, not the images;
* threads not used for ``thread_days`` days (30 by default) are deleted.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = ["ThreadStore", "ThreadsLocked", "workdir", "new_session_id",
           "forget_record", "record_path", "make_title", "fallback_title",
           "unlock", "unlock_async", "release", "is_unlocked", "strip_images",
           "LIVE_SESSIONS", "at_exit", "settle", "SCREEN_REMOVED"]

_LIST_FILE = "claude_threads.enc"
_KEY_FILE = "claude_threads.key.json"
_PENDING_FILE = "claude_threads.pending.json"
_RECORDS_DIR = "claude_records"
#: The plain list of 2.0.30 — taken over (encrypted) at the first unlock.
_LEGACY_FILE = "claude_threads.json"

#: Messages kept per thread for the panel (the full context is Claude's record).
_MAX_MESSAGES = 400
_TITLE_MAX = 70
_MAGIC = b"HHT1"
_AAD_LIST = b"hospitalhub/claude-threads/list"
_AAD_KEY = b"hospitalhub/claude-threads/key"

SCREEN_REMOVED = "[zrzut ekranu usunięty z zapisanej rozmowy]"
_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}

#: Session ids of the conversations running in this process — nothing may
#: seal, delete or sweep their records.
LIVE_SESSIONS: set = set()


class ThreadsLocked(Exception):
    """The thread key is not in memory — no vault that holds it is open."""


def _data_dir() -> Path:
    from config import app_data_dir
    return Path(app_data_dir())


def workdir() -> str:
    """The one working folder of every support conversation — Claude Code
    files its records by folder, so a resume must start in the same one."""
    path = _data_dir() / "claude_work"
    path.mkdir(parents=True, exist_ok=True)
    return str(path)


def new_session_id() -> str:
    return str(uuid.uuid4())


_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _claude_projects() -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(
        os.path.expanduser("~"), ".claude")
    return Path(base) / "projects"


def record_path(session_id: str) -> Path | None:
    """Claude Code's record of a session (…/projects/<folder>/<id>.jsonl)."""
    if not _ID.fullmatch(session_id or ""):
        return None
    root = _claude_projects()
    if not root.is_dir():
        return None
    for path in root.glob(f"*/{session_id}.jsonl"):
        return path
    return None


def _long(path) -> str:
    r"""A path Windows takes past 260 characters (\\?\ prefix): Claude Code's
    folder name is the whole working path, its screenshots sit two levels
    deeper — a plain delete failed there, silently (live test 2026-11-13)."""
    text = os.path.abspath(str(path))
    if os.name == "nt" and not text.startswith(_LONG_PREFIX):
        if text.startswith("\\\\"):
            return _LONG_PREFIX + "UNC\\" + text[2:]
        return _LONG_PREFIX + text
    return text


_LONG_PREFIX = "\\\\?\\"


def forget_record(session_id: str) -> bool:
    """Delete Claude Code's record of a session (and its folder of
    attachments — Claude Code keeps a screenshot there as a .png of its own —
    even when the .jsonl is gone already).  False while something is held."""
    if not _ID.fullmatch(session_id or ""):
        return True
    root = _claude_projects()
    if not root.is_dir():
        return True
    ok = True
    for path in root.glob(f"*/{session_id}.jsonl"):
        try:
            os.remove(_long(path))
        except FileNotFoundError:
            pass
        except OSError:
            ok = False
    for folder in root.glob(f"*/{session_id}"):
        if os.path.isdir(_long(folder)):
            shutil.rmtree(_long(folder), ignore_errors=True)
            ok = ok and not os.path.exists(_long(folder))
    return ok


# ══════════════════════════════════════════════════════════════════════════
# Encryption
# ══════════════════════════════════════════════════════════════════════════

def _seal_bytes(key: bytes, plain: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    return _MAGIC + nonce + AESGCM(key).encrypt(nonce, plain, aad)


def _open_bytes(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if blob[:4] != _MAGIC or len(blob) < 4 + 12 + 16:
        raise ValueError("not a thread file")
    return AESGCM(key).decrypt(blob[4:16], blob[16:], aad)


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _read_json(path: Path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return default
    return data if isinstance(data, type(default)) else default


def _write_json(path: Path, data) -> None:
    _write_atomic(path, json.dumps(data, ensure_ascii=False, indent=1).encode("utf-8"))


# ══════════════════════════════════════════════════════════════════════════
# The thread key: wrapped by vault passwords, unwrapped into memory
# ══════════════════════════════════════════════════════════════════════════

_KEY_LOCK = threading.Lock()
_STATE = {"key": None, "owners": set()}


def _vault_id(vault_path: str) -> str:
    return os.path.normcase(os.path.abspath(vault_path or ""))


def _kek(password: str, salt: bytes) -> bytes:
    from crypto import _derive_key
    return bytes(_derive_key(password, salt))


def _wrap(key: bytes, vault_path: str, password: str) -> dict:
    salt, nonce = os.urandom(16), os.urandom(12)
    wrapped = AESGCM(_kek(password, salt)).encrypt(nonce, key, _AAD_KEY)
    return {"vault": _vault_id(vault_path),
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "key": base64.b64encode(wrapped).decode()}


def _unwrap(entry: dict, password: str) -> bytes | None:
    try:
        salt = base64.b64decode(entry["salt"])
        nonce = base64.b64decode(entry["nonce"])
        wrapped = base64.b64decode(entry["key"])
        key = AESGCM(_kek(password, salt)).decrypt(nonce, wrapped, _AAD_KEY)
    except Exception:
        return None
    return key if len(key) == 32 else None


def _has_threads(root: Path) -> bool:
    records = root / _RECORDS_DIR
    return (root / _LIST_FILE).exists() or (
        records.is_dir() and any(records.glob("*.enc")))


def unlock(vault_path: str, password: str, owner=None, root: Path | None = None) -> bool:
    """A vault was opened: its password unwraps the thread key into memory.

    The first vault ever opened makes the key.  A vault whose password wraps
    no key yet gets one wrapped for it — when the key is already in memory
    (another vault open, or a password just changed: the old password's wrap
    of this vault is replaced).  False when the threads stay locked: they
    were saved under a vault that is not open.
    """
    root = Path(root) if root else _data_dir()
    if not password:
        return False
    with _KEY_LOCK:
        key_path = root / _KEY_FILE
        data = _read_json(key_path, {})
        wraps = [w for w in data.get("wraps", []) if isinstance(w, dict)]
        vid = _vault_id(vault_path)
        found, mine = None, False
        for w in wraps:
            k = _unwrap(w, password)
            if k is not None:
                found = k
                mine = mine or w.get("vault") == vid
                if mine:
                    break
        key = found or _STATE["key"]
        if key is None:
            if wraps and _has_threads(root):
                return False
            key, wraps = os.urandom(32), []
        if not mine:
            wraps = [w for w in wraps if w.get("vault") != vid]
            wraps.append(_wrap(key, vault_path, password))
            _write_json(key_path, {"version": 1, "wraps": wraps})
        _STATE["key"] = key
        _STATE["owners"].add(id(owner) if owner is not None else "default")
    try:
        ThreadStore(root).maintain()
    except Exception:
        pass
    return True


def unlock_async(vault_path: str, password: str, owner=None) -> None:
    """:func:`unlock` off the UI thread (Argon2 takes a moment per wrap)."""
    threading.Thread(target=lambda: unlock(vault_path, password, owner),
                     name="claude-threads-unlock", daemon=True).start()


def release(owner=None) -> None:
    """A vault window closed: the key leaves memory with the last one."""
    with _KEY_LOCK:
        _STATE["owners"].discard(id(owner) if owner is not None else "default")
        if not _STATE["owners"]:
            _STATE["key"] = None


def is_unlocked() -> bool:
    return _STATE["key"] is not None


def _current_key() -> bytes | None:
    return _STATE["key"]


# ══════════════════════════════════════════════════════════════════════════
# Screenshots out of a record
# ══════════════════════════════════════════════════════════════════════════

def _strip(obj):
    if isinstance(obj, dict):
        if obj.get("type") == "image":
            return {"type": "text", "text": SCREEN_REMOVED}
        return {k: _strip(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip(v) for v in obj]
    return obj


def strip_images(jsonl: str) -> str:
    """Claude Code's record with every image block replaced by a line of
    text — the conversation stays valid for ``--resume``."""
    out = []
    for line in jsonl.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            out.append(line)
            continue
        out.append(json.dumps(_strip(event), ensure_ascii=False))
    return "\n".join(out) + ("\n" if jsonl.endswith("\n") else "")


def _settings() -> tuple[bool, int]:
    try:
        from config import load_claude_strip_screens, load_claude_thread_days
        return load_claude_strip_screens(), load_claude_thread_days()
    except Exception:
        return True, 30


# ══════════════════════════════════════════════════════════════════════════
# The list
# ══════════════════════════════════════════════════════════════════════════

_SAFE_PART = re.compile(r"[^\\/:*?\"<>|]+")


class ThreadStore:
    """Threads in ``claude_threads.enc``; records in ``claude_records``.

    `key` is for tests; normally the key unlocked by the vault login.
    """

    def __init__(self, root: Path | None = None, *, key: bytes | None = None):
        self._root = Path(root) if root else _data_dir()
        self._key = key
        self._lock = threading.RLock()

    # -- files ---------------------------------------------------------------- #

    @property
    def key(self) -> bytes | None:
        return self._key or _current_key()

    @property
    def unlocked(self) -> bool:
        return self.key is not None

    def _need_key(self) -> bytes:
        key = self.key
        if key is None:
            raise ThreadsLocked()
        return key

    def _record_blob(self, session_id: str) -> Path:
        if not _ID.fullmatch(session_id or ""):
            raise ValueError("bad session id")
        return self._root / _RECORDS_DIR / f"{session_id}.enc"

    def _load(self) -> list[dict]:
        key = self.key
        if key is None:
            return []
        try:
            blob = (self._root / _LIST_FILE).read_bytes()
            data = json.loads(_open_bytes(key, blob, _AAD_LIST).decode("utf-8"))
        except FileNotFoundError:
            return []
        except Exception:
            return []
        threads = data.get("threads") if isinstance(data, dict) else None
        return [t for t in threads if isinstance(t, dict) and t.get("id")] \
            if isinstance(threads, list) else []

    def _save(self, threads: list[dict]) -> None:
        plain = json.dumps({"threads": threads}, ensure_ascii=False).encode("utf-8")
        _write_atomic(self._root / _LIST_FILE,
                      _seal_bytes(self._need_key(), plain, _AAD_LIST))

    def _pending(self) -> list[dict]:
        items = _read_json(self._root / _PENDING_FILE, {}).get("pending", [])
        out = []
        for p in items if isinstance(items, list) else []:
            if isinstance(p, str):                    # the 2.0.30 shape
                p = {"id": p, "saved": False}
            if isinstance(p, dict) and _ID.fullmatch(str(p.get("id", ""))):
                out.append({"id": p["id"], "saved": bool(p.get("saved"))})
        return out

    def _set_pending(self, items: list[dict]) -> None:
        _write_json(self._root / _PENDING_FILE, {"pending": items})

    # -- threads -------------------------------------------------------------- #

    def threads(self) -> list[dict]:
        """Saved threads, the last used first ([] while locked)."""
        with self._lock:
            items = self._load()
        return sorted(items, key=lambda t: t.get("updated", ""), reverse=True)

    def get(self, thread_id: str) -> dict | None:
        return next((t for t in self.threads() if t["id"] == thread_id), None)

    def save(self, thread_id: str, *, title: str, kind: str, label: str,
             messages: list) -> dict:
        """Create or update a thread (its id = the Claude Code session id)."""
        now = datetime.now().isoformat(timespec="seconds")
        with self._lock:
            self._need_key()
            threads = self._load()
            thread = next((t for t in threads if t["id"] == thread_id), None)
            if thread is None:
                thread = {"id": thread_id, "created": now}
                threads.append(thread)
            thread.update(title=(title or "Rozmowa")[:_TITLE_MAX], kind=kind,
                          label=label, updated=now,
                          messages=list(messages)[-_MAX_MESSAGES:])
            self._save(threads)
            pending = self._pending()
            for p in pending:
                if p["id"] == thread_id:
                    p["saved"] = True
            self._set_pending(pending)
            return dict(thread)

    def rename(self, thread_id: str, title: str) -> None:
        with self._lock:
            self._need_key()
            threads = self._load()
            for t in threads:
                if t["id"] == thread_id:
                    t["title"] = (title.strip() or t.get("title", ""))[:_TITLE_MAX]
            self._save(threads)

    def delete(self, thread_id: str) -> None:
        """Forget a thread — its record (sealed or at Claude Code) goes too."""
        with self._lock:
            self._need_key()
            self._save([t for t in self._load() if t["id"] != thread_id])
            try:
                self._record_blob(thread_id).unlink()
            except (OSError, ValueError):
                pass
        forget_record(thread_id)

    def is_saved(self, thread_id: str) -> bool:
        return self.get(thread_id) is not None

    # -- records: readable only while their conversation runs ---------------- #

    def open_record(self, session_id: str) -> bool:
        """A saved thread resumes: its record back where Claude Code reads it.
        False when there is nothing to resume from."""
        if record_path(session_id) is not None:
            return True                      # still there (ended a moment ago)
        with self._lock:
            key = self._need_key()
            try:
                blob = self._record_blob(session_id).read_bytes()
                data = json.loads(_open_bytes(
                    key, blob, session_id.encode("ascii")).decode("utf-8"))
            except (OSError, ValueError):
                return False
            folder = str(data.get("folder", ""))
            if not _SAFE_PART.fullmatch(folder) or folder in (".", ".."):
                return False
            target = _claude_projects() / folder / f"{session_id}.jsonl"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(data.get("jsonl", ""), encoding="utf-8")
            extra = target.with_suffix("")
            for rel, b64 in (data.get("files") or {}).items():
                parts = Path(rel).parts
                if not parts or any(not _SAFE_PART.fullmatch(p) or p in (".", "..")
                                    for p in parts):
                    continue
                dest = extra.joinpath(*parts)
                os.makedirs(_long(dest.parent), exist_ok=True)
                with open(_long(dest), "wb") as fh:
                    fh.write(base64.b64decode(b64))
            return True

    def seal(self, session_id: str) -> bool:
        """Claude Code's record of a saved thread → encrypted, the plain
        file deleted.  False while that cannot be done (locked, file held)."""
        path = record_path(session_id)
        if path is None:
            # Sealed already — a folder of attachments left behind goes.
            return forget_record(session_id)
        key = self.key
        if key is None:
            return False
        strip, _days = _settings()
        try:
            jsonl = path.read_text(encoding="utf-8")
        except OSError:
            return False
        files = {}
        extra = path.with_suffix("")
        if extra.is_dir():
            for f in extra.rglob("*"):
                if not f.is_file():
                    continue
                rel = f.relative_to(extra).as_posix()
                if strip and f.suffix.lower() in _IMAGE_SUFFIXES:
                    continue
                try:
                    with open(_long(f), "rb") as fh:
                        raw = fh.read()
                except OSError:
                    return False
                if strip and f.suffix.lower() in (".json", ".jsonl"):
                    try:
                        raw = strip_images(raw.decode("utf-8")).encode("utf-8")
                    except UnicodeDecodeError:
                        pass
                files[rel] = base64.b64encode(raw).decode("ascii")
        if strip:
            jsonl = strip_images(jsonl)
        plain = json.dumps({"folder": path.parent.name, "jsonl": jsonl,
                            "files": files}, ensure_ascii=False).encode("utf-8")
        with self._lock:
            _write_atomic(self._record_blob(session_id),
                          _seal_bytes(key, plain, session_id.encode("ascii")))
        return forget_record(session_id)

    # -- conversations running / ended --------------------------------------- #

    def started(self, session_id: str, *, saved: bool = False) -> None:
        """A conversation began: its plain record is now on disk until it ends."""
        with self._lock:
            pending = [p for p in self._pending() if p["id"] != session_id]
            pending.append({"id": session_id, "saved": saved})
            self._set_pending(pending)

    def finished(self, session_id: str) -> None:
        """A conversation ended: saved → sealed, unsaved → deleted."""
        if session_id in LIVE_SESSIONS:
            return                           # resumed again in the meantime
        with self._lock:
            pending = self._pending()
            entry = next((p for p in pending if p["id"] == session_id), None)
            saved = (entry["saved"] if entry else False) or self.is_saved(session_id)
            done = self.seal(session_id) if saved else forget_record(session_id)
            if done:
                self._set_pending([p for p in pending if p["id"] != session_id])

    def sweep(self, keep=()) -> None:
        """Records left by conversations that never ended cleanly (a crash,
        a killed process) — except `keep` and the ones still running."""
        keep = set(keep) | LIVE_SESSIONS
        with self._lock:
            pending = self._pending()
            left = []
            for p in pending:
                if p["id"] in keep:
                    left.append(p)
                    continue
                saved = p["saved"] or self.is_saved(p["id"])
                if saved and not self.unlocked:
                    left.append(p)           # sealed at the next unlock
                    continue
                done = self.seal(p["id"]) if saved else forget_record(p["id"])
                if not done:
                    left.append(p)
            if left != pending:
                self._set_pending(left)

    def expire(self, days: int, *, now=None) -> int:
        """Threads not used for `days` days are deleted; how many."""
        if days <= 0 or not self.unlocked:
            return 0
        limit = ((now or datetime.now()) - timedelta(days=days)).isoformat(
            timespec="seconds")
        old = [t["id"] for t in self.threads()
               if t.get("updated", "") < limit and t["id"] not in LIVE_SESSIONS]
        for tid in old:
            self.delete(tid)
        return len(old)

    def _migrate_legacy(self) -> None:
        """The plain list of 2.0.30 → encrypted; its records sealed."""
        legacy = self._root / _LEGACY_FILE
        if not legacy.exists() or not self.unlocked:
            return
        data = _read_json(legacy, {})
        old = [t for t in data.get("threads", []) if isinstance(t, dict)
               and _ID.fullmatch(str(t.get("id", "")))]
        with self._lock:
            threads = self._load()
            known = {t["id"] for t in threads}
            threads += [t for t in old if t["id"] not in known]
            self._save(threads)
            pending = self._pending()
            ids = {p["id"] for p in pending}
            for p in data.get("pending", []):
                if isinstance(p, str) and _ID.fullmatch(p) and p not in ids:
                    pending.append({"id": p, "saved": False})
            for t in old:
                if t["id"] not in ids:
                    pending.append({"id": t["id"], "saved": True})
            self._set_pending(pending)
        try:
            legacy.unlink()
        except OSError:
            pass

    def maintain(self) -> None:
        """After a login: take over 2.0.30's list, seal or delete what a
        crash left, delete threads past their days."""
        self._migrate_legacy()
        self.sweep()
        _strip, days = _settings()
        self.expire(days)


def settle(timeout: float = 2.5, *, final: bool = False) -> None:
    """A vault window (or HospitalHub) is closing, the key is still in memory:
    seal or delete the records of the conversations that just ended (Claude
    Code lets go of a file ~0.5 s after its stdin closes).  Waits only while
    there is such a record.  What cannot be done now is done at the next login."""
    if final:
        LIVE_SESSIONS.clear()
    store = ThreadStore()
    deadline = time.monotonic() + timeout
    while True:
        try:
            store.sweep()
            waiting = [p for p in store._pending() if p["id"] not in LIVE_SESSIONS]
        except Exception:
            return
        if not waiting or time.monotonic() >= deadline:
            return
        time.sleep(0.25)


def at_exit(timeout: float = 2.5) -> None:
    """HospitalHub is quitting: :func:`settle` for every conversation."""
    settle(timeout, final=True)


# ══════════════════════════════════════════════════════════════════════════
# A name from the content
# ══════════════════════════════════════════════════════════════════════════

def fallback_title(messages: list) -> str:
    """The owner's first question, shortened — when Claude cannot name it."""
    first = next((m.get("text", "") for m in messages if m.get("who") == "user"), "")
    first = " ".join(first.split())
    if not first:
        return "Rozmowa " + datetime.now().strftime("%Y-%m-%d %H:%M")
    return first if len(first) <= 60 else first[:57].rstrip() + "…"


_TITLE_PROMPT = (
    "Poniżej jest rozmowa administratora z asystentem o serwerze szpitalnym. "
    "Nadaj jej krótki tytuł po polsku (3–8 słów), mówiący, czego dotyczyła — "
    "system, problem, wniosek. Bez cudzysłowów, bez kropki na końcu, bez danych "
    "osobowych. Odpowiedz tylko tytułem.\n\n")


def _transcript(messages: list, limit: int = 6000) -> str:
    who = {"user": "Administrator", "claude": "Asystent"}
    lines = [f"{who[m['who']]}: {m.get('text', '')}" for m in messages
             if m.get("who") in who]
    text = "\n\n".join(lines)
    return text[-limit:]


def make_title(messages: list, label: str, *, executable: str | None = None,
               run=subprocess.run, timeout: int = 60) -> str:
    """A name for the thread from its content: one short call to Claude Code
    (Haiku, no tools, nothing persisted); the fallback when it fails."""
    from claude_support import _clean_environment, find_claude
    exe = executable or find_claude()
    text = _transcript(messages)
    if not exe or not text.strip():
        return fallback_title(messages)
    prompt = _TITLE_PROMPT + f"Karta: {label}\n\n{text}"
    try:
        result = run([exe, "-p", "--model", "haiku", "--tools", "",
                      "--setting-sources", "", "--no-session-persistence"],
                     input=prompt, capture_output=True, text=True,
                     encoding="utf-8", errors="replace", timeout=timeout,
                     env=_clean_environment(),
                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        return fallback_title(messages)
    title = " ".join((result.stdout or "").split()).strip(" \"'„”.")
    if result.returncode != 0 or not title or len(title) > 120:
        return fallback_title(messages)
    return title[:_TITLE_MAX]
