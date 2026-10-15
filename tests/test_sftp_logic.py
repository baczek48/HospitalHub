"""Unit tests for the pure helpers extracted from ssh_panel.

We cover the bits that could quietly break or get slow:

* `_pl_pl` — drives the Polish text in the delete-confirm dialog. Wrong
  declension would surface as "1 pliki, 4 podkatalogów" which would
  embarrass us. Cheap to test, regressions are easy to spot.
* `_ssh_fingerprint` — the fingerprint shown in the TOFU prompt. A
  wrong format (or a typo in the hashing) would make every host look
  unrecognisable and quietly tempt users into clicking "accept new
  key" out of resignation. Security-critical.
* `_count_dir_with_cap` — runs against every delete-confirm. A bug
  here can either freeze the UI for minutes (no early bail) or under-
  count the blast radius (wrong stack discipline). Performance + UX.

The full ssh_panel module pulls in PyQt6, paramiko, and pyte. We
tolerate the heavy import here because the test cost is dwarfed by
the cost of a regression — but we DO NOT spin up a QApplication. If
the import ever grows side effects, extract the helpers into a leaf
module.
"""

import os
import sys
import hashlib
import stat as _stat

import pytest


# Make `import ui.ssh_panel` work whether the tests run from the
# project root or from inside hospital_hub/.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from ui.ssh_panel import (  # noqa: E402
    _pl_pl,
    _ssh_fingerprint,
    _count_dir_with_cap,
)


# ── _pl_pl ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("n,expected", [
    (0,  "0 plików"),       # zero takes the genitive plural
    (1,  "1 plik"),
    (2,  "2 pliki"),
    (3,  "3 pliki"),
    (4,  "4 pliki"),
    (5,  "5 plików"),
    (10, "10 plików"),
    (11, "11 plików"),      # 11-14 always genitive plural
    (12, "12 plików"),
    (13, "13 plików"),
    (14, "14 plików"),
    (21, "21 plików"),      # last digit 1 but not "1" → genitive plural
    (22, "22 pliki"),
    (23, "23 pliki"),
    (24, "24 pliki"),
    (25, "25 plików"),
    (101, "101 plików"),
    (102, "102 pliki"),
    (111, "111 plików"),
    (112, "112 plików"),
])
def test_pl_pl_files(n, expected):
    assert _pl_pl(n, "plik", "pliki", "plików") == expected


def test_pl_pl_works_for_dirs_too():
    # Same machinery on a different noun set — sanity, not exhaustive.
    assert _pl_pl(1, "katalog", "katalogi", "katalogów") == "1 katalog"
    assert _pl_pl(3, "katalog", "katalogi", "katalogów") == "3 katalogi"
    assert _pl_pl(5, "katalog", "katalogi", "katalogów") == "5 katalogów"


# ── _ssh_fingerprint ──────────────────────────────────────────────────

class _FakeKey:
    """Minimal stand-in for paramiko.PKey — _ssh_fingerprint only uses
    asbytes()."""
    def __init__(self, raw: bytes):
        self._raw = raw
    def asbytes(self) -> bytes:
        return self._raw


def test_ssh_fingerprint_format():
    key = _FakeKey(b"\x00\x01\x02 the key bytes \x99")
    hex_fp, display_fp = _ssh_fingerprint(key)

    # Hex form is the literal sha256 of the raw bytes (back-compat with
    # the legacy known_hosts JSON the app already wrote to disk).
    expected_hex = hashlib.sha256(b"\x00\x01\x02 the key bytes \x99").hexdigest()
    assert hex_fp == expected_hex

    # Display form is the OpenSSH-style `SHA256:base64` with no padding.
    assert display_fp.startswith("SHA256:")
    body = display_fp.removeprefix("SHA256:")
    assert "=" not in body, "OpenSSH fingerprints have no padding"
    # And it decodes back to the same 32-byte digest.
    import base64
    pad = "=" * (-len(body) % 4)
    digest = base64.b64decode(body + pad)
    assert digest == hashlib.sha256(b"\x00\x01\x02 the key bytes \x99").digest()


def test_ssh_fingerprint_stable_across_calls():
    key = _FakeKey(b"static")
    a = _ssh_fingerprint(key)
    b = _ssh_fingerprint(key)
    assert a == b


# ── _count_dir_with_cap ──────────────────────────────────────────────

class _Attr:
    """Mirror of paramiko's SFTPAttributes for what we read."""
    def __init__(self, filename: str, is_dir: bool):
        self.filename = filename
        self.st_mode = (_stat.S_IFDIR if is_dir else _stat.S_IFREG) | 0o644


def _tree_listdir(tree: dict):
    """Build a listdir_attr-style callable from a {path: [_Attr,...]} dict.
    Missing keys raise IOError to mimic paramiko's "no such directory"."""
    def _listdir(path):
        try:
            return list(tree[path])
        except KeyError:
            raise IOError(f"No such file or directory: {path}")
    return _listdir


def test_count_empty_directory():
    listdir = _tree_listdir({'/root': []})
    res = _count_dir_with_cap(listdir, '/root', cap=100)
    assert res == {'files': 0, 'dirs': 0, 'capped': False, 'error': None}


def test_count_flat_directory():
    tree = {'/root': [_Attr('a.txt', False), _Attr('b.txt', False),
                      _Attr('c.txt', False)]}
    res = _count_dir_with_cap(_tree_listdir(tree), '/root', cap=100)
    assert res['files'] == 3
    assert res['dirs'] == 0
    assert res['capped'] is False
    assert res['error'] is None


def test_count_nested_directory():
    tree = {
        '/root':     [_Attr('sub1', True), _Attr('top.txt', False)],
        '/root/sub1': [_Attr('file1', False), _Attr('sub2', True)],
        '/root/sub1/sub2': [_Attr('deep.log', False), _Attr('other.log', False)],
    }
    res = _count_dir_with_cap(_tree_listdir(tree), '/root', cap=100)
    # top.txt + file1 + deep.log + other.log = 4 files
    # sub1 + sub2 = 2 dirs
    assert res['files'] == 4
    assert res['dirs'] == 2
    assert res['capped'] is False


def test_count_hits_cap_and_bails_early():
    # 50 files at the top — cap is 10 → we stop counting.
    tree = {'/root': [_Attr(f'f{i}.txt', False) for i in range(50)]}
    res = _count_dir_with_cap(_tree_listdir(tree), '/root', cap=10)
    assert res['capped'] is True
    # cap+1 is acceptable — the loop notices on the entry that pushes
    # us past the threshold, so we don't have to count exactly to cap.
    assert res['files'] <= 11
    assert res['files'] >= 10


def test_count_root_unreadable_sets_error():
    listdir = _tree_listdir({})  # no entries at all
    res = _count_dir_with_cap(listdir, '/root', cap=100)
    assert res['error'] is not None
    assert res['files'] == 0
    assert res['dirs'] == 0


def test_count_subdir_unreadable_continues_with_partial():
    # /root lists fine; one subdir is unreadable; counting should
    # surface the visible entries and ignore the broken subdir, not
    # bubble an error to the top.
    tree = {
        '/root': [
            _Attr('readable', True),
            _Attr('broken', True),
            _Attr('top.txt', False),
        ],
        '/root/readable': [_Attr('inside.log', False)],
        # '/root/broken' deliberately absent — listdir raises IOError
    }
    res = _count_dir_with_cap(_tree_listdir(tree), '/root', cap=100)
    assert res['error'] is None              # broken subdir is non-fatal
    # 2 dirs (readable, broken) + 2 files (top.txt, inside.log)
    assert res['dirs'] == 2
    assert res['files'] == 2


def test_count_handles_deep_tree_without_recursion_limit():
    # 2000 nested dirs would blow Python's default recursion limit on a
    # recursive implementation. Iterative version must keep up.
    tree = {}
    path = '/root'
    for i in range(2000):
        sub = f'd{i}'
        tree[path] = [_Attr(sub, True)]
        path = path.rstrip('/') + '/' + sub
    tree[path] = []
    res = _count_dir_with_cap(_tree_listdir(tree), '/root', cap=5000)
    assert res['dirs'] == 2000
    assert res['files'] == 0
    assert res['capped'] is False
    assert res['error'] is None
