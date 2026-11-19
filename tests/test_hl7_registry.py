"""The "Rejestr HL7" of HospitalHub Portable (owner, 2026-11-19): the
packages of one AMMS order, ACKs nested by their OZID row, read only.

A fake Oracle connection answers the four statements of hl7_registry with
rows shaped like the owner's SYSADM.WYMD_PACZKA / WYMD_PACZKA_OBIEKT."""

import datetime as dt
import os
import sys
import time

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import hl7_registry as hr  # noqa: E402
import models  # noqa: E402

T = dt.datetime(2026, 11, 19, 10, 0, 0)

# gidk → package columns (czy_wyjsc, postac, gener, docel, status, typ, dt)
PACKAGES = {
    "SZSZPM15DCA": ("T", "CPIHL7", "CENTRUM", "^SZPM^", "W", "^OML_O21^", T),
    "20150331131424": ("N", "CPIHL7", "SZPM", "^CENTRUM^", "P", "^ACK^",
                       T + dt.timedelta(seconds=2)),
    "WYN0001": ("N", "WYMD", "SZPM", "^CENTRUM^", "B", "^ORU_R01^",
                T + dt.timedelta(minutes=30)),
}
# (gidk, r_obiektu, id_obiektu, potw_status, potw_kod)
OBJECTS = [
    ("SZSZPM15DCA", "ZLEC", "76764524", None, None),
    ("20150331131424", "POTZ", "76764524", None, None),
    ("20150331131424", "OZID", "SZSZPM15DCA", None, None),
    ("WYN0001", "WYNZ", "76764524", "E", "AE"),
]
CONTENT = {
    "SZSZPM15DCA": "MSH|^~\\&|CENTRUM|SZP|SZPM|LAB|20261119100000||OML^O21|X1|P|2.3\r"
                   "PID|1|85010112345|98265||Kowalski^Jan\r"
                   "ORC|NW|76764524",
}


def _row(gidk, kind, oid, ps, pk):
    czy, via, gen, docel, st, typ, t = PACKAGES[gidk]
    return (gidk, kind, oid, czy, via, gen, docel, st, typ, t, t, None, t,
            ps, pk, None, "@")


class FakeCursor:
    def __init__(self, conn):
        self.c = conn
        self._rows = []

    def execute(self, sql, params=None):
        self.c.log.append((sql, dict(params or {})))
        low = sql.lower()
        if low.startswith("set transaction"):
            self.c.read_only = True
            return
        assert self.c.read_only, "query outside the read-only transaction"
        assert low.lstrip().startswith("select"), sql
        params = params or {}
        if sql == hr.ORDER_SQL:
            self._rows = sorted(
                (_row(*o) for o in OBJECTS if o[2] == params["id"]),
                key=lambda r: (r[9], r[0]))
        elif sql == hr.PACKAGE_SQL:
            self._rows = [(o[1], o[2]) for o in OBJECTS if o[0] == params["g"]]
        elif sql == hr.CONTENT_SQL:
            g = params["g"]
            self._rows = ([(CONTENT.get(g, ""), None, None, None, None, None)]
                          if g in PACKAGES else [])
        elif "r_obiektu = 'OZID'" in sql:
            wanted = set(params.values())
            self._rows = [(o[2],) + _row(*o) for o in OBJECTS
                          if o[1] == "OZID" and o[2] in wanted]
        else:
            raise AssertionError(sql)

    def fetchmany(self, n):
        return self._rows[:n]

    def close(self):
        pass


class FakeConn:
    def __init__(self):
        self.log = []
        self.read_only = False
        self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def rollback(self):
        self.read_only = False

    def close(self):
        self.closed = True


# ── Logic ────────────────────────────────────────────────────────────────

def test_an_order_gives_its_packages_with_the_ack_under_the_one_it_confirms():
    c = FakeConn()
    order, pkgs = hr.find_chain(c, "order", "76764524")
    assert order == "76764524"
    assert [p.gidk for p in pkgs] == ["SZSZPM15DCA", "WYN0001"]
    zlec, wyn = pkgs
    assert [a.gidk for a in zlec.acks] == ["20150331131424"]
    assert zlec.acks[0].ack_for == "SZSZPM15DCA" and zlec.acks[0].is_ack
    assert zlec.outgoing is True and zlec.via_si and zlec.msg_type == "OML_O21"
    assert zlec.receivers == "SZPM"
    assert hr.status_words(zlec) == "W wysłana"
    assert hr.status_words(wyn) == "B błędna" and not wyn.via_si
    assert (wyn.ack_status, wyn.ack_code) == ("E", "AE")


def test_a_package_leads_to_its_order_even_from_an_ack():
    order, pkgs = hr.find_chain(FakeConn(), "package", "WYN0001")
    assert order == "76764524" and len(pkgs) == 2
    order, pkgs = hr.find_chain(FakeConn(), "package", "20150331131424")
    assert order == "76764524"


def test_nothing_found():
    assert hr.find_chain(FakeConn(), "order", "1") == ("1", [])
    assert hr.find_chain(FakeConn(), "package", "NOPE") == ("", [])
    assert hr.find_chain(FakeConn(), "order", "  ") == ("", [])


def test_only_selects_in_a_read_only_transaction_with_binds():
    c = FakeConn()
    hr.find_chain(c, "order", "76764524")
    hr.fetch_content(c, "SZSZPM15DCA")
    sqls = [s.lower() for s, _ in c.log]
    assert sqls.count("set transaction read only") == 2
    for s, params in c.log:
        assert "76764524" not in s and "szszpm15dca" not in s.lower()
    for s in (hr.ORDER_SQL, hr.PACKAGE_SQL, hr.ACK_SQL, hr.CONTENT_SQL):
        low = s.lower()
        assert low.startswith("select")
        for word in ("insert", "update", "delete", "merge", "drop", "alter"):
            assert f" {word} " not in f" {low} "


def test_the_long_content_is_read_by_gidk():
    c = hr.fetch_content(FakeConn(), "SZSZPM15DCA")
    assert c["found"] and "PID|1|85010112345" in c["text"]
    assert hr.fetch_content(FakeConn(), "NOPE") == {"text": "", "found": False}


def test_clean_list_and_direction():
    assert hr.clean_list("^ORU_R01^") == "ORU_R01"
    assert hr.clean_list("^A^B^") == "A, B"
    assert hr.clean_list(None) == ""
    assert hr.direction("T") is True and hr.direction("N") is False
    assert hr.direction(None) is None


# ── The window ───────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def pump_until(cond, timeout=5.0):
    from PyQt6.QtWidgets import QApplication
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        QApplication.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


def _hospital():
    ms = models.Database(host="10.0.0.9", port="1433", name="x", db_type="MSSQL",
                         credentials=[models.Credential(login="sa", password="a")])
    ora = models.Database(host="10.0.0.8", port="1521", name="AMMS",
                          db_type="Oracle",
                          credentials=[models.Credential(login="sysadm",
                                                         password="tajne")])
    return models.Hospital(name="S", databases=[ms, ora]), ora


@pytest.fixture
def win(app):
    from ui.hl7_registry_window import Hl7RegistryWindow
    h, ora = _hospital()
    conns, calls = [], []

    def connect(host, port, service, user, pw):
        calls.append((host, port, service, user, pw))
        conns.append(FakeConn())
        return conns[-1]
    w = Hl7RegistryWindow(h, connect_fn=connect)
    w.show()
    w._test = (h, ora, conns, calls)
    yield w
    w.close()


def test_oracle_comes_first_and_the_choice_is_saved(win):
    h, ora, conns, calls = win._test
    assert win.current_db() is ora
    saved = []
    win.data_changed.connect(lambda: saved.append(dict(h.si)))
    win._db.setCurrentIndex(1)
    assert saved and saved[-1]["hl7_db"] == h.databases[0].id


def test_search_fills_the_register_and_shows_the_message(win):
    h, ora, conns, calls = win._test
    win._value.setText("76764524")
    win.search()
    assert pump_until(lambda: win._tree.topLevelItemCount() == 2, 5)
    assert calls == [("10.0.0.8", "1521", "AMMS", "sysadm", "tajne")]
    from ui.hl7_registry_window import COL
    top = win._tree.topLevelItem(0)
    assert top.text(COL["GIDK"]) == "SZSZPM15DCA" and COL["GIDK"] == 0
    # The ACK under its package, closed (owner, 2026-11-19).
    assert top.childCount() == 1 and not top.isExpanded()
    assert [COL[c] for c in ("Kier.", "Status", "Typ", "Wygenerowana")] == [
        1, 2, 3, 4]
    # The letter only, its meaning in the bubble (owner, 2026-11-19).
    assert top.text(COL["Status"]) == "W"
    assert top.toolTip(COL["Status"]) == "W wysłana"
    # Raw content first and shown, wrapped to the window.
    from PyQt6.QtWidgets import QPlainTextEdit
    assert win._tabs.tabText(0) == "Surowa treść"
    assert win._tabs.currentWidget() is win._raw
    assert win._raw.lineWrapMode() == QPlainTextEdit.LineWrapMode.WidgetWidth
    assert top.text(COL["Typ"]) == "OML_O21" and top.text(COL["Kanał"]) == "SI"
    assert top.text(COL["Wygenerowana"]) == "19.11 10:00:00"
    assert top.childCount() == 1 and top.child(0).text(COL["Typ"]) == "ACK"
    assert "paczek 2, ACK 1" in win._info.text()
    assert pump_until(lambda: win._segs.topLevelItemCount() == 3, 5)
    pid = win._segs.topLevelItem(1)
    assert pid.text(0) == "PID"
    fields = {pid.child(i).text(0): pid.child(i).text(2)
              for i in range(pid.childCount())}
    assert fields["PID.2"] == "85010112345" and fields["PID.3"] == "98265"
    assert "85010112345" in win._raw.toPlainText()
    # One connection for the search and the content.
    assert len(conns) == 1


def test_show_ack_selects_it_and_a_package_without_one_says_so(win):
    win._value.setText("76764524")
    win.search()
    assert pump_until(lambda: win._tree.topLevelItemCount() == 2, 5)
    pump_until(lambda: not win.busy(), 5)
    zlec = win._tree.topLevelItem(0).data(0, 0x0100)
    win.show_ack(zlec)
    assert win._current_package().gidk == "20150331131424"
    wyn = win._tree.topLevelItem(1).data(0, 0x0100)
    win.show_ack(wyn)
    assert "brak ACK" in win._info.text() and "E AE" in win._info.text()


def test_a_database_without_a_login_is_refused_with_a_message(app):
    from ui.hl7_registry_window import Hl7RegistryWindow
    ora = models.Database(host="h", port="1521", name="AMMS", db_type="Oracle")
    w = Hl7RegistryWindow(models.Hospital(name="S", databases=[ora]),
                          connect_fn=lambda *a: pytest.fail("connected"))
    w._value.setText("1")
    w.search()
    assert pump_until(lambda: "loginu" in w._info.text(), 5)
    w.close()


def test_closing_the_window_closes_the_connection(win):
    h, ora, conns, calls = win._test
    win._value.setText("76764524")
    win.search()
    assert pump_until(lambda: bool(conns), 5)
    pump_until(lambda: not win.busy(), 5)
    win.close()
    assert conns[0].closed


@pytest.mark.parametrize("host,port,name,want", [
    # The owner's vault, 2026-11-19: the JDBC URL of AMMS in the host field.
    ("jdbc:oracle:thin:@10.20.30.40:1521:amms01", "1521", "amms01",
     ("10.20.30.40", 1521, "", "amms01")),
    ("jdbc:oracle:thin:@//10.0.0.8:1522/AMMS", "1521", "x",
     ("10.0.0.8", 1522, "AMMS", "")),
    ("10.0.0.8:1523/AMMSP", "", "x", ("10.0.0.8", 1523, "AMMSP", "")),
    ("10.0.0.8", "1521", "AMMS", ("10.0.0.8", 1521, "AMMS", "")),
])
def test_where_the_database_is(host, port, name, want):
    t = hr.parse_target(host, port, name)
    assert (t["host"], t["port"], t["service"], t["sid"]) == want


def test_a_tns_descriptor_is_used_as_it_is():
    t = hr.parse_target("(DESCRIPTION=(ADDRESS=(HOST=a)(PORT=1)))", "", "")
    assert t["descriptor"].startswith("(DESCRIPTION")


def test_the_driver_loads_with_its_cryptography():
    pytest.importorskip("oracledb")
    out = hr.selftest()
    assert out.startswith("thin: OK "), out


def test_the_label_is_readable():
    from ui.hl7_registry_window import db_label
    d = models.Database(host="jdbc:oracle:thin:@10.20.30.40:1521:amms01",
                        port="1521", name="amms01", db_type="Oracle")
    assert db_label(d) == "10.20.30.40:1521 · SID amms01 · Oracle"


# ── Old 10G passwords: the thick driver (owner's sysadm, DPY-3015) ───────

class _FakeOracle:
    class Error(Exception):
        pass

    def __init__(self, fail_thin):
        self.fail_thin = fail_thin
        self.thick = None
        self.calls = []

    def makedsn(self, host, port, sid=None, service_name=None):
        return f"{host}:{port}:{sid or service_name}"

    def connect(self, user, password, dsn):
        self.calls.append(("thick" if self.thick else "thin", dsn))
        if not self.thick and self.fail_thin:
            raise self.Error("DPY-3015: password verifier type 0x939 is not "
                             "supported by python-oracledb in thin mode")

        class C:
            call_timeout = 0
        return C()

    def init_oracle_client(self, lib_dir, config_dir):
        self.thick = (lib_dir, config_dir)


@pytest.fixture
def fake_oracle(monkeypatch):
    def make(fail_thin=True):
        f = _FakeOracle(fail_thin)
        monkeypatch.setitem(sys.modules, "oracledb", f)
        monkeypatch.setitem(hr._thick, "lib", "")
        return f
    return make


def test_an_old_password_goes_to_the_instant_client_found(fake_oracle,
                                                          monkeypatch, tmp_path):
    f = fake_oracle()
    ic = tmp_path / "instantclient_19_29"
    ic.mkdir()
    (ic / "oci.dll").write_bytes(b"")
    monkeypatch.setattr(hr, "_program_dir", lambda: str(tmp_path))
    hr.connect("jdbc:oracle:thin:@10.20.30.40:1521:amms01", "1521", "amms01",
               "sysadm", "x")
    assert f.calls == [("thin", "10.20.30.40:1521:amms01"),
                       ("thick", "10.20.30.40:1521:amms01")]
    lib, cfg = f.thick
    assert lib == str(ic)
    with open(os.path.join(cfg, "sqlnet.ora"), encoding="ascii") as fh:
        assert "SQLNET.ALLOWED_LOGON_VERSION_CLIENT=10" in fh.read()


def test_without_an_instant_client_the_message_says_what_to_do(
        fake_oracle, monkeypatch, tmp_path):
    fake_oracle()
    monkeypatch.setattr(hr, "_program_dir", lambda: str(tmp_path))
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("ORACLE_HOME", raising=False)
    with pytest.raises(hr.NeedsInstantClient, match="instantclient_19"):
        hr.connect("10.0.0.1", "1521", "AMMS", "u", "p")


def test_a_new_password_stays_thin(fake_oracle):
    f = fake_oracle(fail_thin=False)
    hr.connect("10.0.0.1", "1521", "AMMS", "u", "p")
    assert f.thick is None and [c[0] for c in f.calls] == ["thin"]


def test_url_encoded_content_is_decoded_into_segments():
    """Owner's srv-si, 2026-11-19: TRESC is stored URL-encoded and showed as
    one MSH line with fields MSH.83, MSH.129…"""
    stored = ("MSH|^~\\&|SZPM||RADPOINT||20260514075058||ORM^O01|SZSZPM1BAE97"
              "|P|2.3%0DPID|1|85010112345|98265||Kowalski^Jan%0D"
              "OBR|1||76764524|TK-001^Komputerowa tomografia g%C5%82owy%0D")
    text, decoded = hr.decode_content(stored)
    assert decoded
    import hl7_parser
    assert [s.name for s in hl7_parser.parse(text).segments] == ["MSH", "PID",
                                                                 "OBR"]
    assert "głowy" in text


def test_a_plain_message_is_left_as_it_is():
    plain = "MSH|^~\\&|A|B\rPID|1|100%25 pewne"
    assert hr.decode_content(plain) == (plain, False)
    assert hr.decode_content("") == ("", False)


def test_a_field_or_a_segment_can_be_copied_from_segmenty(win):
    """Owner, 2026-11-19: "jak skopiować z Segmenty jakąś pozycję?"."""
    from PyQt6.QtWidgets import QApplication
    win._value.setText("76764524")
    win.search()
    assert pump_until(lambda: win._segs.topLevelItemCount() == 3, 5)
    pump_until(lambda: not win.busy(), 5)
    pid = win._segs.topLevelItem(1)
    pid3 = next(pid.child(i) for i in range(pid.childCount())
                if pid.child(i).text(0) == "PID.3")
    win._segs.setCurrentItem(pid3)
    win._copy_text(win._seg_value(win._segs.currentItem()))
    assert QApplication.clipboard().text() == "98265"
    win._copy_text(win._seg_value(pid))
    assert QApplication.clipboard().text().startswith("PID|1|85010112345|98265")
    assert "Skopiowano" in win._info.text()
