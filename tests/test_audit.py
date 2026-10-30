from p2psec.audit import AuditLog
from p2psec import db as dbmod


def _log(conn, ident, n=5):
    log = AuditLog(conn, ident)
    for i in range(n):
        log.append("CRED_VIEWED", {"cred_id": f"c{i}"}, {"i": i})
    return log


def test_chain_verifies(conn, ident):
    log = _log(conn, ident)
    assert log.verify() == (True, None)
    assert log.head()[0] == 5


def test_edit_detected(conn, ident):
    log = _log(conn, ident)
    conn.execute("UPDATE audit SET details='{\"i\":99}' WHERE seq=3")
    assert log.verify() == (False, 3)


def test_delete_middle_detected(conn, ident):
    log = _log(conn, ident)
    conn.execute("DELETE FROM audit WHERE seq=2")
    ok, bad = log.verify()
    assert not ok and bad == 3


def test_forged_signature_detected(conn, ident):
    from p2psec.crypto import Identity
    log = _log(conn, ident)
    AuditLog(conn, Identity.generate())  # another key cannot validate this log
    conn.execute("UPDATE audit SET sig=? WHERE seq=4", (b"\x00" * 64,))
    assert log.verify() == (False, 4)


def test_anchor_regression_alerts(conn, ident):
    log = AuditLog(conn, ident)
    assert log.record_anchor("peer", 10, "aa")
    assert not log.record_anchor("peer", 7, "bb")
    alerts = dbmod.rows(conn, "SELECT * FROM alerts")
    assert alerts[0]["kind"] == "LOG_ANCHOR_MISMATCH"


def test_anchor_same_seq_different_hash_alerts(conn, ident):
    log = AuditLog(conn, ident)
    log.record_anchor("peer", 10, "aa")
    assert not log.record_anchor("peer", 10, "bb")
    assert log.record_anchor("peer", 11, "cc")
