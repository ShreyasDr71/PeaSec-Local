import copy
import pytest
from p2psec.vault import Vault, BadPassword, Locked

FAST = {"t": 1, "m": 8192, "p": 1}


def test_round_trip_both_tiers():
    v, _ = Vault.create("pw", params=FAST)
    for tier in ("personal", "service"):
        ct = v.enc(tier, "cred", "1", b"s3cret")
        assert v.dec(tier, "cred", "1", ct) == b"s3cret"


def test_wrong_password():
    _, header = Vault.create("pw", params=FAST)
    before = copy.deepcopy(header)
    with pytest.raises(BadPassword):
        Vault.unlock(header, "nope")
    assert header == before


def test_unlock_after_create():
    v, header = Vault.create("pw", params=FAST)
    ct = v.enc("personal", "cred", "1", b"x")
    v2 = Vault.unlock(header, "pw")
    assert v2.dec("personal", "cred", "1", ct) == b"x"


def test_soft_lock_keeps_service_tier():
    v, _ = Vault.create("pw", params=FAST)
    p = v.enc("personal", "cred", "1", b"a")
    s = v.enc("service", "gsec", "1", b"b")
    v.soft_lock()
    assert not v.personal_unlocked and v.service_unlocked
    with pytest.raises(Locked):
        v.dec("personal", "cred", "1", p)
    assert v.dec("service", "gsec", "1", s) == b"b"


def test_full_lock_wipes_both():
    v, _ = Vault.create("pw", params=FAST)
    s = v.enc("service", "gsec", "1", b"b")
    v.full_lock()
    with pytest.raises(Locked):
        v.dec("service", "gsec", "1", s)


def test_unlock_personal_restores_after_soft_lock():
    v, header = Vault.create("pw", params=FAST)
    v.soft_lock()
    v.unlock_personal(header, "pw")
    assert v.personal_unlocked


def test_rewrap():
    v, header = Vault.create("old", params=FAST)
    new_header = v.rewrap(header, "old", "new")
    Vault.unlock(new_header, "new")
    with pytest.raises(BadPassword):
        Vault.unlock(new_header, "old")
