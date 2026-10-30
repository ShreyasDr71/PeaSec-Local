import asyncio
import pytest
from p2psec.crypto import Identity
from p2psec.pairing import PairingInitiator, PairingResponder, PairingError
from p2psec import framing


def card(name):
    return {"name": name, "title": "Engineer", "dept": "IT", "demo": False}


def run_pair(ia, ib):
    a = PairingInitiator(ia, card("A"))
    b = PairingResponder(ib, card("B"))
    m2 = b.on_msg1(a.msg1())
    m4 = b.on_msg3(a.on_msg2(m2))
    a.on_msg4(m4)
    return a, b


def test_honest_pairing_equal_sas_and_cards():
    ia, ib = Identity.generate(), Identity.generate()
    a, b = run_pair(ia, ib)
    assert len(a.sas) == 6 and a.sas.isdigit()
    assert a.sas == b.sas
    assert a.peer_card["name"] == "B" and b.peer_card["name"] == "A"
    assert a.peer_identity_fpr == ib.fingerprint()
    assert b.peer_identity_fpr == ia.fingerprint()


def test_mitm_substitution_mismatched_sas():
    ia, ib, im = Identity.generate(), Identity.generate(), Identity.generate()
    a = PairingInitiator(ia, card("A"))
    b = PairingResponder(ib, card("B"))
    m_as_resp = PairingResponder(im, card("B"))   # Mallory pretends to be B toward A
    m_as_init = PairingInitiator(im, card("A"))   # and to be A toward B
    # A -> M
    m2_to_a = m_as_resp.on_msg1(a.msg1())
    # M -> B
    m2_from_b = b.on_msg1(m_as_init.msg1())
    m3_to_b = m_as_init.on_msg2(m2_from_b)
    m_as_init.on_msg4(b.on_msg3(m3_to_b))
    # back to A
    m3_from_a = a.on_msg2(m2_to_a)
    a.on_msg4(m_as_resp.on_msg3(m3_from_a))
    assert a.sas != b.sas
    assert a.peer_identity_fpr != ib.fingerprint()


def test_commit_mismatch_aborts():
    ia, ib, ix = Identity.generate(), Identity.generate(), Identity.generate()
    a = PairingInitiator(ia, card("A"))
    other = PairingInitiator(ix, card("X"))
    b = PairingResponder(ib, card("B"))
    m2 = b.on_msg1(a.msg1())
    other.msg1()
    forged = other.on_msg2(m2)    # reveal of keys that were not committed
    with pytest.raises(PairingError, match="commit"):
        b.on_msg3(forged)


def test_card_signature_bad_rejected():
    ia, ib = Identity.generate(), Identity.generate()
    a = PairingInitiator(ia, card("A"))
    b = PairingResponder(ib, card("B"))
    m2 = b.on_msg1(a.msg1())
    m3 = a.on_msg2(m2)
    m4 = b.on_msg3(m3)
    m4["card"] = m4["card"][:-2] + ("AA" if m4["card"][-2:] != "AA" else "BB")
    with pytest.raises(PairingError):
        a.on_msg4(m4)


def test_confirmation_exchange():
    a, b = run_pair(Identity.generate(), Identity.generate())
    assert b.on_confirm(a.confirm(True)) is True
    assert a.on_confirm(b.confirm(False)) is False


async def test_frame_too_large_rejected():
    reader = asyncio.StreamReader()
    reader.feed_data((framing.MAX_FRAME + 1).to_bytes(4, "big"))
    with pytest.raises(framing.FrameError):
        await framing.recv_frame(reader)


async def test_frame_round_trip():
    reader = asyncio.StreamReader()
    reader.feed_data(len(b"abc").to_bytes(4, "big") + b"abc")
    assert await framing.recv_frame(reader) == b"abc"
