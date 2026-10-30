import re
import pytest
from cryptography.exceptions import InvalidTag
from p2psec import crypto


def test_aead_round_trip():
    key = crypto.random_key()
    ct = crypto.aead_encrypt(key, b"hunter2", "cred|1")
    assert crypto.aead_decrypt(key, ct, "cred|1") == b"hunter2"


def test_aead_wrong_aad_rejected():
    key = crypto.random_key()
    ct = crypto.aead_encrypt(key, b"hunter2", "cred|1")
    with pytest.raises(InvalidTag):
        crypto.aead_decrypt(key, ct, "cred|2")


def test_aead_tamper_rejected():
    key = crypto.random_key()
    ct = bytearray(crypto.aead_encrypt(key, b"hunter2", "cred|1"))
    ct[-1] ^= 1
    with pytest.raises(InvalidTag):
        crypto.aead_decrypt(key, bytes(ct), "cred|1")


def test_from_seed_deterministic_and_per_node():
    a1 = crypto.Identity.from_seed("s", "priya")
    a2 = crypto.Identity.from_seed("s", "priya")
    b = crypto.Identity.from_seed("s", "marcus")
    assert a1.ed_pub_bytes() == a2.ed_pub_bytes()
    assert a1.x_pub_bytes() == a2.x_pub_bytes()
    assert a1.ed_pub_bytes() != b.ed_pub_bytes()


def test_fingerprint_format():
    fpr = crypto.Identity.generate().fingerprint()
    assert re.fullmatch(r"([0-9a-f]{4} ){7}[0-9a-f]{4}", fpr)


def test_identity_private_round_trip():
    a = crypto.Identity.generate()
    b = crypto.Identity.from_private_bytes(a.private_bytes())
    assert b.fingerprint() == a.fingerprint()


def test_verify_rejects_modified_message():
    ident = crypto.Identity.generate()
    sig = crypto.sign(ident.ed_priv, b"msg")
    assert crypto.verify(ident.ed_pub_bytes(), sig, b"msg")
    assert not crypto.verify(ident.ed_pub_bytes(), sig, b"msh")


def test_canonical_json_stable():
    assert crypto.canonical_json({"b": 1, "a": [1, "é"]}) == '{"a":[1,"é"],"b":1}'.encode()
