import pytest
from p2psec.crypto import Identity
from p2psec import groups
from p2psec.groups import GroupError

POLICY = {"auto_approve_members": True, "max_lease_minutes": 240, "default_lease_minutes": 60,
          "allow_non_member_requests": True}


@pytest.fixture
def people():
    return {n: Identity.generate() for n in ("priya", "elena", "marcus", "jamal", "mallory")}


def pinned_for(people):
    table = {i.fingerprint(): i.ed_pub_bytes() for i in people.values()}
    return table.get


def genesis(p, custodians=("priya", "elena")):
    return groups.make_genesis("g1", "Infrastructure", "desc",
                               custodians=[groups.person(n, p[n]) for n in custodians],
                               members=[groups.person("marcus", p["marcus"])],
                               policy=POLICY, credentials=[], signers=[p[custodians[0]]])


def test_genesis_and_member_change_accepted(people):
    v1 = genesis(people)
    pinned = pinned_for(people)
    assert groups.validate_extension(None, v1, people["marcus"].fingerprint(), pinned) == "accept"
    v2 = groups.make_next(v1, {"members": v1["members"] + [groups.person("jamal", people["jamal"])]},
                          [people["elena"]])
    assert groups.validate_extension(v1, v2, people["marcus"].fingerprint(), pinned) == "accept"


def test_genesis_signed_by_unpaired_key_rejected(people):
    v1 = genesis(people)
    with pytest.raises(GroupError) as e:
        groups.validate_extension(None, v1, people["marcus"].fingerprint(), lambda f: None)
    assert e.value.code == "GENESIS_UNTRUSTED"


def test_not_listed_rejected(people):
    v1 = genesis(people)
    with pytest.raises(GroupError) as e:
        groups.validate_extension(None, v1, people["jamal"].fingerprint(), pinned_for(people))
    assert e.value.code == "NOT_LISTED"


def test_member_self_promotion_rejected(people):
    v1 = genesis(people)
    v2 = groups.make_next(v1, {"custodians": v1["custodians"] + [groups.person("marcus", people["marcus"])]},
                          [people["marcus"]])
    with pytest.raises(GroupError) as e:
        groups.validate_extension(v1, v2, people["marcus"].fingerprint(), pinned_for(people))
    assert e.value.code == "NOT_CUSTODIAN"


def test_custodian_change_needs_majority(people):
    v1 = genesis(people, custodians=("priya", "elena", "jamal"))
    new_c = [c for c in v1["custodians"] if c["name"] != "jamal"]
    one = groups.make_next(v1, {"custodians": new_c}, [people["priya"]])
    with pytest.raises(GroupError) as e:
        groups.validate_extension(v1, one, people["priya"].fingerprint(), pinned_for(people))
    assert e.value.code == "NEED_MAJORITY"
    two = groups.cosign(one, people["elena"])
    assert groups.validate_extension(v1, two, people["priya"].fingerprint(), pinned_for(people)) == "accept"


def test_removed_custodian_fork_rejected(people):
    v1 = genesis(people)
    v2 = groups.make_next(v1, {"description": "real"}, [people["elena"]])
    rogue = groups.make_next(v1, {"description": "rogue"}, [people["priya"]])
    with pytest.raises(GroupError) as e:
        groups.validate_extension(v2, rogue, people["marcus"].fingerprint(), pinned_for(people))
    assert e.value.code == "FORK"
    rogue3 = groups.make_next(rogue, {"description": "rogue3"}, [people["priya"]])
    with pytest.raises(GroupError) as e:
        groups.validate_extension(v2, rogue3, people["marcus"].fingerprint(), pinned_for(people))
    assert e.value.code == "FORK"


def test_gap_is_not_extension(people):
    v1 = genesis(people)
    v2 = groups.make_next(v1, {"description": "2"}, [people["priya"]])
    v3 = groups.make_next(v2, {"description": "3"}, [people["priya"]])
    with pytest.raises(GroupError) as e:
        groups.validate_extension(v1, v3, people["marcus"].fingerprint(), pinned_for(people))
    assert e.value.code == "NOT_EXTENSION"


def test_duplicate_and_stale(people):
    v1 = genesis(people)
    v2 = groups.make_next(v1, {"description": "2"}, [people["priya"]])
    pinned = pinned_for(people)
    assert groups.validate_extension(v2, v2, "x", pinned) == "duplicate"
    assert groups.validate_extension(v2, v1, "x", pinned) == "stale"


def test_tampered_doc_bad_sig(people):
    v1 = genesis(people)
    v2 = groups.make_next(v1, {"description": "2"}, [people["priya"]])
    v2["policy"] = dict(v2["policy"], max_lease_minutes=999)
    with pytest.raises(GroupError) as e:
        groups.validate_extension(v1, v2, "x", pinned_for(people))
    assert e.value.code == "BAD_SIG"


@pytest.mark.parametrize("mutate", [
    lambda d: d["custodians"][0].pop("name"),
    lambda d: d.__setitem__("credentials", ["not-a-dict"]),
    lambda d: d.__setitem__("policy", "nope"),
    lambda d: d.__setitem__("credentials", [{"cred_id": "c", "name": "n", "url": "", "username": "",
                                             "account_type": "Root", "criticality": "Mega"}]),
    lambda d: d.__setitem__("name", "x" * 5000),
])
def test_I5_malformed_doc_rejected(people, mutate):
    doc = genesis(people)
    mutate(doc)
    doc = groups.cosign(dict(doc, sigs=[]), people["priya"])
    with pytest.raises(GroupError) as e:
        groups.validate_extension(None, doc, people["marcus"].fingerprint(), pinned_for(people))
    assert e.value.code == "BAD_SCHEMA"
