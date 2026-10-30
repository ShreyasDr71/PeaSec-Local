import pytest
from p2psec import db as dbmod
from p2psec.crypto import Identity


@pytest.fixture
def conn(tmp_path):
    c = dbmod.open_db(str(tmp_path / "n.db"))
    yield c
    c.close()


@pytest.fixture
def ident():
    return Identity.generate()
