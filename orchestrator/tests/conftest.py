import pytest
from cryptography.fernet import Fernet

from wgoctopus_orch.crypto import Crypto
from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head


@pytest.fixture
def crypto():
    return Crypto(Fernet.generate_key())


@pytest.fixture
def session(tmp_path):
    url = f"sqlite:///{tmp_path / 'test.db'}"
    upgrade_to_head(url)
    engine = make_engine(url)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar().lower() == "wal"
    factory = make_session_factory(engine)
    with factory() as db:
        yield db
    engine.dispose()
