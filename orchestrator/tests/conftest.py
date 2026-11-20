import os

import pytest
import pytest_asyncio
from api_helpers import api_client  # noqa: F401
from cryptography.fernet import Fernet
from fake_agent import FakeAgent

from wgoctopus_orch.crypto import Crypto
from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head

os.environ.setdefault("USER", "tester")


@pytest.fixture
def api(request):
    return request.getfixturevalue("api_client")


@pytest_asyncio.fixture
async def fake_agent_factory():
    agents = []

    async def create(count=1, *, delay=0):
        started = []
        for _ in range(count):
            agent = FakeAgent(delay=delay)
            await agent.start()
            agents.append(agent)
            started.append(agent)
        return started

    yield create
    for agent in agents:
        await agent.stop()


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
