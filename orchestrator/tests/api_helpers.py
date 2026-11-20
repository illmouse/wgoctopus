import asyncio

import pytest
from fastapi.testclient import TestClient

from wgoctopus_orch.api import create_app
from wgoctopus_orch.db import make_engine, make_session_factory, upgrade_to_head
from wgoctopus_orch.push import PushOutcome, PushStatus


class RecordingReconciler:
    def __init__(self):
        self.kicks = []
        self.dangerous = []
        self.statuses = {}
        self._kick = asyncio.Event()

    def kick(self, node_id, **kwargs):
        self.kicks.append((node_id, kwargs))

    def status(self):
        return self.statuses

    async def apply_dangerous(self, node_id):
        self.dangerous.append(node_id)
        return PushOutcome(PushStatus.OK, revision=3)

    async def run(self, stop):
        await stop.wait()


@pytest.fixture
def api_client(tmp_path, crypto, monkeypatch):
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", "test-admin-token")
    url = f"sqlite:///{tmp_path / 'api.db'}"
    upgrade_to_head(url)
    engine = make_engine(url)
    sessions = make_session_factory(engine)
    reconciler = RecordingReconciler()
    app = create_app(session_factory=sessions, reconciler=reconciler, crypto=crypto, migrate=False)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer test-admin-token"
        yield client, sessions, reconciler, crypto
    engine.dispose()
