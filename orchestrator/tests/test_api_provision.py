import asyncio
import time

import pytest
from sqlalchemy import select
from test_provision_steps import FakeHost

from wgoctopus_orch.models import ProvisionJob
from wgoctopus_orch.provision import ProvisionError, Step, validate_options
from wgoctopus_orch.provision_steps import STEPS


def swap(client, host=None, steps=None):
    runner = client.app.state.provision

    async def opener(node, settings):
        return host

    runner.executor_factory = opener
    runner.steps = list(steps or STEPS)
    return runner


def wait_state(client, job_id, states, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        view = client.get(f"/v1/provision/jobs/{job_id}").json()
        if view["state"] in states:
            return view
        time.sleep(0.05)
    raise AssertionError(view)


def mk(client, name="n1", **extra):
    r = client.post("/v1/nodes", json={"name": name, "ssh_host": "127.0.0.1", "ssh_user": "root",
                                       "agent_token": "tok-0123456789abcdef", **extra})
    assert r.status_code == 201, r.text
    return r.json()


def test_provision_flow_and_views(api_client):
    client, *_ = api_client
    host = FakeHost()
    swap(client, host)
    node = mk(client, provision={"health_interval": 0})
    assert node["protected"] is False and node["provision"] == {"health_interval": 0}
    r = client.post(f"/v1/nodes/{node['id']}/provision", json={"options": {"image": "agent:t"}})
    assert r.status_code == 202
    job = wait_state(client, r.json()["job_id"], {"succeeded", "failed"})
    assert job["state"] == "succeeded", job
    assert job["options"] == {"health_interval": 0, "image": "agent:t"}
    assert [s["state"] for s in job["steps"]][-1] == "ok"
    assert "tok-0123456789abcdef" not in str(job)
    assert client.get("/v1/provision/jobs").json()[0]["id"] == job["id"]
    assert client.get(f"/v1/provision/jobs?node_id={node['id'] + 5}").json() == []
    assert 'wgoctopus_provision_jobs{state="succeeded"} 1' in client.get("/metrics").text
    assert client.get("/v1/provision/jobs/999").status_code == 404


def test_errors_auth_protected_conflict_cancel(api_client):
    client, *_ = api_client
    gate = {"ev": None}

    async def block(ctx):
        gate["ev"] = asyncio.Event()
        await gate["ev"].wait()

    swap(client, FakeHost(), [Step("block", block)])
    assert client.post("/v1/nodes/99/provision", json={}).status_code == 404
    node = mk(client, protected=True)
    assert client.post(f"/v1/nodes/{node['id']}/provision", json={"options": {"bogus": 1}}).status_code == 422
    assert client.post(f"/v1/nodes/{node['id']}/provision", json={"options": {"image": 5}}).status_code == 422
    r = client.post(f"/v1/nodes/{node['id']}/provision", json={})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "confirmation_required"
    r = client.post(f"/v1/nodes/{node['id']}/provision", json={"confirm_protected": True})
    assert r.status_code == 202
    job_id = r.json()["job_id"]
    wait_state(client, job_id, {"running"})
    dup = client.post(f"/v1/nodes/{node['id']}/provision", json={"confirm_protected": True})
    assert dup.status_code == 409 and dup.json()["detail"]["error"] == "conflict"
    assert client.post(f"/v1/provision/jobs/{job_id}/cancel").status_code == 202
    assert wait_state(client, job_id, {"cancelled"})["state"] == "cancelled"
    assert client.post(f"/v1/provision/jobs/{job_id}/cancel").status_code == 409
    assert client.post("/v1/provision/jobs/999/cancel").status_code == 404
    anon = {"Authorization": ""}
    assert client.get("/v1/provision/jobs", headers=anon).status_code == 401
    assert client.post(f"/v1/nodes/{node['id']}/provision", headers=anon, json={}).status_code == 401


def test_patch_provision_and_protected(api_client):
    client, *_ = api_client
    node = mk(client)
    r = client.patch(f"/v1/nodes/{node['id']}", json={"protected": True, "provision": {"mgmt_user": "wgo"}})
    assert r.status_code == 200 and r.json()["protected"] is True and r.json()["provision"] == {"mgmt_user": "wgo"}
    assert client.patch(f"/v1/nodes/{node['id']}", json={"provision": {"nope": 1}}).status_code == 422
    assert client.patch(f"/v1/nodes/{node['id']}", json={"provision": None}).json()["provision"] is None
    assert client.post("/v1/nodes", json={"name": "bad", "ssh_host": "h", "ssh_user": "u",
                                          "provision": {"x": 1}}).status_code == 422


@pytest.mark.asyncio
async def test_auto_provision_starts_once_and_skips_protected(session, crypto):
    from sqlalchemy.orm import sessionmaker

    from wgoctopus_orch.config import Settings
    from wgoctopus_orch.provision import ProvisionRunner
    from wgoctopus_orch.service import create_node
    create_node(session, "auto1", "127.0.0.1", "root", crypto=crypto,
                provision_options={"auto": True, "health_interval": 0})
    create_node(session, "auto-protected", "127.0.0.1", "root", crypto=crypto, protected=True,
                provision_options={"auto": True})
    create_node(session, "manual", "127.0.0.1", "root", crypto=crypto, provision_options={"mgmt_user": "x"})
    factory = sessionmaker(bind=session.get_bind(), expire_on_commit=False)

    async def opener(node, settings):
        return FakeHost()

    runner = ProvisionRunner(factory, crypto, Settings(), opener, STEPS)
    started = runner.auto_provision()
    assert len(started) == 1
    await asyncio.gather(*runner._tasks.values())
    assert runner.job_view(started[0])["state"] == "succeeded"
    assert runner.auto_provision() == []
    with factory() as s:
        assert len(list(s.scalars(select(ProvisionJob)))) == 1
    runner.cancel(12345)
    await runner.shutdown()


def test_validate_options():
    assert validate_options(None) == {}
    assert validate_options({"auto": True, "health_interval": 0.5}) == {"auto": True, "health_interval": 0.5}
    for bad in ([], {"image": 1}, {"health_attempts": True}, {"zzz": 1}):
        with pytest.raises(ProvisionError):
            validate_options(bad)
