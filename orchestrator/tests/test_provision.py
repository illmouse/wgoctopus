import asyncio

import pytest
from sqlalchemy import select

from wgoctopus_orch.config import Settings
from wgoctopus_orch.models import Event, ProvisionJob, ProvisionStep
from wgoctopus_orch.provision import ProvisionError, ProvisionRunner, Step
from wgoctopus_orch.service import create_node


class FakeExecutor:
    use_sudo = False
    async def run(self, *args, **kwargs):
        return None
    async def close(self):
        pass


def factory_for(session):
    from sqlalchemy.orm import sessionmaker
    return sessionmaker(bind=session.get_bind(), expire_on_commit=False)


@pytest.mark.asyncio
async def test_runner_persists_order_redaction_events_and_views(session, crypto):
    node = create_node(session, "provision-me", "127.0.0.1", "root", agent_token="secret-token", crypto=crypto)
    calls = []
    async def first(ctx):
        calls.append("first")
        ctx.log(ctx.token)
    async def skipped(ctx):
        calls.append("skip")
        return "skipped"
    runner = ProvisionRunner(factory_for(session), crypto, Settings(), lambda *_: FakeExecutor(),
                             [Step("one", first), Step("two", skipped)])
    job_id = runner.create_job(node.id, {"test": True})
    await runner.run_job(job_id)
    view = runner.job_view(job_id)
    assert calls == ["first", "skip"]
    assert view["state"] == "succeeded" and [s["state"] for s in view["steps"]] == ["ok", "skipped"]
    assert "secret-token" not in view["steps"][0]["log"]
    assert runner.list_jobs(node.id)[0]["id"] == job_id
    assert {e.kind for e in session.scalars(select(Event).where(Event.kind.like("provision.%")))} == {
        "provision.started", "provision.succeeded"}
    assert all("secret-token" not in str(e.data) for e in session.scalars(select(Event)))


@pytest.mark.asyncio
async def test_failure_duplicate_protected_cancel_recovery(session, crypto):
    node = create_node(session, "provision-fail", "127.0.0.1", "root", agent_token="secret-token", crypto=crypto)
    async def fail(ctx):
        ctx.log("safe")
        raise ProvisionError("bad secret-token")
    async def never(ctx):
        pytest.fail("later step ran")
    runner = ProvisionRunner(factory_for(session), crypto, Settings(), lambda *_: FakeExecutor(),
                             [Step("bad", fail), Step("later", never)])
    job_id = runner.create_job(node.id)
    with pytest.raises(ProvisionError, match="already"):
        runner.create_job(node.id)
    await runner.run_job(job_id)
    view = runner.job_view(job_id)
    assert view["state"] == "failed" and view["steps"][0]["state"] == "failed"
    assert view["steps"][1]["state"] == "pending" and "secret-token" not in view["error"]
    runner.is_protected = lambda _: True
    with pytest.raises(ProvisionError, match="confirmation"):
        runner.create_job(node.id)
    assert runner.create_job(node.id, confirm_protected=True)
    with factory_for(session).begin() as s:
        running = ProvisionJob(node_id=node.id, state="running", options={})
        s.add(running)
        s.flush()
        s.add(ProvisionStep(job_id=running.id, seq=0, name="x", state="running"))
        interrupted_id = running.id
    runner.recover_interrupted()
    assert runner.job_view(interrupted_id)["error"] == "interrupted by restart"


@pytest.mark.asyncio
async def test_cancel_marks_job_cancelled(session, crypto):
    node = create_node(session, "provision-cancel", "127.0.0.1", "root", crypto=crypto)
    entered, wait = asyncio.Event(), asyncio.Event()
    async def block(ctx):
        entered.set()
        await wait.wait()
    runner = ProvisionRunner(factory_for(session), crypto, Settings(), lambda *_: FakeExecutor(), [Step("block", block)])
    job = runner.create_job(node.id)
    task = runner.run_in_background(job)
    await entered.wait()
    assert runner.active_jobs() == [job]
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert runner.job_view(job)["state"] == "cancelled"
    assert runner.job_view(job)["steps"][0]["state"] == "failed"
