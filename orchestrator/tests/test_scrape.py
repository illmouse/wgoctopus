import asyncio
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from wgoctopus_orch.api import create_app
from wgoctopus_orch.config import Settings
from wgoctopus_orch.metrics import render_metrics
from wgoctopus_orch.models import Event, Node
from wgoctopus_orch.reconciler import NodeState, Reconciler
from wgoctopus_orch.transport import DirectHttpTransport


async def converge(rec, predicate, attempts=30):
    for _ in range(attempts):
        await rec.reconcile_once()
        if predicate():
            return
        await asyncio.sleep(0.02)
    assert predicate(), "agent did not converge"


def setup_api(session, crypto, monkeypatch, *, scrape_timeout=1, enabled=True):
    sessions = sessionmaker(bind=session.get_bind(), expire_on_commit=False)
    settings = Settings(transport="direct", scrape_timeout=scrape_timeout, scrape_enabled=enabled)
    rec = Reconciler(sessions, lambda _: DirectHttpTransport(settings, crypto=crypto), settings, crypto=crypto)
    async def idle(stop_event):
        await stop_event.wait()

    rec.run = idle
    token = "scrape-api-token"
    monkeypatch.setenv("WGOCTOPUS_API_TOKEN", token)
    client = TestClient(create_app(session_factory=sessions, reconciler=rec, crypto=crypto, migrate=False))
    client.headers["Authorization"] = f"Bearer {token}"
    return client, sessions, rec


def add_node_and_instance(client, agent, name="scrape-node", instance_name="wg0", listen_port=51820):
    node_response = client.post("/v1/nodes", json={"name": name, "ssh_host": "127.0.0.1", "ssh_user": "root",
        "agent_port": agent.port, "agent_token": agent.token})
    node_response.raise_for_status()
    node = node_response.json()
    instance_response = client.post("/v1/instances", json={"name": instance_name, "listen_port": listen_port,
        "address": "10.0.0.1/24"})
    instance_response.raise_for_status()
    instance = instance_response.json()
    client.put(f"/v1/instances/{instance['id']}/placements/{node['id']}", json={"role": "active"}).raise_for_status()
    return node, instance


@pytest.mark.asyncio
async def test_scrape_success_metrics_and_unknown_peer(session, crypto, fake_agent_factory, monkeypatch):
    (agent,) = await fake_agent_factory()
    client, sessions, rec = setup_api(session, crypto, monkeypatch)
    with client:
        node, instance = add_node_and_instance(client, agent, "scrape-success", "wg-success")
        peers = [client.post(f"/v1/instances/{instance['id']}/peers", json={"name": f"peer{i}"}).json() for i in range(2)]
        now = datetime(2025, 1, 1, tzinfo=UTC)
        agent.metrics_text = "\n".join([
            'wg_interface_up{interface="wg-success"} 1',
            *[f'wg_peer_last_handshake_timestamp_seconds{{interface="wg-success",public_key="{p["public_key"]}"}} {now.timestamp() - age}' for p, age in zip(peers, (179, 181))],
            *[f'wg_peer_rx_bytes_total{{interface="wg-success",public_key="{p["public_key"]}"}} {12+i}' for i, p in enumerate(peers)],
            *[f'wg_peer_tx_bytes_total{{interface="wg-success",public_key="{p["public_key"]}"}} {34+i}' for i, p in enumerate(peers)],
            f'wg_peer_rx_bytes_total{{interface="wg-success",public_key="{"Z"*43}="}} 9',
        ])
        rec.kick(node["id"], force=True)
        await converge(rec, lambda: rec.status().get(node["id"]) and rec.status()[node["id"]].state == NodeState.IN_SYNC)
        with sessions() as db:
            text = render_metrics(db, rec, now=now)
    for p, age in zip(peers, (179, 181)):
        assert f'peer="{p["name"]}"' in text
        assert f'wgoctopus_peer_handshake_age_seconds{{node="scrape-success",instance="wg-success",peer="{p["name"]}"}} {float(age)}' in text
    assert 'wgoctopus_instance_peers_active{node="scrape-success",instance="wg-success"} 1' in text
    assert 'wgoctopus_unknown_peers{node="scrape-success",instance="wg-success"} 1' in text
    assert 'wgoctopus_interface_up{node="scrape-success",instance="wg-success"} 1' in text
    assert "Z" * 43 not in text


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["http", "garbage", "timeout"])
async def test_scrape_failure_is_non_disruptive_and_keeps_previous_data(session, crypto, fake_agent_factory, monkeypatch, mode):
    (agent,) = await fake_agent_factory()
    client, sessions, rec = setup_api(session, crypto, monkeypatch, scrape_timeout=.3 if mode == "timeout" else 1)
    with client:
        node, instance = add_node_and_instance(client, agent, f"scrape-{mode}", f"wg-{mode}")
        peer = client.post(f"/v1/instances/{instance['id']}/peers", json={"name": "peer"}).json()
        agent.metrics_text = f'wg_interface_up{{interface="wg-{mode}"}} 1\nwg_peer_rx_bytes_total{{interface="wg-{mode}",public_key="{peer["public_key"]}"}} 1'
        rec.kick(node["id"], force=True)
        await converge(rec, lambda: rec.scrapes().get(node["id"], None) is not None and rec.scrapes()[node["id"]].ok)
        if mode == "http":
            agent.metrics_status = 500
        elif mode == "garbage":
            agent.metrics_text = "garbage\nnot a metric"
        else:
            agent.metrics_delay = 1.0
        rec.kick(node["id"], force=True)
        await rec.reconcile_once([node["id"]])
        scrape = rec.scrapes()[node["id"]]
        assert not scrape.ok
        assert rec.status()[node["id"]].state == NodeState.IN_SYNC
    with sessions() as db:
        text = render_metrics(db, rec)
        event_kinds = set(db.scalars(select(Event.kind)).all())
        assert db.get(Node, node["id"]).enabled
    assert f'wgoctopus_node_scrape_success{{node="scrape-{mode}"}} 0' in text
    assert f'wgoctopus_peer_rx_bytes_total{{node="scrape-{mode}",instance="wg-{mode}",peer="peer"}} 1' in text
    assert "reconcile.error" not in event_kinds and "node.unreachable" not in event_kinds


@pytest.mark.asyncio
async def test_scrape_disabled_and_hop_are_not_scraped(session, crypto, fake_agent_factory, monkeypatch):
    backend, hop = await fake_agent_factory(2)
    client, _, rec = setup_api(session, crypto, monkeypatch)
    _, instance = add_node_and_instance(client, backend, "scrape-hop", "wg-hop")
    hop_response = client.post("/v1/nodes", json={"name": "scrape-hop-node", "kind": "hop", "wan_interface": "eth0", "hop_ip": "192.0.2.20",
        "ssh_host": "192.0.2.21", "ssh_user": "root", "agent_port": hop.port, "agent_token": hop.token}).json()
    hop_node = hop_response
    client.put(f"/v1/hops/{hop_node['id']}/links/{instance['id']}")
    with client:
        await converge(rec, lambda: bool(rec.status()))
    assert not any(req[1] == "/metrics" for req in hop.requests)
    (disabled,) = await fake_agent_factory()
    client2, _, rec2 = setup_api(session, crypto, monkeypatch, enabled=False)
    n, _ = add_node_and_instance(client2, disabled, "disabled-scrape", "wg-disabled", listen_port=51821)
    with client2:
        await converge(rec2, lambda: rec2.status().get(n["id"]) is not None)
    assert not any(req[1] == "/metrics" for req in disabled.requests)


def test_scrape_optional_rendering_and_api_secrets(api):
    from types import SimpleNamespace

    from wgoctopus_orch.metrics import render_metrics

    client, sessions, _, _ = api
    with sessions() as db:
        assert render_metrics(db, None) == render_metrics(db, SimpleNamespace())
    text = client.get("/metrics").text
    for secret in ("test-token-not-secret", "192.0.2.10", "198.51.100."):
        assert secret not in text
