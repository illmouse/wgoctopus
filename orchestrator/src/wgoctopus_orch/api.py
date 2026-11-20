"""HTTP API for the orchestrator service."""
# ruff: noqa: B008, C408, BLE001
import hmac
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import service
from .config import database_url
from .crypto import Crypto
from .db import make_engine, make_session_factory, upgrade_to_head
from .models import Event, Instance, Node, NodeObserved, NodeRevision, Peer, Placement
from .reconciler import build_reconciler

log = logging.getLogger(__name__)


def _token():
    token = os.getenv("WGOCTOPUS_API_TOKEN")
    path = os.getenv("WGOCTOPUS_API_TOKEN_FILE")
    if token is None and path:
        try:
            token = Path(path).read_text().strip()
        except OSError as exc:
            raise RuntimeError("cannot read WGOCTOPUS_API_TOKEN_FILE") from exc
    return token


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InstanceIn(Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,14}$")
    listen_port: int = Field(ge=1, le=65535)
    address: str
    obfuscation: dict | None = None
    mtu: int | None = Field(default=None, ge=576, le=9000)
    egress_interface: str | None = None
    snat_ip: str | None = None


class InstancePatch(Strict):
    mtu: int | None = Field(default=None, ge=576, le=9000)
    egress_interface: str | None = None
    snat_ip: str | None = None


class PlacementIn(Strict):
    role: str = Field(default="active", pattern="^(active|standby)$")
    weight: int = Field(default=1, ge=1)


class NodeIn(Strict):
    name: str
    ssh_host: str
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_user: str
    mgmt_mode: str = Field(default="push", pattern="^(push|pull)$")
    agent_port: int = Field(default=18080, ge=1, le=65535)
    agent_token: str | None = None
    egress_interface: str | None = None
    snat_ip: str | None = None
    enabled: bool = True


class PeerIn(Strict):
    name: str
    owner: str | None = None


class PeerPatch(Strict):
    enabled: StrictBool | None = None
    owner: str | None = None
    name: str | None = None


class NodePatch(Strict):
    name: str | None = Field(default=None, min_length=1)
    ssh_host: str | None = None
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_user: str | None = None
    mgmt_mode: str | None = Field(default=None, pattern="^(push|pull)$")
    agent_port: int | None = Field(default=None, ge=1, le=65535)
    agent_token: str | None = None
    egress_interface: str | None = None
    snat_ip: str | None = None
    enabled: bool | None = None


def create_app(*, session_factory=None, reconciler=None, crypto=None, migrate=None):
    engine = make_engine(database_url()) if session_factory is None else None
    sessions = session_factory or make_session_factory(engine)
    cipher = crypto or Crypto()
    enabled = os.getenv("WGOCTOPUS_RECONCILER_ENABLED", "true").lower() == "true"

    @asynccontextmanager
    async def lifespan(app):
        if migrate if migrate is not None else os.getenv("WGOCTOPUS_AUTO_MIGRATE", "true").lower() == "true":
            try:
                upgrade_to_head()
            except Exception:
                log.exception("Database migration failed")
                raise
        if reconciler is None and enabled:
            app.state.reconciler = build_reconciler(__import__("wgoctopus_orch.config", fromlist=["Settings"]).Settings.from_env(), sessions)
        else:
            app.state.reconciler = reconciler
        stop = __import__("asyncio").Event()
        task = __import__("asyncio").create_task(app.state.reconciler.run(stop)) if app.state.reconciler else None
        yield
        if task:
            stop.set()
            app.state.reconciler._kick.set()
            await task
        if engine:
            engine.dispose()

    docs = os.getenv("WGOCTOPUS_API_DOCS", "false").lower() == "true"
    app = FastAPI(lifespan=lifespan, openapi_url="/openapi.json" if docs else None,
                  docs_url="/docs" if docs else None)
    app.state.sessions = sessions
    app.state.crypto = cipher
    app.state.reconciler = reconciler
    token = _token()
    allow_no_auth = os.getenv("WGOCTOPUS_API_ALLOW_NO_AUTH", "false").lower() == "true"
    if not token and not allow_no_auth:
        raise RuntimeError("WGOCTOPUS_API_TOKEN or WGOCTOPUS_API_TOKEN_FILE is required")
    if not token:
        log.warning("API authentication disabled; development mode only")

    def db():
        with sessions() as session:
            try:
                yield session
                session.commit()
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

    def auth(authorization: str | None = Header(default=None)):
        if token and (not authorization or not authorization.startswith("Bearer ") or
                      not hmac.compare_digest(authorization[7:], token)):
            raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})

    def kick(session, node_ids):
        reconciler_obj = app.state.reconciler
        if reconciler_obj:
            for ident in set(node_ids):
                reconciler_obj.kick(ident)

    def placed_nodes(session, instance_id):
        return session.scalars(select(Placement.node_id).where(Placement.instance_id == instance_id)).all()

    def inst(i, session):
        peers = session.scalar(select(__import__("sqlalchemy").func.count(Peer.id)).where(Peer.instance_id == i.id))
        placements = session.scalars(select(Placement).where(Placement.instance_id == i.id)).all()
        return dict(id=i.id, name=i.name, listen_port=i.listen_port, address=i.address, public_key=i.public_key,
                    obfuscation=i.obfuscation, mtu=i.mtu, egress_interface=i.egress_interface, snat_ip=i.snat_ip,
                    placements=[dict(node_id=p.node_id, role=p.role, weight=p.weight) for p in placements], peer_count=peers,
                    created_at=i.created_at)

    def node(n, session):
        rev=session.get(NodeRevision,n.id); obs=session.get(NodeObserved,n.id)
        status=(app.state.reconciler.status().get(n.id) if app.state.reconciler else None)
        return dict(id=n.id,name=n.name,ssh_host=n.ssh_host,ssh_port=n.ssh_port,ssh_user=n.ssh_user,
                    mgmt_mode=n.mgmt_mode,agent_port=n.agent_port,egress_interface=n.egress_interface,snat_ip=n.snat_ip,
                    enabled=n.enabled,desired_revision=rev.desired_revision if rev else None,
                    observed=dict(last_seen_at=obs.last_seen_at,applied_revision=obs.applied_revision,healthy=obs.healthy,last_error=obs.last_error) if obs else None,
                    reconciler=dict(state=status.state.value,last_attempt_at=status.last_attempt_at,next_attempt_at=status.next_attempt_at,
                                    consecutive_failures=status.consecutive_failures,last_outcome=status.last_outcome.status.value) if status else None)

    def peer(p):
        return dict(id=p.id,instance_id=p.instance_id,name=p.name,public_key=p.public_key,allowed_ip=p.allowed_ip,
                    enabled=p.enabled,owner=p.owner,created_at=p.created_at)

    @app.exception_handler(ValueError)
    async def value_error(_, exc):
        return JSONResponse(status_code=404 if str(exc).startswith("unknown ") else 422,
                            content={"error":"not_found" if str(exc).startswith("unknown ") else "validation_error","detail":str(exc)})

    @app.exception_handler(HTTPException)
    async def http_error(_, exc):
        code = "not_found" if exc.status_code == 404 else "conflict" if exc.status_code == 409 else "unauthorized" if exc.status_code == 401 else "error"
        return JSONResponse(status_code=exc.status_code, content={"error":code,"detail":exc.detail}, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(_: Request, exc: RequestValidationError):
        return JSONResponse(status_code=422, content={"error":"validation_error","detail":exc.errors()})

    @app.exception_handler(IntegrityError)
    async def integrity_error(_, exc):
        return JSONResponse(status_code=409,content={"error":"conflict","detail":"resource conflicts with existing state"})

    @app.get("/healthz")
    def health(): return {"status":"ok"}

    @app.get("/readyz")
    def ready():
        try:
            with sessions() as s: s.execute(select(1))
            cipher.decrypt(cipher.encrypt("ready"))
            return {"status":"ready"}
        except Exception: raise HTTPException(503,"not ready")

    @app.post("/v1/instances", dependencies=[Depends(auth)], status_code=201)
    def create_instance(body: InstanceIn, s: Session=Depends(db)):
        return inst(service.create_instance(s,body.name,body.listen_port,body.address,obfuscation=body.obfuscation,mtu=body.mtu,egress_interface=body.egress_interface,snat_ip=body.snat_ip,crypto=cipher),s)

    @app.get("/v1/instances", dependencies=[Depends(auth)])
    def list_instances(s: Session=Depends(db)): return [inst(i,s) for i in s.scalars(select(Instance)).all()]

    @app.get("/v1/instances/{ident}", dependencies=[Depends(auth)])
    def get_instance(ident:int,s:Session=Depends(db)):
        i=s.get(Instance,ident)
        if not i: raise HTTPException(404,"unknown instance")
        return inst(i,s)

    @app.patch("/v1/instances/{ident}",dependencies=[Depends(auth)])
    def patch_instance(ident:int, body:InstancePatch, s:Session=Depends(db)):
        i=s.get(Instance,ident)
        if not i: raise HTTPException(404,"unknown instance")
        for k,v in body.model_dump(exclude_unset=True).items(): setattr(i,k,v)
        nodes=placed_nodes(s,ident); s.flush()
        for n in nodes: service.bump_revision(s,n,cipher)
        kick(s,nodes); return inst(i,s)

    @app.delete("/v1/instances/{ident}",dependencies=[Depends(auth)],status_code=204)
    def delete_instance(ident:int,s:Session=Depends(db)):
        i=s.get(Instance,ident)
        if not i: raise HTTPException(404,"unknown instance")
        if s.scalar(select(Peer.id).where(Peer.instance_id==ident)) or s.scalar(select(Placement.id).where(Placement.instance_id==ident)): raise HTTPException(409,"instance has peers or placements")
        s.delete(i); return Response(status_code=204)

    @app.put("/v1/instances/{ident}/placements/{node_id}",dependencies=[Depends(auth)])
    def put_placement(ident:int,node_id:int,body:PlacementIn,s:Session=Depends(db)):
        body=body.model_dump()
        if not s.get(Instance, ident): raise HTTPException(404,"unknown instance")
        if not s.get(Node, node_id): raise HTTPException(404,"unknown node")
        p=s.scalar(select(Placement).where(Placement.instance_id==ident,Placement.node_id==node_id))
        if p: p.role=body.get("role","active"); p.weight=body.get("weight",1); s.flush(); service.bump_revision(s,node_id,cipher)
        else: p=service.place(s,ident,node_id,body.get("role","active"),body.get("weight",1),cipher)
        kick(s,[node_id]); return dict(instance_id=ident,node_id=node_id,role=p.role,weight=p.weight)

    @app.delete("/v1/instances/{ident}/placements/{node_id}",dependencies=[Depends(auth)],status_code=204)
    def del_placement(ident:int,node_id:int,s:Session=Depends(db)):
        p=s.scalar(select(Placement).where(Placement.instance_id==ident,Placement.node_id==node_id))
        if not p: raise HTTPException(404,"unknown placement")
        s.delete(p); s.flush(); service.bump_revision(s,node_id,cipher); kick(s,[node_id]); return Response(status_code=204)

    @app.post("/v1/nodes",dependencies=[Depends(auth)],status_code=201)
    def create_node(body:NodeIn,s:Session=Depends(db)):
        n=service.create_node(s,body.name,body.ssh_host,body.ssh_user,ssh_port=body.ssh_port,mgmt_mode=body.mgmt_mode,agent_port=body.agent_port,agent_token=body.agent_token,egress_interface=body.egress_interface,snat_ip=body.snat_ip,enabled=body.enabled,crypto=cipher)
        return node(n,s)

    @app.get("/v1/nodes",dependencies=[Depends(auth)])
    def list_nodes(s:Session=Depends(db)): return [node(n,s) for n in s.scalars(select(Node)).all()]

    @app.get("/v1/nodes/{ident}",dependencies=[Depends(auth)])
    def get_node(ident:int,s:Session=Depends(db)):
        n=s.get(Node,ident)
        if not n: raise HTTPException(404,"unknown node")
        return node(n,s)

    @app.patch("/v1/nodes/{ident}",dependencies=[Depends(auth)])
    def patch_node(ident:int,body:NodePatch,s:Session=Depends(db)):
        n=s.get(Node,ident)
        if not n: raise HTTPException(404,"unknown node")
        body=body.model_dump(exclude_unset=True)
        for k,v in body.items():
            if k == "agent_token":
                n.agent_token_enc = cipher.encrypt(v)
            else:
                setattr(n, k, v)
        if body:
            service.bump_revision(s,ident,cipher)
        kick(s,[ident]); return node(n,s)

    @app.delete("/v1/nodes/{ident}",dependencies=[Depends(auth)],status_code=204)
    def delete_node(ident:int,s:Session=Depends(db)):
        n=s.get(Node,ident)
        if not n: raise HTTPException(404,"unknown node")
        if s.scalar(select(Placement.id).where(Placement.node_id==ident)): raise HTTPException(409,"node has placements")
        s.delete(n); return Response(status_code=204)

    @app.post("/v1/instances/{ident}/peers",dependencies=[Depends(auth)],status_code=201)
    def create_peer(ident:int,body:PeerIn,s:Session=Depends(db)):
        try:
            p=service.add_peer(s,ident,body.name,owner=body.owner,crypto=cipher)
        except ValueError as exc:
            if "no free peer IPs" in str(exc):
                raise HTTPException(409, "instance subnet has no free peer address") from exc
            raise
        kick(s,placed_nodes(s,ident)); return peer(p)

    @app.get("/v1/instances/{ident}/peers",dependencies=[Depends(auth)])
    def list_peers(ident:int,owner:str|None=None,enabled:bool|None=None,limit:int=Query(100,ge=1,le=1000),offset:int=Query(0,ge=0),s:Session=Depends(db)):
        q=select(Peer).where(Peer.instance_id==ident)
        if owner is not None:q=q.where(Peer.owner==owner)
        if enabled is not None:q=q.where(Peer.enabled==enabled)
        return [peer(p) for p in s.scalars(q.offset(offset).limit(limit)).all()]

    @app.get("/v1/peers/{ident}",dependencies=[Depends(auth)])
    def get_peer(ident:int,s:Session=Depends(db)):
        p=s.get(Peer,ident)
        if not p: raise HTTPException(404,"unknown peer")
        return peer(p)

    @app.patch("/v1/peers/{ident}",dependencies=[Depends(auth)])
    def patch_peer(ident:int,body:PeerPatch,s:Session=Depends(db)):
        p=s.get(Peer,ident)
        if not p: raise HTTPException(404,"unknown peer")
        body=body.model_dump(exclude_unset=True)
        nodes=placed_nodes(s,p.instance_id)
        if "enabled" in body: service.set_peer_enabled(s,ident,body.pop("enabled"),cipher)
        for k,v in body.items():setattr(p,k,v)
        if body:
            s.flush()
            for n in nodes:service.bump_revision(s,n,cipher)
        kick(s,nodes); return peer(p)

    @app.delete("/v1/peers/{ident}",dependencies=[Depends(auth)],status_code=204)
    def delete_peer(ident:int,s:Session=Depends(db)):
        nodes=placed_nodes(s,s.get(Peer,ident).instance_id) if s.get(Peer,ident) else []
        if not service.remove_peer(s,ident,cipher): raise HTTPException(404,"unknown peer")
        kick(s,nodes); return Response(status_code=204)

    @app.get("/v1/peers/{ident}/config",dependencies=[Depends(auth)])
    def peer_config(ident:int,endpoint_host:str|None=None,s:Session=Depends(db)):
        endpoint_host=endpoint_host or os.getenv("WGOCTOPUS_CLIENT_ENDPOINT_HOST")
        if not endpoint_host: raise HTTPException(422,"endpoint_host is required")
        text=service.render_client_config(s,ident,endpoint_host,crypto=cipher)
        s.add(Event(kind="peer.config_issued",subject=str(ident),data={}))
        return Response(text,media_type="text/plain",headers={"Cache-Control":"no-store"})

    @app.post("/v1/nodes/{ident}/reconcile",dependencies=[Depends(auth)],status_code=202)
    def reconcile(ident:int, s: Session=Depends(db)):
        if not s.get(Node, ident): raise HTTPException(404,"unknown node")
        r=app.state.reconciler
        if not r: raise HTTPException(503,"reconciler disabled")
        r.kick(ident,force=True); return {"status":"accepted"}

    @app.post("/v1/nodes/{ident}/apply-dangerous",dependencies=[Depends(auth)])
    async def apply_dangerous(ident:int,body:dict,s:Session=Depends(db)):
        if body!={"confirm":True}: raise HTTPException(422,"confirm must be true")
        if not s.get(Node, ident): raise HTTPException(404,"unknown node")
        r=app.state.reconciler
        if not r: raise HTTPException(503,"reconciler disabled")
        outcome=await r.apply_dangerous(ident)
        return {"status":outcome.status.value,"error":outcome.error}

    @app.get("/v1/events",dependencies=[Depends(auth)])
    def events(limit:int=Query(100,ge=1,le=1000),kind:str|None=None,subject:str|None=None,s:Session=Depends(db)):
        q=select(Event).order_by(Event.id.desc())
        if kind:q=q.where(Event.kind==kind)
        if subject:q=q.where(Event.subject==subject)
        return [dict(id=e.id,ts=e.ts,kind=e.kind,subject=e.subject,data=e.data) for e in s.scalars(q.limit(limit)).all()]

    @app.get("/v1/status",dependencies=[Depends(auth)])
    def status(s:Session=Depends(db)):
        states={k:0 for k in ["IN_SYNC","SYNCING","UNREACHABLE","BLOCKED_DANGEROUS","BLOCKED_REVISION_AHEAD","BLOCKED_INVALID","BLOCKED_AUTH","DISABLED","UNKNOWN"]}
        statuses=app.state.reconciler.status().values() if app.state.reconciler else []
        for st in statuses: states[st.state.value]+=1
        return {"nodes_by_state":states,"nodes_unhealthy":s.scalar(select(__import__("sqlalchemy").func.count(NodeObserved.node_id)).where(NodeObserved.healthy.is_(False))),
                "instances":s.scalar(select(__import__("sqlalchemy").func.count(Instance.id))),"peers":s.scalar(select(__import__("sqlalchemy").func.count(Peer.id)))}

    return app
