"""Relational desired and observed state models."""

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON


def now_utc() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Instance(Base):
    __tablename__ = "instances"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(15), unique=True, nullable=False)
    listen_port: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    address: Mapped[str] = mapped_column(String, nullable=False)
    private_key_enc: Mapped[str] = mapped_column(Text, nullable=False)
    public_key: Mapped[str] = mapped_column(String(44), nullable=False)
    obfuscation: Mapped[dict] = mapped_column(JSON, nullable=False)
    mtu: Mapped[int | None] = mapped_column(Integer)
    egress_interface: Mapped[str | None] = mapped_column(String(15))
    snat_ip: Mapped[str | None] = mapped_column(String)
    endpoint_host: Mapped[str | None] = mapped_column(String)
    client_dns: Mapped[str | None] = mapped_column(String)
    client_keepalive: Mapped[int | None] = mapped_column(Integer)
    client_allowed_ips: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class Node(Base):
    __tablename__ = "nodes"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String, default="awg", nullable=False)
    wan_interface: Mapped[str | None] = mapped_column(String(15))
    hop_ip: Mapped[str | None] = mapped_column(String)
    backend_ip: Mapped[str | None] = mapped_column(String)
    name: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    ssh_host: Mapped[str] = mapped_column(String, nullable=False)
    ssh_port: Mapped[int] = mapped_column(Integer, default=22, nullable=False)
    ssh_user: Mapped[str] = mapped_column(String, nullable=False)
    mgmt_mode: Mapped[str] = mapped_column(String, nullable=False)
    agent_port: Mapped[int] = mapped_column(Integer, default=18080, nullable=False)
    agent_token_enc: Mapped[str] = mapped_column(Text, nullable=False)
    pull_public_key: Mapped[str | None] = mapped_column(Text)
    protected: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0", nullable=False)
    provision_options: Mapped[dict | None] = mapped_column(JSON)
    egress_interface: Mapped[str | None] = mapped_column(String(15))
    snat_ip: Mapped[str | None] = mapped_column(String)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)

class HopLink(Base):
    __tablename__ = "hop_links"
    __table_args__ = (UniqueConstraint("hop_id", "instance_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    hop_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class Probe(Base):
    __tablename__ = "probes"
    __table_args__ = (UniqueConstraint("hop_id", "instance_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    hop_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"), nullable=False)
    runner_node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    peer_id: Mapped[int] = mapped_column(ForeignKey("peers.id", ondelete="CASCADE"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class Placement(Base):
    __tablename__ = "placements"
    __table_args__ = (UniqueConstraint("instance_id", "node_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"), nullable=False)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False)
    weight: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class Peer(Base):
    __tablename__ = "peers"
    __table_args__ = (UniqueConstraint("instance_id", "allowed_ip"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    public_key: Mapped[str] = mapped_column(String(44), nullable=False)
    private_key_enc: Mapped[str | None] = mapped_column(Text)
    preshared_key_enc: Mapped[str | None] = mapped_column(Text)
    allowed_ip: Mapped[str] = mapped_column(String, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    owner: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)


class NodeRevision(Base):
    __tablename__ = "node_revisions"
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True)
    desired_revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    desired_checksum: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class NodeObserved(Base):
    __tablename__ = "node_observed"
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_revision: Mapped[int | None] = mapped_column(Integer)
    applied_checksum: Mapped[str | None] = mapped_column(String(64))
    healthy: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict | None] = mapped_column(JSON)


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    subject: Mapped[str] = mapped_column(String, nullable=False)
    data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class AlertState(Base):
    __tablename__ = "alert_state"
    key: Mapped[str] = mapped_column(String, primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)


class FailoverProposal(Base):
    __tablename__ = "failover_proposals"
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"), nullable=False)
    hop_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    from_node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    to_node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False)
    mode_at_creation: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decided_by: Mapped[str | None] = mapped_column(String)
    error: Mapped[str | None] = mapped_column(Text)


class BotUser(Base):
    __tablename__ = "bot_users"
    __table_args__ = (CheckConstraint("role IN ('admin','user')"), CheckConstraint("status IN ('enabled','disabled')"), CheckConstraint("config_limit >= -1"))
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    tg_id: Mapped[int | None] = mapped_column(Integer, unique=True)
    role: Mapped[str] = mapped_column(String, default="user", nullable=False)
    config_limit: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    status: Mapped[str] = mapped_column(String, default="enabled", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_by: Mapped[str | None] = mapped_column(String)
    language: Mapped[str | None] = mapped_column(String(8))


class UserRequest(Base):
    __tablename__ = "user_requests"
    __table_args__ = (CheckConstraint("type IN ('access','limit')"), CheckConstraint("status IN ('pending','approved','declined')"))
    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, default="pending", nullable=False)
    tg_id: Mapped[int] = mapped_column(Integer, nullable=False)
    username: Mapped[str | None] = mapped_column(String(64))
    first_name: Mapped[str | None] = mapped_column(String)
    last_name: Mapped[str | None] = mapped_column(String)
    requested_limit: Mapped[int | None] = mapped_column(Integer)
    previous_limit: Mapped[int | None] = mapped_column(Integer)
    admin_id: Mapped[int | None] = mapped_column(Integer)
    admin_username: Mapped[str | None] = mapped_column(String(64))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notification_refs: Mapped[list] = mapped_column(JSON, default=list, nullable=False)


class AdminUsernameHistory(Base):
    __tablename__ = "admin_username_history"
    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)


class BootstrapManaged(Base):
    __tablename__ = "bootstrap_managed"
    __table_args__ = (UniqueConstraint("kind", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)


class ProvisionJob(Base):
    __tablename__ = "provision_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False)
    options: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ProvisionStep(Base):
    __tablename__ = "provision_steps"
    __table_args__ = (UniqueConstraint("job_id", "seq"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("provision_jobs.id", ondelete="CASCADE"), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    state: Mapped[str] = mapped_column(String, nullable=False)
    log: Mapped[str] = mapped_column(Text, default="", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WebAccount(Base):
    __tablename__ = "web_accounts"
    __table_args__ = (CheckConstraint("role IN ('admin','operator','viewer')"), CheckConstraint("source IN ('local','oidc')"))
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String, nullable=False)
    source: Mapped[str] = mapped_column(String, default="local", nullable=False)
    subject: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WebSession(Base):
    __tablename__ = "web_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[int] = mapped_column(ForeignKey("web_accounts.id", ondelete="CASCADE"), nullable=False)
    csrf_token: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ip: Mapped[str | None] = mapped_column(String)
