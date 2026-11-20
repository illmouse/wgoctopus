"""Relational desired and observed state models."""

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
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
