from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class QueueEntry(Base):
    __tablename__ = "queue_entries"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    queue_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    message_id: Mapped[str | None] = mapped_column(Text, index=True)
    envelope_from: Mapped[str | None] = mapped_column(Text, index=True)
    size: Mapped[int | None] = mapped_column(BigInteger)
    recipient_count: Mapped[int | None] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=False), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=False))
    client_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    client_name: Mapped[str | None] = mapped_column(Text)
    sasl_username: Mapped[str | None] = mapped_column(Text, index=True)


class QueueLink(Base):
    __tablename__ = "queue_links"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    parent_queue_id: Mapped[str] = mapped_column(String(32), index=True)
    child_queue_id: Mapped[str] = mapped_column(String(32), index=True)
    relation: Mapped[str] = mapped_column(String(32))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=False))
    __table_args__ = (UniqueConstraint("parent_queue_id", "child_queue_id", "relation"),)


class DeliveryAttempt(Base):
    __tablename__ = "delivery_attempts"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    queue_id: Mapped[str] = mapped_column(String(32), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), index=True)
    recipient: Mapped[str | None] = mapped_column(Text, index=True)
    original_recipient: Mapped[str | None] = mapped_column(Text, index=True)
    transport: Mapped[str] = mapped_column(String(64))
    relay: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str | None] = mapped_column(String(32), index=True)
    dsn: Mapped[str | None] = mapped_column(String(16))
    reply: Mapped[str | None] = mapped_column(Text)
    delay: Mapped[str | None] = mapped_column(String(32))
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    __table_args__ = (
        Index("ix_delivery_recipient_time", "recipient", "occurred_at"),
        UniqueConstraint("queue_id", "occurred_at", "recipient", "status", "relay", "reply", name="uq_delivery_event"),
    )


class Rejection(Base):
    __tablename__ = "rejections"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), index=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    sender: Mapped[str | None] = mapped_column(Text, index=True)
    recipient: Mapped[str | None] = mapped_column(Text, index=True)
    stage: Mapped[str | None] = mapped_column(String(32))
    reply: Mapped[str | None] = mapped_column(Text)
    __table_args__ = (UniqueConstraint("occurred_at", "client_ip", "sender", "recipient", "reply", name="uq_rejection_event"),)


class IngestCheckpoint(Base):
    __tablename__ = "ingest_checkpoints"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source: Mapped[str] = mapped_column(Text, unique=True)
    fingerprint: Mapped[str] = mapped_column(Text)
    byte_offset: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=False))
