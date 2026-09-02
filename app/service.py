from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .models import DeliveryAttempt, QueueEntry, QueueLink, Rejection


def human_status(attempt: DeliveryAttempt) -> str:
    if attempt.status == "sent" and "/lmtp" in attempt.transport and (attempt.dsn or "").startswith("2"):
        return "delivered"
    if attempt.status == "sent":
        return "sent"
    if attempt.status == "deferred":
        return "queued"
    if attempt.status == "bounced":
        return "failed"
    return attempt.status or "unknown"


def search(session: Session, query: str, limit: int = 100) -> list[dict]:
    like = f"%{query.strip()}%"
    stmt = (
        select(DeliveryAttempt, QueueEntry)
        .outerjoin(QueueEntry, QueueEntry.queue_id == DeliveryAttempt.queue_id)
        .where(or_(
            DeliveryAttempt.recipient.ilike(like), DeliveryAttempt.original_recipient.ilike(like),
            QueueEntry.envelope_from.ilike(like), QueueEntry.message_id.ilike(like),
            QueueEntry.queue_id.ilike(like), QueueEntry.sasl_username.ilike(like), QueueEntry.client_ip.ilike(like),
        ))
        .order_by(DeliveryAttempt.occurred_at.desc()).limit(min(limit, 500))
    )
    result = []
    for attempt, queue in session.execute(stmt):
        result.append({
            "queue_id": attempt.queue_id, "message_id": queue.message_id if queue else None,
            "sender": queue.envelope_from if queue else None, "recipient": attempt.recipient,
            "original_recipient": attempt.original_recipient, "time": attempt.occurred_at.isoformat(),
            "status": human_status(attempt), "technical_status": attempt.status, "dsn": attempt.dsn,
            "reply": attempt.reply, "relay": attempt.relay,
        })
    return result


def trace(session: Session, queue_id: str) -> dict:
    links = session.execute(select(QueueLink)).scalars().all()
    adjacent: dict[str, set[str]] = defaultdict(set)
    for link in links:
        adjacent[link.parent_queue_id].add(link.child_queue_id)
        adjacent[link.child_queue_id].add(link.parent_queue_id)
    ids, pending = set(), deque([queue_id])
    while pending and len(ids) < 5000:
        current = pending.popleft()
        if current in ids:
            continue
        ids.add(current)
        pending.extend(adjacent[current] - ids)
    queues = session.execute(select(QueueEntry).where(QueueEntry.queue_id.in_(ids))).scalars().all()
    attempts = session.execute(select(DeliveryAttempt).where(DeliveryAttempt.queue_id.in_(ids)).order_by(DeliveryAttempt.occurred_at)).scalars().all()
    recipients: dict[str, list[dict]] = defaultdict(list)
    for a in attempts:
        recipients[a.recipient or "—"].append({"time": a.occurred_at.isoformat(), "status": human_status(a), "dsn": a.dsn, "reply": a.reply, "relay": a.relay})
    return {
        "root_queue_id": queue_id, "queue_ids": sorted(ids),
        "message_ids": sorted({q.message_id for q in queues if q.message_id}),
        "senders": sorted({q.envelope_from for q in queues if q.envelope_from}),
        "recipients": recipients,
    }


def stats(session: Session) -> dict:
    return {
        "messages": session.scalar(select(func.count()).select_from(QueueEntry)) or 0,
        "attempts": session.scalar(select(func.count()).select_from(DeliveryAttempt)) or 0,
        "rejections": session.scalar(select(func.count()).select_from(Rejection)) or 0,
    }
