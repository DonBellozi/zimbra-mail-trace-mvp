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


def search(
    session: Session,
    query: str,
    page: int = 1,
    page_size: int = 50,
    date_from: datetime | None = None,
    date_to_exclusive: datetime | None = None,
    sender: str | None = None,
    recipient: str | None = None,
) -> dict:
    like = f"%{query.strip()}%"
    filters = [or_(
        DeliveryAttempt.recipient.ilike(like), DeliveryAttempt.original_recipient.ilike(like),
        QueueEntry.envelope_from.ilike(like), QueueEntry.message_id.ilike(like),
        QueueEntry.queue_id.ilike(like), QueueEntry.sasl_username.ilike(like), QueueEntry.client_ip.ilike(like),
    )]
    if date_from:
        filters.append(DeliveryAttempt.occurred_at >= date_from)
    if date_to_exclusive:
        filters.append(DeliveryAttempt.occurred_at < date_to_exclusive)
    if sender and sender.strip():
        filters.append(QueueEntry.envelope_from.ilike(f"%{sender.strip()}%"))
    if recipient and recipient.strip():
        recipient_like = f"%{recipient.strip()}%"
        filters.append(or_(DeliveryAttempt.recipient.ilike(recipient_like), DeliveryAttempt.original_recipient.ilike(recipient_like)))
    stmt = (
        select(DeliveryAttempt, QueueEntry)
        .outerjoin(QueueEntry, QueueEntry.queue_id == DeliveryAttempt.queue_id)
        .where(*filters)
        .order_by(DeliveryAttempt.occurred_at.desc(), DeliveryAttempt.id.desc())
        # Technical hops are collapsed below. The safety ceiling prevents an
        # unbounded request; ordinary investigations remain fully pageable.
        .limit(50_000)
    )
    rows = list(session.execute(stmt))
    queue_ids = {attempt.queue_id for attempt, _ in rows}

    # Queue IDs change after DKIM/Amavis and other internal hand-offs. Build
    # connected components from the explicit "queued as"/bounce relationships;
    # Message-ID alone is not reliable enough because it may be absent.
    parent = {queue_id: queue_id for queue_id in queue_ids}

    def find(queue_id: str) -> str:
        while parent[queue_id] != queue_id:
            parent[queue_id] = parent[parent[queue_id]]
            queue_id = parent[queue_id]
        return queue_id

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    if queue_ids:
        links = session.execute(select(QueueLink).where(or_(
            QueueLink.parent_queue_id.in_(queue_ids),
            QueueLink.child_queue_id.in_(queue_ids),
        ))).scalars()
        for link in links:
            if link.parent_queue_id in parent and link.child_queue_id in parent:
                union(link.parent_queue_id, link.child_queue_id)

    grouped: dict[tuple[str, str], dict] = {}
    for attempt, queue in rows:
        message_key = find(attempt.queue_id)
        recipient_key = (attempt.original_recipient or attempt.recipient or "").lower()
        key = (message_key, recipient_key)
        row = {
            "queue_id": attempt.queue_id, "message_id": queue.message_id if queue else None,
            "sender": queue.envelope_from if queue else None, "recipient": attempt.recipient,
            "original_recipient": attempt.original_recipient, "time": attempt.occurred_at.isoformat(),
            "status": human_status(attempt), "technical_status": attempt.status, "dsn": attempt.dsn,
            "reply": attempt.reply, "relay": attempt.relay, "_occurred_at": attempt.occurred_at,
        }
        # Rows arrive newest-first. The first event for this message/recipient is
        # its current status; older queued-as stages remain available in trace().
        if key not in grouped:
            grouped[key] = row
        elif not grouped[key].get("sender") and row.get("sender"):
            grouped[key]["sender"] = row["sender"]
    results = list(grouped.values())

    # "queued as" confirms only an internal hand-off. It is not a final result.
    collapsed = []
    for row in results:
        is_handoff = row["status"] == "sent" and "queued as" in (row.get("reply") or "").lower()
        if is_handoff:
            continue
        collapsed.append(row)
    for row in collapsed:
        row.pop("_occurred_at", None)
    total = len(collapsed)
    page_size = min(max(page_size, 1), 100)
    page = max(page, 1)
    start = (page - 1) * page_size
    return {
        "items": collapsed[start:start + page_size],
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_previous": page > 1,
        "has_next": start + page_size < total,
    }


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
