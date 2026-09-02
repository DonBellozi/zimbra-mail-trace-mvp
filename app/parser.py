from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SYSLOG = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+(?P<program>[^\[]+)\[(?P<pid>\d+)\]:\s+(?P<body>.*)$")
QUEUE = re.compile(r"^(?P<queue>[A-F0-9]{5,}):\s+(?P<body>.*)$")
PAIR = re.compile(r"(?P<key>[a-z_-]+)=(?:<(?P<angle>[^>]*)>|(?P<plain>[^, ]+))")
QUEUED_AS = re.compile(r"queued as (?P<child>[A-F0-9]{5,})", re.I)
SMTP_REPLY = re.compile(r"\((?P<reply>.*)\)$")
CLIENT = re.compile(r"(?P<name>[^\s\[]+)\[(?P<ip>[^\]]+)\]")
NOQUEUE = re.compile(r"NOQUEUE: reject: (?P<stage>\w+) from (?P<client>[^:]+): (?P<reply>.*)")
BOUNCE = re.compile(r"sender non-delivery notification: (?P<child>[A-F0-9]{5,})")


@dataclass(slots=True)
class Event:
    timestamp: datetime
    host: str
    program: str
    pid: int
    kind: str
    queue_id: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)


def _timestamp(match: re.Match[str], year: int) -> datetime:
    return datetime.strptime(f"{year} {match['month']} {match['day']} {match['time']}", "%Y %b %d %H:%M:%S")


def _pairs(text: str) -> dict[str, str]:
    return {m["key"]: (m["angle"] if m["angle"] is not None else m["plain"]) for m in PAIR.finditer(text)}


def parse_line(line: str, year: int) -> Event | None:
    sm = SYSLOG.match(line.rstrip())
    if not sm:
        return None
    body = sm["body"]
    common = dict(timestamp=_timestamp(sm, year), host=sm["host"], program=sm["program"], pid=int(sm["pid"]))

    if body.startswith("NOQUEUE:"):
        nm = NOQUEUE.match(body)
        fields = _pairs(body)
        if nm:
            fields.update(stage=nm["stage"], reply=nm["reply"])
            cm = CLIENT.search(nm["client"])
            if cm:
                fields.update(client_name=cm["name"], client_ip=cm["ip"])
        return Event(**common, kind="rejected", fields=fields)

    qm = QUEUE.match(body)
    if not qm:
        return None
    queue_id, payload = qm["queue"], qm["body"]
    fields = _pairs(payload)

    if payload.startswith("client="):
        cm = CLIENT.search(payload)
        if cm:
            fields.update(client_name=cm["name"], client_ip=cm["ip"])
        return Event(**common, kind="accepted", queue_id=queue_id, fields=fields)
    if payload.startswith("message-id="):
        return Event(**common, kind="message_id", queue_id=queue_id, fields=fields)
    if "queue active" in payload:
        return Event(**common, kind="queued", queue_id=queue_id, fields=fields)
    if payload == "removed":
        return Event(**common, kind="removed", queue_id=queue_id)
    bm = BOUNCE.search(payload)
    if bm:
        return Event(**common, kind="bounce", queue_id=queue_id, fields={"child_queue_id": bm["child"]})
    if "status=" in payload:
        child = QUEUED_AS.search(payload)
        reply = SMTP_REPLY.search(payload)
        if child:
            fields["child_queue_id"] = child["child"]
        if reply:
            fields["reply"] = reply["reply"]
        delays = fields.get("delays", "").split("/")
        if len(delays) == 4:
            fields["delay_before_queue"], fields["delay_in_queue"], fields["delay_connect"], fields["delay_transmit"] = delays
        relay = CLIENT.search(fields.get("relay", ""))
        if relay:
            fields.update(relay_name=relay["name"], relay_ip=relay["ip"])
        kind = "delivery"
        return Event(**common, kind=kind, queue_id=queue_id, fields=fields)
    return None
