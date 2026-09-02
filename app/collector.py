from __future__ import annotations

import gzip
import hashlib
import io
import posixpath
from datetime import datetime
from pathlib import PurePosixPath
from typing import BinaryIO, Iterable

import paramiko
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from .models import DeliveryAttempt, IngestCheckpoint, QueueEntry, QueueLink, Rejection
from .parser import Event, parse_line


def apply_event(session: Session, event: Event) -> None:
    f = event.fields
    if event.kind in {"accepted", "message_id", "queued", "removed"} and event.queue_id:
        values = {
            "queue_id": event.queue_id,
            "first_seen": event.timestamp,
            "last_seen": event.timestamp,
        }
        mapping = {
            "message-id": "message_id", "from": "envelope_from", "size": "size", "nrcpt": "recipient_count",
            "client_ip": "client_ip", "client_name": "client_name", "sasl_username": "sasl_username",
        }
        for source, target in mapping.items():
            if source in f:
                value = f[source]
                if target in {"size", "recipient_count"}:
                    value = int(value)
                values[target] = value
        stmt = insert(QueueEntry).values(**values)
        updates = {k: v for k, v in values.items() if k not in {"queue_id", "first_seen"}}
        session.execute(stmt.on_conflict_do_update(index_elements=[QueueEntry.queue_id], set_=updates))

    if event.kind == "delivery" and event.queue_id:
        session.execute(insert(DeliveryAttempt).values(
            queue_id=event.queue_id, occurred_at=event.timestamp, recipient=f.get("to"),
            original_recipient=f.get("orig_to"), transport=event.program, relay=f.get("relay"),
            status=f.get("status"), dsn=f.get("dsn"), reply=f.get("reply"), delay=f.get("delay"), details=f,
        ).on_conflict_do_nothing())
        if f.get("child_queue_id"):
            session.execute(insert(QueueLink).values(
                parent_queue_id=event.queue_id, child_queue_id=f["child_queue_id"], relation="queued_as",
                occurred_at=event.timestamp,
            ).on_conflict_do_nothing())
    elif event.kind == "bounce" and event.queue_id:
        session.execute(insert(QueueLink).values(
            parent_queue_id=event.queue_id, child_queue_id=f["child_queue_id"], relation="bounce",
            occurred_at=event.timestamp,
        ).on_conflict_do_nothing())
    elif event.kind == "rejected":
        session.execute(insert(Rejection).values(
            occurred_at=event.timestamp, client_ip=f.get("client_ip"), sender=f.get("from"),
            recipient=f.get("to"), stage=f.get("stage"), reply=f.get("reply"),
        ).on_conflict_do_nothing())


def ingest_lines(session: Session, lines: Iterable[str], year: int, batch_size: int = 2000) -> dict[str, int]:
    parsed = stored = 0
    for line in lines:
        parsed += 1
        event = parse_line(line, year)
        if event:
            apply_event(session, event)
            stored += 1
        if parsed % batch_size == 0:
            session.commit()
    session.commit()
    return {"lines": parsed, "events": stored}


class SSHSource:
    def __init__(self, config: dict):
        self.config = config

    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        policy = self.config.get("host_key_policy", "accept-new")
        # Legacy 0.1 configs used "reject" without providing a known_hosts file,
        # which made every fresh container unable to connect.
        if policy == "accept-new" or not self.config.get("known_hosts_path"):
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(hostname=self.config["ssh_host"], port=int(self.config.get("ssh_port", 22)), username=self.config["ssh_user"], timeout=15)
        if self.config.get("ssh_private_key"):
            key_text = self.config["ssh_private_key"]
            key = None
            for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
                try:
                    key = key_class.from_private_key(io.StringIO(key_text), password=self.config.get("ssh_key_passphrase"))
                    break
                except (paramiko.SSHException, ValueError):
                    continue
            if key is None:
                raise ValueError("Не удалось прочитать приватный SSH-ключ")
            kwargs["pkey"] = key
        else:
            kwargs["password"] = self.config.get("ssh_password")
        client.connect(**kwargs)
        return client

    def test(self) -> dict:
        client = self._connect()
        try:
            _, stdout, _ = client.exec_command("hostname", timeout=10)
            return {"ok": True, "hostname": stdout.read().decode(errors="replace").strip()}
        finally:
            client.close()

    def list_logs(self) -> list[dict]:
        base = self.config.get("mail_log_path", "/var/log/mail.log")
        directory, prefix = posixpath.dirname(base), posixpath.basename(base)
        client = self._connect()
        try:
            sftp = client.open_sftp()
            result = []
            for item in sftp.listdir_attr(directory):
                if item.filename == prefix or item.filename.startswith(prefix + "."):
                    result.append({"path": posixpath.join(directory, item.filename), "size": item.st_size, "mtime": item.st_mtime})
            return sorted(result, key=lambda x: x["mtime"])
        finally:
            client.close()

    def sync(self, session: Session, year: int | None = None) -> dict:
        """Read rotations oldest-first and resume the active file by byte offset."""
        year = year or datetime.now().year
        base = self.config.get("mail_log_path", "/var/log/mail.log")
        directory, prefix = posixpath.dirname(base), posixpath.basename(base)
        client = self._connect()
        totals = {"files": 0, "lines": 0, "events": 0}
        try:
            sftp = client.open_sftp()
            attrs = [a for a in sftp.listdir_attr(directory) if a.filename == prefix or a.filename.startswith(prefix + ".")]
            for attr in sorted(attrs, key=lambda a: a.st_mtime):
                path = posixpath.join(directory, attr.filename)
                with sftp.open(path, "rb") as probe:
                    fingerprint = hashlib.sha256(probe.read(4096)).hexdigest()
                checkpoint = session.scalar(select(IngestCheckpoint).where(IngestCheckpoint.source == fingerprint))
                compressed = path.endswith(".gz")
                if compressed and checkpoint:
                    continue
                offset = checkpoint.byte_offset if checkpoint and path == base else 0
                if not compressed and offset > attr.st_size:
                    offset = 0
                with sftp.open(path, "rb") as remote:
                    if compressed:
                        binary: BinaryIO = gzip.GzipFile(fileobj=remote)
                    else:
                        remote.seek(offset)
                        binary = remote
                    stream = io.TextIOWrapper(binary, encoding="utf-8", errors="replace")
                    result = ingest_lines(session, stream, year)
                    final_offset = attr.st_size if compressed else remote.tell()
                if checkpoint:
                    checkpoint.byte_offset = final_offset
                    checkpoint.fingerprint = path
                    checkpoint.updated_at = datetime.now()
                else:
                    session.add(IngestCheckpoint(source=fingerprint, fingerprint=path, byte_offset=final_offset, updated_at=datetime.now()))
                session.commit()
                totals["files"] += 1
                totals["lines"] += result["lines"]
                totals["events"] += result["events"]
            return totals
        finally:
            client.close()
